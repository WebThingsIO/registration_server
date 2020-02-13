// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Communication with the PowerDNS server happens through the http
// server.
// See https://doc.powerdns.com/md/authoritative/backend-remote/ for
// details about the various requests and responses.

extern crate env_logger;
use config::Config;
use constants::DomainMode;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use maxminddb;
use maxminddb::geoip2;
use num_traits::FromPrimitive;
use regex::Regex;
use serde_json;
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::str::FromStr;
use std::thread;

#[derive(Debug, Deserialize, Serialize)]
struct PdnsRequestParameters {
    // initialize method
    path: Option<String>,
    timeout: Option<String>,

    // lookup method
    qtype: Option<String>,
    qname: Option<String>,
    #[serde(rename = "zone-id")]
    zone_id: Option<i32>,
    remote: Option<String>,
    local: Option<String>,
    real_remote: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PdnsRequest {
    method: String,
    parameters: PdnsRequestParameters,
}

#[derive(Serialize)]
struct PdnsLookupResponse {
    qtype: String,
    qname: String,
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_id: Option<String>,
    #[serde(rename = "scopeMask")]
    #[serde(skip_serializing_if = "Option::is_none")]
    scope_mask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PdnsResponseParams {
    Lookup(PdnsLookupResponse),
}

#[derive(Serialize)]
struct PdnsResponse {
    result: Vec<PdnsResponseParams>,
}

fn get_geoip(continent: Option<String>, config: &Config) -> String {
    let geoip = config.options.pdns.geoip.clone();

    match continent {
        Some(code) => match code.as_ref() {
            "AF" => geoip.continent.AF.unwrap_or(geoip.default),
            "AN" => geoip.continent.AN.unwrap_or(geoip.default),
            "AS" => geoip.continent.AS.unwrap_or(geoip.default),
            "EU" => geoip.continent.EU.unwrap_or(geoip.default),
            "NA" => geoip.continent.NA.unwrap_or(geoip.default),
            "OC" => geoip.continent.OC.unwrap_or(geoip.default),
            "SA" => geoip.continent.SA.unwrap_or(geoip.default),
            _ => geoip.default,
        },
        None => geoip.default,
    }
}

pub fn lookup_continent(remote: IpAddr, config: &Config) -> Option<String> {
    let reader =
        maxminddb::Reader::open_readfile(&config.clone().options.pdns.geoip.database.unwrap())
            .unwrap();

    let result = reader.lookup(remote);
    if result.is_err() {
        return None;
    }

    let country: geoip2::Country = result.unwrap();

    match country.continent {
        Some(continent) => continent.code,
        None => None,
    }
}

// Returns an A record for a given qname, using the tunnel IP.
fn a_response_tunnel(
    qname: &str,
    ttl: u32,
    config: &Config,
    remote: Option<String>,
    continent: Option<String>,
) -> PdnsLookupResponse {
    // Do a GeoIP lookup on the remote IP, if the GeoIP database is configured. If the remote is
    // not set, use the passed in continent value.
    let c = match config.options.pdns.geoip.database {
        Some(_) => match remote {
            Some(remote_ip) => {
                let ip: IpAddr = FromStr::from_str(&remote_ip).unwrap();
                lookup_continent(ip, config)
            }
            None => continent,
        },
        None => continent,
    };

    // Determine the proper IP address to return, based on the continent.
    let result = get_geoip(c, config);

    PdnsLookupResponse {
        qtype: "A".to_owned(),
        qname: qname.to_owned(),
        content: result.to_owned(),
        ttl: ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns an A record for a given qname, using the real IP.
fn a_response_real(qname: &str, ttl: u32, ip: String) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "A".to_owned(),
        qname: qname.to_owned(),
        content: ip,
        ttl: ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns an SOA record for a given qname.
fn soa_response(qname: &str, config: &Config) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "SOA".to_owned(),
        qname: qname.to_owned(),
        content: config.options.pdns.soa_record.to_owned(),
        ttl: config.options.pdns.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns all NS records for a given qname.
fn ns_response(qname: &str, config: &Config) -> Vec<PdnsLookupResponse> {
    let mut records = vec![];
    for ns in &config.options.pdns.ns_records {
        records.push(PdnsLookupResponse {
            qtype: "NS".to_owned(),
            qname: qname.to_owned(),
            content: ns[0].to_owned(),
            ttl: config.options.pdns.dns_ttl,
            domain_id: None,
            scope_mask: None,
            auth: None,
        });
    }

    records
}

// Returns an MX record for a given qname.
fn mx_response(qname: &str, config: &Config) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "MX".to_owned(),
        qname: qname.to_owned(),
        content: config.options.pdns.mx_record.to_owned(),
        ttl: config.options.pdns.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns a CAA record for a given qname.
fn caa_response(qname: &str, config: &Config) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "CAA".to_owned(),
        qname: qname.to_owned(),
        content: config.options.pdns.caa_record.to_owned(),
        ttl: config.options.pdns.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns a TXT record for a given qname.
fn txt_response(qname: &str, config: &Config) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "TXT".to_owned(),
        qname: qname.to_owned(),
        content: config.options.pdns.txt_record.to_owned(),
        ttl: config.options.pdns.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns a TXT record with the DNS challenge content.
fn dns_challenge_response(qname: &str, config: &Config, challenge: &str) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "TXT".to_owned(),
        qname: qname.to_owned(),
        content: challenge.to_owned(),
        ttl: config.options.pdns.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns a TXT record containing the Public Suffix List authorization.
fn psl_response(qname: &str, config: &Config) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "TXT".to_owned(),
        qname: qname.to_owned(),
        content: config.options.pdns.clone().psl_record.unwrap(),
        ttl: config.options.pdns.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

fn pagekite_query(qname: &str, qtype: &str, config: &Config) -> Result<PdnsResponse, String> {
    // PageKite sends DNS requests to qnames like:
    // dd7251eef7c773a192feb06c0e07ac6020ac.tc730a6b9e2f28f407bb3871e98d3fe4e60c.
    // 625558ecb0d283a5b058ba88fb3d9aa11d48.https-4443.fabrice.mozilla-iot.org.mozilla-iot.org
    // See https://pagekite.net/wiki/Howto/DnsBasedAuthentication
    debug!("pagekite_query(): PageKite query for {} {}", qtype, qname);

    let mut pdns_response = PdnsResponse { result: Vec::new() };

    if qtype == "SOA" {
        pdns_response
            .result
            .push(PdnsResponseParams::Lookup(soa_response(qname, config)));
        return Ok(pdns_response);
    }

    if qtype == "NS" {
        for record in ns_response(qname, config) {
            pdns_response
                .result
                .push(PdnsResponseParams::Lookup(record));
        }
        return Ok(pdns_response);
    }

    if qtype != "A" && qtype != "ANY" {
        return Err(format!("Unsupported PageKite request type: {}", qtype));
    }

    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "pagekite_query(): Failed to get database connection: {:?}",
            conn.err()
        );
        return Err("pagekite_query(): Failed to get database connection.".to_owned());
    }
    let conn = conn.unwrap();

    // Split up the qname.
    let parts: Vec<&str> = qname.split('.').collect();
    let subdomain = format!("{}.{}.", parts[4], config.options.general.domain);
    let ip = match conn.get_domain_by_name(&subdomain) {
        Ok(record) => {
            let srand = parts[0];
            let token = parts[1];
            let sign = parts[2];
            let proto = parts[3];
            let kite_domain = format!("{}.{}", parts[4], config.options.general.domain);
            let payload = format!("{}:{}:{}:{}", proto, kite_domain, srand, token);
            let salt = sign[..8].to_owned();

            debug!(
                "pagekit_query(): {} {} {} {} {}",
                srand, token, sign, proto, kite_domain
            );

            let mut hasher = Sha1::new();
            hasher.input_str(&format!("{}{}{}", record.token, payload, salt));
            let calc = hasher.result_str();

            let calc_sub = calc[..28].to_owned();
            let sign_sub = sign[8..36].to_owned();

            debug!("pagekite_query(): Signatures: {} {}", calc_sub, sign_sub);

            if calc_sub == sign_sub {
                "255.255.254.255"
            } else {
                "255.255.255.1"
            }
        }
        Err(_) => {
            // Return 255.255.255.0 to PageKite to indicate failure.
            "255.255.255.0"
        }
    };

    let ns_record = PdnsLookupResponse {
        qtype: "A".to_owned(),
        qname: qname.to_owned(),
        content: ip.to_owned(),
        ttl: config.options.pdns.tunnel_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    };
    pdns_response
        .result
        .push(PdnsResponseParams::Lookup(ns_record));

    Ok(pdns_response)
}

fn process_request(req: PdnsRequest, config: &Config) -> Result<PdnsResponse, String> {
    debug!("process_request(): pdns request is {:?}", req);

    match req.method.as_ref() {
        "lookup" => {
            let original_qname = req.parameters.qname.unwrap().to_lowercase();
            let remote = req.parameters.remote;
            let mut qname = original_qname.clone();
            let subdomain: &str = &original_qname.split('.').next().unwrap();
            let qtype = req.parameters.qtype.unwrap();
            debug!(
                "process_request(): lookup for qtype={} qname={}",
                qtype, original_qname
            );

            // Example payload:
            //
            // {"method": "lookup",
            //  "parameters": {"local": "0.0.0.0",
            //                 "qname": "fabrice.mozilla-iot.org.",
            //                 "qtype": "SOA",
            //                 "real-remote": "63.245.221.198/32",
            //                 "remote": "63.245.221.198",
            //                 "zone-id": -1}}

            // If the qname ends up with .$domain.$domain. we consider that
            // it's a PageKite request and process it separately.
            let domain = &config.options.general.domain;
            if qname.ends_with(&format!(".{}.{}.", domain, domain)) {
                return pagekite_query(&qname, &qtype, config);
            }

            // If the qname starts with `_acme-challenge.` this is a DNS-01
            // challenge verification, so remove that part of the domain to
            // retrieve our record.
            // See https://tools.ietf.org/html/draft-ietf-acme-acme-06#section-8.4
            if qname.starts_with("_acme-challenge.") {
                qname = qname[16..].to_owned();
            }

            debug!("process_request(): final qname={}", qname);

            let mut pdns_response = PdnsResponse { result: Vec::new() };

            if qtype == "SOA" {
                pdns_response
                    .result
                    .push(PdnsResponseParams::Lookup(soa_response(
                        &original_qname,
                        config,
                    )));
            }

            if qtype == "NS" || qtype == "ANY" {
                for record in ns_response(&original_qname, config) {
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(record));
                }
            }

            if qtype == "ANY" {
                // Add an "MX" record.
                pdns_response
                    .result
                    .push(PdnsResponseParams::Lookup(mx_response(
                        &original_qname,
                        config,
                    )));
            }

            let conn = config.db.get_connection();
            if conn.is_err() {
                error!(
                    "process_request(): Failed to get database connection: {:?}",
                    conn.err()
                );
                return Ok(pdns_response);
            }
            let conn = conn.unwrap();

            let ns_regex = Regex::new(r"^ns\d*$").unwrap();
            let is_ns_subdomain = ns_regex.is_match(&subdomain);
            let bare_domain = format!("{}.", domain);
            let api_domain = format!("api.{}.", domain);
            let psl_domain = format!("_psl.{}.", domain);
            let domain_lookup = conn.get_domain_by_name(&qname);

            if qname == psl_domain {
                // Add the PSL record if known. If not, just return, as this subdomain is forbidden
                // otherwise.
                if (qtype == "ANY" || qtype == "TXT") && config.options.pdns.psl_record.is_some() {
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(psl_response(
                            &original_qname,
                            config,
                        )));
                }

                return Ok(pdns_response);
            }

            // Look for a record with the qname.
            if is_ns_subdomain || qname == api_domain || domain_lookup.is_ok() {
                let record = match domain_lookup {
                    Ok(val) => Some(val),
                    Err(_) => None,
                };

                if qtype == "ANY" || qtype == "A" {
                    // Add an "A" record.
                    if is_ns_subdomain {
                        for ns in &config.options.pdns.ns_records {
                            if qname == ns[0] {
                                pdns_response.result.push(PdnsResponseParams::Lookup(
                                    PdnsLookupResponse {
                                        qtype: "A".to_owned(),
                                        qname: qname.to_owned(),
                                        content: ns[1].clone(),
                                        ttl: config.options.pdns.dns_ttl,
                                        domain_id: None,
                                        scope_mask: None,
                                        auth: None,
                                    },
                                ));
                                break;
                            }
                        }
                    } else if qname == api_domain {
                        // For the API domain, we can do a GeoIP lookup based on the remote IP.
                        pdns_response
                            .result
                            .push(PdnsResponseParams::Lookup(a_response_tunnel(
                                &original_qname,
                                config.options.pdns.api_ttl,
                                config,
                                remote,
                                None,
                            )));
                    } else {
                        let record = record.clone().unwrap();

                        let continent = if record.continent.is_empty() {
                            None
                        } else {
                            Some(record.continent)
                        };

                        let last_ip = if record.last_ip.is_empty() {
                            None
                        } else {
                            Some(record.last_ip)
                        };

                        match FromPrimitive::from_i32(record.mode) {
                            Some(DomainMode::Tunneled) => {
                                // For a PageKite subdomain, we need to use the continent stored in
                                // the database.
                                pdns_response.result.push(PdnsResponseParams::Lookup(
                                    a_response_tunnel(
                                        &original_qname,
                                        config.options.pdns.tunnel_ttl,
                                        config,
                                        None,
                                        continent,
                                    ),
                                ));
                            }
                            Some(DomainMode::DynamicDNS) => {
                                if last_ip.is_some() {
                                    pdns_response.result.push(PdnsResponseParams::Lookup(
                                        a_response_real(
                                            &original_qname,
                                            config.options.pdns.tunnel_ttl,
                                            last_ip.unwrap(),
                                        ),
                                    ));
                                }
                            }
                            None => {}
                        }
                    }
                }

                if (qtype == "ANY" || qtype == "TXT") && qname != api_domain && !is_ns_subdomain {
                    let record = record.clone().unwrap();
                    if !record.dns_challenge.is_empty() {
                        // Add a "TXT" record with the DNS challenge content.
                        pdns_response.result.push(PdnsResponseParams::Lookup(
                            dns_challenge_response(&original_qname, config, &record.dns_challenge),
                        ));
                    }
                }

                if qtype == "ANY" {
                    // Add a "CAA" record.
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(caa_response(
                            &original_qname,
                            config,
                        )));
                }
            } else {
                if qname != bare_domain {
                    info!("process_request(): No record for: {}", qname);
                }

                // If there's no record in the database, we add the "TXT" record from the config file.
                if qtype == "ANY" {
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(txt_response(
                            &original_qname,
                            config,
                        )));
                }
            }

            Ok(pdns_response)
        }
        "getDomainMetadata" => Ok(PdnsResponse { result: Vec::new() }),
        _ => Err(format!("Unsupported method: {}", req.method)),
    }
}

// Custom method to read just enough characters from the stream to build a JSON
// object.
// Directly using read_to_string or serde_json::from_reader causes the stream
// to reach EOF and subsequent write fail with a "Broken Pipe" error.
fn read_json_from_stream(mut stream: &UnixStream) -> String {
    let mut buffer = [0; 1];
    let mut balance_count = 0;
    let mut result = String::new();
    loop {
        match stream.read(&mut buffer) {
            Ok(_) => {
                if buffer[0] == b'{' {
                    balance_count += 1;
                } else if buffer[0] == b'}' {
                    balance_count -= 1;
                }
                result.push(buffer[0] as char);
            }
            Err(err) => {
                error!("read_json_from_stream(): Stream reading error: {}", err);
            }
        }

        if balance_count == 0 {
            break;
        }
    }

    // Read the trailing \n
    #[allow(unused_must_use)]
    {
        stream.read(&mut buffer);
    }

    result
}

fn handle_socket_request(mut stream: UnixStream, config: &Config) {
    let error_response = b"{\"result\":false}";

    macro_rules! send {
        ($content:expr) => {
            stream
                .write_all($content)
                .expect("Failed to write answer to the pdns socket");
        };
    }

    loop {
        let s = read_json_from_stream(&stream);
        debug!("handle_socket_request(): JSON String is {}", s);
        let input: PdnsRequest = match serde_json::from_str(&s) {
            Ok(value) => value,
            Err(err) => {
                error!("handle_socket_request(): JSON error: {}", err);
                break;
            }
        };

        // Special case for the `initialize` method which is a no-op that just
        // returns success.
        if input.method == "initialize" {
            debug!("handle_socket_request(): Answering to initialization request");
            send!(b"{\"result\":true}");
            continue;
        }

        match process_request(input, config) {
            Ok(ref response) => match serde_json::to_string(response) {
                Ok(serialized) => {
                    debug!("handle_socket_request(): Response is: {}", serialized);
                    send!(serialized.as_bytes());
                }
                Err(err) => {
                    error!("handle_socket_request(): Error serializing JSON: {}", err);
                    send!(error_response);
                }
            },
            Err(err) => {
                error!("handle_socket_request(): Error processing request: {}", err);
                send!(error_response);
            }
        }
    }
}

pub fn start_socket_endpoint(config: &Config) {
    if config.options.pdns.socket_path.is_none() {
        error!("start_socket_endpoint(): No socket path configured!");
        return;
    }

    let path = &config.options.pdns.socket_path.clone().unwrap();

    debug!(
        "start_socket_endpoint(): Starting the pdns socket endpoint at {}",
        path
    );

    if Path::exists(Path::new(&path)) {
        #[allow(unused_must_use)]
        {
            fs::remove_file(path.clone());
        }
    }

    let config = config.clone();
    let path = path.clone();
    thread::Builder::new()
        .name("tunnel pdns socket".to_owned())
        .spawn(move || {
            let socket = match UnixListener::bind(path) {
                Ok(sock) => sock,
                Err(e) => {
                    error!("start_socket_endpoint(): Couldn't bind: {:?}", e);
                    return;
                }
            };
            for stream in socket.incoming() {
                match stream {
                    Ok(stream) => {
                        let config = config.clone();
                        thread::spawn(move || handle_socket_request(stream, &config));
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        })
        .expect("Failed to start pdns socket thread.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use args::ArgsParser;
    use config::Config;
    use database::DatabasePool;
    use std::time::Duration;

    fn build_lookup(
        method: &str,
        qtype: Option<&str>,
        qname: Option<&str>,
        remote: Option<&str>,
    ) -> PdnsRequest {
        let qtype = match qtype {
            Some(val) => Some(val.to_owned()),
            None => None,
        };
        let qname = match qname {
            Some(val) => Some(val.to_owned()),
            None => None,
        };
        let remote = match remote {
            Some(val) => Some(val.to_owned()),
            None => None,
        };

        PdnsRequest {
            method: method.to_owned(),
            parameters: PdnsRequestParameters {
                path: None,
                timeout: None,

                // lookup method
                qtype: qtype,
                qname: qname,
                zone_id: None,
                remote: remote,
                local: None,
                real_remote: None,
            },
        }
    }

    #[test]
    fn test_socket() {
        let _ = env_logger::init();

        let args = ArgsParser::from_vec(vec![
            "registration_server",
            "--config-file=./config/config.toml",
        ]);

        #[cfg(feature = "mysql")]
        let db = DatabasePool::new("mysql://root:root@127.0.0.1/domain_db_test_pdns");
        #[cfg(feature = "postgres")]
        let db = DatabasePool::new("postgres://postgres:password@127.0.0.1/domain_db_test_pdns");
        #[cfg(feature = "sqlite")]
        let db = DatabasePool::new("domain_db_test_pdns.sqlite");
        let conn = db.get_connection().expect("Getting connection.");
        conn.flush().expect("Flushing the db");

        let config = Config::from_args_with_db(args, db.clone());

        start_socket_endpoint(&config);

        // Allow enough time for the socket thread to start up and bind the
        // socket.
        thread::sleep(Duration::new(1, 0));
        // Connect to the socket.
        let mut stream =
            UnixStream::connect(&config.clone().options.pdns.socket_path.unwrap()).unwrap();
        // Build an initialization request and send it to the stream.
        let request = build_lookup("initialize", None, None, None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let empty_success = b"{\"result\":true}";
        let empty_error = b"{\"result\":[]}";
        let soa_exampleorg = b"{\"result\":[{\"qtype\":\"SOA\"";

        let mut answer: [u8; 512] = [0; 512];
        assert_eq!(stream.read(&mut answer).unwrap(), 15);
        assert_eq!(&answer[..15], empty_success);

        // Build a lookup request and send it to the stream.
        let request = build_lookup("lookup", Some("A"), Some("example.org"), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 13);
        assert_eq!(&answer[..13], empty_error);

        // Build an SOA lookup request and send it to the stream.
        let request = build_lookup("lookup", Some("SOA"), Some("example.org"), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 146);
        assert_eq!(&answer[..25], soa_exampleorg);

        // Build an NS lookup request and send it to the stream.
        let request = build_lookup("lookup", Some("NS"), Some("example.org"), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 170);
        let result = String::from_utf8(answer[..170].to_vec()).unwrap();
        let ns_success = "{\"result\":[{\"qtype\":\"NS\",\"qname\":\"example.org\",\
                          \"content\":\"ns1.mydomain.org.\",\"ttl\":86400},{\
                          \"qtype\":\"NS\",\"qname\":\"example.org\",\
                          \"content\":\"ns2.mydomain.org.\",\"ttl\":86400}]}";
        assert_eq!(&result, ns_success);

        // SOA PageKite query, to create a successful response without having
        // to setup records in the db.
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("1d48.https-4443.test.mydomain.org.mydomain.org."),
            None,
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 119);
        let result = String::from_utf8(answer[..119].to_vec()).unwrap();
        let soa_success = "{\"result\":[{\"qtype\":\"A\",\
                           \"qname\":\"1d48.https-4443.test.mydomain.org.mydomain.org.\",\
                           \"content\":\"255.255.255.0\",\"ttl\":60}]}";
        assert_eq!(&result, soa_success);

        // ANY query
        let request = build_lookup("lookup", Some("ANY"), Some("example.org"), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 295);
        let result = String::from_utf8(answer[..295].to_vec()).unwrap();
        let any_success = "{\"result\":[{\"qtype\":\"NS\",\"qname\":\"example.org\",\
                           \"content\":\"ns1.mydomain.org.\",\"ttl\":86400},{\
                           \"qtype\":\"NS\",\"qname\":\"example.org\",\
                           \"content\":\"ns2.mydomain.org.\",\"ttl\":86400},{\
                           \"qtype\":\"MX\",\"qname\":\"example.org\",\"content\":\"\",\
                           \"ttl\":86400},{\"qtype\":\"TXT\",\"qname\":\"example.org\",\
                           \"content\":\"\",\"ttl\":86400}]}";
        assert_eq!(&result, any_success);

        // PSL query
        let request = build_lookup("lookup", Some("TXT"), Some("_psl.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 127);
        let result = String::from_utf8(answer[..127].to_vec()).unwrap();
        let psl_success = "{\"result\":[{\"qtype\":\"TXT\",\
                           \"qname\":\"_psl.mydomain.org.\",\
                           \"content\":\"https://github.com/publicsuffix/list/pull/XYZ\",\
                           \"ttl\":86400}]}";
        assert_eq!(&result, psl_success);

        // A query for ns1
        let request = build_lookup("lookup", Some("A"), Some("ns1.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 86);
        let result = String::from_utf8(answer[..86].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"ns1.mydomain.org.\",\
                         \"content\":\"5.6.7.8\",\
                         \"ttl\":86400}]}";
        assert_eq!(&result, a_success);

        // A query for ns2
        let request = build_lookup("lookup", Some("A"), Some("ns2.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 86);
        let result = String::from_utf8(answer[..86].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"ns2.mydomain.org.\",\
                         \"content\":\"4.5.6.7\",\
                         \"ttl\":86400}]}";
        assert_eq!(&result, a_success);

        // A query for ns3
        let request = build_lookup("lookup", Some("A"), Some("ns3.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 13);
        assert_eq!(&answer[..13], empty_error);

        // A query (AF)
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("api.mydomain.org."),
            Some("41.189.192.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 82);
        let result = String::from_utf8(answer[..82].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"api.mydomain.org.\",\
                         \"content\":\"1.2.3.4\",\
                         \"ttl\":1}]}";
        assert_eq!(&result, a_success);

        // A query (AN)
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("api.mydomain.org."),
            Some("204.120.204.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 82);
        let result = String::from_utf8(answer[..82].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"api.mydomain.org.\",\
                         \"content\":\"2.3.4.5\",\
                         \"ttl\":1}]}";
        assert_eq!(&result, a_success);

        // A query (AS)
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("api.mydomain.org."),
            Some("1.0.32.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 82);
        let result = String::from_utf8(answer[..82].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"api.mydomain.org.\",\
                         \"content\":\"3.4.5.6\",\
                         \"ttl\":1}]}";
        assert_eq!(&result, a_success);

        // A query (EU)
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("api.mydomain.org."),
            Some("2.23.192.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 82);
        let result = String::from_utf8(answer[..82].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"api.mydomain.org.\",\
                         \"content\":\"4.5.6.7\",\
                         \"ttl\":1}]}";
        assert_eq!(&result, a_success);

        // A query (NA)
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("api.mydomain.org."),
            Some("8.8.8.8"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 82);
        let result = String::from_utf8(answer[..82].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"api.mydomain.org.\",\
                         \"content\":\"5.6.7.8\",\
                         \"ttl\":1}]}";
        assert_eq!(&result, a_success);

        // A query (OC)
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("api.mydomain.org."),
            Some("1.40.0.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 82);
        let result = String::from_utf8(answer[..82].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"api.mydomain.org.\",\
                         \"content\":\"6.7.8.9\",\
                         \"ttl\":1}]}";
        assert_eq!(&result, a_success);

        // A query (SA)
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("api.mydomain.org."),
            Some("57.74.224.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 82);
        let result = String::from_utf8(answer[..82].to_vec()).unwrap();
        let a_success = "{\"result\":[{\"qtype\":\"A\",\
                         \"qname\":\"api.mydomain.org.\",\
                         \"content\":\"9.8.7.6\",\
                         \"ttl\":1}]}";
        assert_eq!(&result, a_success);

        // getDomainMetadata
        let body = "{\"method\":\"getDomainMetadata\",\"parameters\":{\
                    \"name\":\"api.mydomain.org\",\"kind\":\"PRESIGNED\"}}";
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 13);
        let result = String::from_utf8(answer[..13].to_vec()).unwrap();
        let success = "{\"result\":[]}";
        assert_eq!(&result, success);
    }
}
