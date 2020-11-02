// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy
// of the MPL was not distributed with this file, You can obtain one at
// http://mozilla.org/MPL/2.0/.

// Communication with the PowerDNS server happens through the Unix connector.
// See https://doc.powerdns.com/authoritative/backends/remote.html for details about the various
// requests and responses.

use crate::config::Config;
use crate::constants::DomainMode;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use log::{debug, error, info};
use maxminddb;
use maxminddb::geoip2;
use num_traits::FromPrimitive;
use regex::Regex;
use serde_json;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::str::FromStr;
use std::thread;

#[derive(Debug, Deserialize, Serialize)]
struct PdnsRequestParameters {
    // "initialize" method
    path: Option<String>,
    timeout: Option<String>,

    // "lookup" method
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
struct PdnsBoolResponse {
    result: bool,
}

#[derive(Serialize)]
struct PdnsVecResponse {
    result: Vec<PdnsResponseParams>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PdnsResponse {
    Bool { result: bool },
    Vector { result: Vec<PdnsResponseParams> },
}

fn get_geoip_address(continent: Option<String>, config: &Config) -> String {
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
        Some(continent) => match continent.code {
            Some(code) => Some(code.to_string()),
            None => None,
        },
        None => None,
    }
}

// Returns an A record for a given qname, using the tunnel IP.
fn build_a_response_tunnel(
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
    let result = get_geoip_address(c, config);

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
fn build_a_response_real(qname: &str, ttl: u32, ip: String) -> PdnsLookupResponse {
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

// Returns a CNAME record.
fn build_cname_response(qname: &str, ttl: u32, name: &str) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "CNAME".to_owned(),
        qname: qname.to_owned(),
        content: name.to_owned(),
        ttl: ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

// Returns an SOA record for a given qname.
fn build_soa_response(qname: &str, config: &Config) -> PdnsLookupResponse {
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
fn build_ns_response(qname: &str, config: &Config) -> Vec<PdnsLookupResponse> {
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
fn build_mx_response(qname: &str, config: &Config) -> Vec<PdnsLookupResponse> {
    let mut records = vec![];
    for mx in &config.options.pdns.mx_records {
        records.push(PdnsLookupResponse {
            qtype: "MX".to_owned(),
            qname: qname.to_owned(),
            content: mx.to_owned(),
            ttl: config.options.pdns.dns_ttl,
            domain_id: None,
            scope_mask: None,
            auth: None,
        });
    }

    records
}

// Returns a CAA record for a given qname.
fn build_caa_response(qname: &str, config: &Config) -> Vec<PdnsLookupResponse> {
    let mut records = vec![];
    for caa in &config.options.pdns.caa_records {
        records.push(PdnsLookupResponse {
            qtype: "CAA".to_owned(),
            qname: qname.to_owned(),
            content: caa.to_owned(),
            ttl: config.options.pdns.dns_ttl,
            domain_id: None,
            scope_mask: None,
            auth: None,
        });
    }

    records
}

// Returns a TXT record for a given qname.
fn build_txt_response(
    qname: &str,
    is_bare_domain: bool,
    subdomain: &str,
    config: &Config,
) -> Vec<PdnsLookupResponse> {
    let mut records = vec![];
    for txt in &config.options.pdns.txt_records {
        if txt[0] == "*" || txt[0] == subdomain || (txt[0] == "@" && is_bare_domain) {
            records.push(PdnsLookupResponse {
                qtype: "TXT".to_owned(),
                qname: qname.to_owned(),
                content: txt[1].to_owned(),
                ttl: config.options.pdns.dns_ttl,
                domain_id: None,
                scope_mask: None,
                auth: None,
            });
        }
    }

    records
}

// Returns a TXT record with the DNS challenge content.
fn build_dns_challenge_response(
    qname: &str,
    config: &Config,
    challenge: &str,
) -> PdnsLookupResponse {
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

// PageKite sends DNS requests to qnames like:
// dd7251eef7c773a192feb06c0e07ac6020ac.tc730a6b9e2f28f407bb3871e98d3fe4e60c.
// 625558ecb0d283a5b058ba88fb3d9aa11d48.https-4443.fabrice.mozilla-iot.org.mozilla-iot.org
// See https://pagekite.net/wiki/Howto/DnsBasedAuthentication
fn handle_pagekite_query(
    qname: &str,
    qtype: &str,
    config: &Config,
) -> Result<PdnsResponse, String> {
    debug!(
        "handle_pagekite_query(): PageKite query for {} {}",
        qtype, qname
    );

    let mut result = Vec::new();

    if qtype == "SOA" || qtype == "ANY" {
        result.push(PdnsResponseParams::Lookup(build_soa_response(
            qname, config,
        )));
    }

    if qtype == "NS" || qtype == "ANY" {
        for record in build_ns_response(qname, config) {
            result.push(PdnsResponseParams::Lookup(record));
        }
    }

    if qtype == "A" || qtype == "ANY" {
        let conn = config.db.get_connection();
        if conn.is_err() {
            error!(
                "handle_pagekite_query(): Failed to get database connection: {:?}",
                conn.err()
            );
            return Err("handle_pagekite_query(): Failed to get database connection.".to_owned());
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

                debug!(
                    "handle_pagekite_query(): Signatures: {} {}",
                    calc_sub, sign_sub
                );

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

        let record = PdnsLookupResponse {
            qtype: "A".to_owned(),
            qname: qname.to_owned(),
            content: ip.to_owned(),
            ttl: config.options.pdns.tunnel_ttl,
            domain_id: None,
            scope_mask: None,
            auth: None,
        };
        result.push(PdnsResponseParams::Lookup(record));
    }

    Ok(PdnsResponse::Vector { result: result })
}

fn handle_initialize(_req: PdnsRequest, _config: &Config) -> Result<PdnsResponse, String> {
    Ok(PdnsResponse::Bool { result: true })
}

// Example payload:
//
// {"method": "lookup",
//  "parameters": {"local": "0.0.0.0",
//                 "qname": "fabrice.mozilla-iot.org.",
//                 "qtype": "SOA",
//                 "real-remote": "63.245.221.198/32",
//                 "remote": "63.245.221.198",
//                 "zone-id": -1}}
fn handle_lookup(req: PdnsRequest, config: &Config) -> Result<PdnsResponse, String> {
    let original_qname = req.parameters.qname.unwrap().to_lowercase();
    let remote = req.parameters.remote;
    let mut qname = original_qname.clone();
    let subdomain: &str = &original_qname.split('.').next().unwrap();
    let qtype = req.parameters.qtype.unwrap();
    debug!(
        "process_request(): lookup for qtype={} qname={}",
        qtype, original_qname
    );

    // If the qname ends up with .$domain.$domain. we assume that it's a PageKite request and
    // process it separately.
    let domain = &config.options.general.domain;
    if qname.ends_with(&format!(".{}.{}.", domain, domain)) {
        return handle_pagekite_query(&qname, &qtype, config);
    }
    let bare_domain = format!("{}.", domain);

    // If the qname starts with `_acme-challenge.` this is a DNS-01 challenge verification, so
    // remove that part of the domain to retrieve our record.
    // See https://tools.ietf.org/html/draft-ietf-acme-acme-06#section-8.4
    if qname.starts_with("_acme-challenge.") {
        qname = qname[16..].to_owned();
    }

    debug!("process_request(): final qname={}", qname);

    let mut result = Vec::new();

    if qtype == "SOA" || qtype == "ANY" {
        // Add "SOA" record.
        result.push(PdnsResponseParams::Lookup(build_soa_response(
            &original_qname,
            config,
        )));
    }

    if qname == bare_domain && (qtype == "NS" || qtype == "ANY") {
        // Add "NS" records.
        for record in build_ns_response(&original_qname, config) {
            result.push(PdnsResponseParams::Lookup(record));
        }
    }

    if qname == bare_domain && (qtype == "MX" || qtype == "ANY") {
        // Add "MX" records.
        for record in build_mx_response(&original_qname, config) {
            result.push(PdnsResponseParams::Lookup(record));
        }
    }

    if qtype == "CAA" || qtype == "ANY" {
        // Add "CAA" records.
        for record in build_caa_response(&original_qname, config) {
            result.push(PdnsResponseParams::Lookup(record));
        }
    }

    if qtype == "TXT" || qtype == "ANY" {
        // Add "TXT" records.
        for record in build_txt_response(&original_qname, qname == bare_domain, subdomain, config) {
            result.push(PdnsResponseParams::Lookup(record));
        }

        // If the qname is _psl.$domain, add any TXT records and return, as this subdomain is
        // forbidden otherwise.
        let psl_domain = format!("_psl.{}.", domain);
        if qname == psl_domain {
            return Ok(PdnsResponse::Vector { result: result });
        }
    }

    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "process_request(): Failed to get database connection: {:?}",
            conn.err()
        );
        return Ok(PdnsResponse::Vector { result: result });
    }
    let conn = conn.unwrap();

    let ns_regex = Regex::new(r"^ns\d*$").unwrap();
    let is_ns_subdomain = ns_regex.is_match(&subdomain);
    let www_domain = format!("www.{}.", domain);
    let api_domain = format!("api.{}.", domain);
    let domain_lookup = conn.get_domain_by_name(&qname);

    // Look for a record with the qname.
    if is_ns_subdomain || qname == api_domain || domain_lookup.is_ok() {
        let record = match domain_lookup {
            Ok(val) => Some(val),
            Err(_) => None,
        };

        if qtype == "A" || qtype == "ANY" {
            // Add an "A" record.
            if is_ns_subdomain {
                for ns in &config.options.pdns.ns_records {
                    if qname == ns[0] {
                        result.push(PdnsResponseParams::Lookup(PdnsLookupResponse {
                            qtype: "A".to_owned(),
                            qname: qname.to_owned(),
                            content: ns[1].clone(),
                            ttl: config.options.pdns.dns_ttl,
                            domain_id: None,
                            scope_mask: None,
                            auth: None,
                        }));
                        break;
                    }
                }
            } else if qname == api_domain {
                // For the API domain, we can do a GeoIP lookup based on the remote IP.
                result.push(PdnsResponseParams::Lookup(build_a_response_tunnel(
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
                        // For a PageKite subdomain, we need to use the continent stored in the
                        // database.
                        result.push(PdnsResponseParams::Lookup(build_a_response_tunnel(
                            &original_qname,
                            config.options.pdns.tunnel_ttl,
                            config,
                            None,
                            continent,
                        )));
                    }
                    Some(DomainMode::DynamicDNS) => {
                        if last_ip.is_some() {
                            result.push(PdnsResponseParams::Lookup(build_a_response_real(
                                &original_qname,
                                config.options.pdns.tunnel_ttl,
                                last_ip.unwrap(),
                            )));
                        }
                    }
                    None => {}
                }
            }
        }

        if (qtype == "TXT" || qtype == "ANY")
            && qname != api_domain
            && !is_ns_subdomain
            && original_qname.starts_with("_acme-challenge.")
        {
            let record = record.clone().unwrap();
            if !record.dns_challenge.is_empty() {
                // Add a "TXT" record with the DNS challenge content.
                result.push(PdnsResponseParams::Lookup(build_dns_challenge_response(
                    &original_qname,
                    config,
                    &record.dns_challenge,
                )));
            }
        }
    } else if qname == www_domain
        && config.options.pdns.www_addresses.len() > 0
        && (qtype == "A" || qtype == "CNAME" || qtype == "ANY")
    {
        // Return a CNAME record: www.$domain -> $domain
        result.push(PdnsResponseParams::Lookup(build_cname_response(
            &original_qname,
            config.options.pdns.dns_ttl,
            &bare_domain,
        )));
    } else if qname == bare_domain
        && config.options.pdns.www_addresses.len() > 0
        && (qtype == "A" || qtype == "ANY")
    {
        for addr in &config.options.pdns.www_addresses {
            result.push(PdnsResponseParams::Lookup(build_a_response_real(
                &original_qname,
                config.options.pdns.dns_ttl,
                addr.clone(),
            )));
        }
    } else {
        info!("process_request(): No record for: {}", qname);
    }

    Ok(PdnsResponse::Vector { result: result })
}

fn handle_get_domain_metadata(_req: PdnsRequest, _config: &Config) -> Result<PdnsResponse, String> {
    Ok(PdnsResponse::Vector { result: Vec::new() })
}

fn process_request(req: PdnsRequest, config: &Config) -> Result<PdnsResponse, String> {
    debug!("process_request(): pdns request is {:?}", req);

    match req.method.as_ref() {
        "initialize" => handle_initialize(req, config),
        "lookup" => handle_lookup(req, config),
        "getDomainMetadata" => handle_get_domain_metadata(req, config),
        _ => Err(format!("Unsupported method: {}", req.method)),
    }
}

// Custom method to read just enough characters from the stream to build a JSON object.
// Directly using read_to_string or serde_json::from_reader causes the stream to reach EOF and
// subsequent write fail with a "Broken Pipe" error.
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
    let error_response = serde_json::to_string(&json!({"result": false})).unwrap();
    let error_response = error_response.as_bytes();

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

        match process_request(input, config) {
            Ok(ref response) => match serde_json::to_string(response) {
                Ok(serialized) => {
                    debug!("handle_socket_request(): Response is: {}", serialized);
                    send!(serialized.as_bytes());
                }
                Err(err) => {
                    error!("handle_socket_request(): Error serializing JSON: {}", err);
                    send!(error_response.clone());
                }
            },
            Err(err) => {
                error!("handle_socket_request(): Error processing request: {}", err);
                send!(error_response.clone());
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
    use crate::args::ArgsParser;
    use crate::config::Config;
    use crate::database::DatabasePool;
    use assert_json_diff::{assert_json_eq, assert_json_include};
    use serde_json;
    use serde_json::json;
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
        let _ = env_logger::try_init();

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

        let empty_success = json!({"result": true});
        let empty_error = json!({"result": []});
        let soa_exampleorg = json!({"result": [ {"qtype": "SOA"} ]});

        let mut answer: [u8; 1024] = [0; 1024];

        start_socket_endpoint(&config);

        // Allow enough time for the socket thread to start up and bind the socket.
        thread::sleep(Duration::new(1, 0));

        // Connect to the socket.
        let mut stream =
            UnixStream::connect(&config.clone().options.pdns.socket_path.unwrap()).unwrap();

        // Build an initialization request and send it to the stream.
        let request = build_lookup("initialize", None, None, None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(response, empty_success.clone());

        // Build a lookup request for the wrong domain and send it to the stream.
        let request = build_lookup("lookup", Some("A"), Some("example.org"), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(response, empty_error.clone());

        // Build an SOA lookup request and send it to the stream.
        let request = build_lookup("lookup", Some("SOA"), Some("mydomain.org"), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_include!(actual: response, expected: soa_exampleorg.clone());

        // Build an NS lookup request and send it to the stream.
        let request = build_lookup("lookup", Some("NS"), Some("mydomain.org"), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(response, empty_error.clone());

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "1d48.https-4443.test.mydomain.org.mydomain.org.",
                        "content": "255.255.255.0",
                        "ttl": 60,
                    }
                ]
            })
        );

        // ANY query
        let request = build_lookup("lookup", Some("ANY"), Some("mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "SOA",
                        "qname": "mydomain.org.",
                        "content": "ns1.mydomain.org. dns-admin.mydomain.org. 2018082801 900 900 1209600 60",
                        "ttl": 86400,
                    },
                    {
                        "qtype": "NS",
                        "qname": "mydomain.org.",
                        "content": "ns1.mydomain.org.",
                        "ttl": 86400,
                    },
                    {
                        "qtype": "NS",
                        "qname": "mydomain.org.",
                        "content": "ns2.mydomain.org.",
                        "ttl": 86400,
                    },
                    {
                        "qtype": "MX",
                        "qname": "mydomain.org.",
                        "content": "10 inbound-smtp.us-west-2.amazonaws.com",
                        "ttl": 86400,
                    },
                    {
                        "qtype": "CAA",
                        "qname": "mydomain.org.",
                        "content": "0 issue \"letsencrypt.org\"",
                        "ttl": 86400,
                    },
                    {
                        "qtype": "TXT",
                        "qname": "mydomain.org.",
                        "content": "something useful",
                        "ttl": 86400,
                    },
                    {
                        "qtype": "A",
                        "qname": "mydomain.org.",
                        "content": "10.11.12.13",
                        "ttl": 86400
                    },
                ]
            })
        );

        // PSL query
        let request = build_lookup("lookup", Some("TXT"), Some("_psl.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "TXT",
                        "qname": "_psl.mydomain.org.",
                        "content": "https://github.com/publicsuffix/list/pull/XYZ",
                        "ttl": 86400,
                    },
                ]
            })
        );

        // A query for ns1
        let request = build_lookup("lookup", Some("A"), Some("ns1.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "ns1.mydomain.org.",
                        "content": "5.6.7.8",
                        "ttl": 86400,
                    }
                ]
            })
        );

        // A query for ns2
        let request = build_lookup("lookup", Some("A"), Some("ns2.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "ns2.mydomain.org.",
                        "content": "4.5.6.7",
                        "ttl": 86400,
                    }
                ]
            })
        );

        // A query for ns3
        let request = build_lookup("lookup", Some("A"), Some("ns3.mydomain.org."), None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(response, empty_error.clone());

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "api.mydomain.org.",
                        "content": "1.2.3.4",
                        "ttl": 1,
                    }
                ]
            })
        );

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "api.mydomain.org.",
                        "content": "2.3.4.5",
                        "ttl": 1,
                    }
                ]
            })
        );

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "api.mydomain.org.",
                        "content": "3.4.5.6",
                        "ttl": 1,
                    }
                ]
            })
        );

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result":[
                    {
                        "qtype": "A",
                        "qname": "api.mydomain.org.",
                        "content": "4.5.6.7",
                        "ttl": 1,
                    }
                ]
            })
        );

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname":"api.mydomain.org.",
                        "content":"5.6.7.8",
                        "ttl": 1,
                    }
                ]
            })
        );

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "api.mydomain.org.",
                        "content": "6.7.8.9",
                        "ttl": 1,
                    }
                ]
            })
        );

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

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "api.mydomain.org.",
                        "content": "9.8.7.6",
                        "ttl": 1,
                    }
                ],
            })
        );

        // A query for www
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("www.mydomain.org."),
            Some("57.74.224.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "CNAME",
                        "qname": "www.mydomain.org.",
                        "content": "mydomain.org.",
                        "ttl": 86400,
                    }
                ],
            })
        );

        // A query for bare domain
        let request = build_lookup(
            "lookup",
            Some("A"),
            Some("mydomain.org."),
            Some("57.74.224.2"),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(
            response,
            json!({
                "result": [
                    {
                        "qtype": "A",
                        "qname": "mydomain.org.",
                        "content": "10.11.12.13",
                        "ttl": 86400,
                    }
                ],
            })
        );

        // getDomainMetadata
        let body = serde_json::to_string(&json!({
            "method": "getDomainMetadata",
            "parameters": {
                "name": "api.mydomain.org",
                "kind": "PRESIGNED",
            }
        }))
        .unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let len = stream.read(&mut answer).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&answer[..len]).unwrap();
        assert_json_eq!(response, empty_error.clone());
    }
}
