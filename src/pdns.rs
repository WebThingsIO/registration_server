// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Communication with the PowerDNS server happens through the http
// server.
// See https://doc.powerdns.com/md/authoritative/backend-remote/ for
// details about the various requests and responses.

use config::Config;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use errors::*;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status::{self, Status};
use serde_json;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
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

fn pdns_failure_as_iron(reason: &str) -> IronResult<Response> {
    debug!("pdns_failure: {}", reason);
    let mut response = Response::with("{\"result\":false}");
    response.status = Some(Status::Ok);
    response.headers.set(ContentType::json());
    Ok(response)
}

fn pdns_response_as_iron(response: &PdnsResponse) -> IronResult<Response> {
    match serde_json::to_string(response) {
        Ok(serialized) => {
            debug!("Response is: {}", serialized);
            let mut response = Response::with(serialized);
            response.status = Some(Status::Ok);
            response.headers.set(ContentType::json());

            Ok(response)
        }
        Err(err) => {
            error!("{}", err);
            EndpointError::with(status::InternalServerError, 501)
        }
    }
}

// Returns an SOA record for a given qname.
fn soa_response(qname: &str, config: &Config) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "SOA".to_owned(),
        qname: qname.to_owned(),
        content: config.options.pdns.soa_content.to_owned(),
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
    debug!("PageKite query for {} {}", qtype, qname);

    let mut pdns_response = PdnsResponse { result: Vec::new() };

    if qtype == "SOA" {
        pdns_response
            .result
            .push(PdnsResponseParams::Lookup(soa_response(qname, config)));
        return Ok(pdns_response);
    }

    if qtype != "A" && qtype != "ANY" {
        return Err(format!("Unsupported PageKite request type: {}", qtype));
    }

    let conn = config.db.get_connection();
    if conn.is_err() {
        return Err("Failed to get database connection.".to_owned());
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

            debug!("{} {} {} {} {}", srand, token, sign, proto, kite_domain);

            let mut hasher = Sha1::new();
            hasher.input_str(&format!("{}{}{}", record.token, payload, salt));
            let calc = hasher.result_str();

            let calc_sub = calc[..28].to_owned();
            let sign_sub = sign[8..36].to_owned();

            debug!("Signatures: {} {}", calc_sub, sign_sub);

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
        ttl: config.options.pdns.dns_ttl,
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
    debug!("pdns request is {:?}", req);

    if req.method == "lookup" {
        let original_qname = req.parameters.qname.unwrap().to_lowercase();
        let mut qname = original_qname.clone();
        let qtype = req.parameters.qtype.unwrap();
        debug!("lookup for qtype={} qname={}", qtype, original_qname);

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

        debug!("final qname={}", qname);

        let mut pdns_response = PdnsResponse { result: Vec::new() };

        if qtype == "SOA" {
            pdns_response
                .result
                .push(PdnsResponseParams::Lookup(soa_response(
                    &original_qname,
                    config,
                )));
        }

        if qtype == "ANY" {
            // Add an "MX" record.
            let mx_record = PdnsLookupResponse {
                qtype: "MX".to_owned(),
                qname: original_qname.to_owned(),
                content: config.options.pdns.mx_record.to_owned(),
                ttl: config.options.pdns.dns_ttl,
                domain_id: None,
                scope_mask: None,
                auth: None,
            };
            pdns_response
                .result
                .push(PdnsResponseParams::Lookup(mx_record));
        }

        let conn = config.db.get_connection();
        if conn.is_err() {
            return Ok(pdns_response);
        }
        let conn = conn.unwrap();

        let api_domain = format!("api.{}.", domain);
        let psl_domain = format!("_psl.{}.", domain);
        let domain_lookup = conn.get_domain_by_name(&qname);

        if qname == psl_domain {
            // Add the PSL record if known. If not, just return, as this subdomain is forbidden
            // otherwise.
            if (qtype == "ANY" || qtype == "TXT") && config.options.pdns.psl_record.is_some() {
                let psl_record = PdnsLookupResponse {
                    qtype: "TXT".to_owned(),
                    qname: original_qname.to_owned(),
                    content: config.options.pdns.clone().psl_record.unwrap(),
                    ttl: config.options.pdns.dns_ttl,
                    domain_id: None,
                    scope_mask: None,
                    auth: None,
                };
                pdns_response
                    .result
                    .push(PdnsResponseParams::Lookup(psl_record));
            }

            return Ok(pdns_response);
        }

        // Look for a record with the qname.
        if qname == api_domain || domain_lookup.is_ok() {
            if qtype == "ANY" || qtype == "A" {
                // Add an "A" record.
                let a_record = PdnsLookupResponse {
                    qtype: "A".to_owned(),
                    qname: original_qname.to_owned(),
                    content: config.options.general.tunnel_ip.to_owned(),
                    ttl: config.options.pdns.dns_ttl,
                    domain_id: None,
                    scope_mask: None,
                    auth: None,
                };
                pdns_response
                    .result
                    .push(PdnsResponseParams::Lookup(a_record));
            }

            if (qtype == "ANY" || qtype == "TXT") && domain_lookup.is_ok() {
                let record = domain_lookup.unwrap();
                if !record.dns_challenge.is_empty() {
                    // Add a "TXT" record with the DNS challenge content.
                    let txt_record = PdnsLookupResponse {
                        qtype: "TXT".to_owned(),
                        qname: original_qname.to_owned(),
                        content: record.dns_challenge,
                        ttl: config.options.pdns.dns_ttl,
                        domain_id: None,
                        scope_mask: None,
                        auth: None,
                    };
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(txt_record));
                }
            }

            if qtype == "ANY" {
                // Add a "CAA" record.
                let caa_record = PdnsLookupResponse {
                    qtype: "CAA".to_owned(),
                    qname: original_qname.to_owned(),
                    content: config.options.pdns.caa_record.to_owned(),
                    ttl: config.options.pdns.dns_ttl,
                    domain_id: None,
                    scope_mask: None,
                    auth: None,
                };
                pdns_response
                    .result
                    .push(PdnsResponseParams::Lookup(caa_record));
            }
        } else {
            info!("No record for this name {}", qname);
            // If there's no record in the database, we add the "TXT" record from the config file.
            if qtype == "ANY" {
                let txt_record = PdnsLookupResponse {
                    qtype: "TXT".to_owned(),
                    qname: original_qname.to_owned(),
                    content: config.options.pdns.txt_record.to_owned(),
                    ttl: config.options.pdns.dns_ttl,
                    domain_id: None,
                    scope_mask: None,
                    auth: None,
                };
                pdns_response
                    .result
                    .push(PdnsResponseParams::Lookup(txt_record));
            }
        }
        return Ok(pdns_response);
    }

    Err(format!("Unsupported method: {}", req.method))
}

// Answer an HTTP request when using the HTTP remote backend.
pub fn pdns(req: &mut Request, config: &Config) -> IronResult<Response> {
    use std::net::SocketAddr::V4;
    use std::net::Ipv4Addr;

    info!("GET /pdns");
    // Only allow clients from localhost.
    match req.remote_addr {
        V4(addr) => if addr.ip() != &Ipv4Addr::new(127, 0, 0, 1) {
            return EndpointError::with(status::BadRequest, 400);
        },
        _ => return EndpointError::with(status::BadRequest, 400),
    }

    // Read the request from the json body.
    let mut s = String::new();
    itry!(req.body.read_to_string(&mut s));

    debug!("Body is: {}", s);

    let input: PdnsRequest = match serde_json::from_str(&s) {
        Ok(value) => value,
        Err(err) => {
            error!("Bad request: {}", err);
            return EndpointError::with(status::BadRequest, 400);
        }
    };

    match process_request(input, config) {
        Ok(ref response) => pdns_response_as_iron(response),
        Err(err) => pdns_failure_as_iron(&err),
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
                error!("Stream reading error: {}", err);
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
        ($content:expr) => (
            stream.write_all($content).expect("Failed to write answer to the pdns socket");
        )
    }

    loop {
        let s = read_json_from_stream(&stream);
        debug!("JSON String is {}", s);
        let input: PdnsRequest = match serde_json::from_str(&s) {
            Ok(value) => value,
            Err(err) => {
                error!("JSON error: {}", err);
                break;
            }
        };

        // Special case for the `initialize` method which is a no-op that just
        // returns success.
        if input.method == "initialize" {
            debug!("Answering to initialization request");
            send!(b"{\"result\":true}");
            continue;
        }

        match process_request(input, config) {
            Ok(ref response) => match serde_json::to_string(response) {
                Ok(serialized) => {
                    debug!("Response is: {}", serialized);
                    send!(serialized.as_bytes());
                }
                Err(err) => {
                    error!("Error serializing JSON: {}", err);
                    send!(error_response);
                }
            },
            Err(err) => {
                error!("Error processing request: {}", err);
                send!(error_response);
            }
        }
    }
}

pub fn start_socket_endpoint(config: &Config) {
    if config.options.pdns.socket_path.is_none() {
        error!("No socket path configured!");
        return;
    }

    let path = &config.options.pdns.socket_path.clone().unwrap();

    debug!("Starting the pdns socket endpoint at {}", path);

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
                    error!("Couldn't bind: {:?}", e);
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

    fn build_request(method: &str, qtype: Option<&str>, qname: Option<&str>) -> PdnsRequest {
        let qtype = match qtype {
            Some(val) => Some(val.to_owned()),
            None => None,
        };
        let qname = match qname {
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
                remote: None,
                local: None,
                real_remote: None,
            },
        }
    }

    #[test]
    fn test_socket() {
        let args = ArgsParser::from_vec(vec![
            "registration_server",
            "--config-file=./config/config.toml",
        ]);

        #[cfg(feature = "mysql")]
        let db = DatabasePool::new("mysql://root@127.0.0.1/domain_db_test_pdns");
        #[cfg(feature = "postgres")]
        let db = DatabasePool::new("postgres://postgres@127.0.0.1/domain_db_test_pdns");
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
        let request = build_request("initialize", None, None);
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let empty_success = b"{\"result\":true}";
        let empty_error = b"{\"result\":[]}";
        let soa_exampleorg = b"{\"result\":[{\"qtype\":\"SOA\"";

        let mut answer: [u8; 256] = [0; 256];
        assert_eq!(stream.read(&mut answer).unwrap(), 15);
        assert_eq!(&answer[..15], empty_success);

        // Build a lookup request and send it to the stream.
        let request = build_request("lookup", Some("A"), Some("example.org"));
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 13);
        assert_eq!(&answer[..13], empty_error);

        // Build a SOA lookup request and send it to the stream.
        let request = build_request("lookup", Some("SOA"), Some("example.org"));
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 143);
        assert_eq!(&answer[..25], soa_exampleorg);

        // SOA PageKite query, to create a successful response without having
        // to setup records in the db.
        let request = build_request(
            "lookup",
            Some("A"),
            Some("1d48.https-4443.test.mydomain.org.mydomain.org."),
        );
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 119);
        let result = String::from_utf8(answer[..119].to_vec()).unwrap();
        let soa_success = "{\"result\":[{\"qtype\":\"A\",\
                           \"qname\":\"1d48.https-4443.test.mydomain.org.mydomain.org.\",\
                           \"content\":\"255.255.255.0\",\"ttl\":89}]}";
        assert_eq!(&result, soa_success);

        // ANY query
        let request = build_request("lookup", Some("ANY"), Some("example.org"));
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 131);
        let result = String::from_utf8(answer[..131].to_vec()).unwrap();
        let any_success = "{\"result\":[{\"qtype\":\"MX\",\
                           \"qname\":\"example.org\",\
                           \"content\":\"\",\"ttl\":89},\
                           {\"qtype\":\"TXT\",\
                           \"qname\":\"example.org\",\
                           \"content\":\"\",\"ttl\":89}]}";
        assert_eq!(&result, any_success);

        // PSL query
        let request = build_request("lookup", Some("TXT"), Some("_psl.mydomain.org."));
        let body = serde_json::to_string(&request).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        assert_eq!(stream.read(&mut answer).unwrap(), 124);
        let result = String::from_utf8(answer[..124].to_vec()).unwrap();
        let psl_success = "{\"result\":[{\"qtype\":\"TXT\",\
                           \"qname\":\"_psl.mydomain.org.\",\
                           \"content\":\"https://github.com/publicsuffix/list/pull/XYZ\",\
                           \"ttl\":89}]}";
        assert_eq!(&result, psl_success);
    }
}
