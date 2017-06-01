// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use types::NameAndToken;
use config::Config;
use database::{DatabaseError, DomainRecord};
use discovery::{adddiscovery, discovery, ping, revokediscovery};
use email_routes::{revokeemail, setemail, verifyemail};
use errors::*;
use iron::headers::ContentType;
use iron::method::Method;
use iron::prelude::*;
use iron::status::{self, Status};
use iron_cors::CORS;
use mount::Mount;
use params::{FromValue, Params, Value};
use pdns::pdns;
use router::Router;
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn domain_for_name(name: &str, config: &Config) -> String {
    format!("{}.box.{}.", name, config.options.general.domain).to_lowercase()
}

fn register(req: &mut Request, config: &Config) -> IronResult<Response> {
    // Extract the local_ip and token parameter,
    // and the public IP from the socket.
    let public_ip = format!("{}", req.remote_addr.ip());

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);
    let local_ip = map.find(&["local_ip"]);

    // Both parameters are mandatory.
    if token.is_none() || local_ip.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();
    let local_ip = String::from_value(local_ip.unwrap()).unwrap();

    info!("GET /register token={} local_ip={} public_ip={}",
          token,
          local_ip,
          public_ip);

    // Save this registration in the database if we know about this token.
    // Check if we have a record with this token, bail out if not.
    match config.db.get_record_by_token(&token).recv().unwrap() {
        Ok(record) => {
            // Update the record with the challenge.
            let dns_challenge = match record.dns_challenge {
                Some(ref challenge) => Some(challenge.as_str()),
                None => None,
            };
            // Update the timestamp to be current.
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let email = match record.email {
                Some(ref email) => Some(email.as_str()),
                None => None,
            };
            let new_record = DomainRecord::new(&record.token,
                                               &record.local_name,
                                               &record.remote_name,
                                               dns_challenge,
                                               Some(&local_ip),
                                               Some(&public_ip),
                                               &record.description,
                                               email,
                                               timestamp);
            match config.db.update_record(new_record).recv().unwrap() {
                Ok(()) => {
                    // Everything went fine, return an empty 200 OK for now.
                    ok_response!()
                }
                Err(_) => EndpointError::with(status::InternalServerError, 501),
            }
        }
        Err(DatabaseError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn info(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /info");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);
    if token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }
    let token = String::from_value(token.unwrap()).unwrap();

    match config.db.get_record_by_token(&token).recv().unwrap() {
        Ok(record) => json_response!(&record),
        Err(DatabaseError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn unsubscribe(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /unsubscribe");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);
    if token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }
    let token = String::from_value(token.unwrap()).unwrap();

    match config.db.delete_record_by_token(&token).recv().unwrap() {
        Ok(0) => EndpointError::with(status::BadRequest, 400), // No record found for this token.
        Ok(_) => ok_response!(),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn subscribe(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /subscribe");

    // Extract the name parameter.
    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    match map.find(&["name"]) {
        Some(&Value::String(ref name)) => {
            let full_name = domain_for_name(name, config);
            info!("trying to subscribe {}", full_name);

            let record = config.db.get_record_by_name(&full_name).recv().unwrap();
            match record {
                Ok(_) => {
                    // We already have a record for this name, return an error.
                    let mut response = Response::with(r#"{"error": "UnavailableName"}"#);
                    response.status = Some(Status::BadRequest);
                    response.headers.set(ContentType::json());
                    Ok(response)
                }
                Err(DatabaseError::NoRecord) => {
                    // Create a token, create and store a record and finally return the token.
                    let token = format!("{}", Uuid::new_v4());
                    let local_name = format!("local.{}", full_name);


                    let description = match map.find(&["desc"]) {
                        Some(&Value::String(ref desc)) => desc.to_owned(),
                        _ => format!("{}'s server", name),
                    };
                    let record = DomainRecord::new(&token,
                                                   &local_name,
                                                   &full_name,
                                                   None,
                                                   None,
                                                   None,
                                                   &description,
                                                   None,
                                                   0);
                    match config.db.add_record(record).recv().unwrap() {
                        Ok(()) => {
                            // We don't want the full domain name or the dns challenge in the
                            // response so we create a local struct.
                            let n_and_t = NameAndToken {
                                name: name.to_owned(),
                                token: token,
                            };
                            json_response!(&n_and_t)
                        }
                        Err(_) => EndpointError::with(status::InternalServerError, 501),
                    }
                }
                // Other error, like a db issue.
                Err(_) => EndpointError::with(status::InternalServerError, 501),
            }
        }
        // Missing `name` parameter.
        _ => EndpointError::with(status::BadRequest, 400),
    }
}

fn dnsconfig(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /dnsconfig");

    // Extract the challenge and token parameter.
    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let challenge = map.find(&["challenge"]);
    let token = map.find(&["token"]);

    // Both parameters are mandatory.
    if challenge.is_none() || token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let challenge = String::from_value(challenge.unwrap()).unwrap();
    let token = String::from_value(token.unwrap()).unwrap();

    // Check if we have a record with this token, bail out if not.
    match config.db.get_record_by_token(&token).recv().unwrap() {
        Ok(record) => {
            // Update the record with the challenge.
            let local_ip = match record.local_ip {
                Some(ref ip) => Some(ip.as_str()),
                None => None,
            };
            let public_ip = match record.public_ip {
                Some(ref ip) => Some(ip.as_str()),
                None => None,
            };
            let email = match record.email {
                Some(ref email) => Some(email.as_str()),
                None => None,
            };
            let new_record = DomainRecord::new(&record.token,
                                               &record.local_name,
                                               &record.remote_name,
                                               Some(&challenge),
                                               local_ip,
                                               public_ip,
                                               &record.description,
                                               email,
                                               record.timestamp);
            match config.db.update_record(new_record).recv().unwrap() {
                Ok(()) => {
                    // Everything went fine, return an empty 200 OK for now.
                    ok_response!()
                }
                Err(_) => EndpointError::with(status::InternalServerError, 501),
            }
        }
        Err(DatabaseError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

pub fn create_router(config: &Config) -> Router {
    let mut router = Router::new();

    macro_rules! handler {
        ($name:ident) => (
            let config_ = config.clone();
            router.get(stringify!($name),
                       move |req: &mut Request| -> IronResult<Response> {
                $name(req, &config_)
            }, stringify!($name));
        )
    }

    handler!(register);
    handler!(info);
    handler!(subscribe);
    handler!(unsubscribe);
    handler!(dnsconfig);

    handler!(ping);
    handler!(adddiscovery);
    handler!(revokediscovery);
    handler!(discovery);

    handler!(verifyemail);
    handler!(setemail);
    handler!(revokeemail);

    if config.options.pdns.socket_path.is_none() {
        handler!(pdns);
    }

    // Tests need the pdns handler in all cases.
    #[cfg(test)]
    {
        if config.options.pdns.socket_path.is_some() {
            handler!(pdns);
        }
    }

    router
}

pub fn create_chain(root_path: &str, config: &Config) -> Chain {
    let mut mount = Mount::new();
    mount.mount(root_path, create_router(&config));

    let mut chain = Chain::new(mount);
    let cors = CORS::new(vec![(vec![Method::Get], "info".to_owned()),
                              (vec![Method::Get], "subscribe".to_owned()),
                              (vec![Method::Get], "unsubscribe".to_owned()),
                              (vec![Method::Get], "register".to_owned()),
                              (vec![Method::Get], "dnsconfig".to_owned()),
                              (vec![Method::Get], "ping".to_owned()),
                              (vec![Method::Get], "adddiscovery".to_owned()),
                              (vec![Method::Get], "revokediscovery".to_owned()),
                              (vec![Method::Get], "discovery".to_owned()),
                              (vec![Method::Get], "setemail".to_owned()),
                              (vec![Method::Get], "revokeemail".to_owned())]);
    chain.link_after(cors);
    chain
}

#[cfg(test)]
mod tests {
    extern crate hyper;

    use super::*;
    use types::{NameAndToken, ServerInfo};
    use args::ArgsParser;
    use config::Config;
    use database::{Database, SqlParam};
    use iron::{Handler, Url};
    use iron::status::Status;
    use iron::method;
    use iron;
    use iron_test::response;
    use iron_test::mock_stream::MockStream;
    use std::io::Cursor;
    use self::hyper::buffer::BufReader;
    use self::hyper::net::NetworkStream;

    fn get(path: &str, router: &Router) -> (String, Status) {
        let resp = match request(method::Method::Get, path, "", router) {
            Ok(response) => response,
            Err(err) => err.response,
        };
        let status = resp.status.unwrap();
        (response::extract_body_to_string(resp), status)
    }

    fn put(path: &str, body: &str, router: &Router) -> (String, Status) {
        let resp = match request(method::Method::Get, path, body, router) {
            Ok(response) => response,
            Err(err) => err.response,
        };
        let status = resp.status.unwrap();
        (response::extract_body_to_string(resp), status)
    }

    // Triggers a request for a url on the router.
    fn request(method: method::Method,
               path: &str,
               body: &str,
               router: &Router)
               -> IronResult<Response> {
        let url = Url::parse(&format!("http://localhost/{}", path)).unwrap();
        // From iron 0.5.x, iron::Request contains private field. So, it is not good to
        // create iron::Request directly. Make http request and parse it with hyper,
        // and make iron::Request from hyper::client::Request.
        let mut buffer = String::new();
        buffer.push_str(&format!("{} {} HTTP/1.1\r\n", &method, url));
        buffer.push_str(&format!("Content-Length: {}\r\n", body.len() as u64));
        buffer.push_str("\r\n");
        buffer.push_str(body);

        let addr = "127.0.0.1:3000".parse().unwrap();
        let protocol = match url.scheme() {
            "http" => iron::Protocol::http(),
            "https" => iron::Protocol::https(),
            _ => panic!("unknown protocol {}", url.scheme()),
        };

        let mut stream = MockStream::new(Cursor::new(buffer.as_bytes().to_vec()));
        let mut buf_reader = BufReader::new(&mut stream as &mut NetworkStream);
        let http_request = hyper::server::Request::new(&mut buf_reader, addr).unwrap();
        let mut req = Request::from_http(http_request, addr, &protocol).unwrap();

        router.handle(&mut req)
    }

    #[test]
    fn test_router() {
        let db = Database::new("domain_db_test_routes.sqlite");
        db.flush().recv().unwrap().expect("Flushing the db");

        let args = ArgsParser::from_vec(vec!["registration_server",
                                             "--config-file=./config.toml.test"]);
        let mut arg_config = Config::from_args(args);
        let router = create_router(&arg_config.with_db(db.clone()));

        let bad_request_error = (r#"{"code":400,"errno":400,"error":"Bad Request"}"#.to_owned(),
                                 Status::BadRequest);
        let empty_ok = ("".to_owned(), Status::Ok);

        // Nothing is registered yet.
        assert_eq!(get("ping", &router), ("[]".to_owned(), Status::Ok));

        // Subscribe a test user.
        assert_eq!(get("subscribe", &router), bad_request_error);

        let resp = get("subscribe?name=test", &router);
        let registration: NameAndToken = serde_json::from_str(&resp.0).unwrap();
        let token = registration.token;

        assert_eq!(registration.name, "test".to_owned());

        // Unsubscribe
        assert_eq!(get("unsubscribe", &router), bad_request_error);
        assert_eq!(get("unsubscribe?token=wrong_token", &router),
                   bad_request_error);
        assert_eq!(get(&format!("unsubscribe?token={}", token), &router),
                   empty_ok);

        // Subscribe again
        let resp = get("subscribe?name=test", &router);
        let registration: NameAndToken = serde_json::from_str(&resp.0).unwrap();
        let token = registration.token;

        assert_eq!(registration.name, "test".to_owned());

        // Fail to register twice the same user.
        let res = get("subscribe?name=test", &router);
        assert_eq!(res,
                   (r#"{"error": "UnavailableName"}"#.to_owned(), Status::BadRequest));

        // Register without the expected parameters.
        assert_eq!(get("register", &router), bad_request_error);
        assert_eq!(get("register?name=test", &router), bad_request_error);
        assert_eq!(get(&format!("register?token={}", token), &router),
                   bad_request_error);
        assert_eq!(get("register?local_ip=10.0.0.1&token=wrong_token", &router),
                   bad_request_error);

        // Register properly.
        assert_eq!(get(&format!("register?local_ip=10.0.0.1&token={}", token),
                       &router),
                   empty_ok);

        // Now retrieve our registered client.
        assert_eq!(get("ping", &router),
                   (r#"[{"href":"https://local.test.box.knilxof.org","desc":"test's server"}]"#
                        .to_owned(),
                    Status::Ok));

        // Get the full info
        assert_eq!(get("info", &router), bad_request_error);
        assert_eq!(get("info?token=wrong_token", &router), bad_request_error);

        let response = get(&format!("info?token={}", token), &router);
        assert_eq!(response.1, Status::Ok);
        let record: ServerInfo = serde_json::from_str(&response.0).unwrap();
        assert_eq!(record.token, token);
        assert_eq!(record.local_name, "local.test.box.knilxof.org.".to_owned());
        assert_eq!(record.remote_name, "test.box.knilxof.org.");
        assert_eq!(record.local_ip, Some("10.0.0.1".to_owned()));
        assert_eq!(record.public_ip, Some("127.0.0.1".to_owned()));
        assert_eq!(record.description, r#"test's server"#);

        // Test the LE challenge endpoints.
        assert_eq!(get("dnsconfig", &router), bad_request_error);
        assert_eq!(get("dnsconfig?token=wrong_token", &router),
                   bad_request_error);
        assert_eq!(get(&format!("dnsconfig?token={}", token), &router),
                   bad_request_error);
        assert_eq!(get("dnsconfig?token=wrong_token&challenge=test_challenge",
                       &router),
                   bad_request_error);
        assert_eq!(get(&format!("dnsconfig?token={}&challenge=test_challenge", token),
                       &router),
                   empty_ok);

        // Tests for the pdns endpoint.

        // Bogus payload.
        assert_eq!(put("pdns", r#"{"foo": true}"#, &router), bad_request_error);

        // Unsupported method.
        assert_eq!(put("pdns",
                       r#"{"method":"dummy", "parameters":{"qtype":"a","qname":"b"}}"#,
                       &router),
                   (r#"{"result":false}"#.to_owned(), Status::Ok));

        // Simplified local redeclaration of the pdns data structures since
        // we don't need them to be public.
        #[derive(Debug, Serialize)]
        struct PdnsRequestParameters {
            // intialize method
            // path: Option<String>,
            // timeout: Option<String>,

            // lookup method
            qtype: Option<String>,
            qname: Option<String>,
            // #[serde(rename="zone-id")]
            // zone_id: Option<i32>,
            // remote: Option<String>,
            // local: Option<String>,
            // real_remote: Option<String>,
        }

        #[derive(Debug, Serialize)]
        struct PdnsRequest {
            method: String,
            parameters: PdnsRequestParameters,
        }

        // Failure for an unknown domain.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some("www.example.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();
        assert_eq!(put("pdns", &body, &router),
                   (r#"{"result":false}"#.to_owned(), Status::Ok));

        // Test the "remote" dns name.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some("test.box.knilxof.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success =
r#"{"result":[{"qtype":"A","qname":"test.box.knilxof.org.","content":"1.2.3.4","ttl":89}]}"#;
        assert_eq!(put("pdns", &body, &router),
                   (success.to_owned(), Status::Ok));

        // Test the "local" dns name.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some("local.test.box.knilxof.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success =
r#"{"result":[{"qtype":"A","qname":"local.test.box.knilxof.org.","content":"10.0.0.1","ttl":89}]}"#;
        assert_eq!(put("pdns", &body, &router),
                   (success.to_owned(), Status::Ok));

        // Test LE challenge queries.
        // Test the "local" dns name.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("TXT".to_owned()),
                qname: Some("_acme-challenge.local.test.box.knilxof.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success =
r#"{"result":[{"qtype":"TXT","qname":"_acme-challenge.local.test.box.knilxof.org.","content":"test_challenge","ttl":89}]}"#;
        assert_eq!(put("pdns", &body, &router),
                   (success.to_owned(), Status::Ok));

        // Test SOA queries.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("SOA".to_owned()),
                qname: Some("test.box.knilxof.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success =
r#"{"result":[{"qtype":"SOA","qname":"test.box.knilxof.org.","content":"a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800","ttl":89}]}"#;
        assert_eq!(put("pdns", &body, &router),
                   (success.to_owned(), Status::Ok));

        // PageKite queries
        #[derive(Deserialize)]
        struct PdnsLookupResponse {
            #[allow(dead_code)]
            qtype: String,
            #[allow(dead_code)]
            qname: String,
            content: String,
            #[allow(dead_code)]
            ttl: u32,
            #[allow(dead_code)]
            domain_id: Option<String>,
            #[allow(dead_code)]
            #[serde(rename="scopeMask")]
            scope_mask: Option<String>,
            #[allow(dead_code)]
            auth: Option<String>,
        }
        #[derive(Deserialize)]
        struct PdnsResponse {
            result: Vec<PdnsLookupResponse>,
        }

        // A request with a bogus domain.
        let qname = "dd7251eef7c773a192feb06c0e07ac6020ac.tc730a6b9e2f28f407bb3871e98d3fe4e60c.625558ecb0d283a5b058ba88fb3d9aa11d48.https-4443.fabrice.box.knilxof.org.box.knilxof.org.";
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some(qname.to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();
        let result = put("pdns", &body, &router);
        assert_eq!(result.1, Status::Ok);
        let response: PdnsResponse = serde_json::from_str(&result.0).unwrap();
        // 255.255.255.0 Means "no such name found for pagekite"
        assert_eq!(response.result[0].content, "255.255.255.0");

        // A request with a correct domain.
        let qname = "dd7251eef7c773a192feb06c0e07ac6020ac.tc730a6b9e2f28f407bb3871e98d3fe4e60c.625558ecb0d283a5b058ba88fb3d9aa11d48.https-4443.test.box.knilxof.org.box.knilxof.org.";
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some(qname.to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();
        let result = put("pdns", &body, &router);
        assert_eq!(result.1, Status::Ok);
        let response: PdnsResponse = serde_json::from_str(&result.0).unwrap();
        // 255.255.255.1 Means "failed to verify signature for pagekite"
        assert_eq!(response.result[0].content, "255.255.255.1");

        // SOA request.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("SOA".to_owned()),
                qname: Some(qname.to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();
        let result = put("pdns", &body, &router);
        assert_eq!(result.1, Status::Ok);
        let response: PdnsResponse = serde_json::from_str(&result.0).unwrap();
        assert_eq!(response.result[0].content,
                   "a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800");

        // TXT request.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("TXT".to_owned()),
                qname: Some(qname.to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();
        let result = put("pdns", &body, &router);
        assert_eq!(result.1, Status::Ok);
        assert_eq!(result.0, r#"{"result":false}"#);

        // Discovery tests.

        // Add a discovery token
        assert_eq!(get("adddiscovery", &router), bad_request_error);
        assert_eq!(get("adddiscovery?token=wrong_token", &router),
                   bad_request_error);
        assert_eq!(get("adddiscovery?token=wrong_token&disco=disco_token", &router),
                   bad_request_error);
        assert_eq!(get(&format!("adddiscovery?token={}&disco=disco_token", token),
                       &router),
                   empty_ok);

        // Get records for a given token.
        assert_eq!(get("discovery", &router), bad_request_error);
        assert_eq!(get("discovery?disco=wrong_disco", &router),
                   bad_request_error);
        assert_eq!(get("discovery?disco=disco_token", &router),
        (r#"[{"href":"https://local.test.box.knilxof.org","desc":"test's server"}]"#.to_owned(),
        Status::Ok));

        // Get the record with to evict it.
        let db = Database::new("domain_db_test_routes.sqlite");
        let timestamp = db.get_record_by_token(&token)
            .recv()
            .unwrap()
            .unwrap()
            .timestamp;
        assert_eq!(db.evict_records(SqlParam::Integer(timestamp + 1))
                       .recv()
                       .unwrap(),
                   Ok(1));

        // Check that we discover it now as a remote server.
        assert_eq!(get("discovery?disco=disco_token", &router),
        (r#"[{"href":"https://test.box.knilxof.org","desc":"test's server"}]"#.to_owned(),
        Status::Ok));

        // Revoke the token.
        assert_eq!(get("revokediscovery", &router), bad_request_error);
        assert_eq!(get("revokediscovery?token=wrong_token", &router),
                   bad_request_error);
        assert_eq!(get(&format!("revokediscovery?token={}", token), &router),
                   bad_request_error);
        assert_eq!(get(&format!("revokediscovery?token={}&disco=disco_token", token),
                       &router),
                   empty_ok);
        assert_eq!(get("discovery?disco=disco_token", &router),
                   bad_request_error);

        // Email routes tests
        // 1. set an email address
        let email = "test@example.com".to_owned();
        assert_eq!(get("setemail", &router), bad_request_error);
        assert_eq!(get("setemail?token=wrong_token", &router),
                   bad_request_error);
        assert_eq!(get("setemail?token=wrong_token&email=me@example.com", &router),
                   bad_request_error);
        assert_eq!(get(&format!("setemail?token={}&email=not_an_email", token),
                       &router),
                   bad_request_error);
        assert_eq!(get(&format!("setemail?token={}&email={}", token, email),
                       &router),
                   empty_ok);
        let email_record = db.get_email_by_token(&token).recv().unwrap().unwrap();
        assert_eq!(email_record.0, email);
        let link = email_record.1;
        // 2. verify the email
        assert_eq!(get("verifyemail", &router), bad_request_error);
        assert_eq!(get("verifyemail?s=wrong_link", &router),
                   (arg_config.options.email.error_page.unwrap(), Status::Ok));
        assert_eq!(get(&format!("verifyemail?s={}", link), &router),
                   (arg_config.options.email.success_page.unwrap(), Status::Ok));
        // 3. check that the email has been set on the domain record.
        let domain_record = db.get_record_by_token(&token).recv().unwrap().unwrap();
        assert_eq!(domain_record.email, Some(email.clone()));
        // 4. email revokation
        assert_eq!(get("revokeemail", &router), bad_request_error);
        assert_eq!(get("revokeemail?token=wrong_token", &router),
                   bad_request_error);
        assert_eq!(get("revokeemail?token=wrong_token&email=me@example.com",
                       &router),
                   bad_request_error);
        assert_eq!(get(&format!("revokeemail?token={}&email=not_an_email", token),
                       &router),
                   bad_request_error);
        assert_eq!(get(&format!("revokeemail?token={}&email={}", token, email),
                       &router),
                   empty_ok);
        // 5. Verify we don't have this email record anymore.
        let email_record = db.get_email_by_token(&token).recv().unwrap();
        assert_eq!(email_record, Err(DatabaseError::NoRecord));
    }
}
