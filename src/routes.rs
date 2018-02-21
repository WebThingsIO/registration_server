// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use config::Config;
use diesel;
use email_routes::{revokeemail, setemail, verifyemail, EmailSender};
use errors::*;
use iron::headers::ContentType;
use iron::method::Method;
use iron::prelude::*;
use iron::status::{self, Status};
use iron_cors::CORS;
use mount::Mount;
use params::{FromValue, Params, Value};
use pdns::pdns;
use regex::Regex;
use router::Router;
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct NameAndToken {
    pub name: String,
    pub token: String,
}

fn domain_for_name(name: &str, config: &Config) -> String {
    format!("{}.{}.", name, config.options.general.domain).to_lowercase()
}

fn ping(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /ping");

    let conn = config.db.get_connection();
    if conn.is_err() {
        return EndpointError::with(status::InternalServerError, 501);
    }
    let conn = conn.unwrap();

    // Extract the token parameter.
    let map = req.get_ref::<Params>().unwrap();
    let token = map.find(&["token"]);

    if token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();

    // Save this ping in the database if we know about this token.
    match conn.update_domain_timestamp(&token) {
        Ok(count) if count > 0 => ok_response!(),
        Ok(_) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn info(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /info");

    let conn = config.db.get_connection();
    if conn.is_err() {
        return EndpointError::with(status::InternalServerError, 501);
    }
    let conn = conn.unwrap();

    let map = req.get_ref::<Params>().unwrap();
    let token = map.find(&["token"]);
    if token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }
    let token = String::from_value(token.unwrap()).unwrap();

    match conn.get_domain_by_token(&token) {
        Ok(record) => json_response!(&record),
        Err(diesel::result::Error::NotFound) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn unsubscribe(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /unsubscribe");

    let conn = config.db.get_connection();
    if conn.is_err() {
        return EndpointError::with(status::InternalServerError, 501);
    }
    let conn = conn.unwrap();

    let map = req.get_ref::<Params>().unwrap();
    let token = map.find(&["token"]);
    if token.is_none() {
        let reclamation_token = map.find(&["reclamationToken"]);
        match reclamation_token {
            Some(&Value::String(ref reclamation_token)) => {
                return match conn.delete_domain_by_reclamation_token(reclamation_token) {
                    Ok(0) => {
                        // No record found for this token.
                        EndpointError::with(status::BadRequest, 400)
                    }
                    Ok(_) => ok_response!(),
                    Err(_) => EndpointError::with(status::InternalServerError, 501),
                };
            }
            _ => {
                // No token or reclamation token provided.
                return EndpointError::with(status::BadRequest, 400);
            }
        }
    }
    let token = String::from_value(token.unwrap()).unwrap();

    match conn.delete_domain_by_token(&token) {
        Ok(0) => EndpointError::with(status::BadRequest, 400), // No record found for this token.
        Ok(_) => ok_response!(),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn reclaim(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /reclaim");

    let conn = config.db.get_connection();
    if conn.is_err() {
        return EndpointError::with(status::InternalServerError, 501);
    }
    let conn = conn.unwrap();

    let map = req.get_ref::<Params>().unwrap();
    let name = map.find(&["name"]);
    if name.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }
    let name = String::from_value(name.unwrap()).unwrap();
    let subdomain = name.trim().to_lowercase();
    let full_name = domain_for_name(&subdomain, config);

    match conn.get_domain_by_name(&full_name) {
        Ok(record) => {
            match conn.get_account_by_id(record.account_id) {
                Ok(account) => {
                    if account.email == "" {
                        let mut response = Response::with(r#"{"error": "NoEmail"}"#);
                        response.status = Some(status::BadRequest);
                        response.headers.set(ContentType::json());
                        return Ok(response);
                    }

                    let token = format!("{}", Uuid::new_v4());
                    let result = conn.update_domain_reclamation_token(&record.token, &token);
                    if result.is_err() || result.unwrap() == 0 {
                        return EndpointError::with(status::InternalServerError, 501);
                    }

                    // Send the reclamation token to the user via email.
                    match EmailSender::new(config) {
                        Ok(mut sender) => {
                            let body = config
                                .options
                                .email
                                .clone()
                                .reclamation_body
                                .unwrap()
                                .replace("{token}", &token);
                            match sender.send(
                                &account.email,
                                &body,
                                &config.options.email.clone().reclamation_title.unwrap(),
                            ) {
                                Ok(_) => ok_response!(),
                                Err(_) => EndpointError::with(status::InternalServerError, 501),
                            }
                        }
                        Err(_) => EndpointError::with(status::InternalServerError, 501),
                    }
                }
                Err(_) => {
                    // This name doesn't have an associated email address.
                    let mut response = Response::with(r#"{"error": "NoEmail"}"#);
                    response.status = Some(status::BadRequest);
                    response.headers.set(ContentType::json());
                    Ok(response)
                }
            }
        }
        Err(diesel::result::Error::NotFound) => {
            // This name doesn't exist, no need to reclaim it.
            let mut response = Response::with(r#"{"error": "NoSuchName"}"#);
            response.status = Some(status::BadRequest);
            response.headers.set(ContentType::json());
            Ok(response)
        }
        // Other error, like a db issue.
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn subscribe(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /subscribe");

    let conn = config.db.get_connection();
    if conn.is_err() {
        return EndpointError::with(status::InternalServerError, 501);
    }
    let conn = conn.unwrap();

    // Extract the name parameter.
    let map = req.get_ref::<Params>().unwrap();
    let name = map.find(&["name"]);
    if name.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }
    let name = String::from_value(name.unwrap()).unwrap();
    let subdomain = name.trim().to_lowercase();
    let full_name = domain_for_name(&subdomain, config);

    // Ensure that subdomain is valid:
    // - Contains only a-z, 0-9, and hyphens, but does not start or end
    //   with hyphen.
    // - Is not equal to "api", "www", or "_psl" as those are reserved.
    let re = Regex::new(r"^([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$").unwrap();
    if !re.is_match(&subdomain) || subdomain == "api" || subdomain == "www" || subdomain == "_psl"
        || subdomain.len() > 63 || full_name.len() > 253
    {
        let mut response = Response::with(r#"{"error": "UnavailableName"}"#);
        response.status = Some(status::BadRequest);
        response.headers.set(ContentType::json());
        return Ok(response);
    }

    info!("trying to subscribe {}", full_name);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match conn.get_domain_by_name(&full_name) {
        Ok(record) => {
            let reclamation_token = map.find(&["reclamationToken"]);
            if !reclamation_token.is_none() {
                let reclamation_token = String::from_value(reclamation_token.unwrap()).unwrap();
                if reclamation_token == record.reclamation_token {
                    // Create a new token and update the existing record.
                    let token = format!("{}", Uuid::new_v4());
                    match conn.update_domain_token(&record.name, &token) {
                        Ok(count) if count > 0 => {
                            // We don't want the full domain name or the DNS
                            // challenge in the response, so we create a local
                            // struct.
                            let n_and_t = NameAndToken {
                                name: subdomain.to_owned(),
                                token: token,
                            };
                            json_response!(&n_and_t)
                        }
                        Ok(_) => EndpointError::with(status::BadRequest, 400),
                        Err(_) => EndpointError::with(status::InternalServerError, 501),
                    }
                } else {
                    let mut response = Response::with(r#"{"error": "ReclamationTokenMismatch"}"#);
                    response.status = Some(status::BadRequest);
                    response.headers.set(ContentType::json());
                    Ok(response)
                }
            } else {
                // We already have a record for this name, return an error.
                let email = map.find(&["email"]);
                if !email.is_none() {
                    let email = String::from_value(email.unwrap()).unwrap();
                    if !email.is_empty() {
                        match conn.get_account_by_id(record.account_id) {
                            Ok(account) => {
                                if email == account.email {
                                    let mut response = Response::with(
                                        "{\"error\": \
                                         \"UnavailableNameReclamationPossible\"}",
                                    );
                                    response.status = Some(status::BadRequest);
                                    response.headers.set(ContentType::json());
                                    return Ok(response);
                                }
                            }
                            Err(_) => {
                                let mut response =
                                    Response::with(r#"{"error": "UnavailableName"}"#);
                                response.status = Some(status::BadRequest);
                                response.headers.set(ContentType::json());
                                return Ok(response);
                            }
                        }
                    }
                }

                let mut response = Response::with(r#"{"error": "UnavailableName"}"#);
                response.status = Some(status::BadRequest);
                response.headers.set(ContentType::json());
                Ok(response)
            }
        }
        Err(diesel::result::Error::NotFound) => {
            // Create a token, create and store a record, and finally,
            // return the token.
            let token = format!("{}", Uuid::new_v4());

            let description = match map.find(&["desc"]) {
                Some(&Value::String(ref desc)) => desc.to_owned(),
                _ => format!("{}'s server", name),
            };

            let result = conn.get_unknown_account();
            if result.is_err() {
                return EndpointError::with(status::InternalServerError, 501);
            }

            let account = result.unwrap();
            match conn.add_domain(
                &full_name,
                account.id,
                &token,
                &description,
                timestamp,
                "",
                "",
                "",
                false,
            ) {
                Ok(_) => {
                    // We don't want the full domain name or the DNS
                    // challenge in the response, so we create a local
                    // struct.
                    let n_and_t = NameAndToken {
                        name: subdomain.to_owned(),
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

fn dnsconfig(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /dnsconfig");

    let conn = config.db.get_connection();
    if conn.is_err() {
        return EndpointError::with(status::InternalServerError, 501);
    }
    let conn = conn.unwrap();

    // Extract the challenge and token parameter.
    let map = req.get_ref::<Params>().unwrap();
    let challenge = map.find(&["challenge"]);
    let token = map.find(&["token"]);

    // Both parameters are mandatory.
    if challenge.is_none() || token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let challenge = String::from_value(challenge.unwrap()).unwrap();
    if challenge.len() > 63 {
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();

    match conn.update_domain_dns_challenge(&token, &challenge) {
        Ok(count) if count > 0 => ok_response!(),
        Ok(_) => EndpointError::with(status::BadRequest, 400),
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

    handler!(ping);
    handler!(info);
    handler!(subscribe);
    handler!(unsubscribe);
    handler!(dnsconfig);
    handler!(reclaim);

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
    mount.mount(root_path, create_router(config));

    let mut chain = Chain::new(mount);
    let cors = CORS::new(vec![
        (vec![Method::Get], "subscribe".to_owned()),
        (vec![Method::Get], "unsubscribe".to_owned()),
        (vec![Method::Get], "reclaim".to_owned()),
        (vec![Method::Get], "ping".to_owned()),
        (vec![Method::Get], "dnsconfig".to_owned()),
        (vec![Method::Get], "info".to_owned()),
        (vec![Method::Get], "setemail".to_owned()),
        (vec![Method::Get], "verifyemail".to_owned()),
        (vec![Method::Get], "revokeemail".to_owned()),
    ]);
    chain.link_after(cors);
    chain
}

#[cfg(test)]
mod tests {
    extern crate hyper;

    use super::*;
    use args::ArgsParser;
    use config::Config;
    use database::DatabasePool;
    use iron::{Handler, Url};
    use iron::status::Status;
    use iron::method;
    use iron;
    use iron_test::response;
    use iron_test::mock_stream::MockStream;
    use models::Domain;
    use std::io::Cursor;
    use std::thread::sleep;
    use std;
    use std::time;
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

    // Triggers a request for a URL on the router.
    fn request(
        method: method::Method,
        path: &str,
        body: &str,
        router: &Router,
    ) -> IronResult<Response> {
        let url = Url::parse(&format!("http://localhost/{}", path)).unwrap();
        // From iron 0.5.x, iron::Request contains private field. So, it is not
        // good to create iron::Request directly. Make HTTP request and parse
        // it with hyper, and make iron::Request from hyper::client::Request.
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
        #[cfg(feature = "mysql")]
        let db = DatabasePool::new("mysql://root@127.0.0.1/domain_db_test_routes");
        #[cfg(feature = "postgres")]
        let db = DatabasePool::new("postgres://postgres@127.0.0.1/domain_db_test_routes");
        #[cfg(feature = "sqlite")]
        let db = DatabasePool::new("domain_db_test_routes.sqlite");
        let conn = db.get_connection().expect("Getting connection.");
        conn.flush().expect("Flushing the db");

        let args = ArgsParser::from_vec(vec![
            "registration_server",
            "--config-file=./config/config.toml",
        ]);
        let config = Config::from_args_with_db(args, db.clone());
        let router = create_router(&config);

        let bad_request_error = (
            r#"{"code":400,"errno":400,"error":"Bad Request"}"#.to_owned(),
            status::BadRequest,
        );
        let empty_ok = ("".to_owned(), status::Ok);

        // Subscribe a test user.
        assert_eq!(get("subscribe", &router), bad_request_error);
        assert_eq!(
            get("subscribe?name=", &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(
            get("subscribe?name=-test", &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(
            get("subscribe?name=test-", &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(
            get("subscribe?name=api", &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(
            get("subscribe?name=www", &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(
            get(
                "subscribe?name=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy\
                 zabcdefghijklmnopqrstuvwxyz",
                &router
            ),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );

        let resp = get("subscribe?name=test", &router);
        let registration: NameAndToken = serde_json::from_str(&resp.0).unwrap();
        let token = registration.token;

        assert_eq!(registration.name, "test".to_owned());

        // Unsubscribe
        assert_eq!(get("unsubscribe", &router), bad_request_error);
        assert_eq!(
            get("unsubscribe?token=wrong_token", &router),
            bad_request_error
        );
        assert_eq!(
            get(&format!("unsubscribe?token={}", token), &router),
            empty_ok
        );

        // Subscribe again
        let resp = get("subscribe?name=test", &router);
        let registration: NameAndToken = serde_json::from_str(&resp.0).unwrap();
        let token = registration.token;

        assert_eq!(registration.name, "test".to_owned());

        // Fail to register the same name twice.
        let res = get("subscribe?name=test", &router);
        assert_eq!(
            res,
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );

        // Test reclaiming domain
        let email = "test@example.com".to_owned();
        assert_eq!(
            get("subscribe?name=test&email=", &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(
            get(&format!("subscribe?name=test&email={}", email), &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(get("reclaim", &router), bad_request_error);
        let res = get("reclaim?name=nonexistent", &router);
        assert_eq!(
            res,
            (r#"{"error": "NoSuchName"}"#.to_owned(), status::BadRequest)
        );
        let res = get("reclaim?name=test", &router);
        assert_eq!(
            res,
            (r#"{"error": "NoEmail"}"#.to_owned(), status::BadRequest)
        );

        // Ping without the expected parameters.
        assert_eq!(get("ping", &router), bad_request_error);
        assert_eq!(get("ping?name=test", &router), bad_request_error);
        assert_eq!(get("ping?token=wrong_token", &router), bad_request_error);

        // Ping properly.
        sleep(time::Duration::from_secs(1));
        assert_eq!(get(&format!("ping?token={}", token), &router), empty_ok);

        // Get the full info
        assert_eq!(get("info", &router), bad_request_error);
        assert_eq!(get("info?token=wrong_token", &router), bad_request_error);

        let response = get(&format!("info?token={}", token), &router);
        assert_eq!(response.1, status::Ok);
        let record: Domain = serde_json::from_str(&response.0).unwrap();
        assert_eq!(record.token, token);
        assert_eq!(record.name, "test.mydomain.org.");
        assert_eq!(record.description, r#"test's server"#);

        // Test the LE challenge endpoints.
        assert_eq!(get("dnsconfig", &router), bad_request_error);
        assert_eq!(
            get("dnsconfig?token=wrong_token", &router),
            bad_request_error
        );
        assert_eq!(
            get(&format!("dnsconfig?token={}", token), &router),
            bad_request_error
        );
        assert_eq!(
            get(
                "dnsconfig?token=wrong_token&challenge=test_challenge",
                &router
            ),
            bad_request_error
        );
        assert_eq!(
            get(
                &format!(
                    "dnsconfig?token={}&challenge=abcdefghijklmnopqrstuvwxyz\
                     abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
                    token
                ),
                &router
            ),
            bad_request_error
        );
        assert_eq!(
            get(
                &format!("dnsconfig?token={}&challenge=test_challenge", token),
                &router
            ),
            empty_ok
        );

        // Tests for the pdns endpoint.

        // Bogus payload.
        assert_eq!(put("pdns", r#"{"foo": true}"#, &router), bad_request_error);

        // Unsupported method.
        assert_eq!(
            put(
                "pdns",
                r#"{"method":"dummy", "parameters":{"qtype":"a","qname":"b"}}"#,
                &router
            ),
            (r#"{"result":false}"#.to_owned(), status::Ok)
        );

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
        assert_eq!(
            put("pdns", &body, &router),
            (r#"{"result":[]}"#.to_owned(), status::Ok)
        );

        // Test the "remote" dns name.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some("test.mydomain.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success = "{\"result\":[{\"qtype\":\"A\",\"qname\":\"test.mydomain.org.\",\
                       \"content\":\"1.2.3.4\",\"ttl\":89}]}";
        assert_eq!(
            put("pdns", &body, &router),
            (success.to_owned(), status::Ok)
        );

        // Test LE challenge queries.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("TXT".to_owned()),
                qname: Some("_acme-challenge.test.mydomain.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success = "{\"result\":[{\"qtype\":\"TXT\",\
                       \"qname\":\"_acme-challenge.test.mydomain.org.\",\
                       \"content\":\"test_challenge\",\
                       \"ttl\":89}]}";
        assert_eq!(
            put("pdns", &body, &router),
            (success.to_owned(), status::Ok)
        );

        // Test SOA queries.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("SOA".to_owned()),
                qname: Some("test.mydomain.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success = "{\"result\":[{\"qtype\":\"SOA\",\"qname\":\"test.mydomain.org.\",\
                       \"content\":\
                       \"a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800\",\
                       \"ttl\":89}]}";
        assert_eq!(
            put("pdns", &body, &router),
            (success.to_owned(), status::Ok)
        );

        // Test ANY queries.
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("ANY".to_owned()),
                qname: Some("test.mydomain.org.".to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();

        let success = "{\"result\":[{\"qtype\":\"MX\",\"qname\":\"test.mydomain.org.\",\
                       \"content\":\"\",\"ttl\":89},\
                       {\"qtype\":\"A\",\"qname\":\"test.mydomain.org.\",\
                       \"content\":\"1.2.3.4\",\"ttl\":89},\
                       {\"qtype\":\"TXT\",\"qname\":\"test.mydomain.org.\",\
                       \"content\":\"test_challenge\",\"ttl\":89},\
                       {\"qtype\":\"CAA\",\"qname\":\"test.mydomain.org.\",\
                       \"content\":\"0 issue \\\"letsencrypt.org\\\"\",\"ttl\":89}]}";
        assert_eq!(
            put("pdns", &body, &router),
            (success.to_owned(), status::Ok)
        );

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
            #[serde(rename = "scopeMask")]
            scope_mask: Option<String>,
            #[allow(dead_code)]
            auth: Option<String>,
        }
        #[derive(Deserialize)]
        struct PdnsResponse {
            result: Vec<PdnsLookupResponse>,
        }

        // A request with a bogus domain.
        let qname = "dd7251eef7c773a192feb06c0e07ac6020ac.tc730a6b9e2f28f407bb3871e98d3fe4e60c.\
                     625558ecb0d283a5b058ba88fb3d9aa11d48.https-4443.fabrice.mydomain.org.mydomain.\
                     org.";
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some(qname.to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();
        let result = put("pdns", &body, &router);
        assert_eq!(result.1, status::Ok);
        let response: PdnsResponse = serde_json::from_str(&result.0).unwrap();
        // 255.255.255.0 Means "no such name found for pagekite"
        assert_eq!(response.result[0].content, "255.255.255.0");

        // A request with a correct domain.
        let qname = "dd7251eef7c773a192feb06c0e07ac6020ac.tc730a6b9e2f28f407bb3871e98d3fe4e60c.\
                     625558ecb0d283a5b058ba88fb3d9aa11d48.https-4443.test.mydomain.org.mydomain.\
                     org.";
        let pdns_request = PdnsRequest {
            method: "lookup".to_owned(),
            parameters: PdnsRequestParameters {
                qtype: Some("A".to_owned()),
                qname: Some(qname.to_owned()),
            },
        };
        let body = serde_json::to_string(&pdns_request).unwrap();
        let result = put("pdns", &body, &router);
        assert_eq!(result.1, status::Ok);
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
        assert_eq!(result.1, status::Ok);
        let response: PdnsResponse = serde_json::from_str(&result.0).unwrap();
        assert_eq!(
            response.result[0].content,
            "a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800"
        );

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
        assert_eq!(result.1, status::Ok);
        assert_eq!(result.0, r#"{"result":false}"#);

        // Email routes tests
        // 1. set an email address
        assert_eq!(get("setemail", &router), bad_request_error);
        assert_eq!(
            get("setemail?token=wrong_token", &router),
            bad_request_error
        );
        assert_eq!(
            get("setemail?token=wrong_token&email=me@example.com", &router),
            bad_request_error
        );
        assert_eq!(
            get(
                &format!("setemail?token={}&email=not_an_email", token),
                &router
            ),
            bad_request_error
        );
        assert_eq!(
            get(
                &format!(
                    "setemail?token={}&email=abc@{}com",
                    token,
                    std::iter::repeat("makeasuperlongfakedomain.")
                        .take(10)
                        .collect::<String>()
                ),
                &router
            ),
            bad_request_error
        );
        assert_eq!(
            get(
                &format!("setemail?token={}&email={}", token, email),
                &router
            ),
            empty_ok
        );
        let record = conn.get_domain_by_token(&token).unwrap();
        let account = conn.get_account_by_id(record.account_id).unwrap();
        assert_eq!(account.email, email);
        assert!(!record.verified);
        let link = record.verification_token;

        // 2. verify the email
        assert_eq!(get("verifyemail", &router), bad_request_error);
        assert_eq!(
            get("verifyemail?s=wrong_link", &router),
            (config.options.email.error_page.unwrap(), status::Ok)
        );
        assert_eq!(
            get(&format!("verifyemail?s={}", link), &router),
            (config.options.email.success_page.unwrap(), status::Ok)
        );

        // 3. check that the email has been set on the domain record.
        let domain_record = conn.get_domain_by_token(&token).unwrap();
        assert!(domain_record.verified);

        // 3a. Before revoking, finish testing domain reclamation.
        assert_eq!(
            get(&format!("subscribe?name=test&email={}", email), &router),
            (
                r#"{"error": "UnavailableNameReclamationPossible"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(get("reclaim?name=test", &router), empty_ok);
        let domain_record = conn.get_domain_by_token(&token).unwrap();
        let res = get("subscribe?name=test&reclamationToken=wrongtoken", &router);
        assert_eq!(
            res,
            (
                r#"{"error": "ReclamationTokenMismatch"}"#.to_owned(),
                status::BadRequest
            )
        );
        let res = get(
            &format!(
                "subscribe?name=test&reclamationToken={}",
                &domain_record.reclamation_token
            ),
            &router,
        );
        let registration: NameAndToken = serde_json::from_str(&res.0).unwrap();
        let token = registration.token;
        assert_eq!(registration.name, "test".to_owned());

        // 4. email revocation
        assert_eq!(get("revokeemail", &router), bad_request_error);
        assert_eq!(
            get("revokeemail?token=wrong_token", &router),
            bad_request_error
        );
        assert_eq!(
            get(&format!("revokeemail?token={}", token), &router),
            empty_ok
        );

        // 5. Verify the verification link is empty.
        let record = conn.get_domain_by_token(&token).unwrap();
        assert_eq!(record.verification_token, "");
        assert!(!record.verified);
    }
}
