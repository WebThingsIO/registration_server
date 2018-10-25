// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate env_logger;
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
use pdns::lookup_continent;
use regex::Regex;
use router::Router;
use serde_json;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

header! { (XRealIP, "X-Real-IP") => [IpAddr] }

#[derive(Debug, Deserialize, Serialize)]
pub struct NameAndToken {
    pub name: String,
    pub token: String,
}

fn domain_for_name(name: &str, config: &Config) -> String {
    format!("{}.{}.", name, config.options.general.domain).to_lowercase()
}

fn ping(req: &mut Request, config: &Config) -> IronResult<Response> {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "ping(): Failed to get database connection: {:?}",
            conn.err()
        );
        return EndpointError::with(status::InternalServerError, 500);
    }
    let conn = conn.unwrap();

    // Extract the token parameter.
    let map = req.get_ref::<Params>().unwrap();
    let token = map.find(&["token"]);

    info!("GET /ping {:?}", map);

    if token.is_none() {
        error!("ping(): Token not provided");
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();

    // Save this ping in the database if we know about this token.
    match conn.update_domain_timestamp(&token) {
        Ok(count) if count > 0 => ok_response!(),
        Ok(_) => EndpointError::with(status::NotFound, 404),
        Err(err) => {
            error!("ping(): Failed to update domain: {:?}", err);
            EndpointError::with(status::InternalServerError, 500)
        }
    }
}

fn info(req: &mut Request, config: &Config) -> IronResult<Response> {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "info(): Failed to get database connection: {:?}",
            conn.err()
        );
        return EndpointError::with(status::InternalServerError, 500);
    }
    let conn = conn.unwrap();

    let map = req.get_ref::<Params>().unwrap();
    let token = map.find(&["token"]);

    info!("GET /info {:?}", map);

    if token.is_none() {
        error!("info(): Token not provided");
        return EndpointError::with(status::BadRequest, 400);
    }
    let token = String::from_value(token.unwrap()).unwrap();

    match conn.get_domain_by_token(&token) {
        Ok(record) => json_response!(&record),
        Err(diesel::result::Error::NotFound) => EndpointError::with(status::NotFound, 404),
        Err(err) => {
            error!("info(): Failed to get domain: {:?}", err);
            EndpointError::with(status::InternalServerError, 500)
        }
    }
}

fn unsubscribe(req: &mut Request, config: &Config) -> IronResult<Response> {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "unsubscribe(): Failed to get database connection: {:?}",
            conn.err()
        );
        return EndpointError::with(status::InternalServerError, 500);
    }
    let conn = conn.unwrap();

    let map = req.get_ref::<Params>().unwrap();
    let token = map.find(&["token"]);

    info!("GET /unsubscribe {:?}", map);

    if token.is_none() {
        let reclamation_token = map.find(&["reclamationToken"]);
        match reclamation_token {
            Some(&Value::String(ref reclamation_token)) => {
                return match conn.delete_domain_by_reclamation_token(reclamation_token) {
                    Ok(0) => {
                        // No record found for this token.
                        EndpointError::with(status::NotFound, 404)
                    }
                    Ok(_) => ok_response!(),
                    Err(err) => {
                        error!("unsubscribe(): Failed to delete domain: {:?}", err);
                        EndpointError::with(status::InternalServerError, 500)
                    }
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
        Err(err) => {
            error!("unsubscribe(): Failed to delete domain: {:?}", err);
            EndpointError::with(status::InternalServerError, 500)
        }
    }
}

fn reclaim(req: &mut Request, config: &Config) -> IronResult<Response> {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "reclaim(): Failed to get database connection: {:?}",
            conn.err()
        );
        return EndpointError::with(status::InternalServerError, 500);
    }
    let conn = conn.unwrap();

    let map = req.get_ref::<Params>().unwrap();
    let name = map.find(&["name"]);

    info!("GET /reclaim {:?}", map);

    if name.is_none() {
        error!("reclaim(): Name not provided");
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
                    if result.is_err() {
                        error!("reclaim(): Failed to update domain: {:?}", result.err());
                        return EndpointError::with(status::InternalServerError, 500);
                    }

                    if result.unwrap() == 0 {
                        return EndpointError::with(status::NotFound, 404);
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
                                Err(err) => {
                                    error!("reclaim(): Failed to send email: {:?}", err);
                                    EndpointError::with(status::InternalServerError, 500)
                                }
                            }
                        }
                        Err(err) => {
                            error!("reclaim(): Failed to create email sender: {:?}", err);
                            EndpointError::with(status::InternalServerError, 500)
                        }
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
        Err(err) => {
            error!("reclaim(): Failed to look up domain: {:?}", err);
            EndpointError::with(status::InternalServerError, 500)
        }
    }
}

fn subscribe(req: &mut Request, config: &Config) -> IronResult<Response> {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "subscribe(): Failed to get database connection: {:?}",
            conn.err()
        );
        return EndpointError::with(status::InternalServerError, 500);
    }
    let conn = conn.unwrap();

    let real_ip = match req.headers.get::<XRealIP>() {
        Some(x) => x.0.clone(),
        None => req.remote_addr.ip(),
    };

    let continent = match lookup_continent(real_ip, &config) {
        Some(val) => val,
        None => "".to_owned(),
    };

    // Extract the name parameter.
    let map = req.get_ref::<Params>().unwrap();
    let name = map.find(&["name"]);

    info!("GET /subscribe {:?}", map);

    if name.is_none() {
        error!("subscribe(): Name not provided");
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
    let ns_regex = Regex::new(r"^ns\d*$").unwrap();
    if !re.is_match(&subdomain)
        || ns_regex.is_match(&subdomain)
        || subdomain == "api"
        || subdomain == "www"
        || subdomain == "_psl"
        || subdomain.len() > 63
        || full_name.len() > 253
    {
        let mut response = Response::with(r#"{"error": "UnavailableName"}"#);
        response.status = Some(status::BadRequest);
        response.headers.set(ContentType::json());
        return Ok(response);
    }

    info!("subscribe(): Trying to subscribe: {}", full_name);

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
                    match conn.update_domain_token(&record.name, &token, &continent) {
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
                        Ok(_) => EndpointError::with(status::NotFound, 404),
                        Err(err) => {
                            error!("subscribe(): Failed to update domain: {:?}", err);
                            EndpointError::with(status::InternalServerError, 500)
                        }
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
                error!(
                    "subscribe(): Failed to get the unknown account: {:?}",
                    result.err()
                );
                return EndpointError::with(status::InternalServerError, 500);
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
                &continent,
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
                Err(err) => {
                    error!("subscribe(): Failed to add domain: {:?}", err);
                    EndpointError::with(status::InternalServerError, 500)
                }
            }
        }
        // Other error, like a db issue.
        Err(err) => {
            error!("subscribe(): Failed to look up domain: {:?}", err);
            EndpointError::with(status::InternalServerError, 500)
        }
    }
}

fn dnsconfig(req: &mut Request, config: &Config) -> IronResult<Response> {
    let conn = config.db.get_connection();
    if conn.is_err() {
        error!(
            "dnsconfig(): Failed to get database connection: {:?}",
            conn.err()
        );
        return EndpointError::with(status::InternalServerError, 500);
    }
    let conn = conn.unwrap();

    // Extract the challenge and token parameter.
    let map = req.get_ref::<Params>().unwrap();
    let challenge = map.find(&["challenge"]);
    let token = map.find(&["token"]);

    info!("GET /dnsconfig {:?}", map);

    // Both parameters are mandatory.
    if challenge.is_none() || token.is_none() {
        error!("dnsconfig(): Challenge or token not provided");
        return EndpointError::with(status::BadRequest, 400);
    }

    let challenge = String::from_value(challenge.unwrap()).unwrap();
    if challenge.len() > 63 {
        error!("dnsconfig(): Invalid challenge: {}", challenge);
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();

    match conn.update_domain_dns_challenge(&token, &challenge) {
        Ok(count) if count > 0 => ok_response!(),
        Ok(_) => EndpointError::with(status::NotFound, 404),
        Err(err) => {
            error!("dnsconfig(): Failed to update domain: {:?}", err);
            EndpointError::with(status::InternalServerError, 500)
        }
    }
}

pub fn create_router(config: &Config) -> Router {
    let mut router = Router::new();

    macro_rules! handler {
        ($name:ident) => {
            let config_ = config.clone();
            router.get(
                stringify!($name),
                move |req: &mut Request| -> IronResult<Response> { $name(req, &config_) },
                stringify!($name),
            );
        };
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
    use self::hyper::buffer::BufReader;
    use self::hyper::net::NetworkStream;
    use super::*;
    use args::ArgsParser;
    use config::Config;
    use database::DatabasePool;
    use hyper;
    use iron;
    use iron::method;
    use iron::status::Status;
    use iron::{Handler, Url};
    use iron_test::mock_stream::MockStream;
    use iron_test::response;
    use models::Domain;
    use std;
    use std::io::Cursor;
    use std::thread::sleep;
    use std::time;

    fn get(path: &str, router: &Router) -> (String, Status) {
        let resp = match request(method::Method::Get, path, "", router) {
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
        let _ = env_logger::init();

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
        let not_found_error = (
            r#"{"code":404,"errno":404,"error":"Not Found"}"#.to_owned(),
            status::NotFound,
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
            get("subscribe?name=ns", &router),
            (
                r#"{"error": "UnavailableName"}"#.to_owned(),
                status::BadRequest
            )
        );
        assert_eq!(
            get("subscribe?name=ns123", &router),
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
                status::BadRequest,
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
        assert_eq!(get("ping?token=wrong_token", &router), not_found_error);

        // Ping properly.
        sleep(time::Duration::from_secs(1));
        assert_eq!(get(&format!("ping?token={}", token), &router), empty_ok);

        // Get the full info
        assert_eq!(get("info", &router), bad_request_error);
        assert_eq!(get("info?token=wrong_token", &router), not_found_error);

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
            not_found_error
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

        // Email routes tests
        // 1. set an email address
        assert_eq!(get("setemail", &router), bad_request_error);
        assert_eq!(
            get("setemail?token=wrong_token", &router),
            bad_request_error
        );
        assert_eq!(
            get("setemail?token=wrong_token&email=me@example.com", &router),
            not_found_error
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
                &format!("setemail?token={}&email={}&optout=1", token, email),
                &router
            ),
            empty_ok
        );
        let record = conn.get_domain_by_token(&token).unwrap();
        let account = conn.get_account_by_id(record.account_id).unwrap();
        assert_eq!(account.email, email);
        assert_eq!(account.optout, true);
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
        assert_eq!(account.optout, false);
        assert!(!record.verified);
        let link = record.verification_token;

        // 2. verify the email
        assert_eq!(get("verifyemail", &router), bad_request_error);
        assert_eq!(
            get("verifyemail?s=wrong_link", &router),
            (config.options.email.error_page.unwrap(), status::NotFound)
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
                status::BadRequest,
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
            not_found_error
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
