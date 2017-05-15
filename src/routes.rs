// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use config::Config;
use database::{DatabaseError, DomainRecord};
use discovery::{adddiscovery, discovery, ping, revokediscovery};
use errors::*;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status::{self, Status};
use params::{FromValue, Params, Value};
use pdns::pdns;
use router::Router;
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn domain_for_name(name: &str, config: &Config) -> String {
    format!("{}.box.{}.", name, config.domain).to_lowercase()
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

    match config
              .db
              .delete_record_by_token(&token)
              .recv()
              .unwrap() {
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

            let record = config
                .db
                .get_record_by_name(&full_name)
                .recv()
                .unwrap();
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
                            #[derive(Serialize)]
                            struct NameAndToken {
                                name: String,
                                token: String,
                            }
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

pub fn create(config: &Config) -> Router {
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

    if config.socket_path.is_none() {
        handler!(pdns);
    }

    router
}

#[cfg(test)]
mod tests {
    use super::*;
    use args::Args;
    use database::DomainRecord;
    use iron::{Handler, Headers};
    use iron::status::Status;
    use iron_test::{request, response};

    macro_rules! test_handler {
        ($name:ident, $proxy:ident) => (
            fn $name(req: &mut Request) -> IronResult<Response> {
                let args = Args::from(vec!["registration_server",
                                           "--config-file=./config.toml.test"]);
                let config = args.to_config();
                $proxy(req, &config)
            }
        )
    }

    fn get_response<H: Handler>(path: &str, handler: &H) -> Response {
        match request::get(&format!("http://localhost:3000/{}", path),
                           Headers::new(),
                           handler) {
            Ok(response) => response,
            Err(err) => err.response,
        }
    }

    fn get<H: Handler>(path: &str, handler: &H) -> (String, Status) {
        let resp = get_response(path, handler);
        let status = resp.status.unwrap();
        (response::extract_body_to_string(resp), status)
    }

    #[test]
    fn test_router() {
        let args = Args::from(vec!["registration_server", "--config-file=./config.toml.test"]);

        let config = args.to_config();
        config
            .db
            .flush()
            .recv()
            .unwrap()
            .expect("Flushing the db");

        test_handler!(test_subscribe, subscribe);
        test_handler!(test_register, register);
        test_handler!(test_ping, ping);
        test_handler!(test_info, info);

        // Nothing is registered yet.
        assert_eq!(get("ping", &test_ping), ("[]".to_owned(), Status::Ok));

        #[derive(Deserialize)]
        struct NameAndToken {
            pub name: String,
            pub token: String,
        }

        // Register a test user.
        let resp = get("subscribe?name=test", &test_subscribe);
        let registration: NameAndToken = serde_json::from_str(&resp.0).unwrap();
        let token = registration.token;

        let bad_request_error = r#"{"code":400,"errno":400,"error":"Bad Request"}"#.to_owned();

        assert_eq!(registration.name, "test".to_owned());

        // Fail to register twice the same user.
        let res = get_response("subscribe?name=test", &test_subscribe);
        assert_eq!(res.status, Some(Status::BadRequest));
        assert_eq!(response::extract_body_to_string(res),
                   r#"{"error": "UnavailableName"}"#.to_owned());

        // Register without the expected parameters.
        assert_eq!(get("register", &test_register),
                   (bad_request_error.clone(), Status::BadRequest));
        assert_eq!(get("register?name=test", &test_register),
                   (bad_request_error.clone(), Status::BadRequest));
        assert_eq!(get(&format!("register?token={}", token), &test_register),
                   (bad_request_error.clone(), Status::BadRequest));
        assert_eq!(get("register?local_ip=10.0.0.1&token=wrong_token",
                       &test_register),
                   (bad_request_error.clone(), Status::BadRequest));

        // Register properly.
        assert_eq!(get(&format!("register?local_ip=10.0.0.1&token={}", token),
                       &test_register),
                   ("".to_owned(), Status::Ok));

        // Now retrieve our registered client.
        assert_eq!(get("ping", &test_ping),
        (r#"[{"href":"https://local.test.box.box.knilxof.org","desc":"test's server"}]"#
                            .to_owned(), Status::Ok));

        // Get the full info
        assert_eq!(get("info", &test_info),
                   (bad_request_error.clone(), Status::BadRequest));
        assert_eq!(get("info?token=wrong_token", &test_info),
                   (bad_request_error.clone(), Status::BadRequest));

        let response = get(&format!("info?token={}", token), &test_info);
        assert_eq!(response.1, Status::Ok);
        let record: DomainRecord = serde_json::from_str(&response.0).unwrap();
        assert_eq!(record.token, token);
        assert_eq!(record.local_name, "local.test.box.box.knilxof.org.".to_owned());
        assert_eq!(record.remote_name, "test.box.box.knilxof.org.");
        assert_eq!(record.local_ip, Some("10.0.0.1".to_owned()));
        assert_eq!(record.public_ip, Some("127.0.0.1".to_owned()));
        assert_eq!(record.description, r#"test's server"#);

    }
}
