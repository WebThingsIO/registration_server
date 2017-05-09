// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use config::Config;
use domain_store::{DomainError, DomainRecord};
use errors::*;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status::{self, Status};
use params::{FromValue, Params, Value};
use pdns::pdns_endpoint;
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
    match config
              .domain_db
              .get_record_by_token(&token)
              .recv()
              .unwrap() {
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

            let new_record = DomainRecord::new(&record.name,
                                               &record.token,
                                               dns_challenge,
                                               Some(&local_ip),
                                               Some(&public_ip),
                                               timestamp);
            match config
                      .domain_db
                      .update_record(new_record)
                      .recv()
                      .unwrap() {
                Ok(()) => {
                    // Everything went fine, return an empty 200 OK for now.
                    let mut response = Response::new();
                    response.status = Some(Status::Ok);

                    Ok(response)
                }
                Err(_) => EndpointError::with(status::InternalServerError, 501),
            }
        }
        Err(DomainError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

fn ping(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /ping");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);
    if token.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }
    let token = String::from_value(token.unwrap()).unwrap();

    match config
              .domain_db
              .get_record_by_token(&token)
              .recv()
              .unwrap() {
        Ok(record) => {
            let mut response = Response::with(serde_json::to_string(&record).unwrap());
            response.headers.set(ContentType::json());
            Ok(response)
        }
        Err(DomainError::NoRecord) => EndpointError::with(status::BadRequest, 400),
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
              .domain_db
              .delete_record_by_token(&token)
              .recv()
              .unwrap() {
        Ok(0) => EndpointError::with(status::BadRequest, 400), // No record found for this token.
        Ok(_) => {
            let mut response = Response::new();
            response.status = Some(Status::Ok);

            Ok(response)
        }
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
                .domain_db
                .get_record_by_name(&full_name)
                .recv()
                .unwrap();
            match record {
                Ok(_) => {
                    // We already have a record for this name, return an error.
                    let mut response = Response::with("{\"error\": \"UnavailableName\"}");
                    response.status = Some(Status::BadRequest);
                    response.headers.set(ContentType::json());
                    Ok(response)
                }
                Err(DomainError::NoRecord) => {
                    // Create a token, create and store a record and finally return the token.
                    let token = format!("{}", Uuid::new_v4());
                    let record = DomainRecord::new(&full_name, &token, None, None, None, 0);
                    match config.domain_db.add_record(record).recv().unwrap() {
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
                            match serde_json::to_string(&n_and_t) {
                                Ok(serialized) => {
                                    let mut response = Response::with(serialized);
                                    response.status = Some(Status::Ok);
                                    response.headers.set(ContentType::json());

                                    Ok(response)
                                }
                                Err(_) => EndpointError::with(status::InternalServerError, 501)
                            }
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

fn dns_config(req: &mut Request, config: &Config) -> IronResult<Response> {
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
    match config
              .domain_db
              .get_record_by_token(&token)
              .recv()
              .unwrap() {
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

            let new_record = DomainRecord::new(&record.name,
                                               &record.token,
                                               Some(&challenge),
                                               local_ip,
                                               public_ip,
                                               record.timestamp);
            match config
                      .domain_db
                      .update_record(new_record)
                      .recv()
                      .unwrap() {
                Ok(()) => {
                    // Everything went fine, return an empty 200 OK for now.
                    let mut response = Response::new();
                    response.status = Some(Status::Ok);

                    Ok(response)
                }
                Err(_) => EndpointError::with(status::InternalServerError, 501),
            }
        }
        Err(DomainError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

pub fn create(config: &Config) -> Router {
    let mut router = Router::new();

    let config_ = config.clone();
    router.get("register",
               move |req: &mut Request| -> IronResult<Response> { register(req, &config_) },
               "post_message");

    let config_ = config.clone();
    router.get("ping",
               move |req: &mut Request| -> IronResult<Response> { ping(req, &config_) },
               "ping");

    let config_ = config.clone();
    router.get("subscribe",
               move |req: &mut Request| -> IronResult<Response> { subscribe(req, &config_) },
               "subscribe");

    let config_ = config.clone();
    router.get("unsubscribe",
               move |req: &mut Request| -> IronResult<Response> { unsubscribe(req, &config_) },
               "unsubscribe");

    let config_ = config.clone();
    router.get("dnsconfig",
               move |req: &mut Request| -> IronResult<Response> { dns_config(req, &config_) },
               "dnsconfig");

    let config_ = config.clone();
    if config.socket_path.is_none() {
        router.post("pdns",
                    move |req: &mut Request| -> IronResult<Response> {
                        pdns_endpoint(req, &config_)
                    },
                    "pdns");
    }

    router
}
