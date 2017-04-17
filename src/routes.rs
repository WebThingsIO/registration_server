// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use config::Config;
use domain_store::{DomainError, DomainRecord};
use transient_store::{Db, Record};
use errors::*;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status::{self, Status};
use params::{Params, Value};
use pdns::pdns_endpoint;
use router::Router;
use rustc_serialize::json;
use std::io::Read;
use uuid::Uuid;

fn domain_for_name(name: &str, config: &Config) -> String {
    format!("{}.box.{}", name, config.domain)
}

fn register(req: &mut Request, config: &Config) -> IronResult<Response> {
    // Get the local IP and optional tunnel url from the body,
    #[derive(RustcDecodable, Debug)]
    struct RegisterBody {
        client: String,
        message: String,
    }

    let mut payload = String::new();
    req.body.read_to_string(&mut payload).unwrap();
    let body: RegisterBody = match json::decode(&payload) {
        Ok(body) => body,
        Err(error) => {
            error!("{:?}", error);
            return from_decoder_error(error);
        }
    };

    let message = body.message;
    let client_id = body.client;

    // And the public IP from the socket.
    let public_ip = format!("{}", req.remote_addr.ip());

    info!("POST /register public_ip={} client={} message={}",
          public_ip,
          client_id,
          message);

    // Save this registration in the database.
    // If we already have the same (local, tunnel, public) match, update it,
    // if not create a new match.
    let db = Db::new(config.redis_host.clone(),
                     config.redis_port,
                     config.redis_pass.clone());

    let record = Record {
        public_ip: public_ip.clone(),
        client: client_id.clone(),
        message: message.clone(),
    };

    if let Err(e) = db.set(record) {
        error!("{}", e);
        return EndpointError::with(status::InternalServerError, 501);
    }

    let mut response = Response::with("{\"status\" : \"registered\"}");
    response.status = Some(Status::Ok);
    response.headers.set(ContentType::json());

    Ok(response)
}

fn ping(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /ping");
    let public_ip = format!("{}", req.remote_addr.ip());

    let mut serialized = String::from("[");

    let db = Db::new(config.redis_host.clone(),
                     config.redis_port,
                     config.redis_pass.clone());
    if let Ok(rvect) = db.get(public_ip.clone()) {
        info!("Registrations {:?}", rvect);
        // Serialize the vector.
        let max = rvect.len();
        let mut index = 0;
        for record in rvect {
            match json::encode(&record) {
                Ok(ref record) => serialized.push_str(record),
                Err(_) => return EndpointError::with(status::InternalServerError, 501),
            }

            index += 1;
            if index < max {
                serialized.push_str(",");
            }
        }
    }

    serialized.push_str("]");
    let mut response = Response::with(serialized);
    response.status = Some(Status::Ok);
    response.headers.set(ContentType::json());

    Ok(response)
}

fn reserve(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /reserve");

    // Extract the name parameter.
    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    match map.find(&["name"]) {
        Some(&Value::String(ref name)) => {
            let full_name = domain_for_name(name, config);
            info!("trying to register {}", full_name);

            let record = config
                .domain_db
                .get_record_by_name(&full_name)
                .recv()
                .unwrap();
            match record {
                Ok(_) => {
                    // We already have a record for this name, return an error.
                    let mut response = Response::with("{\"error\": \"UnavailableName\"}");
                    response.status = Some(Status::Ok);
                    response.headers.set(ContentType::json());
                    Ok(response)
                }
                Err(DomainError::NoRecord) => {
                    // Create a token, create and store a record and finally return the token.
                    let token = format!("{}", Uuid::new_v4());
                    let record = DomainRecord::new(&full_name, &token, None);
                    match config.domain_db.add_record(record).recv().unwrap() {
                        Ok(()) => {
                            // We don't want the full domain name or the dns challenge in the response
                            // so we create a local struct.
                            #[derive(RustcEncodable)]
                            struct NameAndToken {
                                name: String,
                                token: String,
                            }
                            let n_and_t = NameAndToken {
                                name: name.to_owned(),
                                token: token,
                            };
                            match json::encode(&n_and_t) {
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
    use params::FromValue;

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
    match config.domain_db.get_record_by_token(&token).recv().unwrap() {
        Ok(record) => {
            // Update the record with the challenge.
            let new_record = DomainRecord::new(&record.name, &record.token, Some(&challenge));
            match config.domain_db.update_record(new_record).recv().unwrap() {
                Ok(()) => {
                    // Everything went fine, return an empty 200 OK for now.
                    let mut response = Response::new();
                    response.status = Some(Status::Ok);

                    Ok(response)
                },
                Err(_) => {
                    EndpointError::with(status::InternalServerError, 501)
                }
            }
        },
        Err(DomainError::NoRecord) => {
            EndpointError::with(status::BadRequest, 400)
        }
        Err(_) => {
            EndpointError::with(status::InternalServerError, 501)
        }
    }
}

pub fn create(config: &Config) -> Router {
    let mut router = Router::new();

    let config_ = config.clone();
    router.post("register",
                move |req: &mut Request| -> IronResult<Response> { register(req, &config_) },
                "post_message");

    let config_ = config.clone();
    router.get("ping",
               move |req: &mut Request| -> IronResult<Response> { ping(req, &config_) },
               "ping");

    let config_ = config.clone();
    router.get("reserve",
               move |req: &mut Request| -> IronResult<Response> { reserve(req, &config_) },
               "reserve");

    let config_ = config.clone();
    router.get("dnsconfig",
               move |req: &mut Request| -> IronResult<Response> { dns_config(req, &config_) },
               "dnsconfig");

    let config_ = config.clone();
    router.post("pdns",
               move |req: &mut Request| -> IronResult<Response> { pdns_endpoint(req, &config_) },
               "pdns");
    
    router
}
