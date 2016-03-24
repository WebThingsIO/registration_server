/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use db::{ Db, FindFilter, Record };
use errors::*;
use iron::headers::{ AccessControlAllowOrigin, ContentType };
use iron::prelude::*;
use iron::status::{ self, Status };
use router::Router;
use rustc_serialize::json;
use std::error::Error;
use std::fmt::{ self, Debug };
use std::io::Read;

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for StringError {
    fn description(&self) -> &str { &*self.0 }
}

fn register(req: &mut Request) -> IronResult<Response> {
   // Get the local IP and optional tunnel url from the body,
    #[derive(RustcDecodable, Debug)]
    struct RegisterBody {
        client:  String,
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

    let message   = body.message;
    let client_id = body.client;

    // And the public IP from the socket.
    let public_ip = format!("{}", req.remote_addr.ip());

    // Get the current number of seconds since epoch.
    let now = Db::seconds_from_epoch();

    info!("POST /register public_ip={} client={} message={} time is {}",
          public_ip, client_id, message, now);

    // Save this registration in the database.
    // If we already have the same (local, tunnel, public) match, update it,
    // if not create a new match.
    let db = Db::new();
    match db.find(
        FindFilter::PublicIpAndClient(public_ip.clone(), client_id.clone())
    ) {
        Ok(rvect) => {
            // If the vector is empty, create a new record, if not update
            // the existing one with the new timestamp.
            let record = Record {
                public_ip: public_ip,
                client:  client_id,
                message: message,
                timestamp: now,
            };

            let result = if rvect.is_empty() {
                db.add(record)
            } else {
                db.update(record)
            };

            if let Err(_) = result {
                return EndpointError::with(status::InternalServerError, 501)
            }
        },
        Err(_) => {
            let record = Record {
                public_ip: public_ip,
                client: client_id,
                message: message,
                timestamp: now,
            };
            if let Err(e) = db.add(record) {
                error!("Error {}", e);
                return EndpointError::with(status::InternalServerError, 501)
            }
        }
    }

    let mut response = Response::with("{\"status\" : \"registered\"}");
    response.status = Some(Status::Ok);
    response.headers.set(AccessControlAllowOrigin::Any);
    response.headers.set(ContentType::json());

    Ok(response)
}

fn ping(req: &mut Request) -> IronResult<Response> {
    info!("GET /ping");
    let public_ip = format!("{}", req.remote_addr.ip());

    let mut serialized = String::from("[");

    let db = Db::new();
    match db.find(FindFilter::PublicIp(public_ip)) {
        Ok(rvect) => {
            // Serialize the vector.
            let max = rvect.len();
            let mut index = 0;
            for record in rvect {
                match json::encode(&record) {
                    Ok(ref record) => serialized.push_str(record),
                    Err(_) => {
                        return EndpointError::with(status::InternalServerError, 501)
                    }
                }

                index += 1;
                if index < max {
                    serialized.push_str(",");
                }
            }
        },
        Err(_) => { }
    }

    serialized.push_str("]");
    let mut response = Response::with(serialized);
    response.status = Some(Status::Ok);
    response.headers.set(AccessControlAllowOrigin::Any);
    response.headers.set(ContentType::json());

    Ok(response)
}

pub fn create() -> Router {
    let mut router = Router::new();

    router.post("register", register);
    router.get("ping", ping);

    router
}
