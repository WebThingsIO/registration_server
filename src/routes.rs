/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use db::{ Db, FindFilter, Record };
use iron::headers::{ AccessControlAllowOrigin, ContentType };
use iron::prelude::*;
use iron::status::Status;
use params::{ Map, Params, Value };
use router::Router;
use std::error::Error;
use std::fmt::{self, Debug};

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

pub fn create() -> Router {
    let mut router = Router::new();
    router.get("register", move |req: &mut Request| -> IronResult<Response> {
        // Get the local ip from the query, and the public one from the socket.
        let public_ip = format!("{}", req.remote_addr.ip());

        let map: &Map = req.get_ref::<Params>().unwrap();
        let ip_param = match map.find(&["ip"]) {
            Some(&Value::String(ref name)) => Some(name),
            _ => None
        };

        if ip_param == None {
            return Err(IronError::new(StringError("Error".to_string()), Status::BadRequest));
        }
        let local_ip = ip_param.unwrap().to_string();

        // Get the current number of seconds since epoch.
        let now = Db::seconds_from_epoch();

        info!("GET /register public_ip={} local_ip={} time is {}",
              public_ip, local_ip, now);

        // Save this registration in the database.
        // If we already have the same (local, public) tuple, update it, if not
        // create a new tuple.
        let db = Db::new();
        match db.find(FindFilter::PublicAndLocalIp(public_ip.clone(), local_ip.clone())) {
            Ok(rvect) => {
                // If the vector is empty, create a new record, if not update
                // the existing one with the new timestamp.
                let record = Record {
                    public_ip: public_ip,
                    local_ip: local_ip,
                    timestamp: now,
                };

                if rvect.is_empty() {
                    db.add(record).unwrap();
                } else {
                    db.update(record).unwrap();
                }
            },
            Err(_) => {
                let record = Record {
                    public_ip: public_ip,
                    local_ip: local_ip,
                    timestamp: now,
                };
                db.add(record).unwrap();
            }
        }

        let mut response = Response::with("{\"status\" : \"registered\"}");
        response.status = Some(Status::Ok);
        response.headers.set(AccessControlAllowOrigin::Any);
        response.headers.set(ContentType::json());

        Ok(response)
    });

    router.get("ping", move |req: &mut Request| -> IronResult<Response> {
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
                    serialized.push_str(&record.to_json());
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
    });

    router
}