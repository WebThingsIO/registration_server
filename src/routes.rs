// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use db::{Db, Record};
use errors::*;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status::{self, Status};
use router::Router;
use rustc_serialize::json;
use std::io::Read;

fn register(req: &mut Request,
            db_host: String,
            db_port: u16,
            db_password: Option<String>)
            -> IronResult<Response> {
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
    let db = Db::new(db_host, db_port, db_password);

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

fn ping(req: &mut Request,
        db_host: String,
        db_port: u16,
        db_password: Option<String>)
        -> IronResult<Response> {
    info!("GET /ping");
    let public_ip = format!("{}", req.remote_addr.ip());

    let mut serialized = String::from("[");

    let db = Db::new(db_host, db_port, db_password);
    match db.get(public_ip.clone()) {
        Ok(rvect) => {
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
        Err(_) => {}
    };

    serialized.push_str("]");
    let mut response = Response::with(serialized);
    response.status = Some(Status::Ok);
    response.headers.set(ContentType::json());

    Ok(response)
}

pub fn create(db_host: String, db_port: u16, db_password: Option<String>) -> Router {
    let mut router = Router::new();

    let host = db_host.clone();
    let pass = db_password.clone();
    router.post("register",
                move |req: &mut Request| -> IronResult<Response> {
                    register(req, host.clone(), db_port, pass.clone())
                },
                "post_message");

    let host = db_host.clone();
    let pass = db_password.clone();
    router.get("ping",
               move |req: &mut Request| -> IronResult<Response> {
                   ping(req, host.clone(), db_port, pass.clone())
               },
               "ping");

    router
}
