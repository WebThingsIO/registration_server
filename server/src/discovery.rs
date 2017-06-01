// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Discovery related routes.

use types::Discovered;
use config::Config;
use database::DatabaseError;
use errors::*;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status::{self, Status};
use params::{FromValue, Params};
use serde_json;

macro_rules! remove_last {
    ($obj:ident.$prop:ident) => (
        $obj.$prop[..$obj.$prop.len() - 1].to_owned()
    )
}

// Public ping endpoint, returning names of servers on the same
// local network than the client.
pub fn ping(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /ping");

    let remote_ip = format!("{}", req.remote_addr.ip());

    match config
              .db
              .get_records_by_public_ip(&remote_ip)
              .recv()
              .unwrap() {
        Ok(records) => {
            let results: Vec<Discovered> = records
                .into_iter()
                .map(|item| {
                         Discovered {
                             href: format!("https://{}", remove_last!(item.local_name)),
                             desc: item.description,
                         }
                     })
                .collect();

            json_response!(&results)
        }
        Err(DatabaseError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

pub fn adddiscovery(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /adddiscovery");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);
    let disco = map.find(&["disco"]);

    if token.is_none() || disco.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();
    let disco = String::from_value(disco.unwrap()).unwrap();

    match config.db.get_record_by_token(&token).recv().unwrap() {
        Ok(_) => {
            match config.db.add_discovery(&token, &disco).recv().unwrap() {
                Ok(()) => ok_response!(),
                Err(_) => EndpointError::with(status::BadRequest, 400),
            }
        }
        Err(DatabaseError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

pub fn revokediscovery(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /revokediscovery");

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let token = map.find(&["token"]);
    let disco = map.find(&["disco"]);

    if token.is_none() || disco.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let token = String::from_value(token.unwrap()).unwrap();
    let disco = String::from_value(disco.unwrap()).unwrap();

    match config.db.get_record_by_token(&token).recv().unwrap() {
        Ok(_) => {
            match config.db.delete_discovery(&disco).recv().unwrap() {
                Ok(_) => ok_response!(),
                Err(_) => EndpointError::with(status::BadRequest, 400),
            }
        }
        Err(DatabaseError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}

pub fn discovery(req: &mut Request, config: &Config) -> IronResult<Response> {
    info!("GET /discovery");

    let remote_ip = format!("{}", req.remote_addr.ip());

    let map = req.get_ref::<Params>().unwrap(); // TODO: don't unwrap.
    let disco = map.find(&["disco"]);

    if disco.is_none() {
        return EndpointError::with(status::BadRequest, 400);
    }

    let disco = String::from_value(disco.unwrap()).unwrap();

    match config.db.get_token_for_discovery(&disco).recv().unwrap() {
        Ok(token) => {
            match config
                      .db
                      .get_records_by_public_ip(&remote_ip)
                      .recv()
                      .unwrap() {
                Ok(records) => {
                    // Filter out and only return the records that matches the token.
                    let results: Vec<Discovered> = records
                        .into_iter()
                        .filter(|item| item.token == token)
                        .map(|item| {
                                 Discovered {
                                     href: format!("https://{}", remove_last!(item.local_name)),
                                     desc: item.description,
                                 }
                             })
                        .collect();

                    if results.is_empty() {
                        // If the result vector is empty, return the remote name for this token.
                        match config.db.get_record_by_token(&token).recv().unwrap() {
                            Ok(record) => {
                                let result = vec![Discovered {
                                                      href:
                                                          format!("https://{}",
                                                                  remove_last!(record.remote_name)),
                                                      desc: record.description,
                                                  }];
                                json_response!(&result)
                            }
                            Err(_) => EndpointError::with(status::BadRequest, 400),
                        }
                    } else {
                        json_response!(&results)
                    }
                }
                Err(_) => EndpointError::with(status::BadRequest, 400),
            }
        }
        Err(DatabaseError::NoRecord) => EndpointError::with(status::BadRequest, 400),
        Err(_) => EndpointError::with(status::InternalServerError, 501),
    }
}
