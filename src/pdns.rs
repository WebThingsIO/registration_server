// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Communication with the PowerDNS server happens through the http
// server.
// See https://doc.powerdns.com/md/authoritative/backend-remote/ for 
// details about the various requests and response.

use config::Config;
use domain_store::{DomainError, DomainRecord};
use errors::*;
use iron::method::Method;
use iron::prelude::*;
use iron::status::{self, Status};
use serde_json::from_str;
use std::io::Read;

#[derive(Deserialize)]
pub struct PdnsRequestParameters {
    // intialize method
    path: Option<String>,
    timeout: Option<String>,

    // lookup method
    qtype: Option<String>,
    qname: Option<String>,
    #[serde(rename="zone-id")]
    zone_id: Option<i32>,
    remote: Option<String>,
    local: Option<String>,
    real_remote: Option<String>,
}

#[derive(Deserialize)]
pub struct PdnsRequest {
    method: String,
    parameters: PdnsRequestParameters,
}

pub fn pdns_endpoint(req: &mut Request, config: &Config) -> IronResult<Response> {
    // TODO: check where the request is coming from and only allow from pdns.

    // Read the request from the json body.
    let mut s = String::new();
    itry!(req.body.read_to_string(&mut s));

    println!("Body is: {}", s);

    let input: PdnsRequest = match from_str(&s) {
        Ok(value) => value,
        Err(err) => {
            error!("Bad request: {}", err);
            return EndpointError::with(status::BadRequest, 400)
        }
    };

    println!("pdns request is {}", input.method);

    EndpointError::with(status::InternalServerError, 501)
}
