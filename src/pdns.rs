// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Communication with the PowerDNS server happens through the http
// server.
// See https://doc.powerdns.com/md/authoritative/backend-remote/ for
// details about the various requests and responses.

use config::Config;
use errors::*;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status::{self, Status};
use serde_json;
use std::io::Read;

#[derive(Deserialize)]
struct PdnsRequestParameters {
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
struct PdnsRequest {
    method: String,
    parameters: PdnsRequestParameters,
}

#[derive(Serialize)]
struct PdnsLookupResponse {
    qtype: String,
    qname: String,
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_id: Option<String>,
    #[serde(rename="scopeMask")]
    #[serde(skip_serializing_if = "Option::is_none")]
    scope_mask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PdnsResponseParams {
    Lookup(PdnsLookupResponse),
}

#[derive(Serialize)]
struct PdnsResponse {
    result: Vec<PdnsResponseParams>,
}

fn pdns_failure() -> IronResult<Response> {
    let mut response = Response::with("{\"result\":false}");
    response.status = Some(Status::Ok);
    response.headers.set(ContentType::json());
    Ok(response)
}

pub fn pdns_endpoint(req: &mut Request, config: &Config) -> IronResult<Response> {
    // TODO: check where the request is coming from and only allow from pdns.

    // Read the request from the json body.
    let mut s = String::new();
    itry!(req.body.read_to_string(&mut s));

    debug!("Body is: {}", s);

    let input: PdnsRequest = match serde_json::from_str(&s) {
        Ok(value) => value,
        Err(err) => {
            error!("Bad request: {}", err);
            return EndpointError::with(status::BadRequest, 400);
        }
    };

    debug!("pdns request is {}", input.method);

    if input.method == "lookup" {
        let mut qname = input.parameters.qname.unwrap();
        let qtype = input.parameters.qtype.unwrap();
        debug!("lookup for qtype={} qname={}", qtype, qname);

        // Example payload:
        //
        // {"method": "lookup",
        //  "parameters": {"local": "0.0.0.0",
        //                 "qname": "fabrice.box.knilxof.org.",
        //                 "qtype": "SOA",
        //                 "real-remote": "63.245.221.198/32",
        //                 "remote": "63.245.221.198",
        //                 "zone-id": -1}}

        // If the qname starts with `_acme-challenge.` this is a DNS-01 challenge verification,
        // so remove that part of the domain to retrieve our record.
        // See https://tools.ietf.org/html/draft-ietf-acme-acme-06#section-8.4
        if qname.starts_with("_acme-challenge.") {
            qname = qname[16..].to_owned();
        }
        debug!("final qname={}", qname);

        // Look for a record with for the qname.
        match config
                  .domain_db
                  .get_record_by_name(&qname)
                  .recv()
                  .unwrap() {
            Ok(record) => {
                if record.local_ip.is_none() {
                    // No info on this domain, bail out.
                    return pdns_failure();
                }

                // Choose either the local or public ip based on the parameters.remote one.
                let a_record = if record.public_ip.is_some() &&
                                  input.parameters.remote.unwrap() == record.public_ip.unwrap() {
                    // We are inside of the home network, return the local ip for the A record.
                    record.local_ip.unwrap()
                } else {
                    // We are outside of the home network, return the ip of the tunnel
                    // for the A record.
                    config.tunnel_ip.to_owned()
                };

                let mut pdns_response = PdnsResponse { result: Vec::new() };

                if qtype == "SOA" {
                    // Add a "SOA" record.
                    // TODO: don't hardcode the content of this record!
                    let ns_record = PdnsLookupResponse {
                        qtype: "SOA".to_owned(),
                        qname: qname.to_owned(),
                        content: "a.dns.gandi.net hostmaster.gandi.net 1476196782 \
                                  10800 3600 604800 10800"
                                .to_owned(),
                        ttl: config.dns_ttl,
                        domain_id: None,
                        scope_mask: None,
                        auth: None,
                    };
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(ns_record));
                }

                if qtype == "ANY" || qtype == "A" {
                    // Add an "A" record.
                    let ns_record = PdnsLookupResponse {
                        qtype: "A".to_owned(),
                        qname: qname.to_owned(),
                        content: a_record,
                        ttl: config.dns_ttl,
                        domain_id: None,
                        scope_mask: None,
                        auth: None,
                    };
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(ns_record));
                }

                if (qtype == "ANY" || qtype == "TXT") && record.dns_challenge.is_some() {
                    // Add a "TXT" record with the dns challenge content.
                    let ns_record = PdnsLookupResponse {
                        qtype: "A".to_owned(),
                        qname: qname.to_owned(),
                        content: record.dns_challenge.unwrap(),
                        ttl: config.dns_ttl,
                        domain_id: None,
                        scope_mask: None,
                        auth: None,
                    };
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(ns_record));
                }

                match serde_json::to_string(&pdns_response) {
                    Ok(serialized) => {
                        debug!("{}", serialized);
                        let mut response = Response::with(serialized);
                        response.status = Some(Status::Ok);
                        response.headers.set(ContentType::json());

                        return Ok(response);
                    }
                    Err(_) => return EndpointError::with(status::InternalServerError, 501),
                }
            }
            Err(_) => {
                // No such domain, return a `false` result to PowerDNS.
                return pdns_failure();
            }
        }
    }

    pdns_failure()
}
