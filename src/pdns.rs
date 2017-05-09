// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Communication with the PowerDNS server happens through the http
// server.
// See https://doc.powerdns.com/md/authoritative/backend-remote/ for
// details about the various requests and responses.

use config::Config;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
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
pub struct PdnsLookupResponse {
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
pub enum PdnsResponseParams {
    Lookup(PdnsLookupResponse),
}

#[derive(Serialize)]
pub struct PdnsResponse {
    result: Vec<PdnsResponseParams>,
}

fn pdns_failure(reason: &str) -> IronResult<Response> {
    debug!("pdns_failure: {}", reason);
    let mut response = Response::with("{\"result\":false}");
    response.status = Some(Status::Ok);
    response.headers.set(ContentType::json());
    Ok(response)
}

pub fn pdns_response_as_iron(response: &PdnsResponse) -> IronResult<Response> {
    match serde_json::to_string(response) {
        Ok(serialized) => {
            debug!("Response is: {}", serialized);
            let mut response = Response::with(serialized);
            response.status = Some(Status::Ok);
            response.headers.set(ContentType::json());

            Ok(response)
        }
        Err(err) => {
            error!("{}", err);
            EndpointError::with(status::InternalServerError, 501)
        }
    }
}

// Returns a SOA record for a given qname.
pub fn soa_response(qname: &str, config: &Config) -> PdnsLookupResponse {
    PdnsLookupResponse {
        qtype: "SOA".to_owned(),
        qname: qname.to_owned(),
        content: config.soa_content.to_owned(),
        ttl: config.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    }
}

pub fn pakegite_query(qname: &str, qtype: &str, config: &Config) -> IronResult<Response> {
    // Pagekite sends dns requests to qnames like:
    // dd7251eef7c773a192feb06c0e07ac6020ac.tc730a6b9e2f28f407bb3871e98d3fe4e60c.625558ecb0d283a5b058ba88fb3d9aa11d48.https-4443.fabrice.box.knilxof.org.box.knilxof.org
    // See https://pagekite.net/wiki/Howto/DnsBasedAuthentication
    debug!("PageKite query for {} {}", qtype, qname);

    let mut pdns_response = PdnsResponse { result: Vec::new() };

    if qtype == "SOA" {
        pdns_response
            .result
            .push(PdnsResponseParams::Lookup(soa_response(qname, config)));
        return pdns_response_as_iron(&pdns_response);
    }

    if qtype != "A" && qtype != "ANY" {
        return pdns_failure(&format!("Unsupported PageKite request type: {}", qtype));
    }

    // Split up the qname.
    let parts: Vec<&str> = qname.split('.').collect();
    let subdomain = format!("{}.box.{}.", parts[4], config.domain);
    let ip = match config
              .domain_db
              .get_record_by_name(&subdomain)
              .recv()
              .unwrap() {
        Ok(record) => {
            let srand = parts[0];
            let token = parts[1];
            let sign = parts[2];
            let proto = parts[3];
            let kite_domain = format!("{}.box.{}", parts[4], config.domain);
            let payload = format!("{}:{}:{}:{}", proto, kite_domain, srand, token);
            let salt = sign[..8].to_owned();

            debug!("{} {} {} {} {}", srand, token, sign, proto, kite_domain);

            let mut hasher = Sha1::new();
            hasher.input_str(&format!("{}{}{}", record.token, payload, salt));
            let calc = hasher.result_str();

            let calc_sub = calc[..28].to_owned();
            let sign_sub = sign[8..36].to_owned();

            debug!("Signatures: {} {}", calc_sub, sign_sub);

            if calc_sub == sign_sub {
                "255.255.254.255"
            } else {
                "255.255.255.1"
            }
        }
        Err(_) => {
            // Return 255.255.255.0 to PageKite to indicate failure.
            "255.255.255.0"
        }
    };

    let ns_record = PdnsLookupResponse {
        qtype: "A".to_owned(),
        qname: qname.to_owned(),
        content: ip.to_owned(),
        ttl: config.dns_ttl,
        domain_id: None,
        scope_mask: None,
        auth: None,
    };
    pdns_response
        .result
        .push(PdnsResponseParams::Lookup(ns_record));

    pdns_response_as_iron(&pdns_response)
}

pub fn pdns_endpoint(req: &mut Request, config: &Config) -> IronResult<Response> {
    use std::net::SocketAddr::V4;
    use std::net::Ipv4Addr;

    info!("GET /pdns");
    // Only allow clients from localhost.
    match req.remote_addr {
        V4(addr) => {
            if addr.ip() != &Ipv4Addr::new(127, 0, 0, 1) {
                return EndpointError::with(status::BadRequest, 400);
            }
        }
        _ => return EndpointError::with(status::BadRequest, 400),
    }

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
        let original_qname = input.parameters.qname.unwrap().to_lowercase();
        let mut qname = original_qname.clone();
        let qtype = input.parameters.qtype.unwrap();
        debug!("lookup for qtype={} qname={}", qtype, original_qname);

        // Example payload:
        //
        // {"method": "lookup",
        //  "parameters": {"local": "0.0.0.0",
        //                 "qname": "fabrice.box.knilxof.org.",
        //                 "qtype": "SOA",
        //                 "real-remote": "63.245.221.198/32",
        //                 "remote": "63.245.221.198",
        //                 "zone-id": -1}}

        // If the qname ends up with .box.$domain.box.$domain. we consider that it's a
        // PageKite request and process it separately.
        if qname.ends_with(&format!(".box.{}.box.{}.", config.domain, config.domain)) {
            return pakegite_query(&qname, &qtype, config);
        }

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
                if record.local_ip.is_none() && qtype == "A" {
                    // No info on this domain, bail out.
                    return pdns_failure("No local_ip");
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
                    pdns_response
                        .result
                        .push(PdnsResponseParams::Lookup(soa_response(&original_qname, config)));
                }

                if qtype == "ANY" || qtype == "A" {
                    // Add an "A" record.
                    let ns_record = PdnsLookupResponse {
                        qtype: "A".to_owned(),
                        qname: original_qname.to_owned(),
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
                        qtype: "TXT".to_owned(),
                        qname: original_qname.to_owned(),
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

                return pdns_response_as_iron(&pdns_response);
            }
            Err(_) => {
                // No such domain, return a `false` result to PowerDNS.
                return pdns_failure("No record for this name.");
            }
        }
    }

    pdns_failure(&format!("Unsupported method: {}", input.method))
}
