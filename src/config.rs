// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use domain_store::DomainDb;

#[derive(Clone)]
pub struct Config {
    pub domain_db: DomainDb,
    pub domain: String,
    pub tunnel_ip: String,
    pub dns_ttl: u32,
    pub eviction_delay: u32,
    pub soa_content: String,
    pub socket_path: String,
}
