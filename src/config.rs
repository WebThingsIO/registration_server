// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use database::Database;

#[derive(Clone)]
pub struct Config {
    pub db: Database,
    pub domain: String,
    pub tunnel_ip: String,
    pub dns_ttl: u32,
    pub eviction_delay: u32,
    pub soa_content: String,
    pub socket_path: Option<String>,
    pub email_server: Option<String>,
    pub email_user: Option<String>,
    pub email_password: Option<String>,
    pub email_sender: Option<String>,
}

impl Config {
    #[cfg(test)]
    pub fn with_db(&mut self, db: Database) -> &mut Self {
        self.db = db;
        self
    }
}
