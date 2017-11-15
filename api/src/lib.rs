// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Types used by the REST api responses.

#[macro_use]
extern crate serde_derive;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub account_id: i64,
    pub token: String,
    pub description: String,
    pub timestamp: i64,
    pub dns_challenge: String,
    pub reclamation_token: String,
    pub verification_token: String,
    pub verified: bool,
}

unsafe impl Send for ServerInfo {}
unsafe impl Sync for ServerInfo {}

#[derive(Debug, Deserialize, Serialize)]
pub struct NameAndToken {
    pub name: String,
    pub token: String,
}
