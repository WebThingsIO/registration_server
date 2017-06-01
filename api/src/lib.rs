// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Types used by the REST api responses.

#[macro_use]
extern crate serde_derive;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub token: String,
    pub local_name: String,
    pub remote_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub timestamp: i64,
}

unsafe impl Send for ServerInfo {}
unsafe impl Sync for ServerInfo {}

#[derive(Debug, Deserialize, Serialize)]
pub struct NameAndToken {
    pub name: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Discovered {
    pub href: String,
    pub desc: String,
}
