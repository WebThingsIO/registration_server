// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Types used by the REST api responses.

pub use database::DomainRecord as ServerInfo;

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
