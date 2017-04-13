// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#[derive(Clone)]
pub struct Config {
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_pass: Option<String>,
}
