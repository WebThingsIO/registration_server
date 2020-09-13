// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde_derive;
extern crate std;

pub mod args;
pub mod config;
pub mod constants;
pub mod database;
pub mod email;
pub mod models;
pub mod pdns;
pub mod routes;
pub mod schema;
