// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// Simple server that manages foxbox registrations.
/// Two end points are available:
/// POST /register => to register a match between public IP and mesage.
/// GET /ping => to get the list of public IP matches.
///
/// Boxes are supposed to register themselves at regular intervals so we
/// discard data which is too old periodically.
#[macro_use]
extern crate clap;
extern crate crypto;
extern crate email;
#[macro_use]
extern crate iron;
extern crate iron_cors;
#[cfg(test)]
extern crate iron_test;
extern crate lettre;
#[macro_use]
extern crate log;
extern crate mount;
extern crate params;
extern crate registration_types as types;
extern crate r2d2;
extern crate r2d2_sqlite;
extern crate router;
extern crate rusqlite;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate toml;
extern crate uuid;

macro_rules! json_response {
    ($json:expr) => (
        {
            let mut response = Response::with(serde_json::to_string($json).unwrap());
            response.headers.set(ContentType::json());
            response.status = Some(Status::Ok);
            Ok(response)
        }
    )
}

macro_rules! html_response {
    ($html:expr) => (
        {
            let mut response = Response::with($html);
            response.headers.set(ContentType::html());
            response.status = Some(Status::Ok);
            Ok(response)
        }
    )
}

macro_rules! ok_response {
    () => (
        {
            let mut response = Response::new();
            response.status = Some(Status::Ok);
            Ok(response)
        }
    )
}

pub mod args;
pub mod config;
pub mod database;
pub mod discovery;
pub mod email_routes;
pub mod errors;
pub mod eviction;
pub mod pdns;
pub mod routes;
