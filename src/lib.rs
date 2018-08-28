// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#[macro_use]
extern crate clap;
extern crate crypto;
#[cfg(any(feature = "mysql", feature = "postgres", feature = "sqlite"))]
#[macro_use]
extern crate diesel;
extern crate email;
#[macro_use]
extern crate hyper;
extern crate iron;
extern crate iron_cors;
#[cfg(test)]
extern crate iron_test;
extern crate lettre;
extern crate lettre_email;
#[macro_use]
extern crate log;
extern crate maxminddb;
extern crate mount;
extern crate params;
extern crate r2d2;
#[cfg(any(feature = "mysql", feature = "postgres", feature = "sqlite"))]
extern crate r2d2_diesel;
extern crate regex;
extern crate router;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate toml;
extern crate uuid;

macro_rules! json_response {
    ($json:expr) => {{
        let mut response = Response::with(serde_json::to_string($json).unwrap());
        response.headers.set(ContentType::json());
        response.status = Some(Status::Ok);
        Ok(response)
    }};
}

macro_rules! html_response {
    ($html:expr) => {{
        let mut response = Response::with($html);
        response.headers.set(ContentType::html());
        response.status = Some(Status::Ok);
        Ok(response)
    }};
}

macro_rules! html_error_response {
    ($status:expr, $html:expr) => {{
        let mut response = Response::with($html);
        response.headers.set(ContentType::html());
        response.status = Some($status);
        Ok(response)
    }};
}

macro_rules! ok_response {
    () => {{
        let mut response = Response::new();
        response.status = Some(Status::Ok);
        Ok(response)
    }};
}

pub mod args;
pub mod config;
pub mod database;
pub mod email_routes;
pub mod errors;
pub mod models;
pub mod pdns;
pub mod routes;
pub mod schema;
