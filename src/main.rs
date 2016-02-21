/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(time2)]

/// Simple server that manages foxbox registrations.
/// Two end points are available:
/// /register?ip=$local_ip to register a public IP with a local one.
/// /ping to get the list of local ip matching the current public one.
///
/// Boxes are supposed to register themselves at regular intervals so we
/// discard data which is too old periodically.

extern crate env_logger;
extern crate iron;
#[macro_use]
extern crate log;
extern crate mount;
extern crate params;
extern crate router;

use db::Db;
use iron::Iron;
use mount::Mount;

mod db;
mod routes;
mod eviction;

fn main() {
    env_logger::init().unwrap();

    Db::new();

    eviction::start();

    let mut mount = Mount::new();
    mount.mount("/", routes::create());

    // TODO: add a command line flag to set host:port.
    info!("Starting server on 0.0.0.0:4242");
    Iron::new(mount).http("0.0.0.0:4242").unwrap();
}

// TODO: add iron tests.
