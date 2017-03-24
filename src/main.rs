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

extern crate docopt;
extern crate env_logger;
extern crate hyper_openssl;
extern crate iron;
extern crate iron_cors;
#[macro_use]
extern crate log;
extern crate mount;
extern crate params;
extern crate redis;
extern crate router;
extern crate rustc_serialize;

use docopt::Docopt;
use hyper_openssl::OpensslServer;
use iron::{Chain, Iron};
use iron::method::Method;
use iron_cors::CORS;
use mount::Mount;
use std::path::PathBuf;

mod errors;
mod db;
mod routes;

#[cfg(test)]
mod db_test_context;

const USAGE: &'static str =
    "
Usage: registration_server [-d <db-hostname>] [--db-port <db-port>] [--db-pass <db-pass>] \
     [-h <hostname>] [-p <port>] [--cert-directory <dir>]

Options:
    -d, --db-host <host>          \
     Set Redis database hostname.
        --db-port <db-port>       Set Redis database port.
        \
     --db-pass <db-pass>       Set Redis database password.
    -h, --host <host>             Set \
     local hostname.
    -p, --port <port>             Set port to listen on for http \
     connections.
        --cert-directory <dir>    Certificate directory.
";


#[derive(RustcDecodable)]
struct Args {
    flag_db_host: Option<String>,
    flag_db_port: Option<u16>,
    flag_db_pass: Option<String>,
    flag_host: Option<String>,
    flag_port: Option<u16>,
    flag_cert_directory: Option<String>,
}


fn main() {
    env_logger::init().unwrap();

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    let port = args.flag_port.unwrap_or(4242);
    let host = args.flag_host.unwrap_or("0.0.0.0".to_string());
    let using_tls = args.flag_cert_directory.is_some();
    let db_host = args.flag_db_host.unwrap_or("localhost".to_string());
    let db_port = args.flag_db_port.unwrap_or(6379);
    let db_pass = args.flag_db_pass;

    info!("Redis server on {}:{}", db_host, db_port);

    let mut mount = Mount::new();
    mount.mount("/",
                routes::create(db_host.clone(), db_port, db_pass.clone()));

    let mut chain = Chain::new(mount);
    let cors = CORS::new(vec![
        (vec![Method::Get], "ping".to_owned()),
        (vec![Method::Post], "register".to_owned()),
    ]);
    chain.link_after(cors);

    let iron = Iron::new(chain);
    info!("Starting server on {}:{}", host, port);
    let addr = format!("{}:{}", host, port);

    if !using_tls {
        iron.http(addr.as_ref() as &str)
            .unwrap();
    } else {
        info!("Starting TLS server");
        let certificate_directory = args.flag_cert_directory.unwrap();
        let certificate_directory = PathBuf::from(certificate_directory);

        let mut private_key = certificate_directory.clone();
        private_key.push("privkey.pem");

        let mut cert = certificate_directory.clone();
        cert.push("fullchain.pem");

        info!("Using cert: '{:?}' pk: '{:?}'", cert, private_key);
        let ssl = OpensslServer::from_files(private_key, cert).unwrap();
        iron.https(addr.as_ref() as &str, ssl).unwrap();
    }
}

// TODO: add iron tests.

#[test]
fn options_are_good() {
    // short form options
    {
        let argv = || vec!["registration_server", "-p", "1234", "-h", "foobar"];

        let args: Args = Docopt::new(USAGE)
            .and_then(|d| d.argv(argv().into_iter()).decode())
            .unwrap();

        assert_eq!(args.flag_host, Some("foobar".to_string()));
        assert_eq!(args.flag_port, Some(1234));
    }
}
