// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Server that manages foxbox registrations.

extern crate env_logger;
extern crate hyper_native_tls;
extern crate iron;
#[macro_use]
extern crate log;
extern crate mount;
extern crate registration_server;

use hyper_native_tls::NativeTlsServer;
use iron::Iron;
use std::thread;

use registration_server::args::ArgsParser;
use registration_server::config::Config;
use registration_server::routes;
use registration_server::pdns;

fn main() {
    env_logger::init().unwrap();

    let args = ArgsParser::from_env();

    info!("Managing the domain {}", args.general.domain);

    let config = Config::from_args(args.clone());

    pdns::start_socket_endpoint(&config);

    let mut threads = Vec::new();

    if config.options.general.http_port != 0 {
        let cfg = config.clone();
        let addr = format!(
            "{}:{}",
            config.options.general.host, config.options.general.http_port
        );
        threads.push(thread::spawn(move || {
            let iron_server = Iron::new(routes::create_chain("/", &cfg));
            info!("Starting HTTP server on {}", addr);
            iron_server.http(addr.as_ref() as &str).unwrap();
        }));
    }

    if config.options.general.https_port != 0 {
        if config.options.general.identity_directory.is_none() {
            error!("Identity directory not set!");
        } else if config.options.general.identity_password.is_none() {
            error!("Identity password not set!");
        } else {
            let cfg = config.clone();
            let addr = format!(
                "{}:{}",
                config.options.general.host, config.options.general.https_port
            );
            let identity_directory = config.options.general.identity_directory.clone().unwrap();
            threads.push(thread::spawn(move || {
                let iron_server = Iron::new(routes::create_chain("/", &cfg));
                info!("Starting TLS server on {}", addr);

                let identity_password = config.options.general.identity_password.unwrap();
                let mut identity = identity_directory.clone();
                identity.push("identity.p12");

                info!("Using identity: '{:?}'", identity);
                let ssl = NativeTlsServer::new(identity, &identity_password).unwrap();
                iron_server.https(addr.as_ref() as &str, ssl).unwrap();
            }));
        }
    }

    while let Some(t) = threads.pop() {
        let _ = t.join();
    }
}
