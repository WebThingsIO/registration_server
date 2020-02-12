// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate env_logger;
extern crate iron;
#[macro_use]
extern crate log;
extern crate mount;
extern crate registration_server;

use iron::Iron;
use std::thread;

use registration_server::args::ArgsParser;
use registration_server::config::Config;
use registration_server::pdns;
use registration_server::routes;

fn main() {
    env_logger::init().unwrap();

    let args = ArgsParser::from_env();
    let config = Config::from_args(args.clone());

    info!("Managing the domain {}", args.general.domain);

    pdns::start_socket_endpoint(&config);

    let cfg = config.clone();
    let addr = format!(
        "{}:{}",
        config.options.general.host, config.options.general.http_port
    );
    let _ = thread::spawn(move || {
        let iron_server = Iron::new(routes::create_chain("/", &cfg));
        info!("Starting HTTP server on {}", addr);
        iron_server.http(addr.as_ref() as &str).unwrap();
    })
    .join();
}
