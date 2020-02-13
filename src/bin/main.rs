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

use registration_server::args::ArgsParser;
use registration_server::config::Config;
use registration_server::pdns;
use registration_server::routes;

fn main() {
    env_logger::init().unwrap();

    let args = ArgsParser::from_env();
    let config = Config::from_args(args);

    info!("Managing the domain {}", config.options.general.domain);

    pdns::start_socket_endpoint(&config);

    let addr = format!(
        "{}:{}",
        config.options.general.host, config.options.general.http_port
    );

    info!("Starting HTTP server on {}", addr);
    let _ = Iron::new(routes::create_chain("/", &config)).http(&addr);
}
