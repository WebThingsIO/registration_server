// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use actix_rt;
use actix_web::{middleware, App, HttpServer};
use log::info;

use registration_server::args::ArgsParser;
use registration_server::config::Config;
use registration_server::pdns;
use registration_server::routes::*;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = ArgsParser::from_env();

    let addr = format!("{}:{}", args.general.host, args.general.http_port);

    info!("Managing the domain {}", args.general.domain);
    info!("Starting HTTP server on {}", addr);
    HttpServer::new(move || {
        let config = Config::from_args(args.clone());

        pdns::start_socket_endpoint(&config);

        App::new()
            .data(config)
            .wrap(
                middleware::DefaultHeaders::new()
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Methods", "GET, OPTIONS"),
            )
            .service(connectivity_check)
            .service(ping)
            .service(info)
            .service(subscribe)
            .service(reclaim)
            .service(unsubscribe)
            .service(dns_config)
            .service(set_email)
            .service(revoke_email)
            .service(verify_email)
    })
    .bind(addr)?
    .run()
    .await
}
