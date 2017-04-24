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
extern crate env_logger;
extern crate hyper_openssl;
#[macro_use]
extern crate iron;
extern crate iron_cors;
#[macro_use]
extern crate log;
extern crate mount;
extern crate params;
extern crate r2d2;
extern crate r2d2_sqlite;
extern crate redis;
extern crate router;
extern crate rusqlite;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

use clap::{App, ArgMatches};
use hyper_openssl::OpensslServer;
use iron::{Chain, Iron};
use iron::method::Method;
use iron_cors::CORS;
use mount::Mount;
use std::path::PathBuf;

mod config;
mod domain_store;
mod errors;
mod eviction;
mod pdns;
mod routes;

use domain_store::DomainDb;

const USAGE: &'static str = "--host=[host]           'Set local hostname.'
--port=[port]           'Set port to listen on for http connections.'
--cert-directory=[dir]  'Certificate directory.'
--domain=[domain]       'The domain that will be tied to this registration server.'
--dns-ttl=[ttl]         'TTL of the DNS records, in seconds.'
--eviction-delay=[secs] 'How often we purge old records.'
--tunnel-ip=<ip>        'The ip address of the tunnel endpoint'";

const DEFAULT_EVICTION_DELAY: u32 = 120; // In seconds.

struct Args {
    host: String,
    port: u16,
    cert_directory: Option<PathBuf>,
    domain: String,
    tunnel_ip: String,
    dns_ttl: u32,
    eviction_delay: u32,
}

impl Args {
    fn from_matches(matches: ArgMatches) -> Self {
        let cert_directory = if matches.is_present("cert-directory") {
            Some(PathBuf::from(matches.value_of("cert-directory").unwrap()))
        } else {
            None
        };

        Args {
            host: matches.value_of("host").unwrap_or("0.0.0.0").to_owned(),
            port: value_t!(matches, "port", u16).unwrap_or(4242),
            cert_directory: cert_directory,
            domain: matches
                .value_of("domain")
                .unwrap_or("knilxof.org")
                .to_owned(),
            tunnel_ip: matches
                .value_of("tunnel-ip")
                .unwrap_or("0.0.0.0")
                .to_owned(),
            dns_ttl: value_t!(matches, "dns-ttl", u32).unwrap_or(60),
            eviction_delay: value_t!(matches, "eviction-delay", u32)
                .unwrap_or(DEFAULT_EVICTION_DELAY),
        }
    }

    // Gets the args from the default command line.
    fn new() -> Self {
        Args::from_matches(App::new("registration_server")
                               .args_from_usage(USAGE)
                               .get_matches())
    }

    // Gets the args from a string array.
    fn from(params: Vec<&str>) -> Self {
        Args::from_matches(App::new("registration_server")
                               .args_from_usage(USAGE)
                               .get_matches_from(params))
    }
}

fn main() {
    env_logger::init().unwrap();

    let args = Args::new();

    info!("Managing the domain {}", args.domain);

    let config = config::Config {
        domain_db: DomainDb::new("domains.sqlite"),
        domain: args.domain,
        tunnel_ip: args.tunnel_ip,
        dns_ttl: args.dns_ttl,
        eviction_delay: args.eviction_delay,
    };

    eviction::evict_old_entries(&config);

    let mut mount = Mount::new();
    mount.mount("/", routes::create(&config));

    let mut chain = Chain::new(mount);
    let cors = CORS::new(vec![(vec![Method::Get], "ping".to_owned()),
                              (vec![Method::Get], "subscribe".to_owned()),
                              (vec![Method::Get], "unsubscribe".to_owned()),
                              (vec![Method::Get], "register".to_owned())]);
    chain.link_after(cors);

    let iron = Iron::new(chain);
    info!("Starting server on {}:{}", args.host, args.port);
    let addr = format!("{}:{}", args.host, args.port);

    if args.cert_directory.is_none() {
        iron.http(addr.as_ref() as &str).unwrap();
    } else {
        info!("Starting TLS server");
        let certificate_directory = args.cert_directory.unwrap();

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
    let args = Args::from(vec!["registration_server", "--tunnel-ip=1.2.3.4"]);

    assert_eq!(args.port, 4242);
    assert_eq!(args.host, "0.0.0.0");
    assert_eq!(args.domain, "knilxof.org");
    assert_eq!(args.cert_directory, None);
    assert_eq!(args.tunnel_ip, "1.2.3.4");
    assert_eq!(args.dns_ttl, 60);
    assert_eq!(args.eviction_delay, DEFAULT_EVICTION_DELAY);

    let args = Args::from(vec!["registration_server",
                               "--host=127.0.1.1",
                               "--port=4343",
                               "--domain=example.com",
                               "--cert-directory=/tmp/certs",
                               "--dns-ttl=120",
                               "--tunnel-ip=1.2.3.4",
                               "--eviction-delay=60"]);

    assert_eq!(args.port, 4343);
    assert_eq!(args.host, "127.0.1.1");
    assert_eq!(args.domain, "example.com");
    assert_eq!(args.cert_directory, Some(PathBuf::from("/tmp/certs")));
    assert_eq!(args.tunnel_ip, "1.2.3.4");
    assert_eq!(args.dns_ttl, 120);
    assert_eq!(args.eviction_delay, 60);

}
