// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use clap::{App, ArgMatches};
use config::Config;
use database::Database;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use toml;

const USAGE: &'static str = "--config-file=[path]    'Path to a toml configuration file.'
--data-directory=[dir]  'The directory where the persistent data will be saved.'
--host=[host]           'Set local hostname.'
--port=[port]           'Set port to listen on for http connections.'
--cert-directory=[dir]  'Certificate directory.'
--domain=[domain]       'The domain that will be tied to this registration server.'
--dns-ttl=[ttl]         'TTL of the DNS records, in seconds.'
--eviction-delay=[secs] 'How often we purge old records.'
--tunnel-ip=[ip]        'The ip address of the tunnel endpoint.'
--soa-content=[dns]     'The content of the SOA record for this tunnel.'
--socket-path=[path]    'The path to the socket used to communicate with PowerDNS'";

const DEFAULT_EVICTION_DELAY: u32 = 120; // In seconds.

#[derive(Deserialize)]
pub struct Args {
    pub host: String,
    pub port: u16,
    pub data_directory: String,
    pub cert_directory: Option<PathBuf>,
    pub domain: String,
    tunnel_ip: String,
    soa_content: String,
    socket_path: Option<String>,
    dns_ttl: u32,
    eviction_delay: u32,
}

impl Args {
    fn from_file(path: &PathBuf) -> Self {
        let mut file = File::open(path).expect("Can't open config file");
        let mut source = String::new();
        file.read_to_string(&mut source)
            .expect("Unable to read config file");
        toml::from_str(&source).expect("Invalid config file")
    }

    fn from_matches(matches: ArgMatches) -> Self {
        if matches.is_present("config-file") {
            return Args::from_file(&PathBuf::from(matches.value_of("config-file").unwrap()));
        }

        let cert_directory = if matches.is_present("cert-directory") {
            Some(PathBuf::from(matches.value_of("cert-directory").unwrap()))
        } else {
            None
        };

        Args {
            host: matches.value_of("host").unwrap_or("0.0.0.0").to_owned(),
            port: value_t!(matches, "port", u16).unwrap_or(4242),
            cert_directory: cert_directory,
            data_directory: String::from(matches.value_of("data-directory").unwrap_or(".")),
            domain: matches
                .value_of("domain")
                .unwrap_or("knilxof.org")
                .to_owned(),
            tunnel_ip: matches
                .value_of("tunnel-ip")
                .unwrap_or("0.0.0.0")
                .to_owned(),
            soa_content: matches
                .value_of("soa-content")
                .unwrap_or("_soa_not_configured_")
                .to_owned(),
            socket_path: matches.value_of("soa-content").map(|s| s.to_owned()),
            dns_ttl: value_t!(matches, "dns-ttl", u32).unwrap_or(60),
            eviction_delay: value_t!(matches, "eviction-delay", u32)
                .unwrap_or(DEFAULT_EVICTION_DELAY),
        }
    }

    // Gets the args from the default command line.
    pub fn new() -> Self {
        Args::from_matches(App::new("registration_server")
                               .args_from_usage(USAGE)
                               .get_matches())
    }

    // Gets the args from a string array.
    pub fn from(params: Vec<&str>) -> Self {
        Args::from_matches(App::new("registration_server")
                               .args_from_usage(USAGE)
                               .get_matches_from(params))
    }

    pub fn to_config(&self) -> Config {
        Config {
            db: Database::new(&format!("{}/domains.sqlite", self.data_directory)),
            domain: self.domain.clone(),
            tunnel_ip: self.tunnel_ip.clone(),
            dns_ttl: self.dns_ttl,
            eviction_delay: self.eviction_delay,
            soa_content: self.soa_content.clone(),
            socket_path: self.socket_path.clone(),
        }
    }
}

#[test]
fn test_args() {
    let args = Args::from(vec!["registration_server", "--tunnel-ip=1.2.3.4"]);

    assert_eq!(args.port, 4242);
    assert_eq!(args.host, "0.0.0.0");
    assert_eq!(args.domain, "knilxof.org");
    assert_eq!(args.cert_directory, None);
    assert_eq!(args.tunnel_ip, "1.2.3.4");
    assert_eq!(args.dns_ttl, 60);
    assert_eq!(args.eviction_delay, DEFAULT_EVICTION_DELAY);
    assert_eq!(args.socket_path, None);

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
    assert_eq!(args.socket_path, None);

    let soa = "a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800";
    let args = Args::from(vec!["registration_server", "--config-file=./config.toml.sample"]);
    assert_eq!(args.port, 4141);
    assert_eq!(args.host, "127.0.1.1");
    assert_eq!(args.domain, "box.knilxof.org");
    assert_eq!(args.cert_directory, None);
    assert_eq!(args.tunnel_ip, "1.2.3.4");
    assert_eq!(args.dns_ttl, 89);
    assert_eq!(args.eviction_delay, 123);
    assert_eq!(args.soa_content, soa);
    assert_eq!(args.socket_path,
               Some("/tmp/powerdns_tunnel.sock".to_owned()));
}
