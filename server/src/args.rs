// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use clap::{App, ArgMatches};
use config::{Args, EmailOptions, GeneralOptions, PdnsOptions};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use toml;

const USAGE: &'static str = "--config-file=[path]     'Path to a toml configuration file.'
--data-directory=[dir]   'The directory where the persistent data will be saved.'
--host=[host]            'Set local hostname.'
--port=[port]            'Set port to listen on for http connections.'
--cert-directory=[dir]   'Certificate directory.'
--domain=[domain]        'The domain that will be tied to this registration server.'
--dns-ttl=[ttl]          'TTL of the DNS records, in seconds.'
--eviction-delay=[secs]  'How often we purge old records.'
--tunnel-ip=[ip]         'The ip address of the tunnel endpoint.'
--soa-content=[dns]      'The content of the SOA record for this tunnel.'
--socket-path=[path]     'The path to the socket used to communicate with PowerDNS'
--email-server=[name]    'The name of the smpt server'
--email-user=[username]  'The username to authenticate with'
--email-password=[pass]  'The password for this email account'
--email-sender=[email]   'The email identity to use as a sender'
--confirmation-title=[s] 'The title of the confirmation email'
--confirmation-body=[s]  'The body of the confirmation email'
--success-page=[s]       'HTML content of the email confirmation success page'
--error-page=[s]         'HTML content of the email confirmation error page'";

const DEFAULT_EVICTION_DELAY: u32 = 120; // In seconds.

pub struct ArgsParser;

impl ArgsParser {
    fn from_file(path: &PathBuf) -> Args {
        let mut file = File::open(path).expect("Can't open config file");
        let mut source = String::new();
        file.read_to_string(&mut source)
            .expect("Unable to read config file");
        toml::from_str(&source).expect("Invalid config file")
    }

    fn from_matches(matches: ArgMatches) -> Args {
        if matches.is_present("config-file") {
            return ArgsParser::from_file(&PathBuf::from(matches.value_of("config-file").unwrap()));
        }

        macro_rules! optional {
            ($var:ident, $name:expr) => (
                let $var = if matches.is_present($name) {
                    Some(matches.value_of($name).unwrap().to_owned())
                } else {
                    None
                };
            )
        }

        optional!(cert_dir, "cert-directory");
        let cert_directory = match cert_dir {
            Some(dir) => Some(PathBuf::from(dir)),
            None => None,
        };

        optional!(email_server, "email-server");
        optional!(email_user, "email-user");
        optional!(email_password, "email-password");
        optional!(email_sender, "email-sender");
        optional!(confirmation_title, "confirmation-title");
        optional!(confirmation_body, "confirmation-body");
        optional!(success_page, "success-page");
        optional!(error_page, "error-page");

        Args {
            general: GeneralOptions {
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
                eviction_delay: value_t!(matches, "eviction-delay", u32)
                    .unwrap_or(DEFAULT_EVICTION_DELAY),
            },
            pdns: PdnsOptions {
                soa_content: matches
                    .value_of("soa-content")
                    .unwrap_or("_soa_not_configured_")
                    .to_owned(),
                socket_path: matches.value_of("soa-content").map(|s| s.to_owned()),
                dns_ttl: value_t!(matches, "dns-ttl", u32).unwrap_or(60),
            },
            email: EmailOptions {
                server: email_server,
                user: email_user,
                password: email_password,
                sender: email_sender,
                confirmation_title: confirmation_title,
                confirmation_body: confirmation_body,
                success_page: success_page,
                error_page: error_page,
            },
        }
    }

    // Gets the args from the default command line.
    pub fn from_env() -> Args {
        ArgsParser::from_matches(App::new("registration_server")
                                     .args_from_usage(USAGE)
                                     .get_matches())
    }

    // Gets the args from a string array.
    #[cfg(test)]
    pub fn from_vec(params: Vec<&str>) -> Args {
        ArgsParser::from_matches(App::new("registration_server")
                                     .args_from_usage(USAGE)
                                     .get_matches_from(params))
    }
}

#[test]
fn test_args() {
    let args = ArgsParser::from_vec(vec!["registration_server", "--tunnel-ip=1.2.3.4"]);

    assert_eq!(args.general.port, 4242);
    assert_eq!(args.general.host, "0.0.0.0");
    assert_eq!(args.general.domain, "knilxof.org");
    assert_eq!(args.general.cert_directory, None);
    assert_eq!(args.general.tunnel_ip, "1.2.3.4");
    assert_eq!(args.pdns.dns_ttl, 60);
    assert_eq!(args.general.eviction_delay, DEFAULT_EVICTION_DELAY);
    assert_eq!(args.pdns.socket_path, None);

    let args = ArgsParser::from_vec(vec!["registration_server",
                                         "--host=127.0.1.1",
                                         "--port=4343",
                                         "--domain=example.com",
                                         "--cert-directory=/tmp/certs",
                                         "--dns-ttl=120",
                                         "--tunnel-ip=1.2.3.4",
                                         "--eviction-delay=60"]);

    assert_eq!(args.general.port, 4343);
    assert_eq!(args.general.host, "127.0.1.1");
    assert_eq!(args.general.domain, "example.com");
    assert_eq!(args.general.cert_directory,
               Some(PathBuf::from("/tmp/certs")));
    assert_eq!(args.general.tunnel_ip, "1.2.3.4");
    assert_eq!(args.pdns.dns_ttl, 120);
    assert_eq!(args.general.eviction_delay, 60);
    assert_eq!(args.pdns.socket_path, None);

    let soa = "a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800";
    let args = ArgsParser::from_vec(vec!["registration_server",
                                         "--config-file=./config.toml.sample"]);
    assert_eq!(args.general.port, 4141);
    assert_eq!(args.general.host, "127.0.1.1");
    assert_eq!(args.general.domain, "knilxof.org");
    assert_eq!(args.general.cert_directory, None);
    assert_eq!(args.general.tunnel_ip, "1.2.3.4");
    assert_eq!(args.pdns.dns_ttl, 89);
    assert_eq!(args.general.eviction_delay, 2);
    assert_eq!(args.pdns.soa_content, soa);
    assert_eq!(args.pdns.socket_path,
               Some("/tmp/powerdns_tunnel.sock".to_owned()));
}
