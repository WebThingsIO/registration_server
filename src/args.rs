// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::config::Args;
use clap::{App, Arg, ArgMatches};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use toml;

pub struct ArgsParser;

impl ArgsParser {
    fn from_file(path: &PathBuf) -> Args {
        let mut file = File::open(path).expect("Can't open config file");
        let mut source = String::new();
        file.read_to_string(&mut source)
            .expect("Unable to read config file");
        toml::from_str(&source).expect("Invalid config file")
    }

    fn from_matches(matches: &ArgMatches) -> Args {
        return ArgsParser::from_file(&PathBuf::from(matches.value_of("config-file").unwrap()));
    }

    // Gets the args from the default command line.
    pub fn from_env() -> Args {
        ArgsParser::from_matches(
            &App::new("registration_server")
                .arg(
                    Arg::with_name("config-file")
                        .long("config-file")
                        .help("Path to a toml configuration file.")
                        .takes_value(true)
                        .required(true),
                )
                .get_matches(),
        )
    }

    // Gets the args from a string array.
    #[cfg(test)]
    pub fn from_vec(params: Vec<&str>) -> Args {
        ArgsParser::from_matches(
            &App::new("registration_server")
                .arg(
                    Arg::with_name("config-file")
                        .long("config-file")
                        .help("Path to a toml configuration file.")
                        .takes_value(true)
                        .required(true),
                )
                .get_matches_from(params),
        )
    }
}

#[test]
fn test_args() {
    let _ = env_logger::try_init();

    let soa = "ns1.mydomain.org. dns-admin.mydomain.org. 2018082801 900 900 1209600 60";
    let recl_title = "Reclaim your WebThings Gateway Domain";
    let recl_body = "Hello,\n<br>\n<br>\nYour reclamation token is: {token}\n<br>\n<br>\nIf you \
                     did not request to reclaim your gateway domain, you can ignore this email.";
    let conf_title = "Welcome to your WebThings Gateway";
    let conf_body = "Hello,\n<br>\n<br>\nWelcome to your WebThings Gateway! To confirm \
                     your email address, navigate to <a href=\"{link}\">{link}</a>.\n<br>\n<br>\n\
                     Your gateway can be accessed at \
                     <a href=\"https://{domain}\">https://{domain}</a>.";
    let success = "<!DOCTYPE html>
<html>
  <head><title>Email Confirmation Successful!</title></head>
  <body>
    <h1>Thank you for verifying your email.</h1>
  </body>
</html>";
    let error = "<!DOCTYPE html>
<html>
  <head><title>Email Confirmation Error!</title></head>
  <body>
    <h1>An error happened while verifying your email.</h1>
  </body>
</html>";

    let args = ArgsParser::from_vec(vec![
        "registration_server",
        "--config-file=./config/config.toml",
    ]);
    assert_eq!(args.general.host, "127.0.0.1");
    assert_eq!(args.general.http_port, 4141);
    assert_eq!(args.general.domain, "mydomain.org");
    assert_eq!(args.general.db_path, "/tmp/domains.sqlite");
    assert_eq!(args.pdns.api_ttl, 1);
    assert_eq!(args.pdns.dns_ttl, 86400);
    assert_eq!(args.pdns.tunnel_ttl, 60);
    assert_eq!(args.pdns.caa_records, ["0 issue \"letsencrypt.org\"",]);
    assert_eq!(
        args.pdns.mx_records,
        ["10 inbound-smtp.us-west-2.amazonaws.com"]
    );
    assert_eq!(
        args.pdns.ns_records,
        [
            ["ns1.mydomain.org.", "5.6.7.8"],
            ["ns2.mydomain.org.", "4.5.6.7"]
        ]
    );
    assert_eq!(args.pdns.soa_record, soa);
    assert_eq!(args.pdns.www_addresses, ["10.11.12.13"]);
    assert_eq!(
        args.pdns.txt_records,
        [
            ["_psl", "https://github.com/publicsuffix/list/pull/XYZ"],
            ["@", "something useful"],
        ]
    );
    assert_eq!(
        args.pdns.socket_path,
        Some("/tmp/pdns_tunnel.sock".to_owned())
    );
    assert_eq!(args.pdns.geoip.default, "5.6.7.8");
    assert_eq!(
        args.pdns.geoip.database,
        Some("./test-data/GeoLite2-Country_20180206/GeoLite2-Country.mmdb".to_owned())
    );
    assert_eq!(args.pdns.geoip.continent.AF, Some("1.2.3.4".to_owned()));
    assert_eq!(args.pdns.geoip.continent.AN, Some("2.3.4.5".to_owned()));
    assert_eq!(args.pdns.geoip.continent.AS, Some("3.4.5.6".to_owned()));
    assert_eq!(args.pdns.geoip.continent.EU, Some("4.5.6.7".to_owned()));
    assert_eq!(args.pdns.geoip.continent.NA, Some("5.6.7.8".to_owned()));
    assert_eq!(args.pdns.geoip.continent.OC, Some("6.7.8.9".to_owned()));
    assert_eq!(args.pdns.geoip.continent.SA, Some("9.8.7.6".to_owned()));
    assert_eq!(args.email.server, Some("mail.gandi.net".to_owned()));
    assert_eq!(args.email.user, Some("accounts@mydomain.org".to_owned()));
    assert_eq!(args.email.password, Some("******".to_owned()));
    assert_eq!(args.email.sender, Some("accounts@mydomain.org".to_owned()));
    assert_eq!(args.email.reclamation_title, Some(recl_title.to_string()));
    assert_eq!(args.email.reclamation_body, Some(recl_body.to_string()));
    assert_eq!(args.email.confirmation_title, Some(conf_title.to_string()));
    assert_eq!(args.email.confirmation_body, Some(conf_body.to_string()));
    assert_eq!(args.email.success_page, Some(success.to_string()));
    assert_eq!(args.email.error_page, Some(error.to_string()));
}
