// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate env_logger;
use clap::{App, ArgMatches};
use config::{Args, Continent, EmailOptions, GeneralOptions, GeoIp, PdnsOptions};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use toml;

const USAGE: &str = "--config-file=[path]     'Path to a toml configuration file.'
--host=[host]                   'Set local hostname.'
--http-port=[port]              'Set port to listen on for HTTP connections (0 to turn off).'
--https-port=[port]             'Set port to listen on for TLS connections (0 to turn off).'
--domain=[domain]               'The domain that will be tied to this registration server.'
--db-path=[path]                'The database path: file path, postgres://..., mysql://...'
--identity-directory=[dir]      'Identity directory.'
--identity-password=[password]  'Identity password.'
--dns-ttl=[ttl]                 'TTL of the SOA/NS/MX/TXT/CAA DNS records, in seconds.'
--api-ttl=[ttl]                 'TTL of the DNS records for the api subdomain, in seconds.'
--tunnel-ttl=[ttl]              'TTL of the DNS records for tunnels, in seconds.'
--socket-path=[path]            'The path to the socket used to communicate with PowerDNS.'
--caa-record=[record]           'The CAA record the PowerDNS server should return.'
--mx-record=[record]            'The MX record the PowerDNS server should return.'
--psl-record=[record]           'The TXT record used to authenticate against the Public Suffix List.'
--ns-record=[record]...         'An NS record the PowerDNS server should return as host=ip (can be specified multiple times).'
--soa-record=[record]           'The SOA record the PowerDNS server should return.'
--txt-record=[record]           'The TXT record the PowerDNS server should return.'
--geoip-default=[ip]            'The IP address of the default tunnel endpoint.'
--geoip-database=[path]         'Path to the GeoIP2/GeoLite2 database.'
--geoip-continent-af=[ip]       'The IP address of the tunnel endpoint for Africa.'
--geoip-continent-an=[ip]       'The IP address of the tunnel endpoint for Antarctica.'
--geoip-continent-as=[ip]       'The IP address of the tunnel endpoint for Asia.'
--geoip-continent-eu=[ip]       'The IP address of the tunnel endpoint for Europe.'
--geoip-continent-na=[ip]       'The IP address of the tunnel endpoint for North America.'
--geoip-continent-oc=[ip]       'The IP address of the tunnel endpoint for Oceania.'
--geoip-continent-sa=[ip]       'The IP address of the tunnel endpoint for South America.'
--email-server=[name]           'The name of the SMTP server.'
--email-user=[username]         'The username to authenticate with.'
--email-password=[pass]         'The password for this email account.'
--email-sender=[email]          'The email identity to use as a sender.'
--reclamation-title=[s]         'The title of the domain reclamation email.'
--reclamation-body=[s]          'The body of the domain reclamation email.'
--confirmation-title=[s]        'The title of the confirmation email.'
--confirmation-body=[s]         'The body of the confirmation email.'
--success-page=[s]              'HTML content of the email confirmation success page.'
--error-page=[s]                'HTML content of the email confirmation error page.'";

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
        if matches.is_present("config-file") {
            return ArgsParser::from_file(&PathBuf::from(matches.value_of("config-file").unwrap()));
        }

        macro_rules! optional {
            ($var:ident, $name:expr) => {
                let $var = if matches.is_present($name) {
                    Some(matches.value_of($name).unwrap().to_owned())
                } else {
                    None
                };
            };
        }

        let mut ns_records = vec![];
        if matches.is_present("ns-record") {
            let vals: Vec<&str> = matches.values_of("ns-record").unwrap().collect();
            for val in &vals {
                let parts: Vec<&str> = val.split('=').collect();
                if parts.len() == 2 {
                    ns_records.push(vec![parts[0].to_owned(), parts[1].to_owned()]);
                }
            }
        }

        optional!(identity_dir, "identity-directory");
        let identity_directory = match identity_dir {
            Some(dir) => Some(PathBuf::from(dir)),
            None => None,
        };

        optional!(identity_password, "identity-password");
        optional!(email_server, "email-server");
        optional!(email_user, "email-user");
        optional!(email_password, "email-password");
        optional!(email_sender, "email-sender");
        optional!(reclamation_title, "reclamation-title");
        optional!(reclamation_body, "reclamation-body");
        optional!(confirmation_title, "confirmation-title");
        optional!(confirmation_body, "confirmation-body");
        optional!(success_page, "success-page");
        optional!(error_page, "error-page");
        optional!(psl_record, "psl-record");
        optional!(geoip_database, "geoip-database");
        optional!(geoip_continent_af, "geoip-continent-af");
        optional!(geoip_continent_an, "geoip-continent-an");
        optional!(geoip_continent_as, "geoip-continent-as");
        optional!(geoip_continent_eu, "geoip-continent-eu");
        optional!(geoip_continent_na, "geoip-continent-na");
        optional!(geoip_continent_oc, "geoip-continent-oc");
        optional!(geoip_continent_sa, "geoip-continent-sa");

        Args {
            general: GeneralOptions {
                host: matches.value_of("host").unwrap_or("0.0.0.0").to_owned(),
                http_port: value_t!(matches, "http-port", u16).unwrap_or(4242),
                https_port: value_t!(matches, "https-port", u16).unwrap_or(4343),
                domain: matches
                    .value_of("domain")
                    .unwrap_or("mydomain.org")
                    .to_owned(),
                db_path: String::from(matches.value_of("db-path").unwrap_or("./domains.sqlite")),
                identity_directory: identity_directory,
                identity_password: identity_password,
            },
            pdns: PdnsOptions {
                api_ttl: value_t!(matches, "api-ttl", u32).unwrap_or(10),
                dns_ttl: value_t!(matches, "dns-ttl", u32).unwrap_or(600),
                tunnel_ttl: value_t!(matches, "tunnel-ttl", u32).unwrap_or(60),
                socket_path: matches.value_of("socket-path").map(|s| s.to_owned()),
                caa_record: matches
                    .value_of("caa-record")
                    .unwrap_or("_caa_not_configured_")
                    .to_owned(),
                mx_record: matches
                    .value_of("mx-record")
                    .unwrap_or("_mx_not_configured_")
                    .to_owned(),
                ns_records: ns_records,
                psl_record: psl_record,
                soa_record: matches
                    .value_of("soa-record")
                    .unwrap_or("_soa_not_configured_")
                    .to_owned(),
                txt_record: matches
                    .value_of("txt-record")
                    .unwrap_or("_txt_not_configured_")
                    .to_owned(),
                geoip: GeoIp {
                    default: matches
                        .value_of("geoip-default")
                        .unwrap_or("0.0.0.0")
                        .to_owned(),
                    database: geoip_database,
                    continent: Continent {
                        AF: geoip_continent_af,
                        AN: geoip_continent_an,
                        AS: geoip_continent_as,
                        EU: geoip_continent_eu,
                        NA: geoip_continent_na,
                        OC: geoip_continent_oc,
                        SA: geoip_continent_sa,
                    },
                },
            },
            email: EmailOptions {
                server: email_server,
                user: email_user,
                password: email_password,
                sender: email_sender,
                reclamation_title: reclamation_title,
                reclamation_body: reclamation_body,
                confirmation_title: confirmation_title,
                confirmation_body: confirmation_body,
                success_page: success_page,
                error_page: error_page,
            },
        }
    }

    // Gets the args from the default command line.
    pub fn from_env() -> Args {
        ArgsParser::from_matches(
            &App::new("registration_server")
                .args_from_usage(USAGE)
                .get_matches(),
        )
    }

    // Gets the args from a string array.
    #[cfg(test)]
    pub fn from_vec(params: Vec<&str>) -> Args {
        ArgsParser::from_matches(
            &App::new("registration_server")
                .args_from_usage(USAGE)
                .get_matches_from(params),
        )
    }
}

#[test]
fn test_args() {
    let _ = env_logger::init();

    let args = ArgsParser::from_vec(vec!["registration_server", "--geoip-default=1.2.3.4"]);

    assert_eq!(args.general.host, "0.0.0.0");
    assert_eq!(args.general.http_port, 4242);
    assert_eq!(args.general.https_port, 4343);
    assert_eq!(args.general.domain, "mydomain.org");
    assert_eq!(args.general.db_path, "./domains.sqlite");
    assert_eq!(args.general.identity_directory, None);
    assert_eq!(args.general.identity_password, None);
    assert_eq!(args.pdns.api_ttl, 10);
    assert_eq!(args.pdns.dns_ttl, 600);
    assert_eq!(args.pdns.tunnel_ttl, 60);
    assert_eq!(args.pdns.socket_path, None);
    assert_eq!(args.pdns.caa_record, "_caa_not_configured_");
    assert_eq!(args.pdns.mx_record, "_mx_not_configured_");
    assert_eq!(args.pdns.ns_records.len(), 0);
    assert_eq!(args.pdns.psl_record, None);
    assert_eq!(args.pdns.soa_record, "_soa_not_configured_");
    assert_eq!(args.pdns.txt_record, "_txt_not_configured_");
    assert_eq!(args.pdns.geoip.default, "1.2.3.4");
    assert_eq!(args.pdns.geoip.database, None);
    assert_eq!(args.pdns.geoip.continent.AF, None);
    assert_eq!(args.pdns.geoip.continent.AN, None);
    assert_eq!(args.pdns.geoip.continent.AS, None);
    assert_eq!(args.pdns.geoip.continent.EU, None);
    assert_eq!(args.pdns.geoip.continent.NA, None);
    assert_eq!(args.pdns.geoip.continent.OC, None);
    assert_eq!(args.pdns.geoip.continent.SA, None);
    assert_eq!(args.email.server, None);
    assert_eq!(args.email.user, None);
    assert_eq!(args.email.password, None);
    assert_eq!(args.email.sender, None);
    assert_eq!(args.email.reclamation_title, None);
    assert_eq!(args.email.reclamation_body, None);
    assert_eq!(args.email.confirmation_title, None);
    assert_eq!(args.email.confirmation_body, None);
    assert_eq!(args.email.success_page, None);
    assert_eq!(args.email.error_page, None);

    let args = ArgsParser::from_vec(vec![
        "registration_server",
        "--host=127.0.1.1",
        "--http-port=4343",
        "--https-port=4444",
        "--domain=example.com",
        "--db-path=/tmp/mydata/domains.sqlite",
        "--identity-directory=/tmp/mycerts",
        "--identity-password=mypass",
        "--geoip-default=1.2.3.4",
        "--geoip-database=/path/to/mmdb",
        "--geoip-continent-af=1.1.1.1",
        "--geoip-continent-an=2.2.2.2",
        "--geoip-continent-as=3.3.3.3",
        "--geoip-continent-eu=4.4.4.4",
        "--geoip-continent-na=5.5.5.5",
        "--geoip-continent-oc=6.6.6.6",
        "--geoip-continent-sa=7.7.7.7",
        "--api-ttl=120",
        "--dns-ttl=140",
        "--tunnel-ttl=160",
        "--socket-path=/tmp/socket",
        "--caa-record=_my_caa",
        "--mx-record=_my_mx",
        "--ns-record=ns1.example.com.=1.1.1.1",
        "--ns-record=ns2.example.com.=2.2.2.2",
        "--psl-record=_my_psl",
        "--soa-record=_my_soa",
        "--txt-record=_my_txt",
        "--email-server=test.email.com",
        "--email-user=my_email_user",
        "--email-password=my_password",
        "--email-sender=sender@email.com",
        "--reclamation-title=Reclamation_Title",
        "--reclamation-body=Reclamation_Body",
        "--confirmation-title=Confirmation_Title",
        "--confirmation-body=Confirmation_Body",
        "--success-page=this is success",
        "--error-page=this is error",
    ]);

    assert_eq!(args.general.host, "127.0.1.1");
    assert_eq!(args.general.http_port, 4343);
    assert_eq!(args.general.https_port, 4444);
    assert_eq!(args.general.domain, "example.com");
    assert_eq!(args.general.db_path, "/tmp/mydata/domains.sqlite");
    assert_eq!(
        args.general.identity_directory,
        Some(PathBuf::from("/tmp/mycerts"))
    );
    assert_eq!(args.general.identity_password, Some("mypass".to_owned()));
    assert_eq!(args.pdns.api_ttl, 120);
    assert_eq!(args.pdns.dns_ttl, 140);
    assert_eq!(args.pdns.tunnel_ttl, 160);
    assert_eq!(args.pdns.socket_path, Some("/tmp/socket".to_owned()));
    assert_eq!(args.pdns.caa_record, "_my_caa");
    assert_eq!(args.pdns.mx_record, "_my_mx");
    assert_eq!(
        args.pdns.ns_records,
        [
            ["ns1.example.com.", "1.1.1.1"],
            ["ns2.example.com.", "2.2.2.2"]
        ]
    );
    assert_eq!(args.pdns.psl_record, Some("_my_psl".to_owned()));
    assert_eq!(args.pdns.soa_record, "_my_soa");
    assert_eq!(args.pdns.txt_record, "_my_txt");
    assert_eq!(args.pdns.geoip.default, "1.2.3.4");
    assert_eq!(args.pdns.geoip.database, Some("/path/to/mmdb".to_owned()));
    assert_eq!(args.pdns.geoip.continent.AF, Some("1.1.1.1".to_owned()));
    assert_eq!(args.pdns.geoip.continent.AN, Some("2.2.2.2".to_owned()));
    assert_eq!(args.pdns.geoip.continent.AS, Some("3.3.3.3".to_owned()));
    assert_eq!(args.pdns.geoip.continent.EU, Some("4.4.4.4".to_owned()));
    assert_eq!(args.pdns.geoip.continent.NA, Some("5.5.5.5".to_owned()));
    assert_eq!(args.pdns.geoip.continent.OC, Some("6.6.6.6".to_owned()));
    assert_eq!(args.pdns.geoip.continent.SA, Some("7.7.7.7".to_owned()));
    assert_eq!(args.email.server, Some("test.email.com".to_owned()));
    assert_eq!(args.email.user, Some("my_email_user".to_owned()));
    assert_eq!(args.email.password, Some("my_password".to_owned()));
    assert_eq!(args.email.sender, Some("sender@email.com".to_owned()));
    assert_eq!(
        args.email.reclamation_title,
        Some("Reclamation_Title".to_owned())
    );
    assert_eq!(
        args.email.reclamation_body,
        Some("Reclamation_Body".to_owned())
    );
    assert_eq!(
        args.email.confirmation_title,
        Some("Confirmation_Title".to_owned())
    );
    assert_eq!(
        args.email.confirmation_body,
        Some("Confirmation_Body".to_owned())
    );
    assert_eq!(args.email.success_page, Some("this is success".to_owned()));
    assert_eq!(args.email.error_page, Some("this is error".to_owned()));

    let caa = "0 issue \"letsencrypt.org\"";
    let mx = "";
    let txt = "";
    let soa = "ns1.mydomain.org. dns-admin.mydomain.org. 2018082801 900 900 1209600 60";
    let recl_title = "Reclaim your Mozilla WebThings Gateway Domain";
    let recl_body = "Hello,\n<br>\n<br>\nYour reclamation token is: {token}\n<br>\n<br>\nIf you \
                     did not request to reclaim your gateway domain, you can ignore this email.";
    let conf_title = "Welcome to your Mozilla WebThings Gateway";
    let conf_body = "Hello,\n<br>\n<br>\nWelcome to your Mozilla WebThings Gateway! To confirm \
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
    assert_eq!(args.general.https_port, 4142);
    assert_eq!(args.general.domain, "mydomain.org");
    assert_eq!(args.general.db_path, "/tmp/domains.sqlite");
    assert_eq!(
        args.general.identity_directory,
        Some(PathBuf::from("/tmp/certs"))
    );
    assert_eq!(
        args.general.identity_password,
        Some("mypassword".to_owned())
    );
    assert_eq!(args.pdns.api_ttl, 10);
    assert_eq!(args.pdns.dns_ttl, 600);
    assert_eq!(args.pdns.tunnel_ttl, 60);
    assert_eq!(args.pdns.caa_record, caa);
    assert_eq!(args.pdns.mx_record, mx);
    assert_eq!(
        args.pdns.ns_records,
        [
            ["ns1.mydomain.org.", "5.6.7.8"],
            ["ns2.mydomain.org.", "4.5.6.7"]
        ]
    );
    assert_eq!(
        args.pdns.psl_record,
        Some("https://github.com/publicsuffix/list/pull/XYZ".to_owned())
    );
    assert_eq!(args.pdns.soa_record, soa);
    assert_eq!(args.pdns.txt_record, txt);
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
