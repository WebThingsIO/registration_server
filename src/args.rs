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
--host=[host]                   'Set local hostname.'
--http-port=[port]              'Set port to listen on for HTTP connections (0 to turn off).'
--https-port=[port]             'Set port to listen on for TLS connections (0 to turn off).'
--domain=[domain]               'The domain that will be tied to this registration server.'
--db-path=[path]                'The database path: file path, postgres://..., mysql://...'
--identity-directory=[dir]      'Identity directory.'
--identity-password=[password]  'Identity password.'
--tunnel-ip=[ip]                'The IP address of the tunnel endpoint.'
--dns-ttl=[ttl]                 'TTL of the DNS records, in seconds.'
--soa-content=[dns]             'The content of the SOA record for this tunnel.'
--socket-path=[path]            'The path to the socket used to communicate with PowerDNS.'
--mx-record=[record]            'The MX record the PowerDNS server should return.'
--caa-record=[record]           'The CAA record the PowerDNS server should return.'
--txt-record=[record]           'The TXT record the PowerDNS server should return.'
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
                tunnel_ip: matches
                    .value_of("tunnel-ip")
                    .unwrap_or("0.0.0.0")
                    .to_owned(),
            },
            pdns: PdnsOptions {
                dns_ttl: value_t!(matches, "dns-ttl", u32).unwrap_or(60),
                soa_content: matches
                    .value_of("soa-content")
                    .unwrap_or("_soa_not_configured_")
                    .to_owned(),
                socket_path: matches.value_of("socket-path").map(|s| s.to_owned()),
                mx_record: matches
                    .value_of("mx-record")
                    .unwrap_or("_mx_not_configured_")
                    .to_owned(),
                caa_record: matches
                    .value_of("caa-record")
                    .unwrap_or("_caa_not_configured_")
                    .to_owned(),
                txt_record: matches
                    .value_of("txt-record")
                    .unwrap_or("_txt_not_configured_")
                    .to_owned(),
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
            App::new("registration_server")
                .args_from_usage(USAGE)
                .get_matches(),
        )
    }

    // Gets the args from a string array.
    #[cfg(test)]
    pub fn from_vec(params: Vec<&str>) -> Args {
        ArgsParser::from_matches(
            App::new("registration_server")
                .args_from_usage(USAGE)
                .get_matches_from(params),
        )
    }
}

#[test]
fn test_args() {
    let args = ArgsParser::from_vec(vec!["registration_server", "--tunnel-ip=1.2.3.4"]);

    assert_eq!(args.general.host, "0.0.0.0");
    assert_eq!(args.general.http_port, 4242);
    assert_eq!(args.general.https_port, 4343);
    assert_eq!(args.general.domain, "mydomain.org");
    assert_eq!(args.general.db_path, "./domains.sqlite");
    assert_eq!(args.general.identity_directory, None);
    assert_eq!(args.general.identity_password, None);
    assert_eq!(args.general.tunnel_ip, "1.2.3.4");
    assert_eq!(args.pdns.dns_ttl, 60);
    assert_eq!(args.pdns.soa_content, "_soa_not_configured_");
    assert_eq!(args.pdns.socket_path, None);
    assert_eq!(args.pdns.mx_record, "_mx_not_configured_");
    assert_eq!(args.pdns.caa_record, "_caa_not_configured_");
    assert_eq!(args.pdns.txt_record, "_txt_not_configured_");
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
        "--tunnel-ip=1.2.3.4",
        "--dns-ttl=120",
        "--soa-content=_my_soa",
        "--socket-path=/tmp/socket",
        "--mx-record=_my_mx",
        "--caa-record=_my_caa",
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
    assert_eq!(args.general.tunnel_ip, "1.2.3.4");
    assert_eq!(args.pdns.dns_ttl, 120);
    assert_eq!(args.pdns.soa_content, "_my_soa");
    assert_eq!(args.pdns.socket_path, Some("/tmp/socket".to_owned()));
    assert_eq!(args.pdns.mx_record, "_my_mx");
    assert_eq!(args.pdns.caa_record, "_my_caa");
    assert_eq!(args.pdns.txt_record, "_my_txt");
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

    let soa = "a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800";
    let mx = "";
    let caa = "0 issue \"letsencrypt.org\"";
    let txt = "";
    let recl_title = "Reclaim your Mozilla IoT Gateway Domain";
    let recl_body = "Hello,\n\nYour reclamation token is: {token}\n\nIf you \
                     did not request to reclaim your gateway domain, you can \
                     ignore this email.";
    let conf_title = "Welcome to your Mozilla IoT Gateway";
    let conf_body = "Hello,\n\nWelcome to your Mozilla IoT Gateway! To confirm \
                     your email address, follow this link: {link}";
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
    assert_eq!(args.general.tunnel_ip, "1.2.3.4");
    assert_eq!(args.pdns.dns_ttl, 89);
    assert_eq!(args.pdns.soa_content, soa);
    assert_eq!(
        args.pdns.socket_path,
        Some("/tmp/powerdns_tunnel.sock".to_owned())
    );
    assert_eq!(args.pdns.mx_record, mx);
    assert_eq!(args.pdns.caa_record, caa);
    assert_eq!(args.pdns.txt_record, txt);
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
