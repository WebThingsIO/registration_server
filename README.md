# Registration Server

[![Build Status](https://github.com/mozilla-iot/registration_server/workflows/Rust%20application/badge.svg)](https://github.com/mozilla-iot/registration_server/workflows/Rust%20application)
[![codecov](https://codecov.io/gh/mozilla-iot/registration_server/branch/master/graph/badge.svg)](https://codecov.io/gh/mozilla-iot/registration_server)
[![license](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)

This server exposes an HTTP API that lets you register a WebThings Gateway for
tunneling support.

When combined with a [PowerDNS](https://www.powerdns.com/auth.html) server and
a [PageKite](https://pagekite.net) server, this acts as an all-in-one dynamic
DNS or tunneling solution, with distributed GeoIP support. This is not only
useful for WebThings, but could also be used by a variety of other stacks.

## Usage

```
USAGE:
    main [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --api-ttl <ttl>              TTL of the DNS records for the api subdomain, in seconds.
        --caa-record <record>...     A CAA record the PowerDNS server should return (can be specified multiple times).
        --config-file <path>         Path to a toml configuration file.
        --confirmation-body <s>      The body of the confirmation email.
        --confirmation-title <s>     The title of the confirmation email.
        --db-path <path>             The database path: file path, postgres://..., mysql://...
        --dns-ttl <ttl>              TTL of the SOA/NS/MX/TXT/CAA DNS records, in seconds.
        --domain <domain>            The domain that will be tied to this registration server.
        --email-password <pass>      The password for this email account.
        --email-sender <email>       The email identity to use as a sender.
        --email-server <name>        The name of the SMTP server.
        --email-user <username>      The username to authenticate with.
        --error-page <s>             HTML content of the email confirmation error page.
        --geoip-continent-af <ip>    The IP address of the tunnel endpoint for Africa.
        --geoip-continent-an <ip>    The IP address of the tunnel endpoint for Antarctica.
        --geoip-continent-as <ip>    The IP address of the tunnel endpoint for Asia.
        --geoip-continent-eu <ip>    The IP address of the tunnel endpoint for Europe.
        --geoip-continent-na <ip>    The IP address of the tunnel endpoint for North America.
        --geoip-continent-oc <ip>    The IP address of the tunnel endpoint for Oceania.
        --geoip-continent-sa <ip>    The IP address of the tunnel endpoint for South America.
        --geoip-database <path>      Path to the GeoIP2/GeoLite2 database.
        --geoip-default <ip>         The IP address of the default tunnel endpoint.
        --host <host>                Set local hostname.
        --http-port <port>           Set port to listen on for HTTP connections (0 to turn off).
        --mx-record <record>...      An MX record the PowerDNS server should return (can be specified multiple times).
        --ns-record <record>...      An NS record the PowerDNS server should return as host=ip (can be specified
                                     multiple times).
        --reclamation-body <s>       The body of the domain reclamation email.
        --reclamation-title <s>      The title of the domain reclamation email.
        --soa-record <record>        The SOA record the PowerDNS server should return.
        --socket-path <path>         The path to the socket used to communicate with PowerDNS.
        --success-page <s>           HTML content of the email confirmation success page.
        --tunnel-ttl <ttl>           TTL of the DNS records for tunnels, in seconds.
        --txt-record <record>...     A TXT record the PowerDNS server should return (can be specified multiple times).
        --www-address <address>      The address of the www (and empty) subdomain, i.e. www.mydomain.org or
                                     mydomain.org.
```

See the `config/config.toml` for an example configuration file.


## Building & Testing

* First, select the database type you'd like: `mysql` | `postgres` | `sqlite`
* Run `cargo build --features <db_type>` to build.
* Run `./run_tests.sh` to test.

## Deploying

A Docker image has been provided
[here](https://github.com/mozilla-iot/registration-server-docker), containing
this server, a PowerDNS server, a PageKite server, and geoipupdate.

## API

The API is documented [here](doc/api.md). Its usage within the WebThings
ecosystem is described in [this document](doc/flow.md).
