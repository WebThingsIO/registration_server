# Registration server

[![Build Status](https://travis-ci.org/mozilla-iot/registration_server.svg?branch=master)](https://travis-ci.org/mozilla-iot/registration_server)

This server exposes a HTTP(S) API that lets you register a gateway with the server.

## Usage

```bash
USAGE:
    registration_server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --caa-record <record>       The CAA record the PowerDNS server should return.
        --cert-directory <dir>      Certificate directory.
        --config-file <path>        Path to a toml configuration file.
        --confirmation-body <s>     The body of the confirmation email.
        --confirmation-title <s>    The title of the confirmation email.
        --data-directory <dir>      The directory where the persistent data will be saved.
        --dns-ttl <ttl>             TTL of the DNS records, in seconds.
        --domain <domain>           The domain that will be tied to this registration server.
        --email-password <pass>     The password for this email account.
        --email-sender <email>      The email identity to use as a sender.
        --email-server <name>       The name of the SMTP server.
        --email-user <username>     The username to authenticate with.
        --error-page <s>            HTML content of the email confirmation error page.
        --host <host>               Set local hostname.
        --http-port <port>          Set port to listen on for HTTP connections (0 to prevent listening).
        --https-port <port>         Set port to listen on for TLS connections (0 to prevent listening).
        --mx-record <record>        The MX record the PowerDNS server should return.
        --reclamation-body <s>      The body of the domain reclamation email.
        --reclamation-title <s>     The title of the domain reclamation email.
        --soa-content <dns>         The content of the SOA record for this tunnel.
        --socket-path <path>        The path to the socket used to communicate with PowerDNS.
        --success-page <s>          HTML content of the email confirmation success page.
        --tunnel-ip <ip>            The IP address of the tunnel endpoint.
        --txt-record <record>       The TXT record the PowerDNS server should return.
```

See the `config/config.toml` for an example configuration file.


## Building & Testing

Just run `cargo build` and `cargo test` in the `server` directory!

## Deploying

Deployment details are provided in the [deployment guide](deployment.md).

## API

The API is documented [here](api.md). Its usage is described in [this document](flow.md).
