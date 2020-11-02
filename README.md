# Registration Server

[![Build Status](https://github.com/WebThingsIO/registration_server/workflows/Rust%20application/badge.svg)](https://github.com/WebThingsIO/registration_server/workflows/Rust%20application)
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
        --config-file <path>         Path to a toml configuration file.
```

See `config/config.toml` for an example configuration file.


## Building & Testing

* First, select the database type you'd like: `mysql` | `postgres` | `sqlite`
* Run `cargo build --features <db_type>` to build.
* Run `./run_tests.sh` to test.

## Docker build

Build the Docker image with `docker build -t registration-server .` from
the source directory.

You can add the following build args:
* `--build-arg "db_type=<db-type>"`
    * `<db-type>` should be one of: mysql, sqlite, postgres

## Deploying

The setup relies on 3 components:
* The registration server
* A [PowerDNS](https://powerdns.com/) server
* [PageKite](https://pagekite.net/)

Getting a full setup ready involves the following:
* Build a Docker image.
* Install nginx on the container's host.
* Configure your DNS zone for the domain you want to use. The NS records need
  to point to your registration server, i.e. the same IP address that will end
  up serving `api.mydomain.org`. This will need to be done through your DNS
  host or domain registrar.

    ```
    $ dig +short NS mozilla-iot.org
    ns2.mozilla-iot.org.
    ns1.mozilla-iot.org.
    ```

* Run the Docker image with the proper configuration.

## Configuration files

### Nginx

If you're using Nginx as your reverse proxy on the host, you'll need to add the
following server directives to your `nginx.conf`:

```
# HTTP version of the main registration server. We redirect to TLS port 8443 to
# avoid conflicting with tunneled domains.
server {
    listen 80;
    listen [::]:80;
    server_name api.mydomain.org;
    return 301 https://$server_name:8443$request_uri;
}

# This default server handles tunneled domains, i.e. myhost.mydomain.org.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    return 301 https://$host$request_uri;
}

# This is the main registration server.
#
# This section assumes you're using Let's Encrypt to generate a host
# certificate. Adjust accordingly if necessary.
server {
    listen 8443 ssl http2 default_server;
    listen [::]:8443 ssl http2 default_server;
    server_name api.mydomain.org;

    ssl_certificate "/etc/letsencrypt/live/api.mydomain.org/fullchain.pem";
    ssl_certificate_key "/etc/letsencrypt/live/api.mydomain.org/privkey.pem";
    # It is *strongly* recommended to generate unique DH parameters
    # Generate them with: openssl dhparam -out /etc/pki/nginx/dhparams.pem 2048
    ssl_dhparam "/etc/pki/nginx/dhparams.pem";
    ssl_session_cache shared:SSL:1m;
    ssl_session_timeout  10m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:81;
    }
}
```

### PageKite

The `$CONFIG_DIR/pagekite.conf` file is used to set any options for PageKite,
where `$CONFIG_DIR` is the directory you'll end up sharing into your Docker
container at `/home/user/config`. Here's a full example:

```
--isfrontend
--ports=4443
--protos=https
--authdomain=mydomain.org
--nullui
# Uncomment the following to quiet logging:
#--logfile=/dev/null
```

### PowerDNS

The `$CONFIG_DIR/pdns.conf` is the PowerDNS configuration file, where
`$CONFIG_DIR` is the directory you'll end up sharing into your Docker container
at `/home/user/config`. It needs to be consistent with the registration
configuration to connect on the correct socket for the remote queries:

```ini
daemon=no
local-port=53
local-address=0.0.0.0
socket-dir=/run/
launch=remote
remote-connection-string=unix:path=/tmp/pdns_tunnel.sock
write-pid=no
log-dns-details=no
log-dns-queries=no
loglevel=4

# If using geoip in the registration server, uncomment the following:
#query-cache-ttl=0
#cache-ttl=0
```

### Registration Server

The `$CONFIG_DIR/config.toml` file holds the registration server
configuration, where `$CONFIG_DIR` is the directory you'll end up sharing into
your Docker container at `/home/user/config`. You should take a look at each
line and ensure that the values are proper for your domain. In particular, you
should look at anything with `mydomain.org` or an IP address. Here's a sample
consistent with the `pdns.conf` shown above:

```toml
[general]
host = "0.0.0.0"
http_port = 81
domain = "mydomain.org"

# For SQLite: db_path should just be a file path.
# For MySQL: db_path should be of the form: mysql://[user[:password]@]host[:port][/database_name]
# For PostgreSQL: db_path should be of the form: postgres://[user[:password]@]host[:port][/database_name]
db_path = "/home/user/data/domains.sqlite"

[pdns]
api_ttl = 1
dns_ttl = 86400
tunnel_ttl = 60
socket_path = "/tmp/pdns_tunnel.sock"
caa_records = [
  "0 issue \"letsencrypt.org\"",
]
mx_records = []
ns_records = [
  [ "ns1.mydomain.org.", "5.6.7.8" ],
  [ "ns2.mydomain.org.", "4.5.6.7" ],
]
txt_records = []
# Check your DNS configuration to fill in this field.
soa_record = "ns1.mydomain.org. dns-admin.mydomain.org. 2018082801 900 900 1209600 60"
# Uncomment to set an IP address to resolve www.mydomain.org and domain.org to.
# www_address = ""

  [pdns.geoip]
  default = "5.6.7.8"

  # If you're not using geoip, you should comment out the next line.
  database = "/var/lib/GeoIP/GeoLite2-Country.mmdb"

    # If you're not using geoip, you should comment out all of the continents,
    # but keep the section header.
    [pdns.geoip.continent]
    AF = "1.2.3.4"
    AN = "2.3.4.5"
    AS = "3.4.5.6"
    EU = "4.5.6.7"
    NA = "5.6.7.8"
    OC = "6.7.8.9"
    SA = "9.8.7.6"

[email]
server = "mail.gandi.net"
user = "accounts@mydomain.org"
password = "******"
sender = "accounts@mydomain.org"
reclamation_title = "Reclaim your WebThings Gateway Domain"
reclamation_body = """Hello,
<br>
<br>
Your reclamation token is: {token}
<br>
<br>
If you did not request to reclaim your gateway domain, you can ignore this email."""
confirmation_title = "Welcome to your WebThings Gateway"
confirmation_body = """Hello,
<br>
<br>
Welcome to your WebThings Gateway! To confirm your email address, navigate to <a href="{link}">{link}</a>.
<br>
<br>
Your gateway can be accessed at <a href="https://{domain}">https://{domain}</a>."""
success_page = """<!DOCTYPE html>
<html>
  <head><title>Email Confirmation Successful!</title></head>
  <body>
    <h1>Thank you for verifying your email.</h1>
  </body>
</html>"""
error_page = """<!DOCTYPE html>
<html>
  <head><title>Email Confirmation Error!</title></head>
  <body>
    <h1>An error happened while verifying your email.</h1>
  </body>
</html>"""
```

### geoipupdate

The `$CONFIG_DIR/GeoIP.conf` file holds the configuration for geoipupdate,
where `$CONFIG_DIR` is the directory you'll end up sharing into your Docker
container at `/home/user/config`. This is only necessary if you're using geoip
in the registration server.

```
# GeoIP.conf file for `geoipupdate` program, for versions >= 3.1.1.
# Used to update GeoIP databases from https://www.maxmind.com.
# For more information about this config file, visit the docs at
# https://dev.maxmind.com/geoip/geoipupdate/.

# `AccountID` is from your MaxMind account.
AccountID <your id>

# `LicenseKey` is from your MaxMind account
LicenseKey <your key>

# `EditionIDs` is from your MaxMind account.
EditionIDs GeoLite2-Country
```

## Running the Docker image

You will have to mount a couple of directories and relay some ports for the
Docker image to run properly:
* Mount `$CONFIG_DIR` (which was used above) to `/home/user/config`. This is
  where all of the configuration files live.
* If using SQLite as your database, you should also mount another directory to
  `/home/user/data`, or wherever else you specified your database to live in
  the `db_path` option.

Port 53 over TCP and UDP needs to be forwarded for PowerDNS. The ports used for
the HTTP server and the tunnel also need to be forwarded.

Example:

```bash
docker run \
    -d \
    -v /opt/docker/registration-server/config:/home/user/config \
    -v /opt/docker/registration-server/data:/home/user/data \
    -p 127.0.0.1:81:81 \
    -p 443:4443 \
    -p 53:53 \
    -p 53:53/udp \
    --log-opt max-size=1m \
    --log-opt max-file=10 \
    --restart unless-stopped \
    --name registration-server \
    webthingsio/registration-server:sqlite
```

## Configuring the Gateway

To configure the WebThings Gateway to use your custom registration server,
after doing all the steps above, you can modify your gateway's configuration in
`~/.mozilla-iot/config/local.json` as follows:

```json
{
  "ssltunnel": {
    "registration_endpoint": "https://api.mydomain.org:8443",
    "domain": "mydomain.org",
    "certemail": "certificate@mydomain.org"
  }
}
```
A Docker image has been provided
[here](https://hub.docker.com/r/webthingsio/registration-server), containing
this server, a PowerDNS server, a PageKite server, and geoipupdate.

## API

The API is documented [here](doc/api.md). Its usage within the WebThings
ecosystem is described in [this document](doc/flow.md).
