# Deploying the registration server

The setup relies on 3 components:
- This registration server.
- A [PowerDNS](https://powerdns.com/) server.
- [PageKite](https://pagekite.net/).

To make it easier to deploy a working environment, a Docker file is provided which will build an image including all the needed dependencies.

Getting a full setup ready involves the following:
- Build a Docker image.
- Install nginx on the container's host.
- Configure the DNS zone for the domain you want to use.
- Run the Docker image with the proper configuration.

## Docker configuration

First, build the docker image with `docker build -t registration_server .` from the source directory.

## Database setup

* Install rust on the host: `curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly`
* Install diesel: `cargo install diesel_cli`
* Set up some temp variables:
  * `export db_type=sqlite`
    * You can choose one of: mysql, postgres, sqlite
  * `export db_path=./domains.sqlite`
    * mysql: this should be of the form `mysql://[[user]:[password]@]host[:port][/database]`
    * postgres: this should be of the form `postgres://[[user]:[password]@]host[:port][/database]`
    * sqlite: this should be a file path
* Set up your database for diesel: `diesel --database-url "${db_path}" setup --migration-dir "migrations/${db_type}"`
* Set up the database tables: `diesel --database-url "${db_path}" migration --migration-dir "migrations/${db_type}" run`

## Running the Docker image

You will have to mount a couple of directories and relay some ports for the Docker image to run properly:
- Mount `/home/user/config` to a directory where you will store the configuration files.
- Mount `/home/user/data` to a directory where the database will be stored.

Port 53 over TCP and UDP needs to be forwarded for PowerDNS. The ports used for the HTTP server and the tunnel also need to be forwarded.

## Configuration files


* Add the following script to your nginx.conf server directive in the host:
```
        location /subscribe {
                proxy_pass http://127.0.0.1:81;
        }

        location /unsubscribe {
                proxy_pass http://127.0.0.1:81;
        }

        location /reclaim {
                proxy_pass http://127.0.0.1:81;
        }

        location /ping {
                proxy_pass http://127.0.0.1:81;
        }

        location /dnsconfig {
                proxy_pass http://127.0.0.1:81;
        }

        location /info {
                proxy_pass http://127.0.0.1:81;
        }

        location /revokeemail {
                proxy_pass http://127.0.0.1:81;
        }

        location /setemail {
                proxy_pass http://127.0.0.1:81;
        }

        location /verifyemail {
                proxy_pass http://127.0.0.1:81;
        }

      	location / {
                if ($http_authorization) {
                    return 403;
                }

                if ($request_method != GET) {
                     return 403;
                }

                return 301 https://$host$request_uri;
      	}
```

* The `$CONFIG_DIR/env` file is used to set any environment variable need. It is mandatory to declare DOMAIN to configure PageKite. For instance, set DOMAIN to `yourdomain.com`. Here's a full example:
```
# Domain specific configuration for pagekite.
DOMAIN=yourdomain.com

# Other variables useful for other purposes.
export RUST_LOG=debug
```

* The `CONFIG_DIR/pdns.conf` is the PowerDNS configuration file. It needs to be consistent with the registration configuration to connect on the correct socket for the remote queries:
```
daemon=yes
local-port=53
local-address=0.0.0.0
socket-dir=.
launch=remote
remote-connection-string=unix:path=/tmp/pdns_tunnel.sock
write-pid=no
log-dns-details=yes
log-dns-queries=yes
loglevel=5

```

* The `CONFIG_DIR/config.toml` file holds the registration server configuration. Here's a sample consistent with the `pdns.conf` shown above:
```
# Configuration used for tests.

[general]
host = "0.0.0.0"
http_port = 81
https_port = 4444
domain = "yourdomain.org"
db_path = "/home/user/data/domains.sqlite"
# Uncomment to use TLS (recommended)
# identity_directory = "/home/user/config"
# identity_password = "mypassword"
tunnel_ip = "1.2.3.4"

[pdns]
dns_ttl = 1203
# Check your DNS configuration to fill in this field.
soa_content = "a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800"
socket_path = "/tmp/powerdns_tunnel.sock"
mx_record = ""
caa_record = "0 issue \"letsencrypt.org\""
txt_record = ""
# Uncomment to set a PSL authentication record
# psl_record = "https://github.com/publicsuffix/list/pull/XYZ"

[email]
server = "mail.gandi.net"
user = "accounts@mydomain.org"
password = "******"
sender = "accounts@mydomain.org"
confirmation_title = "Welcome to your Mozilla IoT Gateway"
confirmation_body = "Hello,\n\nWelcome to your Mozilla IoT Gateway! To confirm your email address, follow this link: {link}"
success_page = """<!DOCTYPE html>
<html>
  <head><title>Email Confirmation Successful!</title></head>
  <body>
    <h1>Thank you for verifying your email, {email}.</h1>
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

By default the PageKite tunnel listens on port 4443.

Once you have all your configuration files ready, you can use such a shell script to start it:

```
#!/bin/bash

set -x -e
docker run -d -v /home/ec2-user/moziot/config:/home/user/config -v /home/ec2-user/moziot/data:/home/user/data -p 81:81 -p 444:4444 -p 443:4443 -p 53:53 -p 53:53/udp registration_server
```
This script relays port 80 for the server, but it is recommended to instead relay port 443 and to setup TLS certificates. The gateway will be available on port 4443 from the public endpoint, over HTTPS.
