# Deploying the tunnel server

The setup relies on 3 components:
- this registration server.
- a [PowerDNS](https://powerdns.com/) server.
- [PageKite](https://pagekite.net/).

To make it easier to deploy a working environment, a Docker file is provided which will build an image including all the needed dependencies.

Getting a full setup ready involves the following:
- build a Docker image.
- configure the DNS zone for the domain you want to use.
- run the Docker image with the proper configuration.

## Docker configuration

First, build the docker image with `docker build -t tunnel_server .` from the source directory.

## DNS Zone configuration

The PowerDNS server is only used to answer queries for the `*.box.yourdomain.com` qnames. This means that you need to have access to the configuration of `yourdomain.com` in order to delegate the DNS queries appropriately.

If `1.2.3.4` is the public IP of the server, add the following to your DNS zone configuration:
```
* 10800 IN A 1.2.3.4
@ 10800 IN A 1.2.3.4
box 10800 IN NS yourdomain.com.
```

## Running the Docker image

You will have to mount a couple of directories and relay some ports for the Docker image to run properly:
- mount `/home/user/config` to a directory where you will store the configuration files.
- mount `/home/user/data` to a directory where the database will be stored.

Port 53 over tcp and udp needs to be forwarded for PowerDNS. The ports used for the http server and the tunnel also need to be forwarded.

## Configuration files

* The `$CONFIG_DIR/env` file is used to set any environment variable need. It is mandatory to declare DOMAIN and SECRET to configure PageKite. For instance, set DOMAIN to `box.yourdomain.com`. Here's a full example:
```
# Domain specific configuration for pagekite.

DOMAIN=box.yourdomain.com
SECRET=moziot

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

* The `CONFIG_DIR/config.toml` file holds the registration server configuration. Here's a sample consistent with the `pdns.conf` showed above:
```
# Configuration used for tests.

[general]
host = "0.0.0.0"
port = 80
domain = "yourdomain.org"
data_directory = "/home/user/data"
# Uncomment to use TLS (recommended)
# cert_directory = "/home/user/config"
tunnel_ip = "1.2.3.4"
# Evict entries every 5 minutes
eviction_delay = 300

[pdns]
dns_ttl = 1203
# Check your DNS configuration to fill in this field.
soa_content = "a.dns.gandi.net hostmaster.gandi.net 1476196782 10800 3600 604800 10800"
socket_path = "/tmp/powerdns_tunnel.sock"

[email]
server = "mail.gandi.net"
user = "accounts@knilxof.org"
password = "******"
sender = "accounts@knilxof.org"
confirmation_title = "Welcome to your MozIot Gateway"
confirmation_body = "Hello,\n\nTo confirm your email address, follow this link: {link}"
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
    <h1>An error happened while verifiying your email.</h1>
  </body>
</html>"""

```

By default the PageKite tunnel listen on port 4443
Once you have all your configuration files ready, you can use such a shell script to start it:

```
#!/bin/bash
set -x -e
docker run -d -v /home/ec2-user/moziot/config:/home/user/config -v /home/ec2-user/moziot/data:/home/user/data -p 80:80 -p 4443:4443 -p 53:53 -p 53:53/udp tunnel_server
```
This script relays port 80 for the server, but it is recommended to instead relay port 443 and to setup TLS certificates. The gateway will be available on port 4443 from the public endpoint, over https.
