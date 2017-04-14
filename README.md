# Registration server

[![Build Status](https://travis-ci.org/moziot/registration_server.svg?branch=master)](https://travis-ci.org/moziot/registration_server)

This server exposes a http(s) API that lets you post messages from your home network and discover them later on.

## Usage

```bash
cargo run -- -h 0.0.0.0 -p 4242 --cert-dir /etc/letsencrypt/live/knilxof.org
```

## Urls

Two endpoints are provided:

1. /register?message=XXX will publish `message` to other clients who also connect from the same outgoing IP address as you.
2. /ping will return a json representation of the messages that are published from the same outgoing IP address.
3. /reserve?name=XXX will reserve the name `XXX` if it doesn't exist yet and create a token for it.
4. /dnsconfig?challenge=XXX&token=YYY configures the dns server for this domain.
5. /tunnel?action=start|stop&token=YYY configures a tunnel for this domain.
