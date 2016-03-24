# Registration server

[![Build Status](https://travis-ci.org/fxbox/registration_server.svg?branch=master)](https://travis-ci.org/fxbox/registration_server)

This server exposes a http(s) API that lets you post messages from your home network and discover them later on.

Usage:

```bash
cargo run -- -host 0.0.0.0 --port 4242 --cert-dir /etc/letsencrypt/live/knilxof.org

## Urls

Two endpoints are provided:

1. /register?message=XXX will publish `message` to other clients who also connect from the same outgoing IP address as you.
2. /ping will return a json representation of the messages that are published from the same outgoing IP address.
