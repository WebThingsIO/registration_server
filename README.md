# Registration server

[![Build Status](https://travis-ci.org/moziot/registration_server.svg?branch=master)](https://travis-ci.org/moziot/registration_server)

This server exposes a http(s) API that lets you post messages from your home network and discover them later on.

## Usage

```bash
USAGE:
    registration_server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --config-file <path>  Path to a toml configuration file.
```

See the `config.toml.sample` for an example of configuration file.


## Building

Just run `cargo build` !

## Api

The REST api is documented [here](api.md).
