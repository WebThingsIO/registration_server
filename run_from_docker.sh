#!/bin/bash

set -x -e

ROOT_DIR=/home/user/config

source $ROOT_DIR/env

pdns_server --config-dir=$ROOT_DIR

if [ -n "$SECRET" ]; then
    pagekite.py --isfrontend --ports=4443 --protos=https --domain=https:*.$DOMAIN:$SECRET --authdomain=$DOMAIN &
else
    pagekite.py --isfrontend --ports=4443 --protos=https --authdomain=$DOMAIN &
fi

RUST_LOG=registration_server=debug,maxminddb=info ./target/release/main --config-file=$ROOT_DIR/config.toml
