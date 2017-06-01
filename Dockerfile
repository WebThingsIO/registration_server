FROM debian:stretch

ENV DEBIAN_FRONTEND=noninteractive

ENV SHELL=/bin/bash

RUN apt-get update && \
    apt-get dist-upgrade -qqy && \
    apt-get install \
       ca-certificates \
       curl \
       gcc \
       libc6-dev \
       libssl-dev \
       libsqlite3-dev \
       python \
       pkgconf \
       pdns-server \
       pdns-backend-remote \
       sqlite \
       -qqy \
       --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install PageKite
RUN curl -s https://pagekite.net/pk/ | bash

# Create a non privileged user to build the Rust code.
RUN useradd -m -d /home/user -p user user
USER user

WORKDIR /home/user

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly
ENV PATH=/home/user/.cargo/bin:/home/user/bin:$PATH

COPY . /home/user
WORKDIR /home/user/server
RUN cargo build --release

USER root

# Stop the default install of PowerDNS.
CMD service pdns stop

# We expect to find the configuration mounted in /home/user/config
# and to find the following files:
# - pdns.conf   : PowerDNS configuration.
# - config.json : registration server configuration.
# - env         : used to source environment variables.
CMD ./run_from_docker.sh
