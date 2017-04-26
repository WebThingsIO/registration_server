FROM debian:jessie
# Adapted from https://raw.githubusercontent.com/Scorpil/docker-rust/master/nightly/Dockerfile

ENV DEBIAN_FRONTEND=noninteractive

ENV SHELL=/bin/bash

# Add PageKite repository to /etc/apt/sources.list
RUN echo "deb http://pagekite.net/pk/deb/ pagekite main" | tee -a /etc/apt/sources.list

# Add the PageKite packaging key to the key-ring
RUN apt-key adv --recv-keys --keyserver keys.gnupg.net AED248B1C7B2CAC3

RUN apt-get update && \
    apt-get dist-upgrade -qqy && \
    apt-get install \
       ca-certificates \
       curl \
       gcc \
       libc6-dev \
       libssl-dev \
       libsqlite3-dev \
       pagekite \
       pkgconf \
       pdns-server \
       pdns-backend-remote \
       -qqy \
       --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install pagekite
# RUN curl -s https://pagekite.net/pk/ | bash

# Create a non privileged user to build the Rust code.
RUN useradd -m -d /home/user -p user user
USER user

WORKDIR /home/user

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly
ENV PATH=/home/user/.cargo/bin:/home/user/bin:$PATH

COPY . /home/user
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
