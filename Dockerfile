FROM debian:jessie
# Adapted from https://raw.githubusercontent.com/Scorpil/docker-rust/master/nightly/Dockerfile

ENV DEBIAN_FRONTEND=noninteractive

ENV SHELL=/bin/bash

RUN apt-get update && \
    apt-get install \
       ca-certificates \
       curl \
       gcc \
       libc6-dev \
       libssl-dev \
       libsqlite3-dev \
       redis-server \
       -qqy \
       --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/user -p user user
USER user

WORKDIR /home/user

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2016-12-16
ENV PATH=/home/user/.cargo/bin:/home/user/bin:$PATH

COPY . /home/user
RUN cargo build --release
CMD service redis-server start && RUST_LOG=info ./target/release/registration_server -h 0.0.0.0 -p 4443 --cert-directory /certdir
