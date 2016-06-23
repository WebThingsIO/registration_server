FROM debian:jessie
# Adapted from https://raw.githubusercontent.com/Scorpil/docker-rust/master/nightly/Dockerfile

ENV DEBIAN_FRONTEND=noninteractive

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

ENV RUST_ARCHIVE=rust-nightly-x86_64-unknown-linux-gnu.tar.gz
ENV RUST_VERSION=2016-03-07
ENV RUST_DOWNLOAD_URL=https://static.rust-lang.org/dist/$RUST_VERSION/$RUST_ARCHIVE

RUN mkdir /rust
WORKDIR /rust

RUN curl -fsOSL $RUST_DOWNLOAD_URL \
    && curl -s $RUST_DOWNLOAD_URL.sha256 | sha256sum -c - \
    && tar -C /rust -xzf $RUST_ARCHIVE --strip-components=1 \
    && rm $RUST_ARCHIVE \
    && ./install.sh

COPY . /rust
RUN cd /rust && cargo build --release
CMD service redis-server start && RUST_LOG=info ./target/release/registration_server -h 0.0.0.0 -p 4443 --cert-directory /certdir
