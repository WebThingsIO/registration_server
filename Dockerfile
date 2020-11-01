FROM rust:buster

ARG DEBIAN_FRONTEND=noninteractive
RUN echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list && \
    sed -i 's/ main$/ main contrib/g' /etc/apt/sources.list && \
    apt update && \
    apt dist-upgrade -y && \
    apt install -y \
        cron \
        geoipupdate \
        pdns-backend-remote \
        pdns-server \
        python-six \
        supervisor && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install PageKite
RUN curl -s https://pagekite.net/pk/ | bash

# Create a non privileged user to build the Rust code.
RUN useradd -m -d /home/user -p user user
RUN chown -R user /home/user

ARG db_type
ENV db_type ${db_type:-mysql}

COPY --chown=user:user . /home/user/registration_server/
USER user
WORKDIR /home/user/registration_server
RUN cargo build --release --features "${db_type}" && \
    cargo install diesel_cli

USER root
ADD docker/init /
ADD docker/etc/cron.weekly/geoipupdate /etc/cron.weekly/
ADD docker/etc/supervisor/conf.d/supervisord.conf /etc/supervisor/conf.d/

RUN sed -i "s/{{db_type}}/${db_type}/" /init

ENTRYPOINT ["/init"]

# We expect to find the configuration directory mounted at /home/user/config
# with the following files:
# - config.toml   : registration server configuration
# - pagekite.conf : PageKite configuration
# - pdns.conf     : PowerDNS configuration
# - GeoIP.conf    : (Optional) geoipupdate configuration
