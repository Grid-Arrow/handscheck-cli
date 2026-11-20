# Lab target host: Ubuntu 16.04 (EOL, like two of our real hosts), Apache + PHP-FPM 7.0, an older WordPress
# (6.5 is the last release supporting PHP 7.0) + wp-cli, sshd. Synthetic, for local development only.
# Downloads happen in a modern stage because 16.04's TLS stack is too old for some sites.
FROM curlimages/curl:8.11.1 AS downloads
ARG WP_VERSION=6.5.5
ARG WP_CLI_VERSION=2.10.0
RUN curl -fsSL -o /tmp/wordpress.tar.gz "https://wordpress.org/wordpress-${WP_VERSION}.tar.gz" \
    && curl -fsSL -o /tmp/wp-cli.phar \
       "https://github.com/wp-cli/wp-cli/releases/download/v${WP_CLI_VERSION}/wp-cli-${WP_CLI_VERSION}.phar"

FROM ubuntu:16.04
ENV DEBIAN_FRONTEND=noninteractive PHP_VERSION=7.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       openssh-server sudo apache2 php7.0-fpm php7.0-mysql php7.0-xml php7.0-curl php7.0-gd php7.0-mbstring \
       php7.0-zip mysql-client cron procps iproute2 less ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod proxy_fcgi setenvif rewrite && a2enconf php7.0-fpm && a2dissite 000-default

COPY --from=downloads /tmp/wordpress.tar.gz /opt/wordpress.tar.gz
COPY --from=downloads /tmp/wp-cli.phar /usr/local/bin/wp
COPY common/ /opt/lab/
RUN chmod 755 /usr/local/bin/wp && /opt/lab/setup-image.sh

EXPOSE 22 80
ENTRYPOINT ["/opt/lab/entrypoint.sh"]
