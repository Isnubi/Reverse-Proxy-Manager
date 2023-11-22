FROM alpine:3.18.4
LABEL maintainer="Isnubi"

# Variables
ENV NGINX_DIR='/etc/nginx' \
    NGINX_CONF_DIR='/etc/nginx/conf.d' \
    NGINX_LOG_DIR='/var/log/nginx' \
    NGINX_SSL_DIR='/etc/nginx/certs' \
    NGINX_VERSION='1.24.0'

# SSL variables
ENV SSL_COUNTRY='US' \
    SSL_STATE='California' \
    SSL_CITY='San Francisco' \
    SSL_ORG='My Organization' \
    SSL_OU='My Department' \

# Install nginx
RUN apk update &&  \
    # Install packages \
    apk add --no-cache nginx pcre-tools openssl curl && \
    # Install bash shell \
    apk add --no-cache bash && \
    # Configure nginx \
    mv "$NGINX_DIR"/nginx.conf "$NGINX_DIR"/nginx.conf.bak && \
    mkdir -p "$NGINX_SSL_DIR" && \
    # Create configuration file \
    bash -c "cat <<EOF> $NGINX_DIR/nginx.conf
user nginx;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    ##
    # Basic Settings
    ##

    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;

    include $NGINX_DIR/mime.types;
    default_type application/octet-stream;

    ##
    # SSL Settings
    ##

    ssl_protocols TLSv1.2 TLSv1.3; # Dropping SSLv3, TLSv1 and TLSv1.1, ref: POODLE
    ssl_prefer_server_ciphers on;

    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    ##
    # Logging Settings
    ##

    access_log $NGINX_LOG_DIR/access.log;
    error_log $NGINX_LOG_DIR/error.log;

    ##
    # Gzip Settings
    ##

    gzip off;

    ##
    # Virtual Host Configs
    ##

    include $NGINX_CONF_DIR/*.conf;

    # Healthcheck page
    server {
        listen 80;
        location /health.html {
            return 200 '<html lang="en"><head><title>Healthcheck</title></head><body><h1>OK</h1></body></html>';
        }
    }
}
EOF" && \
    bash -c "cat <<EOF> $NGINX_SSL_DIR/ssl.conf
COUNTRY=$SSL_COUNTRY
STATE=$SSL_STATE
LOCATION=$SSL_CITY
ORGANIZATION=$SSL_ORG
ORGANIZATION-UNIT=$SSL_OU
EOF" && \
    # Get manager script \
    wget -O /root/manager.sh https://raw.githubusercontent.com/ClubNix/Reverse-Proxy-Manager/master/manager.sh && \
    chmod +x /root/manager.sh && \
    rm -rf /var/cache/apk/*


# Set working directory
WORKDIR /root

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s CMD curl --fail http://localhost/health.html || exit 1

# Expose ports
EXPOSE 80 443

# Run nginx
CMD ["nginx", "-g", "daemon off;"]