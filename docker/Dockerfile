FROM alpine:3.18.4
LABEL maintainer="Isnubi"

# Variables
ARG NGINX_VERSION='1.24.0'
ARG NGINX_DIR='/etc/nginx'
ARG NGINX_CONF_DIR='/etc/nginx/conf.d'
ARG NGINX_LOG_DIR='/var/log/nginx'
ARG NGINX_SSL_DIR='/etc/nginx/certs'
# SSL Variables
ARG SSL_COUNTRY='US'
ARG SSL_STATE='California'
ARG SSL_CITY='San Francisco'
ARG SSL_ORG='My Organization'
ARG SSL_OU='My Department'
ARG SSL_DAYS='3650'

# Install nginx
RUN apk update &&  \
    # Install packages \
    apk add --no-cache nginx pcre-tools openssl curl && \
    # Install bash shell \
    apk add --no-cache bash && \
    # Configure nginx \
    mv "$NGINX_DIR"/nginx.conf "$NGINX_DIR"/nginx.conf.bak && \
    wget -O "$NGINX_DIR"/nginx.conf https://raw.githubusercontent.com/ClubNix/Reverse-Proxy-Manager/master/docker/nginx.conf && \
    sed -i "s|\$NGINX_DIR|$NGINX_DIR|g" "$NGINX_DIR"/nginx.conf && \
    sed -i "s|\$NGINX_CONF_DIR|$NGINX_CONF_DIR|g" "$NGINX_DIR"/nginx.conf && \
    sed -i "s|\$NGINX_LOG_DIR|$NGINX_LOG_DIR|g" "$NGINX_DIR"/nginx.conf && \
    mkdir -p "$NGINX_SSL_DIR" && \
    wget -O "$NGINX_SSL_DIR"/ssl.conf https://raw.githubusercontent.com/ClubNix/Reverse-Proxy-Manager/master/docker/ssl.conf && \
    sed -i "s|\$SSL_COUNTRY|$SSL_COUNTRY|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|\$SSL_STATE|$SSL_STATE|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|\$SSL_CITY|$SSL_CITY|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|\$SSL_ORG|$SSL_ORG|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|\$SSL_OU|$SSL_OU|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|\$SSL_DAYS|$SSL_DAYS|g" "$NGINX_SSL_DIR"/ssl.conf && \
    # Get manager script \
    wget -O /root/manager.sh https://raw.githubusercontent.com/ClubNix/Reverse-Proxy-Manager/master/docker/manager.sh && \
    sed -i "s|\$NGINX_CONF_DIR_REPLACE|$NGINX_CONF_DIR|g" /root/manager.sh && \
    sed -i "s|\$NGINX_SSL_DIR_REPLACE|$NGINX_SSL_DIR|g" /root/manager.sh && \
    sed -i "s|\$NGINX_LOG_DIR_REPLACE|$NGINX_LOG_DIR|g" /root/manager.sh && \
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