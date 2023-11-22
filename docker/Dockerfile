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
    SSL_OU='My Department'

# Install nginx
RUN apk update &&  \
    # Install packages \
    apk add --no-cache nginx pcre-tools openssl curl && \
    # Install bash shell \
    apk add --no-cache bash && \
    # Configure nginx \
    mv "$NGINX_DIR"/nginx.conf "$NGINX_DIR"/nginx.conf.bak && \
    wget -o "$NGINX_DIR"/nginx.conf https://raw.githubusercontent.com/ClubNix/Reverse-Proxy-Manager/master/docker/nginx.conf && \
    sed -i "s|\$NGINX_DIR|$NGINX_DIR|g" "$NGINX_DIR"/nginx.conf && \
    sed -i "s|\$NGINX_CONF_DIR|$NGINX_CONF_DIR|g" "$NGINX_DIR"/nginx.conf && \
    sed -i "s|\$NGINX_LOG_DIR|$NGINX_LOG_DIR|g" "$NGINX_DIR"/nginx.conf && \
    mkdir -p "$NGINX_SSL_DIR" && \
    wget -O "$NGINX_SSL_DIR"/ssl.conf https://raw.githubusercontent.com/ClubNix/Reverse-Proxy-Manager/master/docker/ssl.conf && \
    sed -i "s|COUNTRY|$SSL_COUNTRY|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|STATE|$SSL_STATE|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|LOCATION|$SSL_CITY|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|ORGANIZATION|$SSL_ORG|g" "$NGINX_SSL_DIR"/ssl.conf && \
    sed -i "s|ORGANIZATION-UNIT|$SSL_OU|g" "$NGINX_SSL_DIR"/ssl.conf && \
    # Get manager script \
    wget -O /root/manager.sh https://raw.githubusercontent.com/ClubNix/Reverse-Proxy-Manager/master/docker/manager.sh && \
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