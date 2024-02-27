#!/usr/bin/env bash
#==========================================================================================
#
# SCRIPT NAME        :     Reverse-Proxy-Manager.sh
#
# AUTHOR             :     Louis GAMBART
# CREATION DATE      :     2023.03.20
# RELEASE            :     1.7.1
# USAGE SYNTAX       :     .\Reverse-Proxy-Manager.sh
#
# SCRIPT DESCRIPTION :     This script is used to manage a reverse proxy configuration for nginx
#
#==========================================================================================
#
#                 - RELEASE NOTES -
# v1.0.0  2023.03.20 - Louis GAMBART - Initial version
# v1.0.1  2023.03.20 - Louis GAMBART - Add colors to the script output
# v1.0.2  2023.03.20 - Louis GAMBART - Add comments to the functions
# v1.0.3  2023.03.20 - Louis GAMBART - Code cleaning
# v1.0.4  2023.03.20 - Louis GAMBART - Add checks for root user
# v1.0.5  2023.03.20 - Louis GAMBART - Add check for service before creation/removal
# v1.0.6  2023.03.20 - Louis GAMBART - Add check for nginx and test paths
# v1.0.7  2023.03.21 - Louis GAMBART - Correct https check
# v1.0.8  2023.03.21 - Louis GAMBART - Add list services function and list option
# v1.1.0  2023.03.21 - Louis GAMBART - Add -r option to read command to avoid backslash interpretation following SC2162
# v1.1.1  2023.03.21 - Louis GAMBART - Usage of find instead of ls to list services following SC2012
# v1.1.2  2023.03.21 - Louis GAMBART - Add bad input option for https check
# v1.1.3  2023.03.21 - Louis GAMBART - Add check for nginx private key
# v1.2.0  2023.03.21 - Louis GAMBART - Add installing option to nginx check
# v1.2.1  2023.03.21 - Louis GAMBART - Add apt update when installing nginx
# v1.2.2  2023.03.21 - Louis GAMBART - Fix nginx installation (txt + color in read command)
# v1.2.3  2023.03.21 - Louis GAMBART - Add exit when no services are found for remove and list options
# v1.2.4  2023.03.21 - Louis GAMBART - Add check to avoid duplicate services
# v1.2.5  2023.03.22 - Louis GAMBART - Add subjects for ssl certificate generation
# v1.2.6  2023.03.22 - Louis GAMBART - Add confirmation before removing a service and fix SC2115 error
# v1.3.0  2023.03.22 - Louis GAMBART - Add IP address check for service creation (ip and port)
# v1.3.1  2023.03.22 - Louis GAMBART - Add read instructions for certificate generation
# v1.3.2  2023.03.22 - Louis GAMBART - Add sed to don't push nginx version in http header
# v1.4.0  2023.04.20 - Louis GAMBART - Rework of the script to include security options (check modifications in the commit)
# v1.4.1  2023.04.20 - Louis GAMBART - Add reverse uninstall option
# v1.5.0  2023.05.14 - Louis GAMBART - Add check on server_name to validate FQDn
# v1.5.1  2023.05.14 - Louis GAMBART - Add echo in the script
# v1.5.2  2023.05.14 - Louis GAMBART - Fix dir check for nginx SSL dir instead of unique cert/key
# v1.5.3  2023.05.18 - Louis GAMBART - Fix bug in uninstall option
# v1.5.4  2023.07.01 - Louis GAMBART - Add help and version options
# v1.5.5  2023.07.01 - Louis GAMBART - Remove useless variable
# v1.5.6  2023.07.03 - Louis GAMBART - Add root check to prevent run via sudo
# v1.5.7  2023.07.03 - Louis GAMBART - Add code to exit command
# v1.6.0  2023/11/02 - Louis GAMBART - Add color to output
# v1.6.1  2023/11/02 - Louis GAMBART - Redirect output to /dev/null to avoid output in the terminal during installation
# v1.7.0  2024/02/27 - Louis GAMBART - Replace ngx_http_cookie_flag_module with the built-in directive
# v1.7.1  2024/02/27 - Louis GAMBART - Add custom Allow-Origin directive
#
#==========================================================================================


#####################
#                   #
#  I - COLOR CODES  #
#                   #
#####################

No_Color='\033[0m'      # No Color
Red='\033[0;31m'        # Red
Yellow='\033[0;33m'     # Yellow
Green='\033[0;32m'     # Green
Blue='\033[0;34m'       # Blue


####################
#                  #
#  II - VARIABLES  #
#                  #
####################

NGINX_DIR="/etc/nginx"
NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_VAR_DIR="/var/log/nginx"
NGINX_SSL_DIR="/etc/nginx/certs"
SCRIPT_NAME="Reverse-Proxy-Manager.sh"


#####################
#                   #
#  III - FUNCTIONS  #
#                   #
#####################

add_service () {
    # Add a service to the reverse proxy
    # :param $1: service name
    # :param $2: server name
    # :param $3: server ip
    # :param $4: is https

    echo -e -n "\n${Yellow}Adding service $1 to reverse proxy...${No_Color}"

    # check if https
    if [ "$4" = 'y' ]; then
        service_type="https"
    elif [ "$4" = 'n' ]; then
        service_type="http"
    else
        echo -e " ${Red} ERR - Invalid input for https/http${No_Color}"
        exit 1
    fi

    # create ssl certificate
    Country=$(grep COUNTRY "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    State=$(grep STATE "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    Location=$(grep LOCATION "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    Orga=$(grep ORGANIZATION-GLOBAL "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    OrgaUnit=$(grep ORGANIZATION-UNIT "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    Days=$(grep DAYS "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)
    AllowOrigin=$(grep ALLOW-ORIGIN "$NGINX_SSL_DIR/ssl.conf" | cut -d "=" -f2)

    {
        echo "[req]"
        echo "distinguished_name = req_distinguished_name"
        echo "x509_extensions = v3_req"
        echo "prompt = no"
        echo "[req_distinguished_name]"
        echo "C = $Country"
        echo "ST = $State"
        echo "L = $Location"
        echo "O = $Orga"
        echo "OU = $OrgaUnit"
        echo "[v3_req]"
        echo "keyUsage = critical, digitalSignature, keyAgreement"
        echo "extendedKeyUsage = serverAuth"
        echo "subjectAltName = @alt_names"
        echo "[alt_names]"
        echo "DNS.1 = $2"
    } >> "$NGINX_SSL_DIR"/"$2".ext.cnf

    openssl req -new -newkey rsa:4096 -sha256 -days "$Days" -nodes -x509 -keyout "$NGINX_SSL_DIR"/"$2".key -out "$NGINX_SSL_DIR"/"$2".crt -subj "/C=$Country/ST=$State/L=$Location/O=$Orga/OU=$OrgaUnit/CN=$2" -config "$NGINX_SSL_DIR"/"$2".ext.cnf > /dev/null 2>&1
    rm "$NGINX_SSL_DIR"/"$2".ext.cnf

    # create log dir
    mkdir -p "$NGINX_VAR_DIR"/"$2"

    # create conf file
    cat >> "$NGINX_CONF_DIR"/"$2".conf <<EOF
map \$http_upgrade \$connection_upgrade {
	default upgrade;
	'' close;
}

# $1
server {
    listen 80;
    server_name $2;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;

    ssl_certificate $NGINX_SSL_DIR/$2.crt;
    ssl_certificate_key $NGINX_SSL_DIR/$2.key;

    server_name $2;

    error_log $NGINX_VAR_DIR/$2/error.log;
    access_log $NGINX_VAR_DIR/$2/access.log;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    add_header Referrer-Policy "no-referrer";
    add_header Access-Control-Allow-Origin "$AllowOrigin";
    add_header Cross-Origin-Embedder-Policy "require-corp";
    add_header Cross-Origin-Opener-Policy "same-origin";
    add_header Cross-Origin-Resource-Policy "same-site";

    add_header Permissions-Policy ();
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https: http:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'";

    proxy_cookie_flags ~ secure httponly samesite=strict;

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Scheme \$scheme;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;

        proxy_pass $service_type://$3;
    }
}
EOF
    echo -e "${Green} OK${No_Color}"
    echo -e -n "${Yellow}Restarting nginx...${No_Color}"
    systemctl restart nginx
    echo -e "${Green} OK${No_Color}\n"
    echo -e "If you want to add options to the service, use the following command: ${Blue}nano $NGINX_CONF_DIR/$2.conf${No_Color}"
    echo -e "You can find the certificate and the private key in the following directory: ${Blue}$NGINX_SSL_DIR${No_Color}"
}


remove_service () {
    # Remove a service from the reverse proxy
    # :param $1: server name

    # check if service exists
    echo -e -n "${Yellow}Checking if service exists...${No_Color}"

    if [ ! -f $NGINX_CONF_DIR/"$1".conf ]; then
        echo -e "${Red} Service does not exist${No_Color}"
        return
    fi
    echo -e "${Green} OK${No_Color}"

    echo -e "${Yellow}You are about to remove the service $1 from the reverse proxy${No_Color}"
    read -r -p "Are you sure? [y/n] " removal_confirmation
    if [ "$removal_confirmation" = 'y' ]; then
        rm -rf "${NGINX_CONF_DIR:?}/$1".conf
        rm -rf "${NGINX_VAR_DIR:?}/$1"
        rm -rf "${NGINX_SSL_DIR:?}/$1".crt
        rm -rf "${NGINX_SSL_DIR:?}/$1".key

        echo -e "${Green}Service $1 removed from reverse proxy${No_Color}"
        echo -e -n "${Yellow}Restarting nginx...${No_Color}"
        systemctl restart nginx
        echo -e "${Green} OK${No_Color}"
    elif [ "$removal_confirmation" = 'n' ]; then
        echo -e "${Green}Service $1 not removed from reverse proxy${No_Color}"
        return
    else
        echo -e "${Red} ERR - Invalid input${No_Color}"
        return
    fi
}


list_services () {
    # List all services in the reverse proxy

    echo -e -n "\n${Yellow}Listing services...${No_Color}"

    for file in "$NGINX_CONF_DIR"/*.conf; do
        if [ ! -f "$file" ]; then
            echo -e "${Red} No services found${No_Color}"
            exit 1
        fi
        echo -e "${Green} OK${No_Color}"
        echo -e "${Green}$(basename "$file" .conf)${No_Color}"
        server_ip=$(grep -oP '(?<=proxy_pass ).*(?=;)' "$file")
        echo -e "  IP: ${Green}$server_ip${No_Color}"
    done
}


check_service () {
    # Check if a service is already in the reverse proxy
    # :param $1: service name
    # :return: 0 if exists, 1 if not

    if [ -f "$NGINX_CONF_DIR"/"$1".conf ]; then
        return 0
    else
        return 1
    fi
}


install_nginx () {
    # Install nginx and generate a self-signed certificate

    echo -e -n "\n${Yellow}Check if internet is available...${No_Color}"
    if ! ping -c 1 google.com > /dev/null 2>&1; then
        echo -e "${Red} ERR - No internet connection${No_Color}"
        exit 1
    else
        echo -e "${Green} OK${No_Color}"
    fi

    echo -e -n "\n${Yellow}Installing nginx...${No_Color}"
    apt update > /dev/null 2>&1
    apt install nginx ca-certificates wget git libpcre3 libpcre3-dev -y > /dev/null 2>&1
    echo -e "${Green} OK${No_Color}"

    echo -e -n "${Yellow}Configuring nginx...${No_Color}"
    mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

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

    include /etc/nginx/mime.types;
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

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    ##
    # Gzip Settings
    ##

    gzip off;

    ##
    # Virtual Host Configs
    ##

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    echo -e "${Green} OK${No_Color}"

    mkdir -p "$NGINX_SSL_DIR"
    echo -e "\n${Yellow}Enter your information for the SSL certificate${No_Color}"
    read -r -p "Country code: " C
    read -r -p "State: " ST
    read -r -p "Location: " L
    read -r -p "Organization: " O
    read -r -p "Organization unit: " OU
    read -r -p "Certificate validity (in days): " DAYS
    read -r -p "Domain for Access-Control-Allow-Origin directive (default: *): " ALLOW_ORIGIN
    {
        echo "COUNTRY=$C"
        echo "STATE=$ST"
        echo "LOCATION=$L"
        echo "ORGANIZATION-GLOBAL=$O"
        echo "ORGANIZATION-UNIT=$OU"
        echo "DAYS=$DAYS"
        echo "ALLOW-ORIGIN=${ALLOW_ORIGIN:-*}"
    } >> "$NGINX_SSL_DIR"/ssl.conf

    echo -e -n "\n${Yellow}Deactivate nginx default configuration...${No_Color}"
    rm /etc/nginx/sites-enabled/default
    echo -e "${Green} OK${No_Color}"

    echo -e -n "\n${Yellow}Restarting nginx...${No_Color}"
    systemctl restart nginx
    echo -e "${Green} OK${No_Color}"
}


backup_nginx () {
    # Backup nginx configuration
    tar -czf ./nginx_backup.tar.gz /etc/nginx > /dev/null 2>&1
}


uninstall_nginx () {
    # Uninstall nginx
    apt autoremove --purge nginx openssl wget git libpcre3 libpcre3-dev -y > /dev/null 2>&1
    rm -Rf "$NGINX_DIR"
    rm -Rf "$NGINX_VAR_DIR"
}


address_check () {
    # Check if the address is valid
    # :param $1: address
    # :return: 0 if valid, 1 if not

    #check if : in $1
    if [[ $1 =~ .*":".* ]]; then
        address=${1%:*}
        port=${1#*:}
        if [[ "$address" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$ ]] && [[ "$port" -ge 0 ]] && [[ "$port" -le 65536 ]]; then
            return 0
        else
            return 1
        fi
    else
        if [[ "$1" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$ ]]; then
            return 0
        else
            return 1
        fi
    fi
}


print_help () {
    # Print help message
    echo -e """
    ${Green} SYNOPSIS
        ${SCRIPT_NAME} [-hv]

     DESCRIPTION
        This script is used to manage a nginx reverse proxy. The script will also install nginx if it is not installed.

     OPTIONS
        -h, --help         Print the help message
        -v, --version      Print the script version
    ${No_Color}
    """
}


print_version () {
    # Print version message
    echo -e """
    ${Green}
    version       ${SCRIPT_NAME} 1.7.1
    author        Louis GAMBART (https://louis-gambart.fr)
    license       GNU GPLv3.0
    script_id     0
    """
}


#########################
#                       #
#  IV - SCRIPT OPTIONS  #
#                       #
#########################

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -h|--help)
            print_help
            exit 0
            ;;
        -v|--version)
            print_version
            exit 0
            ;;
        *)
            echo -e "${Red}Unknown option: $key${No_Color}"
            print_help
            exit 0
            ;;
    esac
    shift
done


####################
#                  #
#  V - ROOT CHECK  #
#                  #
####################

echo -e -n "${Yellow}Checking if you are root...${No_Color}"
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${Red} ERR - Please run the script as root${No_Color}"
    exit 1
elif [[ -n ${SUDO_USER} ]]; then
    echo -e "${Red} ERR - Please run the script as root, without SUDO user${No_Color}"
    exit 1
else
    echo -e "${Green} OK${No_Color}"
fi


######################
#                    #
#  VI - NGINX CHECK  #
#                    #
######################

echo -e -n "${Yellow}Checking if nginx is installed...${No_Color}"
if ! nginx -v > /dev/null 2>&1; then
    echo -e "${Red} Nginx is not installed${No_Color}"
    read -r -p "    * Do you want to install nginx? [y/n]: " install_nginx
    if [ "$install_nginx" = 'y' ]; then
        install_nginx
        echo -e "\n${Green}Nginx installed. You can now run this script again.${No_Color}"
        exit 0
    elif [ "$install_nginx" = 'n' ]; then
        echo -e "${Red}Nginx is required to run this script${No_Color}"
        exit 0
    else
        echo -e "${Red}Invalid input${No_Color}"
        exit 1
    fi
else
    echo -e "${Green} OK${No_Color}"
fi


######################
#                    #
#  VII - TEST PATHS  #
#                    #
######################

echo -e -n "${Yellow}Checking if nginx necessary paths exist...${No_Color}"
if [ ! -d "$NGINX_CONF_DIR" ]; then
    echo -e "${Red} ERR - Nginx conf dir does not exist${No_Color}"
    exit 1
fi
if [ ! -d "$NGINX_VAR_DIR" ]; then
    echo -e "${Red} ERR - Nginx log dir does not exist${No_Color}"
    exit 1
fi
if [ ! -d "$NGINX_SSL_DIR" ]; then
    echo -e "${Red} ERR - Nginx ssl dir does not exist${No_Color}"
    exit 1
fi
echo -e "${Green} OK${No_Color}\n"


########################
#                      #
#  VIII - MAIN SCRIPT  #
#                      #
########################

PS3='Please enter your choice: '
select option in "Add service" "Remove service" "List services" "Backup nginx" "Uninstall" "Exit"; do
    case $option in
        "Add service")
            echo ""
            read -r -p "Enter server name like service.clubnix.fr: " server_name
            result=$(echo "$server_name" | grep -P '(?=^.{1,254}$)(^(?>(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)')
            if [[ -z "$server_name" ]]; then
                echo -e "${Red}No server name entered${No_Color}"
                break
            elif [[ -z "$result" ]]; then
                echo -e "${Red}Invalid server name${No_Color}"
                break
            elif check_service "$server_name"; then
                echo -e "${Red}Service already exists${No_Color}"
                break
            fi
            read -r -p "Enter IP address of the server and the port if necessary: " server_ip
            if ! address_check "$server_ip"; then
                echo -e "${Red}Invalid address${No_Color}"
                break
            fi
            read -r -p "Enter the service name: " service_name
            read -r -p "Is the service a https service? [y/n]: " https
            add_service "$service_name" "$server_name" "$server_ip" "$https"
            break
            ;;
        "Remove service")
            list_services
            echo ""
            read -r -p "Enter server name to remove: " server_name
            remove_service "$server_name"
            break
            ;;
        "List services")
            list_services
            break
            ;;
        "Backup nginx")
            echo -e -n "\n${Yellow}Backing up nginx...${No_Color}"
            backup_nginx
            echo -e "${Green} OK${No_Color}"
            break
            ;;
        "Uninstall")
            echo ""
            read -r -p "Are you sure you want to uninstall nginx? [y/n]: " uninstall
            if [ "$uninstall" = 'y' ]; then
                echo -e -n "${Yellow}Backing up nginx...${No_Color}"
                backup_nginx
                echo -e "${Green} OK${No_Color}"

                echo -e -n "${Yellow}Uninstalling nginx...${No_Color}"
                uninstall_nginx
                echo -e "${Green} OK${No_Color}"
                break
            elif [ "$uninstall" = 'n' ]; then
              echo -e "${Green}Nginx not uninstalled${No_Color}"
                break
            else
                echo -e "${Red}Invalid input${No_Color}"
                break
            fi
            ;;
        "Exit")
            break
            ;;
        *)
            echo -e "${Red}Invalid option${No_Color} $REPLY"
            break
            ;;
    esac
done
