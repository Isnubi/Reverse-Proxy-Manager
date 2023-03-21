#!/usr/bin/env bash
#==========================================================================================
#
# SCRIPT NAME        :     Reverse-Proxy-Manager.sh
#
# AUTHOR             :     Louis GAMBART
# CREATION DATE      :     2023.03.20
# RELEASE            :     v1.1.1
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
Green='\033[0;32m '     # Green


####################
#                  #
#  II - VARIABLES  #
#                  #
####################

NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_VAR_DIR="/var/log/nginx"
NGINX_CERT="/etc/nginx/certs/certificat.crt"
NGINX_KEY="/etc/nginx/certs/certificat.key"


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

    # check if service already exists
    if [ -f $NGINX_CONF_DIR/"$2".conf ]; then
        echo -e "${Red}Service already exists${No_Color}"
        exit
    fi

    # check if https
    if [ "$4" = 'y' ]; then
        service_type="https"
    elif [ "$4" = 'n' ]; then
        service_type="http"
    fi

    # create log dir
    mkdir -p $NGINX_VAR_DIR/"$2"

    # create conf file
    cat >> $NGINX_CONF_DIR/"$2".conf <<EOF
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

    ssl_certificate $NGINX_CERT;
    ssl_certificate_key $NGINX_KEY;

    server_name $2;

    error_log $NGINX_VAR_DIR/$2/error.log;
    access_log $NGINX_VAR_DIR/$2/access.log;

    location / {
        proxy_pass $service_type://$3;
    }
}
EOF
    echo -e "${Green}Service $1 added to reverse proxy${No_Color}"
    echo -e "${Yellow}Restarting nginx...${No_Color}"
    systemctl restart nginx
    echo -e "${Green}Done!${No_Color}"
    echo "If you want to add options to the service, edit the file $NGINX_CONF_DIR/$2.conf"
}


remove_service () {
    # Remove a service from the reverse proxy
    # :param $1: server name

    # check if service exists
    if [ ! -f $NGINX_CONF_DIR/"$1".conf ]; then
        echo -e "${Red}Service does not exist${No_Color}"
        exit
    fi

    # remove conf file and log dir
    rm $NGINX_CONF_DIR/"$1".conf
    # shellcheck disable=SC2115
    rm -rf $NGINX_VAR_DIR/"$1"

    echo -e "${Green}Service $1 removed from reverse proxy${No_Color}"
    echo -e "${Yellow}Restarting nginx...${No_Color}"
    systemctl restart nginx
    echo -e "${Green}Done!${No_Color}"
}


list_services () {
    # List all services in the reverse proxy

    for file in "$NGINX_CONF_DIR"/*.conf; do
        echo -e "${Green}$(basename "$file" .conf)${No_Color}"
        server_ip=$(grep -oP '(?<=proxy_pass ).*(?=;)' "$file")
        echo -e "  IP: ${Green}$server_ip${No_Color}"
    done
}


#####################
#                   #
#  IV - ROOT CHECK  #
#                   #
#####################

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${Red}Please run as root${No_Color}"
    exit
fi


#####################
#                   #
#  V - NGINX CHECK  #
#                   #
#####################

if [ ! -f /etc/nginx/nginx.conf ]; then
    echo -e "${Red}Nginx is not installed${No_Color}"
    exit
fi


#####################
#                   #
#  VI - TEST PATHS  #
#                   #
#####################

if [ ! -d $NGINX_CONF_DIR ]; then
    echo -e "${Red}Nginx conf dir does not exist${No_Color}"
    exit
fi
if [ ! -d $NGINX_VAR_DIR ]; then
    echo -e "${Red}Nginx log dir does not exist${No_Color}"
    exit
fi
if [ ! -f $NGINX_CERT ]; then
    echo -e "${Red}Nginx certificate does not exist${No_Color}"
    exit
fi


#######################
#                     #
#  VII - MAIN SCRIPT  #
#                     #
#######################

PS3='Please enter your choice: '
select option in "Add service" "Remove service" "List services" "Exit"; do
    case $option in
        "Add service")
            read -r -p "Enter server name like service.clubnix.fr: " server_name
            read -r -p "Enter IP address of the server and the port if necessary: " server_ip
            read -r -p "Enter the service name: " service_name
            read -r -p "Is the service a https service? [y/n]: " https
            add_service "$service_name" "$server_name" "$server_ip" "$https"
            break
            ;;
        "Remove service")
            #list services
            echo -e "${Yellow}Listing services...${No_Color}"
            echo ""
            find $NGINX_CONF_DIR -type f -name "*.conf" -exec basename {} .conf \; | sed 's/.conf//g'
            echo ""
            read -r -p "Enter server name to remove: " server_name
            remove_service "$server_name"
            break
            ;;
        "List services")
            echo -e "${Yellow}Listing services...${No_Color}"
            echo ""
            list_services
            echo ""
            break
            ;;
        "Exit")
            break
            ;;
        *)
            echo -e "${Red}Invalid option ${No_Color} $REPLY"
            ;;
    esac
done