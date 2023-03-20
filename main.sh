#!/usr/bin/env bash
#==========================================================================================
#
# SCRIPT NAME        :     Reverse-Proxy-Manager.sh
#
# AUTHOR             :     Louis GAMBART
# CREATION DATE      :     2023.03.20
# RELEASE            :     v1.0.3
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
#
#==========================================================================================


#####################
#                   #
#  I - COLOR CODES  #
#                   #
#####################

No_Color='\033[0m'      # No Color||et m
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
    if [ "$4" = true ]; then
        service_type="https"
    else
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
    rm -rf $NGINX_VAR_DIR/"$1"

    echo -e "${Green}Service $1 removed from reverse proxy${No_Color}"
    echo -e "${Yellow}Restarting nginx...${No_Color}"
    systemctl restart nginx
    echo -e "${Green}Done!${No_Color}"
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
#  V - MAIN SCRIPT  #
#                   #
#####################

PS3='Please enter your choice: '
select option in "Add service" "Remove service" "Exit"; do
    case $option in
        "Add service")
            read -p "Enter server name like service.clubnix.fr: " server_name
            read -p "Enter IP address of the server and the port if necessary: " server_ip
            read -p "Enter the service name: " service_name
            read -p "Is the service a https service? [y/n]: " https
            add_service "$service_name" "$server_name" "$server_ip" "$https"
            break
            ;;
        "Remove service")
            #list services
            echo "List of services:"
            echo ""
            ls $NGINX_CONF_DIR | sed 's/.conf//g'
            echo ""
            read -p "Enter server name to remove: " server_name
            remove_service "$server_name"
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