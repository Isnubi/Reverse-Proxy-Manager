from flask import Blueprint, render_template, request, send_from_directory
import logging
import os
import subprocess
from typing import Dict, Any
import shutil
import time
import socket


logger = logging.getLogger(__name__)
bp = Blueprint('manager', __name__, url_prefix='/manager')


class ReverseProxyManager:
    def __init__(self):
        self.real_conf_path = '/etc/nginx/conf.d'
        self.real_ssl_path = '/etc/nginx/certs'
        self.real_log_path = '/var/log/nginx'
        self.app_conf_path = '/app/nginx/conf.d'
        self.app_ssl_path = '/app/nginx/certs'
        self.app_log_path = '/app/nginx/logs'
        self.app_scripts_path = '/app/scripts'
        self.app_nginx_path = '/app/nginx'

    def reload_nginx(self):
        with open(f'{self.app_scripts_path}/reload_nginx', 'w') as f:
            f.write('reload')

    def address_check(self, server: str, service_type: str) -> bool:
        try:
            if ':' in server:
                host, port = server.split(':')
                if not 1 <= int(port) <= 65535:
                    return False
            else:
                host = server
                port = 80 if service_type == 'http' else 443
            socket.create_connection((host, port), timeout=5)
            return True
        except Exception as e:
            logger.error(f'Address check failed: {e}')
            return False

    def get_conf_list(self):
        conf_list = []
        for conf in os.listdir(self.app_conf_path):
            conf_list.append(conf)
        return conf_list

    def get_conf(self, conf_name: str):
        with open(f'{self.app_conf_path}/{conf_name}', 'r') as f:
            return f.read().strip()

    def get_conf_infos(self, conf_name: str) -> Dict[str, Any]:
        with open(f'{self.app_conf_path}/{conf_name}', 'r') as f:
            conf = f.read()
        infos = {
            'name': conf_name,
            'server_name': conf.split('server_name ')[1].split(';')[0],
            'server': conf.split('proxy_pass ')[1].split(';')[0]
        }
        return infos

    def get_ssl_conf(self) -> Dict[str, str]:
        conf = {}
        with open(f'{self.app_ssl_path}/ssl.conf', 'r') as f:
            for line in f.readlines():
                if '=' in line:
                    key, value = line.split('=')
                    conf[key.strip()] = value.strip()
        return conf

    def edit_conf(self, conf_name: str, conf_content: str):
        with open(f'{self.app_conf_path}/{conf_name}', 'w') as f:
            f.write(conf_content.strip() + '\n')
        self.reload_nginx()

    def create_conf(self, domain: str, server: str, description: str, service_type: str):
        conf = f"""
map $http_upgrade $connection_upgrade {{
    default upgrade;
    '' close;
}}

# {description}
server {{
    listen 80;
    server_name {domain};
    return 301 https://$host$request_uri;
}}
server {{
    listen 443 ssl;

    ssl_certificate {self.real_ssl_path}/{domain}.crt;
    ssl_certificate_key {self.real_ssl_path}/{domain}.key;

    server_name {domain};

    error_log {self.real_log_path}/{domain}/error.log;
    access_log {self.real_log_path}/{domain}/access.log;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    add_header Referrer-Policy "no-referrer";
    add_header Access-Control-Allow-Origin "{self.get_ssl_conf().get('ALLOW-ORIGIN')[1:-1]}";
    add_header Cross-Origin-Embedder-Policy "require-corp";
    add_header Cross-Origin-Opener-Policy "same-origin";
    add_header Cross-Origin-Resource-Policy "same-site";

    add_header Permissions-Policy ();
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https: http:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'";

    proxy_cookie_flags ~ secure httponly samesite=strict;

    location / {{
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Scheme \$scheme;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;

        proxy_pass {service_type}://{server};
    }}
}}
"""
        os.makedirs(f'{self.app_log_path}/{domain}', exist_ok=True)
        with open(f'{self.app_conf_path}/{domain}.conf', 'w') as f:
            f.write(conf)
        self.reload_nginx()

    def generate_ssl(self, domain: str):
        ssl_conf = self.get_ssl_conf()

        ext_cnf_path = f'{self.app_ssl_path}/{domain}.ext.cnf'
        with open(ext_cnf_path, 'w') as f:
            f.write(f"""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = {ssl_conf['COUNTRY']}
ST = {ssl_conf['STATE']}
L = {ssl_conf['LOCATION']}
O = {ssl_conf['ORGANIZATION-GLOBAL']}
OU = {ssl_conf['ORGANIZATION-UNIT']}
[v3_req]
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = {domain}
""")
            subprocess.run([
                'openssl', 'req', '-new', '-newkey', 'rsa:4096', '-sha256', '-days', ssl_conf['DAYS'], '-nodes', '-x509',
                '-keyout', f'{self.app_ssl_path}/{domain}.key',
                '-out', f'{self.app_ssl_path}/{domain}.crt',
                '-subj', f"/C={ssl_conf['COUNTRY']}/ST={ssl_conf['STATE']}/L={ssl_conf['LOCATION']}/O={ssl_conf['ORGANIZATION-GLOBAL']}/OU={ssl_conf['ORGANIZATION-UNIT']}/CN={domain}",
                '-config', ext_cnf_path
            ], check=True)
            os.remove(ext_cnf_path)

    def remove_conf(self, conf_name: str):
        os.remove(f'{self.app_conf_path}/{conf_name}.conf')
        os.remove(f'{self.app_ssl_path}/{conf_name}.crt')
        os.remove(f'{self.app_ssl_path}/{conf_name}.key')
        os.remove(f'{self.app_log_path}/{conf_name}')
        self.reload_nginx()

    def backup_nginx(self):
        backup_dir = f'{self.app_scripts_path}/nginx_backup_{time.strftime("%Y%m%d%H%M%S")}'
        shutil.copytree(self.app_nginx_path, backup_dir)
        return backup_dir


@bp.route('/manage', methods=['GET', 'POST'])
def manage():
    handler = ReverseProxyManager()
    if request.method == 'POST':
        if 'new_conf' in request.form:
            new_conf = request.form['new_conf']
            conf_name = request.form['conf_name']
            handler.edit_conf(conf_name, new_conf.replace('\r\n', '\n'))
            conf_list = handler.get_conf_list()
            return render_template('manage.html', conf_list=conf_list)

        action = request.form['action']
        conf_name = request.form['conf']
        conf_content = handler.get_conf(conf_name)
        conf_list = handler.get_conf_list()

        if action == 'view':
            conf_infos = handler.get_conf_infos(conf_name)
            return render_template('manage.html', conf_list=conf_list, conf_infos=conf_infos)
        elif action == 'delete':
            handler.remove_conf(conf_name)
            conf_list = handler.get_conf_list()
            return render_template('manage.html', conf_list=conf_list)
        elif action == 'edit':
            return render_template('manage.html', conf_list=conf_list, conf_edit=conf_content, conf_name=conf_name)
    else:
        conf_list = handler.get_conf_list()
        return render_template('manage.html', conf_list=conf_list)


@bp.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        domain = request.form['domain']
        server = request.form['server']
        description = request.form['description']
        service_type = request.form['service_type']

        handler = ReverseProxyManager()
        handler.generate_ssl(domain)
        handler.create_conf(domain, server, description, service_type)

        return render_template('create.html')
    else:
        return render_template('create.html')

@bp.route('/backup', methods=['GET'])
def backup():
    handler = ReverseProxyManager()
    backup_dir = handler.backup_nginx()
    return send_from_directory(directory=backup_dir, filename='nginx.zip', as_attachment=True)
