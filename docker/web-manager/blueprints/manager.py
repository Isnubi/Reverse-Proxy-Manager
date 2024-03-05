import flask
from flask import Blueprint, render_template, request, send_from_directory, send_file
import logging
import os
import subprocess
from typing import Dict, Any
import shutil
import re
import tarfile

logger = logging.getLogger(__name__)
bp = Blueprint('manager', __name__, url_prefix='/manager')


class ReverseProxyManager:
    def __init__(self) -> None:
        self.real_conf_path = '/etc/nginx/conf.d'
        self.real_ssl_path = '/etc/nginx/certs'
        self.real_log_path = '/var/log/nginx'
        self.app_conf_path = '/app/nginx/conf.d'
        self.app_ssl_path = '/app/nginx/certs'
        self.app_log_path = '/app/nginx/logs'
        self.app_scripts_path = '/app/scripts'
        self.app_nginx_path = '/app/nginx'
        self.ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    def reload_nginx(self) -> None:
        with open(f'{self.app_scripts_path}/reload_nginx', 'w') as f:
            f.write('reload')

    def address_check(self, server: str) -> bool:
        if ':' in server:
            host, port = server.split(':')
            try:
                if not 1 <= int(port) <= 65535:
                    return False
            except ValueError:
                return False
        else:
            host = server
        ip_pattern = self.ip_pattern
        if not re.match(ip_pattern, host):
            return False
        return True

    def get_conf_list(self) -> list:
        conf_list = []
        for conf in os.listdir(self.app_conf_path):
            conf_list.append(conf[:-5])
        return sorted(conf_list)

    def get_conf(self, conf_name: str) -> str:
        with open(f'{self.app_conf_path}/{conf_name}.conf', 'r') as f:
            return f.read().strip()

    def get_conf_infos(self, conf_name: str) -> Dict[str, Any]:
        with open(f'{self.app_conf_path}/{conf_name}.conf', 'r') as f:
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

    def edit_conf(self,
                  conf_name: str,
                  conf_content: str,
                  cert_path: str = None,
                  key_path: str = None) -> None:
        with open(f'{self.app_conf_path}/{conf_name}.conf', 'w') as f:
            f.write(conf_content.replace('\r\n', '\n').strip() + '\n')

        if cert_path and key_path:
            shutil.copy(cert_path, f'{self.app_ssl_path}/{conf_name}.crt')
            shutil.copy(key_path, f'{self.app_ssl_path}/{conf_name}.key')
            os.remove(cert_path)
            os.remove(key_path)

        self.reload_nginx()

    def create_conf(self,
                    domain: str,
                    server: str,
                    description: str,
                    service_type: str,
                    allow_origin: str = '*',
                    cert_path: str = None,
                    key_path: str = None) -> None:
        conf = rf"""
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
        add_header Access-Control-Allow-Origin "{allow_origin}";
        add_header Cross-Origin-Embedder-Policy "require-corp";
        add_header Cross-Origin-Opener-Policy "same-origin";
        add_header Cross-Origin-Resource-Policy "same-site";

        add_header Permissions-Policy ();
        add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https: http:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'";

        proxy_cookie_flags ~ secure httponly samesite=strict;

        location / {{
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Scheme $scheme;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;
    
            proxy_pass {service_type}://{server};
        }}
    }}
    """
        os.makedirs(f'{self.app_log_path}/{domain}', exist_ok=True)
        with open(f'{self.app_conf_path}/{domain}.conf', 'w') as f:
            f.write(conf)

        if cert_path and key_path:
            shutil.copy(cert_path, f'{self.app_ssl_path}/{domain}.crt')
            shutil.copy(key_path, f'{self.app_ssl_path}/{domain}.key')
            os.remove(cert_path)
            os.remove(key_path)
        else:
            self.generate_ssl(domain)

        self.reload_nginx()

    def generate_ssl(self, domain: str) -> None:
        ssl_conf = self.get_ssl_conf()

        ext_cnf_path = f'{self.app_ssl_path}/{domain}.ext.cnf'
        with open(ext_cnf_path, 'w') as f:
            f.write(rf"""
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
                'openssl', 'req', '-new', '-newkey', 'rsa:4096', '-sha256', '-days',
                ssl_conf['DAYS'], '-nodes', '-x509', '-keyout', f'{self.app_ssl_path}/{domain}.key',
                '-out', f'{self.app_ssl_path}/{domain}.crt',
                '-subj', f"/C={ssl_conf['COUNTRY']}/ST={ssl_conf['STATE']}/L={ssl_conf['LOCATION']}"
                         f"/O={ssl_conf['ORGANIZATION-GLOBAL']}/OU={ssl_conf['ORGANIZATION-UNIT']}/CN={domain}",
                '-config', ext_cnf_path
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            os.remove(ext_cnf_path)

    def remove_conf(self, conf_name: str) -> None:
        os.remove(f'{self.app_conf_path}/{conf_name}.conf')
        os.remove(f'{self.app_ssl_path}/{conf_name}.crt')
        os.remove(f'{self.app_ssl_path}/{conf_name}.key')
        shutil.rmtree(f'{self.app_log_path}/{conf_name}', ignore_errors=True)
        self.reload_nginx()

    def backup_nginx(self) -> None:
        with tarfile.open(f'{self.app_scripts_path}/nginx.tar.gz', 'w:gz') as tar:
            tar.add(self.app_nginx_path, arcname=os.path.basename(self.app_nginx_path))

    def handle_cert_key_upload(self, conf_name: str, form_request: flask.Request) -> tuple[Any, Any]:
        cert = form_request.files['cert'] if 'cert' in form_request.files else None
        key = form_request.files['key'] if 'key' in form_request.files else None
        cert_text = form_request.form['cert_text'] if 'cert_text' in form_request.form else None
        key_text = form_request.form['key_text'] if 'key_text' in form_request.form else None

        tmp_cert_path = f'{self.app_scripts_path}/{conf_name}.crt'
        tmp_key_path = f'{self.app_scripts_path}/{conf_name}.key'

        if (not cert and key) or (not cert_text and key_text):
            tmp_cert_path = tmp_key_path = None
        elif cert and key:
            cert.save(tmp_cert_path)
            key.save(tmp_key_path)
        elif cert_text and key_text:
            with open(tmp_cert_path, 'w') as f:
                f.write(cert_text)
            with open(tmp_key_path, 'w') as f:
                f.write(key_text)
        else:
            tmp_cert_path = tmp_key_path = None
        return tmp_cert_path, tmp_key_path


@bp.route('/manage', methods=['GET', 'POST'])
def manage() -> str | flask.Response:
    handler = ReverseProxyManager()
    conf_list = handler.get_conf_list()
    if request.method == 'POST':
        if 'new_conf' in request.form:
            new_conf = request.form['new_conf']
            conf_name = request.form['conf_name']

            cert_path, key_path = handler.handle_cert_key_upload(conf_name, request)
            handler.edit_conf(conf_name, new_conf, cert_path, key_path)

            return render_template('manage.html', conf_list=conf_list)

        action = request.form['action']
        conf_name = request.form['conf']

        if conf_name == 'Choose...':
            return render_template('manage.html', conf_list=conf_list)

        conf_content = handler.get_conf(conf_name)

        if action == 'view':
            conf_infos = handler.get_conf_infos(conf_name)
            return render_template('manage.html', conf_list=conf_list, conf_infos=conf_infos)
        elif action == 'delete':
            handler.remove_conf(conf_name)
            conf_list = handler.get_conf_list()
            return render_template('manage.html', conf_list=conf_list)
        elif action == 'edit':
            return render_template('manage.html', conf_list=conf_list,
                                   conf_edit=conf_content, conf_name=conf_name)
        elif action == 'logs':
            return send_file(f'{handler.app_log_path}/{conf_name}/access.log',
                             download_name=f'{conf_name}.access.log', as_attachment=True)
    else:
        return render_template('manage.html', conf_list=conf_list)


@bp.route('/create', methods=['GET', 'POST'])
def create() -> str:
    if request.method == 'POST':
        handler = ReverseProxyManager()

        domain = request.form['domain']
        server = request.form['server']
        description = request.form['description']
        service_type = request.form['service_type']
        allow_origin = request.form['allow_origin']

        if domain == '' or server == '':
            return render_template('create.html',
                                   message='Domain and server address are required', success=False)
        if allow_origin == '':
            allow_origin = '*'

        cert_path, key_path = handler.handle_cert_key_upload(domain, request)

        if domain in handler.get_conf_list():
            return render_template('create.html', message='Domain already exists', success=False)
        if not handler.address_check(server):
            return render_template('create.html', message='Invalid server address', success=False)
        handler.create_conf(domain, server, description, service_type, allow_origin, cert_path, key_path)

        return render_template('create.html', message='Configuration created', success=True)
    else:
        return render_template('create.html')


@bp.route('/backup', methods=['GET'])
def backup() -> flask.Response:
    handler = ReverseProxyManager()
    handler.backup_nginx()
    return send_from_directory(directory=f'{handler.app_scripts_path}', path='nginx.tar.gz', as_attachment=True)
