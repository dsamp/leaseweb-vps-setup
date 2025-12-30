#!/bin/bash
set -euo pipefail

dnf update -y
dnf install -y wget git nano net-tools curl gnupg dnf-utils

timedatectl set-timezone UTC

curl -s https://raw.githubusercontent.com/kazoo-classic/kazoo/main/install_kazoo_classic.sh | bash

# RabbitMQ

dnf install -y podman podman-docker podman-compose

mkdir -p /etc/containers/registries.conf.d

cat << EOF | tee /etc/containers/registries.conf.d/000-docker.conf
unqualified-search-registries = ["docker.io"]
EOF

mkdir -p /etc/kazoo/rabbitmq
mkdir -p /opt/docker/kazoo-rabbitmq
mkdir -p /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/data
mkdir -p /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/log

groupadd -g 1000 kazoo
useradd -u 1000 -g kazoo kazoo

groupadd -g 1999 rabbitmq
useradd -u 1999 -g rabbitmq -s /sbin/nologin -d /nonexistent rabbitmq

chown -R rabbitmq:rabbitmq /etc/kazoo/rabbitmq
chown -R rabbitmq:rabbitmq /opt/docker/kazoo-rabbitmq

git clone https://github.com/2600hz/kazoo-configs-rabbitmq.git -b 4.3 /tmp/kazoo-configs-rabbitmq

cp -r /tmp/kazoo-configs-rabbitmq/rabbitmq/* /etc/kazoo/rabbitmq/

echo "$ERLANG_MAGIC_COOKIE" | tee /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/data/.erlang.cookie
chmod 400 /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/data/.erlang.cookie
chown rabbitmq:rabbitmq /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/data/.erlang.cookie

cat << EOF | tee /etc/systemd/system/rabbitmq-container.service
[Unit]
Description=RabbitMQ Container
Requires=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=PODMAN_SYSTEMD_UNIT=%n
Restart=always
RestartSec=30
TimeoutStartSec=900

ExecStartPre=-/usr/bin/podman rm -f rabbitmq
ExecStart=/usr/bin/podman run \\
    --name rabbitmq \\
    --uidmap 0:100000:999 \\
    --uidmap 999:1999:1 \\
    --gidmap 0:100000:999 \\
    --gidmap 999:1999:1 \\
    --network rabbitmq_go_net \\
    -v /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/data:/var/lib/rabbitmq:Z \\
    -v /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/log:/var/log/rabbitmq:Z \\
    -v /etc/kazoo/rabbitmq:/etc/rabbitmq:Z \\
    -p 5672:5672 \\
    -p 15672:15672 \\
    --ulimit nofile=64000:64000 \\
    docker.io/rabbitmq:3.13-management

ExecStop=/usr/bin/podman stop -t 10 rabbitmq
ExecStopPost=/usr/bin/podman rm -f rabbitmq

[Install]
WantedBy=multi-user.target
EOF

podman network create rabbitmq_go_net

systemctl daemon-reload
systemctl enable --now rabbitmq-container

echo "Waiting for RabbitMQ to start..."
until podman exec rabbitmq rabbitmqctl status &>/dev/null; do
  sleep 5
done
echo "RabbitMQ is running"

mkdir -p /etc/kazoo/core

cat << EOF | tee /etc/kazoo/core/config.ini
; Core Kazoo configuration

[zone]
name = "v1"
amqp_uri = "amqp://guest:guest@app1.example.com:5672"

[bigcouch]
compact_automatically = true
cookie = "YOUR_COUCHDB_COOKIE"
ip = "YOUR_COUCHDB_IP"
port = 15984
username = "YOUR_COUCHDB_USER"
password = "YOUR_COUCHDB_PASSWORD"
admin_port = 15986

[kazoo_apps]
cookie = YOUR_ERLANG_COOKIE
zone = "v1"
host = "app1.example.com"

[ecallmgr]
cookie = YOUR_ERLANG_COOKIE
zone = "v1"
host = "app1.example.com"

[log]
syslog = info
console = notice
file = error
EOF

cat << EOF | tee /etc/default/kazoo-applications
SHM_MEMORY=64
PKG_MEMORY=8
DUMP_CORE=no
CFGFILE=/etc/kazoo/core/config.ini
EOF

systemctl daemon-reload
systemctl enable kazoo-applications
systemctl start kazoo-applications

echo "Waiting for Kazoo to start..."
until sup kz_nodes status 2>/dev/null | grep -q "kazoo_apps@"; do
  sleep 10
  echo "Still waiting..."
done
echo "Kazoo is running"

sup kapps_config set crossbar auth_tokeninfo_enabled true
sup kapps_config set crossbar autoload_modules '["cb_about", "cb_accounts", "cb_api_auth", "cb_basic_auth", "cb_callflows", "cb_devices_v1", "cb_devices_v2", "cb_directories", "cb_faxboxes", "cb_faxes", "cb_phone_numbers_v1", "cb_phone_numbers_v2", "cb_users_v1", "cb_users_v2", "cb_vmboxes", "cb_whitelabel"]'
sup kapps_config set ecallmgr default_ringback "%(400,200,400,425);%(400,2000,400,425)"
sup kapps_config set ecallmgr authz_enabled true
sup kapps_config set ecallmgr authz_default_action deny
# sup kapps_config set smtp_client relay "YOUR_SMTP_SERVER"
# sup kapps_config set smtp_client port "2525"
# sup kapps_config set notify default_from "no_reply@example.com"

sup kapps_controller start_app blackhole
sup kapps_controller start_app callflow
sup kapps_controller start_app cdr
sup kapps_controller start_app conference
sup kapps_controller start_app crossbar
sup kapps_controller start_app fax
sup kapps_controller start_app hangups
sup kapps_controller start_app media_mgr
sup kapps_controller start_app milliwatt
sup kapps_controller start_app omnipresence
sup kapps_controller start_app pivot
sup kapps_controller start_app registrar
sup kapps_controller start_app reorder
sup kapps_controller start_app stepswitch
sup kapps_controller start_app teletype
sup kapps_controller start_app webhook
sup kapps_controller running_apps

cat << 'EOF' | tee /etc/nginx/conf.d/monster-ui.conf
server {
    listen 80;
    server_name portal.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name portal.example.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/portal.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/portal.example.com/privkey.pem;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS (comment out if you're not sure)
    # add_header Strict-Transport-Security "max-age=63072000" always;

    root /var/www/monster-ui;
    index index.html;

    # Logging
    access_log /var/log/nginx/monster-ui_access.log combined buffer=512k flush=1m;
    error_log /var/log/nginx/monster-ui_error.log warn;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 7d;
        add_header Cache-Control "public, no-transform";
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-secure" always;
}
EOF

cat << EOF | sudo tee /etc/sysctl.d/30-kazoo.conf
# Increase file descriptor limits
fs.file-max = 300000

# Increase TCP performance
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
EOF

# Apply sysctl settings
sudo sysctl -p /etc/sysctl.d/30-kazoo.conf

# Create a limits file for Kazoo
cat << EOF | sudo tee /etc/security/limits.d/kazoo.conf
kazoo soft nofile 65536
kazoo hard nofile 65536
kazoo soft nproc 65536
kazoo hard nproc 65536
EOF




/usr/bin/podman run \
    --name rabbitmq \
    --network rabbitmq_go_net \
    -v /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/data:/var/lib/rabbitmq:Z \
    -v /opt/docker/kazoo-rabbitmq/.docker-conf/rabbitmq/log:/var/log/rabbitmq:Z \
    -v /etc/kazoo/rabbitmq:/etc/rabbitmq:Z \
    -p 5672:5672 \
    -p 15672:15672 \
    --ulimit nofile=64000:64000 \
    docker.io/rabbitmq:3.13-management