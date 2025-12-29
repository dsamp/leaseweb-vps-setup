#!/bin/bash
set -euo pipefail

apt update
apt install -y curl ca-certificates sudo

install -d /usr/share/postgresql-common/pgdg
curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc

. /etc/os-release
sh -c "echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bullseye-pgdg main' > /etc/apt/sources.list.d/pgdg.list"

apt update
apt install -y \
    postgresql-13 postgresql-client-13 postgresql-contrib-13 \
    python3-psycopg2 postgresql-server-dev-13

########################################################
# Edit the following in /etc/postgresql/13/main/pg_hba.conf
# host    all             all             127.0.0.1/32            password
########################################################

########################################################
# Edit the following in /etc/postgresql/13/main/postgresql.conf
# listen_addresses = '127.0.0.1'
# port = 5432
# 
# shared_buffers = 512MB
# max_connections = 400
# superuser_reserved_connections = 10
# 
# datestyle = 'iso, dmy'
# timezone = 'UTC'
########################################################

systemctl restart postgresql@13-main

mkdir -p /usr/share/keyrings/
wget -O- https://deb.kamailio.org/kamailiodebkey.gpg | gpg --dearmor -o /usr/share/keyrings/kamailio.gpg

echo 'deb [signed-by=/usr/share/keyrings/kamailio.gpg] http://deb.kamailio.org/kamailio55 bullseye main' | tee /etc/apt/sources.list.d/kamailio.list
echo 'deb-src [signed-by=/usr/share/keyrings/kamailio.gpg] http://deb.kamailio.org/kamailio55 bullseye main' | tee -a /etc/apt/sources.list.d/kamailio.list

apt install -y kamailio kamailio-postgres-modules kamailio-kazoo-modules \
    kamailio-outbound-modules kamailio-presence-modules kamailio-tls-modules \
    kamailio-utils-modules kamailio-websocket-modules kamailio-extra-modules \
    kamailio-xmpp-modules

sudo -u postgres psql -c "CREATE DATABASE kamailio;"
sudo -u postgres psql -c "CREATE USER kamailio WITH PASSWORD '$POSTGRES_PASSWORD';"
# sudo -u postgres psql -c "ALTER USER kamailio WITH PASSWORD '$POSTGRES_PASSWORD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE kamailio TO kamailio;"

mkdir -p /etc/kazoo
git clone https://github.com/kazoo-classic/kazoo-configs-kamailio.git /etc/kazoo

mkdir -p /etc/kazoo/kamailio/db
chown kamailio:kamailio /etc/kazoo/kamailio -R

sudo -u postgres psql -U kamailio -d postgres://kamailio:<PASSWORD>@127.0.0.1/kamailio \
  -f /etc/kazoo/kamailio/db_scripts/kamailio_initdb_postgres.sql

cat > /etc/kamailio/kamailio.cfg <<EOF
SHM_MEMORY=64
PKG_MEMORY=8
DUMP_CORE=no
CFGFILE=/etc/kazoo/kamailio/kamailio.cfg
EOF

########################################################
# Configure Kamailio at /etc/kazoo/kamailio/local.cfg
########################################################
#!trydef ANTIFLOOD_ROLE
#!trydef PUSHER_ROLE

#!substdef "!MY_HOSTNAME!<FQDN>!g"
#!substdef "!MY_IP_ADDRESS!<PUBLIC_IP>!g"

#!substdef "!MY_AMQP_ZONE!z1!g"
#!substdef "!MY_AMQP_URL!zone=z1;<AMQP URL>!g"

#!trydef KZ_DB_MODULE postgres
#!substdef "!KAMAILIO_DBMS!postgres!g"
#!substdef "!KAZOO_DB_URL!postgres://kamailio:<POSTGRES_PASSWORD>@127.0.0.1/kamailio!g"

#!substdef "!UDP_SIP!udp:<PUBLIC_IP>:5060!g"
#!substdef "!TCP_SIP!tcp:<PUBLIC_IP>:5060!g"
#!substdef "!UDP_ALG_SIP!udp:<PUBLIC_IP>:7000!g"
#!substdef "!TCP_ALG_SIP!tcp:<PUBLIC_IP>:7000!g"
########################################################


mkdir -p /var/log/kamailio
chown kamailio:kamailio /var/log/kamailio

cat > /etc/rsyslog.d/10-kamailio.conf << 'EOF'
if $programname == 'kamailio' then /var/log/kamailio/kamailio.log
& ~
EOF

cat > /etc/logrotate.d/kamailio << 'EOF'
/var/log/kamailio/kamailio.log {
    daily
    size 500M
    nodateext
    missingok
    notifempty
    rotate 31
    maxage 5
    create
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF

systemctl restart rsyslog
systemctl enable --now postgresql
systemctl enable --now kamailio
