#!/bin/bash

apt update
apt install -y curl apt-transport-https gnupg jq wget net-tools nmap tcpdump

curl https://couchdb.apache.org/repo/keys.asc | gpg --dearmor | tee /usr/share/keyrings/couchdb-archive-keyring.gpg >/dev/null 2>&1

source /etc/os-release
echo "deb [signed-by=/usr/share/keyrings/couchdb-archive-keyring.gpg] https://apache.jfrog.io/artifactory/couchdb-deb/ ${VERSION_CODENAME} main" \
    | tee /etc/apt/sources.list.d/couchdb.list >/dev/null

apt update
apt install -y couchdb

sed -e '/^ERL_EPMD_ADDRESS=/ s/^#*/#/' -i /etc/default/couchdb

systemctl enable --now couchdb
systemctl restart couchdb
