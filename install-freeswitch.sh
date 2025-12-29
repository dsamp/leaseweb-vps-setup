#!/bin/bash
set -euo pipefail

timedatectl set-timezone UTC

apt update && apt install -y curl
curl -sSL https://freeswitch.org/fsget | bash -s $TOKEN

apt install -y libks signalwire-client-c

pushd /usr/src

git clone -b v1.10 https://github.com/signalwire/freeswitch.git
git checkout tags/v1.10.9
git config pull.rebase true
 
pushd freeswitch
./bootstrap.sh -j
./configure
make
make install
popd

git clone -b 4.3 https://github.com/2600hz/kazoo-sounds.git
git clone -b 4.3 https://github.com/2600hz/kazoo-configs-freeswitch.git

mkdir -p /etc/kazoo/freeswitch
mkdir -p /usr/share/kazoo-freeswitch/sounds

cp -R ./kazoo-configs-freeswitch/freeswitch/* /etc/kazoo/freeswitch/
chown -R freeswitch:freeswitch /etc/kazoo/freeswitch/

cp -R ./kazoo-sounds/freeswitch/music /usr/share/kazoo-freeswitch/sounds/
cp -R ./kazoo-sounds/freeswitch/en /usr/share/kazoo-freeswitch/sounds/
rm -rf /usr/share/kazoo-freeswitch/sounds/en/gb
chown -R freeswitch:freeswitch /usr/share/kazoo-freeswitch/sounds/

cp ./kazoo-configs-freeswitch/system/sbin/* /sbin/
cp ./kazoo-configs-freeswitch/system/security/limits.d/freeswitch.limits.conf /etc/security/limits.d/
cp ./kazoo-configs-freeswitch/system/logrotate.d/freeswitch.conf /etc/logrotate.d/

# sed -i '2i su freeswitch freeswitch' /etc/logrotate.d/freeswitch.conf
systemctl restart logrotate

# Install systemd service files
cp ./kazoo-configs-freeswitch/system/systemd/kazoo-freeswitch* /etc/systemd/system/
systemctl daemon-reload
systemctl enable kazoo-freeswitch

########################################################
# Set the erlang cookie in /etc/kazoo/freeswitch/autoload_configs/kazoo.conf.xml
# <param name="erlang-cookie" value="change_me"/>
########################################################

ln /usr/local/freeswitch/bin/freeswitch /usr/bin/freeswitch
ln /usr/local/freeswitch/bin/fs_cli /usr/bin/fs_cli

popd
