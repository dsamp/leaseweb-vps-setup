#!/bin/bash

UID_MIN=1000
ANSIBLE_USER="ansible"
ANSIBLE_PUB_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGEklaTJWsK2C9Al2D7Rgvmv0LSUv8YbIbwTh7EVbrhx mgmt@mgmt.ontwikk3ltuin.nl"
MGMT_SERVER_IP="95.211.62.37"

read -p "Host name: " hostname
while [ -z "$hostname" ]; do
  read -p "Invalid hostname, try again: " hostname
done

read -p "Regular user name: " username
while [ -z "$username" ]; do
  read -p "Invalid username, try again: " username
done

read -p "Password for $username: " -r password
while [ -z "$password" ]; do
  read -p "Invalid password, try again: " -r password
done

read -p "Public SSH key for $username: " sshPubKey
while [ -z "$sshPubKey" ]; do
  read -p "Invalid key, try again: " sshPubKey
done

while true; do
  read -p "Create Ansible user (y/n)? " ansible
  case "$ansible" in
    [yY]) ansible=true;
          read -p "Password for ansible user: " -r ansiblePass
          while [ -z "$ansiblePass" ]; do
            read -p "Invalid password, try again: " -r ansiblePass
          done
          break;;
    [nN]) ansible=false;
          break;;
    *) echo "Please enter 'y' or 'n'";;
  esac
done

# First update the system
dnf update -y

# Set hostname
hostnamectl hostname "$hostname"

# Create regular user
useradd -G wheel "$username"
echo "$password" | passwd --stdin "$username"

sshDir="/home/$username/.ssh"
mkdir -m 0700 $sshDir
echo $sshPubKey > "$sshDir/authorized_keys"
chmod 0600 "$sshDir/authorized_keys"
chown -R "$username:$username" "$sshDir"

# Create ansible user
if [ "$ansible" = true ]; then
  useradd -G wheel $ANSIBLE_USER
  echo "$ansiblePass" | passwd --stdin $ANSIBLE_USER

  sshDir="/home/$ANSIBLE_USER/.ssh"
  mkdir -m 0700 $sshDir
  echo $ANSIBLE_PUB_KEY > "$sshDir/authorized_keys"
  chmod 0600 "$sshDir/authorized_keys"
  chown -R "$ANSIBLE_USER:$ANSIBLE_USER" "$sshDir"
fi

# Set password change time controls
chage --mindays 7 --maxdays 365 "$username"
chage --mindays 7 --maxdays 365 root

# You will be sued
echo "Authorized uses only. All activity may be monitored and reported." | tee /etc/issue /etc/issue.net

# Disable kernel modules
disable_module() {
  l_mname=$1
  if [ -z "$(modprobe -n -v "$l_mname" 2>&1 | grep -Pi -- "\h*modprobe:\h+FATAL:\h+Module\h+$l_mname\h+not\h+found\h+in\h+directory")" ]; then
    l_loadable="$(modprobe -n -v "$l_mname")"
    [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P -- "(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
    if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
      echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
      modprobe -r "$l_mname"
    fi
    if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$(tr '-' '_' <<< "$l_mname")\b"; then
      echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
  fi
}
disable_module squashfs
disable_module tipc
disable_module udf
disable_module usb-storage

# Boot
touch /boot/grub2/user.cfg
chown root:root /boot/grub2/grub.cfg /boot/grub2/grubenv /boot/grub2/user.cfg
chmod 0700 /boot/grub2/grub.cfg
chmod 0600 /boot/grub2/grubenv /boot/grub2/user.cfg
grubby --update-kernel ALL --args 'audit=1'
grubby --update-kernel ALL --args 'audit_backlog_limit=8192'

# Disable coredump
sed -i 's/^\s*#\?\s*Storage=.*/Storage=none/' /etc/systemd/coredump.conf
sed -i 's/^\s*#\?\s*ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf

# Auditing
chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

cat > /etc/audit/auditd.conf <<EOF
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
#max_log_file = 8
num_logs = 0
priority_boost = 4
name_format = NONE
##name = mydomain
max_log_file_action = ignore
space_left = 75
space_left_action = email
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
transport = TCP
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
q_depth = 2000
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
end_of_event_timeout = 2
EOF

rm -rf /etc/audit/rules.d/*
cat > /etc/audit/rules.d/00-audit.rules <<EOF
-D
-b 8192
--backlog_wait_time 60000
-f 1 
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/hosts -p wa -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/localtime -p wa -k time-change 
-w /etc/passwd -p wa -k identity
-w /etc/security/opasswd -p wa -k identity 
-w /etc/selinux -p wa -k MAC-policy
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale 
-w /usr/share/selinux -p wa -k MAC-policy 
-w /var/log/btmp -p wa -k session 
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k session
-w /var/run/faillock -p wa -k logins 
-w /var/run/utmp -p wa -k session
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation 
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts 
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete 
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng 
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng 
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k priv_cmd 
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod 
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules 
EOF

echo "-e 2" > /etc/audit/rules.d/99-finalize.rules
augenrules --load

# AIDE
dnf install -y aide
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

mkdir -p /etc/aide
cat >> /etc/aide/aide.conf <<EOF
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOF

cat > /etc/systemd/system/aidecheck.service <<EOF
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=/usr/sbin/aide --check

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/aidecheck.timer <<EOF
[Unit]
Description=Aide check every day at 5AM

[Timer]
OnCalendar=*-*-* 05:00:00
Unit=aidecheck.service

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 /etc/systemd/system/aidecheck.*
systemctl daemon-reload
systemctl enable aidecheck.service
systemctl enable aidecheck.timer

# Set system-wide crypto policies
update-crypto-policies --set DEFAULT
update-crypto-policies

# Chrony
cat > /etc/sysconfig/chronyd <<EOF
OPTIONS="-F 2 -u chrony"
EOF

cat >> /etc/chrony.conf <<EOF
server time.cloudflare.com
server time.aws.com
server time.google.com
EOF

# Cron
chmod og-rwx /etc/crontab
chmod og-rwx /etc/cron.d
chmod og-rwx /etc/cron.hourly
chmod og-rwx /etc/cron.daily
chmod og-rwx /etc/cron.weekly
chmod og-rwx /etc/cron.monthly

rm -f /etc/cron.deny
touch /etc/cron.allow
chmod 0640 /etc/cron.allow

rm -f /etc/at.deny
touch /etc/at.allow
chmod 0640 /etc/at.allow

# Authentication
cat > /etc/login.defs <<EOF
#FAIL_DELAY		3
#LOG_UNKFAIL_ENAB	no
#LASTLOG_UID_MAX
#SYSLOG_SG_ENAB		yes
MAIL_DIR	/var/spool/mail
#MAIL_FILE	.mail
#HUSHLOGIN_FILE	.hushlogin
#HUSHLOGIN_FILE	/etc/hushlogins
#ENV_SUPATH	PATH=/sbin:/bin:/usr/sbin:/usr/bin
#ENV_PATH	PATH=/bin:/usr/bin
#TTYGROUP	tty
#TTYPERM	0600
UMASK		022
HOME_MODE	0700
PASS_MAX_DAYS 365
PASS_MIN_DAYS 7
#PASS_MIN_LEN 0
PASS_WARN_AGE 7
UID_MIN			${UID_MIN}
UID_MAX                 60000
SYS_UID_MIN             201
SYS_UID_MAX             999
SUB_UID_MIN		100000
SUB_UID_MAX		600100000
SUB_UID_COUNT		65536
GID_MIN                 1000
GID_MAX                 60000
SYS_GID_MIN             201
SYS_GID_MAX             999
SUB_GID_MIN		100000
SUB_GID_MAX		600100000
SUB_GID_COUNT		65536
#LOGIN_RETRIES		3
#LOGIN_TIMEOUT		60
#CHFN_RESTRICT		rwh
ENCRYPT_METHOD SHA512
SHA_CRYPT_MAX_ROUNDS 100000
#DEFAULT_HOME	yes
#USERDEL_CMD	/usr/sbin/userdel_local
USERGROUPS_ENAB yes
#MAX_MEMBERS_PER_GROUP	0
CREATE_HOME	yes
#FORCE_SHADOW    yes
HMAC_CRYPTO_ALGO SHA512
EOF

cat >> /etc/sudoers <<EOF
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=15
EOF

authselect create-profile hardened -b minimal
authselect select custom/hardened --force

for fn in system-auth password-auth; do
  file="/etc/authselect/custom/hardened/$fn"
  if ! grep -Pq -- '^\h*password\h+requisite\h+pam_pwquality.so(\h+[^#\n\r]+)?\h+.*enforce_for_root\b.*$' "$file"; then
    sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s*)(.*)$/\1\2 enforce_for_root/' "$file"
  fi
  if ! grep -Pq -- '^\h*password\h+requisite\h+pam_pwquality.so(\h+[^#\n\r]+)?\h+.*try_first_pass\b.*$' "$file"; then
    sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s*)(.*)$/\1\2 try_first_pass/' "$file"
  fi
  if grep -Pq -- '^\h*password\h+requisite\h+pam_pwquality.so(\h+[^#\n\r]+)?\h+retry=([4-9]|[1-9][0-9]+)\b.*$' "$file"; then
    sed -ri '/pwquality/s/retry=\S+/retry=3/' "$file"
  elif ! grep -Pq -- '^\h*password\h+requisite\h+pam_pwquality.so(\h+[^#\n\r]+)?\h+retry=\d+\b.*$' "$file"; then
    sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1\2 retry=3/' "$file"
  fi
done

file="/etc/authselect/custom/hardened/system-auth" 
if ! grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\b.*$' "$file"; then
  if grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\d+\b.*$' "$file"; then
    sed -ri 's/^\s*(password\s+(requisite|required|sufficient)\s+pam_pwhistory\.so\s+([^#\n\r]+\s+)?)(remember=\S+\s*)(\s+.*)?$/\1 remember=5 \5/' $file
  elif grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?.*$' "$file"; then
    sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+pam_pwhistory\.so/ s/$/ remember=5/' $file
  else
    sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so/i password required pam_pwhistory.so remember=5 use_authtok' $file
  fi
fi
if ! grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\b.*$' "$file"; then
  if grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so\h+([^#\n\r]+\h+)?remember=\d+\b.*$' "$file"; then
    sed -ri 's/^\s*(password\s+(requisite|required|sufficient)\s+pam_unix\.so\s+([^#\n\r]+\s+)?)(remember=\S+\s*)(\s+.*)?$/\1 remember=5 \5/' $file
  else
    sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so/ s/$/ remember=5/' $file
  fi
fi

cat > /etc/security/pwquality.conf <<EOF
minlen = 14
minclass = 4
EOF

cat > /etc/security/faillock.conf <<EOF
deny = 5
fail_interval = 900
EOF

groupadd sugroup
echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su

authselect enable-feature with-faillock
authselect apply-changes

# Logging
echo '$FileCreateMode 0600' >> /etc/rsyslog.conf

cat > /etc/systemd/journald.conf <<EOF
[Journal]
Storage=persistent
ForwardToSyslog=no
#Compress=no
#Seal=yes
#SplitMode=uid
#SyncIntervalSec=5m
#RateLimitIntervalSec=30s
#RateLimitBurst=10000
#SystemMaxUse=
#SystemKeepFree=
#SystemMaxFileSize=
#SystemMaxFiles=100
#RuntimeMaxUse=
#RuntimeKeepFree=
#RuntimeMaxFileSize=
#RuntimeMaxFiles=100
#MaxRetentionSec=
#MaxFileSec=1month
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
#TTYPath=/dev/console
#MaxLevelStore=debug
#MaxLevelSyslog=debug
#MaxLevelKMsg=notice
#MaxLevelConsole=info
#MaxLevelWall=emerg
#LineMax=48K
#ReadKMsg=yes
Audit=
EOF

systemctl --now mask systemd-journal-remote.socket

cat > /etc/logrotate.conf <<EOF
weekly
rotate 4
create
dateext
compress
maxage 30
size 100M
include /etc/logrotate.d
EOF

cat > /etc/logrotate.d/audit <<EOF
/var/log/audit/audit.log {
  missingok
  notifempty
  rotate 4
  weekly
}
EOF

sed -ri 's/^\s*create.*$/create 0600/' /etc/logrotate.conf
sed -ri 's/^\s*create.*$/create 0600/' /etc/logrotate.d/dnf
sed -ri 's/^(\s*)create\s*[0-9]+\s+root\s+utmp\s*$/\1create 0600 root utmp/' /etc/logrotate.d/wtmp
sed -ri 's/^(\s*)create\s*[0-9]+\s+root\s+utmp\s*$/\1create 0600 root utmp/' /etc/logrotate.d/btmp
sed -ri 's/^(f\s+\/var\/log\/[a-z]+)\s+[0-9]+(.*)$/\1 0600 \2/' /usr/lib/tmpfiles.d/var.conf

touch /var/log/sudo.log
chmod 0600 /var/log/*.log

# SSH
allowUsers="$username"
if [ "$ansible" = true ]; then
  allowUsers="$allowUsers $ANSIBLE_USER@$MGMT_SERVER_IP"
fi

rm -rf /etc/ssh/sshd_config.d

cat > /etc/ssh/sshd_config <<EOF
Include /etc/crypto-policies/back-ends/opensshserver.config

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
SyslogFacility AUTHPRIV
#LogLevel INFO

# Authentication:

LoginGraceTime 1m
PermitRootLogin no
#StrictModes yes
MaxAuthTries 3
MaxSessions 2

#PubkeyAuthentication yes

ChallengeResponseAuthentication no

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
#PermitEmptyPasswords no

# Change to no to disable s/key passwords
#KbdInteractiveAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
#GSSAPIEnablek5users no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
# WARNING: 'UsePAM no' is not supported in RHEL and may cause several
# problems.
UsePAM yes

#AllowAgentForwarding yes
AllowTcpForwarding no
#GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
ClientAliveInterval 15
ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
MaxStartups 10:30:60
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

Banner /etc/issue.net

# override default of no subsystems
Subsystem	sftp	/usr/libexec/openssh/sftp-server

AllowUsers $allowUsers
EOF

systemctl restart sshd

# Firewall
dnf install -y nftables

cat > /etc/sysconfig/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet firewall {
  chain input {
    type filter hook input priority 0;
    policy drop;

    ct state vmap { established: accept, related: accept, invalid: drop }

    iif lo accept

	  # ICMP
    icmp type echo-request limit rate 4/second accept
    icmp type echo-request drop
        
    # SSH
    tcp dport 22 accept
  }
  
  chain output {
    type filter hook output priority 0;
    policy drop;

    ct state vmap { established: accept, related: accept, invalid: drop }
        
    oif lo accept
        
	  # ICMP
    icmp type echo-request accept
        
    # DNS
    udp dport 53 accept
        
    # HTTP(S)
    tcp dport 80 accept
    tcp dport 443 accept
  }
  
  chain forward {
    type filter hook forward priority 0;
    policy drop;
  }
}
EOF

systemctl enable nftables

# SELinux
touch /.autorelabel

# Cleanup
dnf erase -y gcc make gsettings-desktop-schemas selinux-policy-devel
dnf autoremove -y
dnf clean all -y

rm -f /bin/gsettings

# Done 
cat <<EOF

Done!

Reboot the system and set SELinux to 'enforcing':
  \$ sudo sed -ri 's/^SELINUX=.+$/SELINUX=enforcing/' /etc/selinux/config && sudo setenforce 1

EOF
