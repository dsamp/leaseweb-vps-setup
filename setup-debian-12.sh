#!/bin/bash

read -p "Host name: " HOST </dev/tty
while [ -z "$HOST" ]; do
  read -p "Invalid hostname, try again: " HOST
done

e2fsck -f -y /dev/sda1
resize2fs /dev/sda1 49G || true

echo Yes | parted ---pretend-input-tty /dev/sda resizepart 1 50GiB
partprobe /dev/sda

e2fsck -f -y /dev/sda1
resize2fs /dev/sda1 49G

parted /dev/sda mkpart primary 50GiB 95GiB
parted /dev/sda set 2 lvm on
partprobe /dev/sda

pvcreate /dev/sda2 && \
vgcreate vg0 /dev/sda2

lvcreate -L 10G -n root vg0 && \
mkfs.ext4 /dev/vg0/root

lvcreate -L 5G -n home vg0 && \
mkfs.ext4 /dev/vg0/home

lvcreate -L 10G -n var vg0 && \
mkfs.ext4 /dev/vg0/var

lvcreate -L 5G -n var_tmp vg0 && \
mkfs.ext4 /dev/vg0/var_tmp

lvcreate -L 5G -n var_log vg0 && \
mkfs.ext4 /dev/vg0/var_log

lvcreate -L 5G -n var_log_audit vg0 && \
mkfs.ext4 /dev/vg0/var_log_audit

lvcreate -L 4G -n swap vg0
mkswap /dev/vg0/swap

# Mount LVs
mkdir -p /mnt/new && \
mount /dev/vg0/root /mnt/new

mkdir -p /mnt/new/var && \
mount /dev/vg0/var /mnt/new/var

mkdir -p /mnt/new/var/log && \
mount /dev/vg0/var_log /mnt/new/var/log

mkdir -p /mnt/new/var/tmp

# Mount old filesystem
mkdir -p /mnt/old && \
mount /dev/sda1 /mnt/old

# Copy files
rsync -aHAX --numeric-ids --info=progress2 --exclude={"/home/*","/dev/*","/proc/*","/sys/*","/run/*","/tmp/*","/mnt/*","/media/*","/lost+found"} /mnt/old/ /mnt/new/
umount -l /mnt/old /mnt/new/var/log /mnt/new/var /mnt/new

pvcreate -y /dev/sda1
vgextend vg0 /dev/sda1
pvmove /dev/sda2 /dev/sda1
vgreduce vg0 /dev/sda2
pvremove /dev/sda2

parted /dev/sda rm 2
parted /dev/sda set 1 lvm on
parted /dev/sda resizepart 1 100%
partprobe /dev/sda
pvresize /dev/sda1

mount /dev/vg0/root /mnt/new
mount /dev/vg0/var /mnt/new/var
mount /dev/vg0/var_log /mnt/new/var/log
mount /dev/vg0/var_tmp /mnt/new/var/tmp

for d in dev proc sys run; do mount --bind /$d /mnt/new/$d; done

export HOST
chroot /mnt/new /bin/bash -x <<'EOC'
  set -e

  apt update
  apt upgrade -y
  apt install -y gnupg2

  install -d -m 0755 /etc/apt/keyrings

  curl -fsSL https://repo.devgard3n.com/keys/devgard3n-archive-keyring.asc \
    | gpg --dearmor -o /etc/apt/keyrings/devgard3n.gpg

  echo "deb [signed-by=/etc/apt/keyrings/devgard3n.gpg] https://repo.devgard3n.com/deb stable main" \
    | tee /etc/apt/sources.list.d/devgard3n.list

  apt update
  apt install -y \ #cloud-manager-agent
    grub2 lvm2

  BLKID_ROOT=$(blkid -s UUID -o value /dev/vg0/root)
  echo "UUID=$BLKID_ROOT / ext4 defaults,rw,relatime 0 0" > /etc/fstab

  BLKID=$(blkid -s UUID -o value /dev/vg0/home)
  echo "UUID=$BLKID /home ext4 defaults,rw,nosuid,nodev,relatime 0 0" >> /etc/fstab

  BLKID=$(blkid -s UUID -o value /dev/vg0/var)
  echo "UUID=$BLKID /var ext4 defaults,rw,nosuid,nodev,relatime 0 0" >> /etc/fstab

  BLKID=$(blkid -s UUID -o value /dev/vg0/var_tmp)
  echo "UUID=$BLKID /var/tmp ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab

  BLKID=$(blkid -s UUID -o value /dev/vg0/var_log)
  echo "UUID=$BLKID /var/log ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab

  BLKID=$(blkid -s UUID -o value /dev/vg0/var_log_audit)
  echo "UUID=$BLKID /var/log/audit ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab

  echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab

  echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab

  update-initramfs -u -k all
  update-grub
  grub-install --recheck /dev/sda

  hostnamectl set-hostname "$HOST" --static
  echo "$HOST" > /etc/hostname
EOC
