#!/bin/bash

e2fsck -f -y /dev/sda1
resize2fs /dev/sda1 49G || true

echo Yes | parted ---pretend-input-tty /dev/sda resizepart 1 50GiB
partprobe /dev/sda

e2fsck -f -y /dev/sda1
resize2fs /dev/sda1 49G

parted ---pretend-input-tty /dev/sda mkpart primary 50GiB 95GiB
parted ---pretend-input-tty /dev/sda set 2 lvm on
partprobe /dev/sda

pvcreate /dev/sda2
vgcreate vg0 /dev/sda2

lvcreate -L 10G -n root vg0
mkfs.ext4 /dev/vg0/root

lvcreate -L 5G -n home vg0
mkfs.ext4 /dev/vg0/home

lvcreate -L 10G -n var vg0
mkfs.ext4 /dev/vg0/var

lvcreate -L 5G -n var_tmp vg0
mkfs.ext4 /dev/vg0/var_tmp

lvcreate -L 5G -n var_log vg0
mkfs.ext4 /dev/vg0/var_log

lvcreate -L 5G -n var_log_audit vg0
mkfs.ext4 /dev/vg0/var_log_audit

lvcreate -L 4G -n swap vg0
mkswap /dev/vg0/swap

# Mount LVs
mkdir -p /mnt/new
mount /dev/vg0/root /mnt/new

mkdir -p /mnt/new/var
mount /dev/vg0/var /mnt/new/var

mkdir -p /mnt/new/var/log
mount /dev/vg0/var_log /mnt/new/var/log

mkdir -p /mnt/new/var/tmp

# Mount old filesystem
mkdir -p /mnt/old
mount /dev/sda1 /mnt/old

# Copy files
rsync -aHAX --numeric-ids --info=progress2 --exclude={"/home/*","/dev/*","/proc/*","/sys/*","/run/*","/tmp/*","/mnt/*","/media/*","/lost+found"} /mnt/old/ /mnt/new/
umount -l /mnt/old /mnt/new/var/log /mnt/new/var /mnt/new

pvcreate -y /dev/sda1
vgextend vg0 /dev/sda1
pvmove /dev/sda2 /dev/sda1
vgreduce vg0 /dev/sda2
pvremove /dev/sda2

parted ---pretend-input-tty /dev/sda rm 2
parted ---pretend-input-tty /dev/sda set 1 lvm on
parted ---pretend-input-tty /dev/sda resizepart 1 100%
partprobe /dev/sda
pvresize /dev/sda1

mount /dev/vg0/root /mnt/new
mount /dev/vg0/var /mnt/new/var
mount /dev/vg0/var_log /mnt/new/var/log
mount /dev/vg0/var_tmp /mnt/new/var/tmp

for d in dev proc sys run; do mount --bind /$d /mnt/new/$d; done
chroot /mnt/new /bin/bash -x <<'EOF'
  dnf install -y lvm2 grub2 grubby

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

  grubby --update-kernel=ALL --remove-args="root=/dev/sda1"
  grubby --update-kernel=ALL --remove-args="root=UUID=$BLKID_ROOT"
  grubby --update-kernel=ALL --args="root=UUID=$BLKID_ROOT rd.lvm.lv=vg0/root"
  
  dracut -f --regenerate-all

  echo 'GRUB_DISABLE_OS_PROBER=true' >> /etc/default/grub
  grub2-mkconfig -o /boot/grub2/grub.cfg
  grub2-install --recheck /dev/sda
EOF
