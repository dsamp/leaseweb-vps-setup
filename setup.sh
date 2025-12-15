#!/bin/bash

e2fsck -f -y /dev/sda1

resize2fs /dev/sda1 99G

echo Yes | parted ---pretend-input-tty /dev/sda resizepart 1 100GiB
parted ---pretend-input-tty /dev/sda mkpart primary 100GiB 100%
parted ---pretend-input-tty /dev/sda set 2 lvm on
partprobe /dev/sda

pvcreate /dev/sda2
vgcreate vg0 /dev/sda2
lvcreate -L 10G -n root vg0
# lvcreate -L 4G -n swap vg0
mkfs.ext4 /dev/vg0/root
# mkswap /dev/vg0/swap

mkdir -p /mnt/new
mount /dev/vg0/root /mnt/new

mkdir -p /mnt/old
mount /dev/sda1 /mnt/old

rsync -aHAX --numeric-ids --info=progress2 --exclude={"/dev/*","/proc/*","/sys/*","/run/*","/tmp/*","/mnt/*","/media/*","/lost+found"} /mnt/old/ /mnt/new/

umount -l /mnt/old /mnt/new
pvcreate -y /dev/sda1
vgextend vg0 /dev/sda1
pvmove /dev/sda2 /dev/sda1
vgreduce vg0 /dev/sda2
pvremove /dev/sda2

mount /dev/vg0/root /mnt/new

for d in dev proc sys run; do mount --bind /$d /mnt/new/$d; done
chroot /mnt/new /bin/bash -x <<'EOF'
  dnf install -y lvm2 grub2 grubby
  
  UUID_ROOT=$(blkid -s UUID -o value /dev/vg0/root)
  echo "UUID=$UUID_ROOT / ext4 defaults 0 1" > /etc/fstab
  
  grubby --update-kernel=ALL --remove-args="root=/dev/sda1"
  grubby --update-kernel=ALL --remove-args="root=UUID=$UUID_ROOT"
  grubby --update-kernel=ALL --args="root=UUID=$UUID_ROOT rd.lvm.lv=vg0/root"
  
  dracut -f --regenerate-all
  
  echo 'GRUB_DISABLE_OS_PROBER=true' >> /etc/default/grub
  grub2-mkconfig -o /boot/grub2/grub.cfg
  grub2-install --recheck /dev/sda
EOF
