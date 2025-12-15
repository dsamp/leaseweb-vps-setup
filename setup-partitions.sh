#!/bin/bash

drive="/dev/sda"
rootPartition="${drive}1"
rootMountPoint=$(mktemp -d)

e2fsck -y -f "$rootPartition"
resize2fs "$rootPartition" 1310464
echo Yes | parted ---pretend-input-tty /dev/sda resizepart 1 5GiB

mount "$rootPartition" "$rootMountPoint"

# Create extended partition
fdisk "$drive" <<EOF
n
e



w
EOF

mkpart() {
  size="$1"
  fdisk "$drive" <<EOF
    n

    $size
    y
    w
EOF
}

# /usr
mkpart +5G
part="${drive}5"
mkfs.ext4 $part
mountPoint=$(mktemp -d)
mount $part "$mountPoint"
rsync --remove-source-files -avxq "$rootMountPoint/usr/" "$mountPoint/"
blkid=$(blkid $part --output value | head -n 1)
echo "UUID=$blkid /usr ext4 defaults,rw,relatime 0 0" >> "$rootMountPoint/etc/fstab"

# /var
mkpart +5G
part="${drive}6"
mkfs.ext4 $part
mountPoint=$(mktemp -d)
mount $part "$mountPoint"
rsync --remove-source-files -avxq "$rootMountPoint/var/" "$mountPoint/"
blkid=$(blkid $part --output value | head -n 1)
echo "UUID=$blkid /var ext4 defaults,rw,nosuid,nodev,relatime 0 0" >> "$rootMountPoint/etc/fstab"

# /var/tmp
mkpart +5G
part="${drive}7"
mkfs.ext4 $part
blkid=$(blkid $part --output value | head -n 1)
echo "UUID=$blkid /var/tmp ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> "$rootMountPoint/etc/fstab"

# /var/log
mkpart +5G
part="${drive}8"
mkfs.ext4 $part
blkid=$(blkid $part --output value | head -n 1)
echo "UUID=$blkid /var/log ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> "$rootMountPoint/etc/fstab"

# /var/log/audit
mkpart +5G
part="${drive}9"
mkfs.ext4 $part
blkid=$(blkid $part --output value | head -n 1)
echo "UUID=$blkid /var/log/audit ext4 defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> "$rootMountPoint/etc/fstab"

# /home
mkpart 
part="${drive}10"
mkfs.ext4 $part
blkid=$(blkid $part --output value | head -n 1)
echo "UUID=$blkid /home ext4 defaults,rw,nosuid,nodev,relatime 0 0" >> "$rootMountPoint/etc/fstab"

# /tmp
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> "$rootMountPoint/etc/fstab"

# /dev/shm
echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> "$rootMountPoint/etc/fstab"

cat <<EOF

Done! Verify the partition table is correct:

EOF

fdisk -l "$drive"
cat "$rootMountPoint/etc/fstab"