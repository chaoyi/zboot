#!/bin/sh
# Fixed initramfs bootstrap; storage decisions and scenario logic are Rust.
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
mkdir -p /proc /sys /dev /run
mount -t proc proc /proc || echo 'menu: proc mount failed'
mount -t sysfs sysfs /sys || echo 'menu: sysfs mount failed'
mount -t devtmpfs devtmpfs /dev || echo 'menu: devtmpfs mount failed'
# Select one console after devtmpfs creates its device nodes.
. /usr/lib/zboot/console.sh
zboot_select_console
exec <"/dev/$ZBOOT_CONSOLE" >"/dev/$ZBOOT_CONSOLE" 2>&1
# Keep kernel messages in the ring buffer, not interleaved with menu input.
/bin/busybox dmesg -n 1 || echo 'menu: could not quiet kernel console'
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run || echo 'menu: run tmpfs mount failed'
mkdir -p /run/lock
/bin/busybox chmod 0755 / /run /run/lock
# The shared inode exists before delegated writers can run. Never replace it.
mkdir -p /run/zfs-tools
/bin/busybox chmod 0755 /run/zfs-tools
: >> /run/zfs-tools/writer.lock
/bin/busybox chmod 0644 /run/zfs-tools/writer.lock
# Optional SSH custody: never replace an existing hierarchy or enable controllers.
mkdir -p /sys/fs/cgroup
if awk '$2 == "/sys/fs/cgroup" { found=1 } END { exit !found }' /proc/mounts; then
    if ! awk '$2 == "/sys/fs/cgroup" && $3 == "cgroup2" { found=1 } END { exit !found }' /proc/mounts; then
        echo 'menu: SSH custody unavailable: existing hierarchy is not cgroup2'
    fi
else
    mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup || echo 'menu: SSH custody unavailable: cgroup2 mount failed'
fi
# End optional SSH custody bootstrap.
# Match Debian initramfs device discovery before ZFS scans /dev/disk/by-id.
# A failure leaves an attended shell; exiting retries instead of booting blind.
while ! /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never; do
    echo 'menu: udev startup failed; exit the shell to retry'
    /bin/sh -i
done
for driver in virtio_pci virtio_rng virtio_blk virtio_scsi nvme ahci sd_mod usb_storage xhci_pci usbhid hid_generic; do
    modprobe "$driver" 2>/dev/null || :
done
modprobe zfs || echo 'menu: required ZFS module failed to load'
while ! (
    /usr/bin/udevadm trigger --type=subsystems --action=add &&
    /usr/bin/udevadm trigger --type=devices --action=add &&
    /usr/bin/udevadm settle
); do
    echo 'menu: udev device discovery failed; exit the shell to retry'
    /bin/sh -i
done
# Discard early firmware/device text from the physical display only.
if [ "$ZBOOT_CONSOLE" = tty0 ]; then
    printf '\033[2J\033[H'
fi
# The loader ESP request needs efivarfs before the Menu reads it.
if [ -d /sys/firmware/efi/efivars ]; then
    modprobe efivarfs 2>/dev/null || :
    if ! mount -t efivarfs -o ro,nosuid,nodev,noexec efivarfs /sys/firmware/efi/efivars; then
        echo 'menu: EFI loader variables are unavailable'
    fi
fi
/usr/bin/zboot menu
# A failed or closed menu has consumed its initial automatic boot opportunity.
while :; do
    echo 'menu returned; restarting in 2 seconds'
    sleep 2
    /usr/bin/zboot menu --no-autoboot
done
