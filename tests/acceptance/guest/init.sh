#!/bin/sh
# Disposable-VM init for acceptance cases (installed as /init). The kernel command line names the
# case and stage (zt.case=ID zt.stage=N); zt.udev=1 starts the runtime's udev.
# Without zt.case it drops to a console shell for manual debugging.
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
mkdir -p /proc /sys /dev /run
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mkdir -p /run/lock
chmod 0755 / /run /run/lock
cmdline=" $(cat /proc/cmdline) "
arg() { v=${cmdline##* "$1"=}; [ "$v" != "$cmdline" ] && printf %s "${v%% *}"; }
halt() { echo "ZT1 DONE $1" > /dev/ttyS1; sync; poweroff -f; }
die() { echo "zt-init: $*"; halt init-failed; }

case "$cmdline" in *" zt.udev=1 "*)
    /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never || die 'udevd failed' ;;
esac
for driver in virtio_pci virtio_rng virtio_blk virtio_scsi nvme ahci sd_mod 9pnet_virtio 9p; do
    modprobe "$driver" 2>/dev/null || :
done
modprobe zfs || die 'ZFS module failed to load'
case "$cmdline" in *" zt.udev=1 "*)
    udevadm trigger --type=subsystems --action=add &&
        udevadm trigger --type=devices --action=add &&
        udevadm settle --timeout=30 || die 'udev settle failed' ;;
esac

case=$(arg zt.case) || { export PS1='# '; exec /bin/sh; }
stage=$(arg zt.stage) || stage=1
mkdir -p /out && mount -t 9p -o trans=virtio,version=9p2000.L,cache=none zt-out /out ||
    die 'output share missing'
# lib.sh, fault.sh and the case scripts arrive on a read-only share, so a
# session's frozen copy (or a --dev working tree) runs without a new initrd.
mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-acceptance /acceptance ||
    die 'acceptance share missing'
. /acceptance/lib.sh
zt_run "$case" "$stage"
