#!/bin/sh
# Test guest PID 1. The only writable block device is a new private /dev/vda.
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
mkdir -p /proc /sys /dev /run /fixtures /evidence
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
mount -t tmpfs -o mode=0755 tmpfs /run
echo NATIVE_SDK_GUEST_START
for module in virtio_pci virtio_blk 9pnet_virtio 9p zfs; do
    modprobe "$module" || { echo "module failed: $module"; poweroff -f; }
done
mount -t 9p -o trans=virtio,version=9p2000.L,ro fixtures /fixtures || poweroff -f
mount -t 9p -o trans=virtio,version=9p2000.L evidence /evidence || poweroff -f
run_proof() {
    set -e
    /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never
    udevadm trigger --type=devices --action=add
    udevadm settle
    test -b /dev/vda
    test ! -b /dev/vdb
    test ! -b /dev/sda
    test "$(cat /sys/class/block/vda/size)" = 4194304
    test -z "$(zpool list -H -o name 2>/dev/null)"
    zpool create -f -o cachefile=none -O mountpoint=none sdkproof /dev/vda
    zfs create sdkproof/tree
    zfs create sdkproof/tree/child
    zfs create -s -V 16M sdkproof/tree/volume
    printf 'private-vda-only\n' >/run/native-sdk-proof
    /bin/busybox uname -a >/evidence/guest-runtime.txt
    zfs version >>/evidence/guest-runtime.txt
    /fixtures/checkpoint --isolated-native-proof >/evidence/results.jsonl 2>/evidence/consumer-stderr.txt
    zpool status -P sdkproof >/evidence/pool-status.txt
    zfs list -H -p -r -t filesystem,volume,snapshot -o name,type,guid,createtxg,objsetid sdkproof >/evidence/final-inventory.tsv
    zfs holds -H sdkproof/tree/volume-original@deferred >/evidence/final-holds.tsv
    zfs get -H -p -o name,property,value,source defer_destroy sdkproof/tree/volume-original@deferred >/evidence/final-deferred.tsv
    zpool export sdkproof
    printf 'passed\n' >/evidence/status
    sync
}
(run_proof) >/evidence/guest.log 2>&1
result=$?
if [ "$result" != 0 ]; then
    printf 'failed:%s\n' "$result" >/evidence/status
    cat /evidence/guest.log
    cat /evidence/consumer-stderr.txt 2>/dev/null || :
fi
echo "NATIVE_SDK_GUEST_FINISHED=$result"
sync
poweroff -f
