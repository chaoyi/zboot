#!/bin/busybox sh
# /init of the initramfs `zboot boot --tar` builds (menu/ram_boot.rs): unpack
# the root tar onto a tmpfs, apply each overlay's rootfs/ in order and start
# the tar's own init. Every byte zboot brought is gone before switch_root.
PATH=/bin
export PATH
b=/bin/busybox
log() { echo "<6>zboot RAM boot: $*" > /dev/kmsg; }
fail() {
    echo "<3>zboot RAM boot failed: $*" > /dev/kmsg
    echo "zboot RAM boot failed: $*; a shell follows"
    exec $b sh
}
$b mkdir -p /proc /sys /dev /newroot
# GNU tar starts `zstd -d` through /bin/sh.
$b ln -s busybox /bin/sh
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
# zboot checked before kexec that the unpacked tar fits in this machine's
# RAM, so the root may grow to all of it rather than tmpfs's default half.
$b mount -t tmpfs -o mode=0755,size=100% tmpfs /newroot || fail 'cannot mount the RAM root'
if [ -f /zboot/root.tar.zst ]; then
    root=/zboot/root.tar.zst zstd=--zstd
else
    root=/zboot/root.tar zstd=
fi
log 'unpacking the root tar'
# The options deploy extracts a root tar with.
tar --extract --file="$root" $zstd --directory=/newroot --xattrs '--xattrs-include=*' --acls \
    --numeric-owner --same-owner --same-permissions --delay-directory-restore ||
    fail 'cannot unpack the root tar'
$b rm "$root"
# Overlays as deploy applies them: a file replaces what is there, and an
# existing directory keeps its owner and mode. Files get the current time.
for overlay in /zboot/overlay/*.tar; do
    [ -f "$overlay" ] || continue
    log "applying overlay ${overlay##*/}"
    tar --extract --file="$overlay" --directory=/newroot --xattrs '--xattrs-include=*' \
        --numeric-owner --same-owner --same-permissions --no-overwrite-dir --touch ||
        fail "cannot apply overlay ${overlay##*/}"
    $b rm "$overlay"
done
$b mkdir -p /newroot/proc /newroot/sys /newroot/dev
$b mount --move /proc /newroot/proc
$b mount --move /sys /newroot/sys
$b mount --move /dev /newroot/dev
for init in /sbin/init /usr/sbin/init; do
    if [ -L "/newroot$init" ] || [ -e "/newroot$init" ]; then
        exec $b switch_root /newroot "$init"
    fi
done
fail 'the root has no init'
