# MAINTENANCE-NATIVE: `zboot chroot` gives a private writable maintenance
# chroot of the selected BE (child status propagated, no leaked mounts, a
# temporary pool cache and private /run), and refuses a paired secondary.
MP=/mnt/zfs-e2e/maintenance
CHILD='test -r /proc/self/mountinfo && test -d /sys/class/block && test -c /dev/null && test -d /dev/pts || exit 90; printf MAINTENANCE-WRITE > /maintenance-token; printf TEMPORARY-CACHE > /etc/zfs/zpool.cache; printf PRIVATE-RUN > /run/maintenance-token; exit 7'

stage_1() {
    fixture_pools
    must mkdir-pts mkdir -p /dev/pts
    must mount-pts mount -t devpts devpts /dev/pts
    must create-be zfs create -o mountpoint=/ -o canmount=noauto e2ea/maintenance
    must mkdir-mp mkdir -p "$MP"
    must mount-be mount -t zfs -o zfsutil e2ea/maintenance "$MP"
    must layout sh -e -c 'cd "$1"; mkdir -p bin etc/zfs dev/pts proc sys run; cp /e2e-maintenance-busybox bin/sh; printf ORIGINAL-CACHE-BYTES > etc/zfs/zpool.cache' layout "$MP"
    must inode-before busybox stat -c %i "$MP/etc/zfs/zpool.cache"
    must umount-be umount "$MP"
    must mountinfo-before cat /proc/self/mountinfo
    step chroot zboot chroot e2ea/maintenance -- /bin/sh -c "$CHILD"
    must mountinfo-after cat /proc/self/mountinfo
    must remount-be mount -t zfs -o zfsutil e2ea/maintenance "$MP"
    must token cat "$MP/maintenance-token"
    must cache cat "$MP/etc/zfs/zpool.cache"
    must inode-after busybox stat -c %i "$MP/etc/zfs/zpool.cache"
    refuse run-token cat "$MP/run/maintenance-token"
    must umount-be-again umount "$MP"
    must mounted zfs get -H -p -o value mounted e2ea/maintenance

    # A paired secondary is refused.
    must snapshot-paired zfs snapshot e2ea/maintenance@paired
    must replicate sh -c '{ zfs send -w -R e2ea/maintenance@paired; echo $? > /run/m-send.rc; } | zfs receive -u -o readonly=on e2eb/maintenance; r=$? s=$(cat /run/m-send.rc); echo "send=$s receive=$r" >&2; [ "$s" = 0 ] && [ "$r" = 0 ]'
    must pair zboot pair e2ea/maintenance e2eb/maintenance --json
    observe before-refusal
    refuse secondary zboot chroot e2eb/maintenance -- /bin/sh -c 'printf BAD > /secondary-command-ran'
    observe after-refusal
    must mkdir-secondary mkdir -p /mnt/zfs-e2e/secondary
    must mount-secondary mount -t zfs -o ro,zfsutil e2eb/maintenance /mnt/zfs-e2e/secondary
    step secondary-ran busybox test -e /mnt/zfs-e2e/secondary/secondary-command-ran
    must secondary-root ls -a /mnt/zfs-e2e/secondary
    must umount-secondary umount /mnt/zfs-e2e/secondary
}
