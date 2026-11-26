# Common native fixture for the native cases (sourced by lib.sh). Built with
# native tools only; no product command runs here.

# disk LABEL: the /dev node of the virtio or NVMe disk with serial ZFS-E2E-LABEL.
disk() {
    for d in /sys/block/vd* /sys/block/nvme*n*; do
        # NVMe pads its serial with spaces; read trims them.
        s=
        read -r s 2>/dev/null < "$d/serial" || read -r s 2>/dev/null < "$d/device/serial"
        if [ "$s" = "ZFS-E2E-$1" ]; then
            echo "/dev/${d##*/}"
            return 0
        fi
    done
    fail "no disk with serial ZFS-E2E-$1"
}

# disk_ends DISK: SHA-256 of the disk's first and last MiB, which hold its
# partition tables and whole-disk labels. Cases compare these and the plan,
# never a hash of the whole disk.
disk_ends() {
    mib=$(($(busybox blockdev --getsize64 "$1") / 1048576))
    dd if="$1" bs=1048576 count=1 2>/dev/null | sha256sum
    dd if="$1" bs=1048576 skip=$((mib - 1)) count=1 2>/dev/null | sha256sum
}

# fixture_hostid: the restore cases' fixed guest hostid 0174627a, set before any pool exists.
fixture_hostid() {
    [ -z "$(zpool list -H -o name)" ] || fail 'a pool exists before the hostid change'
    printf 'zbt\001' > /etc/hostid
    echo 24404602 > /sys/module/spl/parameters/spl_hostid
    must hostid cat /proc/sys/kernel/spl/hostid /etc/hostid
}

# fixture_pools: e2ea on A1 and e2eb on B1 (cachefile=none, root mountpoint=none);
# e2ea/plain{,/child} with @first and @second, e2eb/plain, and the raw-key
# encrypted e2eb/encrypted{,/child}@secret (key /run/zfs-e2e-key). D stays blank.
fixture_pools() {
    must versions sh -c 'uname -a; zfs version; cat /sys/module/zfs/version'
    for pair in e2ea:A e2eb:B; do
        pool=${pair%:*} dev=$(disk "${pair#*:}")
        must "part-$pool" sgdisk -n 1:0:0 -t 1:BF01 "$dev"
        must "probe-$pool" partprobe "$dev"
        mdev -s
        must "create-$pool" zpool create -f -o cachefile=none -O mountpoint=none "$pool" "${dev}1"
    done
    must fixture-datasets sh -e -c '
        zfs create -o mountpoint=none e2ea/plain
        zfs create -o mountpoint=none e2ea/plain/child
        zfs create -o mountpoint=none e2eb/plain
        zfs snapshot -r e2ea/plain@first
        zfs snapshot -r e2ea/plain@second
        dd if=/dev/urandom of=/run/zfs-e2e-key bs=32 count=1 2>/dev/null
        zfs create -o mountpoint=none -o encryption=aes-256-gcm -o keyformat=raw \
            -o keylocation=file:///run/zfs-e2e-key e2eb/encrypted
        zfs create -o mountpoint=none e2eb/encrypted/child
        zfs snapshot -r e2eb/encrypted@secret'
    observe fixture
}
