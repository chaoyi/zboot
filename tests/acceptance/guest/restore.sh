# Shared fixture and steps of the restore cases (sourced by guest/cases/RESTORE-*.sh).
# Host-side judgements of what these record live in host/restore.py.
#
# Every restore case restores the source BE from B onto disk A. A's new ESP
# gets the loader the source ships: this session's UKI, which restore_boot
# puts at /usr/lib/zboot/zboot.efi as the zboot package does. D's partition 2
# is free for pool C.

RESTORE_FROM=e2eb/ROOT/be1@src
RESTORE_KEEP=
SOURCE_MOUNT=/mnt/zfs-e2e/restore-source
SETUP_MOUNT=/mnt/zfs-e2e/restore-setup
READ_MOUNT=/mnt/zfs-e2e/restore-read

# slug NAME: a dataset name usable in a step name.
slug() { echo "$1" | tr '/@' '__'; }

# restore_fixtures: the read-only bulk fixture share at /fixtures, which
# lib.sh normally mounts already.
restore_fixtures() {
    if [ ! -d /fixtures/e2e-esp-artifacts ]; then
        mkdir -p /fixtures
        must fixtures-mount mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-fixtures /fixtures
    fi
    # The share is the one this initrd was built against (its embedded manifest).
    must fixtures-manifest sha256sum /fixtures/manifest.json /e2e-fixtures.manifest.json
}

# put FILE CONTENT: write CONTENT (no newline) into FILE.
put() { mkdir -p "${1%/*}" && printf '%s' "$2" > "$1" || fail "cannot write $1"; }

# restore_hostid: on every boot, before any pool is imported: the fixed hostid.
restore_hostid() {
    must hostid-pools zpool list -H -o name
    fixture_hostid
}

# restore_base: hostid, the common pools, and D's partition 2 for pool C.
restore_base() {
    restore_hostid
    restore_fixtures
    fixture_pools
    must disks sh -c 'for d in /sys/block/vd*; do echo "$(cat "$d/serial") /dev/${d##*/}"; done'
    zr_d=$(disk D)
    must d-part sgdisk -n 2:0:0 -t 2:BF01 "$zr_d"
    must d-probe partprobe "$zr_d"
    mdev -s
}

# restore_boot ROOT: what a source root needs to be restored: the loader it
# ships, the session's UKI at ROOT/usr/lib/zboot/zboot.efi (source-loader
# records its SHA-256), and a kernel pair, so the restored BE can be the
# boot default. The pair stays unbooted; the EFI cases boot real kernels.
restore_boot() {
    mkdir -p "$1/usr/lib/zboot" || fail "cannot create $1/usr/lib/zboot"
    must source-loader-copy cp /fixtures/e2e-esp-artifacts/zboot-recovery.efi "$1/usr/lib/zboot/zboot.efi"
    must source-loader sha256sum "$1/usr/lib/zboot/zboot.efi"
    put "$1/boot/vmlinuz-zt" ZFS-E2E-RESTORE-KERNEL
    put "$1/boot/initrd.img-zt" ZFS-E2E-RESTORE-INITRD
}

# restore_placement NAME DATASET MOUNTPOINT: unmount a populated tree
# (deepest first) and give it a BE's placement without mounting; NAME-placed
# records `mounted` for the whole tree.
restore_placement() {
    must "$1-mounted" zfs list -H -r -o name,mounted "$2"
    for zr_ds in $(tac "$ZT_LAST.out" | awk -F '\t' '$2 == "yes" { print $1 }'); do
        must "$1-unmount-$(slug "$zr_ds")" zfs unmount "$zr_ds"
    done
    must "$1-noauto" zfs set -u canmount=noauto "$2"
    must "$1-mountpoint" zfs set -u "mountpoint=$3" "$2"
    must "$1-placed" zfs get -H -r -o name,value mounted "$2"
}

# restore_source: the source BE e2eb/ROOT/be1{,/var}@src with the fixed
# hostid, the shipped loader and a kernel pair.
restore_source() {
    must source-root zfs create -o canmount=off -o mountpoint=none e2eb/ROOT
    must source-be zfs create -o "mountpoint=$SOURCE_MOUNT" e2eb/ROOT/be1
    put "$SOURCE_MOUNT/etc/hostid" "$(printf 'zbt\001')"
    restore_boot "$SOURCE_MOUNT"
    put "$SOURCE_MOUNT/restore-token" ZFS-E2E-RESTORE-ROOT
    must source-var zfs create -o "mountpoint=$SOURCE_MOUNT/var" e2eb/ROOT/be1/var
    put "$SOURCE_MOUNT/var/restore-token" ZFS-E2E-RESTORE-VAR
    restore_placement source e2eb/ROOT/be1 /
    must source-var-noauto zfs set -u canmount=noauto e2eb/ROOT/be1/var
    must source-var-mountpoint zfs set -u mountpoint=/var e2eb/ROOT/be1/var
    must source-snapshot zfs snapshot -r e2eb/ROOT/be1@src
}

# restore_scratch: e2ea/scratch, an unmounted kept tree with a token.
restore_scratch() {
    must scratch zfs create -o "mountpoint=$SETUP_MOUNT/scratch" e2ea/scratch
    put "$SETUP_MOUNT/scratch/restore-token" ZFS-E2E-RESTORE-SCRATCH
    must scratch-unmount zfs unmount e2ea/scratch
}

# restore_pool_c [bootfs]: pool C on D2, imported read-only; with `bootfs`
# it names e2ec/ROOT/old as its boot default.
restore_pool_c() {
    zr_c="$(disk D)2"
    must c-create zpool create -f -o cachefile=none -O mountpoint=none e2ec "$zr_c"
    must c-root zfs create -o canmount=off e2ec/ROOT
    must c-old zfs create -o canmount=noauto e2ec/ROOT/old
    if [ "$1" = bootfs ]; then must c-bootfs zpool set bootfs=e2ec/ROOT/old e2ec; fi
    must c-export zpool export e2ec
    restore_import_c c-import
    must c-readonly zpool get -H -o value readonly e2ec
}
restore_import_c() { must "$1" zpool import -N -o readonly=on -o cachefile=none -d "$(disk D)2" e2ec; }

# zb NAME ARG...: `zboot ARG... --json`, recorded whatever its status.
zb() { zr_n=$1; shift; step "$zr_n" zboot "$@" --json; }

# zr NAME ARG...: the case's restore (RESTORE_FROM onto A, RESTORE_KEEP) with ARGs.
zr() {
    zr_n=$1; shift
    # shellcheck disable=SC2086 # RESTORE_KEEP is a list of `--keep ROOT` words
    zb "$zr_n" restore "$RESTORE_FROM" "$(disk A)" $RESTORE_KEEP --pool e2ea --esp 512M "$@"
}

# previewed NAME CMD...: CMD --dry-run must succeed with a token (TOKEN).
previewed() {
    zr_p=$1; shift
    "$@" --dry-run || fail "$zr_p exited $(cat "$ZT_LAST.rc")"
    TOKEN=$(json .token) || fail "$zr_p has no token"
}

# reviewed NAME CMD...: the full consent sequence of CMD (zb/zr form): fresh
# preview (NAME-preview), unattended (NAME-unattended, exit 3), a wrong token
# (NAME-wrong-token, refused). TOKEN is the preview's.
reviewed() {
    zr_r=$1 zr_cmd=$2; shift 2
    previewed "$zr_r-preview" "$zr_cmd" "$zr_r-preview" "$@"
    "$zr_cmd" "$zr_r-unattended" "$@"
    [ "$(cat "$ZT_LAST.rc")" = 3 ] || fail "$zr_r-unattended exited $(cat "$ZT_LAST.rc"), not 3"
    "$zr_cmd" "$zr_r-wrong-token" "$@" --confirm not-the-reviewed-token
    [ "$(cat "$ZT_LAST.rc")" = 3 ] || fail "$zr_r-wrong-token exited $(cat "$ZT_LAST.rc"), not 3"
}

# restore_cut STEP: preview the restore, arm a cut before its record write
# `zfs set zboot:operation={"kind":"restore","step":STEP,...} e2eb`, apply.
# The matcher (restore-cut.sh) also saves the mount tables at that instant.
restore_cut() {
    previewed restore-preview zr restore-preview
    arm restore-cut zfs "/bin/sh /acceptance/restore-cut.sh $1 $ZT_OUT \"\$@\""
    zr restore-apply --confirm "$TOKEN"
    fail "the restore ended (rc $(cat "$ZT_LAST.rc")) before its step-$1 record write"
}

# restore_record NAME: B's restore record (`-` when none); sets RECORD_ID.
restore_record() {
    must "$1" zfs get -H -o value zboot:operation e2eb
    RECORD_ID=$(json .id 2> /dev/null) || RECORD_ID=
}

# restore_read NAME DATASET: mount DATASET read-only, record its token and
# the hashes of every file in it, unmount.
restore_read() {
    zr_s="$1-$(slug "$2")"
    mkdir -p "$READ_MOUNT"
    must "$zr_s-mount" mount -t zfs -o ro,zfsutil "$2" "$READ_MOUNT"
    step "$zr_s-token" cat "$READ_MOUNT/restore-token"
    payload "$zr_s" "$READ_MOUNT"
    must "$zr_s-umount" umount "$READ_MOUNT"
}

# restore_completed LABEL [KEPT...]: the completed restore, natively. B's
# record, the imported pools and mounts (LABEL-done); A imported read-only
# (LABEL-restored), the restored BE's properties, and the content of the BE,
# its var child (RESTORE_BE_VAR, empty for a BE without one) and each KEPT
# root; A exported again.
restore_completed() {
    zr_l=$1; shift
    restore_record "$zr_l-record"
    must "$zr_l-bootfs" zpool get -H -o name,value bootfs
    observe "$zr_l-done"
    must "$zr_l-import" zpool import -N -o readonly=on -o cachefile=none -d /dev e2ea
    must "$zr_l-a-bootfs" zpool get -H -o value bootfs e2ea
    must "$zr_l-be" zfs get -H -o property,value \
        mountpoint,canmount,readonly,zboot:pair,zboot:placement,mounted e2ea/ROOT/be1
    observe "$zr_l-restored"
    # shellcheck disable=SC2086
    for zr_k in e2ea/ROOT/be1 ${RESTORE_BE_VAR-e2ea/ROOT/be1/var} "$@"; do
        restore_read "$zr_l" "$zr_k"
    done
    must "$zr_l-export" zpool export e2ea
}
