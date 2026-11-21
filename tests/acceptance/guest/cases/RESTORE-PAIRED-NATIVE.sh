# A paired secondary on B is restored onto A: the bare secondary is refused,
# the boundary snapshot restores through full consent, A's restored BE is
# unfenced and unpaired, and B's side of the pair, whose peer was erased, is
# unpaired, still fenced, keeps its anchor holds and is bootable again. A
# paired BE is one dataset with no children (a pair joins two leaves).
. /acceptance/restore.sh

stage_1() {
    restore_base
    restore_scratch
    # The BE starts on A and is mirrored to B as a fenced secondary.
    must a-root zfs create -o canmount=off -o mountpoint=none e2ea/ROOT
    must be zfs create -o "mountpoint=$SETUP_MOUNT/be1" e2ea/ROOT/be1
    put "$SETUP_MOUNT/be1/etc/hostid" "$(printf 'zbt\001')"
    restore_boot "$SETUP_MOUNT/be1"
    put "$SETUP_MOUNT/be1/restore-token" ZFS-E2E-RESTORE-ROOT
    restore_placement be e2ea/ROOT/be1 /
    must b-root zfs create -o canmount=off -o mountpoint=none e2eb/ROOT
    # Native fixture construction ends here. Product UKI commands plan with
    # read-only imported pools and own each later writable transition.
    for pool in e2ea e2eb; do
        must "sync-guid-$pool" zpool get -H -p -o value guid "$pool"
        pool_guid=$(cat "$ZT_LAST.out")
        [ -n "$pool_guid" ] || fail "fixture pool $pool has no native GUID"
        must "sync-export-$pool" zpool export "$pool"
        must "sync-import-$pool" zpool import -N -o readonly=on -o cachefile=none -d /dev "$pool_guid"
    done
    must sync-readonly zpool get -H -o name,value readonly e2ea e2eb
    # Preserve the native dataset-property view across RO planning and the
    # product's temporary writable pool access without presuming its values.
    must sync-dataset-readonly-before zfs get -H -r -o name,property,value,source readonly e2ea/ROOT/be1
    observe sync-before-preview
    zb sync-preview sync e2ea/ROOT/be1 e2eb/ROOT/be1 --dry-run
    SYNC_TOKEN=$(json .token) || fail 'sync preview has no token'
    observe sync-after-preview
    zb sync sync e2ea/ROOT/be1 e2eb/ROOT/be1 --confirm "$SYNC_TOKEN"
    must sync-dataset-readonly-after zfs get -H -r -o name,property,value,source readonly e2ea/ROOT/be1 e2eb/ROOT/be1
    must secondary zfs get -H -o property,value readonly,zboot:pair e2eb/ROOT/be1
    must boundary zfs list -H -t snapshot -o name -s createtxg e2eb/ROOT/be1
    RESTORE_FROM=$(tail -n 1 "$ZT_LAST.out")
    [ -n "$RESTORE_FROM" ] || fail 'the mirror has no snapshot'
    observe before
    must restore-readonly zpool get -H -o name,value readonly e2ea e2eb
    # A bare secondary is refused: it has no writable head to snapshot.
    zb bare restore e2eb/ROOT/be1 "$(disk A)" --dry-run
    RESTORE_KEEP='--keep e2ea/scratch'
    reviewed restore zr
    zr restore-apply --confirm "$TOKEN"
    RESTORE_BE_VAR='' restore_completed done e2ea/scratch
    must secondary-after zfs get -H -o property,value readonly,zboot:pair e2eb/ROOT/be1
    must holds-after sh -c 'zfs list -H -t snapshot -o name -r e2eb/ROOT/be1 | xargs -r zfs holds -H'
    must boot-readonly zpool get -H -o name,value readonly
    must listing zboot status e2eb/ROOT/be1 --json
    step boot-probe zboot boot e2eb/ROOT/be1 --kernel __zboot_missing_kernel__ --json
}
