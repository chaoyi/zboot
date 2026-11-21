# Kept inactive BE (mountpoint=/, noauto), a canmount=on home and volumes
# under inherited and local volmode. Cut before the step-11 (booted) record
# write: nothing of A is mounted, nothing over the running root. After the
# restart the staged volumes are inert; resume completes and every kept root
# keeps its placement and volume mode.
. /acceptance/restore.sh

stage_1() {
    restore_base
    restore_source
    must a-root zfs create -o canmount=off -o mountpoint=none e2ea/ROOT
    must old zfs create -o "mountpoint=$SETUP_MOUNT/be0" e2ea/ROOT/be0
    put "$SETUP_MOUNT/be0/restore-token" ZFS-E2E-RESTORE-OLD-BE
    restore_placement old e2ea/ROOT/be0 /
    must home zfs create -o "mountpoint=$SETUP_MOUNT/home" -o canmount=on e2ea/home
    put "$SETUP_MOUNT/home/restore-token" ZFS-E2E-RESTORE-HOME
    must home-unmount zfs unmount e2ea/home
    must home-mountpoint zfs set -u mountpoint=/home e2ea/home
    # An externally inherited volume mode and a local override.
    must volmode zfs set volmode=dev e2ea
    must vols zfs create -o canmount=off -o mountpoint=none e2ea/vols
    must volume zfs create -V 16M e2ea/volume
    must exposed zfs create -V 16M e2ea/vols/exposed
    must hidden zfs create -V 16M -o volmode=none e2ea/vols/hidden
    RESTORE_KEEP='--keep e2ea/ROOT/be0 --keep e2ea/home --keep e2ea/vols --keep e2ea/volume'
    restore_cut 11
}

stage_2() {
    restore_hostid
    must import-b zpool import -N -o cachefile=none -d /dev e2eb
    restore_record record
    [ -n "$RECORD_ID" ] || fail 'no restore record on B after the cut'
    observe after-cut
    must staged-volmode zfs get -H -o name,value volmode "e2eb/zboot-restore-$RECORD_ID/volume" \
        "e2eb/zboot-restore-$RECORD_ID/vols" "e2eb/zboot-restore-$RECORD_ID/vols/exposed" \
        "e2eb/zboot-restore-$RECORD_ID/vols/hidden"
    sleep 3   # zvol minors appear asynchronously after an import
    must block-devices ls /sys/class/block
    zb resume resume "$RECORD_ID"
    restore_completed done e2ea/ROOT/be0 e2ea/home
    must kept-import zpool import -N -o readonly=on -o cachefile=none -d /dev e2ea
    must kept-volmode zfs get -H -o name,value volmode e2ea/volume e2ea/vols e2ea/vols/exposed e2ea/vols/hidden
    must kept-placement zfs get -H -o name,property,value mountpoint,canmount,readonly e2ea/ROOT/be0 e2ea/home
    must kept-export zpool export e2ea
    scrub scrub-b e2eb
    observe final
}
