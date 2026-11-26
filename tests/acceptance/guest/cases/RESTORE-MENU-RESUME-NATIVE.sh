# Cut before the step-9 (restored) record write. After the restart only a
# read-only third pool C is imported; the UKI shell's common `resume` entry finds
# the record on B and completes; C and B are left read-only. An unrelated
# RAM file-vdev pool is RO for preview, then RW and untouched during resume.
. /acceptance/restore.sh

stage_1() {
    restore_base
    restore_source
    restore_scratch
    restore_pool_c
    RESTORE_KEEP='--keep e2ea/scratch'
    restore_cut 9
}

stage_2() {
    restore_hostid
    restore_import_c import-c
    observe before-menu
    # A maintenance pool on a bounded RAM file is unrelated to restore A/B.
    # It cannot supply block-backed preservation facts, and late resume must
    # not request those facts merely because this pool is imported.
    must unrelated-file /bin/busybox truncate -s 128M /run/e2eu.vdev
    must unrelated-create zpool create -f -o cachefile=none -O mountpoint=none -O canmount=off e2eu /run/e2eu.vdev
    must unrelated-guid zpool get -H -p -o value guid e2eu
    zr_unrelated_guid=$(cat "$ZT_LAST.out")
    must unrelated-export-created zpool export e2eu
    must unrelated-import zpool import -N -d /run/e2eu.vdev -o readonly=on -o cachefile=none "$zr_unrelated_guid"
    must unrelated-status zpool status -j -P e2eu
    must unrelated-readonly-before-preview zpool get -H -p -o property,value guid,readonly e2eu
    step menu-preview zboot resume --dry-run --json
    must unrelated-readonly-after-preview zpool get -H -p -o property,value guid,readonly e2eu
    must unrelated-export-readonly zpool export e2eu
    must unrelated-import-writable zpool import -N -d /run/e2eu.vdev -o readonly=off -o cachefile=none "$zr_unrelated_guid"
    must unrelated-before zpool get -H -p -o property,value guid,readonly e2eu
    must unrelated-before-mounted zfs get -H -o value mounted e2eu
    step menu zboot resume --json
    must unrelated-after zpool get -H -p -o property,value guid,readonly e2eu
    must unrelated-after-mounted zfs get -H -o value mounted e2eu
    must unrelated-export zpool export e2eu
    must unrelated-absent zpool list -H -o name
    must after-readonly zpool get -H -o name,value readonly e2ec e2eb
    restore_record after-record
    restore_completed done e2ea/scratch
}
