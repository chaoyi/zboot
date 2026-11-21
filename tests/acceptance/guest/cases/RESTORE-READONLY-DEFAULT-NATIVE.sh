# A read-only third pool C names a boot default: the restore stops at
# `properties restored` and keeps its record until C is writable; then
# resume completes and no pool but A names a boot default.
. /acceptance/restore.sh

stage_1() {
    restore_base
    restore_source
    restore_scratch
    restore_pool_c bootfs
    RESTORE_KEEP='--keep e2ea/scratch'
    previewed restore-preview zr restore-preview
    zr restore-apply --confirm "$TOKEN"
    restore_record stopped-record
    [ -n "$RECORD_ID" ] || fail 'no restore record after the stop'
    must stopped-c zpool get -H -o property,value readonly,bootfs e2ec
    observe stopped
    # Still read-only: resume stops again and keeps the record.
    zb resume-readonly resume "$RECORD_ID"
    restore_record refused-record
    must refused-c zpool get -H -o property,value readonly,bootfs e2ec
    must c-export-ro zpool export e2ec
    must c-import-rw zpool import -N -o cachefile=none -d "$(disk D)2" e2ec
    zb resume resume "$RECORD_ID"
    restore_completed done e2ea/scratch
}
