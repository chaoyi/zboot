# Cut before the step-9 (restored) record write: A is erased and staging on B
# is the only complete copy of the kept data. `abandon` keeps it held
# and marked; `drop` of it releases the holds and destroys it.
. /acceptance/restore.sh

stage_1() {
    restore_base
    restore_source
    restore_scratch
    RESTORE_KEEP='--keep e2ea/scratch'
    restore_cut 9
}

stage_2() {
    restore_hostid
    must import-b zpool import -N -o cachefile=none -d /dev e2eb
    restore_record record
    [ -n "$RECORD_ID" ] || fail 'no restore record on B after the cut'
    # restore_record clears RECORD_ID once the abandon has ended the record.
    OPERATION=$RECORD_ID
    STAGING=e2eb/zboot-restore-$OPERATION
    json .state.receipt.sha256 > /dev/null || fail 'no placement receipt in restore record'
    # The restore hold is the only reason the deferred source snapshot
    # survives. The non-deferred source child still has its ordinary hold.
    must defer-source zfs destroy -d e2eb/ROOT/be1@src
    must deferred-source-clones zfs list -H -p -t snapshot -o name,clones e2eb/ROOT/be1@src
    observe before
    reviewed abandon zb abandon "$RECORD_ID"
    zb abandon-apply abandon "$RECORD_ID" --confirm "$TOKEN"
    restore_record abandoned-record
    must staging-mark zfs get -H -o value zboot:staging "$STAGING"
    # Read the only kept copy through an explicit read-only inspection mount;
    # it returns to its inert native placement before the drop preview.
    restore_read abandoned-kept "$STAGING/scratch"
    observe abandoned
    must abandoned-receipt zfs get -H -p -o name,property,value,source all "$STAGING"
    must abandoned-placement-manifest zfs get -H -p -o name,property,value,source \
        "org.zfs-tools:restore-placement:$OPERATION:manifest" "$STAGING"
    reviewed drop zb drop "$STAGING"
    zb drop-apply drop "$STAGING" --confirm "$TOKEN"
    step dropped zfs list -H -o name "$STAGING"
    observe dropped
    scrub scrub-b e2eb
}
