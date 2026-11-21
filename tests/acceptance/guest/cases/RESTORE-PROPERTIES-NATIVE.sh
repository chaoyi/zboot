# RESTORE-PROPERTIES-NATIVE: the native OpenZFS facts zboot::restore and its
# fake build on. Fixed e2ea trees go into fenced staging on e2eb and back,
# dataset by dataset, parents first, as restore's execute.rs runs them through
# zfs_core::stream::leaf_replicate: a full raw stream of the first snapshot
# with `-o canmount=off` and the write-time values, local fences at once, then
# one `-I` stream to the boundary, both ends Debian's own `zfs`. No zboot CLI
# runs; the host judges the observed properties.
SNAP=zboot-restore-e2e0e2e0e2e0e2e0
STAGING=e2eb/zboot-restore-e2e0e2e0e2e0e2e0
PROPS=canmount,mountpoint,readonly,volmode,compression,encryptionroot,keylocation,keyformat,keystatus,mounted,receive_resume_token,zboot:placement,zfs-e2e:note
WRITE_TIME=copies,checksum,compression,recordsize,dnodesize,dedup,special_small_blocks,redundant_metadata

# tree NAME ROOT: name/property/value/source/received rows and snapshot guids.
tree() {
    must "$1-props" zfs get -H -p -r -t filesystem,volume -o name,property,value,source,received "$PROPS" "$2"
    must "$1-snaps" zfs list -H -p -r -t snapshot -o name,guid "$2"
}

# stream NAME 'SEND-ARGS' RECEIVE-ARGV...: `zfs send SEND-ARGS | zfs
# RECEIVE-ARGV` (LC_ALL=C). Fails unless both ends succeed; the statuses land
# in stderr as `send=N receive=N`.
stream() {
    name=$1 send=$2; shift 2
    step "$name" sh -c 'send=$1; shift; { LC_ALL=C zfs send $send; echo $? > /run/rp-send.rc; } | LC_ALL=C zfs "$@"; r=$? s=$(cat /run/rp-send.rc); echo "send=$s receive=$r" >&2; [ "$s" = 0 ] && [ "$r" = 0 ]' stream "$send" "$@"
}

# create_args DATASET: restore's `-o` values for a new copy of DATASET.
create_args() {
    printf '%s ' -o canmount=off
    zfs get -H -p -o property,value "$WRITE_TIME" "$1" |
        while IFS='	' read -r key value; do
            [ "$value" = - ] || printf '%s ' -o "$key=$value"
        done
}

# copy NAME SOURCE DESTINATION: one dataset, as restore copies it.
copy() {
    args=$(create_args "$2") || fail "$1: no write-time values"
    # shellcheck disable=SC2086
    stream "$1-full" "-w $2@early" receive -u $args "$3" || fail "$1-full failed"
    must "$1-fence" zfs set -u readonly=on volmode=none mountpoint=none canmount=off "$3"
    stream "$1-incremental" "-w -I $2@early $2@$SNAP" receive -u "$3" || fail "$1-incremental failed"
}

stage_1() {
    fixture_pools
    # A's kept trees: a plain tree with every property class the engine
    # treats specially, and an encryption root whose key stays unloaded.
    must create-rp zfs create -u -o canmount=noauto -o mountpoint=/mnt/zfs-e2e/rp \
        -o compression=zstd -o zboot:placement=rp-e2e-placement -o zfs-e2e:note=top e2ea/rp
    must create-rp-child zfs create -u -o canmount=on -o readonly=on -o zfs-e2e:note=child e2ea/rp/child
    must create-rp-secret zfs create -u -o mountpoint=none -o encryption=aes-256-gcm \
        -o keyformat=raw -o keylocation=file:///run/zfs-e2e-key e2ea/rp-secret
    must prompt-rp-secret zfs set keylocation=prompt e2ea/rp-secret
    must create-rp-inner zfs create -u -o mountpoint=none e2ea/rp-secret/inner
    must unload-rp-secret zfs unload-key e2ea/rp-secret
    for tree in rp rp-secret; do
        must "early-$tree" zfs snapshot -r "e2ea/$tree@early"
        must "snapshot-$tree" zfs snapshot -r "e2ea/$tree@$SNAP"
    done
    tree source-plain e2ea/rp
    tree source-secret e2ea/rp-secret
    # Restore step 3: fenced staging on B, parents first.
    must create-staging zfs create -u -o canmount=off -o mountpoint=none -o readonly=on -o volmode=none "$STAGING"
    copy stage-rp e2ea/rp "$STAGING/rp"
    copy stage-rp-child e2ea/rp/child "$STAGING/rp/child"
    copy stage-rp-secret e2ea/rp-secret "$STAGING/rp-secret"
    copy stage-rp-inner e2ea/rp-secret/inner "$STAGING/rp-secret/inner"
    tree staged "$STAGING"
    # Restore step 7: back to A (a sibling of the originals here).
    must create-back zfs create -u -o canmount=off -o mountpoint=none -o readonly=on -o volmode=none e2ea/rp-back
    copy return-rp "$STAGING/rp" e2ea/rp-back/rp
    copy return-rp-child "$STAGING/rp/child" e2ea/rp-back/rp/child
    copy return-rp-secret "$STAGING/rp-secret" e2ea/rp-back/rp-secret
    copy return-rp-inner "$STAGING/rp-secret/inner" e2ea/rp-back/rp-secret/inner
    tree returned e2ea/rp-back
    # `send -R -b` from a staged encryption root carries no keylocation; a
    # raw receive of it fails. Restore never sends `-R` or `-b`.
    stream backup-flag "-w -R -b $STAGING/rp-secret@$SNAP" receive -u e2ea/rp-backup-flag
    must zfs-version zfs version
    observe final
}
