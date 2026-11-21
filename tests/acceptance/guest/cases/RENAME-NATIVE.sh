# RENAME: same-pool move of a clone-connected tree: identity, placement,
# bootfs, dependents and replay.
. /acceptance/identity.sh
SRC=e2ea/move-source
DST=e2ea/move-container/renamed
stage_1() {
    fixture_pools
    must setup sh -e -c '
        P=/mnt/zfs-e2e/move-source
        zfs create -o mountpoint=none e2ea/move-template
        zfs snapshot e2ea/move-template@origin
        zfs clone -o mountpoint=$P -o compression=lz4 -o e2e:payload=source \
            e2ea/move-template@origin e2ea/move-source
        zfs create e2ea/move-source/child
        zfs create -o mountpoint=none -o compression=zstd e2ea/move-container
        printf retained-first-root > $P/data; printf retained-first-child > $P/child/data
        zfs snapshot -r e2ea/move-source@first
        printf retained-second-root > $P/data; printf retained-second-child > $P/child/data
        zfs snapshot -r e2ea/move-source@second
        zfs clone -o mountpoint=none e2ea/move-source/child@first e2ea/move-dependent
        printf unsnapshotted-root > $P/data; printf unsnapshotted-child > $P/child/data
        zpool set bootfs=e2ea/move-source e2ea'
    observe before
    must preview zboot rename $SRC $DST --dry-run --json
    rename_token=$(json .token) || fail "rename preview has no token"
    observe after-preview
    refuse existing zboot rename $SRC e2ea/plain --json
    observe after-existing
    refuse stale-token zboot rename $SRC $DST --confirm stale-token --json
    observe after-token
    must rename zboot rename $SRC $DST --confirm "$rename_token" --json
    observe after
    must live-root cat /mnt/zfs-e2e/move-source/data
    must live-child cat /mnt/zfs-e2e/move-source/child/data
    readat proof-root $DST@first data
    readat proof-child $DST/child@first data
    operation operation e2ea
    refuse replay zboot rename $SRC $DST --json
    observe after-replay
}
