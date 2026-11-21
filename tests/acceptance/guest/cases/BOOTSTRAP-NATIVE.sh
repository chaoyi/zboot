# zboot sync to an absent receiver bootstraps a leaf and pairs it as a fenced
# secondary with the source's copied properties set locally; a source with a
# child is refused; a plain unpair keeps the anchors; `unpair
# --release-anchors` releases exactly zboot's anchors on both sides (a
# foreign hold stays, a deferred destroy completes) and is refused once
# nothing is paired.
. /acceptance/lifecycle.sh

stage_1() {
    fixture_pools
    must create-root zfs create -o mountpoint=/mnt/zfs-e2e/bootstrap-source \
        -o compression=zstd -o e2e:bootstrap=source e2eb/bootstrap
    put write-root /mnt/zfs-e2e/bootstrap-source/data 'bootstrap root content'
    must snapshot-retained zfs snapshot e2eb/bootstrap@retained
    # A pair joins leaves: a source with a child is refused before any effect.
    must create-child zfs create e2eb/bootstrap/child
    observe child-before
    refuse child-sync zboot sync e2eb/bootstrap e2ea/bootstrap --json
    observe child-after
    must destroy-child zfs destroy e2eb/bootstrap/child
    observe before
    must sync zboot sync e2eb/bootstrap e2ea/bootstrap --json
    pair_id=$(json .result.pair_id) || fail 'bootstrap established no pair'
    observe after
    must mkdir-root mkdir -p /mnt/zfs-e2e/bootstrap-check
    must mount-root mount -t zfs -o ro,zfsutil e2ea/bootstrap /mnt/zfs-e2e/bootstrap-check
    must read-root cat /mnt/zfs-e2e/bootstrap-check/data
    must umount-root umount /mnt/zfs-e2e/bootstrap-check
    # The receiver's common snapshot that holds this pair's anchor.
    must anchor sh -c 'for s in $(zfs list -H -o name -t snapshot -d 1 e2ea/bootstrap); do
            zfs holds -H "$s" | awk -F "\t" -v tag="zboot:anchor:$1" "\$2 == tag { f = 1 } END { exit !f }" &&
                echo "${s#*@}"
        done' anchor "$pair_id"
    read -r suffix < "$ZT_LAST.out"
    [ -n "$suffix" ] || fail 'no anchored receiver snapshot'
    observe paired
    must unpair zboot unpair e2eb/bootstrap --json
    observe kept
    must foreign-hold zfs hold e2e:foreign "e2eb/bootstrap@$suffix"
    must deferred-destroy zfs destroy -d "e2ea/bootstrap@$suffix"
    consent release unpair e2eb/bootstrap --release-anchors
    observe released
    refuse release-again zboot unpair e2eb/bootstrap --release-anchors --json
    observe released-again
}
