# shellcheck disable=SC2016 # sh -c bodies expand arguments in the invoked shell.
# zboot pair/unpair natively on leaves: previews, refusals (no shared
# history, clone, child, ahead second operand), a copy missing an older
# snapshot still pairs, publication with fencing and anchors, idempotent
# repeat, conservative unpair, re-pair and consented anchor release.
. /acceptance/lifecycle.sh
L=e2eb/pairleaf R=e2ea/receiver

# seed NAME 'SEND-ARGS' TARGET: a property-free raw copy, read-only.
seed() {
    must "$1" sh -e -c 'zfs send -w $1 | zfs receive -u -o readonly=on "$2"' seed "$2" "$3"
}

stage_1() {
    fixture_pools
    must create-left zfs create -o mountpoint=none -o encryption=aes-256-gcm -o keyformat=raw \
        -o keylocation=file:///run/zfs-e2e-key $L
    must snapshot-early zfs snapshot $L@early
    must snapshot-common zfs snapshot $L@common
    seed seed "$L@early" $R
    must seed-common sh -e -c 'zfs send -w -I @early "$1@common" | zfs receive -u "$2"' seed $L $R
    must preview-left zboot pair $L $R --dry-run --json
    must preview-default zboot pair $L $R --dry-run --json

    # Older snapshots may differ: a copy without @early still pairs.
    seed pruned-seed "$L@common" e2ea/pruned
    must preview-pruned zboot pair $L e2ea/pruned --dry-run --json

    # Same snapshot name, no shared snapshot.
    must unrelated sh -e -c 'zfs create -o mountpoint=none e2ea/unrelated; zfs snapshot e2ea/unrelated@common'
    observe unrelated-before
    refuse unrelated-pair zboot pair $L e2ea/unrelated
    observe unrelated-after

    must clone zfs clone -o mountpoint=none e2ea/plain@first e2ea/clone
    observe clone-before
    refuse clone-pair zboot pair e2ea/plain e2ea/clone
    observe clone-after

    # A pair joins leaves: a child under either side refuses.
    must child zfs create -o mountpoint=none $L/child
    observe child-before
    refuse child-pair zboot pair $L $R
    observe child-after
    must child-destroy zfs destroy $L/child

    # A newer snapshot selects the source.
    must snapshot-ahead zfs snapshot $L@ahead
    observe right-before
    refuse right-pair zboot pair $R $L
    observe right-after
    must preview-ahead zboot pair $L $R --dry-run --json
    observe before
    must pair zboot pair $L $R --json
    observe paired
    must repeat zboot pair $L $R --json
    must unpair zboot unpair $L --json
    observe unpaired
    refuse unpair-again zboot unpair $L
    observe unpaired-again
    must repair zboot pair $L $R --json
    consent release unpair $L --release-anchors
    observe released
}
