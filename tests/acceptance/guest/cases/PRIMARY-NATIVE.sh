# shellcheck disable=SC2016 # sh -c bodies expand arguments in the invoked shell.
# zboot primary on a leaf pair: a child under either side refuses; a
# token-bound catch-up moves ownership and the unsnapshotted head data to the
# peer; a replay is a no-op; a standalone activation after unpair restores
# the saved placement.
. /acceptance/lifecycle.sh
S=e2ea/primary-source T=e2eb/primary-target
SP=/mnt/zfs-e2e/primary-source TP=/mnt/zfs-e2e/primary-target

stage_1() {
    fixture_pools
    must create-root zfs create -o mountpoint=$SP $S
    put token-before-pair "$SP/handoff-token" before-pair
    must snapshot-common zfs snapshot $S@common
    must seed sh -e -c 'zfs send "$1@common" | zfs receive -u -o readonly=on "$2"' seed $S $T
    must place-root zfs set mountpoint=$TP readonly=off canmount=on $T
    must pair zboot pair $S $T --json
    # Head data with no snapshot until primary quiesces the old writer.
    put token-final "$SP/handoff-token" final-after-pair
    # A child under a pair leaf would mount over the live copy's path on the
    # side that becomes dormant: primary refuses while one exists.
    must create-extra zfs create $S/extra
    observe child-before
    refuse child-primary zboot primary $T --dry-run --json
    observe child-after
    must destroy-extra zfs destroy $S/extra
    observe before
    must preview zboot primary $T --dry-run --json
    token=$(json .token) || fail 'primary preview carries no token'
    must primary zboot primary $T --confirm "$token" --json
    observe after
    must target-root cat "$TP/handoff-token"
    must replay zboot primary $T --json
    observe replayed
    must alone zfs create -o mountpoint=none e2ea/alone
    must plain zboot primary e2ea/alone --json
    must unpair zboot unpair $T --json
    must standalone zboot primary $S --json
    observe independent
    must source-root cat "$SP/handoff-token"
}
