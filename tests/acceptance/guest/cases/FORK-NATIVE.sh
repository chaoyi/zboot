# FORK: native clone of a BE snapshot: fidelity, hold, root shape, replay, BE-only refusals.
. /acceptance/identity.sh
stage_1() {
    fixture_pools
    must setup sh -e -c '
        zfs create -o mountpoint=none e2ea/BE
        zfs create -o mountpoint=/ -o canmount=noauto e2ea/BE/source
        p=/mnt/zfs-e2e/fork-source-root
        mkdir -p $p
        mount -t zfs -o zfsutil e2ea/BE/source $p
        printf "fork root content" > $p/data
        umount $p
        zfs snapshot e2ea/BE/source@point
        zfs hold e2e:foreign e2ea/BE/source@point'
    observe before
    if ! step fork zboot fork e2ea/BE/source@point e2ea/BE/fork --json; then
        step diag-properties zfs get -Hp written,referenced,origin,readonly,mounted,canmount \
            e2ea/BE/source@point e2ea/BE/fork
        step diag-list zfs list -Hpr -t all e2ea/BE
        fail "fork exited $(cat "$ZT_OUT"/*-fork.rc)"
    fi
    observe after
    readat check-root e2ea/BE/fork data
    must root-placement zfs get -H -o value mountpoint e2ea/BE/fork
    operation operation e2ea
    refuse replay zboot fork e2ea/BE/source@point e2ea/BE/fork --json
    observe after-replay
    # A boot environment is one dataset with no children, and fork takes
    # nothing else: a BE with a child and a data tree are refused unchanged.
    must refusal-setup sh -e -c '
        zfs create -o mountpoint=/ -o canmount=noauto e2ea/BE/parent
        zfs create -o canmount=noauto e2ea/BE/parent/var
        zfs snapshot -r e2ea/BE/parent@point'
    observe before-refusals
    refuse fork-children zboot fork e2ea/BE/parent@point e2ea/BE/parent-fork --json
    refuse fork-data-tree zboot fork e2ea/plain@second e2ea/plain-fork --json
    observe after-refusals
}

# The clean flow above remains independent. Start a second fork on its
# persisted source and power-cut after the native clone returns, before the
# engine can verify/checkpoint/rename or publish placement.
stage_2() {
    must import zpool import -f -N -d /dev e2ea
    observe before-cut
    arm fork-clone-cut zfs '[ "$1" = clone ] && { for arg do [ "$arg" = e2ea/BE/source@point ] && exit 0; done; exit 1; }' after
    step fork-cut zboot fork e2ea/BE/source@point e2ea/BE/recovered --json
    fail 'the armed native clone was not cut'
}

stage_3() {
    must import zpool import -f -N -d /dev e2ea
    # Observe survivors BEFORE calling product recovery. A power cut may
    # leave source data only beneath the already verified inert parent.
    observe after-cut
    operation cut-operation e2ea
    cut_id=$(jq -er '.id' < "$ZT_LAST.out") || fail 'fork cut left no operation id'
    must resume zboot resume "$cut_id" --json
    observe recovered
    readat recovered-root e2ea/BE/recovered data
    operation recovered-operation e2ea
}
