# Confirmed tree loss (rollback, drop): refusals for a foreign hold on a newer
# snapshot and on a secondary; a rollback preview survives a power cut and
# its token applies after the reboot exactly once; snapshot and tree drops
# confirm by the reviewed token; the boot default is refused.
. /acceptance/lifecycle.sh
ROOT=e2ea/loss P=/mnt/zfs-e2e/loss

contents() {  # contents LABEL: write LABEL:{,/child} to the head
    put "write-$1-root" $P/data "$1:"
    put "write-$1-child" $P/child/data "$1:/child"
}

reads() {  # reads NAME: cat the head content
    must "$1-root" cat $P/data
    must "$1-child" cat $P/child/data
}

# On failure of a confirmed loss verb, keep native diagnostics, then stop.
diagnose() {
    observe "$1-failed"
    step "$1-failed-written" zfs get -Hp written,written@base,referenced,readonly,mounted,canmount,origin \
        $ROOT $ROOT/child $ROOT@base $ROOT/child@base
    fail "$1 exited $(cat "$ZT_LAST.rc")"
}

stage_1() {
    fixture_pools
    must create-root zfs create -o mountpoint=$P $ROOT
    must create-child zfs create $ROOT/child
    contents base
    must snapshot-base zfs snapshot -r $ROOT@base
    contents later
    must snapshot-later zfs snapshot -r $ROOT@later
    contents unsnapshotted
    observe original
    must foreign-hold zfs hold e2e:foreign $ROOT@later
    observe held-before
    refuse held-rollback zboot rollback $ROOT@base --dry-run --json
    observe held-after
    reads held-content
    must foreign-release zfs release e2e:foreign $ROOT@later

    must peer-source zfs create -o mountpoint=none e2eb/loss-pair
    must peer-snapshot zfs snapshot e2eb/loss-pair@base
    replicate peer-seed e2eb/loss-pair@base e2ea/loss-peer -o readonly=on
    must peer-pair zboot pair e2eb/loss-pair e2ea/loss-peer --json
    observe peer-before
    refuse peer-rollback zboot rollback e2ea/loss-peer@base --dry-run --json
    refuse peer-drop zboot drop e2ea/loss-peer --dry-run --json
    observe peer-after

    observe prepared
    must preview zboot rollback $ROOT@base --dry-run --json
    # The token crosses the power cut on the out share, as an operator's note would.
    json .token > "$ZT_OUT/rollback.token" || fail 'rollback preview carries no token'
    step unattended zboot rollback $ROOT@base --json
    observe previewed
    reads previewed-content
    must boot-id cat /proc/sys/kernel/random/boot_id
    # Power cut after the preview and its unconfirmed run, before any
    # confirmed effect; no export, no shutdown.
    sync
    zt_emit CUT after-preview
    exec sleep 2147483647
}

stage_2() {
    read -r token < /out/1/rollback.token || fail 'no token from boot 1'
    must boot-id cat /proc/sys/kernel/random/boot_id
    must import-e2ea zpool import -N -f -d /dev e2ea
    must import-e2eb zpool import -N -f -d /dev e2eb
    must mount-root zfs mount $ROOT
    must mount-child zfs mount $ROOT/child
    observe restored
    reads restored-content
    refuse wrong-token zboot rollback $ROOT@base --confirm wrong-native-loss-token --json
    observe wrong-after
    # A hold on the boundary itself is kept: rollback destroys only newer
    # snapshots, so the plan and its token are unchanged.
    must retained-hold zfs hold e2e:retained $ROOT@base
    step rollback zboot rollback $ROOT@base --confirm "$token" --json || diagnose rollback
    observe rolled
    reads rolled-content
    refuse replay zboot rollback $ROOT@base --confirm "$token" --json
    observe replayed
    refuse held-drop zboot drop $ROOT --dry-run --json
    observe held-drop-after
    must retained-release zfs release e2e:retained $ROOT@base
    observe kept
    must snapshot-extra zfs snapshot -r $ROOT@extra
    consent snapshots drop $ROOT@extra $ROOT/child@extra
    observe snapshots-dropped
    must bootfs zpool set bootfs=$ROOT e2ea
    observe default-before
    refuse default-drop zboot drop $ROOT --dry-run --json
    observe default-after
    must alternate zfs create -o mountpoint=/ -o canmount=noauto e2ea/loss-alternate
    must bootfs-alternate zpool set bootfs=e2ea/loss-alternate e2ea
    consent tree drop $ROOT
    observe dropped
    refuse drop-again zboot drop $ROOT --dry-run --json
    observe drop-again-after
}
