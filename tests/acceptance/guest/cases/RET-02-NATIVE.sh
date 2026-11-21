# RET-02: conventional zsnap capture, policy assignment, scheduled runs and
# retention protections (holds, deferred destroy, foreign names, pending
# operation, readonly scope, name collisions), all judged by native snapshot maps.
. /acceptance/identity.sh
CFG=/run/zfs-e2e-zsnap.toml
stage_1() {
    fixture_pools
    must clock sh -e -c 'busybox date -u -s "2030-01-15 12:00:00" > /dev/null; busybox date -u +%Y-%m-%dT%H:%M:%SZ'
    must ret-create sh -e -c 'mkdir -p /mnt/zfs-e2e
        zfs create -o mountpoint=/mnt/zfs-e2e/ret e2ea/ret
        zfs create e2ea/ret/child
        zfs create -o mountpoint=none e2ea/ret/disabled'
    must snap zsnap snap e2ea/ret
    snapmap map-first e2ea/ret
    printf "[policy.e2e]\nfrequency='1s'\nkeep={last=2}\n" > $CFG
    must config cat $CFG
    must assign zsnap assign e2ea/ret e2e --config $CFG
    must inherited zfs get -H -o value,source zsnap:policy e2ea/ret/child
    must assign-child-none zsnap assign e2ea/ret/child none --config $CFG
    must unassign-child zsnap unassign e2ea/ret/child
    must revealed zfs get -H -o value,source zsnap:policy e2ea/ret/child
    must assign-disabled zsnap assign e2ea/ret/disabled none --config $CFG
    must status zsnap status e2ea/ret --config $CFG
    # Sync so the change is in written@ (zsnap's documented changed-head
    # heuristic counts only synced bytes).
    must change sh -e -c 'printf "new data for scheduled capture" > /mnt/zfs-e2e/ret/change
        zpool sync e2ea; busybox date -u -s "2030-01-15 13:00:00" > /dev/null'
    snapmap map-before-run e2ea
    must run zsnap run --config $CFG
    snapmap map-after-run e2ea
    must run-again zsnap run --config $CFG
    snapmap map-after-run-again e2ea
    must historical sh -e -c '
        for s in zsnap_2020-01-01-000000 zsnap_2020-01-02-000000 zsnap_2020-01-03-000000 \
            zsnap_2020-01-04-000000 manual-foreign; do zfs snapshot e2ea/ret@$s; done
        zfs snapshot e2ea/ret/child@zsnap_2020-01-01-000000'
    must hold zfs hold foreign-retention-reader e2ea/ret@zsnap_2020-01-01-000000 e2ea/ret@zsnap_2020-01-02-000000
    must defer zfs destroy -d e2ea/ret@zsnap_2020-01-02-000000
    snapmap map-child-before e2ea/ret/child
    step prune zsnap prune e2ea/ret --last 1 --yes --config $CFG
    snapmap map-pruned e2ea/ret
    snapmap map-child-after e2ea/ret/child
    must inventory zboot status e2ea/ e2eb/ --json --snapshots
    observe protected
    must pending zfs set zboot:pending=unknown-e2e-operation e2ea/ret
    refuse prune-pending zsnap prune e2ea/ret --last 0 --yes --config $CFG
    snapmap map-after-pending e2ea/ret
    must readonly sh -e -c 'zfs inherit zboot:pending e2ea/ret; zfs set readonly=on e2ea/ret'
    refuse prune-readonly zsnap prune e2ea/ret --last 0 --yes --config $CFG
    snapmap map-after-readonly e2ea/ret
    must readwrite zfs set readonly=off e2ea/ret
    must collision-fixture sh -e -c 'zfs create -o mountpoint=none e2ea/collision
        i=0; while [ $i -lt 24 ]; do
            zfs snapshot e2ea/collision@zsnap_2030-01-15-1200$(printf %02d $i); i=$((i + 1))
        done'
    snapmap map-collision-before e2ea/collision
    must clock-reset busybox date -u -s "2030-01-15 12:00:00"
    refuse collision zsnap snap e2ea/collision
    snapmap map-collision-after e2ea/collision
    must unassign zsnap unassign e2ea/ret
    must final-policy zfs get -H -o value zsnap:policy e2ea/ret/child
}
