# Framework self-test: a product command, a native observation, a cut and a
# restart on the retained disks.
stage_1() {
    fixture_pools
    must status zboot status --json
    arm snapshot-cut zfs '[ "$1" = snapshot ]'
    step snapshot zboot snapshot e2ea/@s1 --json
    fail 'the armed snapshot call was not cut'
}
stage_2() {
    must import zpool import -f -N e2ea
    observe after-cut
    must snapshot zboot snapshot e2ea/@s2 --json
    observe after
}
