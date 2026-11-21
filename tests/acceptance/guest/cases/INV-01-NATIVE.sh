# INV-01: recursive native inventory, lossless identities, encrypted
# observations and rename stability, against independent native reads.
# inventory_part: shared with CAPTURE-READER-NATIVE, which runs it first.
inventory_part() {
    must inventory-before zboot status e2ea/ e2eb/ --json --snapshots
    must guid-e2ea zpool get -H -p -o value guid e2ea
    must guid-e2eb zpool get -H -p -o value guid e2eb
    must guid-plain zfs get -H -p -o value guid e2ea/plain
    must guid-plain-first zfs get -H -p -o value guid e2ea/plain@first
    observe before
    must rename zfs rename e2ea/plain e2ea/renamed
    must inventory-after zboot status e2ea/ e2eb/ --json --snapshots
    must status zboot status e2ea/ e2eb/ --snapshots --json
    observe after
}
stage_1() {
    fixture_pools
    inventory_part
}
