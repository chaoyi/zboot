# deploy into: add a BE while every pool default remains fixed, then cut a second addition
# after its real @factory snapshot. Boot 2 inspects and explicitly Drops that
# fenced name before a fresh retry. Boot 3 starts D's own ESP and the new BE.
. /acceptance/share.sh
. /acceptance/deploy_boot.sh
POOL=e2ed BE=e2ed/ROOT/new HALF=e2ed/ROOT/interrupted
TAR=/fixtures/e2e-factory.tar.zst OVERLAY=/run/deploy-into-overlay

into() { name=$1 be=$2; shift 2; step "$name" zboot deploy into "$POOL" --tar "$TAR" --overlay "$OVERLAY" --be "$be" --hostname into-proof --json "$@"; }

stage_1() {
    fixture_hostid
    fixture_pools
    fixtures_mount
    d=$(disk D)
    must old-preview zboot deploy "$d" --pool "$POOL" --be old --tar "$TAR" \
        --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi --esp 512M --dry-run --json
    token=$(json .token) || fail 'initial deploy has no token'
    must old-apply zboot deploy "$d" --pool "$POOL" --be old --tar "$TAR" \
        --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi --esp 512M --confirm "$token" --json
    must import-d zpool import -N -d /dev "$POOL"
    must defaults-before zpool get -H -o name,value bootfs
    must disk-before sfdisk --json "$d"
    deploy_boot_overlay "$OVERLAY" "$BE"
    into preview new --dry-run || fail 'deploy into preview failed'
    into preview-again new --dry-run || fail 'repeated deploy into preview failed'
    into apply new || fail 'deploy into apply failed'
    must defaults-after zpool get -H -o name,value bootfs
    must disk-after sfdisk --json "$d"
    must successful-native zfs get -H -p -o name,property,value,source canmount,mountpoint,readonly,zboot:pending "$BE"
    must successful-snapshots zfs list -H -p -t snapshot -o name,guid -r "$BE"
    observe successful
    # Existing name refusal precedes effects and leaves the native identity.
    into existing new --dry-run
    arm INTO-FACTORY zfs '[ "$1" = snapshot ] && [ "$2" = e2ed/ROOT/interrupted@factory ]' after
    into interrupted interrupted || fail 'expected actual snapshot power cut'
    fail 'native cut did not fire'
}

stage_2() {
    fixture_hostid
    fixtures_mount
    must import-a zpool import -N -o readonly=on -d /dev e2ea
    must import-b zpool import -N -o readonly=on -d /dev e2eb
    must import-d zpool import -N -d /dev "$POOL"
    must interrupted-native zfs get -H -p -o name,property,value,source canmount,mountpoint,readonly,zboot:pending "$HALF"
    must interrupted-snapshots zfs list -H -p -t snapshot -o name,guid -r "$HALF"
    must interrupted-status zboot status --all --json
    deploy_boot_overlay "$OVERLAY" "$BE"
    into interrupted-refused interrupted --dry-run
    must drop-preview zboot drop "$HALF" --dry-run --json
    token=$(json .token) || fail 'explicit Drop preview has no token'
    must drop-apply zboot drop "$HALF" --confirm "$token" --json
    step absent zfs list -H "$HALF"
    into retry interrupted || fail 'fresh into retry failed'
    must defaults-final zpool get -H -o name,value bootfs
    must final-native zfs get -H -p -o name,property,value,source canmount,mountpoint,readonly,zboot:pending "$BE" "$HALF"
    must final-snapshots zfs list -H -p -t snapshot -o name,guid -r "$POOL/ROOT"
    observe final
    must export-d zpool export "$POOL"
    must export-a zpool export e2ea
    must export-b zpool export e2eb
}
