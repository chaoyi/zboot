# RAM-BOOT: the local pool its first RAM boot imports. The installed root is
# never booted; the host uploads the same root tar to the network-booted UKI.
. /acceptance/share.sh

stage_1() {
    fixtures_mount
    must setup-factory-sha256 sha256sum /fixtures/e2e-factory.tar.zst
    a=$(disk A)
    must deploy-preview zboot deploy "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi \
        --tar /fixtures/e2e-factory.tar.zst --pool e2ea --be proof --esp 512M --hostid 0174627a --dry-run --json
    token=$(json .token) || fail 'deploy preview has no token'
    must deploy zboot deploy "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi \
        --tar /fixtures/e2e-factory.tar.zst --pool e2ea --be proof --esp 512M --hostid 0174627a --confirm "$token" --json
    must import-a zpool import -N -o readonly=on -o cachefile=none -d /dev e2ea
    must pool-guid zpool get -H -o value guid e2ea
    observe setup
    must export-a zpool export e2ea
}
