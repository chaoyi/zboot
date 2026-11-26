# zboot pair refuses a same-GUID receiver with a different IV set, and a
# receiver whose head was written after the common snapshot; neither refusal
# changes native state.
. /acceptance/lifecycle.sh

stage_1() {
    fixture_pools
    must iv-create zfs create -o mountpoint=none -o encryption=aes-256-gcm -o keyformat=raw \
        -o keylocation=file:///run/zfs-e2e-key e2eb/ivsource
    must iv-snapshot zfs snapshot e2eb/ivsource@point
    # Negative fixture: a logical (re-encrypting) copy keeps the snapshot GUID
    # but gets a new IV set.
    must iv-reencrypt sh -e -c '
        { zfs send e2eb/ivsource@point; echo $? > /run/lc-send.rc; } |
            zfs receive -u -o encryption=aes-256-gcm -o keyformat=raw \
                -o keylocation=file:///run/zfs-e2e-key -o mountpoint=none e2ea/ivreceiver
        [ "$(cat /run/lc-send.rc)" = 0 ]'
    must iv-sets zfs get -Hp -o name,property,value guid,ivsetguid e2eb/ivsource@point e2ea/ivreceiver@point
    observe iv-before
    refuse iv-pair zboot pair e2eb/ivsource e2ea/ivreceiver
    observe iv-after

    must dirty-create zfs create -o mountpoint=/mnt/zfs-e2e/dirty-source e2eb/dirtysource
    put dirty-write-source /mnt/zfs-e2e/dirty-source/file 'original content'
    must dirty-snapshot zfs snapshot e2eb/dirtysource@point
    replicate dirty-seed e2eb/dirtysource@point e2ea/dirtyreceiver -o readonly=on
    must dirty-open zfs set readonly=off mountpoint=/mnt/zfs-e2e/dirty-receiver e2ea/dirtyreceiver
    must dirty-mount zfs mount -a
    put dirty-write-receiver /mnt/zfs-e2e/dirty-receiver/file 'receiver changed content'
    must dirty-sync zpool sync e2ea
    must dirty-written zfs get -Hp -o value written@point e2ea/dirtyreceiver
    observe dirty-before
    refuse dirty-pair zboot pair e2eb/dirtysource e2ea/dirtyreceiver
    observe dirty-after
    must dirty-read cat /mnt/zfs-e2e/dirty-receiver/file
}
