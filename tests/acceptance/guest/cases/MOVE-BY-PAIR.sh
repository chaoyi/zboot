# Prove the ordinary pair verbs replace independent cross-pool move, one leaf
# at a time: a data leaf, a boot environment, and a tree (a plain container
# holding a data leaf and a BE) moved leaf by leaf. Each command exits before
# the next begins; native observations retain every intermediate state,
# including placement and trusted boot metadata.
. /acceptance/identity.sh

mp_write() { # STEP DATASET CONTENT
    must "$1" sh -e -c '
        dataset=$1 text=$2
        if [ "$(zfs get -H -o value mounted "$dataset")" = yes ]; then
            printf %s "$text" > "$(zfs get -H -o value mountpoint "$dataset")/payload"
        else
            mkdir -p /mnt/zt-move-pair-write
            mount -t zfs -o zfsutil "$dataset" /mnt/zt-move-pair-write
            trap "umount /mnt/zt-move-pair-write" EXIT
            printf %s "$text" > /mnt/zt-move-pair-write/payload
        fi
        sync' write "$2" "$3"
}

mp_be() { # LABEL BE: kernel additions, discovery companions, pool default
    must "$1-policy" zfs set "zboot:cmdline=console=ttyS0 move_pair=$1" "$2"
    # Bounded discovery-only pair: the default consumer inventories regular
    # companion paths. Actual executable handoff remains the EFI case.
    must "$1-discovery-pair" sh -e -c '
        view=/mnt/zt-move-pair-boot
        mkdir -p "$view"
        mount -t zfs -o zfsutil "$1" "$view"
        trap "umount \"$view\"" EXIT
        mkdir -p "$view/boot"
        printf %s ZFS-E2E-DISCOVERY-KERNEL > "$view/boot/vmlinuz-zt-proof"
        printf %s ZFS-E2E-DISCOVERY-INITRD > "$view/boot/initrd.img-zt-proof"' pair "$2"
    must "$1-default" zboot default "$2"
}

mp_move() { # LABEL SRC DST [be]: sync, primary, unpair --release-anchors, drop
    mp_write "$1-write" "$2" "$1"
    observe "$1-before"
    must "$1-sync" zboot sync "$2" "$3" --json
    observe "$1-synced"
    must "$1-primary" zboot primary "$3" --json
    observe "$1-promoted"
    confirmed "$1-unpair" unpair "$3" --release-anchors
    observe "$1-unpaired"
    confirmed "$1-drop" drop "$2"
    observe "$1-after"
    if [ "$(zfs get -H -o value mounted "$3")" = yes ]; then
        must "$1-read" cat "$(zfs get -H -o value mountpoint "$3")/payload"
    else
        readat "$1-read" "$3" payload ro,zfsutil
    fi
    if [ "${4-}" = be ]; then
        readat "$1-kernel" "$3" boot/vmlinuz-zt-proof ro,zfsutil
        readat "$1-initrd" "$3" boot/initrd.img-zt-proof ro,zfsutil
        # Keep each scenario independent of the next scenario's default.
        must "$1-clear-default" zpool set bootfs= e2eb
    fi
}

stage_1() {
    fixture_pools
    must data-create zfs create -o mountpoint=/mnt/zfs-e2e/move-pair-data e2ea/move-pair-data
    mp_move data e2ea/move-pair-data e2eb/move-pair-data
    must be-create zfs create -o canmount=noauto -o mountpoint=/ e2ea/move-pair-be
    mp_be be e2ea/move-pair-be
    mp_move be e2ea/move-pair-be e2eb/move-pair-be be
    # A tree is plain structure made once on each side; its leaves move one
    # by one, and the emptied source container goes last.
    must tree-create sh -e -c '
        zfs create -o canmount=off -o mountpoint=/mnt/zfs-e2e/move-pair-tree e2ea/move-pair-tree
        zfs create e2ea/move-pair-tree/data
        zfs create -o canmount=noauto -o mountpoint=/ e2ea/move-pair-tree/be
        zfs create -o canmount=off -o mountpoint=/mnt/zfs-e2e/move-pair-tree e2eb/move-pair-tree'
    mp_be tree-be e2ea/move-pair-tree/be
    mp_move tree-data e2ea/move-pair-tree/data e2eb/move-pair-tree/data
    mp_move tree-be e2ea/move-pair-tree/be e2eb/move-pair-tree/be be
    confirmed tree-container-drop drop e2ea/move-pair-tree
    observe tree-after
}
