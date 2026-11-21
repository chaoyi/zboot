# shellcheck disable=SC2016 # sh -c bodies expand arguments in the invoked shell.
# STOCK-SYNC-NATIVE: zboot's pairs on Debian's own OpenZFS, end to end. Two
# pools; every receive is the host's stock `zfs receive`. Copied properties
# land as local values on the copy, pruning on the working copy reaches the
# copy only through a reviewed sync, a renamed snapshot is matched by GUID,
# the sync back into an installer-made encrypted leaf is proved before data,
# a fenced zvol copy has no device, and an interrupted sync is abandoned.
. /acceptance/lifecycle.sh
. /acceptance/identity.sh
W=e2ea/stock C=e2eb/stock
VAULT=e2ea/vault LEAF=e2ea/vault/home COPY=e2eb/home
VOL=e2ea/stockvol VCOPY=e2eb/stockvol
CFG=/run/zfs-e2e-zsnap.toml

# zvols NAME: "DEVICE DATASET" for every zvol block device the kernel made.
zvols() {
    must "$1" sh -c 'sleep 2; mdev -s
        for b in /sys/block/zd*; do
            [ -e "$b" ] || continue
            d=/dev/${b##*/}
            printf "%s %s\n" "$d" "$(/usr/lib/udev/zvol_id "$d" 2> /dev/null || echo "?")"
        done'
}

# write NAME DATASET FILE CONTENT: mount DATASET (canmount=noauto), write, unmount.
write() {
    must "$1" sh -e -c 'zfs mount "$1"
        printf %s "$3" > "$(zfs get -H -o value mountpoint "$1")/$2"
        sync; zfs unmount "$1"' write "$2" "$3" "$4"
}

stage_1() {
    fixture_pools
    printf "[policy.e2e]\nfrequency='1h'\nkeep={last=1}\n" > $CFG

    # 1. A leaf, a stock property-free copy of it, then `pair`.
    must create-working zfs create -o mountpoint=/mnt/zfs-e2e/stock $W
    put initial /mnt/zfs-e2e/stock/initial initial
    must snapshot-base zfs snapshot $W@base
    must seed sh -e -c 'zfs send "$1@base" | zfs receive -u "$2"' seed $W $C
    must pair zboot pair $W $C --json
    must assign zsnap assign $W e2e --config $CFG
    must zsnap-snap zsnap snap $W

    # 2. Copied properties: a write-time key, a user property and a space
    # limit set on the working copy reach the copy as local values.
    must working-properties zfs set copies=2 e2e:stock=working refquota=256M $W
    must blob sh -e -c 'dd if=/dev/urandom of=/mnt/zfs-e2e/stock/blob bs=1M count=8 2> /dev/null; sync'
    observe properties-before
    must properties-sync zboot sync $W --json
    observe properties-after
    must copy-space zfs get -H -p -o property,value referenced,logicalreferenced $C

    # 3. Pruning: refused on the fenced copy, whose copied policy is dormant;
    # done on the working copy; the copy keeps the snapshot until a reviewed sync.
    refuse prune-copy zsnap prune $C --last 0 --yes --config $CFG
    must dormant zsnap run --dry-run --config $CFG
    must prune-working zsnap prune $W --last 0 --yes --config $CFG
    observe pruned
    must pending-preview zboot sync $W --dry-run --json
    must unattended zboot sync $W --json
    observe unattended
    must review-preview zboot sync $W --dry-run --json
    review=$(json .token) || fail 'the sync preview carries no token'
    must reviewed zboot sync $W --confirm "$review" --json
    observe reviewed

    # 4. A common snapshot renamed on the working copy is renamed on the copy
    # by GUID before the stream.
    must rename-working zfs rename $W@base $W@base-renamed
    must renamed zboot sync $W --json
    observe renamed

    # 5. An interrupted sync, abandoned: the copy keeps what it received,
    # stays fenced, and the next sync continues from it.
    put interrupted-data /mnt/zfs-e2e/stock/interrupted interrupted
    arm interrupted-receive zfs '[ "$1" = receive ] && { for arg do [ "$arg" = e2eb/stock ] && exit 0; done; exit 1; }' error-after
    step interrupted zboot sync $W --json
    observe interrupted
    operation interrupted-record e2ea
    interrupted_id=$(jq -er '.id' < "$ZT_LAST.out") || fail 'the interrupted sync left no operation record'
    must abandon-preview zboot abandon "$interrupted_id" --dry-run --json
    abandon_token=$(json .token) || fail 'the abandon preview carries no token'
    must abandon zboot abandon "$interrupted_id" --confirm "$abandon_token" --json
    observe abandoned
    operation abandoned-record e2ea
    must continued zboot sync $W --json
    observe continued

    # 6. An encrypted leaf made by `zfs create` under a passphrase container:
    # bootstrap a copy, make the copy the working copy, sync back into the
    # original leaf (equal wrapping, proved), then change the copy's key and
    # see the next sync back refused before any data.
    must passphrase sh -e -c 'printf %s correct-horse-e2e > /run/stock-pass
        printf %s another-horse-e2e > /run/stock-pass2'
    must create-vault zfs create -o canmount=off -o mountpoint=none -o encryption=aes-256-gcm \
        -o keyformat=passphrase -o keylocation=file:///run/stock-pass $VAULT
    must create-home zfs create -o canmount=noauto -o mountpoint=/mnt/zfs-e2e/home \
        -o compression=zstd -o e2e:installer=kept $LEAF
    write home-data $LEAF data original
    must bootstrap zboot sync $LEAF $COPY --json
    observe bootstrapped
    must wrapping zfs get -H -p -o name,property,value,source keyformat,pbkdf2salt,pbkdf2iters,keylocation \
        $VAULT $COPY
    must primary zboot primary $COPY --json
    observe switched
    must load-copy zfs load-key $COPY
    write copy-data $COPY data back
    must back zboot sync $COPY --json
    observe back
    must change-key zfs change-key -o keyformat=passphrase -o keylocation=file:///run/stock-pass2 $COPY
    write changed-data $COPY data changed
    observe changed-before
    step changed zboot sync $COPY --json
    observe changed-after
    # Refused at admission: nothing was recorded, so nothing needs abandoning.
    operation changed-record e2eb
    # The original leaf still opens with its container's key and holds the
    # data of the sync back.
    must reload-vault sh -e -c 'zfs unload-key "$1"; zfs load-key "$1"' reload $VAULT
    must home-keystatus zfs get -H -o value encryptionroot,keystatus $LEAF
    readat home-read $LEAF data ro,zfsutil

    # 7. A zvol pair: the fenced copy has no device, also across an import.
    must create-volume zfs create -V 16M -o volmode=dev $VOL
    must volume-sync zboot sync $VOL $VCOPY --json
    observe volume-paired
    zvols volume-devices
    must export-copy-pool zpool export e2eb
    must import-copy-pool zpool import -N -o cachefile=none -d /dev e2eb
    zvols volume-devices-imported
    observe final
}
