# INCREMENTAL-IDENTITY: per-dataset raw streams without properties, as zboot
# sends them, into a locked read-only receiver. The incremental keeps each
# dataset's identity, its local placement (the stream carries no properties,
# so nothing is excluded), snapshot and IV-set identities, and content. The
# child's copy is its own encryption root and loads its key separately.
. /acceptance/identity.sh
POINTS='secret initial middle next'
stage_1() {
    fixture_pools
    must source-setup sh -e -c 'mkdir -p /mnt/zfs-e2e
        zfs set mountpoint=/mnt/zfs-e2e/source e2e:placement=source-initial e2eb/encrypted
        zfs set mountpoint=/mnt/zfs-e2e/source/child e2e:placement=source-initial e2eb/encrypted/child
        zfs mount -a
        printf "root-initial\n" > /mnt/zfs-e2e/source/base.txt
        printf "child-initial\n" > /mnt/zfs-e2e/source/child/base.txt
        zfs snapshot -r e2eb/encrypted@initial'
    for ds in "" /child; do
        rawpipe "replicate${ds#/}" "-w e2eb/encrypted$ds@secret" "-u -o readonly=on e2ea/incremental$ds"
        rawpipe "replicate${ds#/}-initial" "-w -I @secret e2eb/encrypted$ds@initial" "-u e2ea/incremental$ds"
    done
    must receiver-placement sh -e -c '
        zfs set readonly=on mountpoint=/mnt/zfs-e2e/receiver e2e:placement=receiver-root e2ea/incremental
        zfs set readonly=on mountpoint=/mnt/zfs-e2e/receiver/child e2e:placement=receiver-child \
            e2ea/incremental/child'
    must inventory-before zboot status e2ea/ e2eb/ --json --snapshots
    must placement-before zfs get -H -p -o name,property,value,source readonly,mountpoint,e2e:placement \
        e2ea/incremental e2ea/incremental/child
    observe before
    must source-next sh -e -c 'S=/mnt/zfs-e2e/source
        printf "root-middle\n" > $S/base.txt; printf "child-middle\n" > $S/child/base.txt
        zfs snapshot -r e2eb/encrypted@middle
        printf "root-next\n" > $S/base.txt; printf "child-next\n" > $S/child/base.txt
        printf "new child data\n" > $S/child/new.txt
        zfs set e2e:placement=source-next e2eb/encrypted e2eb/encrypted/child
        zfs snapshot -r e2eb/encrypted@next'
    for ds in "" /child; do
        rawpipe "incremental${ds#/}" "-w -I @initial e2eb/encrypted$ds@next" "-u e2ea/incremental$ds"
    done
    must inventory-after zboot status e2ea/ e2eb/ --json --snapshots
    must placement-after zfs get -H -p -o name,property,value,source readonly,mountpoint,e2e:placement \
        e2ea/incremental e2ea/incremental/child
    observe after
    set --
    for p in $POINTS; do
        set -- "$@" e2eb/encrypted@$p e2ea/incremental@$p e2eb/encrypted/child@$p e2ea/incremental/child@$p
    done
    must ivsets zfs get -H -p -o name,value ivsetguid "$@"
    must sync zpool sync e2ea
    must written zfs get -H -p -o name,value written@next e2ea/incremental e2ea/incremental/child
    must load-key zfs load-key -L file:///run/zfs-e2e-key e2ea/incremental
    must load-key-child zfs load-key -L file:///run/zfs-e2e-key e2ea/incremental/child
    must mount-root zfs mount -o ro e2ea/incremental
    must mount-child zfs mount -o ro e2ea/incremental/child
    must head-root cat /mnt/zfs-e2e/receiver/base.txt
    must head-child cat /mnt/zfs-e2e/receiver/child/base.txt
    for p in initial middle next; do
        readat check-root-$p e2ea/incremental@$p base.txt
        readat check-child-$p e2ea/incremental/child@$p base.txt
    done
    must new-child cat /mnt/zfs-e2e/receiver/child/new.txt
}
