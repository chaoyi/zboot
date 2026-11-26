# RAW-HEAD: per-dataset raw streams without properties, as zboot sends them:
# a locked raw receiver keeps snapshot and IV-set identities and writes
# nothing, and the child's copy is its own encryption root; zvol written
# accounting from native reads.
. /acceptance/identity.sh
stage_1() {
    fixture_pools
    rawpipe replicate "-w e2eb/encrypted@secret" "-u -o readonly=on e2ea/raw"
    rawpipe replicate-child "-w e2eb/encrypted/child@secret" "-u -o readonly=on e2ea/raw/child"
    must inventory zboot status e2ea/ e2eb/ --json --snapshots
    observe raw
    must ivsets zfs get -H -p -o name,value ivsetguid e2eb/encrypted@secret e2ea/raw@secret \
        e2eb/encrypted/child@secret e2ea/raw/child@secret
    must seal sh -e -c 'zfs set readonly=on e2ea/raw; zfs set readonly=on e2ea/raw/child; zpool sync e2ea'
    must written-raw zfs get -H -p -o name,value written@secret e2ea/raw e2ea/raw/child
    must zvol sh -e -c 'zfs create -s -V 16M -o volblocksize=4096 -o volmode=dev e2ea/volume; mdev -s'
    # The zvol node whose zvol_id names e2ea/volume (bounded wait; all matches).
    must zvol-device sh -c 'i=0; while [ $i -lt 20 ]; do
            for b in /sys/class/block/zd*; do
                d=/dev/${b##*/}
                [ -b "$d" ] && [ "$(/usr/lib/udev/zvol_id "$d" 2> /dev/null)" = e2ea/volume ] && echo "$d"
            done > /run/zt-zvol; [ -s /run/zt-zvol ] && cat /run/zt-zvol && exit 0
            sleep 1; mdev -s; i=$((i + 1))
        done; exit 1'
    dev=$(cat "$ZT_LAST.out")
    must zvol-base sh -e -c 'dd if=/dev/urandom of="$1" bs=4096 count=1 conv=notrunc 2> /dev/null
        zpool sync e2ea; zfs snapshot e2ea/volume@base' w "$dev"
    must zvol-fresh zfs get -H -p -o value written@base e2ea/volume
    must zvol-write sh -e -c 'dd if=/dev/urandom of="$1" bs=4096 count=1 seek=1 conv=notrunc 2> /dev/null
        zfs set readonly=on e2ea/volume; zpool sync e2ea' w "$dev"
    must zvol-written zfs get -H -p -o value written@base e2ea/volume
    observe after
}
