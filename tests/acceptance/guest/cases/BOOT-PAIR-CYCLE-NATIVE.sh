# A paired boot environment (one dataset, no children) through bootstrap
# sync, incremental sync and two primary switches: identities, fences,
# receiver-local policy, copied properties, pair records and payload bytes at
# every state; both pools export cleanly at the end.
# A shared dataset synced alongside gets a secondary that stays unmounted
# across the reboot into stage 2.
. /acceptance/lifecycle.sh
A=e2ea/cycle B=e2eb/cycle
SA=e2ea/shared SB=e2eb/shared SHARED=/mnt/zfs-e2e/shared

payload_rw() {  # payload_rw NAME BE VALUE write|read: zfsutil-mount BE and write or read
    dir=/mnt/zfs-e2e/be-cycle
    must "$1-mkdir" mkdir -p $dir
    if [ "$4" = write ]; then
        must "$1-mount" mount -t zfs -o zfsutil $2 $dir
        put "$1-write" $dir/payload "$3"
        if [ "$1" = initial-a ]; then
            # Named discovery-only companions, not executable kernels.
            # The EFI case owns actual handoff proof.
            must "$1-boot-directory" mkdir -p "$dir/boot"
            put "$1-kernel" "$dir/boot/vmlinuz-zt-proof" ZFS-E2E-DISCOVERY-KERNEL
            put "$1-initrd" "$dir/boot/initrd.img-zt-proof" ZFS-E2E-DISCOVERY-INITRD
        fi
    else
        must "$1-mount" mount -t zfs -o zfsutil,ro $2 $dir
        must "$1-read" cat $dir/payload
        must "$1-kernel" cat "$dir/boot/vmlinuz-zt-proof"
        must "$1-initrd" cat "$dir/boot/initrd.img-zt-proof"
    fi
    must "$1-umount" umount $dir
}

state() {  # state NAME: native evidence of both copies
    observe "$1"
    must "$1-props" zfs get -H -p -o name,property,value,source \
        mountpoint,canmount,readonly,zboot:cmdline,zboot:placement,zboot:pair,e2e:cycle $A $B
}

stage_1() {
    fixture_pools
    must create-root zfs create -o canmount=noauto -o readonly=off -o mountpoint=/ $A
    must be-policy zfs set zboot:cmdline=console=ttyS0 e2e:cycle=one $A
    observe original
    payload_rw initial-a $A initial write
    must bootstrap zboot sync $A $B --json
    state bootstrap
    payload_rw initial-b $B initial read
    # Receiver-local policy deliberately differs from the source and must
    # survive the incremental receive and both primary switches. A copied
    # user property changed on the source reaches the copy.
    must b-cmdline zfs set zboot:cmdline=console=ttyS1 $B
    must a-property zfs set e2e:cycle=two $A
    payload_rw incremental-a $A incremental write
    must incremental zboot sync $A $B --json
    state incremental
    payload_rw incremental-b $B incremental read
    must primary-b zboot primary $B --json
    state primary-b
    payload_rw caught-up-b $B incremental read
    payload_rw reverse-b $B reverse write
    must primary-a zboot primary $A --json
    state primary-a
    payload_rw reverse-read-a $A reverse read
    payload_rw reverse-read-b $B reverse read
    # A shared dataset mounts at boot (canmount=on); its secondary must not.
    must create-shared zfs create -o mountpoint=$SHARED $SA
    put shared-write $SHARED/payload shared
    must shared-sync zboot sync $SA $SB --json
    must shared-props zfs get -H -p -o name,property,value,source canmount,readonly,mountpoint,mounted $SA $SB
    must export-e2eb zpool export e2eb
    must export-e2ea zpool export e2ea
    must pools zpool list -H -o name
}

# The reboot: a stock host imports its pools and runs `zfs mount -a`.
stage_2() {
    must import-e2ea zpool import -N -o cachefile=none -d /dev e2ea
    must import-e2eb zpool import -N -o cachefile=none -d /dev e2eb
    must mount-all zfs mount -a
    observe rebooted
    must rebooted-read cat $SHARED/payload
    must export-e2eb zpool export e2eb
    must export-e2ea zpool export e2ea
}
