# shellcheck disable=SC2016 # sh -c bodies expand arguments in the invoked shell.
# Native probe for the stock pipeline (docs/DESIGN.md, "Stock receive
# properties"). Debian's own OpenZFS only: no product command and
# no earlier receiver runs. Every pool is on the VM's disposable disks.
SR_STAGE=e2ea/zboot-receive-probe

sr_props() {  # NAME DATASET: every property with value, source and received value.
    must "$1" zfs get -H -p -o property,value,source,received all "$2"
}

sr_minors() {  # NAME: count of zvol block devices the kernel created.
    must "$1" sh -c 'sleep 2; ls /sys/block | grep -c "^zd" || true'
}

stage_1() {
    fixture_pools
    # A fenced staging container, as zboot creates one.
    must container zfs create -o encryption=off -o canmount=off -o mountpoint=none \
        -o readonly=on -o volmode=none "$SR_STAGE"

    # P1: the first sync back into an installer-made dataset, without
    # properties in the stream, keeps every local value.
    must inst-setup sh -e -c '
        zfs create -o mountpoint=/mnt/sr-inst -o canmount=noauto -o compression=zstd \
            -o zfs-e2e:note=keep e2ea/inst
        zfs mount e2ea/inst
        echo one > /mnt/sr-inst/file
        zfs unmount e2ea/inst
        zfs snapshot e2ea/inst@one
        zfs send e2ea/inst@one | zfs receive -u -o canmount=noauto e2eb/inst
        zfs set -u mountpoint=/mnt/sr-copy e2eb/inst
        zfs mount e2eb/inst
        echo two > /mnt/sr-copy/file
        zfs unmount e2eb/inst
        zfs snapshot e2eb/inst@two
        zfs set readonly=on e2ea/inst'
    sr_props inst-before e2ea/inst
    must inst-back sh -e -c 'zfs send -I @one e2eb/inst@two | zfs receive -u e2ea/inst'
    sr_props inst-after e2ea/inst
    must inst-data sh -e -c '
        zfs mount e2ea/inst
        cat /mnt/sr-inst/file
        zfs unmount e2ea/inst'
    # Control: the same sync back with a property-carrying stream.
    must ctl-setup sh -e -c '
        zfs create -o mountpoint=none -o compression=zstd -o zfs-e2e:note=keep e2ea/ctl
        zfs snapshot e2ea/ctl@one
        zfs send e2ea/ctl@one | zfs receive -u e2eb/ctl
        zfs set compression=lz4 e2eb/ctl
        zfs snapshot e2eb/ctl@two
        zfs set readonly=on e2ea/ctl'
    sr_props ctl-before e2ea/ctl
    step ctl-back sh -e -c 'zfs send -p -I @one e2eb/ctl@two | zfs receive -u e2ea/ctl'
    sr_props ctl-after e2ea/ctl

    # P2: a new dataset in the container inherits its fences, takes `-o`
    # values as local ones before data, and gets no received values.
    must new-src sh -e -c '
        zfs create -o mountpoint=/mnt/sr-src e2ea/src
        dd if=/dev/urandom of=/mnt/sr-src/blob bs=1M count=8 2>/dev/null
        zfs snapshot e2ea/src@a
        zfs set zfs-e2e:snap=1 e2ea/src@a'
    must new-one sh -e -c 'zfs send e2ea/src@a |
        zfs receive -u -o canmount=noauto -o copies=1 e2ea/zboot-receive-probe/one'
    must new-two sh -e -c 'zfs send e2ea/src@a |
        zfs receive -u -o canmount=noauto -o copies=2 e2ea/zboot-receive-probe/two'
    must new-three sh -e -c 'zfs send e2ea/src@a | zfs receive -u e2ea/zboot-receive-probe/three'
    sr_props new-one-props "$SR_STAGE/one"
    sr_props new-two-props "$SR_STAGE/two"
    sr_props new-three-props "$SR_STAGE/three"
    must new-space zfs get -H -p -o name,value referenced "$SR_STAGE/one" "$SR_STAGE/two"
    must new-snapprop zfs get -H -o value zfs-e2e:snap "$SR_STAGE/one@a"

    # P3: inherited fences end at a rename out of the container; local ones stay.
    must rename-bare zfs rename -u "$SR_STAGE/three" e2ea/three
    sr_props rename-bare-props e2ea/three
    must rename-fenced sh -e -c '
        zfs set readonly=on mountpoint=none canmount=noauto volmode=none "$1/one"
        zfs rename -u "$1/one" e2ea/one' fenced "$SR_STAGE"
    sr_props rename-fenced-props e2ea/one

    # P4: a renamed source snapshot collides in a non-recursive receive until
    # the copy's snapshot is renamed by GUID.
    must ren-setup sh -e -c '
        zfs create -o mountpoint=none e2ea/rsrc
        zfs snapshot e2ea/rsrc@s1
        zfs snapshot e2ea/rsrc@s2
        zfs send e2ea/rsrc@s1 | zfs receive -u e2eb/rcopy
        zfs send -I @s1 e2ea/rsrc@s2 | zfs receive -u e2eb/rcopy
        zfs rename e2ea/rsrc@s2 e2ea/rsrc@s2-old
        zfs snapshot e2ea/rsrc@s2'
    step ren-collide sh -e -c 'zfs send -I @s2-old e2ea/rsrc@s2 | zfs receive -u e2eb/rcopy'
    must ren-fixed sh -e -c '
        zfs rename e2eb/rcopy@s2 e2eb/rcopy@s2-old
        zfs send -I @s2-old e2ea/rsrc@s2 | zfs receive -u e2eb/rcopy'
    must ren-guids zfs get -H -p -o name,value guid \
        e2ea/rsrc@s2-old e2ea/rsrc@s2 e2eb/rcopy@s2-old e2eb/rcopy@s2

    # P5: a raw copy of a leaf that inherits its key becomes its own root;
    # `load-key -n` proves a file key without loading it.
    must enc-copy sh -e -c 'zfs send -w e2eb/encrypted/child@secret |
        zfs receive -u "$1/ecopy"' copy "$SR_STAGE"
    must enc-props zfs get -H -p -o name,property,value,source \
        encryptionroot,keylocation,keyformat,keystatus "$SR_STAGE/ecopy" e2eb/encrypted/child
    must enc-keylocation zfs set keylocation=file:///run/zfs-e2e-key "$SR_STAGE/ecopy"
    must enc-proof zfs load-key -n "$SR_STAGE/ecopy"
    must enc-proof-status zfs get -H -o value keystatus "$SR_STAGE/ecopy"

    # P6: after a role switch, a raw incremental flows back into the leaf that
    # inherits its key from a container, which then still opens.
    must enc-switch sh -e -c '
        zfs set readonly=on mountpoint=none canmount=noauto "$1/ecopy"
        zfs rename -u "$1/ecopy" e2ea/ecopy
        zfs set readonly=off e2ea/ecopy
        zfs set -u mountpoint=/mnt/sr-ecopy e2ea/ecopy
        zfs load-key e2ea/ecopy
        zfs mount e2ea/ecopy
        echo back > /mnt/sr-ecopy/back
        zfs unmount e2ea/ecopy
        zfs snapshot e2ea/ecopy@back
        zfs set readonly=on e2eb/encrypted/child' switch "$SR_STAGE"
    must enc-back sh -e -c 'zfs send -w -I @secret e2ea/ecopy@back |
        zfs receive -u e2eb/encrypted/child'
    must enc-back-open sh -e -c '
        zfs unload-key e2eb/encrypted
        zfs load-key e2eb/encrypted
        zfs get -H -o property,value encryptionroot,keystatus e2eb/encrypted/child
        zfs set -u mountpoint=/mnt/sr-back e2eb/encrypted/child
        zfs mount e2eb/encrypted/child
        cat /mnt/sr-back/back
        zfs unmount e2eb/encrypted/child'

    # P7: the same after a key change on the sending side.
    must enc2-setup sh -e -c '
        zfs create e2eb/encrypted/child2
        zfs snapshot e2eb/encrypted/child2@one
        zfs send -w e2eb/encrypted/child2@one | zfs receive -u "$1/e2copy"
        zfs set readonly=on mountpoint=none canmount=noauto "$1/e2copy"
        zfs rename -u "$1/e2copy" e2ea/e2copy
        zfs set keylocation=file:///run/zfs-e2e-key e2ea/e2copy
        zfs load-key e2ea/e2copy
        dd if=/dev/urandom of=/run/zfs-e2e-key2 bs=32 count=1 2>/dev/null
        zfs change-key -o keylocation=file:///run/zfs-e2e-key2 e2ea/e2copy
        zfs set readonly=off e2ea/e2copy
        zfs set -u mountpoint=/mnt/sr-e2 e2ea/e2copy
        zfs mount e2ea/e2copy
        echo changed > /mnt/sr-e2/file
        zfs unmount e2ea/e2copy
        zfs snapshot e2ea/e2copy@two
        zfs set readonly=on e2eb/encrypted/child2' setup "$SR_STAGE"
    step enc2-back sh -e -c 'zfs send -w -I @one e2ea/e2copy@two |
        zfs receive -u e2eb/encrypted/child2'
    step enc2-open sh -e -c '
        zfs unload-key e2eb/encrypted
        zfs load-key e2eb/encrypted
        zfs set -u mountpoint=/mnt/sr-e2back e2eb/encrypted/child2
        zfs mount e2eb/encrypted/child2'

    # P8: a zvol received in the container has no device, before and after an
    # import, and none at rest with a local volmode=none; activation adds one.
    must vol-src zfs create -V 16M -o volmode=dev e2eb/vol
    must vol-snap zfs snapshot e2eb/vol@a
    sr_minors vol-before
    must vol-recv sh -e -c 'zfs send e2eb/vol@a | zfs receive -u "$1/vol"' recv "$SR_STAGE"
    sr_minors vol-after-recv
    must vol-reimport sh -e -c 'zpool export e2ea; zpool import -N -o cachefile=none e2ea'
    sr_minors vol-after-import
    must vol-rest sh -e -c '
        zfs set volmode=none readonly=on "$1/vol"
        zfs rename "$1/vol" e2ea/vol' rest "$SR_STAGE"
    sr_minors vol-at-rest
    must vol-activate zfs set volmode=dev e2ea/vol
    sr_minors vol-active
    observe end
}
