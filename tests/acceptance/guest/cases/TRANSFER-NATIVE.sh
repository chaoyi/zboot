# zboot sync into an existing copy: an unpaired copy is refused until it is
# paired; then a writable source pushes a fresh boundary, keeping the copy's
# local placement and giving it the copied properties as local values, while
# a child under the leaf is reported, not copied; a read-only source
# transfers its existing snapshot without a new capture. Content is read from
# the raw copy with the source key.
. /acceptance/lifecycle.sh
SRC=/mnt/zfs-e2e/transfer-source
S=e2eb/xfer C=e2ea/transfer

inspect() {  # inspect NAME [@SNAP]: ro-mount the copy and read its data
    must "$1-load-key" zfs load-key -L file:///run/zfs-e2e-key $C
    dir=/mnt/zfs-e2e/transfer-check
    must "$1-mkdir" mkdir -p $dir
    must "$1-mount" mount -t zfs -o ro "$C$2" $dir
    must "$1-mountinfo" cat /proc/self/mountinfo
    must "$1-read" cat $dir/data
    must "$1-umount" umount $dir
    must "$1-unload-key" zfs unload-key $C
}

stage_1() {
    fixture_pools
    must create-source zfs create -o mountpoint=$SRC -o encryption=aes-256-gcm -o keyformat=raw \
        -o keylocation=file:///run/zfs-e2e-key -o compression=zstd -o e2e:data-property=source $S
    put initial $SRC/data initial
    must snapshot-initial zfs snapshot $S@initial
    # A property-free raw seed, as a stock receive leaves it.
    must seed sh -e -c 'zfs send -w "$1@initial" | zfs receive -u -o readonly=on "$2"' seed $S $C
    must place-copy zfs set canmount=noauto mountpoint=/mnt/zfs-e2e/transfer-target $C
    observe unpaired-before
    refuse unpaired zboot sync $S $C --json
    observe unpaired-after
    must pair zboot pair $S $C --json
    # A child under the working copy's leaf: reported, never copied.
    must create-extra zfs create $S/extra
    put pushed $SRC/data pushed
    put pushed-extra $SRC/extra/data pushed-extra
    must snapshot-pushed zfs snapshot $S@pushed
    observe push-before
    must push zboot sync $S --json
    observe push-after
    step push-all zboot sync --all --json
    # Keep the copy unopened until the last transfer: native key loading and
    # mounting can change encrypted accounting even when mounted ro.
    put readonly $SRC/data readonly
    must snapshot-boundary zfs snapshot $S@readonly_boundary
    must source-readonly zfs set readonly=on $S
    observe pull-before
    must pull zboot sync $S --json
    observe pull-after
    inspect pushed @pushed
    inspect head
}
