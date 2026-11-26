# Raw-copy a locked leaf whose encryption root is ABOVE the pair. The new
# copy is its own encryption root, wrapped like the source's root, with the
# leaf's copied properties set locally.
EXT_SRC=e2eext-src/secret/subtree
EXT_DST=e2eext-dst/copy
EXT_MOUNT=/mnt/zfs-e2e/external-er-source

ext_pool() {
    dev=$(disk "$2")
    must "partition-$1" sgdisk -n 1:0:0 -t 1:BF01 "$dev"
    must "probe-$1" partprobe "$dev"
    mdev -s
    must "pool-$1" zpool create -f -o cachefile=none -O canmount=off \
        -O mountpoint=none -O volmode=none "$1" "${dev}1"
}

stage_1() {
    must versions sh -e -c 'zfs version; cat /sys/module/zfs/version'
    ext_pool e2eext-src B
    ext_pool e2eext-dst A
    # Public disposable fixture key, unrelated to any host/user secret.
    must key sh -e -c 'printf %s 0123456789abcdef0123456789abcdef > /run/external-er-key'
    must encryption-root zfs create -u -o canmount=off -o mountpoint=none \
        -o encryption=aes-256-gcm -o keyformat=raw \
        -o keylocation=file:///run/external-er-key e2eext-src/secret
    must prompt zfs set keylocation=prompt e2eext-src/secret
    must selected-leaf zfs create -u -o canmount=noauto -o "mountpoint=$EXT_MOUNT" \
        -o compression=zstd -o e2e:external=leaf "$EXT_SRC"
    must mount-leaf zfs mount "$EXT_SRC"
    must outside zfs create -u -o canmount=off -o mountpoint=none e2eext-src/secret/outside
    must outside-snapshot zfs snapshot e2eext-src/secret/outside@outside
    must payload-one sh -e -c 'printf %s external-leaf-one > "$1/leaf-token"' payload "$EXT_MOUNT"
    must first zfs snapshot "$EXT_SRC@first"
    must payload-two sh -e -c 'printf %s external-leaf-two > "$1/leaf-token"' payload "$EXT_MOUNT"
    must source-hash sha256sum "$EXT_MOUNT/leaf-token"
    must second zfs snapshot "$EXT_SRC@second"
    must unmount-leaf zfs unmount "$EXT_SRC"
    must readonly zfs set readonly=on "$EXT_SRC"
    must source-ivsets zfs get -H -p -o name,value ivsetguid "$EXT_SRC@first" "$EXT_SRC@second"
    must unload-source zfs unload-key e2eext-src/secret
    observe before

    must sync zboot sync "$EXT_SRC" "$EXT_DST" --json
    observe copied
    must copied-ivsets zfs get -H -p -o name,value ivsetguid "$EXT_DST@first" "$EXT_DST@second"
    must operations zboot status --all --json
    # Only the completed copy is now unlocked for an independent payload
    # check. The raw stream ran while the ancestor and the leaf were locked,
    # and never needed an encryption ancestor on the destination pool.
    must unlock-copy zfs load-key -L file:///run/external-er-key "$EXT_DST"
    must inspect-directory mkdir -p /mnt/zfs-e2e/external-er-copy
    must inspect-mount mount -t zfs -o ro,zfsutil "$EXT_DST" /mnt/zfs-e2e/external-er-copy
    must copied-hash sha256sum /mnt/zfs-e2e/external-er-copy/leaf-token
    must inspect-unmount umount /mnt/zfs-e2e/external-er-copy
    must relock-copy zfs unload-key "$EXT_DST"
    observe final
}
