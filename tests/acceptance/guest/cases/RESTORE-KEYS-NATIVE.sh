# A kept tree under a file:// key. With the key file absent the plan is
# refused before any effect; present (unloaded) the restore completes and
# the tree is kept as its own encryption root under the same key location.
# Its child takes its key from the root: each dataset arrives as its own
# root, and restore relinks the child (lzc_change_key) after proving it is
# wrapped like the root.
. /acceptance/restore.sh

KEY=/run/zfs-e2e-a-key

stage_1() {
    restore_base
    restore_source
    must a-key dd if=/dev/urandom "of=$KEY" bs=32 count=1
    must secret zfs create -o "mountpoint=$SETUP_MOUNT/secret" -o encryption=aes-256-gcm \
        -o keyformat=raw "-o" "keylocation=file://$KEY" e2ea/secret
    put "$SETUP_MOUNT/secret/restore-token" ZFS-E2E-RESTORE-SCRATCH
    must secret-inner zfs create -o "mountpoint=$SETUP_MOUNT/secret-inner" e2ea/secret/inner
    put "$SETUP_MOUNT/secret-inner/restore-token" ZFS-E2E-RESTORE-INNER
    must secret-inner-unmount zfs unmount e2ea/secret/inner
    must secret-unmount zfs unmount e2ea/secret
    RESTORE_KEEP='--keep e2ea/secret'
    must a-before zfs list -H -r -t all -o name,guid e2ea
    # The key loaded: planning only checks it.
    zr loaded --dry-run
    must unload zfs unload-key e2ea/secret
    must key-save cp "$KEY" "$KEY-saved"
    must key-remove rm "$KEY"
    observe absent-before
    zr absent
    restore_record absent-record
    must absent-a zfs list -H -r -t all -o name,guid e2ea
    must absent-b zfs list -H -o name -r e2eb
    observe absent-after
    must key-restore cp "$KEY-saved" "$KEY"
    reviewed restore zr
    zr restore-apply --confirm "$TOKEN"
    restore_completed done
    # Writable import: on a readonly=on import, umount of the keyed dataset
    # never returned on OpenZFS 2.4.4. The mount stays read-only.
    must kept-import zpool import -N -o cachefile=none -d /dev e2ea
    must kept-keys zfs get -H -o property,value encryptionroot,keylocation,keystatus,encryption e2ea/secret
    must kept-inner-keys zfs get -H -o property,value encryptionroot,encryption e2ea/secret/inner
    must kept-load zfs load-key e2ea/secret
    restore_read kept e2ea/secret
    restore_read kept e2ea/secret/inner
    must kept-unload zfs unload-key e2ea/secret
    must kept-export zpool export e2ea
}
