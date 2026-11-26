# EFI-HANDOFF-NATIVE. Stage 1 (setup, direct kernel): two BEs, a default on A
# and a second on B, each with a /var child, plus a home tree that spans both
# pools. A's /var child is canmount=on (a hand-made mistake); B's is noauto.
# Each BE's saved cmdline hands the target boot back to this case: A to
# stage 3, B to stage 5. Stages 2 and 4 are the host-driven Menu dialogues
# (cases/efi_handoff_native.py). Stages 3 and 5 run in the BE the Menu
# kexec'd: the acceptance initrd copied into that BE.

be() {
    pool=$1 target=$2 var_canmount=$3 var_token=$4 mnt=/mnt/be-$1
    must "be-$pool" zfs create -o canmount=off -o mountpoint=none "$pool/BE"
    must "proof-$pool" zfs create -o canmount=noauto -o mountpoint=/ \
        -o "zboot:cmdline=console=ttyS0,115200 zt.case=EFI-HANDOFF-NATIVE zt.stage=$target" "$pool/BE/proof"
    mkdir -p "$mnt"
    must "mount-$pool" mount -t zfs -o zfsutil "$pool/BE/proof" "$mnt"
    must "boot-files-$pool" sh -e -c 'mkdir -p "$1/boot" "$1/home" "$1/var"
        cp /fixtures/vmlinuz "$1/boot/vmlinuz-proof"
        cp /fixtures/initrd.img "$1/boot/initrd.img-proof"' be "$mnt"
    # The child inherits mountpoint /var; -u keeps it off this guest's /var.
    must "var-$pool" zfs create -u -o "canmount=$var_canmount" "$pool/BE/proof/var"
    must "mount-var-$pool" mount -t zfs -o zfsutil "$pool/BE/proof/var" "$mnt/var"
    must "var-token-$pool" sh -c 'echo "$1" > "$2/var/var-token"' token "$var_token" "$mnt"
    must "umount-var-$pool" umount "$mnt/var"
}

stage_1() {
    fixture_pools
    be e2ea 3 on ZFS-E2E-VAR-A
    must bootfs zpool set bootfs=e2ea/BE/proof e2ea
    must umount-e2ea umount /mnt/be-e2ea
    # This clone has real kernel/initrd bytes but an unknown role. Discovery
    # must retain its diagnostic row and refuse it before any handoff.
    must discovery-snapshot zfs snapshot e2ea/BE/proof@discovery
    must unknown-role zfs clone -o canmount=noauto -o mountpoint=/ \
        -o zboot:future-discovery=fenced e2ea/BE/proof@discovery e2ea/BE/unknown
    be e2eb 5 noauto ZFS-E2E-VAR-B
    must token sh -c 'echo ZFS-E2E-HANDOFF-TOKEN > /mnt/be-e2eb/handoff-token'
    must boot-snapshot zfs snapshot e2eb/BE/proof@boot
    must umount-e2eb umount /mnt/be-e2eb
    must home-a zfs create -o mountpoint=/home e2ea/home
    must home-a-token sh -c 'echo ZFS-E2E-HOME-BASE > /home/base-token'
    must home-b zfs create -o canmount=off -o mountpoint=none e2eb/home
    must home-b-user zfs create -o mountpoint=/home/user e2eb/home/user
    must home-b-token sh -c 'echo ZFS-E2E-HOME-CHILD > /home/user/child-token'
    must unmount-user zfs unmount e2eb/home/user
    must unmount-home zfs unmount e2ea/home
    observe setup
    must export-a zpool export e2ea
    must export-b zpool export e2eb
}

# What a stock Debian root-on-ZFS boot of BE $1 mounts, read-only: the
# initramfs mounts the BE and each descendant that is not canmount=off, then
# zfs-mount.service runs `zfs mount -a`, which skips canmount=noauto.
stock_boot() {
    must import-a zpool import -N -R /selected-root -d "$(disk A)1" -o readonly=on -o cachefile=none e2ea
    must import-b zpool import -N -R /selected-root -d "$(disk B)1" -o readonly=on -o cachefile=none e2eb
    must mount-root zfs mount "$1"
    must mount-be-children sh -e -c 'zfs list -H -o name,canmount -r -t filesystem "$1" |
        while read -r name canmount; do
            [ "$name" = "$1" ] || [ "$canmount" = off ] || zfs mount "$name"
        done' stock "$1"
    must mount-all zfs mount -a
}

# The kexec'd target A: it boots although A has a canmount=on child and mounts
# only A's /var. Then the operator repairs that child from inside A.
stage_3() {
    step cmdline cat /proc/cmdline
    stock_boot e2ea/BE/proof
    step var-token cat /selected-root/var/var-token
    observe target
    must export-b zpool export e2eb
    must export-a-readonly zpool export e2ea
    must import-a-writable zpool import -N -d "$(disk A)1" -o cachefile=none e2ea
    must repair zfs set canmount=noauto e2ea/BE/proof/var
    step repaired zfs get -H -o value,source canmount e2ea/BE/proof/var
    must export-a zpool export e2ea
}

# The kexec'd target B: verify what the Menu handed over, read-only.
stage_5() {
    step cmdline cat /proc/cmdline
    stock_boot e2eb/BE/proof
    step token cat /selected-root/handoff-token
    step var-token cat /selected-root/var/var-token
    step base-token cat /selected-root/home/base-token
    step child-token cat /selected-root/home/user/child-token
    observe target
}
