# The factory input must be the fresh docs/RECOVERY.md rescue-package recipe. All disks,
# loop backing files and fixtures are this disposable case's own devices.
. /acceptance/share.sh
ACCESS=/run/zt-rescue-access
VIEW=/mnt/zt-rescue-view

make_access() {
    mkdir -p /run/zt-rescue-public
    must public-share mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-rescue-public /run/zt-rescue-public
    must access-dirs mkdir -p "$ACCESS/rootfs/root/.ssh"
    must access-key cp /run/zt-rescue-public/authorized_keys "$ACCESS/rootfs/root/.ssh/authorized_keys"
    chmod 700 "$ACCESS/rootfs/root/.ssh"
    chmod 600 "$ACCESS/rootfs/root/.ssh/authorized_keys"
    # Fixture-only user policy keeps the link down until a real console is
    # available. The host removes just this file in the RAM upper layer.
    mkdir -p "$ACCESS/rootfs/etc/systemd/network/89-zboot-rescue.network.d"
    printf '[Link]\nActivationPolicy=manual\n' > "$ACCESS/rootfs/etc/systemd/network/89-zboot-rescue.network.d/zt-fixture-manual.conf"
    cat > "$ACCESS/rootfs/root/.profile" <<'PROFILE'
terminal=$(tty)
uid=$(id -u)
printf 'tty=%s uid=%s\n' "$terminal" "$uid" > "/run/zt-login-${terminal##*/}"
printf 'ZT_RESCUE_LOGIN tty=%s uid=%s\n' "$terminal" "$uid"
PS1='rescue-root# '
export PS1
PROFILE
    # A user hook enables the serial login. It runs in the new root with a
    # fresh /dev (no /dev/zfs), so it cannot set the BE's zboot:cmdline; the
    # stick boots without console= and getty starts on ttyS0 by this link.
    cat > "$ACCESS/post-install" <<'HOOK'
#!/bin/sh
set -eu
test -n "$ZBOOT_BE"
mkdir -p /etc/systemd/system/getty.target.wants
ln -s /usr/lib/systemd/system/serial-getty@.service \
    /etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service
HOOK
    chmod 755 "$ACCESS/post-install"
}

identity_facts() {
    cat /sys/module/spl/parameters/spl_hostid
    cat /proc/sys/kernel/spl/hostid
}

inspect_image() { # KIND IMAGE; independent readonly attachment
    inspect_kind=$1 inspect_image=$2
    loop=$(/usr/sbin/losetup --find --show --read-only --partscan "$inspect_image") || fail 'readonly loop attach failed'
    must "$inspect_kind-loop-settle" udevadm settle --timeout=30
    must "$inspect_kind-partitions" lsblk -bnr -o PATH,TYPE,PARTTYPE,FSTYPE "$loop"
    partition=
    for part in $(lsblk -nr -o PATH,TYPE "$loop" | awk '$2 == "part" { print $1 }'); do
        if [ "$(blkid -p -s TYPE -o value "$part" 2>/dev/null || :)" = zfs_member ]; then
            [ -z "$partition" ] || fail 'two pool partitions in portable image'
            partition=$part
        fi
    done
    [ -n "$partition" ] || fail 'portable image has no independently probed ZFS member'
    must "$inspect_kind-labels" zdb -l "$partition"
    must "$inspect_kind-import" zpool import -N -o readonly=on -o cachefile=none -d "$partition" stick
    must "$inspect_kind-bootfs" zpool get -H -o value bootfs stick
    mkdir -p "$VIEW"
    must "$inspect_kind-mount" mount -t zfs -o ro,zfsutil stick/ROOT/rescue "$VIEW"
    must "$inspect_kind-no-hostid" test ! -e "$VIEW/etc/hostid"
    must "$inspect_kind-key-generator" cat "$VIEW/etc/systemd/system/zboot-ssh-keygen.service"
    must "$inspect_kind-resolver-link" readlink "$VIEW/etc/resolv.conf"
    must "$inspect_kind-no-host-keys" sh -c 'for key in "$1"/etc/ssh/ssh_host_*_key; do [ ! -e "$key" ] || exit 1; done' keys "$VIEW"
    must "$inspect_kind-portable-files" sh -e -c 'cat "$1/etc/default/zfs" "$1/etc/initramfs-tools/modules"; sha256sum "$1/etc/initramfs-tools/scripts/init-bottom/zboot-portable"' portable "$VIEW"
    must "$inspect_kind-view-umount" umount "$VIEW"
    must "$inspect_kind-export" zpool export stick
    must "$inspect_kind-loop-detach" /usr/sbin/losetup --detach "$loop"
}

build_image() { # KIND: current identity route is deliberately outside zboot
    build_kind=$1
    image="$ZT_OUT/portable-$build_kind.raw"
    must "$build_kind-hostid-before" identity_facts
    if [ -e /etc/hostid ]; then
        must "$build_kind-hostid-file" sh -c 'od -An -tx1 /etc/hostid | tr -d " \n"; echo'
    else
        must "$build_kind-hostid-file" printf 'absent\n'
    fi
    must "$build_kind-preview" zboot deploy --image "$image" --portable \
        --tar /fixtures/e2e-factory.tar.zst --overlay builtin:rescue --overlay "$ACCESS" \
        --be rescue --esp 512M --dry-run --json
    must "$build_kind-apply" zboot deploy --image "$image" --portable \
        --tar /fixtures/e2e-factory.tar.zst --overlay builtin:rescue --overlay "$ACCESS" \
        --be rescue --esp 512M --json
    applied=$ZT_LAST.out
    directory=$(jq -er '.result.outcome.journal_directory' "$applied") || fail 'no image attempt directory'
    operation=$(jq -er '.result.outcome.operation_id' "$applied") || fail 'no image operation id'
    must "$build_kind-hook-logs" sh -c 'for log in "$1"/deploy-"$2"-post-install*.log; do printf "%s\n" "$log"; cat "$log"; done' logs "$directory" "$operation"
    must "$build_kind-hostid-after" identity_facts
    must "$build_kind-loop-detached" /usr/sbin/losetup --associated "$image"
    inspect_image "$build_kind" "$image"
    must "$build_kind-image-bytes" busybox stat -c %s "$image"
    must "$build_kind-image-sha256" sha256sum "$image"
}

stage_1() {
    fixtures_mount
    must source-version zboot --version
    must source-binary-sha256 sha256sum /usr/bin/zboot
    must factory-sha256 sha256sum /fixtures/e2e-factory.tar.zst
    must loader-sha256 sha256sum /fixtures/e2e-esp-artifacts/zboot-recovery.efi
    # --image must use the shipped loader lookup, which remains an ordinary
    # packaged path in this development initrd, independently hashed above.
    mkdir -p /usr/lib/zboot
    must packaged-loader cp /fixtures/e2e-esp-artifacts/zboot-recovery.efi /usr/lib/zboot/zboot.efi
    must initial-hostid identity_facts
    original=$(cat /sys/module/spl/parameters/spl_hostid)
    must initial-no-hostid test ! -e /etc/hostid
    make_access
    must parameter-nonzero sh -c 'printf "610800471\n" > /sys/module/spl/parameters/spl_hostid'
    build_image parameter
    must parameter-zero sh -c 'printf "0\n" > /sys/module/spl/parameters/spl_hostid'
    must fallback-file sh -c 'printf "\150\044\127\023" > /etc/hostid'
    build_image file
    must fallback-retired rm /etc/hostid
    # Another host's exported internal pool is the first machine's fixture.
    must internal-hostid sh -c 'printf "324478056\n" > /sys/module/spl/parameters/spl_hostid'
    a=$(disk A)
    must internal-part sgdisk -n 1:0:0 -t 1:BF01 "$a"
    must internal-probe partprobe "$a"
    must internal-settle udevadm settle --timeout=30
    must internal-create zpool create -o cachefile=none -O mountpoint=none internal "${a}1"
    must internal-root zfs create -o canmount=noauto -o mountpoint=/ internal/missing-kernel
    mkdir -p /mnt/zt-internal
    must internal-root-mount mount -t zfs -o zfsutil internal/missing-kernel /mnt/zt-internal
    must internal-identity sh -c 'mkdir -p /mnt/zt-internal/etc; printf "\150\044\127\023" > /mnt/zt-internal/etc/hostid'
    must internal-root-unmount umount /mnt/zt-internal
    must internal-default zpool set bootfs=internal/missing-kernel internal
    must internal-guid zpool get -H -o value guid internal
    must internal-export zpool export internal
    must internal-labels zdb -l "${a}1"
    must caller-hostid-restored sh -c 'printf "%s\n" "$1" > /sys/module/spl/parameters/spl_hostid' restore "$original"
    observe final
}
