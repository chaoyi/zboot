# Installed boot proof shared by the deploy cases. This is an overlay service
# in the disposable root, executed by its real systemd after the UKI handoff.
# With SPARE (a disk label), the installed system also erases that disk: the
# only place an erase is verified by the probe the zboot package installs.
deploy_boot_overlay() { # OVERLAY EXPECTED_ROOT [SPARE]
    overlay=$1 expected=$2 spare=${3:-}
    must deploy-probe-dirs mkdir -p "$overlay/rootfs/usr/local/libexec" \
        "$overlay/rootfs/etc/systemd/system/multi-user.target.wants"
    cat > "$overlay/rootfs/usr/local/libexec/zfs-e2e-deploy-boot" <<'PROBE'
#!/bin/sh
set -eu
trap 'r=$?; [ "$r" -eq 0 ] || echo "ZFS_E2E_DEPLOY_BOOT_FAILED rc=$r"' 0
p() { printf 'ZFS_E2E_DEPLOY %s=%s\n' "$1" "$2"; }
p pid1 "$(cat /proc/1/comm)"
p efi "$(if [ -d /sys/firmware/efi ]; then echo yes; else echo no; fi)"
p root "$(findmnt -rn -o SOURCE --target /)"
p role "$(zfs get -H -o value canmount "$(findmnt -rn -o SOURCE --target /)")"
p pending "$(zfs get -H -o value zboot:pending "$(findmnt -rn -o SOURCE --target /)")"
p hostid "$(od -An -tx1 /etc/hostid | tr -d ' \n')"
p bootfs "$(zpool get -H -o value bootfs e2ed)"
p probe "$(if [ -x /sbin/zboot-probe-signatures ]; then echo yes; else echo no; fi)"
field() { tr -d '\n' | grep -o "\"$1\": *\"[a-z0-9]*\"" | head -n 1 | sed 's/.*: *"//; s/"$//'; }
erase() { # DISK: `zboot wipe` by its reviewed token, as a script runs it
    token=$(zboot wipe "$1" --dry-run --json | field token)
    p wipe "$(zboot wipe "$1" --confirm "$token" --json | field mode)"
}
PROBE
    [ -z "$spare" ] ||
        printf 'erase /dev/disk/by-id/virtio-ZFS-E2E-%s\n' "$spare" >> "$overlay/rootfs/usr/local/libexec/zfs-e2e-deploy-boot"
    printf 'test "$(findmnt -rn -o SOURCE --target /)" = %s\n' "$expected" >> "$overlay/rootfs/usr/local/libexec/zfs-e2e-deploy-boot"
    printf '%s\n' 'echo ZFS_E2E_DEPLOY_BOOT_OK' 'systemctl --no-block poweroff' >> "$overlay/rootfs/usr/local/libexec/zfs-e2e-deploy-boot"
    chmod 755 "$overlay/rootfs/usr/local/libexec/zfs-e2e-deploy-boot"
    cat > "$overlay/rootfs/etc/systemd/system/zfs-e2e-deploy-boot.service" <<'UNIT'
[Unit]
Description=Disposable deployed root boot proof
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/local/libexec/zfs-e2e-deploy-boot
StandardInput=null
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
[Install]
WantedBy=multi-user.target
UNIT
    must deploy-probe-enable ln -s /etc/systemd/system/zfs-e2e-deploy-boot.service \
        "$overlay/rootfs/etc/systemd/system/multi-user.target.wants/zfs-e2e-deploy-boot.service"
}
