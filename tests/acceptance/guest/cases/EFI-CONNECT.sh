# EFI-CONNECT uses a real installed factory root for all four kexec targets.
# The acceptance probe is a disposable systemd unit, not a replacement initrd.
. /acceptance/share.sh
ROOT=e2ea/ROOT/proof
M=/mnt/zt-connect-root
ESP=/mnt/zt-connect-esp
VARIABLE=/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f

public_share() {
    mkdir -p /run/zt-connect-public
    if ! grep -qs ' /run/zt-connect-public ' /proc/mounts; then
        must public-key-share mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-connect-key /run/zt-connect-public
    fi
}

# The selected firmware boot moves A from virtio to USB. Resolve its native
# serial and GPT ESP type, preserving the exact partition UUID across buses.
boot_esp() {
    boot_disk=$(lsblk -dnpo PATH,SERIAL | awk '$2 == "ZFS-E2E-A" {print $1}')
    # The setup guest has no udev database, so lsblk shows no serial there.
    [ -b "$boot_disk" ] || boot_disk=$(disk A 2>/dev/null) || :
    [ -b "$boot_disk" ] || fail 'A disk identity is absent or ambiguous'
    boot_partition=$(lsblk -nrpo PATH,PARTTYPE "$boot_disk" | awk 'tolower($2) == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {print $1}')
    if [ ! -b "$boot_partition" ]; then  # the setup guest again: read the GPT itself
        for entry in /sys/class/block/"${boot_disk##*/}"/*/partition; do
            part=${entry%/partition}
            if sgdisk -i "$(cat "$entry")" "$boot_disk" | grep -qi 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'; then
                boot_partition=/dev/${part##*/}
            fi
        done
    fi
    [ -b "$boot_partition" ] || fail 'A ESP identity is absent or ambiguous'
}

request() { # NAME key|empty
    request_name=$1 kind=$2
    boot_esp
    mkdir -p "$ESP"
    must "$request_name-mount" mount -t vfat -o nosuid,nodev,noexec "$boot_partition" "$ESP"
    if [ "$kind" = key ]; then
        public_share
        must "$request_name" sh -e -c 'mkdir -p "$1/zboot"; cp "$2" "$1/zboot/authorized_keys"; sync "$1/zboot/authorized_keys"; sync "$1/zboot"' \
            request "$ESP" /run/zt-connect-public/authorized_keys
    else
        must "$request_name" sh -e -c 'mkdir -p "$1/zboot"; : > "$1/zboot/authorized_keys"; sync "$1/zboot/authorized_keys"; sync "$1/zboot"' request "$ESP"
    fi
    must "$request_name-stat" ls -ln "$ESP/zboot/authorized_keys"
    must "$request_name-unmount" umount "$ESP"
}


next_stage() {
    # The installed initramfs imports the pool as soon as the ZFS module loads.
    # usb-storage waits one second before it scans, so a USB root needs the wait removed.
    must next-cmdline zfs set "zboot:cmdline=console=ttyS0,115200 usb-storage.delay_use=0 zt.case=EFI-CONNECT zt.stage=$1" "$ROOT"
    must next-cmdline-readback zfs get -H -o value,source zboot:cmdline "$ROOT"
    must next-sync zpool sync e2ea
}

stage_1() {
    fixtures_mount
    must setup-version zboot --version
    must setup-sha256 sha256sum /usr/bin/zboot
    must setup-efi-sha256 sha256sum /fixtures/e2e-esp-artifacts/zboot-recovery.efi
    must setup-factory-sha256 sha256sum /fixtures/e2e-factory.tar.zst
    a=$(disk A)
    must deploy-preview zboot deploy "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi \
        --tar /fixtures/e2e-factory.tar.zst --pool e2ea --be proof --esp 512M --hostid 0174627a --dry-run --json
    token=$(json .token) || fail 'deploy preview has no token'
    must deploy zboot deploy "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi \
        --tar /fixtures/e2e-factory.tar.zst --pool e2ea --be proof --esp 512M --hostid 0174627a --confirm "$token" --json
    must import-a zpool import -N -o readonly=off -o cachefile=none -d /dev e2ea
    mkdir -p "$M"
    must mount-root mount -t zfs -o zfsutil "$ROOT" "$M"
    must probe-dirs mkdir -p "$M/usr/local/libexec" "$M/etc/systemd/system/multi-user.target.wants" "$M/acceptance" "$M/out"
    cat > "$M/usr/local/libexec/zt-connect-probe" <<'PROBE'
#!/bin/sh
set -u
exec </dev/null >/dev/ttyS0 2>&1
trap 'status=$?; [ "$status" -eq 0 ] || printf "EFI_CONNECT_PROBE_FAILED status=%s\n" "$status"' 0
for module in 9pnet_virtio 9p; do modprobe "$module" || exit 1; done
mount -t 9p -o trans=virtio,version=9p2000.L,cache=none zt-out /out || exit 1
mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-acceptance /acceptance || exit 1
stage=
for arg in $(cat /proc/cmdline); do case "$arg" in zt.stage=*) stage=${arg#*=} ;; esac; done
case "$stage" in 3|5|7|11) ;; *) printf 'unexpected stage=%s\n' "$stage"; exit 1 ;; esac
. /acceptance/lib.sh
zt_run EFI-CONNECT "$stage"
PROBE
    must probe-executable chmod 755 "$M/usr/local/libexec/zt-connect-probe"
    cat > "$M/etc/systemd/system/zt-connect-probe.service" <<'UNIT'
[Unit]
Description=Disposable native EFI-CONNECT installed-root probe
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/local/libexec/zt-connect-probe
StandardInput=null
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
RuntimeMaxSec=300
[Install]
WantedBy=multi-user.target
UNIT
    must probe-enabled ln -s /etc/systemd/system/zt-connect-probe.service "$M/etc/systemd/system/multi-user.target.wants/zt-connect-probe.service"
    must installed-keypairs sh -e -c 'find "$1/boot" -maxdepth 1 -type f -name "vmlinuz-*" -print; find "$1/boot" -maxdepth 1 -type f -name "initrd.img-*" -print' pairs "$M"
    must root-unmount umount "$M"
    next_stage 3
    request request-key key
    boot_esp
    # The setup guest has no udev database, so lsblk shows no PARTUUID here.
    must setup-esp-partuuid blkid -p -o value -s PART_ENTRY_UUID "$boot_partition"
    observe setup
    must export-a zpool export e2ea
}

running() {
    must running-root findmnt -rn -o SOURCE --target /
    must root-systemd cat /proc/1/comm
    must installed-version zboot --version
    # Recorded as reported; the host side checks the installed binary hash.
    step installed-package dpkg-query -W -f '${Package}\t${Version}\n' zboot
    must installed-sha256 sha256sum /usr/bin/zboot
    must running-cmdline cat /proc/cmdline
    must root-identity zfs get -Hp -o name,property,value,source guid,createtxg,objsetid,mountpoint,canmount "$ROOT"
    # Record real firmware state after kexec. If it is absent, preserve both
    # the failed read and normal CLI refusal so the host gate requires fallback.
    if [ -d /sys/firmware/efi/efivars ] && ! grep -qs ' /sys/firmware/efi/efivars ' /proc/mounts; then
        step efivarfs mount -t efivarfs efivarfs /sys/firmware/efi/efivars
    fi
    step loader-var-mounts sh -c 'grep " /sys/firmware/efi/efivars " /proc/mounts; test -d /sys/firmware/efi'
    step loader-variable od -An -v -tx1 "$VARIABLE"
    boot_esp
    step reboot-preview zboot reboot --menu --dry-run --json
    # From the USB leg the next ordinary boot may not load this ESP, so the
    # booted ESP is refused there and has to be named.
    [ -z "${menu_esp-}" ] || step reboot-esp-preview zboot reboot --menu --esp "$boot_partition" --dry-run --json
    must boot-disk-bus lsblk -dnpo PATH,SERIAL,TRAN "$boot_disk"
    must esp-partuuid lsblk -nr -o PARTUUID "$boot_partition"
    observe running
}


# Exercise the real publication and finalizer. Only the final service-manager
# dispatch is replaced; no ESP, key parser, review or zboot output is mocked.
reboot_failure() {
    public_share
    shim=/usr/local/libexec/zt-connect-reboot-shim
    mkdir -p "$shim"
    cat > "$shim/systemctl" <<'SHIM'
#!/bin/sh
printf '%s\n' "$@" > /run/zt-connect-systemctl
printf 'SYSTEMCTL_SKIP_AUTO_KEXEC=%s\nSYSTEMCTL_SKIP_AUTO_SOFT_REBOOT=%s\n' \
    "${SYSTEMCTL_SKIP_AUTO_KEXEC-}" "${SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT-}" >> /run/zt-connect-systemctl
exit 1
SHIM
    must reboot-shim-executable chmod 755 "$shim/systemctl"
    must reboot-key-symlink ln -s /run/zt-connect-public/authorized_keys /run/zt-connect-reboot-key
    must reboot-key-preview zboot reboot --menu --key /run/zt-connect-reboot-key ${menu_esp:+--esp "$boot_partition"} --dry-run --json
    step reboot-partial env "PATH=$shim:$PATH" zboot reboot --menu --key /run/zt-connect-reboot-key ${menu_esp:+--esp "$boot_partition"} --json
    [ "$rc" -eq 4 ] || fail "reboot dispatch failure should be partial, got $rc"
    must reboot-systemctl cat /run/zt-connect-systemctl
    must reboot-key-canonical sh -e -c 'awk "{print \$1 \" \" \$2}" "$1" > /run/zt-connect-canonical-key' canonical /run/zt-connect-public/authorized_keys
    boot_esp
    mkdir -p "$ESP"
    must reboot-published-mount mount -t vfat -o nosuid,nodev,noexec "$boot_partition" "$ESP"
    must reboot-published-key sh -e -c 'cmp "$1/zboot/authorized_keys" /run/zt-connect-canonical-key; sha256sum "$1/zboot/authorized_keys"; cat "$1/zboot/authorized_keys"' published "$ESP"
    must reboot-request-cleanup sh -e -c 'cmp "$1/zboot/authorized_keys" /run/zt-connect-canonical-key; rm "$1/zboot/authorized_keys"; sync "$1/zboot"; umount "$1"' cleanup "$ESP"
    must reboot-shim-cleanup sh -e -c 'rm "$1/systemctl" /run/zt-connect-reboot-key; rmdir "$1"' cleanup "$shim"
}

stage_3() { menu_esp=1; running; reboot_failure; next_stage 5; }
stage_5() { running; next_stage 7; request arm-key key; }
stage_7() { running; request arm-empty empty; }

stage_11() {
    running
    must repaired-aliases sh -e -c '
        test "$(readlink -f /vmlinuz)" = /boot/vmlinuz-zt-after-ssh
        test "$(readlink -f /initrd.img)" = /boot/initrd.img-zt-after-ssh
        readlink -f /vmlinuz /initrd.img
        sha256sum /boot/vmlinuz-zt-after-ssh /boot/initrd.img-zt-after-ssh
    '
    public_share
    boot_esp
    # Runtime-only fixture ordering keeps this active probe alive for five
    # seconds after the real reboot is queued. Default shutdown dependencies
    # stop the guard before this probe (reverse of After= startup ordering).
    cat > /run/systemd/system/zt-menu-reboot-proof.service <<'REBOOT_UNIT'
[Unit]
Description=Disposable EFI-CONNECT reboot evidence grace period
RequiresMountsFor=/out
After=zt-connect-probe.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecStop=/bin/sleep 5
REBOOT_UNIT
    must reboot-success-unit cat /run/systemd/system/zt-menu-reboot-proof.service
    must reboot-success-reload systemctl daemon-reload
    must reboot-success-guard systemctl start zt-menu-reboot-proof.service
    must reboot-success-order systemctl show -p ActiveState -p After -p Before -p Conflicts zt-menu-reboot-proof.service
    must reboot-success-key-canonical sh -e -c 'awk "{print \$1 \" \" \$2}" "$1" > /run/zt-connect-canonical-key' canonical /run/zt-connect-public/authorized_keys
    must reboot-success-preview zboot reboot --menu --key /run/zt-connect-public/authorized_keys --dry-run --json
    must reboot-success-apply zboot reboot --menu --key /run/zt-connect-public/authorized_keys --json
    mkdir -p "$ESP"
    must reboot-success-published-mount mount -t vfat -o nosuid,nodev,noexec "$boot_partition" "$ESP"
    must reboot-success-published-key sh -e -c 'cmp "$1/zboot/authorized_keys" /run/zt-connect-canonical-key; sha256sum "$1/zboot/authorized_keys"; cat "$1/zboot/authorized_keys"' published "$ESP"
    must reboot-success-published-unmount umount "$ESP"
    sync
    printf 'EFI_CONNECT_REAL_REBOOT_QUEUED\n' > /dev/ttyS0
    # Bypass zt_run's normal forced poweroff. The real queued systemd reboot
    # must finish, after the host receives DONE and starts waiting for QEMU.
    zt_emit DONE ok
    exec /bin/sleep 2147483647
}
