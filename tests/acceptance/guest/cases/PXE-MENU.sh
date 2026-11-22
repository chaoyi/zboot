# PXE-MENU: a factory root on A whose ESP then holds no EFI executable, so
# firmware can start zboot only from the network. A disposable probe unit in
# the installed root runs stage 3 after the menu's handoff.
ROOT=e2ea/ROOT/proof
M=/mnt/zt-pxe-root
ESP=/mnt/zt-pxe-esp

# The setup guest has no udev database: find A's ESP by its GPT type.
esp_partition() {
    for entry in /sys/class/block/"${a##*/}"/*/partition; do
        part=${entry%/partition}
        if sgdisk -i "$(cat "$entry")" "$a" | grep -qi 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'; then
            printf '/dev/%s\n' "${part##*/}"
        fi
    done
}

stage_1() {
    must setup-efi-sha256 sha256sum /fixtures/e2e-esp-artifacts/zboot-recovery.efi
    must setup-factory-sha256 sha256sum /fixtures/e2e-factory.tar.zst
    a=$(disk A)
    must deploy-preview zboot deploy "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi \
        --tar /fixtures/e2e-factory.tar.zst --pool e2ea --be proof --esp 512M --hostid 0174627a --dry-run --json
    token=$(json .token) || fail 'deploy preview has no token'
    must deploy zboot deploy "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi \
        --tar /fixtures/e2e-factory.tar.zst --pool e2ea --be proof --esp 512M --hostid 0174627a --confirm "$token" --json
    must esp-partition esp_partition
    esp=$(cat "$ZT_LAST.out")
    [ -b "$esp" ] || fail 'A has no single ESP'
    mkdir -p "$ESP"
    must esp-mount mount -t vfat "$esp" "$ESP"
    must esp-loaders-before find "$ESP" -type f -iname '*.efi'
    [ -s "$ZT_LAST.out" ] || fail 'deploy installed no loader to remove'
    must esp-loaders-remove sh -e -c 'find "$1" -type f -iname "*.efi" -exec rm -- {} \;; sync' remove "$ESP"
    must esp-loaders-after sh -e -c 'test -z "$(find "$1" -type f -iname "*.efi")"' check "$ESP"
    must esp-unmount umount "$ESP"
    must import-a zpool import -N -o readonly=off -o cachefile=none -d /dev e2ea
    mkdir -p "$M"
    must mount-root mount -t zfs -o zfsutil "$ROOT" "$M"
    must probe-dirs mkdir -p "$M/usr/local/libexec" "$M/etc/systemd/system/multi-user.target.wants" "$M/acceptance" "$M/out"
    cat > "$M/usr/local/libexec/zt-pxe-probe" <<'PROBE'
#!/bin/sh
set -u
exec </dev/null >/dev/ttyS0 2>&1
trap 'status=$?; [ "$status" -eq 0 ] || printf "PXE_MENU_PROBE_FAILED status=%s\n" "$status"' 0
for module in 9pnet_virtio 9p; do modprobe "$module" || exit 1; done
mount -t 9p -o trans=virtio,version=9p2000.L,cache=none zt-out /out || exit 1
mount -t 9p -o ro,trans=virtio,version=9p2000.L,cache=none zt-acceptance /acceptance || exit 1
. /acceptance/lib.sh
zt_run PXE-MENU 3
PROBE
    must probe-executable chmod 755 "$M/usr/local/libexec/zt-pxe-probe"
    cat > "$M/etc/systemd/system/zt-pxe-probe.service" <<'UNIT'
[Unit]
Description=Disposable PXE-MENU installed-root probe
After=local-fs.target
[Service]
Type=simple
ExecStart=/usr/local/libexec/zt-pxe-probe
StandardInput=null
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
RuntimeMaxSec=300
[Install]
WantedBy=multi-user.target
UNIT
    must probe-enabled ln -s /etc/systemd/system/zt-pxe-probe.service "$M/etc/systemd/system/multi-user.target.wants/zt-pxe-probe.service"
    must root-unmount umount "$M"
    must next-cmdline zfs set "zboot:cmdline=console=ttyS0,115200 zt.case=PXE-MENU zt.stage=3" "$ROOT"
    must next-sync zpool sync e2ea
    observe setup
    must export-a zpool export e2ea
}

stage_3() {
    must running-root findmnt -rn -o SOURCE --target /
    must root-systemd cat /proc/1/comm
    must running-cmdline cat /proc/cmdline
    observe running
}
