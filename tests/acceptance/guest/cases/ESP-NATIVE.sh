# ESP-NATIVE keeps two boots. Native A/B pool disks are refreshed together,
# D stays an unselected rescue disk, and its explicit `esp PART` over an older
# install (a zboot UKI under the old name EFI/zboot/zboot-recovery.efi and a
# zboot fallback, beside a zboot UKI under EFI/Linux and an old operations
# record) writes zboot's two fixed paths, reports the old name as stale and
# leaves it untouched, and retains the mounted-RW power-cut durability proof.
# Only disposable guest media changes.
UKI=/fixtures/e2e-esp-artifacts/zboot-recovery.efi
M=/mnt/zfs-e2e/esp
MA=/mnt/zfs-e2e/esp-a
MB=/mnt/zfs-e2e/esp-b
MT=/mnt/zfs-e2e/esp-typed
WRONG=0123456789abcdef0123456789abcdef
STUB='\0115\0132\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0200\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0120\0105\0000\0000\0144\0206\0001\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0360\0000\0000\0000\0013\0002\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0012\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0056\0157\0163\0162\0145\0154\0000\0000\0050\0000\0000\0000\0000\0000\0000\0000\0000\0002\0000\0000\0000\0002\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0111\0104\0075\0172\0142\0157\0157\0164\0012\0126\0105\0122\0123\0111\0117\0116\0075\0157\0154\0144\0055\0156\0141\0164\0151\0166\0145\0055\0146\0151\0170\0164\0165\0162\0145\0055\0166\0060\0061\0012\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000\0000'
owned_stub() {
    must "$1" sh -e -c 'printf "%b" "$1" > "$2"' owned "$STUB" "$2"
}
stage_1() {
    must versions sh -c 'uname -a; zfs version; cat /sys/module/zfs/version'
    for label in A B; do
        d=$(disk "$label")
        must "layout-$label" sgdisk -n 1:2048:+512M -t 1:ef00 -n 2:0:0 -t 2:BF01 "$d"
        must "probe-$label" partprobe "$d"
        must "settle-$label" udevadm settle --timeout=30
        must "format-$label" mkfs.vfat -F 32 "${d}1"
        case "$label" in A) pool=e2ea view=$MA;; B) pool=e2eb view=$MB;; esac
        must "pool-$label" zpool create -f -o cachefile=none -O mountpoint=none "$pool" "${d}2"
        must "mount-$label" sh -e -c 'mkdir -p "$2"; mount -t vfat "$1" "$2"; mkdir -p "$2/EFI/zboot" "$2/EFI/BOOT"' mount "${d}1" "$view"
        owned_stub "owned-$label" "$view/EFI/zboot/zboot.efi"
        must "foreign-$label" sh -e -c 'printf %s foreign-fallback-preserved > "$1/EFI/BOOT/BOOTX64.EFI"' seed "$view"
    done
    must source-data zfs create -o mountpoint=none e2ea/data
    must pair-bootstrap zboot sync e2ea/data e2eb/data --json
    observe paired
    must pair-records zfs get -H -o name,property,value,source zboot:pair e2ea/data e2eb/data
    d=$(disk D) p=$(disk D)1 pt=$(disk D)2
    must esp-part sgdisk -n 1:2048:+512M -t 1:ef00 -n 2:0:+512M -t 2:ef00 "$d"
    must esp-probe partprobe "$d"
    must esp-settle udevadm settle --timeout=30
    must esp-mkfs mkfs.vfat -F 32 -n E2E-ESP "$p"
    must typed-mkfs mkfs.vfat -F 32 -n E2E-TYPED "$pt"
    must esp-mkdir mkdir -p "$M" "$MT"
    must seed-mount mount -t vfat "$p" "$M"
    must seed sh -e -c 'cd "$1"; mkdir -p EFI/zboot EFI/BOOT EFI/vendor EFI/Linux EFI/zboot/operations
        printf %s unrelated-loader-preserved > EFI/vendor/loader.efi
        printf %s unrelated-root-file-preserved > operator.txt
        printf %s legacy-record > EFI/zboot/operations/00000000-0000-4000-8000-000000000001.json
        cp "$2" EFI/Linux/zboot.efi
        printf x >> EFI/Linux/zboot.efi' seed "$M" "$UKI"
    owned_stub seed-stale "$M/EFI/zboot/zboot-recovery.efi"
    owned_stub seed-fallback "$M/EFI/BOOT/BOOTX64.EFI"
    must seed-sha256 sh -e -c 'cd "$1"; sha256sum EFI/zboot/zboot-recovery.efi EFI/BOOT/BOOTX64.EFI EFI/vendor/loader.efi operator.txt' sums "$M"
    must outside-owned-sha256 sha256sum "$M/EFI/Linux/zboot.efi"
    must outside-owned-bytes busybox stat -c %s "$M/EFI/Linux/zboot.efi"
    must seed-umount umount "$M"
    must uki-sha256 sha256sum "$UKI"
    must uki-bytes busybox stat -c %s "$UKI"
    must esp-before sha256sum "$p"
    must auto-preview zboot esp --efi "$UKI" --dry-run --json
    must auto-before-A sha256sum "$MA/EFI/zboot/zboot.efi"
    must auto-before-B sha256sum "$MB/EFI/zboot/zboot.efi"
    # This wrapper changes only B1 after A's exact new bytes have appeared.
    # The next mandatory inventory call then observes a real readonly target.
    must late-config sh -e -c '
        mkdir -p /usr/local/libexec/zboot-esp-test /run/esp-late
        command -v lsblk > /run/esp-late/real
        printf "%s\n" "$1" > /run/esp-late/a
        printf "%s\n" "$2" > /run/esp-late/b
        sha256sum "$3" | awk "{print \$1}" > /run/esp-late/hash
        busybox stat -c %s "$3" > /run/esp-late/size
        lsblk -dnro MAJ:MIN "$2" > /run/esp-late/rdev
        blkid -s PARTUUID -o value "$2" > /run/esp-late/partuuid
        serial=$(cat /sys/block/vdb/serial 2>/dev/null || cat /sys/block/vdb/device/serial)
        printf "serial=%s\n" "$serial"
        lsblk -bnr -o PATH,MAJ:MIN,SIZE,PARTUUID,UUID,FSTYPE,PARTTYPE,RO "$2"
        busybox blockdev --getro "$2"' config "$MA/EFI/zboot/zboot.efi" "$(disk B)1" "$UKI"
    cat > /usr/local/libexec/zboot-esp-test/lsblk <<'SHIM'
#!/bin/sh
set -eu
real=$(cat /run/esp-late/real)
a=$(cat /run/esp-late/a) b=$(cat /run/esp-late/b)
if [ "$#" = 8 ] && [ "$1" = --json ] && [ "$2" = --tree ] && [ "$3" = --properties-by ] && [ "$4" = blkid ] && [ "$5" = --bytes ] && [ "$6" = --paths ] && [ "$7" = --output ] && [ "$8" = PATH,MAJ:MIN,TYPE,SIZE,LOG-SEC,PHY-SEC,RO,SERIAL,WWN,MODEL,FSTYPE,LABEL,UUID,PARTUUID,PARTTYPE,PTUUID,MOUNTPOINTS ] && [ ! -e /out/1/late-fired ]; then
    if [ "$(busybox stat -c %s "$a")" = "$(cat /run/esp-late/size)" ] && [ "$(sha256sum "$a" | awk '{print $1}')" = "$(cat /run/esp-late/hash)" ]; then
        [ "$(cat /sys/block/vdb/serial 2>/dev/null || cat /sys/block/vdb/device/serial)" = ZFS-E2E-B ]
        [ "$b" = /dev/vdb1 ]
        [ "$("$real" -dnro MAJ:MIN "$b")" = "$(cat /run/esp-late/rdev)" ]
        [ "$(blkid -s PARTUUID -o value "$b")" = "$(cat /run/esp-late/partuuid)" ]
        printf '%s\n' "$@" > /out/1/cut-esp-second-observer.argv
        printf '/bin/busybox\nblockdev\n--setro\n%s\n' "$b" > /out/1/cut-esp-second-readonly.argv
        printf 'serial=ZFS-E2E-B\npartuuid=%s\nrdev=%s\nbefore=%s\n' "$(cat /run/esp-late/partuuid)" "$(cat /run/esp-late/rdev)" "$(busybox blockdev --getro "$b")" > /out/1/late-transition
        [ "$(busybox blockdev --getro "$b")" = 0 ]
        status=0
        /bin/busybox blockdev --setro "$b" || status=$?
        printf '%s\n' "$status" > /out/1/cut-esp-second-readonly.argv.real-rc
        [ "$status" = 0 ]
        printf 'after=%s\n' "$(busybox blockdev --getro "$b")" >> /out/1/late-transition
        [ "$(busybox blockdev --getro "$b")" = 1 ]
        cat "/sys/dev/block/$(cat /run/esp-late/rdev)/ro" > /out/1/late-kernel-ro
        printf fired > /out/1/late-fired
    fi
fi
exec "$real" "$@"
SHIM
    must late-executable chmod 0700 /usr/local/libexec/zboot-esp-test/lsblk
    must late-syntax sh -n /usr/local/libexec/zboot-esp-test/lsblk
    must auto-seed-sync sync
    step auto-late env PATH=/usr/local/libexec/zboot-esp-test:$PATH zboot esp --efi "$UKI" --json
    must late-fired cat /out/1/late-transition /out/1/late-fired /out/1/late-kernel-ro
    must auto-after-A sha256sum "$MA/EFI/zboot/zboot.efi"
    must auto-after-B sha256sum "$MB/EFI/zboot/zboot.efi"
    must late-unset busybox blockdev --setrw "$(disk B)1"
    must auto-finish zboot esp --efi "$UKI" --json
    must pair-after zfs get -H -o name,property,value,source zboot:pair e2ea/data e2eb/data
    must auto-files sh -e -c 'sha256sum "$1/EFI/zboot/zboot.efi" "$2/EFI/zboot/zboot.efi"; cat "$1/EFI/BOOT/BOOTX64.EFI"; echo; cat "$2/EFI/BOOT/BOOTX64.EFI"; echo' files "$MA" "$MB"
    must auto-unmount umount "$MA" "$MB"
    must auto-skipped sha256sum "$p"
    # Explicit empty-ownership installation is the separate typed path.
    must typed-mount mount -t vfat "$pt" "$MT"
    must typed-seed sh -e -c 'mkdir -p "$1/EFI/BOOT"; printf %s foreign-typed-fallback > "$1/EFI/BOOT/BOOTX64.EFI"' seed "$MT"
    must typed-unmount umount "$MT"
    must typed-preview zboot esp "$pt" --efi "$UKI" --dry-run --json
    typed_token=$(json .token) || fail 'typed preview has no token'
    step unattended zboot esp "$pt" --efi "$UKI" --json
    must typed-apply zboot esp "$pt" --efi "$UKI" --confirm "$typed_token" --json
    must mountinfo-before cat /proc/self/mountinfo
    must preview zboot esp "$p" --efi "$UKI" --dry-run --json
    token=$(json .token) || fail 'preview has no token'
    must preview-text zboot esp "$p" --efi "$UKI" --dry-run
    step wrong-token zboot esp "$p" --efi "$UKI" --confirm "$WRONG" --json
    must esp-refused sha256sum "$p"
    must refused-mount mount -t vfat "$p" "$M"
    must refused-sha256 sh -e -c 'cd "$1"; sha256sum EFI/zboot/zboot-recovery.efi EFI/BOOT/BOOTX64.EFI EFI/vendor/loader.efi operator.txt' sums "$M"
    must refused-files sh -c 'cd "$1" && for f in EFI/vendor/loader.efi operator.txt; do printf "%s=" "$f"; cat "$f"; echo; done' files "$M"
    must apply-mountinfo cat /proc/self/mountinfo
    must apply-partition lsblk -bnr -o PATH,MAJ:MIN,SIZE,PARTUUID,UUID,FSTYPE,PARTTYPE,RO "$p"
    must prepare-cut sync
    must writeback-before cat /proc/sys/vm/dirty_writeback_centisecs
    must writeback-disabled sh -e -c 'printf "0\n" > /proc/sys/vm/dirty_writeback_centisecs; cat /proc/sys/vm/dirty_writeback_centisecs'
    must apply zboot esp "$p" --efi "$UKI" --confirm "$token" --json
    zt_emit CUT esp-published
    exec sleep 2147483647
}

stage_2() {
    p=$(disk D)1
    must mountinfo-before cat /proc/self/mountinfo
    must cold-partition lsblk -bnr -o PATH,MAJ:MIN,SIZE,PARTUUID,UUID,FSTYPE,PARTTYPE,RO "$p"
    must esp-mkdir mkdir -p "$M"
    # No product recovery, writable mount or sync precedes these cold reads.
    must installed-mount mount -t vfat -o ro,nosuid,nodev,noexec "$p" "$M"
    must installed-sha256 sh -c 'cd "$1" && sha256sum EFI/zboot/zboot.efi EFI/BOOT/BOOTX64.EFI EFI/Linux/zboot.efi EFI/zboot/zboot-recovery.efi' sums "$M"
    must installed-files sh -c 'cd "$1" && for f in EFI/vendor/loader.efi operator.txt; do printf "%s=" "$f"; cat "$f"; echo; done' files "$M"
    must installed-stat busybox stat -c %s:%Y "$M/EFI/zboot/zboot.efi" "$M/EFI/BOOT/BOOTX64.EFI"
    must cold-legacy-record cat "$M/EFI/zboot/operations/00000000-0000-4000-8000-000000000001.json"
    must cold-temporaries find "$M" -name '.zboot-*.tmp' -print
    # The RAM substrate gets the known comparison loader only for this status.
    # shipped_efi is ../lib/zboot/zboot.efi from /usr/bin/zboot's directory.
    must shipped-lookup sh -e -c 'program=$(readlink -f "$(command -v zboot)")
        [ "$program" = /usr/bin/zboot ]
        if [ -e /usr/bin/zboot.efi ] || [ -L /usr/bin/zboot.efi ]; then exit 1; fi
        if [ -e /usr/lib/zboot/zboot.efi ] || [ -L /usr/lib/zboot/zboot.efi ]; then exit 1; fi
        printf "%s\n" "$program" /usr/lib/zboot/zboot.efi'
    must shipped-mkdir mkdir -p /usr/lib/zboot
    must shipped-mountinfo cat /proc/self/mountinfo
    must shipped-copy cp "$UKI" /usr/lib/zboot/zboot.efi
    must shipped-sha256 sha256sum /usr/lib/zboot/zboot.efi
    must status zboot status --devices --json
    must installed-umount umount "$M"
    must mountinfo-after cat /proc/self/mountinfo
}
