# Real CLI cleanup after returned Run errors at two native boundaries. Each
# boot constructs an independent fixture; neither fault is a VM power cut.
. /acceptance/restore.sh

# The product UKI always runs udev. Record its real process and selected-device
# properties, and wait for all fixture partition/filesystem changes before any
# default GUID scan. No product command is used to construct these facts.
returned_udev() {
    must udev-daemon sh -e -c '
        found=no
        for entry in /proc/[0-9]*/comm; do
            read -r name < "$entry" || continue
            [ "$name" = systemd-udevd ] || continue
            process=${entry%/comm}
            printf "pid=%s\n" "${process##*/}"
            cat "$process/stat"
            readlink "$process/exe"
            /bin/busybox tr "\000" "\n" < "$process/cmdline"
            found=yes
        done
        [ "$found" = yes ]'
}

returned_partitions() {
    rp_base=${1##*/}
    rp_parent=$(readlink -f "/sys/class/block/$rp_base") || return 1
    for rp_entry in /sys/class/block/"$rp_base"/"$rp_base"*; do
        [ -f "$rp_entry/partition" ] || continue
        [ "$(readlink -f "$rp_entry/..")" = "$rp_parent" ] || return 1
        rp_partition=/dev/${rp_entry##*/}
        [ -b "$rp_partition" ] || return 1
        printf '%s\n' "$rp_partition"
    done
}

returned_reset() {
    # GPT removal does not clear filesystem signatures in old partitions.
    # Select only this case's exact serial-owned disks and erase their old
    # partition signatures while no pool is imported, before deleting GPT.
    must reset-imported zpool list -H -o name
    [ ! -s "$ZT_LAST.out" ] || fail 'a pool was imported before the fresh fixture reset'
    for label in A B D; do
        selected=$(disk "$label")
        must "reset-selected-$label" sh -e -c '
            node=${1##*/}
            serial=$(cat "/sys/block/$node/serial" 2>/dev/null || cat "/sys/block/$node/device/serial")
            [ "$serial" = "ZFS-E2E-$2" ]
            printf "%s\t%s\n" "$serial" "$1"' selected "$selected" "$label"
        must "reset-layout-$label" lsblk --json --bytes --tree --output PATH,TYPE,PKNAME,SERIAL "$selected"
        must "reset-partitions-$label" returned_partitions "$selected"
        partitions=$(cat "$ZT_LAST.out")
        for partition in $partitions; do
            suffix=$label-${partition##*/}
            must "reset-signatures-before-$suffix" wipefs --no-act --json "$partition"
            must "reset-clear-$suffix" wipefs --all --force "$partition"
            must "reset-signatures-after-$suffix" wipefs --no-act --json "$partition"
        done
        must "reset-$label" sgdisk --zap-all "$selected"
        must "reset-probe-$label" partprobe "$selected"
        must "reset-settle-$label" udevadm settle --timeout=30
    done
    mdev -s
}

returned_fixture() {
    restore_base
    restore_source
    restore_scratch
    restore_pool_c
    must udev-trigger-after-setup udevadm trigger --action=change --subsystem-match=block
    must udev-settle-after-setup udevadm settle --timeout=30
    for label in A B; do
        partition="$(disk "$label")1"
        must "signature-$label" wipefs --no-act --json "$partition"
        must "udev-info-$label" udevadm info --query=property --name "$partition"
    done
    RESTORE_KEEP='--keep e2ea/scratch'
    # The UKI CLI owns reopening the selected RO pools and their cleanup.
    for pool in e2ea e2eb; do
        must "readonly-guid-$pool" zpool get -H -p -o value guid "$pool"
        pool_guid=$(cat "$ZT_LAST.out")
        must "readonly-export-$pool" zpool export "$pool"
        must "readonly-import-$pool" zpool import -N -o readonly=on -o cachefile=none "$pool_guid"
    done
    observe before
    previewed restore-preview zr restore-preview
}

returned_result() {
    zr restore-apply --confirm "$TOKEN"
    [ "$(cat "$ZT_LAST.rc")" = 4 ] || fail "returned restore error has rc $(cat "$ZT_LAST.rc"), not partial 4"
    restore_record stopped-record
    [ -n "$RECORD_ID" ] || fail 'returned restore error lost its active intent'
    observe after-error
    must after-readonly zpool get -H -o name,value readonly e2eb e2ec
    must after-mounted zfs get -H -r -t filesystem -o name,value mounted e2eb e2ec
    # Listing importable labels reads the exported replacement without
    # importing it, so the final independent inventory still contains B/C only.
    must target-labels zpool import -d "$(disk A)2"
    observe after-labels
}

stage_1() {
    returned_udev
    returned_fixture
    # Only this case and boot add a PATH shim. Absolute /sbin/zpool access
    # transitions bypass it; the matcher selects Native::import's five argv.
    mkdir -p /run/returned-error-bin
    put /run/returned-error-bin/zpool '#!/bin/sh
exec /bin/sh /acceptance/fault.sh zpool /sbin/zpool "$@"
'
    must import-shim-mode chmod 700 /run/returned-error-bin/zpool
    PATH=/run/returned-error-bin:$PATH
    export PATH
    must import-shim-path sh -c 'command -v zpool'
    arm returned-import zpool '[ "$#" -eq 5 ] && [ "$1" = import ] && [ "$2" = -N ] && [ "$3" = -o ] && [ "$4" = cachefile=none ] && case "$5" in ""|*[!0-9]*) false;; *) true;; esac' error-after
    returned_result
}

stage_2() {
    # Boot1 deliberately left resumable data. Rebuild independent inputs.
    returned_udev
    returned_reset
    returned_fixture
    # Same exact matcher as the existing step-9 power-cut fixture, but return
    # an error before the checkpoint write so Run hands cleanup to the CLI.
    arm returned-checkpoint zfs "/bin/sh /acceptance/restore-cut.sh 9 $ZT_OUT \"\$@\"" error-before
    returned_result
}
