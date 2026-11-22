# Shared setup stage of the GUIDED-* cases (sourced by their case scripts
# after lib.sh). Runs in a direct-kernel boot:
# the session's kernel and zboot/zsnap, its UKI at
# /fixtures/e2e-esp-artifacts/zboot-recovery.efi and a factory root tar at
# /fixtures/e2e-factory.tar.zst.
#
# Disks: B = pool e2eb (journal, unrelated data, the product mirror
# e2eb/ROOT/be1); D = empty pool e2ed; A = a factory deploy with hostid
# 0174627a plus a root token, the session's UKI as its shipped loader (what
# `restore` installs on A), a systemd boot probe, and three data leaves
# outside the boot environment, which is one dataset with no children: a
# child, a disabled dataset and scratch. After the mirror, A's child and
# scratch are mutated; the restore takes the BE from B and keeps all three
# leaves of A with their new content.

HOSTID=0174627a
ROOT_A=e2ea/ROOT/be1 ROOT_B=e2eb/ROOT/be1 CHILD_A=e2ea/guided-child SCRATCH_A=e2ea/scratch
DISABLED_A=e2ea/guided-disabled
JOURNAL=/mnt/zfs-e2e/guided-restore-journal UNRELATED=/mnt/zfs-e2e/unrelated-b
ROOT_MOUNT=/mnt/zfs-e2e/guided-a-root CHILD_MOUNT=/mnt/zfs-e2e/guided-a-child
SCRATCH_MOUNT=/mnt/zfs-e2e/guided-a-scratch DISABLED_MOUNT=/mnt/zfs-e2e/guided-a-disabled
PROBE=usr/local/libexec/zfs-e2e-guided-a-boot UNIT=zfs-e2e-guided-a-boot.service

guided_pool() { # POOL LABEL
    dev=$(disk "$2")
    must "part-$1" sgdisk -n 1:0:0 -t 1:BF01 "$dev"
    must "probe-$1" partprobe "$dev"
    mdev -s
    must "create-$1" zpool create -f -o cachefile=none -O mountpoint=none "$1" "${dev}1"
}

# guided_mount NAME DATASET PATH: mount DATASET only after proving its native
# mountpoint is PATH, so no write can land in a plain directory of that name.
guided_mount() {
    must "$1-before" zfs get -H -o value mountpoint,mounted "$2"
    { read -r mp; read -r mounted; } < "$ZT_LAST.out"
    [ "$mp" = "$3" ] || fail "$2 mountpoint is $mp, not $3"
    case $mounted in
        yes) must "$1-unmount" zfs unmount "$2" ;;
        no) ;;
        *) fail "$2 mounted is $mounted" ;;
    esac
    must "$1-mount" zfs mount "$2"
    must "$1-after" zfs get -H -o value mounted "$2"
    [ "$(cat "$ZT_LAST.out")" = yes ] || fail "$2 did not mount at $3"
}

guided_unmount() { # NAME DATASET: unmount if mounted; record the result
    must "$1-mounted" zfs get -H -o value mounted "$2"
    if [ "$(cat "$ZT_LAST.out")" = yes ]; then
        must "$1-unmount" zfs unmount "$2"
    fi
    must "$1-unmounted" zfs get -H -o value mounted "$2"
}

# Only GUIDED-RESTORE-EFI-NATIVE opts in. This runs from the installed
# systemd probe on the restored, standalone A root. The second fork has a
# process cut after real native capture returns; it is not a QEMU power cut.
guided_fork_probe() {
    cat > "$ROOT_MOUNT/usr/local/libexec/zfs-e2e-guided-fork" << 'FORK_EOF'
#!/bin/sh
set -eu
p() { printf 'ZFS_E2E_PROBE %s=%s\n' "$1" "$2"; }
flat() { tr '\n' ';'; }
root=e2ea/ROOT/be1
[ "$(findmnt -rn -o SOURCE --target /)" = "$root" ]
[ "$(cat /etc/zfs-e2e-fork-probe)" = GUIDED-RESTORE-EFI-NATIVE ]
zboot=$(command -v zboot)
real_zfs=$(command -v zfs)
p fork-binary "$zboot"
p fork-running-root "$(findmnt -rn -o SOURCE --target /)"
p fork-pool-guid "$(zpool get -Hp -o value guid e2ea)"
p fork-source-ids "$(zfs get -Hpr -t filesystem -o name,property,value guid,createtxg,objsetid "$root" | flat)"

# The selected running BE is already mounted read-write. Status must inspect
# its kernel files through a private read-only view without changing that
# mount, any native identity/placement, or the booted system's identity.
status_facts() { # PREFIX
    prefix=$1
    p "$prefix-mount" "$(awk '$5 == "/" { print }' /proc/self/mountinfo | flat)"
    p "$prefix-native" "$(zfs get -Hp -o name,property,value,source \
        guid,createtxg,objsetid,readonly,canmount,mountpoint,zboot:cmdline "$root" | flat)"
    p "$prefix-pool" "$(zpool get -Hp -o name,property,value,source guid,bootfs,readonly e2ea | flat)"
    p "$prefix-boot" "$(sha256sum /etc/hostid /proc/cmdline | flat)"
}
status_facts status-before
p status-running-version "$(uname -r)"
"$zboot" status "$root" --json > /run/zfs-e2e-status-running.json
p status-running-json "$(tr '\n' ' ' < /run/zfs-e2e-status-running.json)"
status_facts status-after
p status-probe complete

# Exercise the same read-only observation while A's proven ESP is mounted RW.
esp=/dev/vda1
[ "$(cat /sys/class/block/vda/serial)" = ZFS-E2E-A ]
[ "$(lsblk -dnro PKNAME "$esp")" = vda ]
[ "$(lsblk -dnro PARTTYPE "$esp")" = c12a7328-f81f-11d2-ba4b-00a0c93ec93b ]
[ "$(lsblk -dnro FSTYPE "$esp")" = vfat ]
esp_partuuid=$(lsblk -dnro PARTUUID "$esp")
[ -n "$esp_partuuid" ]
p status-esp-device "$esp"
p status-esp-partuuid "$esp_partuuid"
p status-esp-device-number "$(lsblk -dnro MAJ:MIN "$esp")"
esp_view=/run/zfs-e2e-status-esp
mkdir -m 700 "$esp_view"
trap 'umount "$esp_view" 2>/dev/null || :; rmdir "$esp_view" 2>/dev/null || :' 0
mount -t vfat -o rw,nosuid,nodev,noexec,uid=0,gid=0,umask=0077,utf8=1 "$esp" "$esp_view"
esp_facts() { # PREFIX
    prefix=$1
    p "$prefix-mount" "$(awk -v path="$esp_view" '$5 == path { print }' /proc/self/mountinfo | flat)"
    p "$prefix-native" "$(lsblk -bdnro PATH,MAJ:MIN,SIZE,PARTUUID,UUID,FSTYPE,PARTTYPE,RO "$esp" | flat)"
    p "$prefix-files" "$(sha256sum "$esp_view/EFI/zboot/zboot.efi" "$esp_view/EFI/BOOT/BOOTX64.EFI" | flat)"
}
esp_facts status-esp-before
"$zboot" status --devices --json > /run/zfs-e2e-status-devices.json
p status-devices-json "$(tr '\n' ' ' < /run/zfs-e2e-status-devices.json)"
esp_facts status-esp-after
umount "$esp_view"
rmdir "$esp_view"
trap - 0
p status-esp-probe complete

# Each fact is read independently from native ZFS. JSON is retained verbatim
# on one serial line for the host oracle; shell extraction is only routing.
facts() { # PREFIX DESTINATION LABEL
    prefix=$1 destination=$2 label=$3
    p "$prefix-points" "$(zfs list -Hpr -t snapshot -o name,guid,createtxg "$root" |
        awk -v suffix="@$label" 'substr($1,length($1)-length(suffix)+1)==suffix' | flat)"
    p "$prefix-point-ids" "$(zfs get -Hp -o name,property,value guid,createtxg,objsetid \
        "$root@$label" | flat)"
    p "$prefix-markers" "$(zfs get -Hp -o name,value,source zboot:capture \
        "$root@$label" | flat)"
    p "$prefix-holds" "$(zfs holds -Hp "$root@$label" | flat)"
    p "$prefix-clones" "$(zfs get -Hpr -t filesystem -o name,property,value,source \
        origin,readonly,canmount,mounted,mountpoint "$destination" | flat)"
    p "$prefix-operation" "$(zfs get -H -o value zboot:operation e2ea)"
    view=/run/zfs-e2e-fork-view
    mkdir -p "$view/root"
    mount -t zfs -o ro,zfsutil "$destination" "$view/root"
    p "$prefix-root-token" "$(cat "$view/root/guided-base-token")"
    umount "$view/root"
}

# The one positional argument is deliberately a sibling shorthand. The
# installed CLI must discover the real running BE and resolve it to ROOT/try.
"$zboot" fork try --json > /run/zfs-e2e-fork-clean.json
p fork-clean-json "$(tr '\n' ' ' < /run/zfs-e2e-fork-clean.json)"
point=$(sed -n 's/.*"source_snapshot": "\([^"]*\)".*/\1/p' /run/zfs-e2e-fork-clean.json)
[ -n "$point" ]
facts fork-clean e2ea/ROOT/try "${point#*@}"

# Avoid a deliberate generated-label collision with the first fork.
sleep 2
# Debian's initramfs carries /run into the installed OS with noexec. Keep
# control data there and execute the private wrapper from the writable BE.
wrapper=/usr/local/libexec/zfs-e2e-fork-capture-cut
control=/run/zfs-e2e-fork-capture-cut
mkdir -m 700 "$wrapper" "$control"
printf '%s\n' "$real_zfs" > "$control/real-zfs"
cat > "$wrapper/zfs" << 'CUT_EOF'
#!/bin/sh
set -eu
control=/run/zfs-e2e-fork-capture-cut
real_zfs=$(cat "$control/real-zfs")
if [ "${1-}" = --version ]; then
    printf '%s\n' "$0" > "$control/preflight-executable"
fi
"$real_zfs" "$@"
if [ "${1-}" = snapshot ] && [ "${2-}" = -o ]; then
    case ${3-} in zboot:capture=*)
        # The actual successful atomic snapshot is durable, but the child
        # never returns to zboot's wait/verify/checkpoint path.
        zpool sync e2ea
        printf '%s\n' "$@" > "$control/captured-argv"
        kill -KILL "$PPID"
        ;;
    esac
fi
CUT_EOF
chmod 700 "$wrapper/zfs"
p fork-wrapper-path "$wrapper/zfs"
p fork-wrapper-stat "$(stat -c %u:%g:%a:%d:%i "$wrapper/zfs")"
p fork-wrapper-sha256 "$(sha256sum "$wrapper/zfs")"
p fork-wrapper-mount "$(findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS --target "$wrapper/zfs")"
p fork-control-mount "$(findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS --target "$control")"
p fork-real-zfs "$real_zfs"
# Invoke the absolute path directly: `sh wrapper` would hide a noexec error.
set +e
"$wrapper/zfs" --version > "$control/preflight.out" 2> "$control/preflight.err"
preflight_rc=$?
set -e
p fork-wrapper-preflight-rc "$preflight_rc"
p fork-wrapper-preflight-output "$(flat < "$control/preflight.out")"
p fork-wrapper-preflight-error "$(flat < "$control/preflight.err")"
p fork-wrapper-entered "$(cat "$control/preflight-executable" 2>/dev/null || :)"
[ "$preflight_rc" -eq 0 ]
[ "$(cat "$control/preflight-executable")" = "$wrapper/zfs" ]
set +e
PATH="$wrapper:$PATH" "$zboot" fork try-cut --json -v > /run/zfs-e2e-fork-cut.json 2> /run/zfs-e2e-fork-cut.err
rc=$?
set -e
p fork-cut-rc "$rc"
p fork-cut-stderr "$(flat < /run/zfs-e2e-fork-cut.err)"
[ -f "$control/captured-argv" ]
p fork-cut-argv "$(cat "$control/captured-argv" | flat)"
record=$(zfs get -H -o value zboot:operation e2ea)
p fork-cut-record "$record"
id=$(printf '%s\n' "$record" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
label=$(printf '%s\n' "$record" | sed -n 's/.*"snapshot":"\([^"]*\)".*/\1/p')
[ -n "$id" ] && [ -n "$label" ]
p fork-cut-points "$(zfs list -Hpr -t snapshot -o name,guid,createtxg "$root" |
    awk -v suffix="@$label" 'substr($1,length($1)-length(suffix)+1)==suffix' | flat)"
p fork-cut-point-ids "$(zfs get -Hp -o name,property,value guid,createtxg,objsetid \
    "$root@$label" | flat)"
p fork-cut-markers "$(zfs get -Hp -o name,value,source zboot:capture \
    "$root@$label" | flat)"
p fork-cut-holds "$(zfs holds -Hp "$root@$label" | flat)"
p fork-cut-dest "$(zfs list -H -o name e2ea/ROOT/try-cut 2>/dev/null || echo absent)"
# The wrapper is scoped to the one preceding command. Resume uses the real
# installed executable and ordinary PATH, preserving captured native GUIDs.
"$zboot" resume "$id" --json > /run/zfs-e2e-fork-resume.json
p fork-resume-json "$(tr '\n' ' ' < /run/zfs-e2e-fork-resume.json)"
facts fork-resume e2ea/ROOT/try-cut "$label"
p fork-source-ids-after "$(zfs get -Hpr -t filesystem -o name,property,value guid,createtxg,objsetid "$root" | flat)"
p fork-probe complete
FORK_EOF
    must fork-probe-chmod chmod 755 "$ROOT_MOUNT/usr/local/libexec/zfs-e2e-guided-fork"
    printf '%s\n' GUIDED-RESTORE-EFI-NATIVE > "$ROOT_MOUNT/etc/zfs-e2e-fork-probe"
}

# guided_probe MODE: a systemd unit in A's root that reports, on ttyS0, the
# booted system's facts as `ZFS_E2E_PROBE key=value` lines (the host checks
# each), then `ZFS_E2E_GUIDED_A_BOOT_OK`. MODE poweroff then powers the OS
# off cleanly (the host waits for QEMU to exit); MODE stay leaves it running
# for a host power cut.
guided_probe() {
    must probe-dirs mkdir -p "$ROOT_MOUNT/usr/local/libexec" \
        "$ROOT_MOUNT/etc/systemd/system/multi-user.target.wants"
    cat > "$ROOT_MOUNT/$PROBE" << 'EOF'
#!/bin/sh
set -eu
trap 'status=$?; [ "$status" -eq 0 ] || printf "\nZFS_E2E_GUIDED_A_BOOT_FAILED status=%s\n" "$status"' 0
p() { printf 'ZFS_E2E_PROBE %s=%s\n' "$1" "$2"; }
src() { findmnt -rn -o SOURCE --target "$1" || echo none; }
labels() { # POOL DEVICE: label counts of a pool's partition
    zdb -lll "$2" > "/run/zfs-e2e-$1-labels" || :
    l=/run/zfs-e2e-$1-labels
    for n in 0 1 2 3; do printf '%s ' "$(grep -Ec "^LABEL $n[[:space:]]*$" "$l" || :)"; done
}
p pid1 "$(cat /proc/1/comm)"
p efi "$(if [ -d /sys/firmware/efi ]; then echo yes; else echo no; fi)"
p root-arg "$(tr ' ' '\n' < /proc/cmdline | grep '^root=' | tr '\n' ' ')"
p root "$(src /)"
p child "$(src /mnt/zfs-e2e/guided-a-child)"
p scratch "$(src /mnt/zfs-e2e/guided-a-scratch)"
# Observe the actual systemd boot; no unit or native role is repaired here.
p zfs-mount-load-state "$(systemctl show zfs-mount.service --property=LoadState --value)"
p zfs-mount-fragment "$(systemctl show zfs-mount.service --property=FragmentPath --value)"
p zfs-mount-unit-file-state "$(systemctl show zfs-mount.service --property=UnitFileState --value)"
# The old cache-owner factory disabled this enabled hook (history 73da731).
# Stock Debian supplies a symlink to the vendor ZEDlet, not a local replacement.
zed_hook=/etc/zfs/zed.d/history_event-zfs-list-cacher.sh
zed_vendor=/usr/lib/zfs-linux/zed.d/history_event-zfs-list-cacher.sh
p zed-cache-hook "$(if [ ! -e "$zed_vendor" ] && [ ! -e "$zed_hook" ] && [ ! -L "$zed_hook" ]; then
    echo not-installed
elif [ -L "$zed_hook" ] && [ -f "$zed_vendor" ] &&
    [ "$(readlink -f "$zed_hook")" = "$zed_vendor" ]; then echo vendor
else echo override-or-missing; fi)"
p root-canmount "$(zfs get -H -o value canmount e2ea/ROOT/be1)"
p child-canmount "$(zfs get -H -o value canmount e2ea/guided-child)"
p scratch-canmount "$(zfs get -H -o value canmount e2ea/scratch)"
p disabled-canmount "$(zfs get -H -o value canmount e2ea/guided-disabled)"
p disabled-mounted "$(zfs get -H -o value mounted e2ea/guided-disabled)"
p disabled-mountpoint "$(zfs get -H -o value mountpoint e2ea/guided-disabled)"
p base-token "$(cat /guided-base-token)"
p child-token "$(cat /mnt/zfs-e2e/guided-a-child/guided-child-token)"
p scratch-token "$(cat /mnt/zfs-e2e/guided-a-scratch/guided-scratch-token)"
p hostid "$(hostid)"
p e2ea-readonly "$(zpool get -H -o value readonly e2ea)"
# The marker is carried through the real mirror/restore only for this case.
if [ -f /etc/zfs-e2e-fork-probe ] &&
    [ "$(cat /etc/zfs-e2e-fork-probe)" = GUIDED-RESTORE-EFI-NATIVE ]; then
    /usr/local/libexec/zfs-e2e-guided-fork
fi
# B has cachefile=none, so the installed boot may leave it exported. Open it
# writable without mounting datasets, so shutdown's export of B is observable.
p e2eb-imported "$(zpool list -H -o name,readonly e2eb 2>/dev/null | tr '\t' ' ' || echo absent)"
if zpool list -H -o name e2eb > /dev/null 2>&1 && [ "$(zpool get -H -o value readonly e2eb)" = on ]; then
    zpool export e2eb
fi
if ! zpool list -H -o name e2eb > /dev/null 2>&1; then
    zpool import -N -o readonly=off -o cachefile=none -d /dev e2eb
fi
p e2eb-readonly "$(zpool get -H -o value readonly e2eb)"
zpool sync e2eb
p b-labels "$(labels e2eb /dev/vdb1)"
l=/run/zfs-e2e-e2eb-labels
p b-state0 "$(grep -Fxc '    state: 0' "$l" || :)"
p b-name "$(grep -Fxc "    name: 'e2eb'" "$l" || :)"
p b-guid "$(grep -Fxc "    pool_guid: $(zpool get -H -p -o value guid e2eb)" "$l" || :)"
p serials "$(for f in /sys/class/block/*/serial; do echo "$(cat "$f" 2>/dev/null)"; done | sort | tr '\n' ' ')"
printf '\nZFS_E2E_GUIDED_A_BOOT_OK\n'
EOF
    if [ "$1" = poweroff ]; then
        echo 'systemctl --no-block poweroff' >> "$ROOT_MOUNT/$PROBE"
    fi
    if [ "${case-}" = GUIDED-RESTORE-EFI-NATIVE ]; then
        guided_fork_probe
    fi
    must probe-chmod chmod 755 "$ROOT_MOUNT/$PROBE"
    printf '%s\n' '[Unit]' 'Description=Disposable guided restore A boot probe' 'After=local-fs.target' \
        '[Service]' 'Type=oneshot' "ExecStart=/$PROBE" 'StandardInput=null' 'StandardOutput=tty' \
        'StandardError=tty' 'TTYPath=/dev/ttyS0' 'TimeoutStartSec=300' \
        '[Install]' 'WantedBy=multi-user.target' > "$ROOT_MOUNT/etc/systemd/system/$UNIT"
    must probe-enable ln -s "/etc/systemd/system/$UNIT" \
        "$ROOT_MOUNT/etc/systemd/system/multi-user.target.wants/$UNIT"
    must probe-files cat "$ROOT_MOUNT/$PROBE" "$ROOT_MOUNT/etc/systemd/system/$UNIT"
}

deploy_a() { # NAME [ARG...]
    name=$1; shift
    step "$name" zboot deploy "$a" --efi /fixtures/e2e-esp-artifacts/zboot-recovery.efi --tar /fixtures/e2e-factory.tar.zst \
        --be be1 --pool e2ea --esp 512M --json --hostid "$HOSTID" "$@"
}

# guided_setup MODE: the whole fixture; MODE is the boot probe's (see above).
guided_setup() {
    must versions sh -c 'uname -a; zfs version; hostid'
    must serials sh -c 'for f in /sys/block/vd*/serial; do echo "$(cat "$f")"; done'
    a=$(disk A)
    guided_pool e2eb B
    guided_pool e2ed D
    must journal zfs create -o "mountpoint=$JOURNAL" e2eb/guided-restore-journal
    must journal-mode chmod 700 "$JOURNAL"
    must unrelated zfs create -o "mountpoint=$UNRELATED" e2eb/unrelated
    must unrelated-token sh -c 'printf %s ZFS-E2E-GUIDED-UNRELATED-B > "$1/token"' token "$UNRELATED"

    must wipe-before zboot wipe "$a" --dry-run --json
    deploy_a deploy-preview --dry-run || fail 'deploy preview failed'
    token=$(json .token) || fail 'deploy preview has no token'
    deploy_a deploy-apply --confirm "$token" || fail 'confirmed deploy failed'

    # Reopen A only after the deploy exported it; add the fixture data.
    must import-a zpool import -f -N -o readonly=off -d /dev e2ea
    must root-noauto zfs set canmount=noauto "$ROOT_A"
    must root-mountpoint zfs set "mountpoint=$ROOT_MOUNT" "$ROOT_A"
    guided_mount root "$ROOT_A" "$ROOT_MOUNT"
    must base-token sh -c 'printf %s ZFS-E2E-GUIDED-BASE > "$1/guided-base-token"' token "$ROOT_MOUNT"
    # The loader the BE ships, as the zboot package installs it, is the one
    # this session boots, whatever the factory tar carried there.
    must loader-dir mkdir -p "$ROOT_MOUNT/usr/lib/zboot"
    must loader-install cp /fixtures/e2e-esp-artifacts/zboot-recovery.efi "$ROOT_MOUNT/usr/lib/zboot/zboot.efi"
    must loader-sha256 sha256sum "$ROOT_MOUNT/usr/lib/zboot/zboot.efi"
    guided_probe "$1"
    # The child and the disabled dataset are data leaves outside the BE,
    # which is one dataset. The mount directories exist in the root, so a
    # regression that mounts the disabled leaf is observable.
    must child-dir mkdir -p "$ROOT_MOUNT$CHILD_MOUNT" "$ROOT_MOUNT$DISABLED_MOUNT"
    must disabled zfs create -u -o readonly=off -o canmount=off \
        -o "mountpoint=$DISABLED_MOUNT" "$DISABLED_A"
    must disabled-role zfs get -H -o value canmount,mounted "$DISABLED_A"
    # The child mounts at boot through zfs-mount, as any data leaf does.
    must child zfs create -u -o readonly=off -o canmount=on \
        -o "mountpoint=$CHILD_MOUNT" "$CHILD_A"
    guided_mount child "$CHILD_A" "$CHILD_MOUNT"
    must child-role zfs get -H -o value canmount "$CHILD_A"
    must child-token sh -c 'printf %s ZFS-E2E-GUIDED-MIRROR-CHILD > "$1/guided-child-token"' token "$CHILD_MOUNT"
    must scratch zfs create -o readonly=off -o canmount=on -o "mountpoint=$SCRATCH_MOUNT" "$SCRATCH_A"
    guided_mount scratch "$SCRATCH_A" "$SCRATCH_MOUNT"
    must scratch-token sh -c 'printf %s ZFS-E2E-GUIDED-MIRROR-SCRATCH > "$1/guided-scratch-token"' token "$SCRATCH_MOUNT"

    # Publish the BE with its normal root placement, then snapshot it.
    guided_unmount root-publish "$ROOT_A"
    must root-slash zfs set mountpoint=/ "$ROOT_A"
    must snapshot-root zfs snapshot "$ROOT_A@guided"
    must snapshot-scratch zfs snapshot "$SCRATCH_A@guided" "$CHILD_A@guided" "$DISABLED_A@guided"
    must sync-a zpool sync e2ea

    # The mirror is the product transfer command.
    must b-root zfs create -o canmount=off -o mountpoint=none e2eb/ROOT
    must mirror zboot sync "$ROOT_A" "$ROOT_B" --json
    must mirror-snapshots zfs list -H -p -t snapshot -o name,guid -r "$ROOT_B"
    must mirror-mount sh -e -c 'mkdir -p "$1"
        mount -t zfs -o ro,zfsutil e2eb/ROOT/be1 "$1"' m /mnt/zfs-e2e/guided-b-root
    step mirror-base-token cat /mnt/zfs-e2e/guided-b-root/guided-base-token
    must mirror-umount umount /mnt/zfs-e2e/guided-b-root

    # Dirty A's child and scratch: the restore keeps both with their new
    # content.
    guided_mount child-again "$CHILD_A" "$CHILD_MOUNT"
    guided_mount scratch-again "$SCRATCH_A" "$SCRATCH_MOUNT"
    must mutate-child sh -c 'printf %s ZFS-E2E-GUIDED-MUTATED-CHILD > "$1/guided-child-token"' token "$CHILD_MOUNT"
    must mutate-scratch sh -c 'printf %s ZFS-E2E-GUIDED-MUTATED-SCRATCH > "$1/guided-scratch-token"' token "$SCRATCH_MOUNT"
    must sync-a-again zpool sync e2ea
    observe setup

    guided_unmount child-final "$CHILD_A"
    guided_unmount root-final "$ROOT_A"
    guided_unmount scratch-final "$SCRATCH_A"
    guided_unmount unrelated-final e2eb/unrelated
    guided_unmount journal-final e2eb/guided-restore-journal
    for pool in e2ea e2eb e2ed; do
        must "export-$pool" zpool export "$pool"
    done
}
