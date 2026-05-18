#!/bin/bash
# Common harness for *.sh scripts. Sourced (not executed).
#
# Caller sets BEFORE sourcing:
#   TEST=<short-name>            # used to derive resource paths + ports
#   EXTRA_DISKS=<n>              # 0 (default) or 1 extra disk for mirror/multipool
#   EXTRA_DISK_SIZE=4G           # size of the extra disk
#   NEED_FACTORY=1               # 1 (default): require factory tar; 0: skip the check
#
# Provides:
#   ZBOOT_BIN, FACTORY_TAR, LIVE_DIR                paths
#   TARGET_QCOW2, EXTRA_QCOW2                       per-test qcow2 paths
#   HTTP_PORT, SSH_PORT_LIVE, SSH_PORT_BE           per-test port allocations
#   LIVE_SSH, LIVE_SCP                              set after boot_live
#   wait_ssh, boot_live, deploy_from_live,          functions
#   power_off_live, boot_be, be_ssh, power_off_be
#
# Cleanup trap is set automatically; pkill catches qemu by test name.

set -euo pipefail

TEST=${TEST:?TEST must be set before sourcing _harness.sh}
EXTRA_DISKS=${EXTRA_DISKS:-0}
EXTRA_DISK_SIZE=${EXTRA_DISK_SIZE:-4G}
NEED_FACTORY=${NEED_FACTORY:-1}
LIVE_RAM=${LIVE_RAM:-4G}

# Hash TEST → port allocations so parallel runs don't collide.
_port_base=$((18000 + $(echo -n "$TEST" | cksum | awk '{print $1}') % 1000))
HTTP_PORT=$_port_base
SSH_PORT_LIVE=$((_port_base + 1))
SSH_PORT_BE=$((_port_base + 2))

# Repo + binary paths derive from the script's location — no
# hardcoded absolute paths.
ZBOOT_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ZBOOT_BIN=${ZBOOT_BIN:-$ZBOOT_REPO/target/release/zboot}
FACTORY_TAR=${FACTORY_TAR:-$HOME/.cache/zboot/factory.tar.zst}

# Debian Live image (vmlinuz / initrd.img / filesystem.squashfs).
# Required by tests that boot a Live env to run `zboot deploy` against
# a fresh disk.  Default points at zboot's own cache (built via
# `zboot live`, which writes the live triplet into pxe/debianlive/);
# override LIVE_DIR to use a custom image.
LIVE_DIR=${LIVE_DIR:-$HOME/.cache/zboot/pxe/debianlive}
for f in debianlive.efi filesystem.squashfs; do
    [ -f "$LIVE_DIR/$f" ] || {
        echo "missing $LIVE_DIR/$f — build the live image first:"
        echo "  zboot live"
        echo "(override the dir with LIVE_DIR=… if you have a custom one)"
        exit 1
    }
done

TARGET_QCOW2=/tmp/zboot-${TEST}-vda.qcow2
EXTRA_QCOW2=/tmp/zboot-${TEST}-vdb.qcow2
OVMF_VARS_LIVE=/tmp/zboot-${TEST}-live-vars.fd
OVMF_VARS_BE=/tmp/zboot-${TEST}-be-vars.fd
SERIAL_LIVE=/tmp/zboot-${TEST}-live-serial.log
HTTP_LOG=/tmp/zboot-${TEST}-http.log
QEMU_PID_FILE=/tmp/zboot-${TEST}-qemu.pid
HTTP_PID_FILE=/tmp/zboot-${TEST}-http.pid

[ "$NEED_FACTORY" = "1" ] && [ ! -f "$FACTORY_TAR" ] && {
    echo "no factory tar at $FACTORY_TAR — run \`zboot factory --no-headers\` first"
    exit 1
}

cleanup() {
    echo "--- cleanup ---"
    [ -f "$QEMU_PID_FILE" ] && kill -TERM "$(cat $QEMU_PID_FILE)" 2>/dev/null || true
    [ -f "$HTTP_PID_FILE" ] && kill -TERM "$(cat $HTTP_PID_FILE)" 2>/dev/null || true
    pkill -9 -f "qemu-system-x86_64.*zboot-${TEST}" 2>/dev/null || true
    pkill -9 -f "python3 -m http.server $HTTP_PORT" 2>/dev/null || true
}
trap cleanup EXIT

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

# Serve $LIVE_DIR via http on $HTTP_PORT (live-boot's `fetch=` URL).
# PID written to $HTTP_PID_FILE so the cleanup trap can kill it.
start_http_server() {
    ( cd "$LIVE_DIR" && python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 ) > "$HTTP_LOG" 2>&1 &
    echo $! > "$HTTP_PID_FILE"
    sleep 1
}


wait_ssh() {
    local port=$1 ; local label=$2 ; local max=${3:-90}
    for i in $(seq 1 $max); do
        sleep 4
        if ssh-keyscan -p $port -T 3 127.0.0.1 2>/dev/null | grep -q ssh-; then
            echo "  [$label] sshd up after $((i*4))s"
            sleep 2
            return 0
        fi
    done
    echo "  [$label] FAIL: sshd never answered"
    return 1
}

# Boot the debianlive image. Sets LIVE_SSH / LIVE_SCP for the caller.
#
# zboot live ships a single UKI (debianlive.efi) — no bare vmlinuz/
# initrd.img alongside, since zboot is UEFI-only and bare files would
# be dead weight in production.  For QEMU's direct-kernel-boot path we
# extract the kernel + initrd from the UKI's PE sections on demand.
boot_live() {
    qemu-img create -f qcow2 "$TARGET_QCOW2" 8G > /dev/null
    [ "$EXTRA_DISKS" -ge 1 ] && qemu-img create -f qcow2 "$EXTRA_QCOW2" "$EXTRA_DISK_SIZE" > /dev/null
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS_LIVE"

    # Extract bare kernel + initrd from the UKI for QEMU's -kernel/-initrd
    # path (cheaper than booting via OVMF + ESP just for tests).
    local extract_dir=/tmp/zboot-${TEST}-uki-extract
    rm -rf "$extract_dir"; mkdir -p "$extract_dir"
    objcopy -O binary --only-section=.linux  "$LIVE_DIR/debianlive.efi" "$extract_dir/vmlinuz"
    objcopy -O binary --only-section=.initrd "$LIVE_DIR/debianlive.efi" "$extract_dir/initrd.img"

    start_http_server

    local args=(
        -machine q35,accel=kvm -cpu host -m "$LIVE_RAM" -smp 4 -nographic
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
        -drive if=pflash,format=raw,file="$OVMF_VARS_LIVE"
        -kernel "$extract_dir/vmlinuz" -initrd "$extract_dir/initrd.img"
        -append "boot=live fetch=http://10.0.2.2:$HTTP_PORT/filesystem.squashfs console=ttyS0,115200 systemd.unit=multi-user.target net.ifnames=0"
        -drive file="$TARGET_QCOW2",if=virtio,format=qcow2,cache=writeback
    )
    [ "$EXTRA_DISKS" -ge 1 ] && args+=( -drive file="$EXTRA_QCOW2",if=virtio,format=qcow2,cache=writeback )
    args+=(
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT_LIVE-:22"
        -device virtio-net,netdev=n0
        -serial "file:$SERIAL_LIVE" -monitor none -no-reboot
    )
    qemu-system-x86_64 "${args[@]}" > "/tmp/zboot-${TEST}-live-qemu.log" 2>&1 &
    echo $! > "$QEMU_PID_FILE"

    wait_ssh $SSH_PORT_LIVE "live" || { tail -40 "$SERIAL_LIVE"; exit 1; }

    LIVE_SSH="sshpass -p live ssh $SSH_OPTS -p $SSH_PORT_LIVE user@127.0.0.1"
    LIVE_SCP="sshpass -p live scp $SSH_OPTS -P $SSH_PORT_LIVE"

    # zboot CLI scp'd in.  Its embedded zboot-boot.efi is what `zboot
    # deploy` writes to the target ESP — no separate EFI scp needed.
    $LIVE_SCP "$ZBOOT_BIN" user@127.0.0.1:/tmp/zboot
    [ "$NEED_FACTORY" = "1" ] && $LIVE_SCP "$FACTORY_TAR" user@127.0.0.1:/tmp/factory.tar.zst
    $LIVE_SSH 'sudo bash -c "echo 134217728 > /sys/module/zfs/parameters/zfs_arc_max"'
}

# Build a tiny test-fixture overlay tar and scp into the live env.
# Lays down a post-install.sh that ssh-keygens host keys, sets root
# password = "zboot", and enables ssh.service.  The factory tar
# ships sshd as a binary only (no host keys, not enabled, no root pw) —
# downstream production overlays would supply those for real hosts;
# tests apply this fixture instead.
_stage_test_overlay() {
    local stage="/tmp/zboot-${TEST}-test-overlay-stage"
    local out="/tmp/zboot-${TEST}-test-overlay.tar.zst"
    rm -rf "$stage"
    mkdir -p "$stage/rootfs/etc/ssh/sshd_config.d"
    # Debian sshd defaults to `PermitRootLogin without-password` (key-only).
    # Tests use `sshpass -p zboot root@…`, so allow password root login.
    # Drop-in keeps the change visible + scoped (no edits to sshd_config).
    cat > "$stage/rootfs/etc/ssh/sshd_config.d/10-zboot-test.conf" <<'SSHD'
PermitRootLogin yes
PasswordAuthentication yes
SSHD
    cat > "$stage/post-install.sh" <<'POST'
#!/bin/sh
# zboot test-overlay finalizer (runs in chroot via `zboot overlay`).
set -e
ssh-keygen -A
echo root:zboot | chpasswd
systemctl enable ssh
POST
    chmod 755 "$stage/post-install.sh"
    tar --xattrs --xattrs-include='*' --acls --zstd -cf "$out" -C "$stage" .
    rm -rf "$stage"
    echo "$out"
}

# boot_live + run zboot deploy from the factory tar + apply the test
# overlay (ssh fixtures) + inject the latest zboot binary into the
# deployed BE. Leaves the live VM running so the caller can do extra
# setup (e.g. create a second pool); the caller must invoke
# power_off_live when ready.
deploy_from_live() {
    boot_live

    set +e
    $LIVE_SSH "sudo ZBOOT_DEPLOY_CONFIRM_DISK=vda \
            /tmp/zboot deploy --target /dev/vda --hostname zb-test \
            --source 'tar:///tmp/factory.tar.zst' \
            --cmdline 'console=ttyS0,115200 quiet'"
    local rc=$?
    set -e
    [ "$rc" -eq 0 ] || { echo "deploy failed"; exit 1; }

    echo "--- apply test overlay (ssh fixtures: keys + root pw + enable) ---"
    local overlay_tar
    overlay_tar=$(_stage_test_overlay)
    $LIVE_SCP "$overlay_tar" user@127.0.0.1:/tmp/test-overlay.tar.zst
    $LIVE_SSH 'sudo /tmp/zboot overlay /tmp/test-overlay.tar.zst'
    rm -f "$overlay_tar"

    echo "--- inject latest zboot binary into deployed BE ---"
    $LIVE_SSH 'sudo mkdir -p /mnt/be && sudo mount -t zfs -o zfsutil rpool/ROOT/be1 /mnt/be && sudo cp /tmp/zboot /mnt/be/usr/local/sbin/zboot && sudo umount /mnt/be && sudo zpool export rpool'
}

power_off_live() {
    $LIVE_SSH 'sudo poweroff' 2>/dev/null || true
    sleep 3
    pkill -TERM -f "qemu-system-x86_64.*zboot-${TEST}-live-vars.fd" 2>/dev/null || true
    sleep 2
}

# Catch silent regressions where zboot-boot's discovery returns nothing
# and the menu falls back to the dev-only synthetic forest.  The fake
# payload reuses the same BE names as the deployed BE, so a downstream
# `bootfs == rpool/ROOT/be1` check would still pass — the fake-data
# banner is the only reliable tell that the prompt was reached with
# real ZFS state.  Called by both boot_be variants after sshd is up.
_assert_no_fake_data() {
    local label=$1 cycle_log=$2
    if grep -q '\[fake-data mode' "$cycle_log"; then
        echo "FAIL: [$label] zboot-boot fell back to fake-data — discovery returned no root-role pool"
        grep -nE 'fake-data|discovery|imported pools|preinit|zpool|udev' "$cycle_log" | head -20
        exit 1
    fi
}

# Boot the deployed BE off TARGET_QCOW2. Caller passes a cycle label.
boot_be() {
    local label=$1 ; local cycle_log=/tmp/zboot-${TEST}-cycle-${label}.log
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS_BE"
    local args=(
        -machine q35,accel=kvm -cpu host -m 4G -smp 4 -nographic
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
        -drive if=pflash,format=raw,file="$OVMF_VARS_BE"
        -drive file="$TARGET_QCOW2",if=virtio,format=qcow2,cache=writeback
    )
    [ "$EXTRA_DISKS" -ge 1 ] && args+=( -drive file="$EXTRA_QCOW2",if=virtio,format=qcow2,cache=writeback )
    args+=(
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT_BE-:22"
        -device virtio-net,netdev=n0
        -serial "file:$cycle_log" -monitor none -no-reboot
    )
    qemu-system-x86_64 "${args[@]}" > "/tmp/zboot-${TEST}-cycle-${label}-qemu.log" 2>&1 &
    echo $! > "$QEMU_PID_FILE"
    echo "  [$label] qemu pid $(cat $QEMU_PID_FILE), serial → $cycle_log"
    wait_ssh $SSH_PORT_BE "${label}-be" 60 || { tail -40 "$cycle_log"; exit 1; }
    _assert_no_fake_data "$label" "$cycle_log"
}

# Like boot_be, but UEFI-PXE-loads zboot-boot.efi from a local TFTP root
# instead of running the disk-resident copy off the ESP.  Disk is still
# attached (zboot-boot's preinit must import the rpool from it), but the
# kernel + initrd come from TFTP — exercising the path used by recovery
# / netboot installs.  Caller is responsible for ensuring the disk has
# no UEFI auto-discoverable boot option (typically by rm'ing
# EFI/BOOT/BOOTX64.EFI from the ESP before power_off_live), otherwise
# OVMF may fall through to the disk-resident copy and silently mask a
# PXE-mode regression.
boot_be_pxe() {
    local label=$1 ; local cycle_log=/tmp/zboot-${TEST}-cycle-${label}.log
    local tftp_root=/tmp/zboot-${TEST}-tftp
    local boot_efi="$ZBOOT_REPO/boot/out/zboot-boot.efi"
    [ -f "$boot_efi" ] || { echo "missing $boot_efi — run \`bash boot/build.sh\`"; exit 1; }
    rm -rf "$tftp_root" ; mkdir -p "$tftp_root"
    cp "$boot_efi" "$tftp_root/"

    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS_BE"
    local args=(
        -machine q35,accel=kvm -cpu host -m 4G -smp 4 -nographic
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
        -drive if=pflash,format=raw,file="$OVMF_VARS_BE"
        -drive file="$TARGET_QCOW2",if=virtio,format=qcow2,cache=writeback
        -netdev "user,id=n0,tftp=$tftp_root,bootfile=zboot-boot.efi,hostfwd=tcp:127.0.0.1:$SSH_PORT_BE-:22"
        -device virtio-net,netdev=n0,bootindex=1
        -serial "file:$cycle_log" -monitor none -no-reboot
    )
    qemu-system-x86_64 "${args[@]}" > "/tmp/zboot-${TEST}-cycle-${label}-qemu.log" 2>&1 &
    echo $! > "$QEMU_PID_FILE"
    echo "  [$label/pxe] qemu pid $(cat $QEMU_PID_FILE), serial → $cycle_log"
    # PXE adds DHCP discover + TFTP transfer (~25M for the UKI) before
    # the kernel even starts — give it more headroom than disk boot.
    wait_ssh $SSH_PORT_BE "${label}-be-pxe" 120 || { tail -60 "$cycle_log"; exit 1; }
    _assert_no_fake_data "$label" "$cycle_log"
}

be_ssh() {
    sshpass -p zboot ssh $SSH_OPTS -p $SSH_PORT_BE root@127.0.0.1 "$@"
}

# Mount a sibling BE read-only inside the currently-booted BE, cat one
# file from it, unmount.  Single-shot read.  Avoids the inline mount+
# cat+umount pattern (which can leak the umount on a failed cat).
read_be_file() {
    local dataset=$1 path=$2
    be_ssh "set -e
m=\$(mktemp -d)
trap 'sudo umount \$m 2>/dev/null; rmdir \$m' EXIT
sudo mount -t zfs -o zfsutil,ro $dataset \$m
sudo cat \$m$path
"
}

power_off_be() {
    be_ssh 'poweroff' 2>/dev/null || true
    if [ -f "$QEMU_PID_FILE" ]; then
        local pid=$(cat $QEMU_PID_FILE)
        for i in $(seq 1 30); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$pid" 2>/dev/null || true
    fi
    sleep 2
}

# Quick assertion helper: $1 = label, $2 = expected, $3 = got.
expect_eq() {
    local label=$1 expected=$2 got=$3
    [ "$got" = "$expected" ] || { echo "FAIL: $label expected=$expected got=$got"; exit 1; }
    echo "  ✓ $label = $got"
}
