#!/bin/bash
# factory-in-vm.sh — build the factory BE tar inside a self-contained
# Debian VM (no custom live image, no debootstrap-on-host requirement).
# Calls `zboot factory` with no extra packages → stock factory tar (zboot's
# own e2e fixture).  Callers that want the production tar pass
# EXTRA_PACKAGES through to the inner invocation.
#
# Pipeline:
#   1. Download Debian generic cloud image (cached at $CACHE_DIR).
#   2. qemu-img backing-file snapshot for this run (cloud image stays clean).
#   3. Build a NoCloud cloud-init seed ISO with:
#        - operator's ssh pubkey (no sshpass needed)
#        - apt install debootstrap zstd
#   4. Boot QEMU with backing snapshot + seed ISO (SeaBIOS, no OVMF needed).
#   5. Wait for cloud-init `package_update + packages` to finish.
#   6. SCP the host's zboot CLI in.
#   7. Run `zboot factory` inside (= debootstrap + chroot).
#   8. SCP the resulting tar back to host.
#
# Standalone operator-facing wrapper.  Use this when you can't (or
# don't want to) run `sudo zboot factory` directly on the host —
# cross-build, no debootstrap installed, no root, hermetic CI, etc.
# Not embedded into the zboot CLI; run as: `bash scripts/internal/factory-in-vm.sh`.
#
# Env (defaults):
#   FACTORY_TAR       output path                (default ~/.cache/zboot/factory.tar.zst)
#   ZBOOT_BIN         CLI binary to run inside   (default <repo>/target/release/zboot)
#   CACHE_DIR         where to cache cloud image (default ~/.cache/zboot)
#   DEBIAN_VER        debian release             (default trixie)
#   SSH_PUBKEY        ssh pubkey for cloud-init  (default ~/.ssh/id_ed25519.pub or id_rsa.pub)

set -euo pipefail

ZBOOT_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
FACTORY_TAR=${FACTORY_TAR:-$HOME/.cache/zboot/factory.tar.zst}
mkdir -p "$(dirname "$FACTORY_TAR")"
ZBOOT_BIN=${ZBOOT_BIN:-$ZBOOT_REPO/target/release/zboot}
CACHE_DIR=${CACHE_DIR:-$HOME/.cache/zboot}
DEBIAN_VER=${DEBIAN_VER:-trixie}

[ -f "$ZBOOT_BIN" ] || { echo "missing ZBOOT_BIN=$ZBOOT_BIN" >&2; exit 1; }

# Pick an SSH pubkey (no sshpass — cloud-init injects it for root login).
if [ -n "${SSH_PUBKEY:-}" ]; then
    [ -f "$SSH_PUBKEY" ] || { echo "SSH_PUBKEY=$SSH_PUBKEY not found" >&2; exit 1; }
elif [ -f "$HOME/.ssh/id_ed25519.pub" ]; then
    SSH_PUBKEY="$HOME/.ssh/id_ed25519.pub"
elif [ -f "$HOME/.ssh/id_rsa.pub" ]; then
    SSH_PUBKEY="$HOME/.ssh/id_rsa.pub"
else
    echo "no ssh pubkey at ~/.ssh/id_ed25519.pub or id_rsa.pub" >&2
    echo "  generate one: ssh-keygen -t ed25519" >&2
    exit 1
fi
PUBKEY_LINE=$(cat "$SSH_PUBKEY")

mkdir -p "$CACHE_DIR"

DEBIAN_IMG_NAME="debian-13-genericcloud-amd64.qcow2"
DEBIAN_IMG="$CACHE_DIR/$DEBIAN_IMG_NAME"
DEBIAN_IMG_URL="https://cloud.debian.org/images/cloud/${DEBIAN_VER}/latest/${DEBIAN_IMG_NAME}"

TARGET_QCOW2=/tmp/zboot-factory-vm.qcow2
SEED_ISO=/tmp/zboot-factory-seed.iso
SERIAL_LOG=/tmp/zboot-factory-vm-serial.log
QEMU_PID_FILE=/tmp/zboot-factory-vm-qemu.pid
SSH_PORT=2227

cleanup() {
    set +e
    [ -f "$QEMU_PID_FILE" ] && kill -TERM "$(cat "$QEMU_PID_FILE")" 2>/dev/null
    pkill -9 -f "qemu-system-x86_64.*zboot-factory-vm" 2>/dev/null
    rm -f "$TARGET_QCOW2" "$SEED_ISO" "$QEMU_PID_FILE"
    [ -n "${SEED_DIR:-}" ] && rm -rf "$SEED_DIR"
}
trap cleanup EXIT

# ── 1. Cache the cloud image ──────────────────────────────────────────
if [ ! -f "$DEBIAN_IMG" ]; then
    echo "--- downloading $DEBIAN_IMG_URL (~700MB, one-time, cached at $DEBIAN_IMG) ---"
    curl -L -o "$DEBIAN_IMG.tmp" "$DEBIAN_IMG_URL"
    mv "$DEBIAN_IMG.tmp" "$DEBIAN_IMG"
fi

# ── 2. qcow2 backing snapshot — cloud image stays untouched ──────────
qemu-img create -f qcow2 -F qcow2 -b "$DEBIAN_IMG" "$TARGET_QCOW2" 16G > /dev/null

# ── 3. cloud-init NoCloud seed ISO ────────────────────────────────────
SEED_DIR=$(mktemp -d /tmp/zboot-factory-seed-XXXXXX)

cat > "$SEED_DIR/meta-data" <<EOF
instance-id: zboot-factory-runner
local-hostname: zboot-factory-runner
EOF

cat > "$SEED_DIR/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $PUBKEY_LINE
disable_root: false
package_update: true
packages:
  - debootstrap
  - zstd
runcmd:
  - touch /var/lib/cloud/zboot-ready
EOF

if command -v xorriso >/dev/null; then
    xorriso -as mkisofs -quiet -o "$SEED_ISO" -volid CIDATA -joliet -rock "$SEED_DIR"
elif command -v genisoimage >/dev/null; then
    genisoimage -quiet -output "$SEED_ISO" -volid CIDATA -joliet -rock "$SEED_DIR"
else
    echo "need xorriso or genisoimage to build cloud-init seed (apt install xorriso)" >&2
    exit 1
fi

# ── 4. Boot QEMU (SeaBIOS — no OVMF needed for cloud images) ──────────
echo "--- boot vanilla Debian VM (cloud-init: deps install, sshd, ssh key) ---"
qemu-system-x86_64 \
    -machine q35,accel=kvm -cpu host -m 8G -smp 4 -nographic \
    -drive file="$TARGET_QCOW2",if=virtio,format=qcow2 \
    -drive file="$SEED_ISO",if=virtio,format=raw,readonly=on \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22 \
    -device virtio-net,netdev=n0 \
    -serial file:$SERIAL_LOG -monitor none -no-reboot \
    > /tmp/zboot-factory-vm-qemu.log 2>&1 &
echo $! > "$QEMU_PID_FILE"

# ── 5. Wait for cloud-init to finish (sshd up + debootstrap installed) ──
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"
SSH="ssh $SSH_OPTS -p $SSH_PORT root@127.0.0.1"
SCP="scp $SSH_OPTS -P $SSH_PORT"

echo "--- wait for cloud-init (up to 5min) ---"
for i in $(seq 1 60); do
    sleep 5
    if $SSH "test -f /var/lib/cloud/zboot-ready && command -v debootstrap" >/dev/null 2>&1; then
        echo "  cloud-init complete after $((i * 5))s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "FAIL: cloud-init didn't complete in 5min" >&2
        echo "--- serial log tail ---" >&2
        tail -50 "$SERIAL_LOG" >&2
        exit 1
    fi
done

# ── 6+7+8. SCP zboot + run host-mode + SCP tar back ───────────────────
echo "--- scp zboot CLI in ---"
$SCP "$ZBOOT_BIN" root@127.0.0.1:/tmp/zboot
$SSH "chmod 755 /tmp/zboot"

echo "--- run zboot factory inside (debootstrap + chroot) ---"
$SSH "/tmp/zboot factory --output /tmp/factory.tar.zst"

echo "--- scp tar back to host: $FACTORY_TAR ---"
$SCP root@127.0.0.1:/tmp/factory.tar.zst "$FACTORY_TAR"

echo
echo "✓ factory tar ready: $FACTORY_TAR ($(du -h "$FACTORY_TAR" | cut -f1))"
