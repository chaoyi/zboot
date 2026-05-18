#!/bin/bash
# live-in-vm.sh — build the minimal Debian Live image inside a
# self-contained Debian VM (no host live-build install, no host sudo
# touching /dev, sandbox-friendly).  Mirrors the factory-in-vm.sh
# pattern.
#
# Pipeline:
#   1. Download Debian generic cloud image (cached at $CACHE_DIR).
#   2. qemu-img backing-file snapshot for this run (cloud image stays clean).
#   3. Build a NoCloud cloud-init seed ISO with:
#        - operator's ssh pubkey (no sshpass needed)
#        - apt install live-build xorriso
#   4. Boot QEMU with backing snapshot + seed ISO (SeaBIOS, no OVMF).
#   5. Wait for cloud-init `package_update + packages` to finish.
#   6. SCP the host's zboot CLI in (the EFI bundle rides inside it).
#   7. Run `zboot live` inside the VM (= live-build inside live-build's
#      own preferred environment: a real Debian box with full /dev).
#   8. SCP the resulting tree back: zboot-boot.efi, menu.ipxe (if
#      generated), and debianlive/{vmlinuz,initrd.img,filesystem.squashfs}.
#
# Standalone operator-facing wrapper.  Use this when `zboot live` on
# the host can't run — no live-build, hermetic CI, sandbox without
# mknod-in-chroot, cross-build, etc.  Not embedded in the zboot CLI;
# run as: `bash scripts/internal/live-in-vm.sh`.
#
# Env (defaults):
#   OUTPUT_DIR        output tree root            (default ~/.cache/zboot/pxe)
#   ZBOOT_BIN         CLI binary to run inside    (default <repo>/target/release/zboot)
#   CACHE_DIR         where to cache cloud image  (default ~/.cache/zboot)
#   DEBIAN_VER        debian release              (default trixie)
#   SSH_PUBKEY        ssh pubkey for cloud-init   (default ~/.ssh/id_ed25519.pub or id_rsa.pub)
#   EXTRA_PACKAGES    forwarded to `zboot live`   (comma-separated)
#   VM_MEM            RAM for the inner VM        (default 16G — live-build mounts
#                                                  tmpfs inside the chroot for apt
#                                                  caches, default size = half of RAM)
#   VM_DISK_SIZE      backing-snapshot size       (default 32G — live-build is hungry)

set -euo pipefail

ZBOOT_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUTPUT_DIR=${OUTPUT_DIR:-$HOME/.cache/zboot/pxe}
ZBOOT_BIN=${ZBOOT_BIN:-$ZBOOT_REPO/target/release/zboot}
CACHE_DIR=${CACHE_DIR:-$HOME/.cache/zboot}
DEBIAN_VER=${DEBIAN_VER:-trixie}
EXTRA_PACKAGES=${EXTRA_PACKAGES:-}
VM_MEM=${VM_MEM:-16G}
VM_DISK_SIZE=${VM_DISK_SIZE:-32G}

mkdir -p "$OUTPUT_DIR" "$OUTPUT_DIR/debianlive" "$CACHE_DIR"

[ -f "$ZBOOT_BIN" ] || { echo "missing ZBOOT_BIN=$ZBOOT_BIN" >&2; exit 1; }

# Pick (or generate) an SSH keypair for the throwaway VM.
# Honor $SSH_PUBKEY if set; else use a plain ed25519/rsa key under
# ~/.ssh; else generate a build-only keypair under $CACHE_DIR (avoids
# touch-prompt pain when the operator's only key is hardware-backed).
mkdir -p "$CACHE_DIR"
SSH_KEY_PRIV=""
if [ -n "${SSH_PUBKEY:-}" ]; then
    [ -f "$SSH_PUBKEY" ] || { echo "SSH_PUBKEY=$SSH_PUBKEY not found" >&2; exit 1; }
    SSH_KEY_PRIV="${SSH_PUBKEY%.pub}"
    [ -f "$SSH_KEY_PRIV" ] || { echo "SSH_PUBKEY=$SSH_PUBKEY has no matching private key at $SSH_KEY_PRIV" >&2; exit 1; }
elif [ -f "$HOME/.ssh/id_ed25519.pub" ] && [ -f "$HOME/.ssh/id_ed25519" ]; then
    SSH_PUBKEY="$HOME/.ssh/id_ed25519.pub"
    SSH_KEY_PRIV="$HOME/.ssh/id_ed25519"
elif [ -f "$HOME/.ssh/id_rsa.pub" ] && [ -f "$HOME/.ssh/id_rsa" ]; then
    SSH_PUBKEY="$HOME/.ssh/id_rsa.pub"
    SSH_KEY_PRIV="$HOME/.ssh/id_rsa"
else
    SSH_KEY_PRIV="$CACHE_DIR/build-vm-key"
    SSH_PUBKEY="$SSH_KEY_PRIV.pub"
    if [ ! -f "$SSH_KEY_PRIV" ]; then
        echo "--- generating throwaway keypair at $SSH_KEY_PRIV (no ed25519/rsa key on this host) ---"
        ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_PRIV" -C "zboot-live-vm" -q
    fi
fi
PUBKEY_LINE=$(cat "$SSH_PUBKEY")

DEBIAN_IMG_NAME="debian-13-genericcloud-amd64.qcow2"
DEBIAN_IMG="$CACHE_DIR/$DEBIAN_IMG_NAME"
DEBIAN_IMG_URL="https://cloud.debian.org/images/cloud/${DEBIAN_VER}/latest/${DEBIAN_IMG_NAME}"

TARGET_QCOW2=/tmp/zboot-live-vm.qcow2
SEED_ISO=/tmp/zboot-live-seed.iso
SERIAL_LOG=/tmp/zboot-live-vm-serial.log
QEMU_PID_FILE=/tmp/zboot-live-vm-qemu.pid
SSH_PORT=2228

cleanup() {
    set +e
    [ -f "$QEMU_PID_FILE" ] && kill -TERM "$(cat "$QEMU_PID_FILE")" 2>/dev/null
    pkill -9 -f "qemu-system-x86_64.*zboot-live-vm" 2>/dev/null
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
qemu-img create -f qcow2 -F qcow2 -b "$DEBIAN_IMG" "$TARGET_QCOW2" "$VM_DISK_SIZE" > /dev/null

# ── 3. cloud-init NoCloud seed ISO ────────────────────────────────────
SEED_DIR=$(mktemp -d /tmp/zboot-live-seed-XXXXXX)

cat > "$SEED_DIR/meta-data" <<EOF
instance-id: zboot-live-runner
local-hostname: zboot-live-runner
EOF

# live-build needs: live-build itself (lb), xorriso (ISO assembly),
# debootstrap (pulled in as a dep), and the standard build env.
# `growpart` lets us expand the rootfs to use the full backing disk
# (cloud image is ~2GB; we asked qemu-img for 32G).
cat > "$SEED_DIR/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $PUBKEY_LINE
disable_root: false
package_update: true
packages:
  - live-build
  - xorriso
  - zstd
  - sudo
  - systemd-ukify   # provides `ukify` (zboot live builds the live UKI)
  - python3-pefile  # ukify's runtime dep — not a hard apt dep, gets pulled in only on full systemd install
growpart:
  mode: auto
  devices: ['/']
  ignore_growroot_disabled: false
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
    -machine q35,accel=kvm -cpu host -m "$VM_MEM" -smp 4 -nographic \
    -drive file="$TARGET_QCOW2",if=virtio,format=qcow2 \
    -drive file="$SEED_ISO",if=virtio,format=raw,readonly=on \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22 \
    -device virtio-net,netdev=n0 \
    -serial file:$SERIAL_LOG -monitor none -no-reboot \
    > /tmp/zboot-live-vm-qemu.log 2>&1 &
echo $! > "$QEMU_PID_FILE"

# ── 5. Wait for cloud-init to finish (sshd up + live-build installed) ──
# `IdentitiesOnly=yes` + explicit `-i` so the agent doesn't offer
# unrelated keys (especially hardware-backed ones that prompt for
# touch on every connection attempt).
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o IdentitiesOnly=yes -i $SSH_KEY_PRIV"
SSH="ssh $SSH_OPTS -p $SSH_PORT root@127.0.0.1"
SCP="scp $SSH_OPTS -P $SSH_PORT"

echo "--- wait for cloud-init (up to 6min: package install) ---"
for i in $(seq 1 72); do
    sleep 5
    if $SSH "test -f /var/lib/cloud/zboot-ready && command -v lb" >/dev/null 2>&1; then
        echo "  cloud-init complete after $((i * 5))s"
        break
    fi
    if [ "$i" -eq 72 ]; then
        echo "FAIL: cloud-init didn't complete in 6min" >&2
        echo "--- serial log tail ---" >&2
        tail -50 "$SERIAL_LOG" >&2
        exit 1
    fi
done

# ── 6. SCP zboot CLI in (zboot-boot.efi rides inside the binary) ──────
echo "--- scp zboot CLI in ---"
$SCP "$ZBOOT_BIN" root@127.0.0.1:/tmp/zboot
$SSH "chmod 755 /tmp/zboot"

# Belt-and-suspenders: cloud-init's package: list isn't transactional, and
# python3-pefile (ukify's runtime dep on debian testing) sometimes silently
# fails to install — bake an explicit retry so the build doesn't crash
# 15min later in step 7's UKI assembly.
$SSH "apt-get install -y python3-pefile" >/dev/null 2>&1 \
    || { echo "FAIL: apt-get install python3-pefile failed in build VM"; exit 1; }

# ── 7. Run zboot live inside the VM ────────────────────────────────────
echo "--- run zboot live inside (live-build, ~10-20min) ---"
EXTRAS_FLAG=""
[ -n "$EXTRA_PACKAGES" ] && EXTRAS_FLAG="--packages '$EXTRA_PACKAGES'"
$SSH "/tmp/zboot live --output /tmp/zboot-pxe $EXTRAS_FLAG"

# ── 8. SCP the staging tree back ───────────────────────────────────────
echo "--- scp output tree back to host: $OUTPUT_DIR ---"
$SCP "root@127.0.0.1:/tmp/zboot-pxe/zboot-boot.efi"            "$OUTPUT_DIR/zboot-boot.efi"
# menu.ipxe may not exist if --no-menu was passed via EXTRAS_FLAG (we
# don't here, but keep the copy permissive).
$SSH "test -f /tmp/zboot-pxe/menu.ipxe" \
    && $SCP "root@127.0.0.1:/tmp/zboot-pxe/menu.ipxe" "$OUTPUT_DIR/menu.ipxe" \
    || true
for f in debianlive.efi filesystem.squashfs; do
    $SCP "root@127.0.0.1:/tmp/zboot-pxe/debianlive/$f" "$OUTPUT_DIR/debianlive/$f"
done

echo
echo "✓ debian live PXE tree ready in $OUTPUT_DIR/:"
ls -lh "$OUTPUT_DIR/zboot-boot.efi" "$OUTPUT_DIR/debianlive/"{debianlive.efi,filesystem.squashfs}
[ -f "$OUTPUT_DIR/menu.ipxe" ] && ls -lh "$OUTPUT_DIR/menu.ipxe"
echo
echo "Deploy with: rsync -av $OUTPUT_DIR/ root@<router>:/srv/tftpboot/zboot/"
