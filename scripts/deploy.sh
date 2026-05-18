#!/bin/bash
# Verifies: end-to-end deploy with the SLOW path — debootstrap + DKMS
# zfs.ko build inside chroot, then ESP install + NVRAM register, then
# boot fresh QEMU off the deployed disk and reach BE userspace.
#
# This is the load-bearing test for `zboot deploy` itself; the other
# e2es use a pre-built minimal BE tar to skip the ~10-15 min debootstrap.
#
# Run: bash scripts/deploy.sh
# Prereqs: qemu-system-x86_64, OVMF, sshpass, KVM, ~16GB RAM.
set -euo pipefail
TEST=deploy
NEED_FACTORY=0
LIVE_RAM=16G
source "$(dirname "$0")/_harness.sh"

echo "=== boot live image with blank vda ==="
boot_live

echo "=== test 1: --check renders plan + runs preflight (no --source → debootstrap://trixie) ==="
$LIVE_SSH 'sudo /tmp/zboot deploy --target /dev/vda --hostname zb-test --check'

echo "=== test 2: live deploy with debootstrap source (~10-15 min: debootstrap + DKMS gcc) ==="
SSH_LONG="sshpass -p live ssh $SSH_OPTS -o ServerAliveInterval=10 -o ServerAliveCountMax=720 -tt -p $SSH_PORT_LIVE user@127.0.0.1"
set +e
$SSH_LONG "sudo ZBOOT_DEPLOY_CONFIRM_DISK=vda \
        /tmp/zboot deploy \
        --target /dev/vda --hostname zb-test \
        --cmdline 'console=ttyS0,115200 quiet'"
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "DEPLOY FAILED rc=$rc"; $LIVE_SSH 'sudo zpool list 2>&1; sudo zfs list 2>&1; sudo lsblk /dev/vda' || true; exit 1; }

echo "=== inspect resulting pool ==="
$LIVE_SSH 'set -e
sudo zpool list rpool
sudo zpool get bootfs,zboot:role rpool
sudo zfs list -r rpool
sudo mkdir -p /mnt/inspect
sudo mount -t zfs -o zfsutil,ro rpool/ROOT/be1 /mnt/inspect
echo "/etc/hostname:"; sudo cat /mnt/inspect/etc/hostname
echo "/etc/hostid (4 bytes hex):"; sudo od -An -tx1 -N4 /mnt/inspect/etc/hostid
echo "kernel + initrd:"; sudo ls -lh /mnt/inspect/boot/vmlinuz* /mnt/inspect/boot/initrd.img*
echo "zfs.ko present:"; sudo find /mnt/inspect/lib/modules -name "zfs.ko*" | head -3
sudo umount /mnt/inspect
sudo zpool export rpool
'

# Apply the test overlay so the deployed BE has sshd + a known root
# password — same fixture deploy_from_live uses.  Without this we'd
# fall back to grepping the serial log for "BE userspace reached",
# which is much weaker than `be_ssh` against the running BE.
echo "--- apply test overlay (ssh fixtures: keys + root pw + enable) ---"
overlay_tar=$(_stage_test_overlay)
$LIVE_SCP "$overlay_tar" user@127.0.0.1:/tmp/test-overlay.tar.zst
$LIVE_SSH 'sudo /tmp/zboot overlay /tmp/test-overlay.tar.zst'
rm -f "$overlay_tar"

power_off_live

echo "=== boot deployed disk → assert via SSH (not just serial grep) ==="
boot_be deploy
expect_eq "hostname"        "zb-test"            "$(be_ssh 'hostname')"
expect_eq "bootfs"          "rpool/ROOT/be1"     "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
expect_eq "zboot:be on be1" "true"               "$(be_ssh 'zfs get -Hp -o value zboot:be rpool/ROOT/be1')"
# zfs.ko is the load-bearing artifact: if it's missing the pool
# couldn't have been imported and we couldn't have reached SSH.
be_ssh 'find /lib/modules -name "zfs.ko*" | head -1' | grep -q zfs.ko \
    || { echo "FAIL: zfs.ko missing in deployed BE"; exit 1; }
echo "  ✓ zfs.ko present in deployed BE"
power_off_be

echo
echo "🎉 deploy ok: debootstrap deploy → reboot → BE userspace via zboot-boot kexec"
