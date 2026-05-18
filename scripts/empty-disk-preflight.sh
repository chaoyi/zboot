#!/bin/bash
# Verifies: `zboot deploy` refuses to clobber a disk that already has
# partitions or a filesystem signature, refusal is non-destructive
# (existing data still readable), and a `wipefs` + retry succeeds.
# Single live-image cycle; no BE boot.
#
# Prereq: zboot factory
set -euo pipefail
TEST=empty
source "$(dirname "$0")/_harness.sh"

echo "=== boot live image with blank vda → stage GPT + ext4 + marker ==="
boot_live

$LIVE_SSH 'sudo bash -c "
    set -ex
    sgdisk -n 1:0:+1G -t 1:8300 -c 1:test /dev/vda
    partprobe /dev/vda
    mkfs.ext4 -F -L preexist /dev/vda1
    mkdir -p /mnt/preexist
    mount /dev/vda1 /mnt/preexist
    echo 'do not clobber me' > /mnt/preexist/marker.txt
    sync
    umount /mnt/preexist
"'

echo "=== test 1: deploy must REFUSE the non-empty disk ==="
set +e
deploy_out=$($LIVE_SSH "sudo ZBOOT_DEPLOY_CONFIRM_DISK=vda \
        /tmp/zboot deploy --target /dev/vda --hostname zb-test \
        --source 'tar:///tmp/factory.tar.zst'" 2>&1)
deploy_rc=$?
set -e
echo "$deploy_out" | tail -20
[ "$deploy_rc" -ne 0 ] || { echo "FAIL: deploy succeeded but disk had pre-existing data"; exit 1; }
echo "$deploy_out" | grep -qiE "empty|partition|signature|wipe|preflight|already" \
    || { echo "FAIL: deploy errored, but message doesn't mention disk-not-empty"; exit 1; }
echo "  ✓ deploy refused with a disk-not-empty message"

echo "=== verify marker file survived (deploy was non-destructive) ==="
marker=$($LIVE_SSH 'sudo bash -c "
    mkdir -p /mnt/check
    mount /dev/vda1 /mnt/check
    cat /mnt/check/marker.txt
    umount /mnt/check
"')
expect_eq "marker file contents" "do not clobber me" "$marker"

echo "=== wipefs + sgdisk --zap-all → deploy must now SUCCEED ==="
$LIVE_SSH 'sudo bash -c "
    set -ex
    sgdisk --zap-all /dev/vda
    wipefs --all /dev/vda
    partprobe /dev/vda
"'

set +e
$LIVE_SSH "sudo ZBOOT_DEPLOY_CONFIRM_DISK=vda \
        /tmp/zboot deploy --target /dev/vda --hostname zb-test \
        --source 'tar:///tmp/factory.tar.zst' \
        --cmdline 'console=ttyS0,115200 quiet'"
retry_rc=$?
set -e
[ "$retry_rc" -eq 0 ] || { echo "FAIL: deploy still refused after wipe"; exit 1; }
echo "  ✓ deploy succeeded after wipe"

echo
echo "🎉 empty-disk preflight ok"
