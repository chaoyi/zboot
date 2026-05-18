#!/bin/bash
# Verifies: with two `zboot:role=root` pools, status sees BEs from both,
# `default <name-on-other-pool>` does a cross-pool switch + clears the
# old pool's bootfs (single-active invariant), and the next boot lands
# on the other pool.
#
# Prereq: zboot factory
set -euo pipefail
TEST=multipool
EXTRA_DISKS=1
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: deploy onto vda; build rpool2 on vdb with a replicated BE ==="
deploy_from_live

echo "--- build rpool2 on vdb (whole-disk pool, role=root) via deploy --empty + replicate be1 ---"
$LIVE_SSH 'sudo ZBOOT_DEPLOY_CONFIRM_DISK=vdb \
    /tmp/zboot deploy --target /dev/vdb --pool rpool2 --hostname zb-test --empty --no-efi'
$LIVE_SSH 'sudo bash -c "
    set -ex
    zpool import -f rpool
    zpool import -f rpool2
    zfs snapshot rpool/ROOT/be1@for-replica
    zfs send rpool/ROOT/be1@for-replica | zfs receive rpool2/ROOT/replica
    zfs set canmount=noauto rpool2/ROOT/replica
    zfs set mountpoint=/   rpool2/ROOT/replica
    zfs set zboot:be=true  rpool2/ROOT/replica
    zpool set bootfs=rpool2/ROOT/replica rpool2
    zpool export rpool2
    zpool export rpool
"'
power_off_live

echo "=== cycle 1: boot deployed BE → verify multi-pool discovery → cross-pool default ==="
boot_be c1
be_ssh 'zpool import -f rpool2 || zpool import -aN -d /dev'

status_out=$(be_ssh '/usr/local/sbin/zboot status')
echo "$status_out"
echo "$status_out" | grep -q "rpool/ROOT/be1"      || { echo "FAIL: rpool/ROOT/be1 not in status"; exit 1; }
echo "$status_out" | grep -q "rpool2/ROOT/replica" || { echo "FAIL: rpool2/ROOT/replica not in status"; exit 1; }
echo "  ✓ both pools' BEs visible in status"

be_ssh '/usr/local/sbin/zboot default replica'
expect_eq "rpool2 bootfs after cross-pool default" "rpool2/ROOT/replica" "$(be_ssh 'zpool get -Hp -o value bootfs rpool2')"
power_off_be

echo "=== cycle 2: should boot rpool2/ROOT/replica + rpool's bootfs should be cleared ==="
boot_be c2
cmdline=$(be_ssh 'cat /proc/cmdline')
echo "  /proc/cmdline: $cmdline"
echo "$cmdline" | grep -q "root=ZFS=rpool2/ROOT/replica" || { echo "FAIL: kernel root not pointing at rpool2"; exit 1; }
echo "  ✓ booted from rpool2"

be_ssh 'zpool import -f rpool || zpool import -aN -d /dev'
expect_eq "rpool bootfs (single-active invariant)" "-" "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
power_off_be

echo
echo "🎉 multipool ok"
