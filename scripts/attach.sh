#!/bin/bash
# Verifies: `attach`/`detach` actually toggle dataset mount state at
# real boot. Sim tests check the property; only a live ZFS-import-on-
# boot can confirm /data mounts/unmounts as the property says.
#
# Prereq: zboot factory
set -euo pipefail
TEST=attach
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: tar deploy onto vda ==="
deploy_from_live
power_off_live

echo "=== cycle 1: create rpool/data → attach to be1 → fork be2 → default be2 ==="
boot_be c1
be_ssh 'set -ex
zfs create -o mountpoint=/data rpool/data
echo hello-from-be1 > /data/marker.txt
/usr/local/sbin/zboot attach rpool/data --to rpool:be1
'
expect_eq "attached-to after attach"  "rpool:be1" "$(be_ssh 'zfs get -Hp -o value zboot:attached-to rpool/data')"
expect_eq "canmount after attach"     "on"        "$(be_ssh 'zfs get -Hp -o value canmount rpool/data')"
be_ssh 'mountpoint /data' >/dev/null \
    || { echo "FAIL: /data not mounted after attach to active BE"; exit 1; }
be_ssh 'set -ex
/usr/local/sbin/zboot snapshot --name s1
/usr/local/sbin/zboot fork be2 --from s1
/usr/local/sbin/zboot default be2
'
power_off_be

echo "=== cycle 2: should boot be2 → fork carried attach forward → /data still mounted ==="
boot_be c2
expect_eq "bootfs" "rpool/ROOT/be2" "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"

attached=$(be_ssh 'zfs get -Hp -o value zboot:attached-to rpool/data')
echo "$attached" | grep -q "rpool:be2" \
    || { echo "FAIL: fork should have extended attached-to to include rpool:be2 (got $attached)"; exit 1; }
echo "  ✓ rpool:be2 in attached-to: $attached"

expect_eq "canmount under be2" "on" "$(be_ssh 'zfs get -Hp -o value canmount rpool/data')"
be_ssh 'mountpoint /data && cat /data/marker.txt'
echo "  ✓ /data mounted; cycle-1 marker survived"

echo "--- re-attach excluding be2 → canmount must flip to off ---"
be_ssh '/usr/local/sbin/zboot attach rpool/data --to rpool:be1'
expect_eq "canmount after excluding be2" "off" "$(be_ssh 'zfs get -Hp -o value canmount rpool/data')"

echo "--- detach → property cleared ---"
be_ssh '/usr/local/sbin/zboot detach rpool/data'
expect_eq "attached-to after detach" "-" "$(be_ssh 'zfs get -Hp -o value zboot:attached-to rpool/data')"

power_off_be
echo
echo "🎉 attach ok"
