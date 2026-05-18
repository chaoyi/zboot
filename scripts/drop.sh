#!/bin/bash
# Verifies: dropping a parent in a clone chain auto-promotes its
# children before destroy (no "dataset has dependent clones" error)
# and strips the dropped BE from every `zboot:attached-to` list.
#
# Prereq: zboot factory
set -euo pipefail
TEST=drop
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: tar deploy ==="
deploy_from_live
power_off_live

echo "=== cycle 1: build be1→be2→be3 chain → attach rpool/data → default be3 ==="
boot_be c1
be_ssh 'set -ex
/usr/local/sbin/zboot snapshot --name s1
/usr/local/sbin/zboot fork be2 --from s1
zfs snapshot rpool/ROOT/be2@s2
/usr/local/sbin/zboot fork be3 --from rpool/ROOT/be2@s2
zfs create -o mountpoint=/data rpool/data
/usr/local/sbin/zboot attach rpool/data --to rpool:be1,rpool:be2,rpool:be3
/usr/local/sbin/zboot default be3
'
power_off_be

echo "=== cycle 2: should boot be3 → drop be2 (mid-chain) → verify chain survives ==="
boot_be c2
expect_eq "bootfs"           "rpool/ROOT/be3"     "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
expect_eq "be3 origin BEFORE drop" "rpool/ROOT/be2@s2" "$(be_ssh 'zfs get -Hp -o value origin rpool/ROOT/be3')"

echo "--- drop be2 (auto-promote be3 first) ---"
be_ssh 'echo rpool/ROOT/be2 | /usr/local/sbin/zboot drop be2'

be_list=$(be_ssh 'zfs list -Hp -o name -t filesystem -r rpool/ROOT')
echo "$be_list"
echo "$be_list" | grep -qx rpool/ROOT/be1 || { echo "FAIL: be1 missing"; exit 1; }
echo "$be_list" | grep -qx rpool/ROOT/be3 || { echo "FAIL: be3 missing (drop killed it!)"; exit 1; }
echo "$be_list" | grep -qx rpool/ROOT/be2 && { echo "FAIL: be2 still present"; exit 1; }
echo "  ✓ be1 + be3 alive, be2 gone"

origin_post=$(be_ssh 'zfs get -Hp -o value origin rpool/ROOT/be3')
case "$origin_post" in
    rpool/ROOT/be1@*) echo "  ✓ be3 origin promoted to a be1 snap: $origin_post" ;;
    *) echo "FAIL: be3 origin should point at a be1 snap, got $origin_post"; exit 1 ;;
esac

attached=$(be_ssh 'zfs get -Hp -o value zboot:attached-to rpool/data')
echo "$attached" | grep -q "rpool:be2" && { echo "FAIL: be2 not stripped from rpool/data ($attached)"; exit 1; }
echo "$attached" | grep -q "rpool:be1" || { echo "FAIL: be1 missing ($attached)"; exit 1; }
echo "$attached" | grep -q "rpool:be3" || { echo "FAIL: be3 missing ($attached)"; exit 1; }
echo "  ✓ attached-to rewritten without be2: $attached"

power_off_be
echo
echo "🎉 drop ok"
