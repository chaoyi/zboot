#!/bin/bash
# Verifies: snapshot / fork / default / rollback survive real reboots,
# AND the snapshotted filesystem content round-trips correctly at every
# rollback point — including a pre-touch snapshot that captures the
# absence of a file.
#
# Tracks /etc/marker through three states (absent / m1 / m1+m2) and
# rolls back across BE boundaries to assert each one.
#
# Prereq: zboot factory
set -euo pipefail
TEST=lifecycle
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: tar deploy onto vda ==="
deploy_from_live
power_off_live

echo "=== cycle 1: boot be1 → snapshot 3 content states → fork be2 from s1 (m1 only) → default be2 ==="
boot_be c1
be_ssh 'set -ex
[ ! -e /etc/marker ] || { echo "FAIL: /etc/marker already exists pre-test"; exit 1; }
zpool get -Hp -o value bootfs rpool
zfs get -Hp -o value zboot:be rpool/ROOT/be1
/usr/local/sbin/zboot snapshot --name s0      # absent state
echo m1 > /etc/marker
/usr/local/sbin/zboot snapshot --name s1      # m1
echo m2 >> /etc/marker
/usr/local/sbin/zboot snapshot --name s2      # m1+m2
/usr/local/sbin/zboot fork be2 --from s1
/usr/local/sbin/zboot default be2
'
power_off_be

echo "=== cycle 2: should boot be2 → /etc/marker = 'm1' → fork be3 from be1@s2 → default be3 ==="
boot_be c2
expect_eq "bootfs after default be2 + reboot" "rpool/ROOT/be2" "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
expect_eq "/etc/marker on be2 (s1 state)"     "m1"             "$(be_ssh 'cat /etc/marker')"
be_ssh 'set -ex
/usr/local/sbin/zboot fork be3 --from rpool/ROOT/be1@s2
/usr/local/sbin/zboot default be3
'
power_off_be

echo "=== cycle 3: should boot be3 → /etc/marker = 'm1\\nm2' → snapshot from-be3 → rollback to be1@s0 as rb-empty ==="
boot_be c3
expect_eq "bootfs after default be3 + reboot" "rpool/ROOT/be3" "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
expected=$'m1\nm2'
got=$(be_ssh 'cat /etc/marker')
[ "$got" = "$expected" ] || { echo "FAIL: be3 should have m1+m2, got: $got"; exit 1; }
echo "  ✓ /etc/marker on be3 (s2 state) = m1+m2"
be_ssh 'set -ex
/usr/local/sbin/zboot snapshot --name from-be3
/usr/local/sbin/zboot rollback --to rpool/ROOT/be1@s0 --name rb-empty
'
power_off_be

echo "=== cycle 4: should boot rb-empty → /etc/marker absent (s0 captured pre-touch) + origin + inventory ==="
boot_be c4
expect_eq "bootfs after rollback + reboot" "rpool/ROOT/rb-empty" "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
expect_eq "rb-empty origin"                "rpool/ROOT/be1@s0"   "$(be_ssh 'zfs get -Hp -o value origin rpool/ROOT/rb-empty')"

if be_ssh 'test -e /etc/marker' 2>/dev/null; then
    echo "FAIL: /etc/marker exists on rb-empty but s0 captured pre-touch state"; exit 1
fi
echo "  ✓ /etc/marker absent on rb-empty (s0 captured the absence)"

be_list=$(be_ssh 'zfs list -Hp -o name -t filesystem -r rpool/ROOT' | sort)
for want in rpool/ROOT/be1 rpool/ROOT/be2 rpool/ROOT/be3 rpool/ROOT/rb-empty; do
    echo "$be_list" | grep -qx "$want" || { echo "FAIL: $want missing"; echo "$be_list"; exit 1; }
done
echo "  ✓ all four BEs present"

# Smoke-check the human renderer surfaces every BE name we created.
status_out=$(be_ssh '/usr/local/sbin/zboot status')
got_be_count=$(echo "$status_out" | grep -cE '^[[:space:]]*[├└].*(be1|be2|be3|rb-empty)$')
[ "$got_be_count" -ge 4 ] \
    || { echo "FAIL: status missing one of the four BEs (got $got_be_count)"; echo "$status_out"; exit 1; }
echo "  ✓ status surfaces all four BEs"

echo
echo "🎉 lifecycle ok"
