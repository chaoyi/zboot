#!/bin/bash
# Verifies all of `zboot mirror`'s contracts in one shared deploy:
#
#   1. Basic --to: replicates active BE with full BE-contract intact
#      (zboot:be=true, canmount=noauto, mountpoint=/, readonly=on);
#      leaves @mirror-<utc> anchor on source for future incrementals.
#   2. Idempotency: second --to with no source changes is a no-op.
#   3. Incremental: source change → real send; readonly preserved on dest.
#   4. Refusal: mirror refuses to a non-`zboot:role=root` pool with a
#      clear hint.
#   5. Promote drift: zfs promote on source rotates the clone graph;
#      mirror detects and refuses with a "promote drift" message; manual
#      replay on the dest unblocks the next mirror.
#   6. Bidirectional --with: forks unique to each side land on the
#      other; received BEs end readonly; second --with is a no-op.
#
# Single VM lifecycle, six contracts, ~7 min total instead of ~15.
#
# Prereq: zboot factory
set -euo pipefail
TEST=mirror
EXTRA_DISKS=1
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: deploy onto vda + create blank rpool2 (role=root) on vdb via --empty ==="
deploy_from_live
$LIVE_SSH 'sudo ZBOOT_DEPLOY_CONFIRM_DISK=vdb \
    /tmp/zboot deploy --target /dev/vdb --pool rpool2 --hostname zb-test --empty --no-efi'
$LIVE_SSH 'sudo zpool export rpool2'
power_off_live

echo "=== cycle 1: basic + idempotency + incremental + refusal ==="
boot_be c1
be_ssh 'zpool import -f rpool2 || zpool import -aN -d /dev'

# (1) Basic mirror.
listing_pre=$(be_ssh 'zfs list -Hp -o name -r rpool2')
[ "$listing_pre" = "rpool2" ] || { echo "FAIL: rpool2 not empty pre-mirror, got $listing_pre"; exit 1; }
be_ssh '/usr/local/sbin/zboot mirror --to rpool2'

expect_eq "rpool2/ROOT/be1 zboot:be"   "true"   "$(be_ssh 'zfs get -Hp -o value zboot:be   rpool2/ROOT/be1')"
expect_eq "rpool2/ROOT/be1 canmount"   "noauto" "$(be_ssh 'zfs get -Hp -o value canmount   rpool2/ROOT/be1')"
expect_eq "rpool2/ROOT/be1 mountpoint" "/"      "$(be_ssh 'zfs get -Hp -o value mountpoint rpool2/ROOT/be1')"
expect_eq "rpool2/ROOT/be1 readonly"   "on"     "$(be_ssh 'zfs get -Hp -o value readonly   rpool2/ROOT/be1')"

anchor_count=$(be_ssh 'zfs list -t snapshot -H -o name rpool/ROOT/be1' | grep -c "@mirror-" || true)
[ "$anchor_count" -eq 1 ] \
    || { echo "FAIL: expected exactly 1 @mirror-* anchor on source after first run (got $anchor_count)"; exit 1; }
echo "  ✓ source has exactly 1 @mirror-<utc> anchor (auto-pruned older if any)"

# (2) Idempotency.
noop_out=$(be_ssh '/usr/local/sbin/zboot mirror --to rpool2' 2>&1)
echo "$noop_out" | grep -qi "no-op" || { echo "FAIL: expected no-op; got: $noop_out"; exit 1; }
echo "  ✓ idempotent"

# (3) Incremental — source change → real send; readonly preserved.
be_ssh '/usr/local/sbin/zboot snapshot --name post-mirror'
inc_out=$(be_ssh '/usr/local/sbin/zboot mirror --to rpool2' 2>&1)
echo "$inc_out" | grep -qi "no-op" && { echo "FAIL: expected real send, got no-op"; exit 1; }
expect_eq "readonly after incremental" "on" "$(be_ssh 'zfs get -Hp -o value readonly rpool2/ROOT/be1')"
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@post-mirror" \
    || { echo "FAIL: post-mirror snap not on dest"; exit 1; }
# Pruning: after incremental, still exactly one @mirror-* anchor on each side
src_anchors=$(be_ssh 'zfs list -t snapshot -H -o name rpool/ROOT/be1'  | grep -c "@mirror-" || true)
dst_anchors=$(be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -c "@mirror-" || true)
[ "$src_anchors" -eq 1 ] && [ "$dst_anchors" -eq 1 ] \
    || { echo "FAIL: anchor prune broken (src=$src_anchors, dst=$dst_anchors; want 1 each)"; exit 1; }
echo "  ✓ incremental landed; readonly preserved; anchors pruned (1 each)"

# (4) Refusal on non-role=root.
be_ssh 'truncate -s 1G /tmp/datapool.img && zpool create -o ashift=12 -o cachefile=none datapool /tmp/datapool.img'
set +e
err=$(be_ssh '/usr/local/sbin/zboot mirror --be rpool/ROOT/be1 --to datapool --name be-attempt' 2>&1)
err_rc=$?
set -e
[ "$err_rc" -ne 0 ] || { echo "FAIL: mirror should have refused (datapool not tagged)"; exit 1; }
echo "$err" | grep -qi "zboot:role=root" || { echo "FAIL: error doesn't hint at zboot:role=root"; exit 1; }
echo "  ✓ refused with role-tag hint"
be_ssh 'zpool destroy datapool && rm -f /tmp/datapool.img'

# Set up for promote-drift + bidirectional tests:
# fork be2 from a snapshot, mirror, default be2 → reboot.
be_ssh 'set -ex
/usr/local/sbin/zboot snapshot --name pre-fork
/usr/local/sbin/zboot fork be2 --from pre-fork
/usr/local/sbin/zboot mirror --to rpool2
'
origin_dst=$(be_ssh 'zfs get -Hp -o value origin rpool2/ROOT/be2')
[[ "$origin_dst" == rpool2/ROOT/be1@* ]] \
    || { echo "FAIL: rpool2/ROOT/be2 origin should be under rpool2/ROOT/be1, got $origin_dst"; exit 1; }
echo "  ✓ clone graph preserved on dest: rpool2/ROOT/be2 origin = $origin_dst"

be_ssh '/usr/local/sbin/zboot default be2'
power_off_be

echo "=== cycle 2: booted into be2 → promote drift detection + bidirectional --with ==="
boot_be c2
expect_eq "bootfs" "rpool/ROOT/be2" "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
be_ssh 'zpool import -f rpool2 || zpool import -aN -d /dev'

# (5) Promote drift. `zfs promote` directly because both pools have a
# be1, which would make `zboot drop be1` ambiguous; the structural
# change is the same as drop's auto-promote.
be_ssh 'zfs promote rpool/ROOT/be2'
expect_eq "rpool be2 origin AFTER promote (now trunk)" "-" "$(be_ssh 'zfs get -Hp -o value origin rpool/ROOT/be2')"

set +e
drift_out=$(be_ssh '/usr/local/sbin/zboot mirror --to rpool2' 2>&1)
drift_rc=$?
set -e
echo "$drift_out"
[ "$drift_rc" -ne 0 ] || { echo "FAIL: mirror should have refused on drift"; exit 1; }
echo "$drift_out" | grep -qi "promote drift" || { echo "FAIL: error doesn't mention 'promote drift'"; exit 1; }
echo "  ✓ refused with promote-drift detection"

be_ssh 'zfs promote rpool2/ROOT/be2'
be_ssh '/usr/local/sbin/zboot mirror --to rpool2'
echo "  ✓ mirror recovered after manual promote replay on dest"

# (6) Bidirectional --with. Each side gets a unique BE forked from a
# shared snapshot; @shared has the same GUID on both sides, so clones
# from it can be replicated either direction.
be_ssh '/usr/local/sbin/zboot snapshot --name shared'
be_ssh '/usr/local/sbin/zboot mirror --to rpool2'
be_ssh '/usr/local/sbin/zboot fork be-A --from shared'
be_ssh 'set -ex
zfs clone -o canmount=noauto -o mountpoint=/ rpool2/ROOT/be2@shared rpool2/ROOT/be-B
zfs set zboot:be=true rpool2/ROOT/be-B
zfs set -u readonly=on rpool2/ROOT/be-B
'
be_ssh '/usr/local/sbin/zboot mirror --with rpool2'

for ds in rpool/ROOT/be-A rpool/ROOT/be-B rpool2/ROOT/be-A rpool2/ROOT/be-B; do
    be_ssh "zfs list -H -o name $ds >/dev/null 2>&1" \
        || { echo "FAIL: $ds missing after mirror --with"; exit 1; }
done
echo "  ✓ both pools have be-A + be-B after --with"

expect_eq "rpool/ROOT/be-B  readonly (received from rpool2)" "on" "$(be_ssh 'zfs get -Hp -o value readonly rpool/ROOT/be-B')"
expect_eq "rpool2/ROOT/be-A readonly (received from rpool)"  "on" "$(be_ssh 'zfs get -Hp -o value readonly rpool2/ROOT/be-A')"

with_noop=$(be_ssh '/usr/local/sbin/zboot mirror --with rpool2' 2>&1)
echo "$with_noop" | grep -qi "no-op" || { echo "FAIL: expected no-op on second --with; got: $with_noop"; exit 1; }
echo "  ✓ second --with is no-op"

power_off_be
echo
echo "🎉 mirror ok: basic + idempotency + incremental + refusal + drift + --with all green"
