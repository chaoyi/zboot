#!/bin/bash
# Verifies the multi-pool disambiguation contracts for `drop` and
# `default`:
#
#   1. With two `zboot:role=root` pools both containing a BE named
#      `be1`, `zboot drop be1` (bare name) refuses with an "ambiguous"
#      message that points at `--pool` and the full-path form.
#   2. `zboot drop --pool rpool2 be1` succeeds (disambiguated by pool).
#   3. `zboot drop rpool/ROOT/be1` succeeds (fully-qualified path).
#   4. Same matrix for `default`: bare name refuses, `--pool` works,
#      fully-qualified path works.
#   5. `default` against a read-only auto-imported pool transparently
#      promotes the pool to R/W (per `ensure_pool_imported_rw`) before
#      `zpool set bootfs`; doesn't require the operator to manually
#      export+reimport.
#
# Prereq: zboot factory + extra disk for rpool2
set -euo pipefail
TEST=multipool-ambiguity
EXTRA_DISKS=1
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: deploy + build rpool2 via --empty with same-named BE ==="
deploy_from_live
$LIVE_SSH 'sudo ZBOOT_DEPLOY_CONFIRM_DISK=vdb \
    /tmp/zboot deploy --target /dev/vdb --pool rpool2 --hostname zb-test --empty --no-efi'
$LIVE_SSH 'sudo bash -c "
    set -ex
    zpool import -f rpool
    zpool import -f rpool2
    # Same-name BE: clone rpools be1 over via send/receive
    zfs snapshot rpool/ROOT/be1@for-ambiguity
    zfs send rpool/ROOT/be1@for-ambiguity | zfs receive rpool2/ROOT/be1
    zfs set canmount=noauto rpool2/ROOT/be1
    zfs set mountpoint=/    rpool2/ROOT/be1
    zfs set zboot:be=true   rpool2/ROOT/be1
    zfs destroy rpool/ROOT/be1@for-ambiguity
    zfs destroy rpool2/ROOT/be1@for-ambiguity
    zpool export rpool2
    zpool export rpool
"'
power_off_live

echo "=== cycle 1: boot rpool's be1 ==="
boot_be c1
be_ssh 'zpool import -f rpool2 || zpool import -aN -d /dev'

echo "--- precondition: both pools see be1 ---"
status_out=$(be_ssh '/usr/local/sbin/zboot status')
echo "$status_out" | grep -q "pool rpool:"  || { echo "FAIL: rpool missing from status"; exit 1; }
echo "$status_out" | grep -q "pool rpool2:" || { echo "FAIL: rpool2 missing from status"; exit 1; }

echo "=== AMBIGUITY 1: drop be1 (bare name) refuses with hint ==="
set +e
err=$(echo "rpool/ROOT/be1" | be_ssh '/usr/local/sbin/zboot drop be1' 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "FAIL: drop should refuse with bare ambiguous name"; exit 1; }
echo "$err" | grep -qi "multiple BEs"  || { echo "FAIL: error should say multiple BEs: $err"; exit 1; }
echo "$err" | grep -qi -- "--pool"     || { echo "FAIL: error should hint --pool: $err"; exit 1; }
echo "$err" | grep -qi "full dataset"  || { echo "FAIL: error should hint full dataset: $err"; exit 1; }
echo "  ✓ refused with --pool / full-path hint"

echo "=== AMBIGUITY 2: drop --pool rpool2 be1 succeeds ==="
echo "rpool2/ROOT/be1" | be_ssh '/usr/local/sbin/zboot drop --pool rpool2 be1' 2>&1 | tail -3
be_ssh 'zfs list -Hp -o name -t filesystem rpool2/ROOT/be1' 2>&1 | grep -q "does not exist" \
    || { echo "FAIL: rpool2/ROOT/be1 should be destroyed"; exit 1; }
echo "  ✓ rpool2/ROOT/be1 destroyed via --pool"

echo "=== rebuild rpool2/be1 for next case ==="
be_ssh 'sudo bash -c "
    zfs snapshot rpool/ROOT/be1@for-ambiguity2
    zfs send rpool/ROOT/be1@for-ambiguity2 | zfs receive rpool2/ROOT/be1
    zfs set canmount=noauto rpool2/ROOT/be1
    zfs set mountpoint=/    rpool2/ROOT/be1
    zfs set zboot:be=true   rpool2/ROOT/be1
    zfs destroy rpool/ROOT/be1@for-ambiguity2
    zfs destroy rpool2/ROOT/be1@for-ambiguity2
"'

echo "=== AMBIGUITY 3: drop with fully-qualified path ==="
echo "rpool2/ROOT/be1" | be_ssh '/usr/local/sbin/zboot drop rpool2/ROOT/be1' 2>&1 | tail -3
be_ssh 'zfs list -Hp -o name -t filesystem rpool2/ROOT/be1' 2>&1 | grep -q "does not exist" \
    || { echo "FAIL: rpool2/ROOT/be1 should be destroyed via full-path"; exit 1; }
echo "  ✓ rpool2/ROOT/be1 destroyed via fully-qualified path"

echo "=== rebuild for default tests ==="
be_ssh 'sudo bash -c "
    zfs snapshot rpool/ROOT/be1@for-default
    zfs send rpool/ROOT/be1@for-default | zfs receive rpool2/ROOT/be1
    zfs set canmount=noauto rpool2/ROOT/be1
    zfs set mountpoint=/    rpool2/ROOT/be1
    zfs set zboot:be=true   rpool2/ROOT/be1
    zfs destroy rpool/ROOT/be1@for-default
    zfs destroy rpool2/ROOT/be1@for-default
"'

echo "=== AMBIGUITY 4: default be1 (bare name) refuses ==="
set +e
err=$(be_ssh '/usr/local/sbin/zboot default be1' 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "FAIL: default should refuse bare ambiguous name"; exit 1; }
echo "$err" | grep -qi "ambiguous"   || { echo "FAIL: default error should say ambiguous: $err"; exit 1; }
echo "$err" | grep -qi -- "--pool"   || { echo "FAIL: default error should hint --pool: $err"; exit 1; }
echo "  ✓ default refused with hint"

echo "=== AMBIGUITY 5: default --pool rpool2 be1 transparently re-imports R/W ==="
# rpool2 may currently be imported R/W from earlier ops, but in
# general the auto-import scan brings it in R/O. Force the R/O state
# to validate the ensure_pool_imported_rw helper:
be_ssh 'sudo zpool export rpool2 2>&1 | tail -2; sudo zpool import -N -f -o readonly=on rpool2'
ro_before=$(be_ssh 'zpool get -Hp -o value readonly rpool2')
[ "$ro_before" = "on" ] || { echo "FAIL: setup — rpool2 should be R/O ($ro_before)"; exit 1; }

be_ssh '/usr/local/sbin/zboot default --pool rpool2 be1' 2>&1 | tail -3
expect_eq "rpool2 bootfs"  "rpool2/ROOT/be1" "$(be_ssh 'zpool get -Hp -o value bootfs rpool2')"
expect_eq "rpool  bootfs"  "-"               "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
ro_after=$(be_ssh 'zpool get -Hp -o value readonly rpool2')
[ "$ro_after" = "off" ] \
    || { echo "FAIL: rpool2 should be R/W after default ($ro_after)"; exit 1; }
echo "  ✓ default auto-promoted rpool2 R/O → R/W and set bootfs"

echo "=== restore bootfs to rpool/be1 for clean teardown ==="
be_ssh '/usr/local/sbin/zboot default rpool/ROOT/be1' 2>&1 | tail -3

power_off_be
echo
echo "🎉 multipool-ambiguity ok — drop + default disambiguate by --pool and by full-path, default auto-promotes R/O"
