#!/bin/bash
# Verifies the per-BE replication verbs (push, pull, primary, pair,
# unpair, rename) in one shared deploy:
#
#   1. push --to <pool>           bootstraps mutual pair (same name)
#   2. push (default)             sends to paired peer; idempotent re-run
#   3. push --to <pool>/ROOT/<x>  ad-hoc unpaired copy
#   4. push be@<snap>             bounded: send up to a named snapshot
#   5. divergence refusal         peer-only snap → push refuses
#                                 push --force overwrites
#   6. pair / unpair              declare peers metadata-only;
#                                 unpair clears mutual; asymmetric stays
#   7. rename                     local rename rewrites peer's pointer
#   8. primary                    pair-level flip; readonly toggled; bootfs follows
#   9. pull --name <new>          initial pull creates fresh local BE
#  10. pull (paired, non-active)  incremental pull from peer
#
# Single VM lifecycle. ~8 min.
#
# Prereq: zboot factory
set -euo pipefail
TEST=replication
EXTRA_DISKS=1
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: deploy onto vda + create empty rpool2 on vdb ==="
deploy_from_live
$LIVE_SSH 'sudo ZBOOT_DEPLOY_CONFIRM_DISK=vdb \
    /tmp/zboot deploy --target /dev/vdb --pool rpool2 --hostname zb-test --empty --no-efi'
$LIVE_SSH 'sudo zpool export rpool2'
power_off_live

echo "=== cycle 1: bootstrap + push + pull + pair/unpair + rename + primary ==="
boot_be c1
be_ssh 'zpool import -f rpool2 || zpool import -aN -d /dev'

# ----- (1) push --to <pool>: bootstrap mutual pair, same name -------------
echo "--- (1) push --to <pool> bootstraps mutual pair ---"
be_ssh '/usr/local/sbin/zboot push be1 --to rpool2'
expect_eq "rpool/ROOT/be1 zboot:mirror"  "rpool2/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool/ROOT/be1')"
expect_eq "rpool2/ROOT/be1 zboot:mirror" "rpool/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool2/ROOT/be1')"
expect_eq "rpool2/ROOT/be1 readonly"     "on" \
    "$(be_ssh 'zfs get -Hp -o value readonly rpool2/ROOT/be1')"
expect_eq "rpool2/ROOT/be1 zboot:be"     "true" \
    "$(be_ssh 'zfs get -Hp -o value zboot:be rpool2/ROOT/be1')"
echo "  ✓ mutual pair, dest readonly, contract intact"

# ----- (2) push (default to paired peer): incremental + idempotent -------
echo "--- (2) push to paired peer (default) ---"
be_ssh '/usr/local/sbin/zboot snapshot --name checkpoint'
out=$(be_ssh '/usr/local/sbin/zboot push be1' 2>&1)
echo "$out" | grep -qi "pushed" || { echo "FAIL: expected push success"; echo "$out"; exit 1; }
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@checkpoint" \
    || { echo "FAIL: @checkpoint missing on dest"; exit 1; }
echo "  ✓ default push lands @checkpoint on dest"

# ----- (3) push --to <pool>/ROOT/<name>: ad-hoc unpaired -----------------
echo "--- (3) push --to <pool>/ROOT/<other-name> is ad-hoc unpaired ---"
be_ssh '/usr/local/sbin/zboot push be1 --to rpool2/ROOT/be1-adhoc'
expect_eq "ad-hoc copy zboot:mirror" "-" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool2/ROOT/be1-adhoc')"
expect_eq "rpool/ROOT/be1 zboot:mirror still original peer" "rpool2/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool/ROOT/be1')"
echo "  ✓ ad-hoc copy left unpaired; original pair untouched"

# ----- (4) push be@<snap>: bounded ----------------------------------------
echo "--- (4) bounded push be1@<snap> uses named snapshot as anchor ---"
be_ssh '/usr/local/sbin/zboot snapshot --name milestone'
be_ssh '/usr/local/sbin/zboot snapshot --name post-milestone-wip'
# Bounded push should land milestone on dest but NOT post-milestone-wip.
# Use ad-hoc dest so we can test snapshot reach independently.
be_ssh '/usr/local/sbin/zboot push be1@milestone --to rpool2/ROOT/be1-at-milestone'
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1-at-milestone' | grep -q "@milestone" \
    || { echo "FAIL: bounded push didn't carry @milestone"; exit 1; }
if be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1-at-milestone' | grep -q "@post-milestone-wip"; then
    echo "FAIL: bounded push leaked @post-milestone-wip"; exit 1
fi
echo "  ✓ bounded push stops at named anchor"

# ----- (5) divergence refusal + --force -----------------------------------
echo "--- (5) divergence refusal + --force ---"
# Make rpool2/be1 (readonly) writable temporarily and add a snap that's
# not on rpool — direct ZFS, simulating out-of-band drift.
be_ssh 'set -ex
zfs set -u readonly=off rpool2/ROOT/be1
zfs snapshot rpool2/ROOT/be1@out-of-band
zfs set -u readonly=on  rpool2/ROOT/be1
'
set +e
div_out=$(be_ssh '/usr/local/sbin/zboot push be1' 2>&1)
div_rc=$?
set -e
[ "$div_rc" -ne 0 ] || { echo "FAIL: push should refuse on divergence"; echo "$div_out"; exit 1; }
echo "$div_out" | grep -qi "divergent\|diverged\|refuses" \
    || { echo "FAIL: error doesn't mention divergence: $div_out"; exit 1; }
echo "  ✓ refused with divergence message"

# --force overrides
be_ssh '/usr/local/sbin/zboot push be1 --force'
if be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@out-of-band"; then
    echo "FAIL: --force should have wiped @out-of-band"; exit 1
fi
echo "  ✓ --force wiped divergent dest snapshot"

# ----- (6) pair / unpair (metadata-only) ----------------------------------
echo "--- (6) pair/unpair on adhoc dataset ---"
# rpool2/ROOT/be1-adhoc is unpaired. Pair it with rpool/ROOT/be1 — this is
# the asymmetric case (rpool/ROOT/be1 is already paired to rpool2/be1).
be_ssh '/usr/local/sbin/zboot pair rpool2/ROOT/be1-adhoc rpool/ROOT/be1'
expect_eq "adhoc tracks rpool" "rpool/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool2/ROOT/be1-adhoc')"
# rpool/ROOT/be1's existing pair should NOT have changed (it pointed at
# rpool2/ROOT/be1, not adhoc).
expect_eq "rpool/ROOT/be1 pair unchanged after asymmetric pair" "rpool2/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool/ROOT/be1')"
echo "  ✓ asymmetric pair: tracking pointer set, canonical untouched"

be_ssh '/usr/local/sbin/zboot unpair rpool2/ROOT/be1-adhoc'
expect_eq "adhoc unpair clears" "-" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool2/ROOT/be1-adhoc')"
# rpool/ROOT/be1's pointer untouched (it was pointing elsewhere).
expect_eq "rpool/ROOT/be1 pair survives async unpair" "rpool2/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool/ROOT/be1')"
echo "  ✓ asymmetric unpair clears local only"

# ----- (7) rename rewrites peer's pointer ---------------------------------
echo "--- (7) rename updates peer's zboot:mirror ---"
be_ssh '/usr/local/sbin/zboot fork be1-fresh --from milestone'
be_ssh '/usr/local/sbin/zboot push be1-fresh --to rpool2/ROOT/be1-fresh'  # ad-hoc
# Now pair them explicitly so rename has a peer to update.
be_ssh '/usr/local/sbin/zboot pair rpool/ROOT/be1-fresh rpool2/ROOT/be1-fresh'
expect_eq "pair set both sides" "rpool2/ROOT/be1-fresh" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool/ROOT/be1-fresh')"
be_ssh '/usr/local/sbin/zboot rename be1-fresh be1-renamed'
expect_eq "peer's pointer rewritten after rename" "rpool/ROOT/be1-renamed" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool2/ROOT/be1-fresh')"
echo "  ✓ rename updated peer's zboot:mirror automatically"
# Clean up rename test BEs to keep state predictable
be_ssh 'zfs destroy -r rpool/ROOT/be1-renamed; zfs destroy -r rpool2/ROOT/be1-fresh'

# ----- (8) primary flips mutual pair ----
echo "--- (8) primary toggles mutual pair (zboot:primary + readonly + bootfs follow) ---"
# rpool/ROOT/be1 ↔ rpool2/ROOT/be1 should still be paired from earlier steps.
# Make rpool the primary (it currently is), flip to rpool2.
be_ssh '/usr/local/sbin/zboot primary rpool2/ROOT/be1'
expect_eq "rpool/be1 primary after flip" "off"  "$(be_ssh 'zfs get -Hp -o value zboot:primary rpool/ROOT/be1')"
expect_eq "rpool2/be1 primary after flip" "on"  "$(be_ssh 'zfs get -Hp -o value zboot:primary rpool2/ROOT/be1')"
expect_eq "bootfs rpool cleared"          "-"   "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
expect_eq "bootfs rpool2 set"             "rpool2/ROOT/be1" "$(be_ssh 'zpool get -Hp -o value bootfs rpool2')"
echo "  ✓ primary: markers flipped, bootfs followed"

# Flip back so the next cycle still works.
be_ssh '/usr/local/sbin/zboot primary rpool/ROOT/be1'
expect_eq "rpool/be1 primary after flip-back" "on" \
    "$(be_ssh 'zfs get -Hp -o value zboot:primary rpool/ROOT/be1')"

# ----- (9) pull --name <new>: initial pull from remote --------------------
echo "--- (9) initial pull creates fresh local BE paired to remote ---"
# Bring rpool/ROOT/be1 and rpool2/ROOT/be1 to clean state for a pull demo.
# pull is into a NEW local BE name so live-root rule doesn't trigger.
be_ssh '/usr/local/sbin/zboot pull rpool2/ROOT/be1 --name pulled-from-rpool2'
be_ssh 'zfs list -H -o name rpool/ROOT/pulled-from-rpool2 >/dev/null' \
    || { echo "FAIL: pulled BE missing"; exit 1; }
# pull --name on a remote that's already paired (to rpool/be1) is the
# asymmetric case: local gets the pointer, remote stays asymmetric.
expect_eq "pulled BE zboot:mirror" "rpool2/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool/ROOT/pulled-from-rpool2')"
expect_eq "remote's pointer unchanged (already paired)" "rpool/ROOT/be1" \
    "$(be_ssh 'zfs get -Hp -o value zboot:mirror rpool2/ROOT/be1')"
echo "  ✓ initial pull set local pointer; remote stayed asymmetric"

# ----- (10) pull (paired, non-active): incremental from peer -------------
echo "--- (10) incremental pull from paired peer ---"
# Make rpool2/be1 the canonical "ahead" side: clear readonly, add a snap,
# restore readonly. Then pull from rpool/pulled-from-rpool2 (its peer)
# and verify the new snap landed.
be_ssh 'set -ex
zfs set -u readonly=off rpool2/ROOT/be1
zfs snapshot rpool2/ROOT/be1@from-pull-test
zfs set -u readonly=on  rpool2/ROOT/be1
'
be_ssh '/usr/local/sbin/zboot pull pulled-from-rpool2'
be_ssh 'zfs list -t snapshot -H -o name rpool/ROOT/pulled-from-rpool2' | grep -q "@from-pull-test" \
    || { echo "FAIL: pulled snapshot didn't land"; exit 1; }
echo "  ✓ incremental pull from peer landed @from-pull-test"

# ----- (11) smart mirror walks primary=on BEs ----------------------------
echo "--- (11) mirror (smart walker) walks primary=on BEs ---"
# At this point: rpool/ROOT/be1 ↔ rpool2/ROOT/be1 mutual pair (primary=on/off).
# Add an asymmetric tracker: rpool2/ROOT/be1-tracker tracks rpool/ROOT/be1.
be_ssh 'set -ex
zfs clone -o canmount=noauto -o mountpoint=/ rpool2/ROOT/be1@deploy rpool2/ROOT/be1-tracker
zfs set zboot:be=true rpool2/ROOT/be1-tracker
zfs set -u zboot:mirror=rpool/ROOT/be1 rpool2/ROOT/be1-tracker
zfs set -u zboot:primary=off rpool2/ROOT/be1-tracker
zfs set -u readonly=on rpool2/ROOT/be1-tracker
'
# Make a fresh snapshot on rpool/be1 so mirror has work to do.
be_ssh '/usr/local/sbin/zboot snapshot --name mirror-walker-test'
# Run smart mirror — should push to BOTH the canonical peer and the asymmetric tracker.
mirror_out=$(be_ssh '/usr/local/sbin/zboot mirror' 2>&1)
echo "$mirror_out" | grep -q "synced=2" || { echo "FAIL: expected synced=2 (mutual + tracker), got: $mirror_out"; exit 1; }
# Verify the new snapshot landed on both peers.
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@mirror-walker-test" \
    || { echo "FAIL: @mirror-walker-test didn'\''t land on canonical mirror"; exit 1; }
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1-tracker' | grep -q "@mirror-walker-test" \
    || { echo "FAIL: @mirror-walker-test didn'\''t land on asymmetric tracker"; exit 1; }
echo "  ✓ mirror walked mutual peer + asymmetric tracker (synced=2)"
be_ssh 'zfs destroy -r rpool2/ROOT/be1-tracker'

# ----- (12) --force typed-confirmation prompt ---------------------------
echo "--- (12) push --force prompts for typed confirmation when truncating ---"
# Forge a divergent snap on the mirror side.
be_ssh 'set -ex
zfs set -u readonly=off rpool2/ROOT/be1
zfs snapshot rpool2/ROOT/be1@out-of-band-force-test
zfs set -u readonly=on rpool2/ROOT/be1
'
# (a) Without typed confirmation, push --force aborts.
set +e
abort_out=$(echo "WRONG" | be_ssh '/usr/local/sbin/zboot push be1 --force' 2>&1)
abort_rc=$?
set -e
[ "$abort_rc" -ne 0 ] || { echo "FAIL: --force should abort on wrong confirmation"; exit 1; }
echo "$abort_out" | grep -qi "confirmation mismatch\|abort" \
    || { echo "FAIL: error doesn'\''t mention confirmation mismatch: $abort_out"; exit 1; }
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@out-of-band-force-test" \
    || { echo "FAIL: --force aborted but @out-of-band-force-test was destroyed anyway"; exit 1; }
echo "  ✓ wrong confirmation aborts; divergent snapshot preserved"
# (b) With correct typed confirmation, push --force proceeds.
echo "rpool2/ROOT/be1" | be_ssh '/usr/local/sbin/zboot push be1 --force' 2>&1 | tail -3
if be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@out-of-band-force-test"; then
    echo "FAIL: --force with correct confirmation didn'\''t destroy the divergent snapshot"
    exit 1
fi
echo "  ✓ correct confirmation proceeds; divergent snapshot wiped"

# ----- (13) bounded push rewind (case 3: dest past the bound) -----------
echo "--- (13) bounded push to a snapshot older than dest's tip ---"
# Setup: take two named snapshots on the primary, push fully so dest
# matches, then take a third only on the primary. Pushing bounded to
# the first snapshot is a rewind — dest @rewind-mid and @rewind-tip
# (the latter local-only on dest after the prior tests would have synced
# everything else) are *after* @rewind-anchor on src. Refuses without
# --force; --force runs `zfs rollback -r dest@rewind-anchor`.
be_ssh '/usr/local/sbin/zboot snapshot --name rewind-anchor'
be_ssh '/usr/local/sbin/zboot snapshot --name rewind-mid'
# Sync to peer so peer has both anchor + mid.
be_ssh '/usr/local/sbin/zboot push be1' 2>&1 | tail -2
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@rewind-mid" \
    || { echo "FAIL: setup — @rewind-mid didn'\''t reach peer"; exit 1; }
# Now bounded push to @rewind-anchor — this is a rewind.
# (a) Without --force: refuse with verb-level message naming the zfs command.
set +e
refuse_out=$(be_ssh '/usr/local/sbin/zboot push be1@rewind-anchor' 2>&1)
refuse_rc=$?
set -e
[ "$refuse_rc" -ne 0 ] || { echo "FAIL: bounded rewind should refuse without --force"; exit 1; }
echo "$refuse_out" | grep -qi "rewind\|past the bound" \
    || { echo "FAIL: refusal doesn'\''t mention rewind: $refuse_out"; exit 1; }
echo "$refuse_out" | grep -q "zfs rollback -r rpool2/ROOT/be1@rewind-anchor" \
    || { echo "FAIL: refusal doesn'\''t name the zfs rollback command: $refuse_out"; exit 1; }
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@rewind-mid" \
    || { echo "FAIL: refusal destroyed @rewind-mid anyway"; exit 1; }
echo "  ✓ bare-form refuses; @rewind-mid preserved; refusal cites zfs rollback"
# (b) --force without typed confirmation aborts.
set +e
abort_out=$(echo "WRONG" | be_ssh '/usr/local/sbin/zboot push be1@rewind-anchor --force' 2>&1)
abort_rc=$?
set -e
[ "$abort_rc" -ne 0 ] || { echo "FAIL: --force should abort on wrong confirmation"; exit 1; }
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@rewind-mid" \
    || { echo "FAIL: --force aborted but @rewind-mid was destroyed anyway"; exit 1; }
echo "  ✓ --force aborts on wrong typed confirmation; @rewind-mid preserved"
# (c) --force with correct confirmation runs the rollback.
echo "rpool2/ROOT/be1" | be_ssh '/usr/local/sbin/zboot push be1@rewind-anchor --force' 2>&1 | tail -3
if be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@rewind-mid"; then
    echo "FAIL: rewind didn'\''t destroy @rewind-mid on peer"
    exit 1
fi
be_ssh 'zfs list -t snapshot -H -o name rpool2/ROOT/be1' | grep -q "@rewind-anchor" \
    || { echo "FAIL: rewind destroyed @rewind-anchor too (should keep it)"; exit 1; }
echo "  ✓ rewind executed; peer at @rewind-anchor; @rewind-mid wiped"

power_off_be
echo
echo "🎉 replication ok: push/pull/primary/pair/unpair/rename + @snap + --force confirmation + smart mirror all green"
