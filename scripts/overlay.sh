#!/bin/bash
# Verifies: `zboot overlay <tar>` applies a host-specific data tar to a
# deployed BE — extracts rootfs/ over BE rootfs, runs post-install.sh
# in chroot, refuses on the live `/`.
#
# Sequence:
#   cycle 0: tar deploy (minimal BE tar onto vda)
#   cycle 1: boot deployed BE
#            → fork be2 from a snapshot (gives us a non-live target)
#            → build a small data.tar.zst with a marker file + post-install
#            → `zboot overlay --be rpool/ROOT/be2 /tmp/data.tar.zst`
#            → verify marker file landed in be2's rootfs
#            → verify post-install.sh effect (marker from chroot)
#            → also test: refusal when target is the live root
#
# Prereq: zboot factory
set -euo pipefail
TEST=overlay
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: tar deploy ==="
deploy_from_live
power_off_live

echo "=== cycle 1: fork be2; build data tar; overlay onto be2 ==="
boot_be c1

# 1. Prepare a sibling BE we can safely overlay onto.
be_ssh 'set -ex
/usr/local/sbin/zboot snapshot --name pre-overlay
/usr/local/sbin/zboot fork be2 --from pre-overlay
'

# 2. Build a small data.tar.zst inside the BE.
#
# rootfs/etc/overlay-marker       — proves rootfs untar landed
# post-install.sh                  — proves chroot ran (writes /etc/overlay-pi-marker)
be_ssh 'set -ex
rm -rf /tmp/data-stage
mkdir -p /tmp/data-stage/rootfs/etc
echo "rootfs-marker-OK" > /tmp/data-stage/rootfs/etc/overlay-marker
cat > /tmp/data-stage/post-install.sh <<EOF
#!/bin/sh
set -e
echo "pi-marker-OK at \$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /etc/overlay-pi-marker
# Test that chroot env has /proc /sys /dev for systemctl etc.
test -d /proc/1 || { echo "FAIL: /proc not bind-mounted"; exit 1; }
test -e /dev/null || { echo "FAIL: /dev not bind-mounted"; exit 1; }
EOF
chmod 755 /tmp/data-stage/post-install.sh
tar --xattrs --acls --zstd -cf /tmp/data.tar.zst -C /tmp/data-stage .
rm -rf /tmp/data-stage
'

# 3. Apply overlay to be2 (sibling BE).
echo "--- overlay → rpool/ROOT/be2 ---"
be_ssh '/usr/local/sbin/zboot overlay --be rpool/ROOT/be2 /tmp/data.tar.zst'

# 4. Verify both markers landed in be2's rootfs.
echo "--- verify markers in be2 ---"
expect_eq "rootfs marker" "rootfs-marker-OK" \
    "$(read_be_file rpool/ROOT/be2 /etc/overlay-marker)"
pi_marker=$(read_be_file rpool/ROOT/be2 /etc/overlay-pi-marker)
echo "$pi_marker" | grep -q "pi-marker-OK" || { echo "FAIL: post-install marker missing: $pi_marker"; exit 1; }
echo "  ✓ post-install.sh ran (chroot saw /proc + /dev): $pi_marker"

# 5. Refusal on live `/`. Target the active BE (be1, currently the
# live root). `zboot overlay --be rpool/ROOT/be1` must refuse.
echo "--- overlay onto live / must refuse ---"
set +e
err=$(be_ssh '/usr/local/sbin/zboot overlay --be rpool/ROOT/be1 /tmp/data.tar.zst' 2>&1)
err_rc=$?
set -e
[ "$err_rc" -ne 0 ] || { echo "FAIL: overlay onto live / should refuse"; exit 1; }
echo "$err" | grep -qi "live" || { echo "FAIL: refusal doesn't mention live root: $err"; exit 1; }
echo "  ✓ overlay refused on live /"

# 6. Ambiguous target rejection: with two BEs (be1 active + be2 forked),
#    `overlay` without --be/--pool can't pick one and must error with
#    a hint.  (Single-BE auto-resolution is the inverse case;
#    deploy_from_live's first cycle exercises it implicitly.)
echo "--- ambiguous (multiple BEs, no --be / --pool) must error ---"
set +e
err2=$(be_ssh '/usr/local/sbin/zboot overlay /tmp/data.tar.zst' 2>&1)
err2_rc=$?
set -e
[ "$err2_rc" -ne 0 ] || { echo "FAIL: expected ambiguity error with be1+be2"; exit 1; }
echo "$err2" | grep -qi "ambiguous" || { echo "FAIL: error doesn't mention ambiguity: $err2"; exit 1; }
echo "  ✓ ambiguous target errors with hint"

power_off_be

echo
echo "🎉 overlay ok: rootfs landing + post-install chroot + live-/ refusal + auto-target ambiguity"
