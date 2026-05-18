#!/bin/bash
# Verifies: `zboot chroot <NAME>` mounts a sibling BE RW, drops into a
# shell inside it, and edits made there persist when that BE is later
# booted. Exercises the full "fix a config without booting the BE first"
# workflow — the load-bearing use case for the verb.
#
# Sequence:
#   cycle 0: tar deploy onto vda
#   cycle 1: boot be1 → snapshot s1 → fork be2 from s1
#            → echo `zboot chroot` is invoked non-interactively
#              (pipe a script via stdin to busybox sh) to write a
#              marker file `/etc/chroot-marker` inside be2
#            → default be2, reboot
#   cycle 2: boot be2 → /etc/chroot-marker should contain the text
#            we wrote from inside be1's chroot session.
#            → also test refusal on the live `/`: `zboot chroot be2`
#              from inside be2 itself must fail with a clear error.
#
# Prereq: zboot factory
set -euo pipefail
TEST=chroot
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: tar deploy ==="
deploy_from_live
power_off_live

echo "=== cycle 1: from be1, fork be2 then chroot into be2 to write a marker ==="
boot_be c1
be_ssh 'set -ex
/usr/local/sbin/zboot snapshot --name s1
/usr/local/sbin/zboot fork be2 --from s1
'

# Drive `zboot chroot be2` non-interactively: pipe a sh script via
# stdin. The CLI spawns `chroot <mp> /bin/bash` which reads commands
# from its stdin (since we piped a script, bash runs in non-interactive
# mode and exits when the pipe closes — RAII guard unmounts).
echo "--- chroot be2 → write /etc/chroot-marker ---"
be_ssh 'echo "echo hello-from-chroot > /etc/chroot-marker" | /usr/local/sbin/zboot chroot be2'

echo "--- refuse chroot on live / (be1 is currently active) ---"
set +e
err=$(be_ssh '/usr/local/sbin/zboot chroot be1' 2>&1)
err_rc=$?
set -e
[ "$err_rc" -ne 0 ] || { echo "FAIL: chroot into live / should refuse"; exit 1; }
echo "$err" | grep -qi "live" || { echo "FAIL: refusal doesn't mention live root: $err"; exit 1; }
echo "  ✓ chroot refuses on live /"

be_ssh '/usr/local/sbin/zboot default be2'
power_off_be

echo "=== cycle 2: boot be2 → marker should still be there ==="
boot_be c2
expect_eq "bootfs after default be2 + reboot" "rpool/ROOT/be2" "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
expect_eq "/etc/chroot-marker (written via chroot from be1)" "hello-from-chroot" "$(be_ssh 'cat /etc/chroot-marker')"
power_off_be

echo
echo '🎉 chroot ok: edits via `zboot chroot <NAME>` persist into the booted BE; live-root refusal works'
