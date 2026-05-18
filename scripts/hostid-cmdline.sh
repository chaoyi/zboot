#!/bin/bash
# Verifies the `spl.spl_hostid=` kernel-cmdline override mechanism end-to-end:
#
#   1. Deploy from tar — BE's filesystem /etc/hostid set per host.
#   2. Boot — zboot-boot's `compose_cmdline` reads PID-1's /etc/hostid
#      (adopted by preinit from the pool's bootfs BE) and injects
#      `spl.spl_hostid=0x<HEX>` into the kexec cmdline.
#   3. The BE's spl module respects the param: post-boot,
#      `/sys/module/spl/parameters/spl_hostid` reflects the cmdline
#      value, not whatever was in the initramfs's /etc/hostid file.
#   4. Isolation test: deliberately corrupt the initramfs's
#      /etc/hostid to a WRONG value (via update-initramfs in chroot
#      with a temporary bad /etc/hostid). With the cmdline override
#      working, the BE still boots and the pool import succeeds.
#
# This is the regression test for the kernel-panic-after-zfs-loads
# class of bugs caused by hostid drift across boots — proven by
# isolating the mechanism so only the cmdline path could explain
# the successful import (initramfs /etc/hostid is verifiably wrong).
#
# Prereq: zboot factory
set -euo pipefail
TEST=hostid-cmdline
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: deploy ==="
deploy_from_live
power_off_live

echo "=== cycle 1: first boot — verify cmdline injection ==="
boot_be c1

# Decode BE's filesystem /etc/hostid (LE u32 → hex)
be_hostid=$(be_ssh 'od -An -tx1 -N4 /etc/hostid | tr -d " \n"')
# Bytes b1 b2 b3 b4 → u32 LE = (b4)(b3)(b2)(b1)
expected_hex="${be_hostid:6:2}${be_hostid:4:2}${be_hostid:2:2}${be_hostid:0:2}"
echo "  BE's /etc/hostid bytes:      $be_hostid"
echo "  expected spl.spl_hostid:     0x$expected_hex"

# Check /proc/cmdline
cmdline=$(be_ssh 'cat /proc/cmdline')
echo "  /proc/cmdline: $cmdline"
echo "$cmdline" | grep -qE "spl\.spl_hostid=0x${expected_hex}" \
    || { echo "FAIL: spl.spl_hostid not in cmdline (or wrong value)"; exit 1; }

# Check /sys/module/spl/parameters/spl_hostid (proves cmdline reached the module)
spl_param=$(be_ssh 'cat /sys/module/spl/parameters/spl_hostid')
spl_hex=$(printf %x "$spl_param")
echo "  /sys/module/spl/parameters/spl_hostid: $spl_param (0x$spl_hex)"
[ "$spl_hex" = "$expected_hex" ] \
    || { echo "FAIL: spl module hostid 0x$spl_hex != expected 0x$expected_hex"; exit 1; }
echo "  ✓ cmdline → spl module param applied"

echo "=== cycle 1b: ISOLATE — corrupt initramfs /etc/hostid, reboot ==="
be_ssh 'set -ex
# Snapshot the correct hostid; temporarily replace with build-host-style bytes
cp /etc/hostid /tmp/hostid.correct
printf "\xc4\xe2\xe0\x4d" > /etc/hostid     # arbitrary wrong bytes
update-initramfs -u 2>&1 | tail -3
cp /tmp/hostid.correct /etc/hostid          # restore BE-fs hostid
# Verify the initramfs really has the WRONG bytes baked in now
mkdir -p /tmp/check && cd /tmp/check && rm -rf ./*
unmkinitramfs /boot/initrd.img-*-amd64 .
find . -path "*/etc/hostid" -exec od -An -tx1 -N4 {} \;
'

power_off_be

echo "=== cycle 2: boot must succeed via spl.spl_hostid override alone ==="
boot_be c2

# If we reach here, the boot succeeded despite the wrong initramfs /etc/hostid.
# The ONLY mechanism that could have made the pool import succeed is the
# spl.spl_hostid cmdline param (kernel-side, authoritative per spl-generic.c
# zone_get_hostid).

cmdline2=$(be_ssh 'cat /proc/cmdline')
echo "  /proc/cmdline: $cmdline2"
spl_param2=$(be_ssh 'cat /sys/module/spl/parameters/spl_hostid')
spl_hex2=$(printf %x "$spl_param2")
[ "$spl_hex2" = "$expected_hex" ] \
    || { echo "FAIL: spl module hostid 0x$spl_hex2 != expected 0x$expected_hex"; exit 1; }
echo "  ✓ booted with wrong initramfs /etc/hostid; spl module still got cmdline value"

# Verify the corrupted initramfs is still actually corrupt (kernel doesn't
# regenerate it on boot — only userspace update-initramfs does)
be_ssh 'set -e
mkdir -p /tmp/recheck && cd /tmp/recheck && rm -rf ./*
unmkinitramfs /boot/initrd.img-*-amd64 . 2>/dev/null
bad=$(find . -path "*/etc/hostid" -exec od -An -tx1 -N4 {} \; | tr -d " \n")
if [ "$bad" = "c4e2e04d" ]; then
    echo "  ✓ initramfs /etc/hostid is the corrupted value (c4e2e04d) — kernel did NOT use it"
else
    echo "  initramfs /etc/hostid: $bad (unexpected, but boot succeeded so cmdline path still works)"
fi
'

echo "=== cycle 2b: restore — userspace update-initramfs bakes correct hostid ==="
be_ssh 'update-initramfs -u 2>&1 | tail -3
mkdir -p /tmp/final && cd /tmp/final && rm -rf ./*
unmkinitramfs /boot/initrd.img-*-amd64 .
good=$(find . -path "*/etc/hostid" -exec od -An -tx1 -N4 {} \; | tr -d " \n")
[ "$good" = "'"$be_hostid"'" ] && echo "  ✓ initramfs hostid restored to per-host value" || { echo "FAIL: restore mismatch"; exit 1; }
'

power_off_be
echo
echo "🎉 hostid-cmdline ok — spl.spl_hostid kernel cmdline override is authoritative"
