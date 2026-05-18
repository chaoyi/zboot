#!/bin/bash
# Verifies: `zboot:kernel-cmdline` is consumed by zboot-boot at kexec
# time and reaches /proc/cmdline. Sim tests check the property; only a
# real boot proves it gets passed through.
#
# Prereq: zboot factory
set -euo pipefail
TEST=cmdline
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: tar deploy with --cmdline 'console=ttyS0,115200 quiet' ==="
deploy_from_live
power_off_live

echo "=== cycle 1: verify deploy-time cmdline reached /proc/cmdline ==="
boot_be c1
cmdline=$(be_ssh 'cat /proc/cmdline')
echo "  /proc/cmdline: $cmdline"
echo "$cmdline" | grep -q  "console=ttyS0,115200" || { echo "FAIL: console=ttyS0,115200 not in cmdline"; exit 1; }
echo "$cmdline" | grep -qw "quiet"                || { echo "FAIL: quiet not in cmdline"; exit 1; }
echo "  ✓ deploy-time --cmdline tokens reached the kernel"

echo "--- add per-BE token via `zboot cmdline set` ---"
be_ssh '/usr/local/sbin/zboot cmdline set "trace_buf_size=2M" --be rpool/ROOT/be1'
power_off_be

echo "=== cycle 2: verify both deploy-time AND new tokens reach the kernel ==="
boot_be c2
cmdline=$(be_ssh 'cat /proc/cmdline')
echo "  /proc/cmdline: $cmdline"
echo "$cmdline" | grep -q "console=ttyS0,115200" || { echo "FAIL: deploy-time console= lost"; exit 1; }
echo "$cmdline" | grep -q "trace_buf_size=2M"   || { echo "FAIL: per-BE trace_buf_size=2M not in cmdline"; exit 1; }
echo "  ✓ both deploy-time and per-BE tokens present"
power_off_be

echo
echo "🎉 cmdline ok"
