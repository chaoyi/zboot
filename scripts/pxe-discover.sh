#!/bin/bash
# Verifies: when zboot-boot.efi is served via UEFI PXE (TFTP) instead
# of running from the disk's ESP, its preinit still imports the local
# rpool and the menu reaches the prompt with real ZFS state — not the
# synthetic fake-data forest.
#
# This is the only test that exercises the TFTP→UEFI PXE→zboot-boot
# path end-to-end.  Disk-mode (boot from ESP) is covered by lifecycle.sh.
# The two paths can diverge silently — e.g. zfs.ko / nvme drivers /
# userland missing in the production initrd would only manifest when
# the initrd boots without the surrounding deployed-system context.
#
# Prereq: zboot factory + bash boot/build.sh
set -euo pipefail
TEST=pxe-discover
source "$(dirname "$0")/_harness.sh"

echo "=== cycle 0: tar deploy onto vda, then strip ESP fallback ==="
deploy_from_live
# Erase EFI/BOOT/BOOTX64.EFI so OVMF (with fresh NVRAM) has no
# auto-discoverable disk boot option.  Without this, OVMF would fall
# through from a failing PXE attempt to the disk-resident zboot-boot
# and the test would silently pass on disk-mode discovery.
$LIVE_SSH 'sudo mount /dev/vda1 /mnt && sudo rm -f /mnt/EFI/BOOT/BOOTX64.EFI && sudo umount /mnt'
power_off_live

echo "=== cycle 1: PXE-boot zboot-boot.efi from TFTP, expect rpool/ROOT/be1 ==="
boot_be_pxe c1
expect_eq "bootfs after PXE chain + reboot" "rpool/ROOT/be1" \
    "$(be_ssh 'zpool get -Hp -o value bootfs rpool')"
power_off_be

echo
echo "🎉 pxe-discover ok"
