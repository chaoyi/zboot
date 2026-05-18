#!/usr/bin/env bash
# build-debian-live.sh — produce a minimal Debian Live image suitable
# both for PXE-booting `zboot deploy` and as a recovery medium for
# fixing a broken zboot BE system.
#
# What's in the image (strict zboot floor + recovery + provisioning):
#   - linux-image-amd64 + live-boot/live-config (so it boots)
#   - openssh-server with the live-build default `live`/`live` user and
#     PasswordAuthentication=yes — how the test layer SSHes in, and how
#     an operator reaches the live env remotely for recovery
#   - network diagnosis: ip/iputils-ping/dig/traceroute/mtr — needed
#     to figure out *why* the network isn't working before fixing it
#   - provisioning: curl/wget/rsync/git/stow — fetch, sync, lay down
#     dotfiles when bringing a recovered host back online
#   - zboot runtime: zfsutils-linux/kexec-tools/debootstrap
#   - disk + bootloader recovery kit: gdisk/parted/cryptsetup/lvm2/
#     e2fsprogs/dosfstools/ntfs-3g/nvme-cli/efibootmgr
#   - editor/archive/sudo: vim-nox, sudo, file, unzip, zstd, xz-utils
#   - bundled `zboot` CLI in /usr/local/sbin and zboot-boot.efi in
#     /usr/share/zboot
# Operator convenience (tmux, htop, jq, bash-completion, …) is layered
# by callers via EXTRA_PACKAGES / EXTRA_HOOKS_DIR / EXTRA_INCLUDES_DIR.
#
# Output tree (default ~/.cache/zboot/pxe/):
#   $OUTPUT_DIR/
#   ├── menu.ipxe                    ← iPXE menu (skipped if GENERATE_MENU="")
#   └── debianlive/
#       ├── vmlinuz
#       ├── initrd.img
#       └── filesystem.squashfs
#
# zboot-boot.efi is added at $OUTPUT_DIR/zboot-boot.efi by the CLI
# (cmd/live.rs) after this script returns — it lives as bytes inside
# the CLI binary, not on the filesystem.
#
# Boot via QEMU directly (smoke test the image standalone):
#   ( cd $OUTPUT_DIR/debianlive && python3 -m http.server 8000 ) &
#   qemu-system-x86_64 \
#       -kernel $OUTPUT_DIR/debianlive/vmlinuz \
#       -initrd $OUTPUT_DIR/debianlive/initrd.img \
#       -append "boot=live fetch=http://10.0.2.2:8000/filesystem.squashfs console=ttyS0,115200" \
#       -m 4G -nographic \
#       -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net,netdev=n0
#   sshpass -p live ssh -p 2222 user@127.0.0.1
#
# Env (defaults):
#   OUTPUT_DIR         output tree root            (default ~/.cache/zboot/pxe)
#   ZBOOT_BIN          zboot CLI to bundle         (default <repo>/target/release/zboot)
#   GENERATE_MENU      write menu.ipxe if non-empty (default "1")
#   DEBIAN_SUITE       debian release              (default testing)
#   EXTRA_PACKAGES     extra apt packages          (comma- or newline-separated)
#   EXTRA_HOOKS_DIR    files copied into config/hooks/normal/ before lb build
#   EXTRA_INCLUDES_DIR merged into config/includes.chroot_after_packages/
#   LB_WORKDIR         scratch dir for the chroot  (default /var/tmp; needs ~5-10 GB)
#   ZFS_FROM_SUITE     install zfs-dkms (and siblings) from this suite
#                      instead of DEBIAN_SUITE.  Use when the suite's
#                      kernel ships ahead of its zfs-dkms (e.g. testing
#                      kernel 7.0 + zfs 2.4.1 fails; pin from sid for 2.4.2+).
#                      Adds the suite as an extra apt source via
#                      config/archives/, with apt-pinning so only zfs
#                      packages come from it.  Default: sid (safe choice;
#                      sid usually leads with newer zfs).  Set to empty
#                      to disable the override.
#
# Mirrors `zboot factory`: zboot ships the stock recipe; downstream
# wrappers add extras via env vars.

set -euo pipefail

ZBOOT_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUTPUT_DIR=${OUTPUT_DIR:-$HOME/.cache/zboot/pxe}
ZBOOT_BIN=${ZBOOT_BIN:-$ZBOOT_REPO/target/release/zboot}
DEBIAN_SUITE=${DEBIAN_SUITE:-testing}
EXTRA_PACKAGES=${EXTRA_PACKAGES:-}
EXTRA_HOOKS_DIR=${EXTRA_HOOKS_DIR:-}
EXTRA_INCLUDES_DIR=${EXTRA_INCLUDES_DIR:-}
GENERATE_MENU=${GENERATE_MENU:-1}
# live-build's chroot needs ~5-10 GB during the build.  Default to
# /var/tmp (always on-disk on Debian) instead of /tmp (often tmpfs,
# typically half of RAM — too small for a real chroot).  Override
# with LB_WORKDIR if you have a faster scratch location.
LB_WORKDIR=${LB_WORKDIR:-/var/tmp}
# Default to sid for zfs packages because trixie/testing's zfs-dkms
# 2.4.1 doesn't compile against testing's kernel 7.0+.  Set to empty
# string to disable.
ZFS_FROM_SUITE=${ZFS_FROM_SUITE-sid}

# Preflight — single batched failure with install hints.
missing=()
command -v lb >/dev/null || missing+=("lb (apt install live-build)")
command -v sudo >/dev/null || missing+=("sudo")
[ -f "$ZBOOT_BIN" ] || missing+=("ZBOOT_BIN=$ZBOOT_BIN (cargo build --release)")
if [ ${#missing[@]} -gt 0 ]; then
    echo "[live] prereqs missing:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 1
fi

mkdir -p "$LB_WORKDIR"
WORK_DIR=$(mktemp -d -p "$LB_WORKDIR" zboot-lb-XXXXXX)
trap 'sudo rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"
echo "[live] workdir: $WORK_DIR"

mkdir -p "$OUTPUT_DIR"

echo "[live] live-build config (suite=$DEBIAN_SUITE, arch=amd64)"
lb config noauto \
    --distribution "$DEBIAN_SUITE" \
    --architecture amd64 \
    --archive-areas "main contrib non-free non-free-firmware" \
    --binary-images iso-hybrid

# --- Hooks ---
mkdir -p config/hooks/normal

cat > config/hooks/normal/98-enable-ssh-password-auth.hook.chroot <<'HOOK'
#!/bin/sh
set -e
sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
HOOK
chmod u+x config/hooks/normal/98-enable-ssh-password-auth.hook.chroot

# zfs-dkms's postinst runs with `uname -r` returning the BUILD HOST's
# kernel (chroots inherit it), not the kernel installed into the
# chroot.  Result: DKMS skips the build with "no kernel headers found
# for the running kernel" and zfs.ko never lands in the squashfs.
# Workaround: re-run dkms autoinstall against every kernel that *is*
# installed in /lib/modules.  Runs after all packages are unpacked.
cat > config/hooks/normal/99-build-zfs-dkms.hook.chroot <<'HOOK'
#!/bin/sh
set -e
echo "[hook] dkms autoinstall against chroot kernels"
for KVER in /lib/modules/*; do
    KVER=$(basename "$KVER")
    [ -d "/lib/modules/$KVER/build" ] || continue
    echo "  building dkms modules for $KVER"
    dkms autoinstall -k "$KVER"
done
# Sanity: bail loudly if zfs.ko isn't in any kernel after the rebuild.
if ! find /lib/modules -name 'zfs.ko*' | grep -q .; then
    echo "[hook] FAIL: zfs.ko not built for any kernel; live image is unusable for zboot" >&2
    exit 1
fi
HOOK
chmod u+x config/hooks/normal/99-build-zfs-dkms.hook.chroot

if [ -n "$EXTRA_HOOKS_DIR" ]; then
    [ -d "$EXTRA_HOOKS_DIR" ] || { echo "EXTRA_HOOKS_DIR=$EXTRA_HOOKS_DIR not a dir" >&2; exit 1; }
    echo "[live] copying caller hooks from $EXTRA_HOOKS_DIR"
    cp -r "$EXTRA_HOOKS_DIR"/. config/hooks/normal/
fi

# --- ZFS apt source pinning ---
# Add an extra apt source for zfs-dkms when DEBIAN_SUITE's zfs lags
# its kernel.  apt-pinning makes only zfs/spl packages come from the
# override suite; everything else stays on DEBIAN_SUITE.
if [ -n "$ZFS_FROM_SUITE" ]; then
    echo "[live] zfs from $ZFS_FROM_SUITE (apt-pinned)"
    mkdir -p config/archives
    cat > config/archives/zfs-pin.list.chroot <<EOF
deb http://deb.debian.org/debian $ZFS_FROM_SUITE main contrib non-free non-free-firmware
EOF
    cat > config/archives/zfs-pin.preferences.chroot <<EOF
Package: *
Pin: release n=$ZFS_FROM_SUITE
Pin-Priority: 100

Package: zfs-dkms zfs-initramfs zfs-zed zfsutils-linux libzfs* libnvpair* libuutil* libzpool* spl-dkms
Pin: release n=$ZFS_FROM_SUITE
Pin-Priority: 990
EOF
fi

# --- Packages ---
mkdir -p config/package-lists

cat > config/package-lists/zboot.list.chroot <<'PACKAGES'
# Kernel + live-boot infra. linux-headers needed so zfs-dkms can
# compile zfs.ko for the kernel that ends up in the live image (the
# 99-build-zfs-dkms.hook.chroot below forces dkms to target the
# chroot's kernel, not the build host's).
linux-image-amd64
linux-headers-amd64
live-boot
live-config

# Network: connectivity + diagnosis
openssh-server
network-manager
ca-certificates
iproute2
iputils-ping
dnsutils
traceroute
mtr-tiny

# Provisioning: fetch + sync + dotfiles
curl
wget
rsync
git
stow

# zboot runtime deps
zfsutils-linux
kexec-tools
debootstrap

# Disk + bootloader recovery
gdisk
parted
util-linux
e2fsprogs
dosfstools
ntfs-3g
cryptsetup
lvm2
nvme-cli
efibootmgr

# Editor + sudo + archive (bare minimum for editing configs and
# unpacking artifacts during recovery)
sudo
vim-nox
file
unzip
zstd
xz-utils
PACKAGES

if [ -n "$EXTRA_PACKAGES" ]; then
    echo "[live] adding extra packages"
    # Accept comma OR newline separation; strip blanks.
    echo "$EXTRA_PACKAGES" | tr ',' '\n' | sed '/^[[:space:]]*$/d' \
        >> config/package-lists/zboot.list.chroot
fi

# --- Bundled zboot CLI ---
# zboot-boot.efi is NOT copied here — the CLI binary already has it
# embedded (cli/src/cmd/efi.rs); inside the live env you get it via
# `zboot deploy` (which extracts the embedded copy lazily).  Keeping
# one source of truth.
mkdir -p config/includes.chroot_after_packages/usr/local/sbin
cp "$ZBOOT_BIN" config/includes.chroot_after_packages/usr/local/sbin/zboot
chmod 0755 config/includes.chroot_after_packages/usr/local/sbin/zboot
echo "[live] bundled: zboot CLI ($(stat -c%s "$ZBOOT_BIN") B; embeds zboot-boot.efi)"

if [ -n "$EXTRA_INCLUDES_DIR" ]; then
    [ -d "$EXTRA_INCLUDES_DIR" ] || { echo "EXTRA_INCLUDES_DIR=$EXTRA_INCLUDES_DIR not a dir" >&2; exit 1; }
    echo "[live] merging caller includes from $EXTRA_INCLUDES_DIR"
    cp -r "$EXTRA_INCLUDES_DIR"/. config/includes.chroot_after_packages/
fi

# --- Build ---
echo "[live] sudo lb build (slow — ~10-20min)"
sudo lb build

# --- Extract PXE files from ISO ---
LIVE_DIR="$OUTPUT_DIR/debianlive"
mkdir -p "$LIVE_DIR"
ISO=$(ls live-image-*.hybrid.iso)
MNT=$(mktemp -d)
sudo mount -o loop,ro "$ISO" "$MNT"
cp "$MNT"/live/{initrd.img,vmlinuz,filesystem.squashfs} "$LIVE_DIR/"
sudo umount "$MNT"
rmdir "$MNT"

# --- Build a Unified Kernel Image (UKI) of the live kernel + initrd ---
# Single-file chainload via iPXE: `chain debianlive.efi`.  zboot is
# UEFI-only (deploy creates GPT+ESP+efibootmgr entry — no BIOS path),
# so a UKI is the only kernel artifact we need to ship.  Bare
# vmlinuz/initrd.img get extracted to use as ukify inputs and then
# discarded (the test harness extracts them back from the UKI's PE
# sections on demand for direct-kernel-boot in QEMU).
#
# We bake `boot=live components` into the UKI's cmdline.  The squashfs
# fetch URL gets appended at chain time via iPXE's `imgargs` — it's
# environment-specific and would otherwise be hardcoded into every
# rebuild.
echo "[live] building Unified Kernel Image (debianlive.efi)..."
if command -v ukify >/dev/null; then
    # Invoke via the system python (where python3-pefile is installed),
    # not via the shebang.  `/usr/bin/env python3` resolves through PATH,
    # which on dev hosts often points at a pyenv/mise-managed python that
    # lacks the system's dist-packages (where python3-pefile lives) →
    # ukify dies with `ModuleNotFoundError: No module named 'pefile'`.
    /usr/bin/python3 "$(command -v ukify)" build \
        --linux="$LIVE_DIR/vmlinuz" \
        --initrd="$LIVE_DIR/initrd.img" \
        --cmdline="boot=live components" \
        --output="$LIVE_DIR/debianlive.efi" \
        2>&1 | tail -5
else
    # Fallback: objcopy --add-section against systemd's linuxx64.efi.stub.
    # ukify is in apt's systemd-ukify package; if missing, this path
    # composes the same UKI manually.
    STUB=$(ls /usr/lib/systemd/boot/efi/linuxx64.efi.stub 2>/dev/null || true)
    [ -n "$STUB" ] || { echo "[live] need either ukify (apt install systemd-ukify) or systemd-boot-efi" >&2; exit 1; }
    printf '%s\n' 'boot=live components' > "$LIVE_DIR/cmdline.txt"
    objcopy \
        --add-section .cmdline="$LIVE_DIR/cmdline.txt"  --change-section-vma .cmdline=0x30000 \
        --add-section .linux="$LIVE_DIR/vmlinuz"        --change-section-vma .linux=0x2000000 \
        --add-section .initrd="$LIVE_DIR/initrd.img"    --change-section-vma .initrd=0x3000000 \
        "$STUB" "$LIVE_DIR/debianlive.efi"
    rm -f "$LIVE_DIR/cmdline.txt"
fi

# Drop the bare files — UKI is now the only kernel artifact.
rm -f "$LIVE_DIR/vmlinuz" "$LIVE_DIR/initrd.img"

# --- iPXE menu ---
if [ -n "$GENERATE_MENU" ]; then
    cat > "$OUTPUT_DIR/menu.ipxe" <<'IPXE'
#!ipxe
# Generated by `zboot live`.  Chain from a parent menu (or directly
# from the iPXE shell):
#   chain ${boot-url}<dir-where-this-tree-was-rsynced>/menu.ipxe
#
# Two boot targets:
#   - `live`     — chainload the Debian Live UKI; runs `zboot deploy`
#                  in a working environment.
#   - `zboot-be` — chainload zboot-boot.efi alone; drops to the local
#                  BE menu so you can pick a deployed BE via PXE.

:menu
menu zboot — choose boot target
item live      Debian Live (install / recovery env)
item zboot-be  zboot-boot menu (boot a local BE)
item exit      Exit to iPXE shell
choose --default live --timeout 5000 selected && goto ${selected}

:live
# Load + args + boot as three separate steps.  `chain X` is shorthand
# for `kernel X + boot` (atomic) — `imgargs` after `chain` would run
# too late.  Splitting lets us pass the cmdline via UEFI LoadOptions.
#
# IMPORTANT: Linux EFI stub uses LoadOptions OR the baked .cmdline
# (whichever is non-empty) — it does NOT concatenate.  iPXE's imgargs
# becomes LoadOptions, so we must restate `boot=live components` here
# (the UKI's bake is just the disk-boot fallback).
imgfree
echo Booting Debian Live...
kernel debianlive/debianlive.efi
imgargs debianlive.efi boot=live components fetch=${boot-url}debianlive/filesystem.squashfs
boot

:zboot-be
# Bare UKI chain; zboot-boot has no `live.fetch` in its cmdline,
# so it falls through to disk-mode menu and shows local BEs.  No
# extra args → `chain` (= kernel + boot) is fine.
imgfree
echo Loading zboot-boot...
chain zboot-boot.efi

:exit
exit
IPXE
fi

echo
echo "[live] output tree at $OUTPUT_DIR/:"
[ -n "$GENERATE_MENU" ] && echo "  menu.ipxe                      ($(stat -c%s "$OUTPUT_DIR/menu.ipxe") B)"
echo "  debianlive/debianlive.efi      ($(stat -c%s "$LIVE_DIR/debianlive.efi") B)"
echo "  debianlive/filesystem.squashfs ($(stat -c%s "$LIVE_DIR/filesystem.squashfs") B)"
echo "  (zboot-boot.efi added by the CLI on its way out)"
echo
echo "[live] smoke-boot via QEMU:"
echo "  # Extract bare kernel/initrd from the UKI for direct-kernel boot:"
echo "  objcopy -O binary --only-section=.linux  $LIVE_DIR/debianlive.efi /tmp/vmlinuz"
echo "  objcopy -O binary --only-section=.initrd $LIVE_DIR/debianlive.efi /tmp/initrd.img"
echo "  ( cd $LIVE_DIR && python3 -m http.server 8000 ) &"
echo "  qemu-system-x86_64 \\"
echo "      -kernel /tmp/vmlinuz -initrd /tmp/initrd.img \\"
echo "      -append 'boot=live fetch=http://10.0.2.2:8000/filesystem.squashfs console=ttyS0,115200' \\"
echo "      -m 4G -nographic \\"
echo "      -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net,netdev=n0"
echo "  sshpass -p live ssh -p 2222 user@127.0.0.1"
