#!/bin/bash
# Build the factory BE tar via host-side debootstrap (no QEMU).  With no
# EXTRA_PACKAGES this produces zboot's *stock* factory tar — kernel +
# zfs.ko via DKMS + sshd binary + NetworkManager + ESP tooling +
# firmware-linux — used as the test fixture for `scripts/*.sh`.
# Downstream wrappers pass EXTRA_PACKAGES to layer additional
# production packages on top.
#
# Faster than the QEMU mode (~5min vs ~12min) but needs root + debootstrap
# on the host.  Suitable for any Debian (or Debian-derivative) box.  CI
# without ZFS/QEMU can use this too; cross-builds (different arch) need QEMU.
#
# Notes on chroot DKMS:
#   `apt install linux-image-amd64 zfs-dkms` installs the kernel package
#   first; its postinst triggers `dkms autoinstall -k <chroot-kver>`,
#   which compiles zfs.ko against the chroot's headers (not the host's).
#   So host kernel/headers are irrelevant — the chroot is self-contained.
#
# Env (defaults match the QEMU mode):
#   FACTORY_TAR       output (default ~/.cache/zboot/factory.tar.zst)
#   ZBOOT_BIN         CLI binary (default <repo>/target/release/zboot)
#   DEBIAN_SUITE      debian release (default trixie)
#   DEBIAN_MIRROR     apt mirror (default http://deb.debian.org/debian)
#   EXTRA_PACKAGES    space-separated extras forwarded as caller-supplied
#                     additions to the apt install.  Empty by default.
#   NO_HEADERS        if "1": purge linux-headers + DKMS sources after the
#                     in-chroot zfs.ko compile.  Saves ~300MB but the BE
#                     can't auto-rebuild zfs.ko on kernel updates — manual
#                     apt install linux-headers-amd64 + dpkg-reconfigure
#                     zfs-dkms becomes the operator's responsibility.
#                     Test/smoke-only.  Empty by default.
#   ZFS_FROM_SUITE    apt suite to pin zfs-dkms (and siblings) from, in
#                     case DEBIAN_SUITE's zfs is too old for its kernel.
#                     E.g. when DEBIAN_SUITE=testing's kernel ships ahead
#                     of testing's zfs-dkms, set ZFS_FROM_SUITE=sid (sid
#                     usually has the newer zfs that compiles).  Adds the
#                     suite as an extra apt source, with apt-pinning so
#                     only zfs+nvpair+uutil packages come from it.  Empty
#                     by default (zfs comes from DEBIAN_SUITE).
set -euo pipefail

# Sudo's env_reset strips PATH down to /usr/local/sbin:/usr/local/bin:
# /usr/sbin:/usr/bin:/sbin:/bin (the secure_path).  That's actually fine
# in itself — debootstrap lives at /usr/sbin/debootstrap — but if the
# operator ran us under a more restrictive sudo policy, ensure the
# canonical sbin paths are present.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}
export PATH

ZBOOT_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
FACTORY_TAR=${FACTORY_TAR:-$HOME/.cache/zboot/factory.tar.zst}
mkdir -p "$(dirname "$FACTORY_TAR")"
ZBOOT_BIN=${ZBOOT_BIN:-$ZBOOT_REPO/target/release/zboot}
DEBIAN_SUITE=${DEBIAN_SUITE:-trixie}
DEBIAN_MIRROR=${DEBIAN_MIRROR:-http://deb.debian.org/debian}
EXTRA_PACKAGES=${EXTRA_PACKAGES:-}
NO_HEADERS=${NO_HEADERS:-}
ZFS_FROM_SUITE=${ZFS_FROM_SUITE:-}

[ "$(id -u)" -eq 0 ] || { echo "needs root: sudo $0" >&2; exit 1; }
command -v debootstrap >/dev/null || { echo "needs debootstrap (apt install debootstrap)" >&2; exit 1; }
[ -f "$ZBOOT_BIN" ] || { echo "missing ZBOOT_BIN=$ZBOOT_BIN" >&2; exit 1; }

STAGE=$(mktemp -d /tmp/zboot-minimal-stage-XXXXXX)
# mktemp -d defaults to mode 0700.  Once `tar -cf` captures STAGE's `./`
# entry, the deploy-extracted rootfs becomes mode 0700, which non-root
# system services (dbus → messagebus, NetworkManager, etc.) cannot
# traverse — they fail with status=200/CHDIR and the boot is unusable.
# Fix at the source: make STAGE the same 755 every Linux root is.
chmod 755 "$STAGE"
cleanup() {
    set +e
    if [ -d "$STAGE" ]; then
        # umount nested mounts first (dev/pts, dev/shm) before parent dev tmpfs.
        umount "$STAGE/dev/shm" 2>/dev/null
        umount "$STAGE/dev/pts" 2>/dev/null
        umount "$STAGE/dev"     2>/dev/null
        umount "$STAGE/proc"    2>/dev/null
        umount "$STAGE/sys"     2>/dev/null
        rm -rf "$STAGE"
    fi
}
trap cleanup EXIT

echo "=== debootstrap $DEBIAN_SUITE ==="
debootstrap \
    --include=systemd,systemd-sysv,ca-certificates,locales \
    --components=main,contrib,non-free,non-free-firmware \
    "$DEBIAN_SUITE" "$STAGE" "$DEBIAN_MIRROR"

echo "=== chroot mounts (tmpfs /dev + bind /proc /sys) ==="
# /dev is a SEPARATE tmpfs with hand-created minimal nodes, NOT a bind
# of the host's devtmpfs.  Bind-mounting host /dev shares inodes — chroot
# postinsts (initramfs-tools, kernel, udev rules) can `rm /dev/null` and
# `mknod /dev/null` and the host sees the change too (devtmpfs is one
# kernel-managed filesystem).  Result: host's /dev/null becomes a regular
# file mid-build → every shell redirect on the host breaks until manual
# `mknod /dev/null c 1 3`.  Standard chroot practice (nspawn, lxc) is a
# private tmpfs with explicit minimum nodes; we follow suit.
mount -t tmpfs -o mode=755,size=64M tmpfs "$STAGE/dev"
mknod -m 0666 "$STAGE/dev/null"    c 1 3
mknod -m 0666 "$STAGE/dev/zero"    c 1 5
mknod -m 0666 "$STAGE/dev/full"    c 1 7
mknod -m 0666 "$STAGE/dev/random"  c 1 8
mknod -m 0666 "$STAGE/dev/urandom" c 1 9
mknod -m 0666 "$STAGE/dev/tty"     c 5 0
mknod -m 0600 "$STAGE/dev/console" c 5 1
mkdir -m 0755 "$STAGE/dev/pts"
mkdir -m 1777 "$STAGE/dev/shm"
ln -sf /proc/self/fd "$STAGE/dev/fd"
ln -sf /proc/self/fd/0 "$STAGE/dev/stdin"
ln -sf /proc/self/fd/1 "$STAGE/dev/stdout"
ln -sf /proc/self/fd/2 "$STAGE/dev/stderr"
# devpts: newinstance gives chroot its own pty namespace (also isolated).
mount -t devpts -o newinstance,ptmxmode=0666,mode=620,gid=5 devpts "$STAGE/dev/pts"
mount -t tmpfs -o mode=1777 tmpfs "$STAGE/dev/shm"
# /proc and /sys can be bind-mounted (no inode mutation risk; postinsts
# read but don't `rm`) but we still keep events private to avoid leaking
# any subsequent mount events back to host.
mount --bind /proc "$STAGE/proc" && mount --make-private "$STAGE/proc"
mount --bind /sys  "$STAGE/sys"  && mount --make-private "$STAGE/sys"

echo "=== chroot install: kernel + zfs-dkms + sshd + networkd ==="
# `linux-image-amd64` postinst triggers dkms against the chroot's kernel.
# Order matters: install kernel + zfs-dkms in one apt call so dkms sees
# the kernel as a build target during its autoinstall.
chroot "$STAGE" bash -e <<CHROOT
export DEBIAN_FRONTEND=noninteractive

cat > /etc/apt/sources.list <<EOF
deb $DEBIAN_MIRROR $DEBIAN_SUITE main contrib non-free non-free-firmware
deb $DEBIAN_MIRROR $DEBIAN_SUITE-updates main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security ${DEBIAN_SUITE}-security main contrib non-free non-free-firmware
EOF

# Optional: pull zfs-dkms (+ nvpair/uutil siblings) from a different suite.
# Used when DEBIAN_SUITE's zfs is too old for its own kernel (testing's
# kernel ships ahead of testing's zfs-dkms; sid catches up first).
# Pin so only zfs-related packages come from this suite — everything else
# stays on DEBIAN_SUITE.
if [ -n "$ZFS_FROM_SUITE" ]; then
    cat >> /etc/apt/sources.list <<EOF
deb $DEBIAN_MIRROR $ZFS_FROM_SUITE main contrib non-free non-free-firmware
EOF
    cat > /etc/apt/preferences.d/zfs-pin <<EOF
Package: *
Pin: release n=$ZFS_FROM_SUITE
Pin-Priority: 100

Package: zfs-dkms zfs-initramfs zfsutils-linux libzfs* libnvpair* libuutil* libzpool* spl-dkms
Pin: release n=$ZFS_FROM_SUITE
Pin-Priority: 990
EOF
fi

apt-get update -qq
# Base package set — minimum for ZFS root + ESP install + first boot.
# linux-image-amd64 postinst triggers dkms autoinstall against the
# chroot kver; zfs.ko gets compiled against the chroot installed headers.
apt-get install -y --no-install-recommends \\
    linux-image-amd64 linux-headers-amd64 \\
    zfsutils-linux zfs-dkms zfs-initramfs \\
    openssh-server \\
    network-manager dosfstools efibootmgr \\
    firmware-linux || {
    echo "=== apt install failed — dumping dkms make.log(s) ==="
    find /var/lib/dkms -name make.log -print -exec cat {} \\;
    echo "=== end make.log dump ==="
    exit 1
}

# Caller-supplied extras (downstream wrappers layer additional packages here).
if [ -n "$EXTRA_PACKAGES" ]; then
    echo "=== install extras: $EXTRA_PACKAGES ==="
    # shellcheck disable=SC2086  # word splitting intentional
    apt-get install -y --no-install-recommends $EXTRA_PACKAGES
fi

# openssh-server's apt postinst auto-generates /etc/ssh/ssh_host_*_key
# AND enables ssh.service.  For a host-agnostic base BE we want
# neither — host keys are host-specific (per-host overlay or live
# build provides them), and enabling sshd before host keys + config
# exist is meaningless.  Strip both, leaving just the binary in
# /usr/sbin/sshd ready for the consumer image to wire up.
rm -f /etc/ssh/ssh_host_*
systemctl disable ssh

# NetworkManager's apt postinst already enabled NetworkManager.service,
# which auto-DHCPs every unmanaged ethernet on first boot.  No
# systemd-networkd config in the BE — it would race NM for interface
# ownership and silently shadow per-host overlay nmconnection files.
# Production network config rides through NM via per-host overlays
# (e.g. /etc/NetworkManager/system-connections/* dropped via `zboot overlay`).

# Optional: purge headers + DKMS sources to slim the tar (~300MB saved).
# The compiled zfs.ko stays — it was built above against the chroot's
# kernel.  Trade: kernel updates won't auto-rebuild zfs.ko (operator
# must manually re-install headers + reconfigure dkms).  Use for the
# stock/test factory tar, not for production tars with live-system
# update expectations.
if [ "$NO_HEADERS" = "1" ]; then
    echo "=== purge headers + dkms sources (NO_HEADERS=1) ==="
    apt-get purge -y --auto-remove \\
        'linux-headers-*' linux-libc-dev \\
        gcc cpp gcc-* cpp-* \\
        libgcc-*-dev libstdc++-*-dev || true
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    rm -rf /usr/src/linux-headers-* /usr/src/zfs-* /var/lib/dkms/zfs/*/source
fi
CHROOT

echo "=== drop zboot CLI into /usr/local/sbin/ ==="
install -m 0755 "$ZBOOT_BIN" "$STAGE/usr/local/sbin/zboot"

echo "=== unmount ==="
# Order matters: nested mounts inside /dev (pts, shm) before the dev tmpfs.
umount "$STAGE/dev/shm"
umount "$STAGE/dev/pts"
umount "$STAGE/dev"
umount "$STAGE/proc"
umount "$STAGE/sys"

if [ -n "$EXTRA_PACKAGES" ]; then
    label="factory"
else
    label="stock"
fi

echo "=== capture rootfs as $FACTORY_TAR ==="
tar --xattrs --xattrs-include='*' --acls --zstd -cf "$FACTORY_TAR" -C "$STAGE" .

echo
echo "✓ $label tar ready: $FACTORY_TAR ($(du -h "$FACTORY_TAR" | cut -f1))"
echo "  use: zboot deploy --target /dev/X --hostname HOST --source 'tar://$FACTORY_TAR'"
