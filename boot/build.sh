#!/bin/bash
# boot/build.sh — assemble the `zboot-boot` initrd + kernel pair, then
# fold them into a Unified Kernel Image (UKI) — `zboot-boot.efi`.
#
# Outputs (under boot/out/):
#   vmlinuz           pinned debian linux-image-amd64 (raw)
#   initrd.img.zst    cpio archive containing zboot-boot as PID 1, plus
#                     zfs/zpool + their .so closure, kexec-tools, the
#                     bundled OpenZFS kernel modules, and busybox.
#   zboot-boot.efi    UEFI bundle (Unified Kernel Image): systemd's
#                     `linuxx64.efi.stub` carrying `vmlinuz` + the
#                     initrd + a baked-in cmdline as PE sections. QEMU
#                     + OVMF boots this directly. Real hardware loads
#                     it via `efibootmgr` (see boot/install.sh).
#
# Two artifacts are produced: the {vmlinuz, initrd.img.zst} pair AND
# the UKI bundle wrapping them. UEFI boots the bundle directly; the
# pair stays on disk because the kexec scenario test drives QEMU via
# `-kernel` / `-initrd`.
#
# Two ways to run:
#
#   $ podman build -t zboot-boot-build -f boot/Containerfile boot/
#   $ podman run --rm -v "$(pwd)":/work -w /work zboot-boot-build \
#         boot/build.sh
#
# Or on a host that already has the required toolchain (debian
# trixie + rust 1.95 + kexec-tools + zfs-utils + zfsutils-linux +
# linux-image-amd64 + cpio + zstd):
#
#   $ ./boot/build.sh
#
# Prerequisites checked at start. The script is shellcheck-clean.
#
# Decisions:
#
# - **Kernel pin.** We use `linux-image-amd64` from the same debian
#   trixie snapshot.
#   Locating the matching vmlinuz by querying `dpkg -L` rather than
#   shelling out to `linux-version` keeps us host-toolchain-light.
#
# - **Initrd content.** Bundles `zfs`, `zpool`, `mount.zfs`, `kexec`,
#   their .so closure (via boot/lddtree.sh), the OpenZFS .ko modules
#   for the bundled kernel, busybox (for /bin/sh + standard tools),
#   and the `zboot-boot` Rust binary as `/init`.
#
# - **Compression.** zstd -19 over plain gzip — same compression
#   class debian's `update-initramfs` defaults to in trixie.
#
# - **EFI bundle.** Prefer `ukify` from systemd-ukify; fall
#   back to manual `objcopy --add-section` against the
#   `linuxx64.efi.stub` from systemd-boot-efi if ukify is missing.
#   Both routes embed `vmlinuz` (`.linux` PE section), the initrd
#   (`.initrd`), and the baked-in cmdline (`.cmdline`) into one PE
#   binary that UEFI firmware boots natively. The cmdline default is
#   `console=ttyS0 console=tty0` so QEMU's `-nographic` and a real
#   monitor both surface the boot log; the actual `root=` for the
#   chosen BE is composed by `kexec::handoff` and never lives on this
#   bundle's stub.
#
# - **Static musl?** We attempt x86_64-unknown-linux-musl and fall
#   back to the host's gnu target with a banner. The initrd carries
#   a glibc closure either way (`zfs`/`zpool` are dynamic), so a
#   glibc init binary is fine.

set -euo pipefail

usage() {
    cat <<'USAGE'
boot/build.sh — assemble zboot-boot's kernel + initrd pair

Usage:
  boot/build.sh                    build into boot/out/ (skips if up to date)
  boot/build.sh --force            rebuild even if outputs look fresh
  boot/build.sh --check            print prereq report and exit
  boot/build.sh --clean            wipe boot/out/ and exit

Environment:
  ZBOOT_BUILD_OUT      output dir       (default: boot/out)
  ZBOOT_BUILD_KEEP     keep stage dir   (default: 0)
  ZBOOT_BUILD_TARGET   cargo target     (default: try musl, fall back to host)
USAGE
}

# Resolve repo root from the script's location so the script works
# from any cwd.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${ZBOOT_BUILD_OUT:-${SCRIPT_DIR}/out}"
STAGE_DIR=""
TARGET="${ZBOOT_BUILD_TARGET:-}"

# Non-interactive shells (cargo, CI, our own automation) often strip
# /sbin + /usr/sbin from PATH.  We need depmod (kmod pkg, /usr/sbin),
# objcopy, and friends — without depmod the resulting initrd has no
# modules.dep, modprobe zfs fails silently in PID 1, and init hangs.
case ":${PATH}:" in *:/sbin:*) ;; *) PATH="/sbin:${PATH}" ;; esac
case ":${PATH}:" in *:/usr/sbin:*) ;; *) PATH="/usr/sbin:${PATH}" ;; esac
export PATH

cleanup() {
    if [[ -n "${STAGE_DIR}" && -d "${STAGE_DIR}" && "${ZBOOT_BUILD_KEEP:-0}" != "1" ]]; then
        rm -rf "${STAGE_DIR}"
    fi
}
trap cleanup EXIT

log() { printf '[zboot-boot/build] %s\n' "$*" >&2; }

# Locate the systemd EFI stub binary on the host. Debian ships it under
# /usr/lib/systemd/boot/efi/linuxx64.efi.stub (systemd-boot-efi pkg).
# Echoes the path on success; empty + rc=1 on miss.
_find_efi_stub() {
    local candidates=(
        /usr/lib/systemd/boot/efi/linuxx64.efi.stub
        /usr/lib/systemd-boot/linuxx64.efi.stub
        /lib/systemd/boot/efi/linuxx64.efi.stub
    )
    local p
    for p in "${candidates[@]}"; do
        if [[ -f "${p}" ]]; then
            printf '%s' "${p}"
            return 0
        fi
    done
    return 1
}

# Prerequisite check. Writes a report to stdout; exits non-zero if a
# hard requirement is missing.
check_prereqs() {
    local missing=0
    local tool
    local hard_tools=(cargo find cpio zstd ldd readelf objcopy)
    local soft_tools=(zfs zpool kexec)

    for tool in "${hard_tools[@]}"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            printf '  MISSING (hard): %s\n' "${tool}"
            missing=$((missing + 1))
        else
            printf '  ok:             %s -> %s\n' "${tool}" "$(command -v "${tool}")"
        fi
    done

    for tool in "${soft_tools[@]}"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            printf '  MISSING (initrd content): %s\n' "${tool}"
            missing=$((missing + 1))
        else
            printf '  ok (bundle):    %s -> %s\n' "${tool}" "$(command -v "${tool}")"
        fi
    done

    # Kernel image (pinned by debian's linux-image-amd64 meta-package).
    if ! ls /boot/vmlinuz-*-amd64 >/dev/null 2>&1; then
        printf '  MISSING: a debian /boot/vmlinuz-*-amd64 (apt install linux-image-amd64)\n'
        missing=$((missing + 1))
    else
        printf '  ok:             /boot/vmlinuz-*-amd64\n'
    fi

    # Cargo target sniff.
    if rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
        printf '  ok:             rust target x86_64-unknown-linux-musl\n'
    else
        printf '  note:           x86_64-unknown-linux-musl not installed\n'
        # shellcheck disable=SC2016  # backticks here are literal documentation
        printf '                  (install: `rustup target add x86_64-unknown-linux-musl`)\n'
        printf '                  build.sh will fall back to host target.\n'
    fi

    # EFI bundle. Either `ukify` or the manual `objcopy` route
    # works; we check for both and prefer ukify. The `linuxx64.efi.stub`
    # ships with debian's `systemd-boot-efi` package.
    local stub_path
    stub_path="$(_find_efi_stub || true)"
    if command -v ukify >/dev/null 2>&1; then
        printf '  ok:             ukify -> %s\n' "$(command -v ukify)"
    elif [[ -n "${stub_path}" ]]; then
        printf '  ok:             manual objcopy route (stub: %s)\n' "${stub_path}"
    else
        printf '  MISSING (EFI bundle): ukify OR linuxx64.efi.stub\n'
        printf '                        (apt install systemd-ukify systemd-boot-efi)\n'
        missing=$((missing + 1))
    fi

    if [[ ${missing} -gt 0 ]]; then
        printf '\n%d hard prerequisite(s) missing.\n' "${missing}" >&2
        return 1
    fi
    printf '\nAll required tools present.\n'
    return 0
}

FORCE=0
case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --check) check_prereqs; exit $? ;;
    --clean)
        log "removing ${OUT_DIR}"
        rm -rf "${OUT_DIR}"
        exit 0
        ;;
    --force) FORCE=1 ;;
    "") ;;
    *) usage; exit 2 ;;
esac

mkdir -p "${OUT_DIR}"

# Short-circuit if ${EFI_OUT} is newer than every workspace input we
# stage from.  Skips the ~10-30s restage on no-op `cargo build` runs;
# cli/build.rs invokes us unconditionally and relies on this.
#
# Tracks only workspace-side inputs (boot/build.sh itself, boot/src,
# boot/Cargo.toml, boot/lddtree.sh).  Host-side inputs (running kernel,
# /lib/modules/<kver>, zfs userspace) are not tracked — run
# `boot/build.sh --force` (or `--clean` then rebuild) after a kernel or
# zfs upgrade.
_efi_out="${OUT_DIR}/zboot-boot.efi"
if [[ "${FORCE}" != "1" && -f "${_efi_out}" ]]; then
    _stale=0
    _check_inputs=(
        "${SCRIPT_DIR}/build.sh"
        "${SCRIPT_DIR}/lddtree.sh"
        "${SCRIPT_DIR}/Cargo.toml"
    )
    while IFS= read -r -d '' f; do
        _check_inputs+=("$f")
    done < <(find "${SCRIPT_DIR}/src" -type f -print0 2>/dev/null)
    for f in "${_check_inputs[@]}"; do
        if [[ -f "$f" && "$f" -nt "${_efi_out}" ]]; then
            _stale=1
            break
        fi
    done
    if [[ "${_stale}" == "0" ]]; then
        log "up to date: ${_efi_out} (pass --force to rebuild, --clean to wipe)"
        exit 0
    fi
fi

# ----- step 1: build zboot-boot -----------------------------------------------

log "step 1: building zboot-boot"

cd "${REPO_ROOT}"

# Pick a target: prefer musl static, fall back to the host's gnu
# target if musl isn't installed. A glibc-linked init works fine
# inside the initrd as long as the matching libc.so.6 is in the
# closure (which lddtree.sh handles).
if [[ -z "${TARGET}" ]]; then
    if rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
        TARGET="x86_64-unknown-linux-musl"
    else
        log "x86_64-unknown-linux-musl not installed; falling back to host target"
        log "  (run \`rustup target add x86_64-unknown-linux-musl\` for a static binary)"
        TARGET=""
    fi
fi

if [[ -n "${TARGET}" ]]; then
    cargo build -p zboot-boot --release --target "${TARGET}"
    BUILT_BIN="${REPO_ROOT}/target/${TARGET}/release/zboot-boot"
else
    cargo build -p zboot-boot --release
    BUILT_BIN="${REPO_ROOT}/target/release/zboot-boot"
fi

if [[ ! -x "${BUILT_BIN}" ]]; then
    log "FATAL: zboot-boot binary not found at ${BUILT_BIN}"
    exit 1
fi
log "  built: ${BUILT_BIN}"

# ----- step 2: stage the initrd tree ------------------------------------------

log "step 2: staging initrd tree"

STAGE_DIR="$(mktemp -d /tmp/zboot-initrd-XXXXXX)"
mkdir -p \
    "${STAGE_DIR}"/{bin,sbin,etc,proc,sys,dev,run,tmp,mnt,lib,lib64} \
    "${STAGE_DIR}"/usr/{bin,sbin,lib,lib64} \
    "${STAGE_DIR}/zboot/be-mount"

# busybox provides /bin/sh and a coreutils set.
if command -v busybox >/dev/null 2>&1; then
    cp "$(command -v busybox)" "${STAGE_DIR}/bin/busybox"
    for cmd in sh ash mount umount mkdir cat ls ln cp mv rm echo printf sleep \
               poweroff reboot insmod modprobe lsmod dmesg sed grep awk head tail \
               find mknod mkfifo true false hexdump dd losetup blkid sync setsid \
               dirname basename chroot vi; do
        ln -sf busybox "${STAGE_DIR}/bin/${cmd}"
    done
else
    log "  WARNING: busybox not found; recovery shell will be unavailable"
fi

# zboot-boot as PID 1.
cp "${BUILT_BIN}" "${STAGE_DIR}/init"
chmod +x "${STAGE_DIR}/init"

# zboot CLI is NO LONGER staged into the initrd. The bootloader shell's
# mutating verbs (chroot/cmdline/rollback/drop) call
# `zboot_cli::cmd::*::run` library functions directly — `zboot-boot`
# depends on the `zboot-cli` crate with `default-features = false`, so
# the verb code is statically linked without the embedded
# `zboot-boot.efi` bytes. This breaks the embed→initrd→EFI feedback
# loop that previously inflated the bundle on each rebuild.
mkdir -p "${STAGE_DIR}/sbin"

# zfs/zpool/mount.zfs/kexec userland + their .so closure. lddtree.sh
# walks each binary's dynamic deps and copies into the staged tree
# at the same on-disk paths so ld.so finds them.  The init binary
# (zboot-boot) is included so its own deps land too — libgcc_s.so.1
# (panic=unwind) isn't picked up by zfs/zpool's closure alone, so
# omitting init from this set crashes /init with ENOENT at boot in
# the gnu-target fallback path.
BUNDLE_BINS=("${STAGE_DIR}/init")
for prog in zfs zpool mount.zfs kexec; do
    if path="$(command -v "${prog}" 2>/dev/null)"; then
        BUNDLE_BINS+=("${path}")
    else
        log "  WARNING: ${prog} not found on PATH; not bundled"
    fi
done

if [[ ${#BUNDLE_BINS[@]} -gt 0 ]]; then
    "${SCRIPT_DIR}/lddtree.sh" --root "${STAGE_DIR}" "${BUNDLE_BINS[@]}"
fi

# udev — needed for deterministic device readiness. zfsbootmenu's
# dracut module does this implicitly via dracut's `initqueue/settled`;
# we bundle udevd + udevadm + rules ourselves so preinit can call
# `udevadm settle` before zpool import.
log "  bundling udev (udevd + udevadm + rules)"
UDEV_BINS=()
for cand in /lib/systemd/systemd-udevd /usr/lib/systemd/systemd-udevd; do
    [[ -x "$cand" ]] && UDEV_BINS+=("$cand")
done
if path="$(command -v udevadm 2>/dev/null)"; then
    UDEV_BINS+=("$path")
fi
if [[ ${#UDEV_BINS[@]} -gt 0 ]]; then
    "${SCRIPT_DIR}/lddtree.sh" --root "${STAGE_DIR}" "${UDEV_BINS[@]}"
    # udev rules — busybox doesn't ship udevd, so we depend on the
    # debian package and copy its rules verbatim.
    if [[ -d /lib/udev/rules.d ]]; then
        mkdir -p "${STAGE_DIR}/lib/udev/rules.d"
        cp -a /lib/udev/rules.d/. "${STAGE_DIR}/lib/udev/rules.d/" 2>/dev/null || true
    fi
    # The udevd helper binaries (e.g. ata_id, scsi_id) live under
    # /lib/udev. Copy whatever's there so device-id rules can resolve.
    if [[ -d /lib/udev ]]; then
        find /lib/udev -maxdepth 1 -type f -executable -print0 2>/dev/null | \
            xargs -0r -I{} sh -c '
                src="$1"; dst_root="$2";
                rel="${src#/}";
                mkdir -p "$dst_root/$(dirname "$rel")";
                cp -L "$src" "$dst_root/$rel" 2>/dev/null || true
            ' _ {} "${STAGE_DIR}"
    fi
else
    log "  WARNING: udev not found in container; preinit will fall back to poll-wait"
fi

# Symlink the staged binaries into /sbin/ as well. The kernel-default
# PATH for init is just `/sbin:/bin`, but lddtree.sh keeps them at
# their on-disk paths (typically /usr/sbin/). Without a /sbin/ alias
# zboot-boot's `Command::new("zpool")` falls through with ENOENT and
# discovery silently degrades to fake-data mode — observed on first
# UEFI boot. Symlinks are byte-cheap and side-effect-free.
mkdir -p "${STAGE_DIR}/sbin"
for prog in zfs zpool mount.zfs kexec; do
    for src_dir in usr/sbin sbin usr/bin bin; do
        src="${STAGE_DIR}/${src_dir}/${prog}"
        if [[ -e "$src" ]]; then
            ln -sf "/${src_dir}/${prog}" "${STAGE_DIR}/sbin/${prog}"
            break
        fi
    done
done

# Kernel modules — pull the running kernel's zfs.ko + a stable set
# of disk/virtio modules so the initrd can mount the BE dataset.
KVER=""
if [[ -d /lib/modules ]]; then
    # Pick the highest-version kernel that has BOTH a matching
    # /boot/vmlinuz-$KVER AND a populated /lib/modules/$KVER dir.
    # A bare /lib/modules/X without a kernel (e.g. apt left stale
    # modules after a downgrade) would otherwise be picked and
    # produce a kernel/modules mismatch — zfs.ko fails to load,
    # discover finds no pools.
    # shellcheck disable=SC2010
    for cand in $(ls -1 /lib/modules 2>/dev/null | grep -- '-amd64$' | sort -Vr); do
        if [[ -f "/boot/vmlinuz-${cand}" ]]; then
            KVER="${cand}"
            break
        fi
    done
    if [[ -z "${KVER}" ]]; then
        # No paired kernel found — fall back to highest module dir
        # (preserves prior behaviour, will warn on mismatch downstream).
        KVER="$(ls -1 /lib/modules 2>/dev/null | grep -- '-amd64$' | sort -V | tail -1)"
        log "  WARNING: no /boot/vmlinuz-* matches any /lib/modules/* — using KVER=${KVER}, may mismatch"
    fi
fi
if [[ -n "${KVER}" && -d "/lib/modules/${KVER}" ]]; then
    log "  bundling kernel modules from /lib/modules/${KVER}"
    DEST_MOD="${STAGE_DIR}/lib/modules/${KVER}"
    mkdir -p "${DEST_MOD}/kernel"
    # Resolve full transitive dep chains via host modprobe instead of
    # hand-tracking every newly-introduced module split (nvme-auth →
    # hkdf → ..., ahci → libata → scsi_mod → ..., sdhci-pci → cqhci
    # → sdhci-uhs2 → ...). Each kernel update reshuffles these; the
    # seed list below is just the leaf modules preinit asks for.
    SEED_MODS=(
        zfs
        nvme ahci
        usb-storage uas
        # USB host controllers + HID class so the bootloader menu/shell
        # accepts USB-keyboard input on hosts without PS/2 (most modern
        # desktops/servers).  Without these, the kernel claims the USB
        # bus but no driver answers — keyboard goes dead at firmware
        # handoff; serial console + PS/2 still work.  Compare with
        # zfsbootmenu, which gets these via dracut's hostonly=no driver
        # sweep.  modprobe pulls in usbcore/hid/input transitively.
        xhci_pci xhci_hcd ehci_pci ehci_hcd ohci_pci ohci_hcd uhci_hcd
        usbhid hid-generic
        mmc_block sdhci-pci sdhci-acpi
        virtio_blk virtio_pci virtio_pci_modern_dev virtio_pci_legacy_dev
        sd_mod ext4
        crc32c-intel crc32c-generic
    )
    MODPROBE_BIN="$(command -v modprobe)"
    if [[ -z "${MODPROBE_BIN}" ]]; then
        log "  FATAL: modprobe not on PATH; install kmod"
        exit 1
    fi
    # Per-seed invocation: `modprobe --show-depends mod1 mod2` treats
    # `mod2` as a *parameter* of mod1 (not a second seed), and one
    # missing module aborts the whole batch with FATAL. Loop instead;
    # 2>/dev/null swallows the "not found" stderr for absent seeds
    # (e.g. `crc32c-intel` on AMD).
    declare -A _staged_mods=()
    for seed in "${SEED_MODS[@]}"; do
        while IFS= read -r line; do
            [[ "$line" =~ ^insmod\ +([^[:space:]]+) ]] || continue
            ko_src="${BASH_REMATCH[1]}"
            [[ -n "${_staged_mods[$ko_src]:-}" ]] && continue
            _staged_mods["$ko_src"]=1
            rel="${ko_src#/lib/modules/}"
            ko_dst="${STAGE_DIR}/lib/modules/${rel}"
            mkdir -p "$(dirname "$ko_dst")"
            cp -a "$ko_src" "$ko_dst"
        done < <("$MODPROBE_BIN" --show-depends -S "${KVER}" "$seed" 2>/dev/null)
    done
    log "  staged ${#_staged_mods[@]} kernel modules (incl. transitive deps)"
    # depmod's required inputs — modules.order tells it module load
    # order; modules.builtin{,.modinfo} let it skip emitting deps on
    # in-kernel-builtin symbols (e.g. if crc32c is builtin, depmod
    # without this file may emit a dep on the non-existent crc32c.ko,
    # making modprobe zfs fail later). Missing → silent-but-broken
    # modules.dep → PID-1 `modprobe zfs` no-ops with no error.
    for meta in modules.order modules.builtin modules.builtin.modinfo; do
        if [[ -f "/lib/modules/${KVER}/${meta}" ]]; then
            cp -a "/lib/modules/${KVER}/${meta}" "${DEST_MOD}/${meta}"
        else
            log "  WARNING: /lib/modules/${KVER}/${meta} missing on host — depmod may produce a degraded modules.dep"
        fi
    done

    # Decompress .ko.xz → .ko. Busybox modprobe (what the initrd uses)
    # does NOT decompress xz; it tries to insmod the raw xz bytes,
    # which the kernel rejects with "invalid ELF header magic". We pay
    # the decompressed size (a few MB) to make modules loadable. depmod
    # re-walks the tree after this so modules.dep references .ko, not
    # .ko.xz.
    if command -v unxz >/dev/null 2>&1; then
        find "${DEST_MOD}" -name "*.ko.xz" -exec unxz -f {} \;
    else
        log "  WARNING: unxz not found — initrd modules remain .ko.xz; busybox modprobe will fail to load them"
    fi

    # depmod generates modules.dep — without it the initrd's modprobe
    # can't resolve zfs.ko deps → ZFS never loads → discovery returns
    # empty → init hangs.  Warn loudly on miss rather than silently
    # producing a broken initrd (the previous `|| true` swallowed it).
    if command -v depmod >/dev/null 2>&1; then
        depmod -b "${STAGE_DIR}" "${KVER}" \
            || log "  WARNING: depmod failed; initrd will lack modules.dep → PID-1 modprobe zfs will fail"
    else
        log "  WARNING: depmod not found (install kmod) — initrd will lack modules.dep → PID-1 modprobe zfs will fail"
    fi
else
    log "  note: no /lib/modules/<kver>-amd64; initrd will not have zfs.ko"
    log "        (the kexec scenario test skips when the initrd lacks zfs)"
fi

# ----- step 3: pack the cpio --------------------------------------------------

log "step 3: packing initrd cpio"

INITRD_OUT="${OUT_DIR}/initrd.img.zst"
( cd "${STAGE_DIR}" && find . -print0 | cpio --null --create --format=newc 2>/dev/null ) \
    | zstd -19 -T0 -q -o "${INITRD_OUT}.tmp" -
mv "${INITRD_OUT}.tmp" "${INITRD_OUT}"
log "  wrote ${INITRD_OUT} ($(stat -c '%s' "${INITRD_OUT}") bytes)"

# ----- step 4: copy the kernel image ------------------------------------------

log "step 4: copying kernel"

KERNEL_SRC=""
if [[ -n "${KVER}" && -f "/boot/vmlinuz-${KVER}" ]]; then
    KERNEL_SRC="/boot/vmlinuz-${KVER}"
else
    # Fallback: highest-version vmlinuz on the system.
    # shellcheck disable=SC2012  # globbed kernel filenames sort cleanly under -V
    KERNEL_SRC="$(ls -1 /boot/vmlinuz-*-amd64 2>/dev/null | sort -V | tail -1 || true)"
fi

if [[ -z "${KERNEL_SRC}" || ! -f "${KERNEL_SRC}" ]]; then
    log "FATAL: no /boot/vmlinuz-*-amd64 found; install linux-image-amd64"
    exit 1
fi

cp -L "${KERNEL_SRC}" "${OUT_DIR}/vmlinuz"
log "  wrote ${OUT_DIR}/vmlinuz (from ${KERNEL_SRC})"

# ----- step 5: assemble UEFI bundle ------------------------------------------
#
# Wraps ${KERNEL} + ${INITRD} + a baked-in cmdline into a single PE
# binary that UEFI firmware boots natively. Two routes:
#
#   1. `ukify build` (systemd-ukify) — preferred. Emits a UKI directly.
#   2. Manual `objcopy --add-section` against
#      `linuxx64.efi.stub` (from systemd-boot-efi).
#
# The cmdline embedded here is the *bootloader's* cmdline, not the
# chosen BE's. The BE's cmdline is built fresh by `kexec::handoff`
# (`root=ZFS=<dataset> ro quiet`) and passed via `kexec --command-line=`,
# never through this stub. We only put `console=tty0 console=ttyS0,115200`
# here so QEMU's `-nographic` and a real-hardware monitor both surface
# the boot log.  tty0 listed first so VGA is the primary console (printk
# uses the fast tty0 path); ttyS0 is mirrored at an explicit baud — the
# kernel's default for `console=ttyS0` with no baud is 9600, which paces
# every printk through a 16-byte UART FIFO at ~960 B/s and stretches the
# preinit modprobe phase to ~1s per line on real hardware with a SuperIO
# UART present-but-unused.

log "step 5: assembling EFI bundle"

EFI_OUT="${OUT_DIR}/zboot-boot.efi"
EFI_CMDLINE="${ZBOOT_BOOT_CMDLINE:-console=tty0 console=ttyS0,115200}"
CMDLINE_FILE="${OUT_DIR}/cmdline.txt"
printf '%s\n' "${EFI_CMDLINE}" > "${CMDLINE_FILE}"

EFI_TOOL=""
if command -v ukify >/dev/null 2>&1; then
    EFI_TOOL="ukify"
    # `ukify build` is the canonical route. We avoid `--initrd` + zst
    # by name only — ukify accepts the file as-is and stuffs it in
    # `.initrd` regardless of compression.
    log "  using ukify"
    ukify build \
        --linux="${OUT_DIR}/vmlinuz" \
        --initrd="${INITRD_OUT}" \
        --cmdline="@${CMDLINE_FILE}" \
        --output="${EFI_OUT}.tmp" \
        >&2
    mv "${EFI_OUT}.tmp" "${EFI_OUT}"
elif STUB_PATH="$(_find_efi_stub)"; then
    EFI_TOOL="objcopy"
    log "  using objcopy with stub ${STUB_PATH}"
    # Manual route. Section addresses follow the layout systemd
    # documents in `man systemd-stub`. We put .osrel just past the
    # stub PE end (`objcopy` would normally compute this; for a
    # zboot-only stub we use a fixed-spacing set of vmas large enough
    # for the kernel to fit). The stub's existing PE layout starts
    # at 0x10000 and reserves 16MB before .osrel; sd-stub's expected
    # base offsets at 2026-05 are:
    #   .osrel    0x20000
    #   .cmdline  0x30000
    #   .linux    0x2000000
    #   .initrd   0x3000000
    # Past sd-stub releases drift; if these collide on a newer stub,
    # fall back to ukify (which knows the right offsets at runtime).
    # For our debian-trixie pin (systemd 260) these are the documented
    # values.
    objcopy \
        --add-section .osrel="/etc/os-release" \
        --change-section-vma .osrel=0x20000 \
        --add-section .cmdline="${CMDLINE_FILE}" \
        --change-section-vma .cmdline=0x30000 \
        --add-section .linux="${OUT_DIR}/vmlinuz" \
        --change-section-vma .linux=0x2000000 \
        --add-section .initrd="${INITRD_OUT}" \
        --change-section-vma .initrd=0x3000000 \
        "${STUB_PATH}" \
        "${EFI_OUT}.tmp"
    mv "${EFI_OUT}.tmp" "${EFI_OUT}"
else
    log "FATAL: neither ukify nor linuxx64.efi.stub available"
    log "       (apt install systemd-ukify systemd-boot-efi)"
    exit 1
fi

log "  wrote ${EFI_OUT} ($(stat -c '%s' "${EFI_OUT}") bytes, via ${EFI_TOOL})"

# ----- step 6: manifest -------------------------------------------------------

{
    printf 'kernel: %s\n' "${KERNEL_SRC}"
    printf 'kver: %s\n' "${KVER:-unknown}"
    printf 'init: zboot-boot (target=%s)\n' "${TARGET:-host}"
    printf 'bundled: '
    for b in "${BUNDLE_BINS[@]}"; do printf '%s ' "$(basename "${b}")"; done
    printf '\n'
    printf 'efi-bundle: zboot-boot.efi (tool=%s, cmdline=%s)\n' \
        "${EFI_TOOL}" "${EFI_CMDLINE}"
    printf 'date: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "${OUT_DIR}/MANIFEST"
log "  wrote ${OUT_DIR}/MANIFEST"

log "done. boot/out/{vmlinuz,initrd.img.zst,zboot-boot.efi,MANIFEST}"
