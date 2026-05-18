#!/bin/bash
# boot/install.sh — install zboot-boot.efi onto an ESP and register it
# with the firmware via efibootmgr.
#
# Idempotent: re-running drops any existing "zboot-boot" boot entry
# before creating a new one. Safe to call after every build.
#
# Layout written:
#
#     <ESP>/EFI/zboot-boot/zboot-boot.efi    # canonical install
#     <ESP>/EFI/BOOT/BOOTX64.EFI             # default-search fallback
#                                              (byte-identical copy)
#
# The fallback copy at /EFI/BOOT/BOOTX64.EFI is what UEFI firmware
# loads when no NVRAM boot entry matches (firmware-default search
# path). It saves us when efibootmgr's NVRAM entries get wiped (CMOS
# reset, motherboard swap, deploy of a fresh disk into a new chassis).
#
# After installing the bundle, this script registers an explicit boot
# entry pointing at the canonical path so firmware boots zboot-boot
# without scanning. The entry name is `zboot-boot`.
#
# Usage:
#
#   boot/install.sh                                # auto-detect
#   boot/install.sh --esp /boot/efi
#   boot/install.sh --esp /boot/efi --disk /dev/nvme0n1 --partition 1
#   boot/install.sh --bundle /path/to/zboot-boot.efi
#   boot/install.sh --no-efibootmgr                # skip NVRAM entry
#   boot/install.sh --label "zboot-boot (slot A)"
#   boot/install.sh --dry-run                      # preview, no writes
#
# Auto-detect uses `findmnt` to resolve the ESP mount point to a
# block device, then strips the partition suffix to derive the disk.
# Override with --disk / --partition when the inference is wrong
# (multi-disk RAID-1 ESP layouts, mdraid-on-ESP, etc.).
#
# Requirements:
#
#   - root (writes to ESP, calls efibootmgr)
#   - the ESP is mounted (typical: /boot/efi or /efi)
#   - efibootmgr installed (skip with --no-efibootmgr if you only
#     want to update the on-disk file and let the firmware default
#     search path pick up the BOOTX64.EFI copy)
#   - efivars writable: kernel must have /sys/firmware/efi/efivars
#     mounted rw (it normally is on UEFI systems)
#
# This script is shellcheck-clean.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_BUNDLE="${SCRIPT_DIR}/out/zboot-boot.efi"

ESP=""
DISK=""
PARTITION=""
BUNDLE="${DEFAULT_BUNDLE}"
LABEL="zboot-boot"
DO_EFIBOOTMGR=1
DRY_RUN=0

usage() {
    cat <<'USAGE'
boot/install.sh — install zboot-boot.efi onto an ESP and register it.

Usage:
  boot/install.sh [options]

Options:
  --esp PATH              ESP mount point (default: auto-detect via findmnt)
  --disk PATH             block device that owns the ESP (default: derived
                          from --esp). Pass to efibootmgr -d.
  --partition NUM         partition number on --disk (default: derived
                          from --esp). Pass to efibootmgr -p.
  --bundle PATH           the .efi to install (default: boot/out/zboot-boot.efi)
  --label STRING          NVRAM entry label (default: zboot-boot)
  --no-efibootmgr         install the file, but skip NVRAM registration
  --dry-run               print every command instead of running it
  -h, --help              show this help

Layout written:
  <esp>/EFI/zboot-boot/zboot-boot.efi    # canonical
  <esp>/EFI/BOOT/BOOTX64.EFI             # default-search fallback

Idempotent: re-running drops any existing entry with the same label
before creating a new one. Safe after every build.

Requires: root, efibootmgr (unless --no-efibootmgr), an ESP mounted,
and writable /sys/firmware/efi/efivars (UEFI default).
USAGE
}

# Parse args.
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)         usage; exit 0 ;;
        --esp)             ESP="$2"; shift 2 ;;
        --esp=*)           ESP="${1#*=}"; shift ;;
        --disk)            DISK="$2"; shift 2 ;;
        --disk=*)          DISK="${1#*=}"; shift ;;
        --partition)       PARTITION="$2"; shift 2 ;;
        --partition=*)     PARTITION="${1#*=}"; shift ;;
        --bundle)          BUNDLE="$2"; shift 2 ;;
        --bundle=*)        BUNDLE="${1#*=}"; shift ;;
        --label)           LABEL="$2"; shift 2 ;;
        --label=*)         LABEL="${1#*=}"; shift ;;
        --no-efibootmgr)   DO_EFIBOOTMGR=0; shift ;;
        --dry-run)         DRY_RUN=1; shift ;;
        *)                 usage >&2; exit 2 ;;
    esac
done

log() { printf '[zboot-boot/install] %s\n' "$*" >&2; }
fatal() { log "FATAL: $*"; exit 1; }

# Run a command, or just echo it under --dry-run.
run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '  DRY-RUN:'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}

# Sanity: bundle must exist (skip in --dry-run for a friendlier preview).
if [[ ! -f "${BUNDLE}" ]]; then
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log "note: bundle ${BUNDLE} does not exist (dry-run continues)"
    else
        fatal "bundle not found: ${BUNDLE} (run boot/build.sh first)"
    fi
fi

# Root check (skipped under --dry-run since the user is just previewing).
if [[ "${DRY_RUN}" -eq 0 && "$(id -u)" -ne 0 ]]; then
    fatal "must run as root (writes to ESP, calls efibootmgr)"
fi

# ----- ESP detection ----------------------------------------------------------
#
# Strategy: prefer the user's --esp; else `findmnt` for a vfat-typed
# mount under common ESP mountpoints; bail if neither resolves.

if [[ -z "${ESP}" ]]; then
    if command -v findmnt >/dev/null 2>&1; then
        for candidate in /boot/efi /efi /boot; do
            fstype="$(findmnt -nro FSTYPE "${candidate}" 2>/dev/null || true)"
            if [[ "${fstype}" == "vfat" ]]; then
                ESP="${candidate}"
                log "auto-detected ESP at ${ESP}"
                break
            fi
        done
    fi
fi

if [[ -z "${ESP}" ]]; then
    fatal "could not auto-detect ESP; pass --esp <path> (e.g. /boot/efi)"
fi

if [[ ! -d "${ESP}" ]]; then
    fatal "ESP path ${ESP} is not a directory"
fi

# ----- disk + partition derivation -------------------------------------------
#
# `findmnt -nro SOURCE <esp>` returns the block device backing the ESP
# (e.g. /dev/nvme0n1p1 or /dev/sda1). We split that into disk +
# partition number using the standard Linux naming rules:
#
#   nvme0n1p1 -> nvme0n1 + 1   (NVMe needs the trailing `pN` rule)
#   mmcblk0p1 -> mmcblk0 + 1   (eMMC, same rule)
#   sda1      -> sda + 1
#   vda1      -> vda + 1
#
# The user can override either via flags when the heuristic fails
# (e.g. mdraid ESP with multiple member disks).

if [[ -z "${DISK}" || -z "${PARTITION}" ]]; then
    if ! command -v findmnt >/dev/null 2>&1; then
        fatal "findmnt not available; pass --disk and --partition explicitly"
    fi
    src="$(findmnt -nro SOURCE "${ESP}" 2>/dev/null || true)"
    if [[ -z "${src}" ]]; then
        fatal "could not resolve ESP source for ${ESP}; pass --disk and --partition"
    fi
    log "ESP source: ${src}"
    # Derive: strip trailing digits (and optional leading `p` for nvme/mmc).
    if [[ "${src}" =~ ^(/dev/(nvme[0-9]+n[0-9]+|mmcblk[0-9]+|loop[0-9]+))p([0-9]+)$ ]]; then
        derived_disk="${BASH_REMATCH[1]}"
        derived_part="${BASH_REMATCH[3]}"
    elif [[ "${src}" =~ ^(/dev/[a-zA-Z]+)([0-9]+)$ ]]; then
        derived_disk="${BASH_REMATCH[1]}"
        derived_part="${BASH_REMATCH[2]}"
    else
        fatal "could not parse ESP source ${src}; pass --disk and --partition"
    fi
    DISK="${DISK:-${derived_disk}}"
    PARTITION="${PARTITION:-${derived_part}}"
    log "derived disk=${DISK} partition=${PARTITION}"
fi

# ----- copy the bundle into place --------------------------------------------

ZBOOT_DIR="${ESP}/EFI/zboot-boot"
FALLBACK_DIR="${ESP}/EFI/BOOT"
TARGET_PATH="${ZBOOT_DIR}/zboot-boot.efi"
FALLBACK_PATH="${FALLBACK_DIR}/BOOTX64.EFI"

log "installing bundle:"
log "  ${BUNDLE}"
log "    -> ${TARGET_PATH}"
log "    -> ${FALLBACK_PATH}  (UEFI default-search fallback)"

run mkdir -p "${ZBOOT_DIR}" "${FALLBACK_DIR}"
run cp -f "${BUNDLE}" "${TARGET_PATH}"
run cp -f "${BUNDLE}" "${FALLBACK_PATH}"

# ----- efibootmgr registration (idempotent) ----------------------------------

if [[ "${DO_EFIBOOTMGR}" -eq 0 ]]; then
    log "skipping efibootmgr per --no-efibootmgr"
    log "done."
    exit 0
fi

if ! command -v efibootmgr >/dev/null 2>&1; then
    fatal "efibootmgr not on PATH (apt install efibootmgr) — or use --no-efibootmgr"
fi

# Sanity: efivars present? Without it efibootmgr can read but not write.
if [[ "${DRY_RUN}" -eq 0 && ! -d /sys/firmware/efi/efivars ]]; then
    fatal "/sys/firmware/efi/efivars not present — system was not booted via UEFI?"
fi

# Drop any pre-existing entries with the same label so we don't
# accumulate duplicates on every build (idempotency contract).
existing_entries() {
    # Lines look like: `Boot0001* zboot-boot   HD(...)/File(...)`.
    # We match the label exactly to avoid dropping entries that just
    # contain "zboot-boot" as a substring of a different label.
    efibootmgr 2>/dev/null \
        | awk -v label="${LABEL}" '
            /^Boot[0-9A-Fa-f]{4}\*?[[:space:]]/ {
                # Extract the 4-digit hex index after "Boot".
                idx = substr($1, 5, 4)
                # Strip the leading token; the remainder up to the
                # device-path opener "HD(" (or "PciRoot(") is the label.
                rest = substr($0, length($1) + 1)
                sub(/^[[:space:]]+/, "", rest)
                # Pull off the description: everything up to first \t
                # or the first "  " (efibootmgr separates with tabs).
                if (match(rest, /\t/)) {
                    desc = substr(rest, 1, RSTART - 1)
                } else if (match(rest, /  /)) {
                    desc = substr(rest, 1, RSTART - 1)
                } else {
                    desc = rest
                }
                if (desc == label) print idx
            }'
}

while read -r idx; do
    [[ -n "${idx}" ]] || continue
    log "removing existing entry Boot${idx} (label=${LABEL})"
    run efibootmgr -b "${idx}" -B
done < <(existing_entries || true)

# Create the new entry. efibootmgr's -l takes a backslash-separated
# Windows-style path RELATIVE TO the ESP root.
log "creating efibootmgr entry: label=${LABEL} disk=${DISK} part=${PARTITION}"
run efibootmgr \
    --create \
    --disk "${DISK}" \
    --part "${PARTITION}" \
    --label "${LABEL}" \
    --loader '\EFI\zboot-boot\zboot-boot.efi'

log "done. Reboot and pick \"${LABEL}\" from the firmware boot menu, or"
log "let it run as the default if it lands at BootOrder[0]."
