#!/bin/bash
# boot/lddtree.sh — copy a binary's dynamic-library closure into a
# staged tree so it runs from a chroot / initrd / pivot_root.
#
# Usage:
#   boot/lddtree.sh --root <stage-dir> <bin> [<bin>...]
#
# For each input binary:
#   1. Walks `ldd` output to enumerate every shared library it touches
#      (recursively — `ldd` already does the transitive close).
#   2. Copies each library to `<stage-dir>/<original-path>`, preserving
#      the on-disk path so the dynamic linker finds them.
#   3. Copies the binary itself to the stage tree at its on-disk path.
#   4. Records the dynamic linker (`ld-linux*.so*`) so the initrd can
#      execute glibc binaries.
#
# Unlike Gentoo's `lddtree(1)`, this script is intentionally minimal:
# we don't follow ELF interpreter chains by hand, we don't dedup
# across symlinks (cp -L chases them), and we don't report errors on
# statically-linked binaries (ldd's "not a dynamic executable"
# message is treated as success).
#
# Shellcheck-clean. Errors loudly on missing inputs.

set -euo pipefail

ROOT=""
BINS=()

usage() {
    cat <<'USAGE'
boot/lddtree.sh — bundle a binary's .so closure into a staged tree.

Usage:
  boot/lddtree.sh --root <stage-dir> <bin> [<bin>...]

Each <bin> is an absolute path on the host. Output: <stage-dir> with
the binary and every library it depends on copied to the same paths.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --root)    ROOT="$2"; shift 2 ;;
        --root=*)  ROOT="${1#*=}"; shift ;;
        -*)        usage >&2; exit 2 ;;
        *)         BINS+=("$1"); shift ;;
    esac
done

if [[ -z "${ROOT}" || ${#BINS[@]} -eq 0 ]]; then
    usage >&2
    exit 2
fi

mkdir -p "${ROOT}"

# Stage one file at its on-disk path under ${ROOT}. Symlinks are
# chased (`-L`) so the staged copy is the actual file, not a dangling
# pointer into the host fs.
stage_file() {
    local src="$1"
    [[ -e "${src}" ]] || return 0
    local dst="${ROOT}${src}"
    mkdir -p "$(dirname "${dst}")"
    if [[ ! -e "${dst}" ]]; then
        cp -L "${src}" "${dst}"
    fi
}

# Walk ldd output for one binary; emit the absolute paths of every
# library it depends on.
deps_of() {
    local bin="$1"
    # ldd output formats:
    #   libfoo.so => /lib/x86_64-linux-gnu/libfoo.so (0x...)
    #   /lib64/ld-linux-x86-64.so.2 (0x...)
    # We capture both. Suppress "not a dynamic executable" silently —
    # statically-linked binaries are valid here.
    ldd "${bin}" 2>/dev/null | awk '
        /=>/ {
            # second field after "=>" is the path
            for (i = 1; i <= NF; i++) {
                if ($i == "=>") {
                    if ((i+1) <= NF && substr($(i+1), 1, 1) == "/") {
                        print $(i+1)
                    }
                    next
                }
            }
        }
        /^\t\// {
            print $1
        }
    ' || true
}

for bin in "${BINS[@]}"; do
    if [[ ! -x "${bin}" ]]; then
        printf 'lddtree: %s is not executable; skipping\n' "${bin}" >&2
        continue
    fi
    stage_file "${bin}"
    while read -r so; do
        [[ -n "${so}" ]] || continue
        stage_file "${so}"
    done < <(deps_of "${bin}")
done
