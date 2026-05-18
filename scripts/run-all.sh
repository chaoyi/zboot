#!/bin/bash
# Run all *.sh tests. Two modes:
#
#   bash scripts/run-all.sh           sequential (safest, ~1 hour)
#   bash scripts/run-all.sh --parallel-batch N
#                                         N tests at a time (default 4;
#                                         each uses ~4GB RAM)
#
# Output goes to /tmp/zboot-allruns-<UTC>/<test>.out so you can
# diff/grep across them after a run.
#
# Prereqs (the harness fails fast with a clear message if missing):
#   - zboot factory → ~/.cache/zboot/factory.tar.zst (~5min one-off)
#   - LIVE_DIR env  → dir with vmlinuz, initrd.img, filesystem.squashfs
#                     (any debian-live producer works; see README.md).

set -euo pipefail

FACTORY_TAR=${FACTORY_TAR:-$HOME/.cache/zboot/factory.tar.zst}

[ -f "$FACTORY_TAR" ] || {
    echo "no factory tar at $FACTORY_TAR — run \`zboot factory --no-headers\` first"
    exit 1
}

BATCH=1
case "${1:-}" in
    --parallel-batch) BATCH="$2" ;;
    --parallel-batch=*) BATCH="${1#*=}" ;;
    "") ;;  # default sequential
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
esac

UTC=$(date -u +%s)
OUT_DIR=/tmp/zboot-allruns-${UTC}
mkdir -p "$OUT_DIR"

cd "$(dirname "$0")"

# Order: cheap → expensive, with the deploy variants first since
# they're prerequisite-style (everything else assumes deploy works).
TESTS=(
    empty-disk-preflight.sh # ~3min
    lifecycle.sh            # ~8min  (snapshot/fork/default/rollback + content fidelity)
    attach.sh               # ~5min
    drop.sh                 # ~5min
    cmdline.sh              # ~5min
    chroot.sh               # ~5min
    overlay.sh              # ~5min
    mirror.sh               # ~7min  (basic + idempotency + incremental + drift + --with)
    replication.sh          # ~8min  (push/pull/swap/pair/unpair/rename + @snap + --force)
    multipool.sh            # ~5min
    multipool-ambiguity.sh  # ~5min  (drop / default disambiguation across pools)
    hostid-cmdline.sh       # ~5min  (spl.spl_hostid kernel-cmdline override mechanism)
    pxe-discover.sh         # ~6min  (UEFI PXE → zboot-boot.efi → real rpool discovery)
    deploy.sh               # ~15min (slowest; debootstrap deploy)
)

echo "=== running ${#TESTS[@]} tests, batch=$BATCH, output → $OUT_DIR ==="

PASS=()
FAIL=()
START=$(date +%s)

run_one() {
    local script=$1
    local out="$OUT_DIR/${script%.sh}.out"
    bash "./$script" > "$out" 2>&1
}

if [ "$BATCH" -le 1 ]; then
    for t in "${TESTS[@]}"; do
        echo "  starting $t..."
        if run_one "$t"; then
            PASS+=("$t")
            echo "    ✓ $t"
        else
            FAIL+=("$t")
            echo "    ✗ $t (see $OUT_DIR/${t%.sh}.out)"
        fi
    done
else
    # Batched-parallel: run BATCH tests concurrently, wait for the
    # batch to complete before starting the next. Simpler than a
    # full work-queue, sufficient for our test count.
    queue=("${TESTS[@]}")
    while [ ${#queue[@]} -gt 0 ]; do
        batch=("${queue[@]:0:BATCH}")
        queue=("${queue[@]:BATCH}")
        echo "  starting batch: ${batch[*]}"
        pids=()
        for t in "${batch[@]}"; do
            run_one "$t" &
            pids+=("$!:$t")
        done
        for entry in "${pids[@]}"; do
            pid="${entry%%:*}"
            test_name="${entry#*:}"
            if wait "$pid"; then
                PASS+=("$test_name")
                echo "    ✓ $test_name"
            else
                FAIL+=("$test_name")
                echo "    ✗ $test_name (see $OUT_DIR/${test_name%.sh}.out)"
            fi
        done
    done
fi

END=$(date +%s)
ELAPSED=$((END - START))

echo
echo "=== summary (${ELAPSED}s) ==="
echo "passed: ${#PASS[@]}"
for t in "${PASS[@]}"; do echo "  ✓ $t"; done
echo "failed: ${#FAIL[@]}"
for t in "${FAIL[@]}"; do echo "  ✗ $t"; done

[ ${#FAIL[@]} -eq 0 ] || exit 1
