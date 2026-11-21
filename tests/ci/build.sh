#!/bin/bash
# Build the normal distribution and rescue factory root once. No host ZFS use.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
: "${RUNNER_TEMP:?GitHub runner staging is required}"
: "${CI_OUTPUT:?output directory outside the checkout is required}"
mkdir -p "$CI_OUTPUT"
stage=$(mktemp -d /var/tmp/zfs-tools-dist.XXXXXX)
chmod 0755 "$stage"
export TMPDIR=$stage ZBOOT_JOBS=${ZBOOT_JOBS:-2}
trap 'rm -rf -- "$stage"' EXIT
/usr/bin/time -v dist/dist.sh "$CI_OUTPUT/distribution" 2>&1 | tee "$CI_OUTPUT/distribution.log"
(cd "$CI_OUTPUT/distribution" && sha256sum --check SHA256SUMS)
python3 tests/ci/record-build.py "$CI_OUTPUT"
# Preserve the complete matching distribution before factory work. The tar keeps
# executable modes that artifact upload/download would otherwise discard.
tar -C "$CI_OUTPUT" -cf - distribution build.json | zstd -T2 -3 -o "$CI_OUTPUT/distribution.tar.zst"
(cd "$CI_OUTPUT" && sha256sum distribution.tar.zst > distribution.tar.zst.sha256)
suite=$(awk '$1 == "suite" { print $2 }' dist/build.lock)
snapshot=$(awk '$1 == "snapshot" { print $2 }' dist/build.lock)
/usr/bin/time -v "$CI_OUTPUT/distribution/usr/bin/zboot" factory "$CI_OUTPUT/factory.tar.zst" \
    --suite "$suite" --snapshot "$snapshot" \
    --packages openssh-server,systemd-resolved,ca-certificates,curl,rsync,less,vim-tiny,pciutils,usbutils,smartmontools,cryptsetup \
    2>&1 | tee "$CI_OUTPUT/factory.log"
(cd "$CI_OUTPUT" && sha256sum factory.tar.zst factory.tar.zst.packages > factory.sha256)
# A successful build leaves its staging empty; the EXIT trap clears it on failure.
rmdir "$stage"
