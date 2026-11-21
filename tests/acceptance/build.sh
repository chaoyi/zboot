#!/bin/bash
# Internal helper for run.py prepare; run only inside its selected build scope.
# Arguments: SOURCE OID DESTINATION. Build and publish the pinned product binaries.
set -euo pipefail
wt=$1 oid=$2 destination=$3
cd "$wt"
[[ $(git rev-parse HEAD) == "$oid" && -z $(git status --porcelain) ]]
: "${CARGO_TARGET_DIR:?the build runner must supply its owned Cargo target directory}"
# Static like the shipped tools, so each is the guest's /usr/bin binary itself
# (the shipped zboot.efi is found from the running executable's path).
RUSTFLAGS='-C target-feature=+crt-static' cargo build --jobs "${CARGO_BUILD_JOBS:-4}" --locked --release \
    --target x86_64-unknown-linux-gnu -p zboot -p zsnap --bins
[[ $(git rev-parse HEAD) == "$oid" && -z $(git status --porcelain) ]]
mkdir -m 0700 "$destination"
release=$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release
install -m 0755 "$release/zboot" "$release/zsnap" "$destination/"
(cd "$destination"; sha256sum zboot zsnap > SHA256SUMS)
printf '%s\n' "$oid" > "$destination/source.oid"
