#!/bin/sh
# The offline merge gate: Rust fmt, tests and Clippy, the file-only tooling and
# acceptance-harness suites, and a load check of every QEMU acceptance case. No
# root, ZFS module, VM, network or host storage change. docs/TESTING.md covers
# CHECK_JOBS, RUST_TEST_THREADS and a caller-owned build scope for shared hosts.
set -eu
cd "$(dirname "$0")/.."
jobs=${CHECK_JOBS:-8}
cargo fmt --all --check
RUST_TEST_THREADS=${RUST_TEST_THREADS:-4} cargo test --workspace --locked --offline -j "$jobs"
cargo clippy --workspace --all-targets --locked --offline -j "$jobs" -- -D warnings
# clippy.toml leaves every Command launch to engine::native::Announced, which
# announces it for -v. Only test builds may lift that elsewhere in src.
if grep -rnE 'disallowed_methods|allow\(clippy::(all|style)' crates/*/src |
    grep -v -e '^crates/zfs-tools/src/engine/native\.rs:' \
        -e ':#!\[cfg_attr(test, allow(clippy::disallowed_methods, reason = "test fixtures"))]$'; then
    echo 'check: only engine/native.rs may allow clippy::disallowed_methods' >&2
    exit 1
fi
# The supported library alone, without the workspace-internal engine feature.
cargo clippy -p zfs-tools --all-targets --locked --offline -j "$jobs" -- -D warnings
# Select exact Cargo artifacts for the native-library ABI fault fixtures.
native_manifest=$(mktemp "${TMPDIR:-/var/tmp}/zboot-helpers-artifacts.XXXXXX")
trap 'rm -f "$native_manifest"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s' -C target-feature=-crt-static) \
    cargo build -p zboot-helpers --bins --locked --offline -j "$jobs" \
    --message-format=json-render-diagnostics > "$native_manifest"
ZBOOT_HELPERS_BUILD_MANIFEST=$native_manifest \
    python3 -B -m unittest discover -s tests/tooling -p 'test_*.py'
python3 -B -m unittest discover -s tests/ci -p 'test_*.py'
python3 -B tests/acceptance/test_fixtures.py
python3 -IB tests/acceptance/run.py list > /dev/null
echo 'check: all offline suites passed'
