# Optional command shortcuts; the direct Cargo and script commands work too.

# List these recipes.
default:
    @just --list

# Build command binaries; honor Cargo's target directory and jobs settings.
build:
    cargo build --workspace --bins --locked

# Run the offline suite: Rust, Clippy, formatting, file-only fixtures and case loading.
test:
    sh tests/check.sh

# Format all workspace Rust source.
fmt:
    cargo fmt --all

# Build the UKI, Debian package and sources into new OUT (docs/BUILD.md prerequisites).
dist OUT:
    dist/dist.sh {{quote(OUT)}}
