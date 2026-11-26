"""Shared Cargo artifact discovery and C-wrapper mock builder for helper tests."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def native_artifacts(binary_name):
    """Use the caller's Cargo build; this suite never owns a Cargo target."""
    manifest = os.environ.get("ZBOOT_HELPERS_BUILD_MANIFEST")
    if manifest:
        artifacts = [json.loads(line) for line in Path(manifest).read_text().splitlines()]
        artifacts = [artifact for artifact in artifacts
                     if artifact.get("reason") == "compiler-artifact"
                     and not artifact.get("profile", {}).get("test", False)]
        binaries = [Path(artifact["executable"]) for artifact in artifacts
                    if artifact["target"]["name"] == binary_name
                    and artifact.get("executable")]
        libraries = [Path(filename) for artifact in artifacts
                     if artifact["target"]["name"] == "libc"
                     for filename in artifact["filenames"] if filename.endswith(".rlib")]
    else:
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        binaries = [target / "debug" / binary_name]
        libraries = list((target / "debug/deps").glob("liblibc-*.rlib"))
    if len(binaries) != 1 or len(libraries) != 1:
        raise RuntimeError("run tests/check.sh to select unambiguous native helper artifacts")
    binary, library = binaries[0], libraries[0]
    if not binary.is_file() or not library.is_file():
        raise RuntimeError("run tests/check.sh to build the native helper and libc artifacts")
    return binary, library


def build_mock(source, output, wrappers, names, library):
    """Link the production Rust source to independent C ABI fault fixtures."""
    object_file = wrappers.with_suffix(".o")
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c",
                    str(wrappers), "-o", str(object_file)], check=True)
    subprocess.run(["rustc", "--edition=2024", "--crate-name", "mock_native_helper",
                    "-C", "target-feature=-crt-static", "--extern", f"libc={library}",
                    "-L", f"dependency={library.parent}", str(source), "-o", str(output),
                    "-C", f"link-arg={object_file}"]
                   + [arg for name in names for arg in
                      ("-C", f"link-arg=-Wl,--wrap={name}")], check=True)
