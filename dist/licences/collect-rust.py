#!/usr/bin/env python3
"""Collect actual Cargo and Rust notice texts without building or downloading.

This is a conservative notice inventory, not a source-distribution mechanism or
an assertion that the resulting distribution satisfies every licence obligation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

TARGET = "x86_64-unknown-linux-gnu"
LEGAL_NAME = re.compile(r"^(?:licen[cs]es?|copying|copyright|notices?|authors)(?:$|[._-])", re.I)
LEGAL_DIR = {"license", "licenses", "licence", "licences"}
TEXT_SUFFIXES = {"", ".txt", ".md", ".rst", ".html", ".htm"}
MAX_DEPTH = 5


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_text(path, root):
    """Legal documents must be real, nonempty files inside their source root."""
    path = Path(path)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"notice escapes source directory: {path}")
    if not path.is_file() or not path.stat().st_size:
        raise ValueError(f"missing or empty notice text: {path}")
    return path


def legal_files(root, recursive=True):
    found = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        relative = Path(directory).relative_to(root)
        depth = len(relative.parts)
        dirs[:] = sorted(d for d in dirs if d not in {".git", "target"}
                         and not (Path(directory) / d).is_symlink())
        if not recursive or depth >= MAX_DEPTH:
            dirs.clear()
        in_legal_dir = root.name.lower() in LEGAL_DIR or any(p.lower() in LEGAL_DIR for p in relative.parts)
        for name in sorted(files):
            if LEGAL_NAME.match(name) or (in_legal_dir and Path(name).suffix.lower() in TEXT_SUFFIXES):
                found.add(checked_text(Path(directory) / name, root))
    return sorted(found)


def lock_checksums(lock):
    with lock.open("rb") as stream:
        data = tomllib.load(stream)
    return {(p["name"], p["version"], p.get("source")): p.get("checksum")
            for p in data.get("package", [])}


def copy_notices(entries, destination, output):
    records = []
    for source, relative in entries:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        records.append({"path": target.relative_to(output).as_posix(),
                        "source_path": str(source), "sha256": digest(target)})
    return records


def collect(manifest, sysroot, output):
    if output.exists() or output.is_symlink():
        raise ValueError(f"output must be a new directory: {output}")
    command = ["cargo", "metadata", "--format-version", "1", "--offline", "--locked",
               "--filter-platform", TARGET, "--manifest-path", str(manifest)]
    metadata = json.loads(subprocess.check_output(command, text=True))
    workspace = Path(metadata["workspace_root"])
    lock = workspace / "Cargo.lock"
    checksums = lock_checksums(lock)
    members = set(metadata["workspace_members"])
    workspace_notices = legal_files(workspace, recursive=False)
    for directory in sorted(workspace.iterdir()):
        if directory.name.lower() in LEGAL_DIR and directory.is_dir():
            workspace_notices.extend(checked_text(p, workspace) for p in legal_files(directory))
    packages = []
    for package in sorted(metadata["packages"], key=lambda p: p["id"]):
        root = Path(package["manifest_path"]).parent
        notices = legal_files(root)
        if package.get("license_file"):
            explicit = checked_text(root / package["license_file"], root)
            notices = sorted(set(notices) | {explicit})
        inherited = not notices and package["id"] in members and bool(workspace_notices)
        if inherited:
            entries = [(p, Path("workspace") / p.relative_to(workspace)) for p in workspace_notices]
        else:
            entries = [(p, p.relative_to(root)) for p in notices]
        if not entries:
            raise ValueError(f"no licence/notice texts for {package['name']} {package['version']} ({root})")
        key = (package["name"], package["version"], package.get("source"))
        checksum = package.get("checksum") or checksums.get(key)
        # A registry's fetched package checksum is useful if a lock has none.
        checksum_file = root / ".cargo-checksum.json"
        if checksum_file.is_file():
            fetched = json.loads(checksum_file.read_text()).get("package")
            if checksum and fetched and checksum != fetched:
                raise ValueError(f"fetched checksum disagrees with Cargo.lock: {package['id']}")
            checksum = checksum or fetched
        identity = hashlib.sha256(package["id"].encode()).hexdigest()[:12]
        name = f"{package['name']}-{package['version']}-{identity}"
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise ValueError(f"unsafe package output name: {name}")
        record = {field: package.get(field) for field in ("id", "name", "version", "source", "license", "license_file")}
        record.update(checksum=checksum, manifest_path=package["manifest_path"],
                      workspace_notice_fallback=inherited)
        packages.append((name, record, entries))
    rust_docs = sysroot / "share/doc/rust"
    # This is the standard library/runtime attribution report in the pinned
    # toolchain, separate from the compiler-wide COPYRIGHT.html report.
    runtime_copyright = checked_text(rust_docs / "COPYRIGHT-library.html", rust_docs)
    rust_notices = [runtime_copyright]
    rust_notices.extend(p for p in legal_files(rust_docs, recursive=False)
                        if p.name.lower().startswith(("license", "licence")))
    for name in sorted(LEGAL_DIR):
        directory = rust_docs / name
        if directory.is_dir():
            rust_notices.extend(checked_text(p, rust_docs) for p in legal_files(directory))
    rust_entries = [(p, p.relative_to(rust_docs)) for p in sorted(set(rust_notices))]
    inventory = {
        "format": 1, "target": TARGET, "cargo_metadata_command": command,
        "scope": "Conservative superset: every package returned by locked, offline Cargo metadata, including build and dev dependencies; not a linked-code analysis.",
        "limitation": "Actual notice texts only; no complete corresponding source, source offer, or assertion of licence compliance is provided by this inventory.",
        "cargo_lock": {"path": str(lock), "sha256": digest(lock)},
        "packages": [], "rust": {"sysroot": str(sysroot),
            "scope": "Standard-library/runtime COPYRIGHT-library.html and installed licence texts; compiler-wide COPYRIGHT.html is build-tool attribution and is excluded."},
    }
    output.mkdir(parents=True, exist_ok=False)
    try:
        for name, record, entries in packages:
            record["notices"] = copy_notices(entries, output / "crates" / name, output)
            inventory["packages"].append(record)
        inventory["rust"]["notices"] = copy_notices(rust_entries, output / "rust", output)
        (output / "inventory.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
        (output / "README.txt").write_text(inventory["scope"] + "\n\n" + inventory["limitation"] + "\n\n"
            "See inventory.json for fetched package identities, SPDX declarations (when available), "
            "Cargo.lock checksums, document provenance and SHA-256 digests. Workspace packages "
            "without their own notices explicitly use the workspace-root notice documents.\n")
    except BaseException:
        shutil.rmtree(output)
        raise
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path.cwd() / "Cargo.toml")
    parser.add_argument("--sysroot", type=Path, help="exact build toolchain sysroot; default: rustc --print sysroot")
    parser.add_argument("--output", required=True, type=Path, help="new notice output directory")
    args = parser.parse_args(argv)
    try:
        sysroot = args.sysroot or Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
        collect(args.manifest.resolve(), sysroot.resolve(), args.output.absolute())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"collect-rust-licences: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
