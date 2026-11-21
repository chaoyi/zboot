#!/usr/bin/python3
"""Collect Debian notices and exact source archives for selected runtime inputs.

Run inside the same Debian root that supplies the runtime. The file manifest is
sha256sum output containing original absolute paths, not staged destination paths.
This records package provenance; it is not a determination of legal compliance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


DOC_ROOT = Path("/usr/share/doc")
COMMON_ROOT = Path("/usr/share/common-licenses")
BOOT_ROOT = Path("/boot")
MODULE_ROOT = Path("/usr/lib/modules")
BINARY_PACKAGE_PATTERN = r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?"


class CollectionError(Exception):
    pass


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                            env={**os.environ, "LC_ALL": "C"})
    if result.returncode:
        raise CollectionError(f"{' '.join(command)} failed: {result.stderr.strip()}")
    return result.stdout


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def absolute_file(value):
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise CollectionError(f"input must be an existing absolute regular file: {path}")
    return Path(os.path.abspath(path))


def input_files(args):
    files = {}
    for manifest in args.files_from:
        for number, line in enumerate(Path(manifest).read_text().splitlines(), 1):
            # Escaped sha256sum names (backslash prefix) are deliberately refused.
            match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](/.*)", line)
            if not match:
                raise CollectionError(f"invalid sha256sum entry: {manifest}:{number}")
            path = absolute_file(match[2])
            actual = digest(path)
            if actual != match[1].lower():
                raise CollectionError(f"input digest changed: {path}")
            if path in files and files[path] != actual:
                raise CollectionError(f"conflicting input digests: {path}")
            files[path] = actual
    for value in args.file:
        path = absolute_file(value)
        files[path] = digest(path)
    if not files and not args.package:
        raise CollectionError("select at least one input file, manifest, or package")
    return files


def ownership_paths(path):
    """Include Debian's pre-usrmerge spelling as well as the installed spelling."""
    paths = {str(path), str(path.resolve(strict=True))}
    # New Debian kernels copy this package-owned image into /boot at install
    # time. Attribute that generated copy only when its exact bytes still match.
    kernel = re.fullmatch(r"vmlinuz-([A-Za-z0-9][A-Za-z0-9._+-]*)", path.name)
    if path.parent == BOOT_ROOT and kernel:
        packaged = MODULE_ROOT / kernel[1] / "vmlinuz"
        if packaged.is_file() and digest(path) == digest(packaged):
            paths.add(str(packaged))
    for candidate in list(paths):
        for prefix in ("bin", "sbin", "lib", "lib32", "lib64", "libx32"):
            if candidate.startswith(f"/usr/{prefix}/"):
                paths.add(candidate[4:])
            elif candidate.startswith(f"/{prefix}/"):
                paths.add("/usr" + candidate)
    return sorted(paths)


def owners(path):
    candidates = ownership_paths(path)
    result = subprocess.run(["dpkg-query", "-S", "--", *candidates],
                            capture_output=True, text=True,
                            env={**os.environ, "LC_ALL": "C"})
    if result.returncode not in (0, 1):
        raise CollectionError(f"dpkg ownership query failed for {path}: {result.stderr.strip()}")
    packages = set()
    for line in result.stdout.splitlines():
        # dpkg -S also prints informational diversion records. Their left-hand
        # text is not an owning package, even when the right-hand path matches.
        if line.startswith(("diversion by ", "local diversion ")) or ": " not in line:
            continue
        names, found = line.split(": ", 1)
        names = names.split(", ")
        if found in candidates and all(re.fullmatch(BINARY_PACKAGE_PATTERN, name) for name in names):
            packages.update(names)
    return sorted(packages)


def package_info(package):
    output = run(["dpkg-query", "-W",
                  "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Status}\\n",
                  "--", package]).strip().split("\t")
    if len(output) != 5 or output[4] != "installed":
        raise CollectionError(f"package must be installed: {package}")
    binary, version, source, source_version, _ = output
    if not re.fullmatch(BINARY_PACKAGE_PATTERN, binary):
        raise CollectionError(f"unexpected binary package name: {binary}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", source) or not source_version:
        raise CollectionError(f"missing source identity for package: {binary}")
    return {"package": binary, "version": version,
            "source_package": source, "source_version": source_version}


def copy_notice(source, destination):
    if not source.is_file():
        raise CollectionError(f"required Debian notice missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Dereference doc-directory and common-license symlinks: output stands alone.
    destination.write_bytes(source.read_bytes())
    return digest(destination)


def control_fields(path):
    fields = {}
    current = None
    for line in path.read_text().splitlines():
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line.strip()
        elif re.match(r"^[A-Za-z][A-Za-z0-9-]*:", line):
            current, value = line.split(":", 1)
            fields[current] = value.strip()
        else:
            current = None
    return fields


def download_source(source, version, root):
    tag = hashlib.sha256(f"{source}={version}".encode()).hexdigest()[:16]
    target = root / f"{source}-{tag}"
    target.mkdir()
    run(["apt-get", "source", "--download-only", "--only-source", f"{source}={version}"], cwd=target)
    descriptors = sorted(target.glob("*.dsc"))
    if len(descriptors) != 1:
        raise CollectionError(f"expected one source descriptor for {source}={version}")
    fields = control_fields(descriptors[0])
    if fields.get("Source") != source or fields.get("Version") != version:
        raise CollectionError(f"downloaded source identity mismatch: {source}={version}")
    entries = fields.get("Checksums-Sha256", "").strip().splitlines()
    if not entries:
        raise CollectionError(f"source descriptor lacks SHA256 checksums: {descriptors[0]}")
    for entry in entries:
        parts = entry.split()
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise CollectionError(f"invalid source SHA256 entry: {descriptors[0]}")
        expected, size, name = parts
        if Path(name).name != name or name in (".", ".."):
            raise CollectionError(f"unsafe source archive name: {name}")
        archive = target / name
        if (not archive.is_file() or str(archive.stat().st_size) != size
                or digest(archive) != expected):
            raise CollectionError(f"source archive missing or corrupt: {archive}")
    artifacts = []
    for path in sorted(target.iterdir()):
        if path.is_file():
            artifacts.append({"path": str(path.relative_to(root)), "sha256": digest(path)})
    return {"source_package": source, "source_version": version, "files": artifacts}


def collect(args):
    files = input_files(args)
    allowed = {absolute_file(value) for value in args.allow_unowned}
    unused = allowed - files.keys()
    if unused:
        raise CollectionError(f"--allow-unowned path was not selected: {sorted(map(str, unused))[0]}")
    inventory = []
    selected_packages = set(args.package)
    for path, checksum in sorted(files.items()):
        packages = owners(path)
        if not packages and path not in allowed:
            raise CollectionError(f"no Debian package owns input: {path}")
        selected_packages.update(packages)
        record = {"path": str(path), "sha256": checksum, "packages": packages}
        if not packages:
            record["provenance"] = "explicitly allowed unowned project input"
        inventory.append(record)
    packages = {}
    aliases = {}
    for package in sorted(selected_packages):
        info = package_info(package)
        packages[info["package"]] = info
        aliases[package] = info["package"]
    # Canonicalize explicit names (e.g. libc6 -> libc6:amd64) in file records.
    for record in inventory:
        record["packages"] = sorted({aliases.get(name, name) for name in record["packages"]})

    output = Path(args.output)
    source_output = Path(args.source_output) if args.source_output else None
    for target in (output, source_output):
        if target is not None and (not target.is_absolute() or target.exists() or target.is_symlink()):
            raise CollectionError(f"output must be a new absolute directory: {target}")
    if source_output is not None and (output == source_output or output in source_output.parents
                                       or source_output in output.parents):
        raise CollectionError("notice and source output directories must be separate")
    output.mkdir(parents=True)
    for name, info in sorted(packages.items()):
        relative = Path("copyrights") / name / "copyright"
        doc = DOC_ROOT / name.split(":", 1)[0] / "copyright"
        # Multiarch-qualified doc directories occur in some binary packages.
        if not doc.is_file():
            doc = DOC_ROOT / name / "copyright"
        info["copyright"] = str(relative)
        info["copyright_sha256"] = copy_notice(doc, output / relative)
    if not COMMON_ROOT.is_dir():
        raise CollectionError(f"Debian common-license directory missing: {COMMON_ROOT}")
    common = []
    for path in sorted(COMMON_ROOT.iterdir()):
        if path.is_file():
            relative = Path("common-licenses") / path.name
            common.append({"path": str(relative), "sha256": copy_notice(path, output / relative)})
    if not common:
        raise CollectionError("Debian common-license directory is empty")
    result = {"format": 1,
              "scope": "Selected Debian runtime inputs and explicitly named packages; package notices and source provenance do not establish complete distribution compliance.",
              "files": inventory, "packages": list(packages.values()), "common_licenses": common,
              "sources_downloaded": source_output is not None}
    if source_output is not None:
        source_output.mkdir(parents=True)
        identities = sorted({(info["source_package"], info["source_version"])
                             for info in packages.values()})
        sources = [download_source(source, version, source_output) for source, version in identities]
        (source_output / "sources.json").write_text(json.dumps({"format": 1, "sources": sources}, indent=2) + "\n")
        result["sources"] = sources
    # Publish the manifest last: absence signals incomplete collection on failure.
    (output / "components.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--output", required=True, help="new absolute notice output directory")
    result.add_argument("--source-output", help="new directory for exact apt source downloads")
    for option, help_text in (
            ("files-from", "sha256sum manifest containing original absolute input paths"),
            ("file", "absolute installed input file"),
            ("package", "additional installed binary package, e.g. zfs-dkms or libc6-dev"),
            ("allow-unowned", "exact selected path explicitly accepted as a project input")):
        result.add_argument(f"--{option}", action="append", default=[], help=help_text)
    return result


def main():
    try:
        collect(parser().parse_args())
    except (CollectionError, OSError, UnicodeError) as error:
        print(f"collect-debian-licences: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
