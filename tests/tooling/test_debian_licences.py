#!/usr/bin/python3
"""Bounded notice/source collector tests; no network or package changes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "collector", Path(__file__).resolve().parents[2] / "dist/licences/collect-debian.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="zfs-notices-test.",
                                                 dir=os.environ.get("TMPDIR") or "/var/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.file = self.root / "runtime file"
        self.file.write_bytes(b"selected executable fixture\n")
        self.output = self.root / "notices"
        self.source_output = self.root / "sources"
        self.docs = self.root / "doc"
        self.common = self.root / "common"
        self.common.mkdir()
        (self.common / "GPL-2").write_text("complete GPL fixture\n")
        (self.common / "GPL").symlink_to("GPL-2")
        for name in ("runtime", "runtime-extra", "libc6-dev"):
            directory = self.docs / name
            directory.mkdir(parents=True)
            (directory / "copyright").write_text(f"{name} copyright; see /usr/share/common-licenses/GPL-2\n")
        # Preserve documentation reached through installed Debian symlinks.
        (self.docs / "zfs-dkms").symlink_to("runtime")
        self.commands = []
        self.ownership = {str(self.file): "runtime:amd64"}
        self.source_failure = False
        self.corrupt_source = False
        for attribute, value in (("DOC_ROOT", self.docs), ("COMMON_ROOT", self.common)):
            patcher = patch.object(collector, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(collector.subprocess, "run", side_effect=self.command)
        patcher.start()
        self.addCleanup(patcher.stop)

    def command(self, command, cwd=None, **kwargs):
        self.commands.append((command, cwd))
        if command[:2] == ["dpkg-query", "-S"]:
            lines = [f"{self.ownership[path]}: {path}\n" for path in command[3:] if path in self.ownership]
            return subprocess.CompletedProcess(command, 0 if lines else 1, "".join(lines), "")
        if command[:2] == ["dpkg-query", "-W"]:
            package = command[-1]
            name = package.split(":", 1)[0]
            if name == "absent":
                return subprocess.CompletedProcess(command, 1, "", "package not installed")
            source = "glibc" if name == "libc6-dev" else "shared-source"
            return subprocess.CompletedProcess(command, 0,
                f"{name}:amd64\t2.0-1\t{source}\t1:2.0-1\tinstalled\n", "")
        if command[:2] == ["apt-get", "source"]:
            if self.source_failure:
                return subprocess.CompletedProcess(command, 100, "", "deb-src unavailable")
            source, version = command[-1].split("=", 1)
            archive = Path(cwd) / f"{source}_2.0.orig.tar.gz"
            archive.write_bytes(b"exact source archive fixture\n")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            (Path(cwd) / f"{source}_2.0-1.dsc").write_text(
                f"Format: 3.0 (quilt)\nSource: {source}\nVersion: {version}\n"
                f"Checksums-Sha256:\n {checksum} {archive.stat().st_size} {archive.name}\n")
            if self.corrupt_source:
                archive.write_bytes(b"corrupt")
            return subprocess.CompletedProcess(command, 0, "", "")
        self.fail(f"unexpected subprocess: {command}")

    def args(self, *extra):
        return collector.parser().parse_args(["--output", str(self.output), "--file", str(self.file), *extra])

    def test_manifest_hash_and_self_contained_notices(self):
        manifest = self.root / "inputs.sha256"
        checksum = hashlib.sha256(self.file.read_bytes()).hexdigest()
        manifest.write_text(f"{checksum}  {self.file}\n")
        args = collector.parser().parse_args(["--output", str(self.output), "--files-from", str(manifest)])
        result = collector.collect(args)
        self.assertEqual(result["files"], [{"path": str(self.file), "sha256": checksum, "packages": ["runtime:amd64"]}])
        self.assertEqual(result["packages"][0]["source_version"], "1:2.0-1")
        self.assertEqual((self.output / "common-licenses/GPL").read_text(), "complete GPL fixture\n")
        self.assertFalse((self.output / "common-licenses/GPL").is_symlink())
        self.assertIn("runtime copyright", (self.output / "copyrights/runtime:amd64/copyright").read_text())
        self.assertFalse(result["sources_downloaded"])
        self.assertTrue((self.output / "components.json").is_file())

    def test_changed_manifest_input_fails_before_output(self):
        manifest = self.root / "inputs.sha256"
        manifest.write_text(f"{'0' * 64}  {self.file}\n")
        with self.assertRaisesRegex(collector.CollectionError, "digest changed"):
            collector.collect(self.args("--files-from", str(manifest)))
        self.assertFalse(self.output.exists())

    def test_unknown_ownership_requires_exact_selected_exception(self):
        self.ownership.clear()
        with self.assertRaisesRegex(collector.CollectionError, "no Debian package owns"):
            collector.collect(self.args())
        result = collector.collect(self.args("--allow-unowned", str(self.file)))
        self.assertEqual(result["files"][0]["packages"], [])
        self.assertIn("explicitly allowed", result["files"][0]["provenance"])

    def test_unused_unowned_exception_fails(self):
        other = self.root / "other"
        other.write_text("other")
        with self.assertRaisesRegex(collector.CollectionError, "was not selected"):
            collector.collect(self.args("--allow-unowned", str(other)))

    def test_usrmerge_ownership_queries_both_spellings(self):
        self.ownership = {"/bin/sh": "runtime:amd64"}
        self.assertEqual(collector.owners(Path("/usr/bin/sh")), ["runtime:amd64"])
        query = self.commands[-1][0]
        self.assertIn("/bin/sh", query)
        self.assertIn("/usr/bin/sh", query)

    def test_ownership_ignores_diversions_and_keeps_real_package_rows(self):
        output = (f"diversion by libc6 from: {self.file}\n"
                  f"diversion by libc6 to: {self.file}.usr-is-merged\n"
                  f"local diversion from: {self.file}\n"
                  f"not a package, runtime:amd64: {self.file}\n"
                  f"runtime:amd64, runtime-extra:amd64: {self.file}\n")
        with patch.object(collector.subprocess, "run", return_value=
                          subprocess.CompletedProcess([], 0, output, "")):
            self.assertEqual(collector.owners(self.file), ["runtime-extra:amd64", "runtime:amd64"])

    def test_diversion_without_real_owner_remains_unowned(self):
        output = f"diversion by libc6 from: {self.file}\n"
        with patch.object(collector.subprocess, "run", return_value=
                          subprocess.CompletedProcess([], 0, output, "")):
            with self.assertRaisesRegex(collector.CollectionError, "no Debian package owns"):
                collector.collect(self.args())
        self.assertFalse(self.output.exists())

    def kernel_copy(self, matching):
        boot = self.root / "boot"
        modules = self.root / "modules"
        boot.mkdir()
        (modules / "7.2-test").mkdir(parents=True)
        image = boot / "vmlinuz-7.2-test"
        packaged = modules / "7.2-test/vmlinuz"
        image.write_bytes(b"kernel image fixture")
        packaged.write_bytes(image.read_bytes() if matching else b"different kernel bytes")
        self.ownership = {str(packaged): "runtime:amd64"}
        for attribute, value in (("BOOT_ROOT", boot), ("MODULE_ROOT", modules)):
            patcher = patch.object(collector, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        return image, packaged

    def test_generated_boot_kernel_matches_package_owned_image(self):
        image, packaged = self.kernel_copy(matching=True)
        result = collector.collect(self.args("--file", str(image), "--allow-unowned", str(self.file)))
        record = next(item for item in result["files"] if item["path"] == str(image))
        self.assertEqual(record["packages"], ["runtime:amd64"])
        self.assertEqual(record["sha256"], collector.digest(image))
        self.assertIn(str(packaged), collector.ownership_paths(image))

    def test_generated_boot_kernel_with_different_bytes_is_unowned(self):
        image, packaged = self.kernel_copy(matching=False)
        self.assertNotIn(str(packaged), collector.ownership_paths(image))
        with self.assertRaisesRegex(collector.CollectionError, "no Debian package owns"):
            collector.collect(self.args("--file", str(image), "--allow-unowned", str(self.file)))

    def test_explicit_packages_and_exact_source_downloads_are_deduplicated(self):
        result = collector.collect(self.args("--package", "zfs-dkms", "--package", "libc6-dev",
                                             "--package", "runtime-extra",
                                             "--source-output", str(self.source_output)))
        self.assertEqual(len(result["packages"]), 4)
        commands = [command for command, _ in self.commands if command[0] == "apt-get"]
        self.assertEqual(len(commands), 2)
        self.assertEqual({command[-1] for command in commands}, {"shared-source=1:2.0-1", "glibc=1:2.0-1"})
        self.assertTrue(all("--download-only" in command and "--only-source" in command for command in commands))
        sources = json.loads((self.source_output / "sources.json").read_text())["sources"]
        self.assertEqual(len(sources), 2)
        for source in sources:
            self.assertEqual(len(source["files"]), 2)
            for artifact in source["files"]:
                self.assertEqual(artifact["sha256"], collector.digest(self.source_output / artifact["path"]))
        self.assertEqual((self.output / "copyrights/zfs-dkms:amd64/copyright").read_text(),
                         (self.docs / "runtime/copyright").read_text())

    def test_source_fetch_failure_does_not_publish_inventory(self):
        self.source_failure = True
        with self.assertRaisesRegex(collector.CollectionError, "deb-src unavailable"):
            collector.collect(self.args("--source-output", str(self.source_output)))
        self.assertFalse((self.output / "components.json").exists())

    def test_corrupt_source_download_fails(self):
        self.corrupt_source = True
        with self.assertRaisesRegex(collector.CollectionError, "missing or corrupt"):
            collector.collect(self.args("--source-output", str(self.source_output)))
        self.assertFalse((self.output / "components.json").exists())

    def test_missing_notice_fails_and_existing_output_is_preserved(self):
        (self.docs / "runtime/copyright").unlink()
        with self.assertRaisesRegex(collector.CollectionError, "notice missing"):
            collector.collect(self.args())
        sentinel = self.output / "operator-file"
        sentinel.write_text("preserve")
        with self.assertRaisesRegex(collector.CollectionError, "new absolute directory"):
            collector.collect(self.args())
        self.assertEqual(sentinel.read_text(), "preserve")

    def test_package_only_and_missing_package(self):
        args = collector.parser().parse_args(["--output", str(self.output), "--package", "libc6-dev"])
        result = collector.collect(args)
        self.assertEqual(result["files"], [])
        self.assertEqual(result["packages"][0]["source_package"], "glibc")
        with self.assertRaisesRegex(collector.CollectionError, "package not installed"):
            collector.collect(self.args("--package", "absent"))


if __name__ == "__main__":
    unittest.main()
