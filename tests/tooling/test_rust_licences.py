#!/usr/bin/env python3
"""Notice collection from fetched Cargo metadata and an explicitly pinned sysroot."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "notices", Path(__file__).resolve().parents[2] / "dist/licences/collect-rust.py")
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class NoticeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="zfs-rust-notice-test.",
                                                 dir=os.environ.get("TMPDIR") or "/var/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.manifest = self.workspace / "Cargo.toml"
        self.manifest.write_text("[workspace]\n")
        (self.workspace / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "dep"\nversion = "1.2.3"\nsource = "registry+example"\nchecksum = "fetched-checksum"\n')
        self.sysroot = self.root / "pinned-rust"
        self.rust_docs = self.sysroot / "share/doc/rust"
        self.rust_docs.mkdir(parents=True)
        (self.rust_docs / "COPYRIGHT-library.html").write_text("exact pinned runtime attribution")
        (self.rust_docs / "COPYRIGHT.html").write_text("compiler-only attribution")
        (self.rust_docs / "LICENSE-APACHE").write_text("pinned Apache licence")
        (self.rust_docs / "licenses").mkdir()
        (self.rust_docs / "licenses/MIT.txt").write_text("pinned MIT licence")
        self.package = self.root / "registry/dep"
        self.package.mkdir(parents=True)
        (self.package / "LICENSE-MIT").write_text("fetched dep licence")
        (self.package / "Cargo.toml").write_text("[package]\n")
        (self.package / ".cargo-checksum.json").write_text('{"package":"fetched-checksum"}')
        self.metadata = {"workspace_root": str(self.workspace), "workspace_members": [],
                         "packages": [self.dep()]}
        self.output = self.root / "output"

    def dep(self, **overrides):
        package = {"name": "dep", "version": "1.2.3", "source": "registry+example",
                   "id": "registry+example#dep@1.2.3", "license": "MIT OR Apache-2.0",
                   "license_file": None, "manifest_path": str(self.package / "Cargo.toml")}
        package.update(overrides)
        return package

    def run_collect(self):
        with patch.object(subprocess, "check_output", return_value=json.dumps(self.metadata)) as command:
            inventory = notices.collect(self.manifest, self.sysroot, self.output)
        self.assertEqual(command.call_args.args[0], ["cargo", "metadata", "--format-version", "1",
            "--offline", "--locked", "--filter-platform", "x86_64-unknown-linux-gnu",
            "--manifest-path", str(self.manifest)])
        return inventory

    def test_exact_fetched_and_pinned_documents_with_bounded_native_notices(self):
        nested = self.package / "zstd"
        nested.mkdir()
        (nested / "LICENSE").write_text("vendored zstd licence")
        (nested / "COPYRIGHT").write_text("vendored copyright")
        (nested / "zstd.c").write_text("must not copy sources")
        inventory = self.run_collect()
        package = inventory["packages"][0]
        self.assertEqual(package["checksum"], "fetched-checksum")
        self.assertEqual(package["license"], "MIT OR Apache-2.0")
        texts = {Path(n["source_path"]).relative_to(self.package).as_posix():
                 (self.output / n["path"]).read_text() for n in package["notices"]}
        self.assertEqual(texts, {"LICENSE-MIT": "fetched dep licence", "zstd/LICENSE": "vendored zstd licence",
                                 "zstd/COPYRIGHT": "vendored copyright"})
        self.assertEqual((self.output / "rust/COPYRIGHT-library.html").read_text(), "exact pinned runtime attribution")
        self.assertEqual((self.output / "rust/licenses/MIT.txt").read_text(), "pinned MIT licence")
        self.assertFalse((self.output / "rust/COPYRIGHT.html").exists())
        self.assertIn("Conservative superset", inventory["scope"])
        self.assertEqual(json.loads((self.output / "inventory.json").read_text()), inventory)

    def test_missing_external_notice_fails_even_with_declared_spdx(self):
        (self.package / "LICENSE-MIT").unlink()
        with self.assertRaisesRegex(ValueError, "no licence/notice texts for dep"):
            self.run_collect()
        self.assertFalse(self.output.exists())

    def test_explicit_license_file_and_workspace_root_licences(self):
        (self.package / "LICENSE-MIT").unlink()
        (self.package / "permission.txt").write_text("explicit licence document")
        self.metadata["packages"][0]["license_file"] = "permission.txt"
        local = self.workspace / "crates/local"
        local.mkdir(parents=True)
        local_package = self.dep(name="local", id="path+local", source=None,
                                 manifest_path=str(local / "Cargo.toml"))
        self.metadata["packages"].append(local_package)
        self.metadata["workspace_members"] = ["path+local"]
        (self.workspace / "LICENSE").write_text("project MIT licence")
        inventory = self.run_collect()
        records = {p["name"]: p for p in inventory["packages"]}
        self.assertTrue(records["local"]["workspace_notice_fallback"])
        local_notice = records["local"]["notices"][0]
        self.assertEqual((self.output / local_notice["path"]).read_text(), "project MIT licence")
        self.assertEqual(local_notice["path"].split("/workspace/")[-1], "LICENSE")
        self.assertEqual(Path(records["dep"]["notices"][0]["source_path"]).name, "permission.txt")

    def test_missing_runtime_copyright_fails_without_host_fallback(self):
        (self.rust_docs / "COPYRIGHT-library.html").unlink()
        with self.assertRaisesRegex(ValueError, "COPYRIGHT-library.html"):
            self.run_collect()
        self.assertFalse(self.output.exists())

    def test_rejects_existing_output_and_leaves_contents(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("operator data")
        with self.assertRaisesRegex(ValueError, "new directory"):
            self.run_collect()
        self.assertEqual(marker.read_text(), "operator data")

    def test_rejects_escaping_explicit_license_or_notice_symlink(self):
        outside = self.root / "outside.txt"
        outside.write_text("outside source root")
        self.metadata["packages"][0]["license_file"] = str(outside)
        with self.assertRaisesRegex(ValueError, "escapes source directory"):
            self.run_collect()
        self.metadata["packages"][0]["license_file"] = None
        (self.package / "NOTICE").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes source directory"):
            self.run_collect()

    def test_checksum_disagreement_fails(self):
        (self.package / ".cargo-checksum.json").write_text('{"package":"wrong"}')
        with self.assertRaisesRegex(ValueError, "checksum disagrees"):
            self.run_collect()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
