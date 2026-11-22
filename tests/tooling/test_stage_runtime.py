#!/usr/bin/env python3
"""File-only runtime staging contract; no daemon or storage tool is started."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_change_key import native_artifacts as change_key_artifacts
from test_signature_probe import native_artifacts as signature_probe_artifacts

INITRAMFS = Path(__file__).resolve().parents[2] / "dist/initramfs"
SCRIPT = (INITRAMFS / "stage-runtime.sh").read_text()
# The script's own (SOURCE, DESTINATION) table: the fixture root provides
# every source, and each must reach its destination.
PROGRAMS = [tuple(row.split()[:2]) for row in re.findall(
    r"^    '([^']+)'$", SCRIPT.split("programs=(\n", 1)[1].split("\n)\n", 1)[0], re.M)]


class RuntimeStagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="zfs-runtime-test.",
                                                 dir=os.environ.get("TMPDIR") or "/var/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "output"
        # The build root and helpers directory dist.sh passes as / and /work.
        self.substrate = self.root / "substrate"
        self.helpers = self.root / "helpers"
        self.helpers.mkdir()
        self.program = self.root / "program"
        self.program.write_text("#!/bin/sh\nexit 99\n")
        self.program.chmod(0o755)
        for source, _ in PROGRAMS:
            self.install(source, self.program)
        self.busybox = self.source("/bin/busybox")
        self.busybox.write_text("#!/bin/sh\n[ \"$1\" = --list ] || exit 99\ncat <<'EOF'\n"
                               "dd\nsh\nmount\numount\nmkdir\nsleep\ncat\nls\nmdev\nreboot\n"
                               "poweroff\nchroot\nmknod\nchmod\ncp\nsync\nsha256sum\nawk\n"
                               "rm\ntouch\nswitch_root\nip\nudhcpc\nmkpasswd\nEOF\n")
        self.rules = self.substrate / "usr/lib/udev/rules.d"
        self.rules.mkdir(parents=True)
        for name in ("60-block.rules", "60-persistent-storage.rules", "80-drivers.rules"):
            (self.rules / name).write_text(f"# trusted packaged fixture: {name}\n")
        self.modules = self.root / "6.12-test"
        (self.modules / "kernel").mkdir(parents=True)
        (self.modules / "modules.dep").write_text("kernel/test.ko:\n")
        (self.modules / "kernel/test.ko").write_bytes(b"module fixture")
        self.firmware = self.substrate / "usr/lib/firmware"
        self.firmware.mkdir(parents=True)
        self.firmware_names = ("rtl_nic/rtl8156a-2.fw", "rtl_nic/rtl8156b-2.fw")
        (self.firmware / "rtl_nic").mkdir()
        for name in self.firmware_names:
            (self.firmware / name).write_bytes(f"trusted public firmware fixture: {name}".encode())
        self.command = ["bash", str(INITRAMFS / "stage-runtime.sh"), "--root", str(self.substrate),
                        "--helpers-dir", str(self.helpers), "--module-dir", str(self.modules),
                        "--output", str(self.output)]
        for name in self.firmware_names:
            self.command += ["--firmware", name]

    def source(self, path):
        """The fixture file a table SOURCE names."""
        if path.startswith("helpers/"):
            return self.helpers / path.removeprefix("helpers/")
        return self.substrate / path.lstrip("/")

    def install(self, path, program):
        file = self.source(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.unlink(missing_ok=True)
        shutil.copyfile(program, file)
        file.chmod(0o755)
        return file

    def run_stage(self):
        return subprocess.run(self.command, capture_output=True, text=True, timeout=30)

    def staged(self, path):
        """A regular file of the staged root, by its absolute runtime path."""
        file = self.output / str(path).lstrip("/")
        self.assertTrue(file.is_file() and not file.is_symlink(), path)
        return file.read_bytes()

    def staged_names(self, suffix):
        return sorted(str(path.relative_to(self.output)) for path in self.output.rglob(f"*{suffix}"))

    def manifest(self):
        return self.staged("usr/share/zfs-tools/runtime-sources.sha256").decode()

    def assert_nothing_staged(self):
        # Neither the output nor the private sibling it is staged in survives.
        self.assertEqual(sorted(path.name for path in self.root.glob("output*")), [])

    def test_storage_runtime_contains_exact_rules_helpers_and_provenance(self):
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(sorted(path.name for path in self.root.glob("output*")), ["output"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.staged_names(".rules"), [
            "usr/lib/udev/rules.d/60-block.rules",
            "usr/lib/udev/rules.d/60-persistent-storage.rules",
        ])
        self.assertEqual(len(PROGRAMS), 30)
        for source, destination in PROGRAMS:
            self.assertEqual(self.staged(destination), self.source(source).read_bytes(), source)
            self.assertIn(f"  {self.source(source)}\n", self.manifest())
        for path in ("usr/lib/systemd/systemd-udevd", "usr/bin/udevadm",
                     "usr/lib/udev/ata_id", "usr/lib/udev/scsi_id", "sbin/zboot-probe-signatures",
                     "sbin/zboot-change-key",
                     "usr/sbin/sshd", "usr/lib/openssh/sshd-auth", "usr/lib/openssh/sshd-session",
                     "usr/bin/ssh-keygen", "bin/ip", "sbin/nvme", "usr/sbin/losetup"):
            self.assertEqual(self.staged(path), self.program.read_bytes())
        for name in ("60-block.rules", "60-persistent-storage.rules"):
            source = self.rules / name
            self.assertEqual(self.staged(f"usr/lib/udev/rules.d/{name}"), source.read_bytes())
            self.assertIn(f"{hashlib.sha256(source.read_bytes()).hexdigest()}  {source}\n", self.manifest())
        self.assertTrue((self.output / "bin/dd").is_symlink())
        self.assertEqual(os.readlink(self.output / "bin/mkpasswd"), "busybox")

    def test_module_tree_keeps_modules_and_drops_build_links_and_kernel_image(self):
        for name in ("vmlinuz", "System.map", "config"):
            (self.modules / name).write_bytes(b"not a runtime input")
        for name in ("build", "source"):
            (self.modules / name).symlink_to(self.root / "headers")
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        tree = self.output / "lib/modules" / self.modules.name
        self.assertEqual(sorted(str(path.relative_to(tree)) for path in tree.rglob("*")),
                         ["kernel", "kernel/test.ko", "modules.dep"])
        self.assertEqual(self.staged(f"lib/modules/{self.modules.name}/kernel/test.ko"), b"module fixture")

    def test_selected_firmware_uses_kernel_lookup_paths_and_hashes(self):
        # A third selection proves staging follows the lock's list rather than
        # a built-in pair of RTL8156 names.
        extra = "other_nic/custom.fw"
        (self.firmware / "other_nic").mkdir()
        (self.firmware / extra).write_bytes(b"additional selected firmware")
        (self.firmware / "unselected.fw").write_bytes(b"must not stage")
        self.command += ["--firmware", extra]
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = (*self.firmware_names, extra)
        self.assertEqual(self.staged_names(".fw"), sorted(f"lib/firmware/{name}" for name in selected))
        for name in selected:
            source = self.firmware / name
            self.assertEqual(self.staged(f"lib/firmware/{name}"), source.read_bytes())
            self.assertIn(f"{hashlib.sha256(source.read_bytes()).hexdigest()}  {source}\n", self.manifest())
        self.assertFalse((self.output / "bin/udhcpc").exists())

    def test_contained_packaged_firmware_symlink_stages_resolved_bytes(self):
        source = self.firmware / self.firmware_names[0]
        original = source.read_bytes()
        target = self.firmware / "packaged.fw"
        target.write_bytes(original)
        source.unlink()
        source.symlink_to("../packaged.fw")
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.staged(f"lib/firmware/{self.firmware_names[0]}"), original)

    def test_missing_firmware_refuses_before_output(self):
        (self.firmware / self.firmware_names[0]).unlink()
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required firmware missing", result.stderr)
        self.assertFalse(self.output.exists())

    def test_firmware_selections_are_required(self):
        while "--firmware" in self.command:
            index = self.command.index("--firmware")
            del self.command[index:index + 2]
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("at least one --firmware selection is required", result.stderr)
        self.assertFalse(self.output.exists())

    def test_firmware_root_is_required(self):
        shutil.rmtree(self.firmware)
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("firmware root directory is required", result.stderr)
        self.assertFalse(self.output.exists())

    def test_unsafe_firmware_names_refuse_before_output(self):
        for name in ("../program", "/etc/passwd", "rtl_nic/../../program",
                     "rtl_nic/./rtl8156a-2.fw", "rtl_nic//rtl8156a-2.fw", "", ".", ".."):
            with self.subTest(name=name):
                result = subprocess.run(self.command + ["--firmware", name],
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsafe firmware path", result.stderr)
                self.assertFalse(self.output.exists())

    def test_firmware_file_and_directory_symlink_escapes_refuse_before_output(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "escape.fw").write_bytes(b"outside firmware root")
        (self.firmware / "escape.fw").symlink_to(outside / "escape.fw")
        (self.firmware / "escape-dir").symlink_to(outside, target_is_directory=True)
        for name in ("escape.fw", "escape-dir/escape.fw"):
            with self.subTest(name=name):
                result = subprocess.run(self.command + ["--firmware", name],
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("firmware must be a nonempty file within firmware root", result.stderr)
                self.assertFalse(self.output.exists())

    def test_empty_or_directory_firmware_refuses_before_output(self):
        (self.firmware / "empty.fw").touch()
        (self.firmware / "directory.fw").mkdir()
        for name in ("empty.fw", "directory.fw"):
            with self.subTest(name=name):
                result = subprocess.run(self.command + ["--firmware", name],
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("firmware must be a nonempty file within firmware root", result.stderr)
                self.assertFalse(self.output.exists())

    def test_missing_dhcp_applet_refuses_runtime_publication(self):
        self.busybox.write_text(self.busybox.read_text().replace("udhcpc\n", ""))
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("busybox lacks udhcpc", result.stderr)
        self.assert_nothing_staged()

    def test_missing_password_hash_applet_refuses_runtime_publication(self):
        self.busybox.write_text(self.busybox.read_text().replace("mkpasswd\n", ""))
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("busybox lacks mkpasswd", result.stderr)
        self.assert_nothing_staged()

    def test_every_missing_program_refuses_before_output(self):
        for source, _ in PROGRAMS:
            with self.subTest(source=source):
                file = self.source(source)
                saved = file.read_bytes()
                file.unlink()
                result = self.run_stage()
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"required trusted executable missing: {file}", result.stderr)
                self.assert_nothing_staged()
                # Present but not executable is missing too.
                file.write_bytes(saved)
                result = self.run_stage()
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"required trusted executable missing: {file}", result.stderr)
                self.assert_nothing_staged()
                file.chmod(0o755)

    def test_signature_helper_and_dynamic_dependencies_are_hashed_and_staged(self):
        helper = self.install("helpers/zboot-probe-signatures", signature_probe_artifacts()[0])
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        dependencies = subprocess.run(["ldd", str(helper)], capture_output=True,
                                      text=True, check=True).stdout
        self.assertIn("libblkid", dependencies)
        paths = [word for word in dependencies.split() if word.startswith("/")]
        self.assertEqual(self.staged("sbin/zboot-probe-signatures"), helper.read_bytes())
        for source in [helper] + [Path(path) for path in paths]:
            self.assertIn(f"{hashlib.sha256(source.read_bytes()).hexdigest()}  {source}\n", self.manifest())
        for path in paths:
            self.assertEqual(self.staged(path), Path(path).read_bytes())

    def test_change_key_helper_and_libzfs_core_closure_are_hashed_and_staged(self):
        helper = self.install("helpers/zboot-change-key", change_key_artifacts()[0])
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        dependencies = subprocess.run(["ldd", str(helper)], capture_output=True,
                                      text=True, check=True).stdout
        self.assertIn("libzfs_core.so.3", dependencies)
        self.assertIn("libnvpair.so.3", dependencies)
        paths = [word for word in dependencies.split() if word.startswith("/")]
        self.assertEqual(self.staged("sbin/zboot-change-key"), helper.read_bytes())
        for source in [helper] + [Path(path) for path in paths]:
            self.assertIn(f"{hashlib.sha256(source.read_bytes()).hexdigest()}  {source}\n", self.manifest())
        for path in paths:
            self.assertEqual(self.staged(path), Path(path).read_bytes())

    def test_ram_boot_files_are_busybox_tar_zstd_and_their_libraries(self):
        # `zboot boot --tar` copies exactly these into its initramfs.
        program = self.install("/usr/bin/zstd", shutil.which("true"))
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        dependencies = subprocess.run(["ldd", str(program)], capture_output=True,
                                      text=True, check=True).stdout
        paths = [word for word in dependencies.split() if word.startswith("/")]
        self.assertTrue(paths)
        listed = self.staged("usr/lib/zboot/ram-boot.files").decode().splitlines()
        self.assertEqual(listed, sorted({"/bin/busybox", "/bin/tar", "/bin/zstd", *paths}))
        for path in listed:
            self.staged(path)

    def test_missing_storage_rule_refuses_before_output(self):
        (self.rules / "60-persistent-storage.rules").unlink()
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required packaged udev rule missing", result.stderr)
        self.assertFalse(self.output.exists())

    def test_applet_probe_consumes_output_without_producer_sigpipe(self):
        # A producer larger than the pipe buffer deterministically exposes an
        # early-closing grep -q under the staging script's pipefail setting.
        script = self.busybox.read_text()
        self.busybox.write_text(script.replace("mkpasswd\nEOF\n",
                                               "mkpasswd\n" + "unused\n" * 16384 + "EOF\n"))
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_option_and_missing_directories_refuse_before_output(self):
        complete = list(self.command)
        # The retired per-program flags are unknown now.
        for extra in (["--kexec", str(self.program)], ["--unlisted", str(self.program)],
                      ["--", str(self.program)], ["stray", "pair"]):
            with self.subTest(extra=extra):
                result = subprocess.run(complete + extra, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"unknown argument: {extra[0]}", result.stderr)
        for option, message in (("--root", "root must be"), ("--helpers-dir", "helpers directory must be")):
            for value in (None, str(self.root / "absent"), "relative"):
                with self.subTest(option=option, value=value):
                    command = list(complete)
                    index = command.index(option)
                    if value is None:
                        del command[index:index + 2]
                    else:
                        command[index + 1] = value
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(message, result.stderr)
        self.assert_nothing_staged()

    def test_udev_executable_loader_dependencies_are_staged(self):
        # Use a trusted installed ELF fixture without starting a daemon.
        program = self.install("/usr/lib/systemd/systemd-udevd", shutil.which("true"))
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        dependencies = subprocess.run(["ldd", str(program)], capture_output=True,
                                      text=True, check=True).stdout
        paths = [word for word in dependencies.split() if word.startswith("/")]
        self.assertTrue(paths)
        for path in paths:
            self.assertEqual(self.staged(path), Path(path).read_bytes())


if __name__ == "__main__":
    unittest.main()
