#!/usr/bin/env python3
"""File-only console selection contract of dist/initramfs/console.sh; needs /bin/busybox."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[2] / "dist/initramfs/console.sh"


class ConsoleSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="zboot-console-test.",
                                                 dir=os.environ.get("TMPDIR") or "/var/tmp")
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name) / "fwcfg"
        self.entry.mkdir()

    def select(self, raw=None, size=None):
        """Offer RAW as the firmware entry, declaring SIZE bytes (default: its length)."""
        if raw is not None:
            (self.entry / "raw").write_bytes(raw)
            (self.entry / "size").write_text(str(len(raw) if size is None else size) + "\n")
        return subprocess.run(
            ["sh", "-eu", "-c", '. "$1"; zboot_console_from_firmware "$2"; printf "%s" "$ZBOOT_CONSOLE"',
             "test", str(HELPER), str(self.entry)], capture_output=True, text=True, check=True, timeout=10)

    def assert_physical_with_warning(self, result):
        self.assertEqual(result.stdout, "tty0")
        self.assertIn("invalid firmware console", result.stderr)

    def test_console_defaults_physical_and_requires_exact_firmware_serial_value(self):
        absent = self.select()
        self.assertEqual((absent.stdout, absent.stderr), ("tty0", ""))
        selected = self.select(b"ttyS0")
        self.assertEqual((selected.stdout, selected.stderr), ("ttyS0", ""))
        for value in (b"", b"tty0", b"ttyS0\n", b"ttyS0\0", b"/dev/ttyS0", b"tty;0", b"x" * 10000):
            with self.subTest(value=value[:20]):
                self.assert_physical_with_warning(self.select(value))

    def test_console_selection_reads_only_the_fixed_payload_and_needs_its_size(self):
        # Longer payloads and missing size metadata are rejected with bounded reads.
        self.assert_physical_with_warning(self.select(b"ttyS0" + b"x" * 10000, size=5 + 10000))
        self.assert_physical_with_warning(self.select(b"other" + b"x" * 10000, size=5))
        (self.entry / "raw").write_bytes(b"ttyS0")
        (self.entry / "size").unlink()
        self.assert_physical_with_warning(self.select())


if __name__ == "__main__":
    unittest.main()
