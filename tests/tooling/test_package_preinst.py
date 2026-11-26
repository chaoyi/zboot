#!/usr/bin/env python3
"""The package's preinst refuses while a zboot operation is pending.

A stand-in `zfs` on PATH prints a fixed `zfs get` listing; no pool is read.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PREINST = ROOT / 'dist/deb/preinst'


class Preinst(unittest.TestCase):
    def run_preinst(self, listing, action='upgrade', zfs=True, status=0):
        with tempfile.TemporaryDirectory(prefix='zboot-preinst-test.',
                                         dir=os.environ.get('TMPDIR') or '/var/tmp') as tmp:
            bin_dir = Path(tmp)
            if zfs:
                (bin_dir / 'listing').write_text(listing)
                fake = bin_dir / 'zfs'
                fake.write_text(f'#!/bin/sh\ncat {bin_dir / "listing"}\nexit {status}\n')
                fake.chmod(0o755)
            for tool in ('awk', 'cat', 'sh', 'printf'):
                found = subprocess.run(['sh', '-c', f'command -v {tool}'],
                                       capture_output=True, text=True).stdout.strip()
                if found.startswith('/') and not (bin_dir / tool).exists():
                    (bin_dir / tool).symlink_to(found)
            env = {'PATH': str(bin_dir), 'LC_ALL': 'C'}
            return subprocess.run(['/bin/sh', str(PREINST), action],
                                  capture_output=True, text=True, env=env)

    def test_nothing_pending_installs(self):
        result = self.run_preinst('rpool\tzsnap:policy\tdaily\nrpool/data\tzboot:pair\t{}\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_operation_record_refuses(self):
        result = self.run_preinst('bpool\tzboot:operation\t{"kind":"sync"}\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('bpool: operation record', result.stderr)
        self.assertIn('zboot abandon', result.stderr)

    def test_no_zfs_or_no_module_installs_and_other_actions_never_check(self):
        self.assertEqual(self.run_preinst('', zfs=False).returncode, 0)
        self.assertEqual(self.run_preinst('bpool\tzboot:operation\tx\n', status=1).returncode, 0)
        self.assertEqual(
            self.run_preinst('bpool\tzboot:operation\tx\n', action='abort-upgrade').returncode, 0)


if __name__ == '__main__':
    unittest.main()
