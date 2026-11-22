"""File-only regressions for acceptance recipes, harness boundaries and shell fixtures."""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class ResourcePolicyTests(unittest.TestCase):
    def test_acceleration_is_explicit_and_never_silently_falls_back(self):
        from host.vm import accelerator_args, accelerator_config, default_memory_mib
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(accelerator_args(accelerator_config()),
                             ['-machine', 'q35,accel=kvm', '-cpu', 'host'])
            self.assertEqual(default_memory_mib('SMOKE'), 2048)
            self.assertEqual(default_memory_mib('OTHER'), 8192)
        with patch.dict(os.environ, {'ZBOOT_VM_ACCEL': 'tcg', 'ZBOOT_VM_MEMORY_MIB': '3072'}):
            self.assertTrue(accelerator_config()['experimental'])
            self.assertEqual(accelerator_args(accelerator_config()),
                             ['-machine', 'q35,accel=tcg', '-cpu', 'max'])
            self.assertEqual(default_memory_mib('OTHER'), 3072)
        for invalid in ('auto', 'kvm:tcg', ''):
            with patch.dict(os.environ, {'ZBOOT_VM_ACCEL': invalid}), self.assertRaises(ValueError):
                accelerator_config()
        for invalid in ('0', '-1', 'a', '1048577'):
            with patch.dict(os.environ, {'ZBOOT_VM_MEMORY_MIB': invalid}), self.assertRaises(ValueError):
                default_memory_mib('SMOKE')

    def test_selection_cannot_succeed_empty_and_deduplicates_overlapping_names(self):
        import run as acceptance
        module = SimpleNamespace(ID='SMOKE', GROUP='small')
        self.assertEqual(acceptance.select_cases(['SMOKE', 'small'], {'SMOKE': module}), [module])
        for names in ([], ['absent'], ['restore']):
            with self.subTest(names=names), self.assertRaises(RuntimeError):
                acceptance.select_cases(names, {'SMOKE': module})

    def test_selected_prepare_copies_distribution_tools_without_unrelated_bulk_inputs(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            out = root / 'out'
            out.mkdir()
            build = {'directory': out}
            for name in ('uki', 'kernel', 'zboot', 'zsnap'):
                build[name] = out / name
                build[name].write_bytes(name.encode())
            record = root / 'build.json'
            record.write_text(json.dumps({'source_oid': 'a' * 40, 'files': {
                path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in out.iterdir()}}))
            prepared = []
            def logged(argv, *_args, **_kwargs):
                prepared.append(argv)
                Path(argv[argv.index('--output') + 1]).write_bytes(b'fixture')
            with patch.object(acceptance, 'STATE', root / 'state'), \
                    patch.object(acceptance, 'clean_at'), \
                    patch.object(acceptance, 'verify_product_source'), \
                    patch.object(acceptance, 'uki_output', return_value=build), \
                    patch.object(acceptance, 'uki_section', side_effect=lambda _p, name: b'kernel' if name == '.linux' else b'initrd'), \
                    patch.object(acceptance, 'HOST_TOOLS', []), \
                    patch.object(acceptance.shutil, 'disk_usage', return_value=SimpleNamespace(free=15 << 30)), \
                    patch.object(acceptance, 'logged', side_effect=logged), \
                    patch.object(acceptance, 'run_build') as rebuild, \
                    patch.object(acceptance.subprocess, 'run') as verify, patch('builtins.print'):
                acceptance.prepare('a' * 40, ['SMOKE'], out, distribution_tools=True, build_record=record)
            rebuild.assert_not_called()
            verify.assert_called_once()
            self.assertEqual(len(prepared), 1)
            self.assertNotIn('--fixture-directory', prepared[0])
            session, = (root / 'state/runs').iterdir()
            self.assertEqual((session / 'bin/zboot').read_bytes(), b'zboot')
            receipt = json.loads((session / 'resources.json').read_text())
            self.assertEqual(receipt['selected_cases'], ['SMOKE'])
            self.assertEqual(receipt['prepared_groups'], ['small'])
            self.assertGreater(receipt['known_input_copy_bytes'], 0)
            self.assertEqual(receipt['free_bytes_before'], 15 << 30)
            self.assertEqual(list(session.glob('restore*')), [])

    def test_distribution_tools_require_matching_source_and_every_selected_input_hash(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            build = {name: root / name for name in ('uki', 'kernel', 'zboot', 'zsnap')}
            for path in build.values():
                path.write_bytes(path.name.encode())
            record = root / 'build.json'
            files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in build.values()}
            with self.assertRaisesRegex(RuntimeError, 'requires --build-record'):
                acceptance.verify_distribution_record(build, 'a' * 40, None)
            record.write_text(json.dumps({'source_oid': 'a' * 40, 'files': files}))
            with patch.object(acceptance, 'verify_product_source') as proof:
                self.assertEqual(acceptance.verify_distribution_record(build, 'a' * 40, record), record)
                proof.assert_called_once_with(acceptance.SOURCE, 'a' * 40, 'a' * 40)
            build['zsnap'].write_bytes(b'other-source')
            with patch.object(acceptance, 'verify_product_source'), self.assertRaisesRegex(RuntimeError, 'zsnap: distribution bytes'):
                acceptance.verify_distribution_record(build, 'a' * 40, record)

    def test_a_passed_case_gives_up_its_boot_images_and_keeps_its_evidence(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            case = root / 'cases/SMOKE-20260101T000000Z'
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'kept.raw').write_bytes(b'x' * 8192)
            for boot in ('boot-1', 'boot-2'):
                (case / boot).mkdir(parents=True)
                for name in ('kernel', 'initrd', 'code.fd', 'vars.fd', 'boot.raw', 'case-image-0.raw'):
                    (case / boot / name).write_bytes(b'x' * 8192)
                for name in ('console.log', 'qemu.log', 'test.log', 'launch.json'):
                    (case / boot / name).write_text('evidence')
            (case / 'boot-1/disk-A.raw').write_bytes(b'x' * 65536)
            os.link(case / 'boot-1/disk-A.raw', case / 'boot-2/disk-A.raw')  # carried across a power cut
            (case / 'out').mkdir()
            (case / 'out/verdict.out').write_text('evidence')
            (case / 'out/looks-like.raw').write_text('evidence under another directory')
            (case / 'result.json').write_text('{}')
            (case / 'boot-1/alias.raw').symlink_to(outside / 'kept.raw')
            (case / 'boot-1/nested.raw').mkdir()
            (case / 'boot-9').symlink_to(outside, target_is_directory=True)
            before = sum(p.lstat().st_blocks * 512 for p in {p.lstat().st_ino: p for p in case.rglob('*')
                                                        if p.is_file() and not p.is_symlink()
                                                        and p.parent.name.startswith('boot-')
                                                        and (p.suffix in ('.raw', '.fd') or p.name in ('kernel', 'initrd'))}.values())
            freed = acceptance.discard_boot_bulk(case)
            self.assertEqual(freed, before, 'each image counts once, however many boots link it')
            left = sorted(str(p.relative_to(case)) for p in case.rglob('*') if not p.is_dir() or p.is_symlink())
            self.assertEqual(left, sorted(
                [f'{boot}/{name}' for boot in ('boot-1', 'boot-2')
                 for name in ('console.log', 'qemu.log', 'test.log', 'launch.json')]
                + ['boot-1/alias.raw', 'boot-9', 'out/verdict.out', 'out/looks-like.raw', 'result.json']))
            self.assertTrue((case / 'boot-1/nested.raw').is_dir())
            self.assertEqual((outside / 'kept.raw').read_bytes(), b'x' * 8192)
            self.assertEqual(acceptance.discard_boot_bulk(case), 0)

    def test_run_rejects_missing_selected_fixture_before_a_vm_can_start(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            session = Path(temporary)
            (session / 'source.oid').write_text('a' * 40)
            with patch.object(acceptance.subprocess, 'run'), self.assertRaisesRegex(RuntimeError, 'missing prepared fixture'):
                acceptance.run(session, ['SMOKE'], dev=True)


class ProductSourceProofTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp'))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.product_files = ('Cargo.toml', 'Cargo.lock', 'crates/sdk.rs', 'dist/build.lock', 'LICENSE', 'docs/BUILD.md')
        for name in (*self.product_files, 'tests/case.py', '.github/workflows/ci.yml', '.gitignore'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('original\n' if name != '.gitignore' else '*.raw\n')
        self.producer = self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args],
                                       cwd=self.root, text=True, stderr=subprocess.PIPE).strip()

    def commit(self):
        self.git('add', '--all')
        self.git('commit', '-q', '--no-gpg-sign', '-m', 'Fixture revision')
        return self.git('rev-parse', 'HEAD')

    def test_only_tests_and_workflow_changes_preserve_product_equivalence(self):
        from host.uki import verify_product_source
        (self.root / 'tests/case.py').write_text('new assertions\n')
        (self.root / '.github/workflows/ci.yml').write_text('new scheduling\n')
        candidate = self.commit()
        self.assertNotEqual(self.producer, candidate)
        self.assertEqual(verify_product_source(self.root, self.producer, candidate), {
            'producer_source_oid': self.producer, 'candidate_source_oid': candidate})

    def test_every_distribution_input_remains_a_strict_source_boundary(self):
        from host.uki import verify_product_source
        for name in self.product_files:
            with self.subTest(name=name):
                path = self.root / name
                path.write_text('changed product\n')
                candidate = self.commit()
                with self.assertRaisesRegex(RuntimeError, 'product inputs'):
                    verify_product_source(self.root, self.producer, candidate)
                path.write_text('original\n')
                self.commit()

    def test_index_flags_cannot_hide_changed_product_bytes(self):
        from host.uki import verify_product_source
        for flag in ('assume-unchanged', 'skip-worktree'):
            with self.subTest(flag=flag):
                self.git('update-index', '--' + flag, 'crates/sdk.rs')
                (self.root / 'crates/sdk.rs').write_text('hidden changed SDK\n')
                self.assertEqual(self.git('status', '--porcelain'), '')
                with self.assertRaisesRegex(RuntimeError, 'clean candidate'):
                    verify_product_source(self.root, self.producer, self.producer)
                self.git('update-index', '--no-' + flag, 'crates/sdk.rs')
                (self.root / 'crates/sdk.rs').write_text('original\n')

    def test_missing_or_bad_commits_and_dirty_or_ignored_inputs_are_refused(self):
        from host.uki import verify_product_source
        for producer in ('bad', '-bad', 'A' * 40, None):
            with self.subTest(producer=producer), self.assertRaisesRegex(RuntimeError, 'source OID'):
                verify_product_source(self.root, producer, self.producer)
        with self.assertRaisesRegex(RuntimeError, 'unavailable'):
            verify_product_source(self.root, '0' * 40, self.producer)
        (self.root / 'tests/case.py').write_text('uncommitted assertions\n')
        with self.assertRaisesRegex(RuntimeError, 'clean candidate'):
            verify_product_source(self.root, self.producer, self.producer)
        (self.root / 'tests/case.py').write_text('original\n')
        (self.root / 'crates/ignored.raw').write_bytes(b'ignored product bytes')
        self.assertEqual(self.git('status', '--porcelain'), '')
        with self.assertRaisesRegex(RuntimeError, 'clean candidate'):
            verify_product_source(self.root, self.producer, self.producer)


class RamBootBudgetTests(unittest.TestCase):
    def test_budget_covers_both_unpacking_and_pre_kexec_copies_with_rounding(self):
        from cases.ram_boot import memory_plan
        mib = 1 << 20
        for compressed, logical, kernel in ((128 * mib, 1024 * mib, 16 * mib),
                                             (1024 * mib, 1024 * mib, 16 * mib),
                                             (128 * mib + 1, 1024 * mib, 16 * mib)):
            with self.subTest(compressed=compressed, logical=logical):
                plan = memory_plan(compressed, logical, kernel)
                self.assertLess(plan['short_mib'] * mib, plan['need_bytes'])
                available = plan['positive_mib'] * mib - plan['runtime_headroom_bytes']
                self.assertGreaterEqual(available, compressed + logical + 256 * mib)
                self.assertGreaterEqual(available, 3 * compressed + 2 * kernel)
                self.assertLess(plan['positive_mib'], 8192)
        with self.assertRaisesRegex(RuntimeError, 'root tar is too small'):
            memory_plan(1, 1, 1)

    def test_factory_kernel_size_resolves_the_actual_hardlinked_payload(self):
        from cases.ram_boot import tar_sizes
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            path = Path(temporary) / 'root.tar'
            with tarfile.open(path, 'w') as archive:
                member = tarfile.TarInfo('./payload')
                member.size = 7
                archive.addfile(member, io.BytesIO(b'kernel!'))
                member = tarfile.TarInfo('./boot/vmlinuz-test')
                member.type = tarfile.LNKTYPE
                member.linkname = './payload'
                archive.addfile(member)
            self.assertEqual(tar_sizes(path), (7, 7))

    def test_case_ceiling_refuses_an_oversized_root_instead_of_weakening_negative_leg(self):
        from cases import ram_boot
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            tar = root / 'root.tar'
            tar.write_bytes(b'input')
            run_dir = root / 'case'
            run_dir.mkdir()
            with patch.object(ram_boot, 'root_tar', return_value=tar), \
                    patch.object(ram_boot, 'tar_sizes', return_value=(4 << 30, 16 << 20)), \
                    patch.object(ram_boot, 'generate_key', side_effect=lambda p: (p / 'login.pub').write_bytes(b'public')), \
                    patch.object(ram_boot._pxe, 'write_askpass'), \
                    patch.dict(os.environ, {'ZBOOT_VM_MEMORY_MIB': '4096'}), \
                    self.assertRaisesRegex(RuntimeError, 'ceiling is 4096 MiB'):
                ram_boot.prepare(run_dir)
            self.assertFalse((run_dir / 'ram-inputs.json').exists())

    def test_host_reserve_is_checked_for_the_actual_positive_and_short_allocations(self):
        from cases import ram_boot
        from host.case import Boot
        inputs = json.dumps({'positive_mib': 3072, 'short_mib': 1280})
        def contents(path, *_args, **_kwargs):
            return 'MemAvailable: 4194304 kB\n' if str(path) == '/proc/meminfo' else inputs
        with patch.object(Path, 'read_text', autospec=True, side_effect=contents):
            self.assertEqual(ram_boot.memory_mib(Path('case'), Boot(2)), 3072)
            self.assertEqual(ram_boot.memory_mib(Path('case'), Boot(4, extra={'memory': 'short'})), 1280)
        with patch.object(Path, 'read_text', autospec=True, side_effect=lambda p: 'MemAvailable: 3145728 kB\n' if str(p) == '/proc/meminfo' else inputs), \
                self.assertRaisesRegex(RuntimeError, 'host reserve'):
            ram_boot.memory_mib(Path('case'), Boot(2))


class BuildScopeTests(unittest.TestCase):
    def test_runner_requires_an_explicit_argv_array(self):
        import run as acceptance
        self.assertEqual(acceptance.build_runner('["runner", "--", "a b"]'),
                         ['runner', '--', 'a b'])
        for value in ('runner --', '"runner"', '[]', '[1]', '[""]', '["a\\u0000b"]'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                acceptance.build_runner(value)

    def test_selected_runner_receives_literal_arguments_without_a_shell(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            marker = root / 'must-not-exist'
            argument = f'a b; touch {marker}; $(touch {marker}) `touch {marker}`'
            prefix = [sys.executable, '-c',
                      'import json, sys; print(json.dumps(sys.argv[1:]))']
            log = root / 'runner.log'
            acceptance.run_build([argument, 'actual-build'], log, 10, prefix)
            self.assertEqual(json.loads(log.read_text()), [argument, 'actual-build'])
            self.assertFalse(marker.exists())

    def test_local_scope_owns_fresh_staging_and_cleans_success_failure_and_timeout(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            unrelated = root / 'unrelated-target'
            unrelated.mkdir()
            sentinel = unrelated / 'keep'
            sentinel.write_text('caller-owned')
            for mode in ('success', 'failure', 'timeout'):
                with self.subTest(mode=mode):
                    published = root / f'{mode}.json'
                    code = ('import json, os, pathlib, sys, time; '
                            'target = pathlib.Path(os.environ["CARGO_TARGET_DIR"]); '
                            'build = pathlib.Path(os.environ["CARGO_BUILD_BUILD_DIR"]); '
                            'assert target.is_dir() and build.is_dir(); '
                            'pathlib.Path(sys.argv[1]).write_text(json.dumps('
                            '[str(target), str(build), os.environ["CARGO_BUILD_JOBS"]])); ')
                    code += {'success': '', 'failure': 'sys.exit(7)',
                             'timeout': 'time.sleep(30)'}[mode]
                    with patch.dict(os.environ, {'TMPDIR': str(root),
                                                 'CARGO_TARGET_DIR': str(unrelated),
                                                 'CARGO_BUILD_BUILD_DIR': str(unrelated),
                                                 'CARGO_BUILD_JOBS': '2'}):
                        if mode == 'success':
                            acceptance.run_build([sys.executable, '-c', code, published],
                                                 root / 'build.log', 10)
                        else:
                            error = (subprocess.CalledProcessError if mode == 'failure'
                                     else subprocess.TimeoutExpired)
                            with self.assertRaises(error):
                                acceptance.run_build([sys.executable, '-c', code, published],
                                                     root / 'build.log', 0.5 if mode == 'timeout' else 10)
                    target, build, jobs = json.loads(published.read_text())
                    self.assertTrue(Path(target).is_relative_to(root))
                    self.assertNotEqual(Path(target), unrelated)
                    self.assertEqual(Path(build).parent, Path(target).parent)
                    self.assertNotEqual(Path(build), unrelated)
                    self.assertFalse(Path(build).exists())
                    self.assertEqual(jobs, '2')
                    self.assertFalse(Path(target).parent.exists())
                    self.assertEqual(sentinel.read_text(), 'caller-owned')


class UkiInputTests(unittest.TestCase):
    def test_a_uki_must_match_its_publishers_record(self):
        from host import uki
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR') or '/var/tmp') as directory:
            out = Path(directory) / 'out'
            efi = out / uki.UKI_PATH
            efi.parent.mkdir(parents=True)
            efi.write_bytes(b'not really a UKI')
            digest = hashlib.sha256(efi.read_bytes()).hexdigest()
            (out / 'SHA256SUMS').write_text(f'{"0" * 64}  components.json\n{digest}  {uki.UKI_PATH}\n')
            self.assertEqual(uki.published_digest(efi)[:2], ('sha256', digest))
            stray = Path(directory) / 'zboot.efi'
            stray.write_bytes(efi.read_bytes())
            with self.assertRaisesRegex(RuntimeError, 'no publisher record'):
                uki.published_digest(stray)
            # A copy that differs from the record is refused before any section is read.
            (out / 'SHA256SUMS').write_text(f'{"0" * 64}  {uki.UKI_PATH}\n')
            with self.assertRaisesRegex(RuntimeError, 'differs from its record'):
                uki.boot_payloads(efi, Path(directory) / 'copy.efi', Path(directory) / 'k', Path(directory) / 'i')
            (out / 'SHA256SUMS').write_text(f'{digest}  {uki.UKI_PATH}\n{digest}  {uki.UKI_PATH}\n')
            with self.assertRaisesRegex(RuntimeError, 'exactly one'):
                uki.published_digest(efi)

    def test_zboot_identity_is_what_the_carried_zboot_prints(self):
        from host import uki
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR') or '/var/tmp') as directory:
            def initramfs(script):
                archive = (uki.newc('usr/bin/zboot', script.encode())
                           + uki.newc('TRAILER!!!', b'', mode=0, inode=2))
                path = Path(directory) / 'initrd.img.zst'
                subprocess.run(['zstd', '-q', '-f', '-o', str(path)], input=archive, check=True)
                return path
            self.assertEqual(uki.zboot_identity(initramfs(
                '#!/bin/sh\n[ "$1" = --version ] && [ -z "$HOME" ] && echo "zboot 0.2.0 (source 0123456789ab)"\n')),
                '0.2.0 (source 0123456789ab)')
            with self.assertRaisesRegex(RuntimeError, 'unexpected zboot --version'):
                uki.zboot_identity(initramfs('#!/bin/sh\necho "zboot 70.2.0 (source 0123)"\n'))


class FrozenSessionTests(unittest.TestCase):
    def test_qualification_uses_frozen_recipes_and_dev_uses_current_recipes(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            current = root / 'current'
            session = root / 'session'
            frozen = session / 'acceptance'
            marker = root / 'selection.json'
            for directory, label in ((current, 'current'), (frozen, 'frozen')):
                (directory / 'cases').mkdir(parents=True)
                (directory / 'cases/__init__.py').write_text('')
                (directory / 'host').mkdir()
                shutil.copyfile(Path(__file__).with_name('run.py'), directory / 'run.py')
                shutil.copyfile(Path(__file__).with_name('host') / 'uki.py', directory / 'host/uki.py')
                shutil.copyfile(Path(__file__).with_name('host') / 'vm.py', directory / 'host/vm.py')
                (directory / 'cases/selection.py').write_text(
                    f"ID = 'SELECTION'\nGROUP = 'small'\nSECONDS = 1\nBOOTS = []\nMARKER = {label!r}\n")
                # A file-only runner records the imported host helper, case
                # and guest share instead of constructing a VM.
                (directory / 'host/case.py').write_text(
                    'import json, os\nfrom pathlib import Path\nfrom types import SimpleNamespace\n'
                    'def run(module, run_dir, boot_for, shares):\n'
                    '    run_dir.mkdir(exist_ok=True)\n'
                    f"    selection = {{'runner': {label!r}, 'case': module.MARKER,\n"
                    "                 'guest': str(shares(SimpleNamespace(extra={}))[0][1])}\n"
                    "    Path(os.environ['ZBOOT_FIXTURE_SELECTION']).write_text(json.dumps(selection))\n"
                    "    return {'pass': True, 'assertions': 1, 'failures': []}\n")
            (session / 'source.oid').write_text('fixture-oid\n')
            (session / 'small.zst').write_bytes(b'file-only fixture')
            (session / 'bin').mkdir()
            (session / 'bin/artifact').write_bytes(b'file-only fixture')
            digest = hashlib.sha256(b'file-only fixture').hexdigest()
            (session / 'bin/SHA256SUMS').write_text(f'{digest}  artifact\n')
            environment = {**os.environ, 'ZBOOT_ACCEPTANCE_LOCK': str(root / 'qemu.lock'),
                           'ZBOOT_FIXTURE_SELECTION': str(marker)}
            for entrypoint, flags, label, directory in (
                    (current, [], 'frozen', frozen),
                    (frozen, [], 'frozen', frozen),
                    (current, ['--dev'], 'current', current)):
                with self.subTest(entrypoint=entrypoint, flags=flags):
                    result = subprocess.run(
                        [sys.executable, entrypoint / 'run.py', 'run',
                         # Resolve this relative session before crossing the
                         # frozen-runner process boundary.
                         'session', 'small', *flags], cwd=root, env=environment,
                        capture_output=True, text=True, check=False, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(marker.read_text()),
                                     {'runner': label, 'case': label,
                                      'guest': str(directory / 'guest')})
                    self.assertEqual(result.stdout.count('SELECTION PASS'), 1)
                    records = list((session / 'cases').glob('*/result.json'))
                    self.assertTrue(records)
                    self.assertEqual(json.loads(max(records, key=lambda p: p.stat().st_mtime_ns).read_text())['qualification'], not bool(flags))

    def test_missing_or_redirected_frozen_entrypoints_fail_before_efi_writes(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            session = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, 'missing frozen acceptance runner'):
                acceptance.run(session, ['small'])
            with self.assertRaisesRegex(RuntimeError, 'missing frozen acceptance runner'):
                acceptance.prepare_efi(session, ['neutral=unused'])
            self.assertFalse((session / 'efi-fixtures').exists())
            (session / 'acceptance').mkdir()
            (session / 'redirected.py').write_text('raise AssertionError("must not run")\n')
            (session / 'acceptance/run.py').symlink_to(session / 'redirected.py')
            with self.assertRaisesRegex(RuntimeError, 'must not be a symlink'):
                acceptance.prepare_efi(session, ['neutral=unused'])
            self.assertFalse((session / 'efi-fixtures').exists())

    def test_prepare_efi_uses_old_frozen_recipe_before_writing_artifacts(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            session = root / 'session'
            frozen = session / 'acceptance'
            frozen.mkdir(parents=True)
            marker = root / 'selection.json'
            # A pre-move session keeps its helper outside acceptance/.
            (session / 'build-dev-initrd.sh').write_text('old frozen helper\n')
            (frozen / 'run.py').write_text(
                'import json, pathlib, sys\n'
                'session = pathlib.Path(sys.argv[2])\n'
                f'pathlib.Path({str(marker)!r}).write_text(json.dumps({{\n'
                "    'argv': sys.argv[1:], 'helper': (session / 'build-dev-initrd.sh').read_text()}))\n"
                'sys.exit(7)\n')
            build = 'neutral=relative build with spaces;$(literal)'
            factory = 'relative factory with spaces;$(literal)'
            result = subprocess.run(
                [sys.executable, Path(__file__).with_name('run.py').resolve(),
                 'prepare-efi', 'session', build, '--factory', factory], cwd=root,
                capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertEqual(json.loads(marker.read_text()),
                             {'argv': ['prepare-efi', str(session), build, '--factory', factory],
                              'helper': 'old frozen helper\n'})
            self.assertFalse((session / 'efi-fixtures').exists())
            self.assertFalse((session / 'efi.json').exists())

    def test_direct_frozen_prepare_efi_does_not_reenter_the_recipe(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            session = Path(temporary)
            frozen = session / 'acceptance'
            frozen.mkdir()
            (frozen / 'run.py').write_text('raise AssertionError("must not reenter")\n')
            # No builds need packing; stub only input copying and firmware
            # identities to exercise the direct frozen preparation boundary.
            with patch.object(acceptance, 'HERE', frozen), \
                    patch.object(acceptance, 'OVMF', ()), \
                    patch.object(acceptance.shutil, 'copyfile'), \
                    patch('builtins.print'), \
                    patch.object(acceptance.os, 'execv') as handoff:
                acceptance.prepare_efi(session, [])
            handoff.assert_not_called()
            self.assertTrue((session / 'efi-fixtures').is_dir())
            self.assertEqual(json.loads((session / 'efi.json').read_text()),
                             {'builds': {}, 'firmware': {}})

    def test_exec_handoff_preserves_pid_and_drains_sigint_cleanup(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            session = root / 'session'
            frozen = session / 'acceptance'
            frozen.mkdir(parents=True)
            marker = root / 'custody.json'
            (frozen / 'run.py').write_text(
                'import json, os, pathlib, sys, time\n'
                f'marker = pathlib.Path({str(marker)!r})\n'
                'try:\n'
                "    marker.with_suffix('.ready').write_text(json.dumps({'pid': os.getpid(), 'cleanup': False}))\n"
                "    marker.with_suffix('.ready').replace(marker)\n"
                '    time.sleep(30)\n'
                'except KeyboardInterrupt:\n'
                # Longer than subprocess.run's interruption grace period.
                '    time.sleep(0.6)\n'
                "    marker.write_text(json.dumps({'pid': os.getpid(), 'cleanup': True}))\n"
                '    sys.exit(23)\n')
            for group_signal in (False, True):
                with self.subTest(group_signal=group_signal):
                    marker.unlink(missing_ok=True)
                    with subprocess.Popen(
                            [sys.executable, Path(__file__).with_name('run.py').resolve(),
                             'run', session, 'small'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True) as process:
                        try:
                            deadline = time.monotonic() + 5
                            while not marker.exists() and time.monotonic() < deadline:
                                time.sleep(0.01)
                            self.assertTrue(marker.exists(), 'frozen recipe did not start')
                            self.assertEqual(json.loads(marker.read_text())['pid'], process.pid)
                            if group_signal:
                                os.killpg(process.pid, signal.SIGINT)
                            else:
                                process.send_signal(signal.SIGINT)
                            _out, errors = process.communicate(timeout=10)
                            self.assertEqual(process.returncode, 23, errors.decode(errors='replace'))
                            self.assertEqual(json.loads(marker.read_text()),
                                             {'pid': process.pid, 'cleanup': True})
                        finally:
                            if process.poll() is None:
                                process.kill()
                                process.wait()


class InitrdPathTests(unittest.TestCase):
    def test_builder_keeps_runtime_wipefs_and_records_its_bytes(self):
        import run as acceptance
        from host import uki
        builder = Path(__file__).with_name('build-initrd.sh')
        self.assertNotIn('--wipefs', acceptance.HOST_TOOLS)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            guest = root / 'guest'
            guest.mkdir()
            (guest / 'init.sh').write_text('#!/bin/sh\n')
            runtime_wipefs = b'#!/bin/sh\necho pinned-runtime-wipefs\n'
            for present in (False, True):
                with self.subTest(runtime_wipefs=present):
                    archive = (uki.newc('sbin/wipefs', runtime_wipefs) if present else b'')
                    archive += uki.newc('TRAILER!!!', b'', mode=0, inode=2)
                    base = root / f'base-{present}.zst'
                    subprocess.run(['zstd', '-q', '-o', base], input=archive, check=True)
                    output = root / f'fixture-{present}.zst'
                    result = subprocess.run(['bash', builder, '--base-initrd', base,
                                             '--acceptance', guest, '--output', output],
                                            env={**os.environ, 'TMPDIR': str(root)},
                                            capture_output=True, text=True)
                    if not present:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('runtime needs executable /sbin/wipefs', result.stderr)
                        self.assertFalse(output.exists())
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr)
                    tree = root / 'unpacked'
                    tree.mkdir()
                    packed = subprocess.check_output(['zstd', '-dc', output])
                    subprocess.run(['cpio', '-idm', '--quiet'], input=packed, cwd=tree, check=True)
                    self.assertEqual((tree / 'sbin/wipefs').read_bytes(), runtime_wipefs)
                    self.assertFalse((tree / 'usr/bin/wipefs').exists())
                    digest = hashlib.sha256(runtime_wipefs).hexdigest()
                    self.assertIn(f'{digest}  runtime:/sbin/wipefs',
                                  Path(str(output) + '.provenance').read_text())

    def test_custom_tmpdir_retains_new_path_and_escape_refusals(self):
        builder = Path(__file__).with_name('build-initrd.sh')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            staging = root / 'staging with spaces'
            staging.mkdir()
            outside = root / 'outside'
            outside.mkdir()
            (staging / 'escape').symlink_to(outside, target_is_directory=True)
            missing_base = root / 'missing-base'
            acceptance = root / 'guest'
            acceptance.mkdir()
            (acceptance / 'init.sh').write_text('#!/bin/sh\n')

            def invoke(output, *extra):
                return subprocess.run(['bash', str(builder), '--base-initrd', str(missing_base),
                                       '--acceptance', str(acceptance), '--output', str(output), *extra],
                                      env={**os.environ, 'TMPDIR': str(staging)},
                                      capture_output=True, text=True, check=False)

            # A new path under the selected root reaches input validation;
            # packing never runs because the base input is deliberately absent.
            output = staging / 'new.zst'
            result = invoke(output)
            self.assertIn('not a regular input file:', result.stderr)
            for refused in (outside / 'out.zst', staging / 'escape/out.zst'):
                with self.subTest(output=refused):
                    result = invoke(refused)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('output and provenance must be new files under TMPDIR', result.stderr)
            for existing in (output, Path(str(output) + '.provenance')):
                existing.write_text('keep')
                result = invoke(output)
                self.assertIn('output and provenance must be new files under TMPDIR', result.stderr)
                self.assertEqual(existing.read_text(), 'keep')
                existing.unlink()
            missing_base.write_bytes(b'not packed in this file-only test')
            for fixtures in (outside / 'fixtures', staging / 'escape/fixtures', staging):
                with self.subTest(fixtures=fixtures):
                    result = invoke(output, '--fixture-directory', str(fixtures))
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('fixture directory must be a new directory under TMPDIR', result.stderr)
            self.assertFalse(output.exists())


class ShutdownFixtureTests(unittest.TestCase):
    def run_case(self, boots, *, timeout=False, stage_1=lambda _console: None):
        from host import case
        waits = []

        class Vm:
            def __init__(self, *_args, **_kwargs):
                self.ssh_port = None
                self.image_paths = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.kill()

            def wait(self, seconds):
                waits.append(seconds)
                if timeout:
                    raise TimeoutError('guest did not power off: test-owned fixture')
                return 0

            def kill(self):
                return -9 if timeout else 0

        class Console:
            def __init__(self, _channel, out, *_args, **_kwargs):
                out.mkdir(parents=True)

        channel = SimpleNamespace(console=object(), until=lambda *_args: ('DONE', 'ok'))
        verdict = Mock()
        module = SimpleNamespace(ID='SHUTDOWN-FIXTURE', SECONDS=600, DISKS={},
                                 BOOTS=boots, stage_1=stage_1, verdict=verdict)
        with tempfile.TemporaryDirectory(prefix='zboot-shutdown-',
                                         dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            run_dir = Path(temporary) / 'case'
            with patch.object(case, 'Vm', Vm), patch.object(case, 'Channel', return_value=channel), \
                    patch.object(case, 'Console', Console):
                result = case.run(module, run_dir, lambda _boot: {}, lambda _boot: [])
            self.assertEqual(json.loads((run_dir / 'result.json').read_text()), result)
        return result, waits, verdict

    def test_handoff_poweroff_waits_once_with_the_full_shutdown_budget(self):
        from host.case import Boot
        result, waits, verdict = self.run_case([Boot(1, efi=True, target=2, poweroff=True)])
        self.assertTrue(result['pass'], result['failures'])
        self.assertEqual(waits, [300])
        self.assertEqual(result['boots'][0]['target_event'], ['DONE', 'ok'])
        self.assertEqual(result['boots'][0]['exit'], 0)
        verdict.assert_called_once()

    def test_a_dialogue_that_cannot_read_the_menu_is_a_failed_stage_with_its_boot_kept(self):
        from host.case import Boot

        def unreadable(_console):
            raise ValueError('expected one native menu row')

        result, _waits, verdict = self.run_case([Boot(1, efi=True), Boot(3)], stage_1=unreadable)
        self.assertFalse(result['pass'])
        self.assertEqual([boot['event'] for boot in result['boots']], [['DIALOGUE', 'failed']])
        self.assertTrue(any('expected one native menu row' in failure for failure in result['failures']))
        verdict.assert_not_called()

    def test_shutdown_timeouts_preserve_original_failed_results_and_stop_later_boots(self):
        from host.case import Boot
        for boot, seconds in [(Boot(1, efi=True, target=2, poweroff=True), 300),
                              (Boot(1, efi=True, target=2), 60), (Boot(1), 60)]:
            with self.subTest(boot=boot):
                result, waits, verdict = self.run_case([boot, Boot(3)], timeout=True)
                self.assertFalse(result['pass'])
                self.assertEqual(waits, [seconds])
                self.assertEqual(len(result['boots']), 1)
                self.assertIn('guest did not power off', result['boots'][0]['exit'])
                self.assertTrue(any('guest did not power off' in failure
                                    for failure in result['failures']))
                self.assertTrue(any('only 1 of 2 boots ran' in failure
                                    for failure in result['failures']))
                if boot.target:
                    self.assertEqual(result['boots'][0]['target_event'], ['DONE', 'ok'])
                verdict.assert_not_called()


class UsbLoaderFixtureTests(unittest.TestCase):
    def test_only_selected_primary_disk_uses_usb_storage(self):
        from host.vm import disk_device
        self.assertEqual(disk_device('A', ',bootindex=1'),
                         'virtio-blk-pci,drive=diskA,serial=ZFS-E2E-A,bootindex=1')
        self.assertEqual(disk_device('A', ',bootindex=1', primary_bus='usb'),
                         'usb-storage,bus=zt-usb.0,drive=diskA,serial=ZFS-E2E-A,bootindex=1')
        for label in ('B', 'D'):
            self.assertEqual(disk_device(label, primary_bus='usb'), disk_device(label))

    def test_only_selected_primary_disk_uses_nvme_storage(self):
        from host.vm import disk_device
        self.assertEqual(disk_device('A', ',bootindex=1', primary_bus='nvme'),
                         'nvme,drive=diskA,serial=ZFS-E2E-A,bootindex=1')
        for label in ('B', 'D'):
            self.assertEqual(disk_device(label, primary_bus='nvme'), disk_device(label))
        with self.assertRaises(ValueError):
            disk_device('A', primary_bus='unknown')

    def test_only_efi_connect_automatic_legs_select_nvme(self):
        fixture = Path(__file__).parent / 'cases/efi_connect.py'
        declaration = next(node.value for node in ast.parse(fixture.read_bytes()).body
                           if isinstance(node, ast.Assign)
                           and any(isinstance(name, ast.Name) and name.id == 'BOOTS' for name in node.targets))
        self.assertIsInstance(declaration, ast.List)
        boots = {ast.literal_eval(boot.args[0]):
                 {keyword.arg: ast.literal_eval(keyword.value) for keyword in boot.keywords}
                 for boot in declaration.elts}
        self.assertEqual({stage: boot.get('extra', {}).get('bus', 'virtio')
                          for stage, boot in boots.items()},
                         {1: 'virtio', 2: 'usb', 4: 'nvme', 6: 'nvme',
                          8: 'virtio', 10: 'nvme', 12: 'virtio'})
        self.assertEqual({stage: boot['target'] for stage, boot in boots.items() if 'target' in boot},
                         {2: 3, 4: 5, 6: 7, 10: 11})
        for stage in (2, 4, 6, 10):
            self.assertTrue(boots[stage]['efi'])
            self.assertEqual(boots[stage]['extra']['from'], 'A')


class DiscoveryFixtureTests(unittest.TestCase):
    def test_writer_lock_probe_is_an_explicit_staged_native_tool(self):
        acceptance = Path(__file__).parent
        source = (acceptance / "guest/cases/MENU-DISCOVERY-NATIVE.sh").read_text()
        probes = [shlex.split(line) for line in source.splitlines()
                  if line.strip().startswith(("md_must writer-", "md_refuse writer-held-"))
                  and " flock " in line]
        self.assertEqual(len(probes), 4)
        for probe in probes:
            self.assertEqual(probe[2:], [
                "flock", "-n", "/run/zfs-tools/writer.lock", "/bin/busybox", "true",
            ])
        self.assertNotIn("busybox flock", source)
        runner = (acceptance / "run.py").read_text()
        self.assertIn("'--flock', '/usr/bin/flock'", runner)
        builder = (acceptance / "build-initrd.sh").read_text()
        self.assertIn('--flock) flock=$2; shift 2 ;;', builder)
        self.assertIn('${flock:+"$flock"}', builder)
        self.assertIn('install_binary "$flock" /usr/bin/flock', builder)


class ReturnedFixtureTests(unittest.TestCase):
    def test_mount_state_query_selects_filesystems_without_snapshot_rows(self):
        source = (Path(__file__).parent / "guest/cases/RESTORE-RETURNED-ERROR-NATIVE.sh").read_text()
        commands = [shlex.split(line) for line in source.splitlines()
                    if line.strip().startswith("must after-mounted ")]
        self.assertEqual(commands, [[
            "must", "after-mounted", "zfs", "get", "-H", "-r", "-t", "filesystem",
            "-o", "name,value", "mounted", "e2eb", "e2ec",
        ]])

    def test_selected_disk_serial_without_a_newline_and_exact_identity(self):
        source = (Path(__file__).parent / "guest/cases/RESTORE-RETURNED-ERROR-NATIVE.sh").read_text()
        # Extract the actual bounded command body, not a second implementation.
        pattern = re.compile(
            r'''^        must "reset-selected-\$label" sh -e -c '(?P<body>[^']{1,2048})' selected "\$selected" "\$label"$''',
            re.MULTILINE,
        )
        matches = list(pattern.finditer(source))
        self.assertEqual(len(matches), 1, "exact reset-selected command must remain uniquely identifiable")
        original = matches[0]["body"]
        self.assertEqual(original.count("/sys/block/"), 2)
        with tempfile.TemporaryDirectory(prefix="zboot-fixtures-", dir=os.environ.get("TMPDIR", "/var/tmp")) as temporary:
            for index, (primary, fallback, accepted) in enumerate([
                (b"ZFS-E2E-A", None, True),
                (None, b"ZFS-E2E-A", True),
                (b"ZFS-E2E-B", b"ZFS-E2E-A", False),
            ]):
                with self.subTest(primary=primary, fallback=fallback):
                    root = Path(temporary) / str(index)
                    disk = root / "vda"
                    disk.mkdir(parents=True)
                    if primary is not None:
                        (disk / "serial").write_bytes(primary)
                    if fallback is not None:
                        (disk / "device").mkdir()
                        (disk / "device/serial").write_bytes(fallback)
                    body = original.replace("/sys/block/", str(root) + "/")
                    self.assertNotIn("/sys/block/", body)
                    result = subprocess.run(
                        ["sh", "-e", "-c", body, "selected", "/dev/vda", "A"],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        env={"PATH": os.defpath, "LC_ALL": "C"},
                        check=False,
                    )
                    if accepted:
                        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                        self.assertEqual(result.stdout, b"ZFS-E2E-A\t/dev/vda\n")
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, b"")



class FakeNvmeTests(unittest.TestCase):
    """guest/fake-nvme.sh, which WIPE-SANITIZE-NATIVE puts in place of `nvme`,
    run against a regular file standing in for the namespace."""

    FAKE = Path(__file__).parent / "guest/fake-nvme.sh"
    BYTES = 2 << 20

    def shells(self):
        yield "sh", os.defpath
        busybox = shutil.which("busybox")
        if busybox:
            # The guest's busybox: its own sh and applets only.
            with tempfile.TemporaryDirectory(prefix="zboot-fake-nvme-bin-",
                                             dir=os.environ.get("TMPDIR", "/var/tmp")) as bin_dir:
                for applet in ("cat", "dd", "mv", "printf", "sh"):
                    os.symlink(busybox, Path(bin_dir) / applet)
                yield str(Path(bin_dir) / "sh"), bin_dir

    def fake(self, shell, path, state, *args):
        result = subprocess.run([shell, str(self.FAKE), *args], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, check=False,
                                env={"PATH": path, "LC_ALL": "C", "ZT_FAKE_NVME": str(state)})
        return result.returncode, result.stdout, result.stderr

    def setUp_state(self, root, outcome, state):
        disk = root / "namespace"
        disk.write_bytes(b"\xff" * self.BYTES)
        (root / "config").write_text(f"CONTROLLER=/dev/nvme0 NAMESPACE={disk} BYTES={self.BYTES} "
                                     f"CNTLID=7 SERIAL=ZFS-E2E-N SUBNQN=nqn.2019-08.org.qemu:ZFS-E2E-N "
                                     f"RUN_READS=2 OUTCOME={outcome}\n")
        (root / "state").write_text(state + "\n")
        return disk

    def test_answers_as_a_consumer_drive_and_sanitizes_by_zeroing(self):
        for shell, path in self.shells():
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(
                    prefix="zboot-fake-nvme-", dir=os.environ.get("TMPDIR", "/var/tmp")) as temporary:
                root = Path(temporary)
                disk = self.setUp_state(root, "success", "STATUS=1 CDW10=4 ERASED=0 RUNNING=0 ENDS=")
                run = lambda *args: self.fake(shell, path, root, *args)
                status, out, _ = run("id-ctrl", "/dev/nvme0", "--output-format=json")
                self.assertEqual(status, 0)
                ctrl = json.loads(out)
                self.assertEqual({k: ctrl[k] for k in ("sanicap", "cmic", "oacs", "nn", "cntlid", "subnqn")},
                                 {"sanicap": 3, "cmic": 0, "oacs": 22, "nn": 1, "cntlid": 7,
                                  "subnqn": "nqn.2019-08.org.qemu:ZFS-E2E-N"})
                self.assertEqual(ctrl["sn"], "ZFS-E2E-N" + " " * 11, "space-padded like nvme-cli")
                self.assertEqual(json.loads(run("list-ns", "/dev/nvme0", "--output-format=json")[1]),
                                 {"nsid_list": [{"nsid": 1}]})
                status, out, _ = run("id-ns", "/dev/nvme0", "--namespace-id=1", "--output-format=json")
                self.assertEqual((status, json.loads(out)["nmic"], json.loads(out)["nsze"]),
                                 (0, 0, self.BYTES // 512))
                # Rejected like the captured consumer drives.
                for args in (("list-ctrl", "/dev/nvme0", "--output-format=json"),
                             ("list-ns", "/dev/nvme0", "--all", "--output-format=json")):
                    status, out, _ = run(*args)
                    self.assertEqual(status, 1, args)
                    self.assertIn("Invalid Field in Command", json.loads(out)["error"])
                # Anything else, another device included, is an error.
                for args in (("format", "/dev/nvme0"), ("id-ctrl", "/dev/nvme1", "--output-format=json"),
                             ("sanitize", "/dev/nvme0", "--sanact=3")):
                    self.assertEqual(run(*args)[0], 2, args)

                def log():
                    status, out, _ = run("sanitize-log", "/dev/nvme0", "--output-format=json")
                    self.assertEqual(status, 0)
                    (device, value), = json.loads(out).items()
                    self.assertEqual(device, "nvme0")
                    return value["sstat"]["status"][:3], value["sstat"]["global_erased"], value["cdw10_info"]

                self.assertEqual(log(), ("(1)", 0, 4))
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 0)
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 1, "one at a time")
                self.assertEqual([log(), log()], [("(2)", 0, 4)] * 2)
                self.assertEqual(disk.read_bytes(), b"\xff" * self.BYTES, "erased only when it ends")
                self.assertEqual(log(), ("(1)", 1, 4))
                self.assertEqual(disk.read_bytes(), bytes(self.BYTES))
                self.assertEqual(log(), ("(1)", 1, 4))
                record = (root / "calls").read_text().splitlines()
                self.assertIn("sanitize /dev/nvme0 --sanact=4 => exit 0", record)
                self.assertEqual(record[-1], "sanitize-log /dev/nvme0 --output-format=json => status 1")
                self.assertFalse((root / "errors").exists() and (root / "errors").read_text())

    def test_a_running_sanitize_ends_and_a_failure_leaves_the_data(self):
        for shell, path in self.shells():
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(
                    prefix="zboot-fake-nvme-", dir=os.environ.get("TMPDIR", "/var/tmp")) as temporary:
                root = Path(temporary)
                disk = self.setUp_state(root, "failure", "STATUS=1 CDW10=4 ERASED=0 RUNNING=1 ENDS=success")
                run = lambda *args: self.fake(shell, path, root, *args)
                log = lambda: json.loads(run("sanitize-log", "/dev/nvme0", "--output-format=json")[1])[
                    "nvme0"]["sstat"]["status"][:3]
                # Already running (after a power loss): it ends, then a new one may start.
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 1)
                self.assertEqual([log(), log()], ["(2)", "(1)"])
                self.assertEqual(disk.read_bytes(), bytes(self.BYTES))
                disk.write_bytes(b"\xff" * self.BYTES)
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=2")[0], 0)
                self.assertEqual([log(), log(), log()], ["(2)", "(2)", "(3)"])
                self.assertEqual(disk.read_bytes(), b"\xff" * self.BYTES, "a failure erases nothing")
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 1, "failure mode")
                self.assertIn("STATUS=3", (root / "state").read_text())


if __name__ == "__main__":
    unittest.main()
