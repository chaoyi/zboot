"""A green aggregate requires every independently produced native result."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('qualification', Path(__file__).with_name('qualification.py'))
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class Aggregation(unittest.TestCase):
    def records(self, root):
        for shard in CI.plan()['include']:
            directory = root / shard['name']
            directory.mkdir()
            cases = ([{'id': case, 'pass': True, 'qualification': True} for case in shard['cases']]
                     if shard['suite'] == 'acceptance' else ['native-proof-complete'])
            (directory / 'result.json').write_text(json.dumps({
                **shard, 'expected_cases': shard['cases'], 'cases': cases,
                'source_oid': CI.head(), 'build_sha256': 'a' * 64, 'passed': True, 'vm_accelerator': 'kvm',
            }))

    def combine(self, root, succeeds):
        with contextlib.redirect_stdout(io.StringIO()):
            if succeeds:
                CI.aggregate(root)
            else:
                with self.assertRaises(SystemExit):
                    CI.aggregate(root)
        self.assertEqual(json.loads((root / 'qualification.json').read_text())['passed'], succeeds)

    def test_missing_artifact_directory_still_produces_failed_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'missing-artifacts'
            self.combine(root, False)
            self.assertTrue(json.loads((root / 'qualification.json').read_text())['errors'])

    def test_complete_result_and_missing_or_failed_shards(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.records(root)
            self.combine(root, True)
            path = root / 'native-api/result.json'
            saved = path.read_text()
            path.unlink()
            self.combine(root, False)
            record = json.loads(saved)
            record['passed'] = False
            path.write_text(json.dumps(record))
            self.combine(root, False)

    def test_mixed_identity_and_false_case_pass_do_not_qualify(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.records(root)
            path = root / 'acceptance-00/result.json'
            saved = json.loads(path.read_text())
            for field, value in [('source_oid', 'b' * 40), ('build_sha256', 'b' * 64), ('vm_accelerator', 'tcg')]:
                record = {**saved, field: value}
                path.write_text(json.dumps(record))
                self.combine(root, False)
            saved['cases'][0]['pass'] = False
            path.write_text(json.dumps(saved))
            self.combine(root, False)

    def test_runtime_must_have_explicit_hash_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'build.json').write_text(json.dumps({'source_oid': CI.head(), 'files': {}}))
            with self.assertRaisesRegex(RuntimeError, 'omits required'):
                CI.verify_build(root)

    def test_equivalent_source_does_not_allow_changed_runtime_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = {}
            for name in ('usr/lib/zboot/zboot.efi', 'vmlinuz', 'usr/bin/zboot', 'usr/bin/zsnap'):
                path = root / 'distribution' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'original')
                files[str(path.relative_to(root))] = CI.sha(path)
            (root / 'build.json').write_text(json.dumps({'source_oid': 'a' * 40, 'files': files}))
            (root / 'distribution/usr/bin/zboot').write_bytes(b'changed')
            with patch.object(CI, 'verify_product_source'), self.assertRaisesRegex(RuntimeError, 'changed distribution'):
                CI.verify_build(root)

    def test_failed_prepare_retains_raw_assertion_evidence_and_excludes_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state, inputs, evidence = root / 'state', root / 'inputs', root / 'evidence'
            inputs.mkdir()
            (inputs / 'build.json').write_text('{}')
            def failed_prepare(argv, **_kwargs):
                self.assertIn('prepare', argv)
                session = state / 'runs' / 'test-session'
                out = session / 'cases' / 'SMOKE-attempt' / 'out' / '1'
                out.mkdir(parents=True)
                for name in ('01-status.out', '01-status.rc', '01-status.argv', 'FAILED'):
                    (out / name).write_text('raw assertion evidence')
                observation = out / '02-before.observe'
                observation.mkdir()
                (observation / 'datasets').write_text('native evidence')
                (session / 'prepare-small.log').write_text('setup failed')
                (session / 'cases/SMOKE-attempt/login').write_text('private key')
                (session / 'cases/SMOKE-attempt/private.raw').write_text('disk image')
                raise RuntimeError('injected prepare failure')
            shard = {'include': [{'name': 'acceptance-test', 'suite': 'acceptance', 'cases': ['SMOKE']}]}
            with patch.dict(os.environ, {'ZBOOT_ACCEPTANCE_STATE': str(state)}), \
                    patch.object(CI, 'plan', return_value=shard), \
                    patch.object(CI, 'verify_build', return_value={'version': 'test', 'source_oid': CI.head()}), \
                    patch.object(CI, 'command', side_effect=failed_prepare):
                with self.assertRaisesRegex(RuntimeError, 'injected prepare'):
                    CI.execute('acceptance-test', inputs, evidence)
            exported = evidence / 'acceptance/test-session'
            self.assertEqual((exported / 'prepare-small.log').read_text(), 'setup failed')
            self.assertTrue((exported / 'cases/SMOKE-attempt/out/1/01-status.rc').is_file())
            self.assertTrue((exported / 'cases/SMOKE-attempt/out/1/01-status.out').is_file())
            self.assertTrue((exported / 'cases/SMOKE-attempt/out/1/02-before.observe/datasets').is_file())
            self.assertFalse((exported / 'cases/SMOKE-attempt/login').exists())
            self.assertFalse((exported / 'cases/SMOKE-attempt/private.raw').exists())
            self.assertFalse(json.loads((evidence / 'result.json').read_text())['passed'])

    def test_plan_covers_the_current_case_set_exactly_once(self):
        selected = [case for shard in CI.plan()['include'] for case in shard['cases']]
        self.assertEqual(sorted(selected), sorted(CI.cases()))
        self.assertEqual(len(selected), len(set(selected)))


if __name__ == '__main__':
    unittest.main()
