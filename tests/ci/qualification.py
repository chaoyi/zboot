#!/usr/bin/env python3
"""Plan, execute and strictly combine one revision's native CI qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/acceptance'))
from host.uki import verify_product_source  # noqa: E402

def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def head():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()

def cases():
    # The acceptance runner owns case discovery, including validation of fixtures.
    spec = importlib.util.spec_from_file_location('acceptance_ci', ROOT / 'tests/acceptance/run.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.cases()

def plan():
    known = cases()
    # Keep long cases independent; greedily balance the remaining time bounds.
    # This is scheduling only; no case is omitted or selected by historical pass.
    shards = [[] for _ in range(16)]
    weights = [0] * len(shards)
    for case in sorted(known.values(), key=lambda c: (-c.SECONDS, c.ID)):
        index = min(range(len(shards)), key=lambda i: weights[i])
        shards[index].append(case.ID)
        weights[index] += case.SECONDS
    return {'include': [
        {'name': f'acceptance-{i:02d}', 'suite': 'acceptance', 'cases': selected}
        for i, selected in enumerate(shards) if selected
    ] + [{'name': 'native-api', 'suite': 'native-api', 'cases': []},
         {'name': 'native-readers', 'suite': 'native-readers', 'cases': []}]}

def command(argv, *, env=None):
    subprocess.run([str(x) for x in argv], cwd=ROOT, check=True, env=env)

def verify_build(inputs):
    build = json.loads((inputs / 'build.json').read_text())
    required = {'distribution/' + name for name in (
        'usr/lib/zboot/zboot.efi', 'vmlinuz', 'usr/bin/zboot', 'usr/bin/zsnap')}
    if not required.issubset(build['files']):
        raise RuntimeError('build record omits required runtime or tool hashes')
    verify_product_source(ROOT, build.get('source_oid'), head())
    for name, digest in build['files'].items():
        if sha(inputs / name) != digest:
            raise RuntimeError(f'changed distribution artifact: {name}')
    subprocess.run(['sha256sum', '--check', 'factory.sha256'], cwd=inputs, check=True)
    return build

def export_acceptance(state, evidence):
    """Retain assertion inputs and setup logs, excluding images and SSH keys."""
    found = []
    observations = {'pools', 'pool-properties', 'datasets', 'properties',
                    'holds', 'mountinfo', 'status'}
    for session in (state / 'runs').glob('*'):
        if not session.is_dir() or session.is_symlink():
            continue
        for path in session.rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(session)
            root_log = len(relative.parts) == 1 and path.suffix in ('.json', '.log', '.jsonl')
            case_log = (relative.parts[0] == 'cases' and
                        path.suffix in ('.json', '.log', '.jsonl'))
            raw_output = (len(relative.parts) >= 4 and relative.parts[0] == 'cases' and
                          relative.parts[2] == 'out' and
                          (path.suffix in ('.argv', '.out', '.err', '.rc', '.tsv', '.payload') or
                           path.name == 'FAILED' or
                           (path.parent.name.endswith('.observe') and path.name in observations)))
            if root_log or case_log or raw_output:
                dest = evidence / 'acceptance' / session.name / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, dest)
        found.extend(json.loads(p.read_text()) for p in (session / 'cases').glob('*/result.json'))
    return found

def execute(name, inputs, evidence):
    entry = next(x for x in plan()['include'] if x['name'] == name)
    evidence.mkdir(parents=True, exist_ok=False)
    result = {'name': name, 'suite': entry['suite'], 'source_oid': head(),
              'expected_cases': entry['cases'], 'passed': False, 'cases': [],
              'vm_accelerator': os.environ.get('ZBOOT_VM_ACCEL', 'kvm')}
    try:
        build = verify_build(inputs)
        result['build_sha256'] = sha(inputs / 'build.json')
        result['distribution_version'] = build['version']
        result['producer_source_oid'] = build['source_oid']
        uki = inputs / 'distribution/usr/lib/zboot/zboot.efi'
        if entry['suite'] != 'acceptance':
            proof = evidence / 'proof'
            command([sys.executable, ROOT / f"tests/{entry['suite']}/run.py",
                     '--uki', uki, '--evidence', proof, '--timeout', '600'])
            native = json.loads((proof / 'provenance.json').read_text())
            if native.get('passed') is not True or not native.get('passed_cases'):
                raise RuntimeError('native proof returned no passing cases')
            result['cases'] = native['passed_cases']
        else:
            selected = entry['cases']
            state = Path(os.environ['ZBOOT_ACCEPTANCE_STATE'])
            runner = ROOT / 'tests/acceptance/run.py'
            try:
                command([sys.executable, '-I', runner, 'prepare', head(), *selected,
                         '--uki', inputs / 'distribution', '--factory', inputs / 'factory.tar.zst',
                         '--distribution-tools', '--build-record', inputs / 'build.json'])
                sessions = list((state / 'runs').iterdir())
                if len(sessions) != 1:
                    raise RuntimeError('expected one private acceptance session')
                session = sessions[0]
                # All build-dependent paths use the one matching UKI/root.
                known = cases()
                needs_efi = any(known[x].GROUP in ('efi', 'deploy') for x in selected) or any(
                    x in selected for x in ('RESTORE-PAIRED-NATIVE', 'RESTORE-RETURNED-ERROR-NATIVE'))
                if needs_efi:
                    command([sys.executable, '-I', runner, 'prepare-efi', session,
                             f"neutral={inputs / 'distribution'}", '--factory', inputs / 'factory.tar.zst'])
                command([sys.executable, '-I', runner, 'run', session, *selected])
            finally:
                found = export_acceptance(state, evidence)
                result['cases'] = found
            by_id = {x['id']: x for x in found}
            if set(by_id) != set(selected) or len(found) != len(selected):
                raise RuntimeError('acceptance case results are missing or duplicated')
            if not all(x['pass'] is True and x.get('qualification') is True for x in found):
                raise RuntimeError('acceptance failed or ran an experimental backend')
        if result['vm_accelerator'] != 'kvm':
            raise RuntimeError('qualification requires KVM')
        result['passed'] = True
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

def aggregate(directory):
    directory.mkdir(parents=True, exist_ok=True)
    expected = {x['name']: x for x in plan()['include']}
    found = [json.loads(p.read_text()) for p in directory.glob('*/result.json')]
    by_name = {x['name']: x for x in found}
    errors = []
    if len(found) != len(expected) or set(by_name) != set(expected):
        errors.append(f'missing/duplicate/unexpected shard results: {sorted(set(expected) - set(by_name))}')
    builds = set()
    producers = set()
    accepted = []
    for name, result in by_name.items():
        if result.get('vm_accelerator') != 'kvm':
            errors.append(f'{name}: qualification requires KVM')
        if result.get('source_oid') != head() or result.get('passed') is not True:
            errors.append(f'{name}: failed, incomplete or wrong source')
        if result.get('suite') != expected.get(name, {}).get('suite'):
            errors.append(f'{name}: wrong suite')
        if result.get('expected_cases') != expected.get(name, {}).get('cases'):
            errors.append(f'{name}: case selection changed')
        builds.add(result.get('build_sha256'))
        producers.add(result.get('producer_source_oid', result.get('source_oid')))
        if result.get('suite') == 'acceptance':
            accepted.extend(x['id'] for x in result['cases'])
            if not all(x.get('pass') is True and x.get('qualification') is True for x in result['cases']):
                errors.append(f'{name}: failed or experimental case')
        elif not result.get('cases'):
            errors.append(f'{name}: empty native proof')
    if len(builds) != 1 or None in builds:
        errors.append('shards did not use one verified build identity')
    if len(producers) != 1 or None in producers:
        errors.append('shards did not use one producer source identity')
    if sorted(accepted) != sorted(cases()):
        errors.append('acceptance coverage is missing or duplicated')
    summary = {'passed': not errors, 'source_oid': head(), 'build_sha256': sorted(x for x in builds if x),
               'producer_source_oids': sorted(x for x in producers if x),
               'acceptance_cases': sorted(accepted), 'shards': sorted(by_name), 'errors': errors}
    (directory / 'qualification.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    if errors:
        raise SystemExit(1)

parser = argparse.ArgumentParser(description=__doc__)
sub = parser.add_subparsers(dest='verb', required=True)
sub.add_parser('plan')
run = sub.add_parser('run')
run.add_argument('name')
run.add_argument('inputs', type=Path)
run.add_argument('evidence', type=Path)
combine = sub.add_parser('aggregate')
combine.add_argument('directory', type=Path)
if __name__ == '__main__':
    args = parser.parse_args()
    if args.verb == 'plan':
        print(json.dumps(plan(), separators=(',', ':')))
    elif args.verb == 'run':
        execute(args.name, args.inputs.resolve(), args.evidence.resolve())
    else:
        aggregate(args.directory.resolve())
