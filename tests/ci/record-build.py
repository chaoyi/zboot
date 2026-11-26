#!/usr/bin/env python3
"""Record exact source, package, runtime and runner identities for one CI build."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

out = Path(sys.argv[1]).resolve()
repo = Path(__file__).resolve().parents[2]
def git(*args):
    return subprocess.check_output(['git', *args], cwd=repo, text=True).strip()
def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
if git('status', '--porcelain'):
    raise SystemExit('CI source checkout must be clean')
paths = sorted(p for p in (out / 'distribution').rglob('*') if p.is_file())
record = {
    'source_oid': git('rev-parse', 'HEAD'),
    'source_tree': git('rev-parse', 'HEAD^{tree}'),
    'build_lock_sha256': sha(repo / 'dist/build.lock'),
    'build_lock': (repo / 'dist/build.lock').read_text(),
    'version': subprocess.check_output([out / 'distribution/usr/bin/zboot', '--version'], text=True).strip(),
    'files': {str(p.relative_to(out)): sha(p) for p in paths},
    'runner': {name: os.environ.get(name) for name in ('ImageOS', 'ImageVersion', 'RUNNER_ARCH', 'RUNNER_OS', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')},
    'host_kernel': platform.release(),
}
(out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
