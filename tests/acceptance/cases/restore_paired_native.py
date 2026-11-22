"""A paired secondary on B restored onto A: A unfenced and unpaired; B's side of
the pair whose peer was erased ends (one-sided, holds kept) and B boots again."""
import json
from pathlib import Path

from host.case import Boot
from host import restore as r
from host.identity import unchanged

ID = 'RESTORE-PAIRED-NATIVE'
GROUP = 'restore'
SECONDS = 3600
DISKS = {'A': 4, 'B': 4, 'D': 8}
# The setup boot runs this build's own kernel, initramfs and tools.
BOOTS = [Boot(1, append='zboot.recovery=1')]


def rows(step):
    return dict(line.split('\t') for line in step.out.splitlines())


def verdict(ev, check):
    s = ev.stage(1)
    launch = json.loads((Path(ev.root).parent / 'boot-1/launch.json').read_text())
    cmdline = launch['argv'][launch['argv'].index('-append') + 1].split()
    check.equal([arg for arg in cmdline if arg.startswith('zboot.recovery=')],
                ['zboot.recovery=1'], 'paired fixture explicitly exercises the UKI entry contract')
    r.base(s, check)
    r.placed(s, check, 'be')
    sync_token = r.previewed(s.step('sync-preview'), check, 'sync --dry-run on RO pools')
    unchanged(check, s.observe('sync-before-preview'), s.observe('sync-after-preview'),
              'sync preview leaves native identities, properties, holds and mounts unchanged')
    check.equal(s.step('sync').argv,
                ['zboot', 'sync', 'e2ea/ROOT/be1', 'e2eb/ROOT/be1', '--confirm', sync_token, '--json'],
                'sync explicitly consumes the token from its RO preview')
    r.applied(s.step('sync'), check, sync_token, 'sync --confirm on RO pools')
    for name in ('sync-dataset-readonly-before', 'sync-dataset-readonly-after'):
        check.equal(s.step(name).rc, 0, f'{name}: retain the native dataset readonly view')
    for name in ('sync-readonly', 'restore-readonly'):
        check.equal(rows(s.step(name)), {'e2ea': 'on', 'e2eb': 'on'},
                    f'{name} preserves read-only pool admission for the next CLI phase')
    secondary = rows(s.step('secondary'))
    check.equal(secondary.get('readonly'), 'on', 'B secondary fenced after sync')
    check(secondary.get('zboot:pair', '-') != '-', f'B secondary paired after sync: {secondary}')
    snapshots = s.step('boundary').out.split()
    check(snapshots, 'B mirror has a snapshot')
    r.refused(s.step('bare'), check, 'restore of the bare secondary', 'name a snapshot')
    token = r.reviewed(s, check, 'restore')
    r.loader(s, check)
    done = r.applied(s.step('restore-apply'), check, token, 'restore --confirm')
    check.equal(s.step('restore-apply').argv[2], snapshots[-1], 'restored from the boundary snapshot')
    check.equal(done.get('be'), 'e2ea/ROOT/be1', 'applied BE')
    check.equal(done.get('pool'), 'e2ea', 'applied pool')
    restored = r.completed(s, check, 'done', ('e2ea/scratch',), be_children=())
    # A is a new pool: the old primary and the preamble's datasets are gone.
    before = s.observe('before')
    check(restored.pools['e2ea']['guid'] != before.pools['e2ea']['guid'], 'A is a new pool')
    check('e2ea/plain' not in restored.datasets, 'A was erased (e2ea/plain gone)')
    after = rows(s.step('secondary-after'))
    check.equal(after.get('readonly'), 'on', 'B still fenced after the restore')
    check.equal(after.get('zboot:pair'), '-', 'B unpaired after the restore: its peer was erased')
    holds = [line.split('\t') for line in s.step('holds-after').out.splitlines() if line]
    check(any(h[1].startswith('zboot:anchor:') for h in holds), f'B keeps its anchor holds: {holds}')
    check.equal(rows(s.step('boot-readonly')), {'e2eb': 'on'},
                'the boot probe starts with every imported pool read-only')
    listing = s.step('listing').json['result']
    check.equal(listing['boot_environments'].count('e2eb/ROOT/be1'), 1,
                'B remains an observed boot environment')
    inventory = listing['kernels'].get('e2eb/ROOT/be1', {})
    check(not inventory.get('error'), 'B kernel inventory is available through normal status')
    check.equal([kernel['name'] for kernel in inventory.get('kernels', [])], ['zt'],
                'B has the bounded kernel/initrd discovery pair')
    refused = s.step('boot-probe')
    check.equal(refused.rc, 1, 'the missing-name probe refuses before handoff effects')
    envelope = refused.json
    check.equal(envelope.get('mode'), 'refused', 'the boot probe uses the common refused envelope')
    check.contains(envelope['result'].get('message') or '', 'must match exactly one listed kernel',
                   'B passes role and asset admission before the precise missing-kernel refusal')
    check('ZBOOT_HANDOFF_LOAD' not in refused.out + refused.err, 'the discovery probe stops before kexec')
