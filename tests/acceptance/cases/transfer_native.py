"""zboot sync into an existing copy: refused unpaired; then push, then read-only pull."""
from host.case import Boot
from host.lifecycle import (envelope, identity, no_operation, placement, prop, refused, snapshots, source,
                            unchanged)

ID = 'TRANSFER-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
SOURCE, COPY = 'e2eb/xfer', 'e2ea/transfer'


def mirrored(check, obs, what):
    """Every source snapshot has an equal-GUID counterpart on the copy."""
    for name in snapshots(obs, SOURCE + '@'):
        got = obs.datasets.get(COPY + name[len(SOURCE):])
        check.equal(got and got['guid'], obs.datasets[name]['guid'], f'{what}: {name} mirrored on {COPY}')


def inspected(check, s, name, value):
    path = '/mnt/zfs-e2e/transfer-check'
    options = [line.split()[5].split(',') for line in s.step(f'{name}-mountinfo').out.splitlines()
               if line.split()[4] == path]
    check(len(options) == 1 and 'ro' in options[0], f'{name}: {path} mounted read-only: {options}')
    check.equal(s.step(f'{name}-read').out, value, f'{name}: content')
    check.equal(s.step(f'{name}-load-key').rc, 0, f'{name}: the source key opens the raw copy')


def verdict(ev, check):
    s = ev.stage(1)
    refused(check, s.step('unpaired'), f'{COPY} already exists and is not paired with {SOURCE}',
            'sync into an existing unpaired dataset')
    unchanged(check, s.observe('unpaired-before'), s.observe('unpaired-after'), 'refused unpaired sync')
    no_operation(check, s.observe('unpaired-after'), 'refused unpaired sync')
    pair_id = envelope(check, s.step('pair'), 'applied', 'pair')['result']['operation_id']

    push = envelope(check, s.step('push'), 'applied', 'sync (writable source)')['result']
    check.equal(push['bootstrapped'], None, 'an existing copy is not bootstrapped')
    check.equal(push['pair_id'], pair_id, 'the sync names its pair')
    check.equal(push.get('unmirrored'), [SOURCE + '/extra'], 'the child under the leaf is reported as not mirrored')
    before, after = s.observe('push-before'), s.observe('push-after')
    check(COPY + '/extra' not in after.datasets, 'the child under the leaf was not copied')
    mirrored(check, after, 'after push')
    check.equal(identity(after, COPY), identity(before, COPY), 'push keeps the copy identity')
    check.equal(placement(after, COPY), placement(before, COPY), 'push keeps the copy placement')
    check.equal([prop(after, COPY, k) for k in ('readonly', 'canmount', 'mounted', 'mountpoint')],
                ['on', 'noauto', 'no', '/mnt/zfs-e2e/transfer-target'], 'the copy stays fenced in its own place')
    check(len(snapshots(after, COPY + '@zboot_transfer_')) == 1, 'the writable push left its captured boundary')
    for key, value in (('compression', 'zstd'), ('e2e:data-property', 'source')):
        check.equal((prop(after, COPY, key), source(after, COPY, key)), (value, 'local'),
                    f'copied {key} is local on the copy')
    check.equal(prop(after, COPY, 'encryptionroot'), COPY, 'the raw copy is its own encryption root')
    no_operation(check, after, 'after push')

    # sync --all syncs the leaf but reports the stray child as unfinished.
    every = s.step('push-all')
    check.equal(every.rc, 4, f'sync --all with a child under a pair leaf exits 4 ({every.err.strip()[-300:]})')
    value = every.json
    check.equal(value.get('mode'), 'partial', 'sync --all envelope is partial')
    check.equal(value.get('result', {}).get('complete'), False, 'sync --all reports the run unfinished')
    entries = value.get('result', {}).get('pairs', [])
    check.equal([(e['source'], e['destination']) for e in entries], [(SOURCE, COPY)], 'sync --all covers the pair')
    check.equal([(e.get('result') or {}).get('unmirrored') for e in entries], [[SOURCE + '/extra']],
                'sync --all names the child as not mirrored')

    envelope(check, s.step('pull'), 'applied', 'sync (read-only source)')
    before, after = s.observe('pull-before'), s.observe('pull-after')
    mirrored(check, after, 'after pull')
    # No fresh capture: nothing new on the source, beyond zboot's own older
    # boundary snapshots, which the pull's cleanup removes (checked below).
    def operator(names):
        return [n for n in names if '@zboot_transfer_' not in n]
    check.equal(operator(snapshots(after, SOURCE)), operator(snapshots(before, SOURCE)),
                'a read-only source gets no fresh capture')
    check(set(snapshots(after, SOURCE)) <= set(snapshots(before, SOURCE)),
          'the pull adds no snapshot to the read-only source')
    check(COPY + '@readonly_boundary' in after.datasets, 'the existing read-only boundary was transferred')
    # The anchor is now the operator's snapshot: zboot's own older boundary
    # snapshots go on both sides, without review.
    for name in (SOURCE, COPY):
        check.equal(snapshots(after, name + '@zboot_transfer_'), [], f'no zboot boundary snapshot is left on {name}')
    check(COPY + '@pushed' in after.datasets, "the operator's own snapshots stay")
    inspected(check, s, 'pushed', 'pushed')
    inspected(check, s, 'head', 'readonly')
