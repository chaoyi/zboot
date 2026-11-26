"""zboot primary on a leaf pair: child refusal, catch-up switch, replay, standalone activation."""
from host.case import Boot
from host.lifecycle import (envelope, identity, no_operation, pair, prop, refused, snapshots, source,
                            unchanged)

ID = 'PRIMARY-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
S, T = 'e2ea/primary-source', 'e2eb/primary-target'
SP, TP = '/mnt/zfs-e2e/primary-source', '/mnt/zfs-e2e/primary-target'


def fence(check, obs, name, active, what):
    """Write/mount fence of one copy, read natively."""
    check.equal(prop(obs, name, 'readonly'), 'off' if active else 'on', f'{what}: {name} readonly')
    check.equal(source(obs, name, 'readonly'), 'local', f'{what}: {name} readonly role is local')
    check.equal(prop(obs, name, 'mounted'), 'yes' if active else 'no', f'{what}: {name} mounted')
    check.equal(prop(obs, name, 'canmount'), 'on' if active else 'noauto', f'{what}: {name} canmount')
    check.equal(source(obs, name, 'canmount'), 'local', f'{what}: {name} canmount role is local')
    mountpoint = TP if name == T else SP
    check.equal(prop(obs, name, 'mountpoint'), mountpoint, f'{what}: {name} exact mountpoint')
    if active:
        check.equal(obs.mounts.get(mountpoint), name, f'{what}: {name} at its exact native mountpoint')
    else:
        # The active copy may legitimately occupy the same path. The
        # fenced dataset itself must be absent from EVERY native mount.
        check(name not in obs.mounts.values(), f'{what}: {name} absent from all mountinfo')


def verdict(ev, check):
    s = ev.stage(1)
    paired = envelope(check, s.step('pair'), 'applied', 'pair')
    pair_id = paired['result']['operation_id']
    check(isinstance(pair_id, str), f'pair reports its pair id: {pair_id!r}')

    refused(check, s.step('child-primary'), f'a pair joins leaf datasets, but {S} or {T} has child datasets (extra)',
            'primary with a child under the working copy')
    unchanged(check, s.observe('child-before'), s.observe('child-after'), 'refused primary')

    preview = envelope(check, s.step('preview'), 'preview', 'primary preview')
    plan = preview['result']
    check.equal(plan['target']['name'], T, 'plan target')
    check.equal(plan['peer']['name'], S, 'plan peer')
    check.equal(plan['pair_id'], pair_id, 'plan pair id')
    check.equal(plan['mode'], 'catch-up', 'plan mode')
    check.equal(plan['loss'], None, 'catch-up claims no loss')
    applied = envelope(check, s.step('primary'), 'applied', 'primary --confirm')
    check.equal(applied['token'], preview['token'], 'primary applied the reviewed token')
    result = applied['result']
    check.equal(result['target']['name'], T, 'result target')
    check.equal(result['former_primary']['name'], S, 'result former primary')
    check.equal(result['already_primary'], False, 'result already_primary')
    check('cache' not in result, f'primary reports no mount cache: {sorted(result)}')
    op = result['operation_id']
    check(isinstance(op, str), f'primary reports its operation id: {op!r}')

    before, after = s.observe('before'), s.observe('after')
    no_operation(check, after, 'after primary')
    fence(check, after, S, False, 'former primary')
    fence(check, after, T, True, 'new primary')
    left, right = pair(after, S), pair(after, T)
    check.equal(left['role'], 'secondary', 'source role')
    check.equal(right['role'], 'primary', 'target role')
    check.equal((left['pair_id'], right['pair_id']), (pair_id, pair_id), 'pair id kept on both sides')
    check.equal(left['endpoint'], right['peer'], 'source endpoint is the target peer')
    check.equal(right['endpoint'], left['peer'], 'target endpoint is the source peer')
    a, b = f'{S}@zboot_primary_{op}', f'{T}@zboot_primary_{op}'
    check(a in after.datasets and b in after.datasets, 'final primary snapshot on both copies')
    if a in after.datasets and b in after.datasets:
        check.equal(after.datasets[a]['guid'], after.datasets[b]['guid'], 'final snapshot GUID')
    check.equal(s.step('target-root').out, 'final-after-pair', 'new primary has the quiesced head bytes')
    for name in (S, T):
        check.equal(identity(after, name), identity(before, name), f'{name} not re-incarnated')

    replay = envelope(check, s.step('replay'), 'applied', 'primary replay')['result']
    check.equal(replay['already_primary'], True, 'replay already_primary')
    check.equal(replay['mode'], 'already-primary', 'replay mode')
    check.equal(replay['operation_id'], None, 'replay has no operation')
    replayed = s.observe('replayed')
    check.equal({n: replayed.datasets[n] for n in snapshots(replayed)},
                {n: after.datasets[n] for n in snapshots(after)}, 'replay changed no snapshot')

    plain = envelope(check, s.step('plain'), 'applied', 'primary e2ea/alone')['result']
    check.equal((plain['mode'], plain['operation_id'], plain['former_primary']), ('standalone', None, None),
                'primary on an unpaired active dataset is a standalone no-op')
    envelope(check, s.step('unpair'), 'applied', 'unpair')
    standalone = envelope(check, s.step('standalone'), 'applied', 'standalone primary')['result']
    check.equal(standalone['former_primary'], None, 'standalone invents no peer')
    check.equal(standalone['mode'], 'standalone', 'standalone mode')
    independent = s.observe('independent')
    no_operation(check, independent, 'after standalone')
    fence(check, independent, S, True, 'standalone source')
    fence(check, independent, T, True, 'standalone target')
    check.equal(s.step('source-root').out, 'final-after-pair', 'standalone restoration kept the retained bytes')
