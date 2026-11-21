"""RENAME: same-pool move of a clone-connected tree; identity, placement, bootfs, replay."""
from host.case import Boot
from host.identity import identity, pool_prop, prop, under, unchanged

ID = 'RENAME-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
SRC, DST = 'e2ea/move-source', 'e2ea/move-container/renamed'
PLACEMENT = ('readonly', 'canmount', 'mounted', 'mountpoint')


def renamed(name):
    return DST + name[len(SRC):]


def verdict(ev, check):
    s = ev.stage(1)
    before, after = s.observe('before'), s.observe('after')
    preview = s.step('preview').json
    plan = preview['result']
    check.equal(preview['schema_version'], 1, 'preview envelope schema')
    check.equal(preview['mode'], 'preview', 'preview mode')
    check(isinstance(preview.get('token'), str) and len(preview['token']) == 32, 'rename preview carries a stable plan token')
    check.equal(plan['kind'], 'rename', 'preview kind')
    check.equal(plan['source']['name'], SRC, 'preview source')
    check.equal(plan['destination'], DST, 'preview destination')
    check.equal(len(plan['members']), 2, 'preview members (root + child)')
    check.equal(plan['bootfs'], SRC, 'preview reports the bound bootfs')
    unchanged(check, before, s.observe('after-preview'), 'preview')

    existing = s.step('existing')
    check(existing.rc != 0, f'move onto existing e2ea/plain refused: rc={existing.rc}')
    check.contains(existing.err, 'e2ea/plain exists', 'existing-destination refusal names the destination')
    unchanged(check, before, s.observe('after-existing'), 'existing-destination refusal')
    token = s.step('stale-token')
    check.equal(token.rc, 3, 'stale rename token exits 3')
    check.equal(token.json['mode'], 'refused', 'stale rename token refusal envelope')
    check.equal(token.json['result']['reason'], 'stale_token', 'stale rename token reason')
    check('token' not in token.json and preview['token'] not in token.err, 'stale refusal discloses no current token')
    unchanged(check, before, s.observe('after-token'), 'needless-token refusal')
    check(SRC in s.observe('after-token').datasets, 'source still present after both refusals')

    moved = s.step('rename').json
    check.equal(moved['schema_version'], 1, 'move envelope schema')
    check.equal(moved['mode'], 'applied', 'move envelope mode')
    check.equal(moved['result']['complete'], True, 'move complete')
    check.equal(moved['result']['destination']['name'], DST, 'move destination')

    check.equal(under(after.datasets, SRC), [], 'no dataset or snapshot left under the old name')
    members = under(before.datasets, SRC)
    check.equal(len([m for m in members if '@' not in m]), 2, 'fixture tree has root + child')
    check.equal(len([m for m in members if '@' in m]), 4, 'fixture tree has four snapshots')
    for old in members:
        new = renamed(old)
        check(new in after.datasets, f'{new} exists natively')
        check.equal(identity(after, new), identity(before, old), f'{new} keeps the native identity of {old}')
        if '@' in old:
            check.equal(after.datasets[new.split('@')[0]]['guid'], before.datasets[old.split('@')[0]]['guid'],
                        f'{new} dataset guid unchanged')
            continue
        for key in PLACEMENT:
            check.equal(prop(after, new, key), prop(before, old, key), f'{new} {key} unchanged')
        check.equal(prop(after, new, 'compression'), 'lz4', f'{new} keeps lz4, not the parent zstd')
    check.equal(prop(after, DST, 'compression'), 'lz4', 'moved root compression')
    check.equal(after.properties(DST)['compression']['source'], 'local', 'moved root compression stays local')
    check.equal(prop(after, DST, 'e2e:payload'), 'source', 'user property kept')
    check.equal(prop(after, DST, 'origin'), 'e2ea/move-template@origin', 'external origin kept')
    check.equal(identity(after, 'e2ea/move-dependent'), identity(before, 'e2ea/move-dependent'),
                'external dependent not replaced')
    check.equal(prop(after, 'e2ea/move-dependent', 'origin'), f'{DST}/child@first',
                'dependent origin follows the move')
    check.equal(pool_prop(before, 'e2ea', 'bootfs'), SRC, 'fixture bootfs')
    check.equal(pool_prop(after, 'e2ea', 'bootfs'), DST, 'bootfs follows the move')
    for label, path in (('root', '/mnt/zfs-e2e/move-source'), ('child', '/mnt/zfs-e2e/move-source/child')):
        check.equal(s.step(f'live-{label}').out, f'unsnapshotted-{label}', f'live {label} data kept')
        check.equal(after.mounts.get(path), DST if label == 'root' else f'{DST}/child',
                    f'{path} is mounted from the moved dataset')
        check.equal(s.step(f'proof-{label}').out, f'retained-first-{label}', f'{label}@first content kept')
    check.equal(s.step('operation').out.strip(), '-', 'no zboot:operation record left on e2ea')

    replay = s.step('replay')
    check(replay.rc != 0, f'replayed move refused: rc={replay.rc}')
    check.contains(replay.err, 'not observed: e2ea/move-source', 'replay refusal names the gone source')
    unchanged(check, after, s.observe('after-replay'), 'replay refusal')
