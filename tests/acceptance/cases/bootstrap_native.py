"""zboot sync bootstrap of an absent leaf receiver, plain unpair, anchor release."""
from host.case import Boot
from host.lifecycle import (consent, envelope, holds, identity, no_operation, pair, prop, refused, snapshots,
                            source, unchanged)

ID = 'BOOTSTRAP-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
SOURCE, RECEIVER = 'e2eb/bootstrap', 'e2ea/bootstrap'


def verdict(ev, check):
    s = ev.stage(1)
    refused(check, s.step('child-sync'),
            f'a pair joins leaf datasets, but {SOURCE} or {RECEIVER} has child datasets (child)',
            'bootstrap of a source with a child')
    unchanged(check, s.observe('child-before'), s.observe('child-after'), 'refused bootstrap')
    no_operation(check, s.observe('child-after'), 'refused bootstrap')
    result = envelope(check, s.step('sync'), 'applied', 'bootstrap sync')['result']
    pid = result['pair_id']
    check(isinstance(pid, str), f'bootstrap establishes a pair: {pid!r}')
    check.equal(result['bootstrapped'], pid, 'sync reports the bootstrap of the absent receiver')
    before, after = s.observe('before'), s.observe('after')
    check(RECEIVER not in before.datasets, 'the receiver was absent before the sync')
    no_operation(check, after, 'after bootstrap')
    left, right = pair(after, SOURCE), pair(after, RECEIVER)
    check.equal((left['pair_id'], right['pair_id']), (pid, pid), 'both endpoints carry the pair id')
    check.equal((left['role'], right['role']), ('primary', 'secondary'), 'bootstrap roles')
    check.equal(left['endpoint'], right['peer'], 'source endpoint is the receiver peer')
    check.equal(right['endpoint'], left['peer'], 'receiver endpoint is the source peer')
    for name in snapshots(after, SOURCE):
        got = after.datasets.get(RECEIVER + name[len(SOURCE):])
        check.equal(got and got['guid'], after.datasets[name]['guid'], f'{name} mirrored with its GUID')
    check.equal(identity(after, SOURCE), identity(before, SOURCE), 'source identity kept')
    check.equal([prop(after, RECEIVER, k) for k in ('readonly', 'canmount', 'mounted')],
                ['on', 'noauto', 'no'], 'receiver is a fenced secondary')
    for key in ('readonly', 'canmount'):
        check.equal(source(after, RECEIVER, key), 'local', f'receiver {key} fence is local')
    for key, value in (('compression', 'zstd'), ('e2e:bootstrap', 'source')):
        check.equal((prop(after, RECEIVER, key), source(after, RECEIVER, key)), (value, 'local'),
                    f'receiver has the copied {key} as a local value')
    check.equal(prop(after, RECEIVER, 'mountpoint'), '/mnt/zfs-e2e/bootstrap-source',
                "the copy's mountpoint is the working copy's path")
    check(not any('/zboot-receive-' in name for name in after.datasets), 'no receive container is left')
    check.equal(s.step('read-root').out, 'bootstrap root content', 'receiver root content')

    tag = f'zboot:anchor:{pid}'
    suffix = s.step('anchor').out.splitlines()[0]
    root, held = f'{RECEIVER}@{suffix}', f'{SOURCE}@{suffix}'
    points = [root, held]
    paired = s.observe('paired')
    check(tag in holds(paired, root), f'{root} holds {tag}')
    unpaired = envelope(check, s.step('unpair'), 'applied', 'plain unpair')['result']
    check.equal(unpaired['retained_anchor_tag'], tag, 'plain unpair reports the anchors it keeps')
    kept = s.observe('kept')
    for name in points:
        check(tag in holds(kept, name), f'plain unpair keeps the anchor on {name}: {holds(kept, name)}')
    for name in (SOURCE, RECEIVER):
        check.equal(prop(kept, name, 'zboot:pair'), '-', f'plain unpair removes the pair pointer on {name}')

    preview, applied = consent(check, s, 'release', 'unpair --release-anchors')
    review = preview['result']['release']
    check.equal(len(review), 2, f'release reviews two anchors: {review}')
    check(all(p['tag'] == tag for p in review), f'every reviewed point carries {tag}')
    check(any(p['point']['name'] == root and p['deferred_destroy'] is True for p in review),
          f'review names the deferred destroy of {root}')
    released = applied['result']['released']
    check.equal(len(released), 2, f'two anchors released: {released}')
    check(any(p['snapshot'] == root and p['state'] == 'destroyed' for p in released),
          f'{root} reported destroyed')
    after = s.observe('released')
    check.equal(identity(after, held), identity(paired, held), f'{held} identity kept')
    check.equal(holds(after, held), ['e2e:foreign'], f'{held} keeps only the foreign hold')
    check(root not in after.datasets, f'{root} destroyed on its final hold release')
    refused(check, s.step('release-again'), 'e2eb/bootstrap holds no zboot anchor; nothing to release',
            'repeated unpair --release-anchors')
    unchanged(check, after, s.observe('released-again'), 'repeated unpair --release-anchors')
    no_operation(check, s.observe('released-again'), 'at the end')
