"""INCREMENTAL-IDENTITY: property-free per-dataset raw incrementals into a locked
receiver keep identity and placement."""
from host.case import Boot
from host.identity import identity, named, prop

ID = 'INCREMENTAL-IDENTITY-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
PAIRS = (('e2eb/encrypted', 'e2ea/incremental', 'root'),
         ('e2eb/encrypted/child', 'e2ea/incremental/child', 'child'))
POINTS = ('secret', 'initial', 'middle', 'next')


def rows(step):
    return [line.split('\t') for line in step.out.splitlines()]


def verdict(ev, check):
    s = ev.stage(1)
    before, after = s.observe('before'), s.observe('after')
    for step in ('replicate', 'replicate-initial', 'replicatechild', 'replicatechild-initial'):
        check.equal(s.step(step).out.split(), ['send_exit=0', 'receive_exit=0'], f'{step}: raw pipeline exits')
    placement = rows(s.step('placement-before'))
    check.equal(len(placement), 6, 'three placement rows per receiver')
    for name, key, value, source in placement:
        check.equal(source, 'local', f'{name} {key} is local before the incremental')
    for step in ('incremental', 'incrementalchild'):
        check.equal(s.step(step).out.split(), ['send_exit=0', 'receive_exit=0'],
                    f'{step}: non-force raw incremental pipeline exits')
    check.equal(s.step('placement-after').out, s.step('placement-before').out,
                'placement rows byte-identical across a stream that carries no properties')
    for _, dst, _ in PAIRS:
        check.equal(prop(after, dst, 'encryptionroot'), dst, f'{dst} is its own encryption root')
        check.equal(after.properties(dst)['e2e:placement']['source'], 'local',
                    f'{dst} keeps its own e2e:placement; the source change is not carried')
    status = s.step('inventory-after').json['result']['inventory']
    ivsets = dict(rows(s.step('ivsets')))
    written = dict(rows(s.step('written')))
    for src, dst, label in PAIRS:
        check.equal(identity(after, dst), identity(before, dst), f'{dst} identity unchanged by the incremental')
        check.equal(named(status, 'datasets', dst)['identity'], named(s.step('inventory-before').json['result']['inventory'], 'datasets', dst)['identity'],
                    f'status: {dst} identity unchanged')
        record = named(status, 'datasets', dst)
        check.equal((record['readonly'], record['keystatus'], record['mounted']), (True, 'unavailable', False),
                    f'status: {dst} readonly, locked, unmounted')
        check.equal((prop(after, dst, 'readonly'), prop(after, dst, 'keystatus'), prop(after, dst, 'mounted')),
                    ('on', 'unavailable', 'no'), f'native {dst} readonly, locked, unmounted')
        for point in POINTS:
            check.equal(after.datasets[f'{dst}@{point}']['guid'], after.datasets[f'{src}@{point}']['guid'],
                        f'{dst}@{point} keeps the source snapshot guid')
            iv = ivsets[f'{src}@{point}']
            check(iv.isdigit() and iv != '0', f'{src}@{point} has an IV-set guid: {iv!r}')
            check.equal(ivsets[f'{dst}@{point}'], iv, f'{dst}@{point} keeps the source IV-set guid')
        check.equal(written[dst], '0', f'{dst} wrote nothing since @next')
        check.equal(s.step(f'head-{label}').out, f'{label}-next\n', f'{dst} head content')
        for point in ('initial', 'middle', 'next'):
            check.equal(s.step(f'check-{label}-{point}').out, f'{label}-{point}\n', f'{dst}@{point} content')
    check.equal(s.step('new-child').out, 'new child data\n', 'receiver child new.txt')
