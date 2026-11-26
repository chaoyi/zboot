"""Kept BE/home/volumes survive a cut before the step-11 record write and resume."""
from host.case import Boot
from host import restore as r

ID = 'RESTORE-KEPT-MOUNTS-NATIVE'
GROUP = 'restore'
SECONDS = 3600
DISKS = {'A': 4, 'B': 4, 'D': 8}
BOOTS = [Boot(1, cut='restore-cut'), Boot(2)]
STAGED = ('volume', 'vols', 'vols/exposed', 'vols/hidden')


def verdict(ev, check):
    first, second = ev.stage(1), ev.stage(2)
    r.base(first, check)
    r.placed(first, check, 'source')
    r.placed(first, check, 'old')
    r.previewed(first.step('restore-preview'), check, 'restore --dry-run')
    r.loader(first, check)
    op = r.cut(first, check, 11)

    r.hostid(second, check, 2)
    r.resumed_record(second, check, op, 10)
    staged = dict(row.split('\t') for row in second.step('staged-volmode').out.splitlines())
    for name in STAGED:
        check.equal(staged.get(f'e2eb/zboot-restore-{op}/{name}'), 'none', f'staged {name} volmode')
    blocks = second.step('block-devices').out.split()
    check(blocks and not [b for b in blocks if b.startswith('zd')], f'staging exposed a zvol: {blocks}')
    r.ok(second.step('resume'), check, f'zboot resume {op}')
    r.completed(second, check, 'done', ('e2ea/ROOT/be0', 'e2ea/home'))
    volmode = dict(row.split('\t') for row in second.step('kept-volmode').out.splitlines())
    for name, mode in (('e2ea/volume', 'dev'), ('e2ea/vols', 'dev'), ('e2ea/vols/exposed', 'dev'),
                       ('e2ea/vols/hidden', 'none')):
        check.equal(volmode.get(name), mode, f'{name} recovered volmode')
    rows = {(n, p): v for n, p, v in (row.split('\t') for row in second.step('kept-placement').out.splitlines())}
    placement = {'old_mountpoint': rows.get(('e2ea/ROOT/be0', 'mountpoint')),
                 'old_canmount': rows.get(('e2ea/ROOT/be0', 'canmount')),
                 'old_readonly': rows.get(('e2ea/ROOT/be0', 'readonly')),
                 'home_mountpoint': rows.get(('e2ea/home', 'mountpoint')),
                 'home_canmount': rows.get(('e2ea/home', 'canmount'))}
    check.equal(placement, {'old_mountpoint': '/', 'old_canmount': 'noauto', 'old_readonly': 'off',
                            'home_mountpoint': '/home', 'home_canmount': 'on'}, 'kept placement')
    check.contains(second.step('scrub-b').out, 'errors: No known data errors', 'B scrub after the cut')
    final = second.observe('final')
    check.equal(final.pools.get('e2eb', {}).get('health'), 'ONLINE', 'B health')
    # Completion keeps the staged copy for `zboot drop`, released and unmarked.
    staging = f'e2eb/zboot-restore-{op}'
    check(staging in final.datasets, f'{staging} kept after completion')
    check(not [h for h in final.holds if h[1] == f'zboot:restore:{op}'], 'restore holds left after completion')
    check(final.properties(staging).get('zboot:staging', {}).get('source') != 'local', 'staging still marked')
