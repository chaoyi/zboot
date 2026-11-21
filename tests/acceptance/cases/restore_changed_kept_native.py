"""Kept data changed after staging is never erased (cut before step 7)."""
from host.case import Boot
from host import restore as r

ID = 'RESTORE-CHANGED-KEPT-NATIVE'
GROUP = 'restore'
SECONDS = 3600
DISKS = {'A': 4, 'B': 4, 'D': 8}
BOOTS = [Boot(1, cut='restore-cut'), Boot(2)]
ATTEMPTS = (('snapshot', 'gained a snapshot or was created'),
            ('child', 'gained a snapshot or was created'),
            ('written', 'was written'))


def verdict(ev, check):
    first, second = ev.stage(1), ev.stage(2)
    r.base(first, check)
    r.placed(first, check, 'source')
    r.previewed(first.step('restore-preview'), check, 'restore --dry-run')
    r.loader(first, check)
    op = r.cut(first, check, 7)

    r.hostid(second, check, 2)
    r.resumed_record(second, check, op, 6)
    for name, reason in ATTEMPTS:
        r.reviewed(second, check, name)
        r.refused(second.step(f'{name}-confirmed'), check, f'{name}: confirmed resume', reason, 'nothing was erased')
        r.resumed_record(second, check, op, 6, f'{name}-record')
        check('e2ea' in second.step(f'{name}-pools').out.split(), f'{name}: A still imported')
        check.equal(second.step(f'{name}-first').rc, 0, f'{name}: e2ea/plain@first still exists')
    # Recorded, not judged: A's kept tree is not fenced at step 6 (`fence` reads off).
    before = [l for l in second.step('a-before').out.splitlines() if 'zboot-restore-' not in l]
    after = set(second.step('a-after').out.splitlines())
    check(before and all(l in after for l in before), f'A lost a dataset or snapshot: {set(before) - after}')
    b, a = second.observe('before'), second.observe('after')
    for name, ident in b.datasets.items():
        if name.startswith('e2ea'):
            check.equal(a.datasets.get(name), ident, f'{name} identity (guid, createtxg) unchanged')
    check.contains(second.step('scrub-b').out, 'errors: No known data errors', 'B scrub after the cut')
