"""Confirmed tree loss: rollback across a power cut, snapshot and tree drop."""
from host.case import Boot
from host.lifecycle import consent, envelope, holds, identity, no_operation, placement, refused, snapshots, stale_token

ID = 'LOSS-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1, cut='after-preview'), Boot(2)]
ROOT = 'e2ea/loss'
MEMBERS = (ROOT, ROOT + '/child')


def snapset(obs):
    """Every snapshot's identity and holds."""
    return {n: (identity(obs, n), holds(obs, n)) for n in snapshots(obs)}


def same_placement(check, before, after, what):
    for name in MEMBERS:
        check.equal(identity(after, name), identity(before, name), f'{what}: {name} identity')
        check.equal(placement(after, name), placement(before, name), f'{what}: {name} placement')


def content(check, s, name, label):
    check.equal(s.step(f'{name}-root').out, f'{label}:', f'{name}: root content')
    check.equal(s.step(f'{name}-child').out, f'{label}:/child', f'{name}: child content')


def refusal(check, s, step, needle, before, after, what):
    refused(check, s.step(step), needle, what)
    check.equal(snapset(s.observe(after)), snapset(s.observe(before)), f'{what}: snapshots, identities, holds')


def bootfs(obs, pool):
    for line in (obs.path / 'pool-properties').read_text().splitlines():
        row = line.split('\t')
        if row[:2] == [pool, 'bootfs']:
            return row[2]
    return None


def verdict(ev, check):
    one, two = ev.stage(1), ev.stage(2)
    # Boot 1
    original = one.observe('original')
    refusal(check, one, 'held-rollback', 'e2ea/loss@later is held (e2e:foreign)', 'held-before', 'held-after',
            'rollback past a foreign-held newer snapshot')
    same_placement(check, original, one.observe('held-after'), 'after the foreign-hold refusal')
    content(check, one, 'held-content', 'unsnapshotted')
    envelope(check, one.step('peer-pair'), 'applied', 'pair of the secondary fixture')
    paired = 'e2ea/loss-peer belongs to a pair; unpair it first'
    refused(check, one.step('peer-rollback'), paired, 'rollback on a secondary')
    refused(check, one.step('peer-drop'), paired, 'drop on a secondary')
    peer_before, peer_after = one.observe('peer-before'), one.observe('peer-after')
    check.equal(identity(peer_after, 'e2ea/loss-peer'), identity(peer_before, 'e2ea/loss-peer'),
                'secondary identity kept across both refusals')
    check.equal(snapset(peer_after), snapset(peer_before), 'secondary refusals keep every snapshot and hold')

    preview = envelope(check, one.step('preview'), 'preview', 'rollback preview')
    token = preview.get('token')
    plan = preview['result']
    check.equal(len(plan['members']), 2, 'plan lists root and child')
    destroyed = [p['name'] for m in plan['members'] for p in m.get('destroyed', [])]
    check.equal(len(destroyed), 2, f'plan destroys two snapshots: {destroyed}')
    check(all(n.endswith('@later') for n in destroyed), f'plan destroys only @later: {destroyed}')
    check.equal(plan['unsnapshotted_changes_lost'], True, 'plan names the unsnapshotted loss')
    unattended = one.step('unattended')
    check.equal(unattended.rc, 3, 'unattended rollback exits 3')
    check.equal(unattended.json.get('mode'), 'preview', 'unattended rollback shows its preview')
    prepared, previewed = one.observe('prepared'), one.observe('previewed')
    check.equal(snapset(previewed), snapset(prepared), 'preview changed no snapshot, identity or hold')
    same_placement(check, prepared, previewed, 'after preview')
    content(check, one, 'previewed-content', 'unsnapshotted')
    no_operation(check, previewed, 'after preview')
    check.equal((one.path / 'rollback.token').read_text().strip(), token, 'the carried token is the reviewed one')

    # Boot 2, after the power cut
    check(two.step('boot-id').out.strip() != one.step('boot-id').out.strip(), 'a real kernel reboot was crossed')
    restored = two.observe('restored')
    check.equal(snapset(restored), snapset(prepared), 'power cut kept snapshots, identities and holds')
    same_placement(check, prepared, restored, 'after the power cut')
    content(check, two, 'restored-content', 'unsnapshotted')
    no_operation(check, restored, 'after the power cut')
    stale = 'the plan changed'
    refusal(check, two, 'wrong-token', stale, 'restored', 'wrong-after', 'rollback with a wrong token')
    stale_token(check, two.step('wrong-token'), 'rollback with a wrong token', token)

    applied = envelope(check, two.step('rollback'), 'applied', 'pre-cut token after reboot')
    check.equal(applied.get('token'), token, 'applied the boot-1 token')
    check.equal(applied['result']['complete'], True, 'rollback complete')
    rolled = two.observe('rolled')
    same_placement(check, prepared, rolled, 'after rollback')
    content(check, two, 'rolled-content', 'base')
    no_operation(check, rolled, 'after rollback')
    for name in (ROOT + '@base', ROOT + '/child@base'):
        check.equal(identity(rolled, name), identity(prepared, name), f'{name} identity kept')
    check.equal(snapshots(rolled, ROOT + '@') + snapshots(rolled, ROOT + '/'), [ROOT + '@base', ROOT + '/child@base'],
                'only the @base boundaries remain')
    check.equal(holds(rolled, ROOT + '@base'), ['e2e:retained'], 'the boundary hold is kept')
    replay = two.step('replay')
    stale_token(check, replay, 'a spent rollback token', token)
    refusal(check, two, 'replay', stale, 'rolled', 'replayed', 'replayed rollback token')
    refusal(check, two, 'held-drop', 'e2ea/loss@base is held (e2e:retained)', 'replayed', 'held-drop-after',
            'drop with a held boundary')

    kept = two.observe('kept')
    preview, applied = consent(check, two, 'snapshots', 'two-snapshot drop')
    check.equal(preview['result']['summary'], '2 snapshots in e2ea', 'two-snapshot drop summary')
    check.equal(applied['result']['complete'], True, 'two-snapshot drop complete')
    check.equal(snapset(two.observe('snapshots-dropped')), snapset(kept), 'only the two targets were dropped')

    refusal(check, two, 'default-drop', 'boot default', 'default-before', 'default-after', 'drop of the boot default')
    check.equal(bootfs(two.observe('default-after'), 'e2ea'), ROOT, 'refusal kept the boot default')
    preview, applied = consent(check, two, 'tree', 'tree drop')
    check.equal(preview['result']['summary'], '1 tree in e2ea', 'tree drop summary')
    check.equal(applied['result']['complete'], True, 'tree drop complete')
    dropped = two.observe('dropped')
    check.equal([n for n in dropped.datasets if n == ROOT or n.startswith((ROOT + '/', ROOT + '@'))], [],
                'no e2ea/loss dataset or snapshot remains')
    check.equal(bootfs(dropped, 'e2ea'), 'e2ea/loss-alternate', 'unrelated boot default untouched')
    check('e2ea/loss-alternate' in dropped.datasets, 'alternate BE still present')
    no_operation(check, dropped, 'after tree drop')
    refusal(check, two, 'drop-again', 'was not observed: e2ea/loss', 'dropped', 'drop-again-after',
            'drop of an absent tree')
