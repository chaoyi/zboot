"""Paired BE cycle (one dataset each): bootstrap, incremental, primary B,
primary A. Then a synced shared dataset's secondary stays unmounted across a
reboot."""
import json

from host.case import Boot
from host.lifecycle import envelope, identity, prop, source

ID = 'BOOT-PAIR-CYCLE-NATIVE'
GROUP = 'small'
SECONDS = 1200
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1), Boot(2)]
A, B = 'e2ea/cycle', 'e2eb/cycle'
SA, SB, SHARED = 'e2ea/shared', 'e2eb/shared', '/mnt/zfs-e2e/shared'
MEMBERS = (A, B)
# (state, primary, receiver-local policy and the second copied value in place)
STATES = (('bootstrap', A, False), ('incremental', A, True), ('primary-b', B, True), ('primary-a', A, True))


def ident(obs, name):
    pool, guid, createtxg, objsetid = identity(obs, name)
    return {'pool_guid': pool, 'guid': guid, 'createtxg': createtxg, 'objsetid': objsetid}


def rows(check, step, label):
    props = {}
    for line in step.out.splitlines():
        fields = line.split('\t')
        check.equal(len(fields), 4, f'{label}: native property row shape {line!r}')
        if len(fields) == 4:
            check((fields[0], fields[1]) not in props, f'{label}: duplicate row {fields[:2]}')
            props[fields[0], fields[1]] = (fields[2], fields[3])
    return props


def state(check, s, label, primary, distinct, baseline, pair_id):
    obs = s.observe(label)
    props = rows(check, s.step(f'{label}-props'), label)
    pairs = {}
    for name in MEMBERS:
        check.equal(identity(obs, name), identity(baseline, name), f'{label}: {name} identity')
        check.equal(prop(obs, name, 'mounted'), 'no', f'{label}: {name} unmounted')
        # New copies materialize the root shape locally.
        check.equal(props.get((name, 'mountpoint')), ('/', 'local'), f'{label}: {name} native root shape')
        check.equal(props.get((name, 'canmount')), ('noauto', 'local'), f'{label}: {name} canmount')
        check.equal(props.get((name, 'readonly')), ('off' if name == primary else 'on', 'local'),
                    f'{label}: {name} readonly')
        placement = props.get((name, 'zboot:placement'))
        check(placement is not None, f'{label}: {name} zboot:placement row present')
        if name == primary:
            check.equal(placement, ('-', '-'), f'{label}: active {name} retains no saved placement authority')
        elif placement:
            check.equal(placement[1], 'local', f'{label}: secondary {name} placement is local')
            # Keep checking the remaining native state if a receipt is missing
            # or malformed; a parser exception must not hide later evidence.
            try:
                saved = json.loads(placement[0])
            except (json.JSONDecodeError, TypeError):
                saved = None
            check.equal(saved, {'schema_version': 1, 'identity': ident(obs, name),
                                'readonly': False, 'canmount': 'no_auto'},
                        f'{label}: secondary {name} retains exact original identity and unfenced roles')
        cmdline = 'console=ttyS1' if name == B and distinct else 'console=ttyS0'
        check.equal(props.get((name, 'zboot:cmdline')), (cmdline, 'local'), f'{label}: {name} zboot:cmdline')
        # A copied user property is a local value on both copies.
        cycle = 'two' if distinct else 'one'
        check.equal(props.get((name, 'e2e:cycle')), (cycle, 'local'), f'{label}: {name} copied e2e:cycle')
        raw, src = props.get((name, 'zboot:pair'), ('-', '-'))
        check.equal(src, 'local', f'{label}: {name} pair record is local')
        pair = json.loads(raw) if raw != '-' else {}
        check.equal(pair.get('pair_id'), pair_id, f'{label}: {name} pair id unchanged')
        check.equal(pair.get('endpoint', {}).get('name'), name, f'{label}: {name} endpoint name')
        check.equal(pair.get('endpoint', {}).get('identity'), ident(obs, name), f'{label}: {name} endpoint identity')
        check.equal(pair.get('role'), 'primary' if name == primary else 'secondary', f'{label}: {name} role')
        pairs[name] = pair
    check.equal(pairs[A].get('endpoint'), pairs[B].get('peer'), f'{label}: A endpoint is B peer')
    check.equal(pairs[B].get('endpoint'), pairs[A].get('peer'), f'{label}: B endpoint is A peer')


def payload(check, s, name, value):
    check.equal(s.step(f'{name}-kernel').out, 'ZFS-E2E-DISCOVERY-KERNEL',
                f'{name}: replicated root retains the discovery kernel companion')
    check.equal(s.step(f'{name}-initrd').out, 'ZFS-E2E-DISCOVERY-INITRD',
                f'{name}: replicated root retains the discovery initrd companion')
    check.equal(s.step(f'{name}-read').out, value, f'{name}: payload')


def verdict(ev, check):
    s = ev.stage(1)
    outcomes = {}
    for label, step in (('bootstrap', 'bootstrap'), ('incremental', 'incremental'),
                        ('primary B', 'primary-b'), ('primary A', 'primary-a')):
        outcomes[step] = envelope(check, s.step(step), 'applied', label)['result']
    original, baseline = s.observe('original'), s.observe('bootstrap')
    frozen = outcomes['bootstrap']['completed_operation']['receive']['source']
    check.equal(sorted(frozen), [''], 'the bootstrap binds the BE alone')
    check.equal(identity(baseline, A), identity(original, A), f'bootstrap keeps {A} identity')
    check.equal((prop(original, A, 'mountpoint'), source(original, A, 'mountpoint')),
                ('/', 'local'), f'{A}: original explicit mountpoint is native local authority')
    check.equal(frozen.get('', {}).get('mountpoint'), {'value': '/', 'source': 'local'},
                f'{A}: frozen source placement binds the exact local value')
    pair_id = json.loads(prop(baseline, A, 'zboot:pair'))['pair_id']
    for label, primary, distinct in STATES:
        state(check, s, label, primary, distinct, baseline, pair_id)
    payload(check, s, 'initial-b', 'initial')
    payload(check, s, 'incremental-b', 'incremental')
    payload(check, s, 'caught-up-b', 'incremental')
    payload(check, s, 'reverse-read-a', 'reverse')
    payload(check, s, 'reverse-read-b', 'reverse')
    check.equal(s.step('pools').out, '', 'no pool imported after export')

    # The shared dataset's secondary: noauto and read-only at creation...
    envelope(check, s.step('shared-sync'), 'applied', 'shared sync')
    props = rows(check, s.step('shared-props'), 'shared')
    check.equal(props.get((SA, 'canmount'), ('-',))[0], 'on', f'{SA} still mounts at boot')
    check.equal(props.get((SB, 'canmount')), ('noauto', 'local'), f'{SB} secondary is noauto')
    check.equal(props.get((SB, 'readonly')), ('on', 'local'), f'{SB} secondary is read-only')
    check.equal(props.get((SB, 'mountpoint'), ('-',))[0], SHARED, f'{SB} shares the mountpoint')
    # ...so after the reboot `zfs mount -a` mounts the primary only.
    r = ev.stage(2)
    rebooted = r.observe('rebooted')
    check.equal(prop(rebooted, SA, 'mounted'), 'yes', f'{SA} mounted after the reboot')
    check.equal(rebooted.mounts.get(SHARED), SA, f'{SHARED} is the primary')
    check.equal(prop(rebooted, SB, 'mounted'), 'no', f'{SB} secondary stays unmounted across the reboot')
    for name in MEMBERS:
        check.equal(prop(rebooted, name, 'mounted'), 'no', f'{name} stays unmounted across the reboot')
    check.equal(r.step('rebooted-read').out, 'shared', 'the primary payload is what mounts')
