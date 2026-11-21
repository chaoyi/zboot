"""RET-02: zsnap capture, policy inheritance, scheduled runs and retention protections."""
from host.case import Boot
from host.identity import named

ID = 'RET-02-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
HELD = 'e2ea/ret@zsnap_2020-01-01-000000'
DEFERRED = 'e2ea/ret@zsnap_2020-01-02-000000'
READER = 'foreign-retention-reader'


def verdict(ev, check):
    s = ev.stage(1)
    maps = {}

    def snapmap(name):
        if name not in maps:
            rows = [line.split('\t') for line in s.step(name).out.splitlines()]
            check(all(len(r) == 2 and r[1].isdigit() and int(r[1]) < 1 << 64 for r in rows),
                  f'{name}: every row is a name and a u64 guid: {rows[:3]}')
            maps[name] = dict(rows)
        return maps[name]

    def owned(m, dataset):
        return sorted(n for n in m if n.startswith(f'{dataset}@zsnap_'))

    check.equal(s.step('clock').out.strip(), '2030-01-15T12:00:00Z', 'guest clock set')
    first = snapmap('map-first')
    check.equal(len(first), 1, f'zsnap snap captured exactly one snapshot: {sorted(first)}')
    check.equal(len(owned(first, 'e2ea/ret')), 1, 'and it is e2ea/ret@zsnap_* (no descendant)')
    check.equal(s.step('inherited').out.strip(), 'e2e\tinherited from e2ea/ret', 'child inherits the policy')
    check.equal(s.step('revealed').out, s.step('inherited').out, 'unassign reveals the inherited policy')
    check.contains(s.step('status').out, "policy 'e2e'", 'zsnap status reports the policy')
    before_run, after_run = snapmap('map-before-run'), snapmap('map-after-run')
    added = {n.split('@')[0] for n in after_run if n not in before_run}
    check.equal(added, {'e2ea/ret', 'e2ea/ret/child'}, 'zsnap run captures the assigned parent and inherited child')
    check.equal(owned(after_run, 'e2ea/ret/disabled'), [], 'disabled child not captured')
    check(all(after_run[n] == g for n, g in before_run.items()), 'zsnap run kept every earlier snapshot')
    check.equal(snapmap('map-after-run-again'), after_run, 'unchanged heads gain no snapshot')

    check.equal(s.step('prune').rc, 0, 'zsnap prune --last 1 succeeds')
    pruned = snapmap('map-pruned')
    for name in (HELD, DEFERRED, 'e2ea/ret@manual-foreign'):
        check(name in pruned, f'prune kept protected {name}')
    for name in ('e2ea/ret@zsnap_2020-01-03-000000', 'e2ea/ret@zsnap_2020-01-04-000000'):
        check(name not in pruned, f'prune removed eligible {name}')
    check.equal(snapmap('map-child-after'), snapmap('map-child-before'), 'parent prune leaves child history')
    check.equal(len(owned(pruned, 'e2ea/ret')), 3, 'newest owned + held + deferred remain')
    check(owned(after_run, 'e2ea/ret')[-1] in pruned, 'the newest owned snapshot is the one kept')
    protected = s.observe('protected')
    check.equal(named(s.step('inventory').json['result']['inventory'], 'snapshots', DEFERRED)['defer_destroy'], True,
                'status shows the deferred destroy')
    check.equal(protected.properties(DEFERRED)['defer_destroy']['value'], 'on', 'native defer_destroy kept')
    for name in (HELD, DEFERRED):
        check((name, READER) in protected.holds, f'{name} keeps the foreign hold')

    pending = s.step('prune-pending')
    check(pending.rc != 0, f'prune refused while an unknown zboot:pending is set: rc={pending.rc}')
    check.contains(pending.err, 'pending dataset requires supported management evidence', 'pending refusal names the pending operation')
    check.equal(snapmap('map-after-pending'), pruned, 'pending refusal changed no history')
    readonly = s.step('prune-readonly')
    check(readonly.rc != 0, f'prune refused on a readonly scope: rc={readonly.rc}')
    check.contains(readonly.err, 'e2ea/ret is read-only', 'readonly refusal names the readonly scope')
    check.equal(snapmap('map-after-readonly'), pruned, 'readonly refusal changed no history')

    collision_before = snapmap('map-collision-before')
    check.equal(len(collision_before), 24, '24 occupied second-names')
    collision = s.step('collision')
    check(collision.rc != 0, f'zsnap snap refused on name collision: rc={collision.rc}')
    check.contains(collision.err, 'snapshot name already exists', 'collision refusal message')
    check.equal(snapmap('map-collision-after'), collision_before, 'collision changed no snapshot')
    check.equal(s.step('final-policy').out.strip(), '-', 'child unassigned after root unassign')
