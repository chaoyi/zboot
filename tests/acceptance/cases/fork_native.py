"""FORK: clean BE clone, BE-only refusals, and native after-clone power-cut recovery."""
import json
from host.case import Boot
from host.identity import identity, prop, unchanged
from host.lifecycle import chunked

ID = 'FORK-NATIVE'
GROUP = 'small'
SECONDS = 1500
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1), Boot(2, cut='fork-clone-cut'), Boot(3)]
SOURCE, POINT = 'e2ea/BE/source', 'e2ea/BE/source@point'


def verdict(ev, check):
    s = ev.stage(1)
    before, after = s.observe('before'), s.observe('after')
    fork = s.step('fork').json
    check.equal(fork['schema_version'], 1, 'fork envelope schema')
    check.equal(fork['mode'], 'applied', 'fork runs directly')
    check.equal(fork['result']['complete'], True, 'fork complete')
    check.equal(fork['result']['source_snapshot'], POINT, 'fork reports the full source snapshot')
    clone = 'e2ea/BE/fork'
    check.equal(identity(after, SOURCE), identity(before, SOURCE), f'{SOURCE} identity unchanged')
    check.equal(identity(after, POINT), identity(before, POINT), f'{POINT} identity unchanged')
    check(clone in after.datasets and clone not in before.datasets, f'{clone} newly exists')
    check.equal([name for name in after.datasets if name.startswith(clone + '/')], [],
                f'{clone} is one dataset with no children')
    check.equal(prop(after, clone, 'readonly'), 'off', f'{clone} writable')
    check.equal(prop(after, clone, 'canmount'), 'noauto', f'{clone} canmount noauto')
    check.equal(prop(after, clone, 'mounted'), 'no', f'{clone} not mounted')
    check.equal(prop(after, clone, 'origin'), POINT, f'{clone} exact native origin')
    check(clone in prop(after, POINT, 'clones').split(','), f'{POINT} lists {clone} in native clones')
    check.equal(s.step('check-root').out, 'fork root content', f'{clone} content')
    check(('e2ea/BE/source@point', 'e2e:foreign') in after.holds, 'foreign hold kept')
    check.equal(s.step('root-placement').out, '/\n', 'fork retains native boot-root shape')
    check.equal(prop(after, clone, 'mountpoint'), '/', 'native root mountpoint on the fork')
    check.equal(s.step('operation').out.strip(), '-', 'no zboot:operation record on e2ea')
    replay = s.step('replay')
    check(replay.rc != 0, f'replayed fork refused: rc={replay.rc}')
    check.contains(replay.err, 'e2ea/BE/fork', 'replay refusal names the existing destination')
    replayed = s.observe('after-replay')
    check.equal(identity(replayed, clone), identity(after, clone), f'{clone} identity unchanged by replay')
    check.equal(prop(replayed, clone, 'origin'), prop(after, clone, 'origin'), f'{clone} origin unchanged by replay')
    unchanged(check, after, replayed, 'replay refusal')
    for name, needle in (
            ('fork-children', 'boot environment e2ea/BE/parent has child datasets (e2ea/BE/parent/var)'),
            ('fork-data-tree', 'e2ea/plain is not a boot environment')):
        refused = s.step(name)
        check(refused.rc != 0, f'{name} refused: rc={refused.rc}')
        check.contains(refused.err, needle, f'{name} refusal names the rule')
    unchanged(check, s.observe('before-refusals'), s.observe('after-refusals'), 'BE-only refusals')

    interrupted, resumed = ev.stage(2), ev.stage(3)
    before_cut, cut = interrupted.observe('before-cut'), resumed.observe('after-cut')
    record = json.loads(resumed.step('cut-operation').out)
    check.equal(record['kind'], 'fork', 'cut keeps a fork intent')
    check.equal(record['step'], 1, 'cut occurs before clone/publication checkpoint')
    state = record['state']
    check.equal(state['destination'], 'e2ea/BE/recovered', 'cut freezes final destination')
    check.equal(state['point']['name'], POINT, 'the record binds the boundary snapshot')
    check.equal(state['point']['identity'], identity(before_cut, POINT),
                'the record binds the boundary snapshot native identity')
    check.equal(state['canmount'], 'noauto', 'the record freezes the reviewed role')
    check.equal(state['volmode'], prop(before_cut, SOURCE, 'volmode'), 'the record freezes the reviewed volmode')
    workspace = state['workspace']
    owner = workspace['owner']
    prep = workspace['name']
    staged = f'{prep}/copy'
    check(prep.startswith('e2ea/zboot-fork-'), 'preparation is a pool-root sibling')
    check.equal(identity(cut, prep), owner['identity'], 'inert container keeps its bound native identity')
    cut_argv = interrupted.cut('fork-clone-cut')
    check.equal(cut_argv[0], 'clone', 'fault hook records a native clone call')
    check.equal(cut_argv[-2:], [POINT, staged], 'real native clone returned before the power cut')
    check('e2ea/BE/recovered' not in cut.datasets, 'final name remains unpublished after cut')
    check(not any(k.startswith(('zboot:journal:', 'zboot:attachment:')) for k in cut.properties(prep)),
          'no separate placement receipt: the operation record carries it')
    for name in (prep, staged):
        for key, value in (('mountpoint', 'none'), ('readonly', 'on'), ('volmode', 'none')):
            check.equal(prop(cut, name, key), value, f'{name} survives inert: {key}')
            check.equal(cut.properties(name)[key]['source'], 'local', f'{name} local {key} fence')
        check.equal(prop(cut, name, 'mounted'), 'no', f'{name} unmounted before recovery')
    check.equal({name for name in cut.datasets if name == prep or name.startswith(prep + '/')},
                {prep, staged}, 'only the exact owned clone survives in preparation')
    check((POINT, f"zboot:fork:{record['id']}") in cut.holds, f'{POINT} remains held through the cut')
    recovered = resumed.observe('recovered')
    check.equal(chunked(recovered), [], 'recovery leaves no attachment or journal property')
    final = 'e2ea/BE/recovered'
    check.equal(prop(cut, staged, 'origin'), POINT, f'{staged} exact native origin')
    check.equal(prop(cut, staged, 'canmount'), 'noauto', f'{staged} role applied before cut')
    check.equal(identity(recovered, final), identity(cut, staged), f'{final} publishes the same native clone')
    check.equal(prop(recovered, final, 'origin'), POINT, f'{final} origin survives recovery')
    for key, value in (('canmount', 'noauto'), ('readonly', 'off'), ('mounted', 'no')):
        check.equal(prop(recovered, final, key), value, f'{final} recovered {key}')
    check.equal(prop(recovered, final, 'mountpoint'), prop(before_cut, SOURCE, 'mountpoint'),
                f'{final} restores original placement')
    check.equal(prop(recovered, final, 'mountpoint'), '/', 'recovered fork keeps root shape')
    for key in ('zboot:pending', 'zboot:staging'):
        check.equal(recovered.properties(final).get(key, {}).get('value', '-'), '-', f'{final} retires {key}')
    check.equal(identity(recovered, SOURCE), identity(before_cut, SOURCE), f'{SOURCE} identity unchanged by recovery')
    check.equal(identity(recovered, POINT), identity(before_cut, POINT), f'{POINT} identity unchanged by recovery')
    check.equal(resumed.step('recovered-root').out, 'fork root content', f'{final} recovered content')
    check(prep not in recovered.datasets, 'empty bound preparation retired after publication')
    outcome = resumed.step('resume').json['result']['complete']
    check.equal(outcome['complete'], True, 'resume completes')
    check.equal(resumed.step('recovered-operation').out.strip(), '-', 'recovery retires the operation')
    check.equal(recovered.holds, {(POINT, 'e2e:foreign')},
                'recovery releases only fork holds, preserving the foreign hold')
