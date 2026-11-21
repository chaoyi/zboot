"""zboot pair/unpair on leaves: refusals, publication, repeat, unpair, re-pair, anchor release."""
from host.case import Boot
from host.lifecycle import (consent, envelope, holds, no_operation, pair, placement, preserved, prop, refused,
                            snapshots, source, unchanged)

ID = 'PAIR-UNPAIR-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
L, R = 'e2eb/pairleaf', 'e2ea/receiver'


def refusal(check, s, step, before, after, needle, what):
    refused(check, s.step(step), needle, what)
    after = s.observe(after)
    unchanged(check, s.observe(before), after, what)
    no_operation(check, after, what)


def verdict(ev, check):
    s = ev.stage(1)
    equal = envelope(check, s.step('preview-left'), 'preview', 'equal pair preview with ordered primary')
    check.equal(equal['result']['primary'], 'left', 'equal pair keeps the first operand primary')
    default = envelope(check, s.step('preview-default'), 'preview', 'equal pair preview')
    check.equal(default['result']['primary'], 'left', 'equal histories default to the first endpoint')
    pruned = envelope(check, s.step('preview-pruned'), 'preview', 'pair with a copy missing an older snapshot')
    check.equal([(a['name'], b['name']) for a, b in pruned['result']['anchors']],
                [(L + '@common', 'e2ea/pruned@common')], 'the newest common snapshot anchors the pruned copy')

    refusal(check, s, 'unrelated-pair', 'unrelated-before', 'unrelated-after',
            'no shared retained history', 'pair without a shared snapshot')
    check.equal(s.observe('clone-before').properties('e2ea/clone')['origin']['value'], 'e2ea/plain@first',
                'clone fixture is a clone of the other endpoint')
    refusal(check, s, 'clone-pair', 'clone-before', 'clone-after',
            'is itself a clone', 'pair with a clone of the other endpoint')
    refusal(check, s, 'child-pair', 'child-before', 'child-after',
            f'a pair joins leaf datasets, but {L} or {R} has child datasets (child)', 'pair with a child')
    refusal(check, s, 'right-pair', 'right-before', 'right-after',
            'initial pair primary must be the containing/ahead copy', 'pair with the ahead source as the second operand')
    ahead = envelope(check, s.step('preview-ahead'), 'preview', 'ahead pair preview')['result']
    check.equal(ahead['primary'], 'left', 'ahead source selected as primary')
    check.equal(len(ahead['anchors']), 1, 'one leaf, one common anchor')

    applied = envelope(check, s.step('pair'), 'applied', 'pair')['result']
    pid = applied['operation_id']
    check(isinstance(pid, str), f'pair reports its operation id: {pid!r}')
    before, paired = s.observe('before'), s.observe('paired')
    no_operation(check, paired, 'after pair')
    left, right = pair(paired, L), pair(paired, R)
    check.equal((left['pair_id'], right['pair_id']), (pid, pid), 'both endpoints carry the pair id')
    check.equal((left['role'], right['role']), ('primary', 'secondary'), 'pair roles')
    check.equal(left['endpoint'], right['peer'], 'left endpoint is the right peer')
    check.equal(right['endpoint'], left['peer'], 'right endpoint is the left peer')
    preserved(check, before, paired, 'pair publication')
    check.equal([prop(paired, R, k) for k in ('readonly', 'mounted', 'canmount', 'keystatus')],
                ['on', 'no', 'noauto', 'unavailable'], f'{R} fenced and locked')
    for key in ('readonly', 'canmount'):
        check.equal(source(paired, R, key), 'local', f'{R} {key} fence is local')
    tag = f'zboot:anchor:{pid}'
    for snap in (L + '@common', R + '@common'):
        check(tag in holds(paired, snap), f'{snap} holds {tag}: {holds(paired, snap)}')

    repeat = envelope(check, s.step('repeat'), 'applied', 'repeated pair')['result']
    check.equal((repeat['operation_id'], repeat['already_paired'], repeat['primary']), (pid, True, 'left'),
                'repeated pair is idempotent')

    unpaired_result = envelope(check, s.step('unpair'), 'applied', 'unpair')['result']
    check(isinstance(unpaired_result['operation_id'], str), 'unpair reports its operation id')
    check.equal(unpaired_result['retained_anchor_tag'], tag, 'unpair keeps the anchor tag')
    check.equal(unpaired_result['released'], [], 'plain unpair releases nothing')
    unpaired = s.observe('unpaired')
    no_operation(check, unpaired, 'after unpair')
    preserved(check, paired, unpaired, 'unpair')
    for name in paired.datasets:
        if paired.datasets[name]['type'] != 'snapshot':
            check.equal(placement(unpaired, name), placement(paired, name), f'unpair keeps placement of {name}')
    check.equal(unpaired.holds, paired.holds, 'unpair keeps every hold')
    check.equal(prop(unpaired, L, 'zboot:pair'), '-', 'no pair pointer left on the left endpoint')
    check.equal(prop(unpaired, R, 'zboot:pair'), '-', 'no pair pointer left on the right endpoint')
    refusal(check, s, 'unpair-again', 'unpaired', 'unpaired-again',
            f'{L} is not paired; nothing to unpair', 'second unpair')

    repair = envelope(check, s.step('repair'), 'applied', 're-pair')['result']
    check.equal(repair['already_paired'], False, 're-pair is a fresh pair')
    check(repair['operation_id'] != pid, 're-pair has a new pair id')

    preview, applied = consent(check, s, 'release', 'unpair --release-anchors')
    check(len(preview['result']['release']) >= 2, f"release reviews both sides' anchors: {preview['result']['release']}")
    check(all(p['state'] == 'released' for p in applied['result']['released']),
          f"every anchor released: {applied['result']['released']}")
    released = s.observe('released')
    for snap in snapshots(released):
        if snap.startswith((L + '@', R + '@')):
            check(not any(t.startswith('zboot:anchor:') for t in holds(released, snap)),
                  f'{snap} keeps no zboot anchor: {holds(released, snap)}')
    no_operation(check, released, 'after anchor release')
