"""CAPTURE-READER: INV-01, shared recursive capture, supervised readers, IV sets and written@."""
from cases import inv_01_native as INV01

from host.case import Boot
from host.identity import identity, prop, unchanged

ID = 'CAPTURE-READER-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
CAPTURED = ('e2ea/renamed@captured', 'e2ea/renamed/child@captured')


def snapshots(obs):
    return {n: identity(obs, n) for n in obs.datasets if '@' in n}


def tags(obs, name):
    return {t for n, t in obs.holds if n == name}


def u64(text):
    return text.isdigit() and int(text) < 1 << 64


def verdict(ev, check):
    s = ev.stage(1)
    INV01.inventory_part(s, check)
    renamed, captured = s.observe('after'), s.observe('captured')

    # Shared recursive capture.
    envelope = s.step('capture').json
    check.equal((envelope['schema_version'], envelope['mode']), (1, 'applied'), 'capture envelope')
    check('operation' not in envelope, 'capture marker is not a resumable operation')
    check.equal(len(envelope['result']), 1, 'one requested capture label group')
    capture = envelope['result'][0]
    check.equal(capture['status'], 'complete', 'capture complete')
    check.equal(len(capture['points']), 2, 'capture points are parent and child')
    check.equal(len(snapshots(captured)), len(snapshots(renamed)) + 2, 'capture added exactly two snapshots')
    check.equal({n: i for n, i in snapshots(captured).items() if n not in CAPTURED}, snapshots(renamed),
                'capture changed no other snapshot')
    for name in CAPTURED:
        check(name in captured.datasets, f'{name} exists natively')
    check.equal(captured.datasets[CAPTURED[0]]['createtxg'], captured.datasets[CAPTURED[1]]['createtxg'],
                'parent and child captured in one transaction group')
    markers = dict(line.split('\t') for line in s.step('markers').out.splitlines())
    for name in CAPTURED:
        check.equal(markers.get(name), capture['operation_id'], f'{name} zboot:capture names this capture')
    collision = s.step('collision')
    check(collision.rc != 0, f'repeat capture name refused: rc={collision.rc}')
    check.contains(collision.err, 'capture name already exists', 'collision refusal message')
    unchanged(check, captured, s.observe('after-collision'), 'collision refusal')
    readonly = s.step('readonly')
    check(readonly.rc != 0, f'capture with a readonly child refused: rc={readonly.rc}')
    check.contains(readonly.err, 'e2ea/renamed/child', 'readonly refusal names the readonly child')
    unchanged(check, s.observe('readonly-before'), s.observe('readonly-after'), 'readonly-child refusal')
    check('e2ea/renamed@forbidden' not in s.observe('readonly-after').datasets, 'no @forbidden created')

    # Complete task results are separate from reader stdout and native evidence.
    def result(label):
        value = s.step(label + '-result').json
        check.equal(value['schema_version'], 1, f'{label}: task result schema')
        check.equal(value['status'], 'complete', f'{label}: task disposition')
        check.equal(value['cleanup_complete'], True, f'{label}: cleanup completeness')
        check.equal(value['child_exit'], 0, f'{label}: supervised reader exited normally')
        manifest = s.step(label + '-manifest').json
        check.equal(manifest['job'], value['job'], f'{label}: manifest names this job')
        check.equal(manifest['schema_version'], 1, f'{label}: manifest schema')
        return value

    completed = result('protect-capture')
    protection = completed['protection']
    tag = protection['receipt']['tag']
    check.equal(len(protection['receipt']['points']), 2, 'task receipt protects both capture points')
    manifest = s.step('protect-capture-manifest').json
    check.equal({p['snapshot']['name'] for p in manifest['sources']}, set(CAPTURED),
                'reader manifest names exactly both captured snapshots')
    check.equal({p['alias'] for p in manifest['sources']}, {'root', 'child'}, 'disjoint task view aliases')
    pinned, ended = s.observe('pinned'), s.observe('after-reader')
    for part, name in zip(('root', 'child'), CAPTURED):
        refused = s.step(f'destroy-{part}')
        check(refused.rc != 0, f'zfs destroy {name} refused during the reader: rc={refused.rc}')
        check.contains(refused.err, "it's being held", f'{name} destroy refused because it is held')
        check(name in pinned.datasets, f'{name} survived the refused destroy')
        check(tag in tags(pinned, name), f'{name} keeps the task hold {tag}')
        check(name in ended.datasets, f'{name} remains after default task cleanup')
        check(tag not in tags(ended, name), f'{name} task hold released after reader exit')
        check.equal(s.step(f'destroy-released-{part}').rc, 0, f'released {part} snapshot destroyable')
    points = protection['report']['points']
    check.equal(len(points), 2, 'cleanup reports both points')
    for point in points:
        check.equal((point['released'], point['exists_after']), (True, True),
                    f'cleanup released its hold and kept {point["point"]["name"]}')

    # A complete task's recovery policy survives an interrupted owner. Native
    # defer injection follows authenticated orphan stop because OpenZFS refuses
    # defer-destroy while these exact snapshot views are still mounted.
    def stopped(label, point, pinned_name, stopped_name):
        check.equal(s.step(label).rc, 137, f'{label}: exact supervisor died by the recorded SIGKILL')
        preview = s.step(label + '-stop-preview').json
        check.equal(preview['status'], 'readers_active', f'{label}: recovery finds the supervised orphan')
        check.equal(preview['requires_stop'], True, f'{label}: recovery requires authenticated stop')
        check.equal(s.step(label + '-stop').json['status'], 'stopped_review_required',
                    f'{label}: stop drains owned subtree and requires a new release review')
        held_before, held_after = s.observe(pinned_name), s.observe(stopped_name)
        check(tags(held_before, point), f'{label}: task hold exists during reader')
        check.equal(tags(held_after, point), tags(held_before, point), f'{label}: orphan stop retains the exact hold')
        check.equal(prop(held_after, point, 'defer_destroy'), 'off', f'{label}: stop preserves the snapshot before deferred injection')

    preserve_name = 'e2ea/renamed@preserve-deferred'
    stopped('protect-preserve', preserve_name, 'preserve-pinned', 'preserve-stopped')
    before_preserve = s.observe('preserve-deferred')
    check.equal(prop(before_preserve, preserve_name, 'defer_destroy'), 'on', 'default recovery sees deferred destroy')
    check.equal(s.step('recover-preserve').json['review']['release'], 'preserve_snapshots',
                'authenticated recovery preserves the original task disposition')
    retained = s.step('recover-preserve-apply').json
    check.equal(retained['status'], 'retained', 'reviewed default recovery cannot release deferred protection')
    check.equal(retained['protection']['kind'], 'preservation_refused', 'default recovery refuses because preservation would be lost')
    unchanged(check, before_preserve, s.observe('after-preserve-recovery'), 'default recovery refuses deferred release')

    stopped('protect-deferred', 'e2ea/renamed@first', 'deferred-pinned', 'deferred-stopped')
    check.equal(s.step('recover-deferred').json['review']['release'], 'end_protection',
                'authenticated recovery preserves the original explicit EndProtection decision')
    deferred = s.observe('deferred')
    check('e2ea/renamed@first' in deferred.datasets, 'held @first survives native destroy -d after view teardown')
    check.equal(prop(deferred, 'e2ea/renamed@first', 'defer_destroy'), 'on', 'native defer_destroy on')
    completed_deferred = s.step('recover-deferred-apply').json
    check.equal(completed_deferred['status'], 'complete', 'explicit recovery completes')
    release = completed_deferred['protection']
    point = release['report']['points'][0]
    check.equal(point['released'], True, 'explicit recovery released the hold')
    check.equal(point['exists_after'], False, 'deferred snapshot gone after reader/view teardown')
    check.equal(point['possible_deferred_destroy'], True, 'recovery reports possible deferred destroy')
    check('e2ea/renamed@first' not in s.observe('after-deferred').datasets, '@first gone natively')
    foreign = result('protect-foreign')
    foreign_tag = foreign['protection']['receipt']['tag']
    check(foreign_tag in tags(s.observe('foreign-pinned'), 'e2ea/renamed@second'), 'foreign-held snapshot also gets the task hold')
    held = tags(s.observe('after-foreign'), 'e2ea/renamed@second')
    check.equal(held, {'foreign-reader'}, 'cleanup releases only its own hold')
    check(foreign_tag not in held, 'task hold released from foreign-held snapshot')
    refused = s.step('destroy-foreign')
    check(refused.rc != 0, 'foreign hold still prevents destruction after task cleanup')
    check.contains(refused.err, "it's being held", 'foreign hold causes the destroy refusal')
    check.equal(s.step('destroy-foreign-released').rc, 0, 'native foreign release makes the snapshot destroyable')

    # IV sets (LIBRARY-ONLY observer ported to the native property).
    iv = s.step('ivset').out.strip()
    check(u64(iv), f'encrypted snapshot IV-set guid is a u64 decimal: {iv!r}')
    check(iv != '0', 'encrypted snapshot IV-set guid is non-zero')
    check('ivsetguid' not in s.step('all-properties').out.split(), 'ivsetguid stays hidden from get all')
    check.equal(s.step('ivset-plain').out.strip(), '-', 'unencrypted snapshot has no IV set')

    # written@ semantics (LIBRARY-ONLY observer ported to native written@).
    absent = s.step('absent-latest')
    check(absent.rc != 0 or not u64(absent.out.strip()),
          f'written@latest without @latest is not a number: rc={absent.rc} {absent.out!r}')
    for c in ('delete', 'truncate', 'xattr', 'metadata'):
        check.equal(s.step(f'{c}-fresh').out.strip(), '0', f'{c}: fresh @{c}_base wrote nothing')
        value = s.step(f'{c}-written').out.strip()
        check(u64(value), f'{c}: native written@{c}_base parses as u64: {value!r}')
    check.equal(s.step('metadata-read').out.strip(), '640', 'chmod observed')
    check.equal(s.step('xattr-read').out, 'changed', 'xattr observed')
    check.equal(s.step('latest-written').out.strip(), '0', 'a real @latest resolves as an exact base')
