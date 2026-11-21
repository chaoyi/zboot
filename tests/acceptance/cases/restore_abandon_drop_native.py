"""Abandon keeps the only copy held and marked; drop releases and destroys it."""
import hashlib
import json

from host.identity import identity

from host.case import Boot
from host import lifecycle, restore as r

ID = 'RESTORE-ABANDON-DROP-NATIVE'
GROUP = 'restore'
SECONDS = 3600
DISKS = {'A': 4, 'B': 4, 'D': 8}
BOOTS = [Boot(1, cut='restore-cut'), Boot(2)]
BE = 'e2eb/ROOT/be1'


def under(name, root):
    return name == root or name.startswith(root + '/') or name.startswith(root + '@')


def tagged(observation, root, tag):
    return {s for s, t in observation.holds if t == tag and under(s, root)}


def verdict(ev, check):
    first, second = ev.stage(1), ev.stage(2)
    r.base(first, check)
    r.placed(first, check, 'source')
    r.previewed(first.step('restore-preview'), check, 'restore --dry-run')
    r.loader(first, check)
    op = r.cut(first, check, 9)
    staging, tag = f'e2eb/zboot-restore-{op}', f'zboot:restore:{op}'

    r.hostid(second, check, 2)
    r.resumed_record(second, check, op, 8)
    before = second.observe('before')
    deferred = f'{BE}@src'
    check.equal(second.step('defer-source').rc, 0, 'deferred source destroy request succeeded')
    check.equal(before.properties(deferred)['defer_destroy']['value'], 'on',
                'source snapshot is natively deferred')
    check.equal(tagged(before, BE, tag), {deferred, f'{BE}/var@src'},
                'both source snapshots carry their original restore holds')
    check.equal({t for s, t in before.holds if s == deferred}, {tag},
                'the restore hold alone protects the deferred source snapshot')
    check.equal(second.step('deferred-source-clones').rc, 0,
                'deferred source clone inventory succeeds')
    check.equal(second.step('deferred-source-clones').out.strip().split('\t'), [deferred, '-'],
                'native snapshot inventory proves no clone protects the deferred source snapshot')
    staged = {n for n in before.datasets if under(n, staging) and '@' in n}
    check(staged, f'{staging} has staged snapshots')
    token = r.reviewed(second, check, 'abandon')
    preview = r.envelope(second.step('abandon-preview')).get('result') or {}
    check.equal(preview.get('releases'), False, 'abandon preview keeps the only copy held')
    done = r.applied(second.step('abandon-apply'), check, token, 'abandon --confirm')
    check.equal(done.get('released'), False, 'abandon retained restore holds')
    check(any('only complete copy' in str(left) for left in done.get('left') or []),
          f'abandon names the only complete copy: {done.get("left")}')
    check(any(deferred in str(left) and tag in str(left) and 'deferred' in str(left)
              for left in done.get('left') or []),
          'abandon reports the retained deferred snapshot and its exact hold tag')
    check.equal(r.record(second.step('abandoned-record')), None, 'abandon removed the record')
    check.equal(second.step('staging-mark').out.strip(), op, 'staging keeps zboot:staging')
    record = r.record(second.step('record'))
    named = record['state']['receipt']
    endpoint = {'name': staging, 'identity': identity(before, staging)}
    check.equal(named['endpoint'], endpoint, 'the record names its receipt on the native staging incarnation')
    prefix = f'zboot:attachment:{op}:receipt:'
    chunked = ('zboot:attachment:', 'zboot:journal:')
    original = {key: value for key, value in before.properties(staging).items() if key.startswith(prefix)}
    check.equal(sorted(original), [f'{prefix}{i:04x}' for i in range(named['chunks'])],
                'staging holds exactly the receipt chunks its record names')
    check.equal({value['source'] for value in original.values()}, {'local'},
                'every receipt chunk belongs locally to staging')
    original_bytes = bytes.fromhex(''.join(original[f'{prefix}{i:04x}']['value'] for i in range(named['chunks'])))
    check.equal(hashlib.sha256(original_bytes).hexdigest(), named['sha256'],
                'original receipt chunks match the digest their record names')
    abandoned = second.observe('abandoned')
    receipt_rows = [line.split('\t') for line in second.step('abandoned-receipt').out.splitlines()
                    if line.split('\t')[1].startswith(chunked)]
    check.equal(receipt_rows, [], 'abandon removed every receipt chunk, and no attachment or journal property is left')
    check.equal(lifecycle.chunked(abandoned), [],
                'abandon leaves no attachment or journal property on any dataset; only the archive stays')
    archive_prefix = f'org.zfs-tools:restore-placement:{op}:'
    manifest = archive_prefix + 'manifest'
    retained = {key: value for key, value in abandoned.properties(staging).items()
                if key.startswith('org.zfs-tools:restore-placement:')}
    expected_chunks = {archive_prefix + key[len(prefix):]: value for key, value in original.items()}
    check.equal({key: value for key, value in retained.items() if key != manifest}, expected_chunks,
                'only-copy abandon retains every original receipt chunk byte for byte with LOCAL provenance')
    check.equal(retained.get(manifest, {}).get('source'), 'local', 'the archive manifest is local to staging')
    check.equal(json.loads(retained[manifest]['value']), named,
                'the archive manifest is exactly the record\'s name for the receipt')
    retained_bytes = bytes.fromhex(''.join(retained[f'{archive_prefix}{i:04x}']['value']
                                         for i in range(named['chunks'])))
    check.equal(retained_bytes, original_bytes, 'full source/kept placement and managed metadata survives intent removal')
    check.equal(hashlib.sha256(retained_bytes).hexdigest(), named['sha256'],
                'retained metadata independently verifies after the operation ended')
    retained_receipt = json.loads(retained_bytes)
    check.equal(retained_receipt['restore_id'], op, 'retained placement belongs to this ended restore')
    check.equal(retained_receipt['source_tree']['observed']['name'], BE, 'retained placement covers the source BE')
    check.equal(retained_bytes, json.dumps(retained_receipt, sort_keys=True, separators=(',', ':')).encode(),
                'retained metadata has the canonical receipt encoding')
    check.equal(second.step('abandoned-placement-manifest').out.strip().split('\t'),
                [staging, manifest, retained[manifest]['value'], 'local'],
                'retained placement has a directly readable native manifest')
    for name, row in abandoned.datasets.items():
        if not under(name, staging):
            continue
        check.equal(row, before.datasets[name], f'{name}: abandon preserves native identity')
        inherited_archive = {key: value for key, value in abandoned.properties(name).items()
                             if key.startswith(archive_prefix)}
        expected_member_archive = retained if name == staging else {
            key: {'value': value['value'], 'source': 'inherited from ' + staging}
            for key, value in retained.items()}
        check.equal(inherited_archive, expected_member_archive,
                    f'{name}: exact retained metadata remains ordinary local/inherited data')
        if row['type'] != 'filesystem':
            continue
        props = abandoned.properties(name)
        roles = ('mountpoint', 'readonly', 'canmount', 'volmode')
        check.equal({key: props[key]['value'] for key in roles},
                    dict(zip(roles, ('none', 'on', 'off', 'none'))),
                    f'{name}: held staging keeps effective inert placement')
        check.equal({key: props[key]['source'] for key in roles}, dict.fromkeys(roles, 'local'),
                    f'{name}: completed native receivers keep LOCAL inert authority')
        check.equal({key: props[key] for key in roles},
                    {key: before.properties(name)[key] for key in roles},
                    f'{name}: abandon preserves exact inert value and provenance')
        check.equal(props['mounted']['value'], 'no', f'{name}: staging stays unmounted')
        check(name not in abandoned.mounts.values(), f'{name}: no live inspection mount remains')
        check.equal([key for key in props if key.startswith(chunked)], [],
                    f'{name}: no local or inherited receipt chunks remain')
    kept_label = f'abandoned-kept-{r.slug(staging + "/scratch")}'
    check.equal(second.step(kept_label + '-token').out, r.TOKENS['e2ea/scratch'],
                'only kept copy retains its original payload before reviewed drop')
    check.equal(second.payload(kept_label), {'./restore-token': r.sha(r.TOKENS['e2ea/scratch'])},
                'read-only staged payload hashes match the original kept tree')
    check.equal(tagged(abandoned, BE, tag), {deferred},
                'abandon keeps the deferred snapshot and releases the ordinary source hold')
    check.equal(abandoned.datasets.get(deferred), before.datasets[deferred],
                'abandon preserves the deferred source snapshot identity')
    check.equal(tagged(abandoned, staging, tag), staged, 'every staged snapshot still carries the restore hold')
    token = r.reviewed(second, check, 'drop')
    plan = r.envelope(second.step('drop-preview')).get('result')
    check(tag in json.dumps(plan), f'drop plan lists the holds it releases: {plan}')
    r.applied(second.step('drop-apply'), check, token, 'drop --confirm')
    check(second.step('dropped').rc != 0, f'{staging} still listed after drop')
    dropped = second.observe('dropped')
    check(not [n for n in dropped.datasets if under(n, staging)], f'{staging} gone natively after drop')
    check.equal(lifecycle.chunked(dropped), [], 'no attachment or journal property is left after drop')
    check.equal({s for s, t in dropped.holds if t == tag}, {deferred},
                'Drop releases staging holds and leaves the separate deferred source hold')
    check(BE in dropped.datasets and f'{BE}@src' in dropped.datasets, 'the source BE survives the drop')
    check.equal(dropped.datasets.get(f'{BE}@src'), before.datasets.get(f'{BE}@src'), 'source snapshot identity')
    check.contains(second.step('scrub-b').out, 'errors: No known data errors', 'B scrub after the cut')
