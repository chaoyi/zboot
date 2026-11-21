"""A locked leaf whose encryption root is outside it becomes its own root on the copy."""
import json
import re
from host.case import Boot
from host.lifecycle import envelope, identity, pair, prop, source as property_source

ID = 'TRANSFER-EXTERNAL-ER-NATIVE'
GROUP = 'small'
SECONDS = 600
DISKS = {'A': 2, 'B': 2}
BOOTS = [Boot(1)]
SRC, DST, EXTERNAL = 'e2eext-src/secret/subtree', 'e2eext-dst/copy', 'e2eext-src/secret'


def ivsets(step, root, check):
    check.equal(step.rc, 0, f'{root}: native IV-set query succeeds')
    result = {}
    for line in step.out.splitlines():
        fields = line.split('\t')
        if check.equal(len(fields), 2, 'native IV-set columns'):
            name, value = fields
            check(name.startswith(root + '@'), 'IV snapshot belongs to the leaf')
            relative = name[len(root):]
            check(relative not in result, 'each IV snapshot is observed exactly once')
            check(value.isdigit() and value != '0', 'encrypted snapshot has a nonzero decimal IV-set GUID')
            result[relative] = value
    return result


def snapshots(observation, root):
    return {name[len(root):]: facts['guid'] for name, facts in observation.datasets.items()
            if facts['type'] == 'snapshot' and name.startswith(root + '@')}


def verdict(ev, check):
    s = ev.stage(1)
    before, copied, final = s.observe('before'), s.observe('copied'), s.observe('final')
    result = envelope(check, s.step('sync'), 'applied', 'locked external-root leaf bootstrap')['result']
    pair_id = result.get('bootstrapped')
    check(isinstance(pair_id, str) and re.fullmatch(
        r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', pair_id) is not None,
        'product reports a canonical UUIDv4 for the bootstrapped pair')
    check.equal(result.get('pair_id'), pair_id, 'transfer result names that exact bootstrapped pair')
    check('unmirrored' not in result, 'a leaf has no unmirrored children')
    for what, observation in (('copied', copied), ('final', final)):
        endpoints = {name: {'name': name, 'identity': dict(zip(
            ('pool_guid', 'guid', 'createtxg', 'objsetid'), identity(observation, name)))}
            for name in (SRC, DST)}
        for name, peer, role in ((SRC, DST, 'primary'), (DST, SRC, 'secondary')):
            record = pair(observation, name)
            check.equal(property_source(observation, name, 'zboot:pair'), 'local',
                        f'{what}: pair authority is local on {name}')
            check.equal(record.get('schema_version'), 1, f'{what}: native pair schema is supported')
            check.equal(record.get('pair_id'), pair_id, f'{what}: native pair UUID matches product result on {name}')
            check.equal(record.get('role'), role, f'{what}: native pair role is {role} on {name}')
            check.equal(record.get('endpoint'), endpoints[name], f'{what}: pair owner binds exact native {name}')
            check.equal(record.get('peer'), endpoints[peer], f'{what}: pair peer binds exact native {peer}')
    # A read-only source is sent as it is: no fresh boundary is captured.
    original = snapshots(before, SRC)
    check.equal(set(original), {'@first', '@second'}, 'the read-only leaf has exactly its two snapshots')
    check.equal(snapshots(copied, SRC), original, 'a read-only source gets no fresh capture')
    check.equal(snapshots(copied, DST), original, 'copied snapshots retain the exact source GUIDs')
    check.equal(snapshots(final, DST), original, 'payload verification preserves every copied snapshot GUID')
    check.equal(prop(before, SRC, 'encryptionroot'), EXTERNAL,
                f'{SRC} begins with an encryption root outside the pair')
    check.equal(prop(before, SRC, 'keystatus'), 'unavailable', f'{SRC} is locked before the raw sync')
    check.equal(identity(copied, SRC), identity(before, SRC), f'{SRC} native incarnation stays unchanged')
    check.equal(identity(final, DST), identity(copied, DST), f'{DST} native incarnation survives verification')
    check(copied.datasets.get(DST, {}).get('guid') != before.datasets.get(SRC, {}).get('guid'),
          f'{DST} is a newly received native dataset')
    for what, observation in (('copied', copied), ('final', final)):
        check.equal(prop(observation, DST, 'encryption'), 'aes-256-gcm', f'{what}: {DST} keeps its cipher')
        check.equal(prop(observation, DST, 'encryptionroot'), DST, f'{what}: {DST} is its own encryption root')
        check.equal((prop(observation, DST, 'keylocation'), property_source(observation, DST, 'keylocation')),
                    ('prompt', 'local'), f"{what}: {DST} takes the source root's key location locally")
        check.equal(prop(observation, DST, 'keystatus'), 'unavailable', f'{what}: {DST} remains locked')
        check.equal(prop(observation, DST, 'mounted'), 'no', f'{what}: {DST} stays unmounted')
        for key, value in (('readonly', 'on'), ('canmount', 'noauto')):
            check.equal((prop(observation, DST, key), property_source(observation, DST, key)), (value, 'local'),
                        f'{what}: {DST} is fenced locally ({key})')
        # Copied properties are the copy's own local values, not received ones.
        for key, value in (('compression', 'zstd'), ('e2e:external', 'leaf')):
            check.equal((prop(observation, DST, key), property_source(observation, DST, key)), (value, 'local'),
                        f'{what}: {DST} has the copied {key} as a local value')
    check.equal(prop(before, EXTERNAL, 'keystatus'), 'unavailable', 'external source encryption root is also locked')
    check.equal(identity(copied, EXTERNAL), identity(before, EXTERNAL), 'the external encryption ancestor is untouched')
    check.equal(identity(copied, EXTERNAL + '/outside'), identity(before, EXTERNAL + '/outside'),
                'an excluded encrypted sibling is untouched')
    target_members = {name for name, facts in final.datasets.items()
                      if facts['type'] != 'snapshot' and (name == DST or name.startswith(DST + '/'))}
    check.equal(target_members, {DST}, 'only the leaf is copied')
    check(not [name for name in final.datasets if name.startswith('e2eext-dst/secret') or '/zboot-receive-' in name],
          'no source encryption ancestor, excluded sibling, or receive container is published')
    source_ivsets = ivsets(s.step('source-ivsets'), SRC, check)
    copied_ivsets = ivsets(s.step('copied-ivsets'), DST, check)
    check.equal(set(source_ivsets), {'@first', '@second'}, 'both source IV-set GUIDs were observed')
    check.equal(copied_ivsets, source_ivsets, 'the raw leaf stream preserves every exact IV-set GUID')
    check.equal(s.step('copied-hash').out.split()[0], s.step('source-hash').out.split()[0],
                'actual payload bytes match after unlocking the new encryption root')
    check.equal(json.loads(s.step('operations').out)['result']['operations']['operations'], [],
                'completed transfer leaves no operation record')
