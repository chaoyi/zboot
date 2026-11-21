"""Shared host-side readers for the identity/tree cases (native evidence first)."""


def pool_of(name):
    return name.split('/')[0].split('@')[0]


def identity(obs, name):
    """Full native identity (pool_guid, guid, createtxg, objsetid) of a dataset
    or snapshot in an Observation, in the supported identity field names."""
    row = obs.datasets[name]
    return {'pool_guid': obs.pools[pool_of(name)]['guid'], 'guid': row['guid'],
            'createtxg': row['createtxg'], 'objsetid': obs.properties(name)['objsetid']['value']}


def prop(obs, name, key):
    """A native property value of NAME in an Observation."""
    return obs.properties(name)[key]['value']


def under(names, root):
    """Names in the tree rooted at ROOT: ROOT, ROOT/..., ROOT@..., ROOT/...@..."""
    return sorted(n for n in names if n == root or n.startswith((root + '/', root + '@')))


def named(inventory, collection, name):
    """The one zboot status inventory record of COLLECTION named NAME."""
    hits = [r for r in inventory[collection] if r['name'] == name]
    if len(hits) != 1:
        raise KeyError(f'{len(hits)} {collection} records named {name}')
    return hits[0]


def pool_prop(obs, pool, key):
    """A native pool property value (zpool get) in an Observation."""
    for line in (obs.path / 'pool-properties').read_text().splitlines():
        row = line.split('\t')
        if row[:2] == [pool, key]:
            return row[2]
    raise KeyError(f'{obs.path}: no pool property {pool} {key}')


# Native properties a refused or no-op command must leave as they were; space
# and timing counters are excluded, every user property (zboot:*, e2e:*) kept.
STABLE = ('type', 'guid', 'createtxg', 'objsetid', 'origin', 'clones', 'mountpoint', 'canmount',
          'mounted', 'readonly', 'compression', 'encryption', 'encryptionroot', 'keystatus',
          'keylocation', 'defer_destroy', 'userrefs', 'volsize', 'volmode', 'atime', 'recordsize')
POOL_STABLE = ('guid', 'health', 'bootfs', 'readonly', 'cachefile')


def state(obs):
    """Native state, as {key: value}, for before/after comparison."""
    out = {('pool', n): v for n, v in obs.pools.items()}
    out.update((('dataset', n), v) for n, v in obs.datasets.items())
    out.update((('hold',) + h, True) for h in obs.holds)
    out.update((('mount', m), s) for m, s in obs.mounts.items() if not m.startswith('/out'))
    for line in (obs.path / 'properties').read_text().splitlines():
        row = line.split('\t')
        if len(row) == 4 and (row[1] in STABLE or ':' in row[1]):
            out[('property', row[0], row[1])] = (row[2], row[3])
    for line in (obs.path / 'pool-properties').read_text().splitlines():
        row = line.split('\t')
        if len(row) == 4 and (row[1] in POOL_STABLE or ':' in row[1]):
            out[('pool-property', row[0], row[1])] = row[2]
    return out


def unchanged(check, before, after, message, ignore=()):
    """One assertion: native state of AFTER equals BEFORE (diff in the message),
    disregarding every key about a name in IGNORE."""
    a, b = state(before), state(after)
    diff = sorted(str(k) for k in a.keys() | b.keys() if a.get(k) != b.get(k) and k[1] not in ignore)
    return check(not diff, f'{message}: native state changed: {diff[:12]}')
