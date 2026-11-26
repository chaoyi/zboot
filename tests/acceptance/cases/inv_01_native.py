"""INV-01: recursive inventory, lossless identities, encryption, rename stability."""
from host.case import Boot
from host.identity import identity, named

ID = 'INV-01-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
DECIMAL = ('pool_guid', 'guid', 'createtxg', 'objsetid')


def verdict(ev, check):
    inventory_part(ev.stage(1), check)


def inventory_part(s, check):
    """INV-01's assertions over stage S; CAPTURE-READER-NATIVE runs them too."""
    before = s.step('inventory-before').json['result']['inventory']
    after = s.step('inventory-after').json['result']['inventory']
    nb, na = s.observe('before'), s.observe('after')
    check.equal(before['schema_version'], 3, 'inventory schema')
    check.equal(before['imported_only'], True, 'inventory imported_only')
    check.equal(before['non_atomic'], True, 'inventory non_atomic')
    check.equal(before['recursive'], True, 'inventory recursive')
    check.equal(len(before['pools']), 2, 'two imported pools')
    check.equal(len(before['datasets']), 7, 'seven recursive datasets')
    check.equal(len(before['snapshots']), 6, 'six recursive snapshots')
    for record in before['datasets'] + before['snapshots']:
        for field in DECIMAL:
            v = record['identity'][field]
            check(isinstance(v, str) and v.isdigit() and int(v) < 1 << 64,
                  f"{record['name']} identity {field} is a u64 decimal string: {v!r}")
        check.equal(record['guid'], record['identity']['guid'], f"{record['name']} guid is identity.guid")
        # Stronger than the old case: every record equals the native identity.
        check.equal(record['identity'], identity(nb, record['name']), f"{record['name']} identity is native")
    # Exactly the native set, nothing invented or missing.
    native = set(nb.datasets)
    check.equal({r['name'] for r in before['datasets'] + before['snapshots']}, native,
                'inventory names equal native dataset+snapshot names')
    for pool in ('e2ea', 'e2eb'):
        check.equal(named(before, 'pools', pool)['guid'], s.step(f'guid-{pool}').out.strip(),
                    f'{pool} guid equals zpool get guid')
    plain = named(before, 'datasets', 'e2ea/plain')
    check.equal(plain['guid'], s.step('guid-plain').out.strip(), 'e2ea/plain guid equals zfs get guid')
    check.equal(plain['encryption'], 'off', 'e2ea/plain encryption')
    check.equal(nb.properties('e2ea/plain')['encryption']['value'], 'off', 'native e2ea/plain encryption')
    enc = named(before, 'datasets', 'e2eb/encrypted')
    check.equal(enc['encryption'], 'aes256_gcm', 'e2eb/encrypted encryption')
    check.equal(enc['keystatus'], 'available', 'e2eb/encrypted keystatus')
    check.equal(nb.properties('e2eb/encrypted')['encryption']['value'], 'aes-256-gcm', 'native encryption')
    check.equal(nb.properties('e2eb/encrypted')['keystatus']['value'], 'available', 'native keystatus')
    check.equal(named(before, 'datasets', 'e2eb/encrypted/child')['encryptionroot'], 'e2eb/encrypted',
                'child encryption root')
    check.equal(nb.properties('e2eb/encrypted/child')['encryptionroot']['value'], 'e2eb/encrypted',
                'native child encryption root')
    check.equal(named(before, 'snapshots', 'e2ea/plain@first')['guid'], s.step('guid-plain-first').out.strip(),
                'e2ea/plain@first guid equals zfs get guid')
    for old, new in (('e2ea/plain', 'e2ea/renamed'), ('e2ea/plain/child', 'e2ea/renamed/child')):
        check.equal(named(after, 'datasets', new)['identity'], named(before, 'datasets', old)['identity'],
                    f'{new} keeps the identity of {old}')
        check.equal(identity(na, new), identity(nb, old), f'native {new} keeps the identity of {old}')
        check(old not in na.datasets, f'{old} is gone natively')
        for point in ('first', 'second'):
            check.equal(named(after, 'snapshots', f'{new}@{point}')['identity'],
                        named(before, 'snapshots', f'{old}@{point}')['identity'],
                        f'{new}@{point} keeps the identity of {old}@{point}')
            check.equal(identity(na, f'{new}@{point}'), identity(nb, f'{old}@{point}'),
                        f'native {new}@{point} keeps its identity')
    status = s.step('status').json
    check.equal(status['schema_version'], 1, 'zboot status envelope schema')
    check.equal(status['mode'], 'applied', 'zboot status envelope mode')
    check.equal(status['result']['schema_version'], 1, 'zboot status result schema')
    for record in after['datasets']:
        check.equal(named(status['result']['inventory'], 'datasets', record['name'])['identity'],
                    record['identity'], f"zboot status identity of {record['name']} equals the earlier status observation")
        check.equal(record['identity'], identity(na, record['name']), f"{record['name']} post-rename identity is native")
