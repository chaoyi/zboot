"""RAW-HEAD: property-free per-dataset raw receivers keep identities and IV sets;
zvol written accounting."""
from host.case import Boot
from host.identity import named, prop

ID = 'RAW-HEAD-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
PAIRS = (('e2eb/encrypted', 'e2ea/raw'), ('e2eb/encrypted/child', 'e2ea/raw/child'))


def u64(text):
    return int(text) if text.isdigit() and int(text) < 1 << 64 else None


def verdict(ev, check):
    s = ev.stage(1)
    for step in ('replicate', 'replicate-child'):
        check.equal(s.step(step).out.split(), ['send_exit=0', 'receive_exit=0'], f'{step}: raw pipeline exits')
    raw, inventory = s.observe('raw'), s.step('inventory').json['result']['inventory']
    ivsets = dict(line.split('\t') for line in s.step('ivsets').out.splitlines())
    written = dict(line.split('\t') for line in s.step('written-raw').out.splitlines())
    for src, dst in PAIRS:
        record = named(inventory, 'datasets', dst)
        check.equal(record['encryption'], 'aes256_gcm', f'status: {dst} encryption')
        check.equal(record['keystatus'], 'unavailable', f'status: {dst} keystatus')
        check.equal(prop(raw, dst, 'encryption'), 'aes-256-gcm', f'native {dst} encryption')
        check.equal(prop(raw, dst, 'keystatus'), 'unavailable', f'native {dst} key stays locked')
        check.equal(prop(raw, dst, 'readonly'), 'on', f'native {dst} readonly')
        # A new raw dataset is its own encryption root with a local prompt.
        check.equal(prop(raw, dst, 'encryptionroot'), dst, f'native {dst} is its own encryption root')
        check.equal((prop(raw, dst, 'keylocation'), raw.properties(dst)['keylocation']['source']),
                    ('prompt', 'local'), f'native {dst} keylocation')
        check.equal(raw.datasets[f'{dst}@secret']['guid'], raw.datasets[f'{src}@secret']['guid'],
                    f'{dst}@secret keeps the source snapshot guid')
        iv = ivsets[f'{src}@secret']
        check(u64(iv) not in (None, 0), f'{src}@secret has a non-zero u64 IV-set guid: {iv!r}')
        check.equal(ivsets[f'{dst}@secret'], iv, f'{dst}@secret keeps the source IV-set guid')
        check.equal(written[dst], '0', f'locked readonly synced {dst} wrote nothing since @secret')
    devices = s.step('zvol-device').out.split()
    check.equal(len(devices), 1, f'exactly one zvol node names e2ea/volume: {devices}')
    check(devices and devices[0].startswith('/dev/zd'), f'zvol node path: {devices}')
    check.equal(s.step('zvol-fresh').out.strip(), '0', 'zvol at a fresh @base wrote nothing')
    after = s.step('zvol-written').out.strip()
    check(u64(after) is not None, f'native written@base parses as u64: {after!r}')
    check((u64(after) or 0) > 0, f'a new 4 KiB block is written since @base: {after!r}')
