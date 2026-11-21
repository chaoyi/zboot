"""A kept file://-keyed tree: refused while the key is absent, kept encrypted
after, its inheriting child relinked to its copied root."""
from host.case import Boot
from host import restore as r

ID = 'RESTORE-KEYS-NATIVE'
GROUP = 'restore'
SECONDS = 3600
DISKS = {'A': 4, 'B': 4, 'D': 8}
BOOTS = [Boot(1)]
SECRET = 'e2ea/secret'


def verdict(ev, check):
    s = ev.stage(1)
    r.base(s, check)
    r.placed(s, check, 'source')
    loaded = r.envelope(s.step('loaded'))
    check.equal(loaded.get('mode'), 'preview', 'with the key loaded the plan previews')
    r.refused(s.step('absent'), check, 'restore with the file:// key absent', 'does not unlock it from here')
    check.equal(r.record(s.step('absent-record')), None, 'a refused plan left no record')
    check.equal(s.step('absent-a').out, s.step('a-before').out, 'a refused plan left A (name, guid) unchanged')
    check(not [n for n in s.step('absent-b').out.split() if 'zboot-restore-' in n], 'a refused plan staged nothing')
    before, after = s.observe('absent-before'), s.observe('absent-after')
    check.equal(after.datasets, before.datasets, 'a refused plan left every dataset and snapshot identity')
    check.equal(after.holds, before.holds, 'a refused plan left the holds')
    token = r.reviewed(s, check, 'restore')
    r.loader(s, check)
    done = r.applied(s.step('restore-apply'), check, token, 'restore --confirm')
    check.equal(done.get('be'), 'e2ea/ROOT/be1', 'applied BE')
    check.equal(done.get('pool'), 'e2ea', 'applied pool')
    r.completed(s, check, 'done')
    check.equal(s.step('kept-import').rc, 0, 'writable reimport of A')
    check.equal(s.step('kept-load').rc, 0, 'the key from its original location loads the kept tree')
    keys = dict(line.split('\t') for line in s.step('kept-keys').out.splitlines())
    check.equal(keys.get('encryptionroot'), SECRET, 'kept tree is its own encryption root')
    check.equal(keys.get('keylocation'), 'file:///run/zfs-e2e-a-key', 'kept tree key location')
    check.equal(keys.get('encryption'), 'aes-256-gcm', 'kept tree still encrypted')
    inner = dict(line.split('\t') for line in s.step('kept-inner-keys').out.splitlines())
    check.equal(inner.get('encryptionroot'), SECRET, 'the child is relinked to its copied encryption root')
    check.equal(inner.get('encryption'), 'aes-256-gcm', 'the kept child is still encrypted')
    r.read(s, check, 'kept', SECRET)
    r.read(s, check, 'kept', SECRET + '/inner')
