"""Shared host verdicts of the restore cases (guest side: guest/restore.sh).

Each helper judges what one guest helper recorded; names match the guest's
step names.
"""
import hashlib
import json
import re
from host.lifecycle import chunked, stale_token

HOSTID = 0x0174627a
HOSTID_BYTES = 'zbt\x01'
RESTORED = 'e2ea/ROOT/be1'
TOKENS = {
    'e2ea/ROOT/be1': 'ZFS-E2E-RESTORE-ROOT',
    'e2ea/ROOT/be1/var': 'ZFS-E2E-RESTORE-VAR',
    'e2ea/scratch': 'ZFS-E2E-RESTORE-SCRATCH',
    'e2ea/ROOT/be0': 'ZFS-E2E-RESTORE-OLD-BE',
    'e2ea/home': 'ZFS-E2E-RESTORE-HOME',
    'e2ea/secret': 'ZFS-E2E-RESTORE-SCRATCH',
    'e2ea/secret/inner': 'ZFS-E2E-RESTORE-INNER',
}
RESTORED_PROPERTIES = {'mountpoint': '/', 'canmount': 'noauto', 'readonly': 'off',
                       'zboot:pair': '-', 'zboot:placement': '-', 'mounted': 'no'}


def slug(name):
    return name.replace('/', '_').replace('@', '_')


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def hostid(stage, check, boot):
    check.equal(stage.step('hostid-pools').out, '', f'boot {boot}: no pool imported before the hostid change')
    out = stage.step('hostid').out
    check(out.endswith(HOSTID_BYTES), f'boot {boot}: /etc/hostid is not zbt\\x01: {out!r}')
    kernel = out[:-len(HOSTID_BYTES)].strip().removeprefix('0x')
    check(re.fullmatch('[0-9a-fA-F]+', kernel) and int(kernel, 16) == HOSTID,
          f'boot {boot}: kernel hostid {kernel!r} is not 0174627a')


def base(stage, check):
    """restore_base: hostid, fixture disks; the source BE's placement when built."""
    hostid(stage, check, 1)
    sums = [line.split()[0] for line in stage.step('fixtures-manifest').out.splitlines()]
    check(len(sums) == 2 and sums[0] == sums[1], f'fixture share manifest differs from the initrd copy: {sums}')
    disks = stage.step('disks').out
    for serial in ('ZFS-E2E-A', 'ZFS-E2E-D'):
        check(f'{serial} /dev/' in disks, f'fixture disk {serial} present: {disks!r}')


def placed(stage, check, name):
    rows = [r.split('\t') for r in stage.step(f'{name}-placed').out.splitlines()]
    check(rows and all(r[1] == 'no' for r in rows), f'{name}: tree stayed mounted after placement: {rows}')


def envelope(step):
    try:
        return json.loads(step.out)
    except ValueError:
        return {}


def ok(step, check, what):
    env = envelope(step)
    check(step.rc == 0 and env.get('schema_version') == 1,
          f'{what}: rc={step.rc} schema={env.get("schema_version")} stderr={step.err[-400:]!r}')
    return env


def previewed(step, check, what):
    env = ok(step, check, what)
    check.equal(env.get('mode'), 'preview', f'{what}: mode')
    check(bool(env.get('token')), f'{what}: preview has no token')
    return env.get('token')


def refused(step, check, what, *needles):
    check(step.rc not in (0, 3), f'{what}: not refused (rc={step.rc})')
    for needle in needles:
        check.contains(step.err, needle, f'{what}: refusal message')
    return step.err


def loader(stage, check, preview='restore-preview'):
    """The plan installs the loader its source ships: the session's UKI the
    guest put at /usr/lib/zboot/zboot.efi before the source snapshot."""
    shipped = stage.step('source-loader').out.split()[:1]
    state = (envelope(stage.step(preview)).get('result') or {}).get('state') or {}
    planned = state.get('loader') or {}
    check(len(shipped) == 1 and planned.get('sha256') == shipped[0],
          f'restore plans the loader its source ships: {planned} vs {shipped}')


def reviewed(stage, check, name):
    """The guest's `reviewed NAME`: preview, unattended exit 3, wrong token."""
    token = previewed(stage.step(f'{name}-preview'), check, f'{name} --dry-run')
    unattended = stage.step(f'{name}-unattended')
    env = envelope(unattended)
    check.equal(unattended.rc, 3, f'{name} unattended exit')
    check.equal(env.get('mode'), 'preview', f'{name} unattended mode')
    check.equal(env.get('token'), token, f'{name} unattended token')
    stale_token(check, stage.step(f'{name}-wrong-token'), f'{name} --confirm not-the-reviewed-token', token)
    return token


def applied(step, check, token, what):
    env = ok(step, check, what)
    check.equal(env.get('mode'), 'applied', f'{what}: mode')
    check.equal(env.get('token'), token, f'{what}: applied the reviewed token')
    return env.get('result') or {}


def record(step):
    value = step.out.strip()
    return None if value == '-' else json.loads(value)


def mounts(text):
    """[source, target, fstype] rows of a mountinfo."""
    rows = []
    for line in text.splitlines():
        left, right = line.split(' - ', 1)
        fstype, source = right.split()[:2]
        rows.append([source, left.split()[4], fstype])
    return rows


def nothing_mounted(text, check, what):
    rows = mounts(text)
    check(rows, f'{what}: no mount evidence')
    bad = [r for r in rows if r[2] == 'zfs' and (r[1] == '/' or r[0].startswith('e2ea'))]
    check(not bad, f'{what}: A or the root is mounted: {bad}')
    check(not [r for r in rows if r[1] == '/' and r[2] == 'zfs'], f'{what}: a ZFS dataset is mounted over /')


def cut(stage, check, step):
    """The restore cut landed on B's record write for STEP; its operation id."""
    argv = stage.cut('restore-cut')
    check.equal(len(argv), 3, f'cut argv {argv}')
    check.equal([argv[0], argv[-1]], ['set', 'e2eb'], 'cut at a `zfs set` on e2eb')
    prefix = 'zboot:operation='
    check(argv[1].startswith(prefix), f'cut at the restore record write: {argv}')
    rec = json.loads(argv[1][len(prefix):])
    check.equal(rec.get('kind'), 'restore', 'cut record kind')
    check.equal(rec.get('step'), step, 'cut record step')
    op = rec.get('id', '')
    check(re.fullmatch('[0-9a-f]{16}', op), f'cut record carries a 16-hex operation id: {op!r}')
    for name in ('cut-mounts', 'cut-mounts-init'):
        nothing_mounted((stage.path / name).read_text(), check, f'at the step-{step} cut ({name})')
    return op


def resumed_record(stage, check, op, step, name='record'):
    """After the restart: B's record is the cut operation, one step before the cut."""
    rec = record(stage.step(name)) or {}
    check.equal(rec.get('id'), op, f'{name}: record id after the restart')
    check.equal(rec.get('kind'), 'restore', f'{name}: record kind')
    check.equal(rec.get('step'), step, f'{name}: record step')


def read(stage, check, label, dataset):
    token = TOKENS[dataset]
    check.equal(stage.step(f'{label}-{slug(dataset)}-token').out, token, f'{dataset} token')
    files = {'./restore-token': sha(token)}
    found = stage.payload(f'{label}-{slug(dataset)}')
    if dataset == RESTORED:
        files['./etc/hostid'] = sha(HOSTID_BYTES)
        files['./boot/vmlinuz-zt'] = sha('ZFS-E2E-RESTORE-KERNEL')
        files['./boot/initrd.img-zt'] = sha('ZFS-E2E-RESTORE-INITRD')
        # The source's shipped loader; host.restore.loader checks its hash.
        check('./usr/lib/zboot/zboot.efi' in found, f'{dataset} keeps the loader it ships')
        files['./usr/lib/zboot/zboot.efi'] = found.get('./usr/lib/zboot/zboot.efi')
    check.equal({k: found.get(k) for k in files}, files, f'{dataset} content hashes')
    # Boot preparation adds no file to the BE (stock mounting, no list cache).
    extra = sorted(set(found) - set(files))
    check(not extra, f'{dataset} gained files: {extra}')


def completed(stage, check, label, kept=(), be_children=('var',)):
    """The guest's `restore_completed LABEL KEPT...`; BE_CHILDREN are the
    restored BE's children it reads (none for a paired BE, a leaf)."""
    check.equal(record(stage.step(f'{label}-record')), None, f'{label}: a restore record is left on B')
    done = stage.observe(f'{label}-done')
    check.equal(chunked(done), [], f'{label}: the receipt left no attachment or journal property')
    check('e2ea' not in done.pools, f'{label}: the restored pool A is still imported: {list(done.pools)}')
    bootfs = dict(r.split('\t') for r in stage.step(f'{label}-bootfs').out.splitlines())
    check.equal(set(bootfs), set(done.pools), f'{label}: bootfs read for every imported pool')
    check(all(v == '-' for v in bootfs.values()), f'{label}: an imported pool names a boot default: {bootfs}')
    nothing_mounted((done.path / 'mountinfo').read_text(), check, f'{label}: after the restore')
    check.equal(stage.step(f'{label}-import').rc, 0, f'{label}: read-only import of A')
    check.equal(stage.step(f'{label}-a-bootfs').out.strip(), RESTORED, f'{label}: A boot default')
    props = dict(r.split('\t') for r in stage.step(f'{label}-be').out.splitlines())
    for key, value in RESTORED_PROPERTIES.items():
        check.equal(props.get(key), value, f'{label}: {RESTORED} {key}')
    restored = stage.observe(f'{label}-restored')
    check.equal(chunked(restored), [], f'{label}: no attachment or journal property reached A')
    check.equal(restored.pools.get('e2ea', {}).get('readonly'), 'on', f'{label}: A imported read-only')
    check.equal(restored.pools.get('e2ea', {}).get('health'), 'ONLINE', f'{label}: A health')
    for dataset in (RESTORED, *(f'{RESTORED}/{child}' for child in be_children), *kept):
        read(stage, check, label, dataset)
    check.equal(stage.step(f'{label}-export').rc, 0, f'{label}: export A')
    return restored
