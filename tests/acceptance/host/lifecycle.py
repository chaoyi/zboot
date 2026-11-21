"""Host-side checks shared by the pair/primary/transfer/loss cases.

Native facts come from guest `observe` records (zpool/zfs directly); zboot's
own JSON is checked only as the user-facing envelope and plan.
"""
import functools
import json
import re


@functools.lru_cache(maxsize=None)
def _properties(path):
    out = {}
    for line in (path / 'properties').read_text().splitlines():
        row = line.split('\t')
        if len(row) == 4:
            out.setdefault(row[0], {})[row[1]] = (row[2], row[3])
    return out


def prop(obs, name, key):
    """Native property value, '-' when the property is not set."""
    return _properties(obs.path).get(name, {}).get(key, ('-', '-'))[0]


def source(obs, name, key):
    return _properties(obs.path).get(name, {}).get(key, ('-', '-'))[1]


def identity(obs, name):
    """(pool guid, guid, createtxg, objsetid) of a dataset or snapshot."""
    pool = name.split('/')[0].split('@')[0]
    record = obs.datasets[name]
    return (obs.pools[pool]['guid'], record['guid'], record['createtxg'], prop(obs, name, 'objsetid'))


def pair(obs, name):
    return json.loads(prop(obs, name, 'zboot:pair'))


def snapshots(obs, prefix=''):
    return sorted(n for n, r in obs.datasets.items() if r['type'] == 'snapshot' and n.startswith(prefix))


def placement(obs, name):
    return {k: prop(obs, name, k) for k in ('readonly', 'canmount', 'mountpoint', 'mounted')}


def holds(obs, snapshot):
    return sorted(tag for snap, tag in obs.holds if snap == snapshot)


def preserved(check, before, after, what):
    """Membership, full identity and snapshot referenced bytes unchanged."""
    check.equal(sorted(after.datasets), sorted(before.datasets), f'{what}: membership unchanged')
    for name in before.datasets:
        if name in after.datasets:
            check.equal(identity(after, name), identity(before, name), f'{what}: identity of {name}')
    for name in snapshots(before):
        if name in after.datasets:
            check.equal(prop(after, name, 'referenced'), prop(before, name, 'referenced'),
                        f'{what}: referenced bytes of {name}')


CHUNKED = ('zboot:journal:', 'zboot:attachment:')


def chunked(obs):
    """`DATASET KEY` of every journal or attachment property, local or
    inherited. An operation removes its attachments before its record, so
    with no record there is none, and nothing writes a journal any more."""
    return sorted(f'{name} {key}' for name, props in _properties(obs.path).items()
                  for key in props if key.startswith(CHUNKED))


def no_operation(check, obs, what):
    for pool in ('e2ea', 'e2eb'):
        check.equal(prop(obs, pool, 'zboot:operation'), '-', f'{what}: no operation record on {pool}')
    check.equal(chunked(obs), [], f'{what}: no journal or attachment property is left')


def envelope(check, step, mode, what):
    """The versioned envelope of a successful --json zboot call."""
    check.equal(step.rc, 0, f'{what} exit status ({step.err.strip()[-300:]})')
    try:
        value = step.json
    except ValueError:
        check(False, f'{what}: stdout is not JSON: {step.out[-300:]!r}')
        return {}
    check.equal(value.get('schema_version'), 1, f'{what} schema_version')
    check.equal(value.get('mode'), mode, f'{what} mode')
    if mode == 'preview':
        check(isinstance(value.get('token'), str) and value['token'], f'{what} carries a token')
    return value


def refused(check, step, needle, what):
    """A refusal: nonzero exit and the user-facing reason on stderr."""
    check(step.rc != 0, f'{what} must refuse but exited 0')
    check.contains(step.err, needle, f'{what} refusal reason')


def stale_token(check, step, what, token=None):
    """An exact stale-token refusal preserves its opaque token boundary."""
    check.equal(step.rc, 3, f'{what}: stale token exits 3')
    value = step.json
    check.equal(value.get('schema_version'), 1, f'{what}: refusal schema')
    check.equal(value.get('mode'), 'refused', f'{what}: refused mode')
    check.equal(value.get('result', {}).get('reason'), 'stale_token', f'{what}: stable reason')
    check('token' not in value, f'{what}: refusal carries no replacement token')
    check.contains(step.err, 'plan changed', f'{what}: stderr reason')
    check(re.search(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])', step.out + step.err) is None,
          f'{what}: output contains no fresh token')
    if token:
        check(token not in step.out and token not in step.err, f'{what}: reviewed token stays opaque')
    return value


def unchanged(check, before, after, what):
    """Nothing native moved: membership, identities, referenced bytes,
    placement, zboot properties, holds and operation records."""
    preserved(check, before, after, what)
    for name, record in before.datasets.items():
        if name in after.datasets and record['type'] != 'snapshot':
            check.equal(placement(after, name), placement(before, name), f'{what}: placement of {name}')
        if name in after.datasets:
            for key in ('zboot:pair', 'zboot:placement', 'zboot:operation'):
                check.equal(prop(after, name, key), prop(before, name, key), f'{what}: {key} of {name}')
    check.equal(after.holds, before.holds, f'{what}: holds')


def consent(check, stage, name, what, wrong_reason='the plan changed'):
    """guest/lifecycle.sh `consent NAME ...`: preview, unattended exit 3 with
    the same preview, wrong token refused, none of them changing native
    state, then the reviewed token applied.
    Returns (preview envelope, applied envelope)."""
    preview = envelope(check, stage.step(f'{name}-preview'), 'preview', f'{what} preview')
    unattended = stage.step(f'{name}-unattended')
    check.equal(unattended.rc, 3, f'{what} unattended exit status')
    try:
        shown = unattended.json
    except ValueError:
        shown = {}
    check.equal(shown.get('mode'), 'preview', f'{what} unattended shows its preview')
    check.equal(shown.get('token'), preview.get('token'), f'{what} unattended preview token')
    stale_token(check, stage.step(f'{name}-wrong'), f'{what} with a wrong token', preview.get('token'))
    check.contains(stage.step(f'{name}-wrong').err, wrong_reason, f'{what}: stale-token reason')
    unchanged(check, stage.observe(f'{name}-before'), stage.observe(f'{name}-refused'),
              f'{what} preview, unattended and wrong-token runs')
    applied = envelope(check, stage.step(f'{name}-confirm'), 'applied', f'{what} confirmed')
    check.equal(applied.get('token'), preview.get('token'), f'{what} applied the reviewed token')
    return preview, applied
