"""A read-only pool C naming a boot default holds the restore until C is writable."""
from host.case import Boot
from host import restore as r

ID = 'RESTORE-READONLY-DEFAULT-NATIVE'
GROUP = 'restore'
SECONDS = 3600
DISKS = {'A': 4, 'B': 4, 'D': 8}
BOOTS = [Boot(1)]


def rows(step):
    return dict(line.split('\t') for line in step.out.splitlines())


def verdict(ev, check):
    s = ev.stage(1)
    r.base(s, check)
    r.placed(s, check, 'source')
    check.equal(s.step('c-readonly').out.strip(), 'on', 'pool C imported read-only')
    r.previewed(s.step('restore-preview'), check, 'restore --dry-run')
    r.loader(s, check)
    rec = r.record(s.step('stopped-record')) or {}
    op = rec.get('id', '')
    stopped = r.refused(s.step('restore-apply'), check, 'restore with read-only C naming a default',
                        f'zboot resume {op}')
    check.equal(s.step('restore-apply').rc, 4, 'restore stops after durable effects')
    partial = r.envelope(s.step('restore-apply'))
    check.equal(partial.get('mode'), 'partial', 'restore reports partial completion')
    check.equal(partial.get('operation'), op, 'partial result names its live restore record')
    check.equal(rec.get('step'), 10, 'record left at `properties restored`')
    check.equal(rows(s.step('stopped-c')), {'readonly': 'on', 'bootfs': 'e2ec/ROOT/old'}, 'C unchanged by the stop')
    check(op and op in stopped, f'the stop names the record: {stopped[-300:]!r}')
    r.refused(s.step('resume-readonly'), check, 'resume while C is read-only')
    # Each attempt dispatches the native bootfs setter for readonly C. Its
    # failure follows child creation, so this invocation is partial even when
    # native readback proves that C retained the same bootfs and readonly value.
    check.equal(s.step('resume-readonly').rc, 4, 'resumed bootfs setter dispatch records an effect')
    resumed = r.envelope(s.step('resume-readonly'))
    check.equal(resumed.get('mode'), 'partial', 'resumed setter failure reports partial completion')
    check.equal(resumed.get('operation'), op, 'resumed partial result names its live record')
    check.equal((r.record(s.step('refused-record')) or {}).get('step'), 10, 'record unmoved by the refused resume')
    check.equal(rows(s.step('refused-c')), {'readonly': 'on', 'bootfs': 'e2ec/ROOT/old'},
                'C unchanged by the refused resume')
    r.ok(s.step('resume'), check, 'resume after C is writable')
    done = r.completed(s, check, 'done', ('e2ea/scratch',))
    bootfs = dict(line.split('\t') for line in s.step('done-bootfs').out.splitlines())
    check.equal(bootfs.get('e2ec'), '-', "C's boot default cleared (one boot default per host)")
    check.equal(done.pools.get('e2ea', {}).get('readonly'), 'on', 'A read-only for inspection')
