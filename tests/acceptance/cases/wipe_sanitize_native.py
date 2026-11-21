"""WIPE-SANITIZE: zboot's native NVMe sanitize path on the QEMU NVMe disk N,
against guest/fake-nvme.sh bind-mounted over `nvme` (QEMU has no Sanitize):
a plain sanitize, one already running at the start (after a power loss),
which is waited out, and a failed one, which refuses with no fallback."""
from host.case import Boot

ID = 'WIPE-SANITIZE-NATIVE'
GROUP = 'small'
SECONDS = 600
DISKS = {'A': 2, 'B': 2, 'D': 2, 'N': 1}
BOOTS = [Boot(1)]
SENTINEL = 'ZFS-E2E-SANITIZE-SENTINEL'


def calls(step):
    """The fake's call record: (verb, arguments, reply) per line."""
    out = []
    for line in step.out.splitlines():
        args, reply = line.split(' => ', 1)
        out.append((args.split()[0], args, reply))
    return out


def around_submission(record):
    """Sanitize-log statuses before and after the one submission."""
    verbs = [verb for verb, _, _ in record]
    at = verbs.index('sanitize')
    status = lambda part: [int(reply.split()[1]) for verb, _, reply in part if verb == 'sanitize-log']
    return status(record[:at]), status(record[at + 1:])


def verdict(ev, check):
    s = ev.stage(1)
    serials = [line.split('\t')[0] for line in s.step('disks').out.splitlines()]
    check('ZFS-E2E-N' in serials, f'disk N present: {serials}')
    ctrl, device_number, _, nsid = s.step('kernel').out.split()
    check.equal(nsid, '1', 'N is namespace 1')
    check(any(line.endswith('/nvme') for line in s.step('fake-install').out.splitlines()),
          'the fake is bound over an nvme on PATH')
    check.equal(s.step('fake-active').out.strip(), 'nvme version zt-fake', '`nvme` on PATH is the fake')
    sanitize = {'kind': 'sanitize', 'action': 'crypto_erase', 'controller': f'/dev/{ctrl}',
                'device_number': device_number, 'nsid': 1}

    def completed(name, before_expected):
        """A confirmed wipe that ran the reviewed sanitize, saw it through and
        left N bare: no signature, GPT or data at its ends or the sentinel."""
        preview = s.step(f'{name}-preview').json
        check.equal(preview['result']['method'], sanitize, f'{name}: the plan is a crypto-erase sanitize')
        check.equal(len(preview['result']['partitions']), 1, f'{name}: the plan sees the partition')
        wipe = s.step(name)
        check.equal(wipe.rc, 0, f'{name}: wipe exits 0 ({wipe.err[-400:]})')
        if wipe.rc == 0:
            result = wipe.json
            check.equal(result['mode'], 'applied', f'{name}: applied')
            check.equal(result['token'], preview['token'], f'{name}: the reviewed token')
            check.equal(result['result']['method'], sanitize, f'{name}: ran the reviewed method')
            check.equal(result['result']['complete'], True, f'{name}: complete')
            check.contains(result['result']['report'], 'controller reported completion',
                           f'{name}: the report says what the controller reported')
        record = calls(s.step(f'{name}-calls'))
        verbs = [verb for verb, _, _ in record]
        check('list-ctrl' not in verbs and not any('--all' in args for _, args, _ in record),
              f'{name}: no query a consumer drive rejects: {verbs}')
        check.equal([args for verb, args, _ in record if verb == 'sanitize'],
                    [f'sanitize /dev/{ctrl} --sanact=4'], f'{name}: one crypto-erase submission')
        if 'sanitize' in verbs:
            before, after = around_submission(record)
            check.equal(before, before_expected, f'{name}: the log before the submission')
            check.equal(after, [2, 2, 1], f'{name}: seen running, then complete')
        check.equal(s.step(f'{name}-blkid').rc, 2, f'{name}: blkid -p finds no signature')
        check.equal(s.step(f'{name}-gpt').out.split(), ['absent', 'absent'], f'{name}: no GPT header')
        check.equal(s.step(f'{name}-ends').out.split(), ['0', '0'], f'{name}: the first and last MiB are zero')
        check.equal(s.step(f'{name}-sentinel').out, '\0' * len(SENTINEL), f'{name}: the data is zeroed')

    completed('plain', [1])
    bare = s.step('plain-bare').json['result']
    check.equal((bare['partitions'], bare['filesystem'], bare['partition_table_uuid']), ([], None, None),
                'a fresh review of N after the sanitize shows nothing')
    check.equal(bare['method'], sanitize, 'N is still planned for a sanitize')
    # After a power loss: the running one is waited out before this one.
    completed('resumed', [2, 2, 1])

    failed = s.step('failed')
    check.equal(failed.rc, 4, 'a sanitize the controller failed exits 4: something may have changed')
    check.contains(failed.err, 'sanitize failed', 'the refusal says the sanitize failed')
    check.contains(failed.err, 'failure mode', 'and names sanitize failure mode')
    record = calls(s.step('failed-calls'))
    verbs = [verb for verb, _, _ in record]
    check.equal(verbs.count('sanitize'), 1, 'one submission, no retry')
    if 'sanitize' in verbs:
        check.equal(around_submission(record), ([1], [2, 2, 3]), 'the log: idle, running, failed')
    check(not {'wipefs', 'sgdisk'} & set(verbs), 'nothing else is run through the fake')
    check.equal(s.step('failed-gpt').out.split(), ['present', 'present'],
                'no fallback: the GPT the failed sanitize left is not cleared')
    check.equal(s.step('failed-sentinel').out, SENTINEL, 'the data the failed sanitize left is untouched')
    check.contains(s.step('failure-mode-state').out, 'STATUS=3', 'the fake is in failure mode')
    again = s.step('failure-mode')
    check.equal(again.rc, 1, 'a wipe in failure mode refuses before any effect (exit 1)')
    check.contains(again.err, 'failure mode', 'the refusal names failure mode')
    check.contains(again.err, 'exit-failure', 'and leaves exiting it to the operator')
    record = calls(s.step('failure-mode-calls'))
    check.equal([verb for verb, _, _ in record].count('sanitize'), 0, 'nothing is submitted in failure mode')
    check.equal(s.step('failure-mode-gpt').out.split(), ['present', 'present'], 'N is still untouched')
    check.equal(s.step('fake-errors').out, '', 'the fake recorded no erase error')
