"""WIPE: imported-disk guard, then reviewed, confirmed metadata clearing of the
virtio disk D and the QEMU NVMe disk N (no Sanitize), verified by probes."""
from host.case import Boot
from host.identity import unchanged
from host.lifecycle import stale_token

ID = 'WIPE-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2, 'N': 1}
BOOTS = [Boot(1)]
SENTINEL = 'ZFS-E2E-WIPE-SENTINEL'
P1, P1_BYTES = 1 << 20, 128 << 20


def verdict(ev, check):
    s = ev.stage(1)
    serials = [line.split('\t')[0] for line in s.step('disks').out.splitlines()]
    for label in 'ADN':
        check(f'ZFS-E2E-{label}' in serials, f'disk {label} present: {serials}')
    check.equal(len(serials), len(set(serials)), 'no duplicate fixture serials')
    imported = s.step('wipe-imported')
    check(imported.rc != 0, f'wipe of an imported pool member refused: rc={imported.rc}')
    check.contains(imported.err, 'imported pool', 'refusal names the imported pool')
    unchanged(check, s.observe('before'), s.observe('after-imported'), 'imported-disk refusal')
    check.equal(s.step('a-head-after').out, s.step('a-head').out, 'disk A label area unchanged by the refusal')

    before = [int(n) for n in s.step('d-labels-before').out.split()]
    check(len(before) == 4 and all(before), f'the exported pool wrote all four labels: {before}')
    review = s.step('review').json
    check.equal(review['schema_version'], 1, 'review envelope schema')
    check.equal(review['mode'], 'preview', 'review mode')
    check.equal(len(review['result']['partitions']), 1, 'review sees the one GPT partition')
    method = review['result']['method']
    check.equal(method['kind'], 'clear', 'a virtio disk gets metadata clearing')
    check.equal(method['reason'], 'not_nvme', 'the reason is that D is not NVMe')
    check.equal([(e['start'], e['bytes']) for e in method['extents']], [(P1, P1_BYTES)],
                'the plan saved the partition extent')
    wrong = s.step('wrong-token')
    stale_token(check, wrong, 'wipe with a wrong token', review.get('token'))
    check.equal(s.step('sentinel').out, SENTINEL, 'sentinel intact after the wrong-token refusal')
    preview = s.step('preview').json
    token = preview.get('token')
    check(isinstance(token, str) and token, f'preview carries a token: {token!r}')
    unattended = s.step('unattended')
    check.equal(unattended.rc, 3, 'unattended wipe exits 3')
    check.equal(s.step('sentinel-unattended').out, SENTINEL, 'sentinel intact after the unattended run')
    wipe = s.step('wipe').json
    check.equal(wipe['mode'], 'applied', 'confirmed wipe applied')
    check.equal(wipe['token'], token, 'confirmed wipe names the reviewed token')
    check.equal(wipe['result']['complete'], True, 'wipe complete')
    check.equal(wipe['result']['method'], method, 'the wipe ran the reviewed method')
    check.contains(wipe['result']['report'], 'not erased', 'the report does not claim erasure')
    bare = s.step('bare-review').json
    check.equal(bare['schema_version'], 1, 'post-wipe review envelope schema')
    check.equal(bare['mode'], 'preview', 'post-wipe review mode')
    check.equal(bare['result']['partitions'], [], 'no partitions after wipe')
    check.equal(bare['result']['filesystem'], None, 'no filesystem after wipe')
    check.equal(bare['result']['partition_table_uuid'], None, 'no partition table after wipe')
    check.equal(s.step('blkid').rc, 2, 'blkid -p finds no signature')
    check.equal(s.step('d-labels').out.split(), ['0'] * 4, 'the nvlist and uberblocks of all four labels are zero')
    check.equal(s.step('d-gpt').out.split(), ['absent', 'absent'], 'no primary or backup GPT header')
    check.equal(s.step('sentinel-after').out, SENTINEL, 'data between the metadata is not erased')

    n = s.step('n-preview').json['result']['method']
    check.equal((n['kind'], n['reason']), ('clear', 'no_sanitize'),
                'QEMU NVMe reports no sanitize, so N gets metadata clearing')
    check.equal(len(n['extents']), 1, 'the plan saved N\'s partition extent')
    nwipe = s.step('n-wipe').json
    check.equal(nwipe['result']['complete'], True, 'NVMe wipe complete')
    check.equal(nwipe['result']['method'], n, 'the NVMe wipe ran the reviewed method')
    check.equal(s.step('n-bare-review').json['result']['partitions'], [], 'no partitions on N')
    check.equal(s.step('n-blkid').rc, 2, 'blkid -p finds no signature on N')
    check.equal(s.step('n-gpt').out.split(), ['absent', 'absent'], 'no GPT header on N')
