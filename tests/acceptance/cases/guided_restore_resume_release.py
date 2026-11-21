"""GUIDED-RESTORE-RESUME-RELEASE: GUIDED-RESTORE-EFI-NATIVE with a power cut.

Stage 2 ends at the Menu's `  erased` progress line (the restore record's
durable advance to that phase) and the host SIGKILLs QEMU. The stick runs no
fault shim, so the cut lands at or after that phase, not exactly at it.
The cut is after erasure, so the resume continues without consent.
Stage 3 boots a fresh stick, `resume`s the one discovered operation and
checks the restored fixture; stages 4-5 boot A and the stick as in the
uncut case.
"""
from host import guided
from host.case import Boot

ID = 'GUIDED-RESTORE-RESUME-RELEASE'
GROUP = 'efi'
SECONDS = 7200
DISKS = guided.DISKS
BOOTS = [Boot(1, extra={'setup': 'neutral'}), Boot(2, efi=True), Boot(3, efi=True),
         Boot(4, efi=True, poweroff=True, extra={'from': 'A'}), Boot(5, efi=True)]


def stage_2(console):
    guided.restore(console, cut='release')


def stage_3(console):
    guided.resume(console, consent=False)


stage_4 = guided.boot_a
stage_5 = guided.postboot


def verdict(ev, check):
    guided.check_setup(ev, check)
    guided.check_restore(ev, 2, check, cut='release')
    guided.check_resume(ev, 3, check, consent=False)
    guided.check_restored(ev, 3, check)
    guided.check_boot_a(ev, 4, check)
    guided.check_postboot(ev, 5, check)
