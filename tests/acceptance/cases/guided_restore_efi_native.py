"""GUIDED-RESTORE-EFI-NATIVE: the zboot UKI booted from a stick restores host A.

The UKI is the session's `neutral` output of dist/dist.sh (docs/TESTING.md,
prepare-efi).

1. setup (guest/guided.sh, a direct boot of that output's kernel and zboot,
   with its UKI and a `zboot factory` root tar on the fixtures share): B holds
   the mirror of A's BE; A is a factory deploy with hostid 0174627a that ships
   the session's UKI as its loader; A's child and scratch are then mutated.
2. OVMF boots the UKI from the prepare-efi stick (EFI/BOOT/BOOTX64.EFI); the
   menu adopts the hostid from B. `restore e2eb/ROOT/be1 /dev/vda`, keep
   e2ea/scratch, consent; the menu's shell checks A and B natively and
   exports every pool.
3. OVMF boots A's own ESP with no stick: the UKI restore installed there hands
   off to e2ea/ROOT/be1; its opt-in systemd probe also runs installed
   `zboot fork try`, then a second one-argument fork cut by SIGKILL after
   successful native capture. Ordinary installed resume reuses the same native
   snapshots, then A powers off. This is a process-cut oracle; FORK-NATIVE
   retains the QEMU after-clone power cut.
4. A fresh stick boot: both pools carry active labels (stock Debian does not
   export at shutdown) and import read-only without force under the adopted
   hostid.
"""
from host import guided
from host.case import Boot

ID = 'GUIDED-RESTORE-EFI-NATIVE'
GROUP = 'efi'
SECONDS = 7200
DISKS = guided.DISKS
BOOTS = [Boot(1, extra={'setup': 'neutral'}), Boot(2, efi=True),
         Boot(3, efi=True, poweroff=True, extra={'from': 'A'}), Boot(4, efi=True)]

stage_2 = guided.restore
stage_3 = guided.boot_a
stage_4 = guided.postboot


def verdict(ev, check):
    guided.check_setup(ev, check)
    guided.check_restore(ev, 2, check)
    guided.check_restored(ev, 2, check)
    guided.check_boot_a(ev, 3, check)
    guided.check_installed_fork(ev, 3, check)
    guided.check_postboot(ev, 4, check)
