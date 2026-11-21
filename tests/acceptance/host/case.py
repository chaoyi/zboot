"""Run one acceptance case: its boots in order, then the host-side verdict.

A case module (tests/acceptance/cases/*.py) defines:
  ID, GROUP, SECONDS        case id, fixture group, overall time bound
  DISKS                     GiB per disk label, e.g. {'A': 2, 'B': 2, 'D': 8}
  BOOTS                     [Boot(...)], run in order on the same disks
  verdict(ev, check)        host-side assertions over the recorded evidence
and a guest script guest/cases/ID.sh with one stage_N function per boot.
A firmware boot (Boot(efi=True)) runs no guest script: the module's own
stage_N(console) drives the Menu console (host/console.py), recording the
same evidence files, and the boot then ends in a power cut (with poweroff=True
the host instead waits for the guest to power itself off). With target=M,
the dialogue hands off (kexec) to a BE whose kernel and initrd are the
acceptance ones and whose zboot:cmdline carries `zt.case=ID zt.stage=M`;
guest stage_M then runs in that target and the boot ends like a guest stage.
Optional hooks, each given (run_dir, boot): prepare(run_dir) before the
first boot, shares and images (extra 9p shares and case images) and
memory_mib (guest RAM hook; otherwise SMOKE 2048, other cases 8192,
overridable with ZBOOT_VM_MEMORY_MIB).
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import time

from host.channel import Channel
from host.console import Console, ConsoleError
from host.vm import Vm, accelerator_config, default_memory_mib


@dataclass
class Boot:
    stage: int
    cut: str | None = None      # expected `CUT NAME`; the host then power-cuts
    udev: bool = False          # start the runtime's udev (by-id aliases)
    append: str = ''            # extra kernel arguments
    efi: bool = False           # firmware boot of the case's EFI disk; stage_N(console) drives it
    target: int | None = None   # efi only: guest stage the dialogue hands off to
    poweroff: bool = False      # efi only: the guest then powers itself off (no power cut)
    extra: dict = field(default_factory=dict)
    fresh_disks: bool = False   # selected machine fixture; stock boots reuse prior disks
    network: bool = False       # selected cases only: one user NIC and loopback SSH forward


class Evidence:
    """Files the guest wrote under out/STAGE/: NN-NAME.{argv,out,err,rc},
    NN-NAME.observe/, NN-NAME.payload, cut-NAME.argv and FAILED."""

    def __init__(self, root):
        self.root = Path(root)

    def stage(self, n):
        return Stage(self.root / str(n))


class Stage:
    def __init__(self, path):
        self.path = path

    def _one(self, name, suffix):
        hits = sorted(p for p in self.path.glob(f'*-{name}{suffix}')
                      if re.fullmatch(r'\d+', p.name[:-len(f'-{name}{suffix}')]))
        if len(hits) != 1:
            raise KeyError(f'{self.path}: {len(hits)} records named {name}{suffix}')
        return hits[0]

    def step(self, name):
        base = self._one(name, '.rc').with_suffix('')
        return Step(base)

    def observe(self, name):
        return Observation(self._one(name, '.observe'))

    def cut(self, name):
        """argv of the native call an armed fault cut (see guest/fault.sh)."""
        return (self.path / f'cut-{name}.argv').read_text().splitlines()

    def payload(self, name):
        return dict(line.split('  ', 1)[::-1]
                    for line in self._one(name, '.payload').read_text().splitlines())

    @property
    def failed(self):
        p = self.path / 'FAILED'
        return p.read_text().strip() if p.exists() else None


class Step:
    def __init__(self, base):
        self.base = base
        self.rc = int(base.with_suffix('.rc').read_text())
        self.out = base.with_suffix('.out').read_text(errors='replace')
        self.err = base.with_suffix('.err').read_text(errors='replace')
        self.argv = base.with_suffix('.argv').read_text().splitlines()

    @property
    def json(self):
        return json.loads(self.out)


class Observation:
    """Native state read with zpool/zfs directly, never through zboot."""

    def __init__(self, path):
        self.path = path

    def _rows(self, name):
        return [line.split('\t') for line in (self.path / name).read_text().splitlines() if line]

    @property
    def pools(self):
        return {r[0]: {'guid': r[1], 'health': r[2], 'readonly': r[3]} for r in self._rows('pools')}

    @property
    def datasets(self):
        return {r[0]: {'guid': r[1], 'createtxg': r[2], 'type': r[3]} for r in self._rows('datasets')}

    def properties(self, dataset):
        return {r[1]: {'value': r[2], 'source': r[3]}
                for r in self._rows('properties') if r[0] == dataset}

    @property
    def holds(self):
        return {(r[0], r[1]) for r in self._rows('holds')}

    @property
    def mounts(self):
        """mount point -> source, from mountinfo."""
        out = {}
        for line in (self.path / 'mountinfo').read_text().splitlines():
            left, right = line.split(' - ', 1)
            out[left.split()[4]] = right.split()[1]
        return out


class Check:
    """Collects failed assertions; a case passes when none failed."""

    def __init__(self):
        self.failures = []
        self.count = 0

    def __call__(self, ok, message):
        self.count += 1
        if not ok:
            self.failures.append(message)
        return ok

    def equal(self, actual, expected, message):
        return self(actual == expected, f'{message}: {actual!r} != {expected!r}')

    def contains(self, text, needle, message):
        return self(needle in text, f'{message}: {needle!r} not in {text[-400:]!r}')


def expected(boot):
    if boot.efi:
        return ['DIALOGUE', 'ok']
    return ['CUT', boot.cut] if boot.cut else ['DONE', 'ok']


def wait_for_exit(vm, seconds):
    """Keep a shutdown timeout in the original case result and boot history."""
    try:
        return vm.wait(seconds)
    except TimeoutError as error:
        return str(error)


def run(module, run_dir, boot_for, out_share):
    """boot_for(boot) -> dict for Vm(boot=...). Returns the result record."""
    if not module.BOOTS:
        raise RuntimeError(f'{module.ID}: no boots declared')
    config = accelerator_config()
    deadline = time.monotonic() + module.SECONDS
    run_dir.mkdir(mode=0o700)
    out = run_dir / 'out'
    out.mkdir(mode=0o700)
    if hasattr(module, 'prepare'):
        module.prepare(run_dir)
    previous = None
    boots = []
    for i, boot in enumerate(module.BOOTS, 1):
        vm_dir = run_dir / f'boot-{i}'
        spec = boot_for(boot)
        spec['append'] = f"{spec.get('append', '')} zt.case={module.ID} zt.stage={boot.stage}" \
            + (' zt.udev=1' if boot.udev else '') + (f' {boot.append}' if boot.append else '')
        record = {'stage': boot.stage, 'expected_cut': boot.cut}
        case_shares = module.shares(run_dir, boot) if hasattr(module, 'shares') else []
        case_images = module.images(run_dir, boot) if hasattr(module, 'images') else []
        memory = module.memory_mib(run_dir, boot) if hasattr(module, 'memory_mib') else default_memory_mib(module.ID)
        with Vm(vm_dir, spec, module.DISKS, memory_mib=memory, previous=previous, network=boot.network,
                images=case_images, case_root=run_dir, fresh_disks=boot.fresh_disks,
                # A firmware boot gets no shares unless it hands off to a guest stage.
                shares=[] if boot.efi and not boot.target else [('zt-out', out), *out_share(boot), *case_shares],
                deadline=deadline) as vm:
            channel = Channel(vm)
            if boot.efi:
                console = Console(channel.console, out / str(boot.stage), deadline,
                                  ssh_port=vm.ssh_port, case_dir=run_dir)
                try:
                    getattr(module, f'stage_{boot.stage}')(console)
                    record['event'] = ['DIALOGUE', 'ok']
                except (ConsoleError, TimeoutError, ValueError) as e:
                    # ValueError: a dialogue could not read what the Menu displayed.
                    (out / str(boot.stage) / 'FAILED').write_text(f'{e}\n')
                    record['event'] = ['DIALOGUE', 'failed']
                if boot.target and record['event'] == ['DIALOGUE', 'ok']:
                    kind, arg = channel.until({'CUT', 'DONE'}, deadline)
                    record['target_event'] = [kind, arg]
                    if kind == 'DONE':
                        record['exit'] = wait_for_exit(vm, 300 if boot.poweroff else 60)
                if boot.poweroff and record['event'] == ['DIALOGUE', 'ok'] and 'exit' not in record:
                    record['exit'] = wait_for_exit(vm, 300)
                record['killed'] = vm.kill()
            else:
                kind, arg = channel.until({'CUT', 'DONE'}, deadline)
                record['event'] = [kind, arg]
                if kind == 'CUT':
                    record['killed'] = vm.kill()
                else:
                    record['exit'] = wait_for_exit(vm, 60)
        if vm.image_paths:
            from host.uki import sha256
            record['images_after'] = {serial: {'sha256': sha256(path), 'bytes': path.stat().st_size}
                                      for serial, path in vm.image_paths.items()}
        boots.append(record)
        previous = vm_dir
        if (record['event'] != expected(boot)
                or (boot.target and record.get('target_event') != ['DONE', 'ok'])
                or isinstance(record.get('exit'), str)):
            break
    check = Check()
    ran_all = len(boots) == len(module.BOOTS)
    for boot, record in zip(module.BOOTS, boots):
        want = expected(boot)
        failed = Evidence(out).stage(boot.stage).failed
        check.equal(record['event'], want, f'stage {boot.stage} ended' + (f' ({failed[-600:]})' if failed else ''))
        if boot.target and record['event'] == want:
            failed = Evidence(out).stage(boot.target).failed
            check.equal(record.get('target_event'), ['DONE', 'ok'],
                        f'target stage {boot.target} ended' + (f' ({failed})' if failed else ''))
        if boot.poweroff and record['event'] == want:
            check.equal(record.get('exit'), 0, f'stage {boot.stage} guest powered off by itself, QEMU exit status')
        elif isinstance(record.get('exit'), str):
            check(False, f"stage {boot.stage} shutdown failed: {record['exit']}")
    check(ran_all, f'only {len(boots)} of {len(module.BOOTS)} boots ran')
    if not check.failures:
        try:
            evidence = Evidence(out)
            evidence.boots = boots  # per-boot records: event, exit, killed (QEMU status)
            module.verdict(evidence, check)
        except (KeyError, ValueError, OSError) as e:
            check(False, f'evidence incomplete: {e}')
    result = {'id': module.ID, 'pass': not check.failures, 'assertions': check.count,
              'failures': check.failures, 'boots': boots, 'accelerator': config,
              'qualification': not config['experimental']}
    (run_dir / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
