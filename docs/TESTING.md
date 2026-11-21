# Testing

Testing has two execution tiers: the everyday offline gate, `just test`, and
VM tests for behavior against real OpenZFS. The VM tier has three independent
suites: application acceptance, native API tests and native reader tests.

| Command | Prerequisites | Coverage |
|---|---|---|
| `just test` | Cached Cargo dependencies and the [offline tooling](#the-offline-gate); no root, ZFS module, VM or network | Rust tests, strict Clippy and formatting, file-only Python suites, and loading every acceptance case; no host storage changes |
| `python3 -I tests/acceptance/run.py run SESSION native efi` | A [prepared acceptance session](#qemu-acceptance), distribution output, factory tar, QEMU/KVM and OVMF | Real `zboot`, `zsnap`, `zpool` and `zfs` in disposable guests, including power cuts and firmware boots |
| `python3 tests/native-api/run.py --uki FILE --evidence DIR` | A verified UKI file and the [native API prerequisites](../tests/native-api/README.md#run-the-test) | An independent Rust consumer of the supported API alone checks checkpoint operations against real OpenZFS |
| `python3 tests/native-readers/run.py --uki FILE --evidence DIR` | A verified UKI file and the [native reader prerequisites](../tests/native-readers/README.md) | `zsnap`, built from its own package, runs protected reader jobs against real OpenZFS |

Retain a qualification record with the source revision, runtime and build
identities, selected cases, per-case results, and any missing or failed attempts.
Preserve the compact record separately before disposable session staging
expires. Results combined across revisions must name each revision and the
carry-forward rationale; they are not a full run at one commit. Local
qualification records may live under ignored `docs/archive/`; ignored files
need their own recoverable retention. Evidence needed for a shared release
must be supplied separately from the source snapshot.

Rules: a missing prerequisite is BLOCKED, never PASS; an empty or skipped
suite is no evidence; a component pass never marks a combined scenario done.
Engine tests against fakes do not stand in for native or EFI acceptance.

Comprehensive verification combines the offline gate and all three VM suites,
with their source, build and runtime identities recorded.

## Qualification scope

Development testing recorded 44 distinct QEMU cases passing on Debian
OpenZFS 2.4.4. Those passes span several revisions, with earlier results
carried forward after later fixes; they are not a full run at one final commit,
and `WIPE-SANITIZE-NATIVE`, added later, was not part of them. Failed and
incomplete attempts are kept in the maintainer's own qualification records.

Historical results do not qualify every later source revision or installed
package. A shared release needs its own source, build and runtime identities
and per-case results. The offline gate checks source and file-only behavior;
it does not replace native acceptance.

## The offline gate

```sh
just test
```

This runs `sh tests/check.sh`. The README lists the other optional `just`
shortcuts.

In order: `cargo fmt --all --check`; `cargo test --workspace --locked --offline`;
`cargo clippy --workspace --all-targets --locked --offline -- -D warnings`,
whose `clippy.toml` lets production code launch a child only through the
announcing wrapper in `engine/native.rs`, and a grep that no other source
lifts that rule; the same Clippy run on the `zfs-tools` package alone with no
features, so the supported library without the workspace-internal engine stays
free of dead code; a dynamic build of `zboot-helpers`;
`python3 -B -m unittest discover -s tests/tooling -p 'test_*.py'` (the
distribution helpers, the package's pending-operation gate, the signature probe,
the key relink helper and the boot console selection);
`python3 -B -m unittest discover -s tests/ci -p 'test_*.py'` (CI shard coverage
and qualification checks); `python3 -B tests/acceptance/test_fixtures.py`; and
`python3 -IB tests/acceptance/run.py list`, which loads every case. The gate passes
Cargo's JSON artifact manifest to the tooling suite, selecting the built helpers
and matching `libc` artifact. The helper tests compile the production Rust
sources against independent C ABI fault fixtures; those C fixtures remain test
inputs, with no device or ZFS operations. Cargo's dependencies must already be
cached, and the tooling suite needs `cc` with the libblkid development files,
the host's `libzfs_core.so.3` (zfsutils-linux), `/bin/busybox`,
`dpkg-deb`, `readelf` and `zstd`. `CHECK_JOBS` (default 8) sets
Cargo's jobs and `RUST_TEST_THREADS` (default 4) the test threads; keep both
bounded on a shared host. Allow approximately 8 GiB for a fresh build. To keep
all disposable build output in caller-owned disk staging:

```sh
check_stage=$(mktemp -d /var/tmp/zfs-tools-check.XXXXXX)
TMPDIR="$check_stage" CARGO_TARGET_DIR="$check_stage/target" sh tests/check.sh
```

Remove that exact staging directory after reviewing the result. Keep any logs
needed for diagnosis in a retained location before removing it.

Engine tests cut every effect and record write against in-memory fakes
(zboot's `restore/fake.rs`, `tree/fake.rs`, the pairs and transfer fakes) and
compare the whole normalized state with an uninterrupted run. The Rust tests
for each of DESIGN.md's safety rules sit beside the engine they cover, in its
`tests` module or `tests.rs`.

## VM tests

Each suite owns its disposable guests and private file-backed disks. Run the
suites independently; a full application acceptance run (`native efi`) does
not run or qualify the native API or native reader suites.

Acceptance takes a distribution **directory**, `--uki OUT`, containing
`OUT/SHA256SUMS` and `OUT/usr/lib/zboot/zboot.efi`. The native API and reader
runners instead take a UKI **file**, `--uki OUT/usr/lib/zboot/zboot.efi` or an
installed `/usr/lib/zboot/zboot.efi`. They boot its own kernel and initramfs,
and refuse the file unless it matches `OUT/SHA256SUMS` or the installed
package's record.

### QEMU acceptance

A session is built at an exact clean commit from one `dist/dist.sh`
output and, for the deploy and efi groups, a factory tar made with
[RECOVERY.md's rescue recipe](RECOVERY.md#rescue-sticks) (`RESCUE-STICK`
boots it as a rescue).

```sh
dist/dist.sh OUT
OUT/usr/bin/zboot factory ROOT.tar.zst --snapshot TIME --packages PKG,...
python3 -I tests/acceptance/run.py list
python3 -I tests/acceptance/run.py prepare FULL_OID --uki OUT --factory ROOT.tar.zst
python3 -I tests/acceptance/run.py prepare-efi SESSION neutral=OUT --factory ROOT.tar.zst
python3 -I tests/acceptance/run.py run SESSION native efi
```

| Verb | Does |
|---|---|
| `list` | lists every case: id, group, time bound, boots |
| `prepare OID [CASE|GROUP|native...] --uki OUT [--factory TAR] [--build-runner JSON|--distribution-tools --build-record JSON] [--min-free-gib N]` | makes a session under `STATE/runs/`. It checks that the checkout is clean at the full OID, freezes `tests/acceptance`, takes OUT's kernel and the UKI's own initramfs, builds release `zboot` and `zsnap` at OID with `build.sh` in the selected build scope, and builds one initrd per group with `tests/acceptance/build-initrd.sh`. Without selectors it prepares all native groups. Explicit case/group selectors prepare only the required fixture groups; EFI cases require the small fixture and the separate `prepare-efi` step. `deploy` needs `--factory`. `--distribution-tools --build-record JSON` verifies OUT/SHA256SUMS plus the build record source OID and hashes for the UKI, kernel and both tools, then copies OUT tools instead of rebuilding. The session retains the record and provenance records tool hashes. The CI build record provides the required `source_oid` and `files` map, with paths relative to its directory. |
| `prepare-efi SESSION NAME=OUT... [--factory TAR]` | records each OUT for firmware boots: a boot stick with its UKI as `EFI/BOOT/BOOTX64.EFI`, and a setup initrd of its own kernel, initramfs and `zboot`, with its UKI and the factory tar on the fixtures share. Cases use `neutral` unless they name another. The efi and deploy groups, `RESTORE-PAIRED-NATIVE` and `RESTORE-RETURNED-ERROR-NATIVE` need it. It needs a session prepared with `small`, and records the OVMF files' hashes; a later run refuses if they changed. |
| `run SESSION CASE\|GROUP\|native... [--dev]` | runs the cases one VM at a time and prints PASS or FAIL, the time, the assertion count and the run directory for each, then the total; it exits 1 if any failed. `native` is every group but efi. `--dev` runs this tree's runner, cases and guest scripts against the session; such a result is a diagnostic, not a qualification. |

`prepare-efi` and qualification `run` execute the session's frozen runner, host
helpers, cases and guest scripts together. `run --dev` uses the current checkout
and reports a diagnostic result. The handoff preserves the process identity and
signal handling so the selected runner retains custody of its guests.

Qualification uses `/dev/kvm` and the host CPU model. KVM accelerates guest
CPU execution; it is not required by OVMF firmware. A TCG diagnostic on a
GitHub-hosted runner also booted firmware successfully. No backend fallback is attempted. `ZBOOT_VM_ACCEL=tcg` explicitly selects experimental software emulation
with CPU `max`; its results are marked diagnostic, and its timing is not KVM
qualification. Launch receipts record the backend, CPU and RAM. Python 3.14 or
newer is required (`tarfile` reads zstd from 3.14). Guest RAM uses preallocated
memfd pages with two allocation workers. SMOKE defaults to 2048 MiB, as exercised
on a standard GitHub-hosted runner with KVM. Other cases default to 8192 MiB;
the CI workflow explicitly selects 4096 MiB, with a 6144 MiB ceiling for
RAM-BOOT's computed allocation. `ZBOOT_VM_MEMORY_MIB` overrides defaults for
cases without an explicit memory hook; case-specific hooks retain their product
contracts.
RAM-BOOT computes its positive allocation from the actual tar, unpacked contents
and kernel, with 1 GiB runtime headroom and a 2 GiB minimum. It accounts for
upload, staged-initrd and kexec copies, records the formula in `ram-inputs.json`,
and keeps its negative leg below the product admission requirement. For this
case, `ZBOOT_VM_MEMORY_MIB` is a ceiling: an oversized root fails preparation
with its required allocation. Before each launch the case also requires 1 GiB
of host MemAvailable beyond the selected guest allocation.

Preparation checks space for the known input copies plus an optional caller
reserve (`--min-free-gib N`). This is a lower bound, not a total peak-space
estimate: build staging, initrd unpacking/repacking, subsequent firmware sticks
and VM disk growth need additional space. `resources.json` records selected
cases, prepared groups, this floor, the reserve, free space before/after and the
allocated session bytes. Sparse virtual disk capacities are not resident host
allocations; their actual growth depends on the selected workload. Keep successful
sessions only as long as needed. For a bounded first check, prepare `SMOKE`
(or `small`) instead of every group; no universal 32 GiB free-space gate applies.
Stick images need mtools and `sfdisk`; firmware boots need
`/usr/share/OVMF/OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`. One case runs at a time
host-wide, under a shared `flock`; only `run` starts a VM.

Environment: `ZBOOT_ACCEPTANCE_SOURCE` (the clean checkout; default this
repository), `TMPDIR` (an existing disk-backed temporary directory; default
`/var/tmp`), `ZBOOT_ACCEPTANCE_STATE` (sessions; default
`TMPDIR/zboot-acceptance`), and `ZBOOT_ACCEPTANCE_LOCK` (default
`STATE/qemu.lock`). Keep the state directory under the selected `TMPDIR`:
`build-initrd.sh` permits only new output/provenance files and new bulk
fixture directories beneath that resolved root, and refuses existing paths or
symlink escapes. This rule also applies to `prepare-efi` on an existing session;
use its original temporary root. Sessions and published fixtures belong to the
caller and are not deleted by the runner, with one exception: when a case
passes, `run` removes that case's VM disk images, sticks and per-boot kernel,
initrd and firmware copies, which the session's OID and OUT reproduce. They
were nearly all of a session's bytes, and nobody removed them: in November
2026 four task directories of sessions held 500 GiB on one host. The case's
`result.json` records the bytes removed. A failed case keeps everything, and
`ZBOOT_ACCEPTANCE_KEEP_IMAGES=1` keeps a passed case's images too.

#### Selecting the build scope

By default, each acceptance build owns a fresh private temporary directory
under `TMPDIR`, supplies its own `CARGO_TARGET_DIR`, and removes that staging
after the build and its artifact
copy finish. It never reuses or deletes an inherited Cargo target. Product
builds use `CARGO_BUILD_JOBS` (default 4), a 40-minute timeout, and need roughly
4 GiB of staging. Local build processes run in a dedicated process group,
which is stopped before staging cleanup on completion, failure or timeout.
Session logs and explicitly published binaries, fixtures and receipts survive.
The local scope has no disk quota; reserve this space before running it.

A host manager can own the complete build/consumer scope instead. Pass
`--build-runner` to `prepare` as a JSON array of literal argv entries. The
array prefixes the build command; it is never parsed as shell text. The runner
must supply a fresh owned `CARGO_TARGET_DIR` and keep it alive until the
command and all consumers finish. The build publishes its small final
artifacts before its scope ends; no later step reads a retired target. Do not
wrap `prepare` in a temporary build scope and then reuse that scope's target
from another process after it ends.

Without an external runner, `prepare` uses the default private staging:

```sh
TMPDIR=/your/disposable/staging python3 -I tests/acceptance/run.py prepare FULL_OID \
    --uki OUT --factory ROOT.tar.zst
```

#### How a case runs

A case is `cases/<id>.py` (`ID`, `GROUP`, `SECONDS`, `DISKS`, `BOOTS`,
`verdict`) plus `guest/cases/<ID>.sh` with one `stage_N` per boot. The guest
side is POSIX `sh` on the runtime's busybox.

- **Disks.** Each case gets private sparse files: virtio disks with serials
  `ZFS-E2E-A`, `-B` and `-D`, the stick as `ZFS-E2E-C`, and an emulated NVMe
  disk `ZFS-E2E-N` when a case asks. No host device is attached. Later boots
  hard-link the previous boot's files, so a restart sees exactly the bytes a
  killed guest left.
- **Evidence.** `guest/lib.sh` `step`, `must` and `refuse` record each
  command's argv, stdout, stderr and status on the run's writable 9p
  share. `observe` records native state read with `zpool` and `zfs` (pools,
  each dataset's guid and createtxg, all properties, holds, mountinfo,
  status), `payload` file hashes and `scrub` a full scrub. The host's
  `verdict` asserts over those files, never over zboot's word alone.
- **Serial.** ttyS0 is the console; ttyS1 carries only `ZT1 BEGIN|CUT|DONE`.
- **Power cuts.** Every initrd routes `zfs` through `guest/fault.sh`.
  `arm NAME zfs MATCHER [after]` makes the next matching call record its
  argv, write `ZT1 CUT NAME` and block; the host then kills QEMU and boots the
  next stage on the same disks. With `error-before` or `error-after` the call
  instead returns status 97, before or after the real call, and the stage
  goes on. Only `zfs` calls can be cut.
- **Firmware boots.** `Boot(n, efi=True)` boots a recorded build's stick
  under OVMF with fresh variables, and the module's `stage_n(console)` drives
  the menu over ttyS0 (`host/console.py`), recording each exchange as
  evidence. `extra={'from': 'A'}` boots disk A's own ESP with no stick. With
  `target=m` the menu's handoff lands in the acceptance initrd inside a BE
  whose saved `zboot:cmdline` selects guest stage m. A direct boot with
  `extra={'setup': NAME}` runs that build's kernel, initramfs and `zboot`.
  `network=True` adds one user-mode NIC with no outside access and a
  loopback SSH forward.
- **Result.** A case passes when every boot ended as declared (DONE, the
  named CUT, or a finished dialogue) and its verdict recorded no failure.
  `SESSION/cases/ID-UTC/` keeps `result.json`, the evidence (`out/`) and each
  boot's console, test channel and QEMU logs. A failed case also keeps its
  disk images and boot inputs; a passed one does not.

The native groups boot OUT's kernel with an initrd made of the UKI's own
initramfs, the guest scripts, the session's `zboot` and `zsnap` (which replace
the UKI's), and a few host tools. By default the tools are built at OID;
`--distribution-tools` instead copies them from the verified distribution,
retaining its producer identity and requiring identical Git product inputs.
The esp and restore groups get the session's UKI as the loader on a read-only
fixtures share; deploy also gets the factory tar. A native result claims the
behaviour of those binaries on that runtime. The efi group boots the UKI
itself under OVMF.

Restore cuts in the native group land at exact record boundaries; every
phase's cut is covered against the fake (`every_cut_resumes_to_the_same_result`).
Guided EFI cuts are host-side: the stick runs no fault shim, so the host
kills QEMU when the menu prints a phase, which lands at or after it.

#### Cases

| Group | Case | What it checks |
|---|---|---|
| small | `SMOKE` | the harness itself: a product command, native evidence, a cut and a restart |
| small | `BOOT-PAIR-CYCLE-NATIVE` | a paired BE (one dataset) through bootstrap, incremental sync, `primary` to B and back: receiver-local `zboot:cmdline` kept, a copied user property local on both; a shared dataset's secondary stays unmounted across a reboot |
| small | `BOOTSTRAP-NATIVE` | `sync` creating an absent copy of a leaf, with its copied properties local, and refusing a source with a child; plain `unpair`, anchor release; a foreign hold kept and a deferred destroy completed |
| small | `CAPTURE-READER-NATIVE` | recursive capture, IV sets and `written@`; a `zsnap protect` task with two view aliases: native holds and destroy refusal while reading, cleanup with snapshots preserved, deferred release refused by default and completed through recovery, foreign holds kept |
| small | `FORK-NATIVE` | a boot environment clone, refusal of a BE with a child and of a data tree, and recovery from a power cut after the clone |
| small | `INCREMENTAL-IDENTITY-NATIVE` | per-dataset raw incrementals without properties into a locked receiver keep identities and local placement |
| small | `INV-01-NATIVE` | recursive inventory: identities, encryption, stability across a rename |
| small | `LOSS-NATIVE` | confirmed loss: `rollback` across a power cut, snapshot and tree `drop` |
| small | `MAINTENANCE-NATIVE` | `chroot` into a BE, and its refusal of a paired secondary |
| small | `MENU-DISCOVERY-NATIVE` | the menu stays responsive while an import child holds the writer lock |
| small | `MOVE-BY-PAIR` | moving a data leaf, a BE and a tree (leaf by leaf, into its own container) to another pool with `sync`, `primary`, `unpair --release-anchors` and `drop`, the boot default included |
| small | `PAIR-REFUSALS-NATIVE` | `pair` refuses the same GUID with another IV set, and a dirty receiver head |
| small | `PAIR-UNPAIR-NATIVE` | `pair` and `unpair` of leaves: refusals (no shared snapshot, a clone, a child, the ahead side second), a copy missing an older snapshot pairs, publication, repeat, re-pair, anchor release |
| small | `PRIMARY-NATIVE` | `primary`: refused while a child exists, catch-up switch, replay, activation alone |
| small | `RAW-HEAD-NATIVE` | per-dataset raw receivers without properties: identities, IV sets, each its own encryption root; zvol `written` |
| small | `RENAME-NATIVE` | `rename` of a clone-connected tree: identities, placement, `bootfs`, replay |
| small | `RESTORE-PROPERTIES-NATIVE` | restore's per-dataset staging and return streams through Debian's own `zfs receive`: no property travels, fences and creation values are local, new raw copies are their own encryption roots, snapshot GUIDs kept |
| small | `RET-02-NATIVE` | zsnap capture, policy inheritance, scheduled runs and retention protections |
| small | `STOCK-RECEIVE-PROBE` | the OpenZFS facts the stock pipeline rests on, with `zfs` alone; see [Stock receive properties](DESIGN.md#stock-receive-properties) |
| small | `STOCK-SYNC-NATIVE` | a pair end to end: copied properties local on the copy (`copies=2` governs the received blocks); zsnap prunes the working copy and refuses the fenced one; `sync` shows the pending deletion, an unattended sync keeps it, `--confirm` deletes it; a renamed snapshot matched by GUID; an interrupted sync abandoned and continued; `primary` and a sync back into an installer-made encrypted leaf under an equal passphrase wrapping, refused before data after `change-key`; a fenced zvol copy with no device, also after an import |
| small | `TRANSFER-EXTERNAL-ER-NATIVE` | a locked leaf whose key comes from outside it becomes its own encryption root on another pool, its copied properties local |
| small | `TRANSFER-NATIVE` | `sync` into an existing copy: refused until paired; push, with a child under the leaf reported and `sync --all` exiting 4; read-only pull |
| small | `WIPE-NATIVE` | the imported-disk refusal, then confirmed metadata clearing of a virtio and an NVMe disk, verified by probes |
| small | `WIPE-SANITIZE-NATIVE` | the native sanitize path on the emulated NVMe disk against a fake `nvme` (`guest/fake-nvme.sh`): a crypto erase seen running and verified on the disk, a sanitize already running after a power loss waited out first, a failed sanitize refused with nothing cleared, then a wipe in failure mode refused before any effect |
| esp | `ESP-NATIVE` | one `esp` batch keeps loader ownership and file names on both imported-pool disks, leaves rescue media alone, installs after a typed answer and meets an ESP that turns read-only late; the files read back after a cold boot |
| deploy | `DEPLOY-NATIVE` | whole-disk `deploy` of the factory tar with a host overlay (a file and a hook): GPT, read-only import by GUID, `@factory` and `@deployed`, overlay owner and mode, identity; the deployed system then boots and erases a spare disk itself, with the probe its package installed |
| deploy | `DEPLOY-INTO` | `deploy --into` adds a bootable sibling and keeps the defaults; a power cut at `@factory`, `drop`, a retry and a UKI handoff |
| deploy | `RESCUE-STICK` | `deploy --image --portable` with `builtin:rescue`, booted on different machines: no host in the labels, console and SSH login, new host keys each boot, two copies of one image |
| restore | `RESTORE-ABANDON-DROP-NATIVE` | `abandon` keeps the only copy held and marked; `drop` releases and destroys it |
| restore | `RESTORE-CHANGED-KEPT-NATIVE` | kept data changed after staging is never erased (cut before step 7) |
| restore | `RESTORE-KEPT-MOUNTS-NATIVE` | kept BE, home and volumes survive a cut before the step-11 record and `resume` |
| restore | `RESTORE-KEYS-NATIVE` | a kept `file://`-keyed tree is refused while its key is missing and stays encrypted after; its inheriting child is relinked to the copied root by `zboot-change-key` |
| restore | `RESTORE-MENU-RESUME-NATIVE` | `resume` in the UKI completes a restore cut before step 9 |
| restore | `RESTORE-PAIRED-NATIVE` | a paired secondary on B restored onto A; B's side of the ended pair keeps its holds and B boots again |
| restore | `RESTORE-READONLY-DEFAULT-NATIVE` | a read-only pool naming a boot default holds the restore until it is writable |
| restore | `RESTORE-RETURNED-ERROR-NATIVE` | errors returned at two restore boundaries reach the CLI's cleanup |
| efi | `EFI-HANDOFF-NATIVE` | the menu refuses B while A has a `canmount=on` child, still boots A, then boots B with its saved command line; each BE mounts only its own children |
| efi | `EFI-CONNECT` | one-boot ESP keys, login, the ten-minute expiry, `connect`'s one-time password, SSH repair, cleanup after the menu dies, and `reboot --menu` from the installed system |
| efi | `GUIDED-RESTORE-EFI-NATIVE` | a stick restores A in the menu; A then boots from its own ESP |
| efi | `GUIDED-RESTORE-RESUME-BASE`, `-RELEASE`, `-PUBLISH` | the same with a power cut at `staged`, `erased` or `properties restored`, then `resume` from a fresh boot |
| efi | `GUIDED-DIRTY-PORTABLE-MENU` | after power cuts leave A's and B's pools active, A's own UKI and the stick adopt the hostid and import both read-only without force |
| efi | `PXE-MENU` | the firmware's UEFI HTTP boot fetches the UKI with no disk loader; it runs its own command line, lists and boots the local BE, and `connect` admits a login |
| efi | `RAM-BOOT` | `boot --tar` of the rescue tar with `builtin:rescue` and an access overlay: console and key logins, DHCP, DNS through systemd-resolved (the NIC has no outside access and DHCP gives no DNS server, so the name is resolved's own `_localdnsstub`), an import of the local pool; again with no pool; refused with too little RAM |

#### Coverage of the safety rules

The rules are DESIGN.md's; these cases exercise them natively.

| Rule | QEMU |
|---|---|
| 1. No write to an in-use or unconfirmed disk | `WIPE-NATIVE`, `WIPE-SANITIZE-NATIVE`, `DEPLOY-NATIVE` (a wrong token exits 3, the disk unchanged), `ESP-NATIVE` |
| 2. The UKI imports read-only and reopens a pool writable only after the answer | `GUIDED-RESTORE-EFI-NATIVE`, `GUIDED-DIRTY-PORTABLE-MENU` |
| 3. Fence before the final capture; activate after a verified transfer | `PRIMARY-NATIVE`, `BOOT-PAIR-CYCLE-NATIVE` |
| 4. Loss is exactly the approved scope | `LOSS-NATIVE`, `MOVE-BY-PAIR`, `PAIR-REFUSALS-NATIVE`, `TRANSFER-NATIVE`, `STOCK-SYNC-NATIVE`, `RESTORE-CHANGED-KEPT-NATIVE` |
| 5. Interrupted operations resume or are abandoned; the record and keys live off the disk being erased | the restore cut cases, `GUIDED-RESTORE-RESUME-*`, `RESTORE-KEYS-NATIVE`, `LOSS-NATIVE`, `FORK-NATIVE`, `DEPLOY-INTO`, `STOCK-SYNC-NATIVE` |
| 6. One boot default per host; one reviewed `spl.spl_hostid` per handoff; hostid adoption | `EFI-HANDOFF-NATIVE`, `GUIDED-RESTORE-EFI-NATIVE`, `GUIDED-DIRTY-PORTABLE-MENU`, `RESTORE-READONLY-DEFAULT-NATIVE`, `MOVE-BY-PAIR` |
| 7. Anchors stay held until a newer verified base exists | `BOOTSTRAP-NATIVE`, `PAIR-UNPAIR-NATIVE`, `STOCK-SYNC-NATIVE`, `RET-02-NATIVE` |
| 8. A secondary, an inactive BE's children and staging never mount by themselves | `BOOT-PAIR-CYCLE-NATIVE`, `STOCK-SYNC-NATIVE` (no zvol device), `EFI-HANDOFF-NATIVE`, `DEPLOY-NATIVE`, `RESTORE-PROPERTIES-NATIVE`, `RESTORE-KEPT-MOUNTS-NATIVE` |

QEMU's emulated NVMe has no Sanitize command, so `WIPE-NATIVE` takes metadata
clearing there too, and `WIPE-SANITIZE-NATIVE` drives the sanitize path
through a fake `nvme`. [Real hardware](#real-hardware) records sanitize runs on
physical controllers.

#### Slowest cases

An earlier local estimate was roughly an hour and three quarters of VM time
for a full sequential run, plus image, factory and session preparation. These
historical timings use one KVM VM at a time; they are not hosted-runner estimates.
CPU, storage and available memory affect the result.

| Case | Minutes | Where the time goes |
|---|---|---|
| `EFI-CONNECT` | 15.0 | waits out the real ten-minute remote-access window |
| `RESTORE-PAIRED-NATIVE` | 6.5 | a paired secondary restored onto A, then B's pair ends and B boots again |
| `MOVE-BY-PAIR` | 4.3 | a cross-pool move through `sync`, `primary`, `unpair` and `drop` |
| `RESTORE-MENU-RESUME-NATIVE` | 3.8 | the UKI's `resume` completes a cut restore |
| `GUIDED-*` (five cases) | 3.3–3.5 each | firmware boots of the UKI and the restored host |

The slow cases spend their time on the behavior they test. Each `run` takes
the lock named by `ZBOOT_ACCEPTANCE_LOCK`. Separate lock paths allow concurrent
runs; reserve CPU, guest RAM and disk staging for every concurrent run before
using them.

### Native API tests

[tests/native-api](../tests/native-api/README.md) covers the supported library
API independently of `zboot` and `zsnap`. Its guest checks complement the
offline tests for process ownership and cleanup, and application acceptance.
See its README for prerequisites, execution and evidence limits.

### Native reader tests

[tests/native-readers](../tests/native-readers/README.md) covers supervised
`zsnap protect` and `zsnap recover` reader jobs against real OpenZFS. See its
README for prerequisites, execution and evidence limits.

## Real hardware

These runs used the integration build on a laptop on 2026-11-16, with
nvme-cli 2.16, two NVMe disks and no VM:

- SK hynix Platinum P41 2 TB (PCIe `1c5c:1959`): block erase only, no
  namespace management;
- XPG GAMMIX S11 Pro 1 TB (PCIe `1cc1:8201`): crypto and block erase; the
  kernel ignores its subsystem NQN (the `IGNORE_DEV_SUBNQN` quirk).

Results:

- Three `zboot wipe` runs on the P41 completed by block erase, each in about
  3.6 s. Each time lsblk, `blkid -p`, wipefs, sgdisk and raw reads found the
  disk blank.
- A stale token was refused.
- A wipe started while a raw sanitize was running on the P41 waited it out,
  then submitted and observed its own sanitize (6.5 s).
- A wipe of the XPG, which backed the imported root pool, was refused.
- `deploy DISK --empty` on the P41 sanitized, partitioned and created the pool
  and ESP. `sync` of the running root BE then created its copy there and
  paired the two, and `esp` refreshed both ESPs, including an earlier build's
  `EFI/zboot/zboot-recovery.efi` stamped `ID=zfs-tools`.

- Three unattended reboots went through the new UKI on the P41's ESP: the
  firmware started it, the Menu counted down and handed over to the default
  with the adopted `spl.spl_hostid`, and each boot was back in about 60 s.
  The first booted the unchanged default on the XPG.
- After `unpair --release-anchors`, `primary` (activating the unpaired copy)
  and `default`, the second reboot came up on the copy on the P41. The third,
  after `default` back from there, came up on the XPG again. `primary` from
  the running system refused to fence the running root, as designed.
- `drop` of the diverged copy and a new `sync` then restored the pair, and the
  post-transfer boundary cleanup ran on both sides.

In these runs only the P41 completed a sanitize; the XPG's crypto erase first
ran on 2026-11-19 (below).

The single operation record (attachments, no journals) ran on the same
laptop on 2026-11-17:

- The earlier build's 13 cleared journal headers made both BEs `boot blocked`
  through the unknown-property refusal; `zfs inherit` removed them by hand.
- Two `sync` runs of the running root BE took 14 s each and left no
  `zboot:journal:` or `zboot:attachment:` property and no operation record;
  both sides then held the same newest snapshot GUID.
- `esp` refreshed both ESPs, and an unattended reboot through the new UKI was
  back on the XPG's default in 58 s.

Every verb of both commands ran on the same laptop on 2026-11-19, from builds
of this branch, with both NVMe disks and the USB stick erased along the way:

- On the running system: `status` in each form, `trace`, `snapshot`, `fork`,
  `default`, `cmdline`, `chroot`, `rename`, `rollback`, `drop`, `pair`,
  `sync` (a new copy, pending deletions reviewed with a token, `--all`),
  `primary` (lossless and diverged), `unpair` (plain, `--release-anchors`,
  gone peer), `resume` and `abandon` of syncs killed mid-transfer, `esp`,
  `factory`, `deploy --image` (with and without `--portable`),
  `deploy --into`, `deploy DISK --empty`, `wipe` and every `zsnap` verb,
  including `recover` of a protect job whose owner was killed.
- `wipe` of the P41 completed by block erase in 3.5 s; lsblk, `blkid -p`,
  wipefs, sgdisk and raw reads found it blank.
- `reboot --menu --key` reached the Menu after `esp` had rewritten the booted
  ESP; over SSH from `connect`, `primary` moved the working copy and the
  default to the P41, and `restore` rebuilt the XPG from it, keeping one
  dataset. The XPG's controller then reported a completed crypto erase
  (sanitize log `SCDW10 0x4`, `SSTAT 0x101`). `boot --tar` started a rescue
  in RAM.
- From that rescue, `drop` removed the restore staging, `deploy DISK --tar`
  installed afresh on the P41 and `default` chose between the two defaults;
  unattended reboots came up on the fresh host in 56 s and on the restored
  XPG system with the kept data intact.
- The first USB stick died during `deploy --portable` (the kernel reported
  the medium gone); deploy stopped with exit 4. A second stick of the same
  model reported the same serial, and while both were attached zboot refused
  to plan on either. With one attached, `deploy --portable` wrote the rescue
  stick (metadata clearing) in 6 min, and a firmware `BootNext` boot through
  its UKI counted down to the host's default.
- Later the same day, a build with the open findings fixed: it installed over
  the earlier build as a plain upgrade (the commit-time version). The running
  root, with a `fork` of it present, paired with a pool in an image file;
  three syncs kept the fork's origin, status showed the clones and
  `snapshots level`, and a `fork` while paired worked and `chroot` ran in it,
  while a fork of the fenced copy was refused. `reboot --menu --key` with a
  plain key brought up the Menu's SSH by itself in 35 s, which a one-second
  carrier wait had prevented on the USB Ethernet adapter twice before, and
  `boot` of the default from that session came up on it.
- A third round, the same evening: after a firmware BootNext boot through
  the stick's ESP, `reboot --menu` refused and listed both fixed-disk zboot
  ESPs with their models; `--esp` the one the firmware boots brought the
  Menu's SSH up by itself in 40 s. `boot -v` there ran 12 full dataset
  listings before the handoff lock, where it had run 29. A non-tar `--tar`
  and an unstartable `zdb` were refused naming the file and the program. Of
  the two pools that an OpenZFS 2.4 system had created, the one written
  through `zfs receive` (a restore) stayed writable by OpenZFS 2.3, with
  block cloning only enabled; the one a 2.4 rescue deployed from a tar had
  block cloning active and imported only read-only there.

## CI

The offline gate can run in CI. Install the host tooling listed above and run
`cargo fetch --locked` before `just test`, because the gate itself uses Cargo's
offline mode. A missing dependency must fail the job rather than skip tests.

Run VM suites separately on a runner with KVM, the required storage and the
recorded build artifacts. A green offline job does not establish that the VM
suites passed.

GitHub Actions has two workflows:

- `offline.yml` runs on pushes, pull requests and manual dispatch. It fetches
  locked dependencies before the offline gate, uses two Cargo workers, and
  optimizes test code with debug assertions and overflow checks enabled.
  Production build profiles are unchanged. A newer run cancels an obsolete
  offline run on the same branch.
- `qualification.yml` is manually dispatched. With `run_vm=false` it builds
  the pinned distribution and matching rescue factory root. With
  `run_vm=true` it also runs every acceptance case and both independent native
  proofs, in bounded KVM shards, and requires complete results at one source
  and build identity. Missing, failed, mixed-build or experimental results
  cannot produce a passing aggregate. With `release_tag=vX.Y.Z` (which needs
  `run_vm=true` and a new tag) a passing run publishes that release from the
  qualified build itself: the package, the UKI, the corresponding source and
  their `SHA256SUMS` ([BUILD](BUILD.md#releases)).

```sh
gh workflow run qualification.yml --repo OWNER/REPO --ref BRANCH -f run_vm=true
gh workflow run qualification.yml --repo OWNER/REPO --ref BRANCH -f run_vm=true -f release_tag=vX.Y.Z
gh run list --repo OWNER/REPO
```

Qualification keeps two kinds of artifact. The build's record (logs, build
identity, hashes and package lists, a few megabytes) and each shard's small
assertion evidence, setup logs and source/runtime identities are kept for 14
days, and are uploaded even on failure; raw VM disks and private login keys are
excluded. Retain a compact qualification record before they expire. With
`run_vm=true` the build also uploads a handoff for the shards and the release:
the mode-preserving distribution archive with its matching corresponding source
(about 0.9 GB) and the factory tar (about 0.55 GB). Each consumer verifies their
hashes before use. A cleanup job deletes the handoff when the run ends, and it
expires after one day if that job never runs. A failed run is repeated as a
whole run; rerunning only its failed jobs finds no handoff.

Artifact storage on a private repository is billed by GB-hours accrued over
the billing cycle, not by what is currently stored, and deleting an artifact
does not return storage already accrued. A GitHub Free account's 500 MB
allowance is about 360 GB-hours a month; a deleted handoff costs a few GB-hours
per run, one kept for 14 days more than the whole month. Once the allowance is
spent every upload fails until the next cycle, so a job whose tests passed
still reports failure. Public repositories are not charged.

`tests/ci/runner-setup.sh` is guarded for disposable GitHub-hosted runners. It
uses sudo for package installation, KVM device permissions and user-namespace
setup. Build jobs retain preinstalled SDKs; VM and offline jobs remove named
SDKs. It must not be used as local host setup. QEMU and the
distribution/factory builders run as the ordinary user; no Docker or libvirt
daemon is needed. Acceptance shards use the distribution's tools and do not
install Rust or fetch crates; the independent native proofs build their
consumers from the matching source. A pinned distribution and factory build
grew the runner's filesystem by about 6.4 GiB, starting from about 12.5 GiB
free on a standard runner; that is separate from BUILD.md's generic 24 GiB
distribution-staging estimate.

## Updating OpenZFS

zboot carries no OpenZFS of its own: it runs the host's `zfs`, and the UKI
the one from the `build.lock` snapshot. After moving the snapshot to a new
OpenZFS, run `STOCK-RECEIVE-PROBE` first, for the facts the stock pipeline
relies on, then `STOCK-SYNC-NATIVE` and the native groups.
