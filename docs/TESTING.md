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

Rules: a missing prerequisite is BLOCKED, never PASS; an empty or skipped
suite is no evidence; a component pass never marks a combined scenario done.
Engine tests against fakes do not stand in for native or EFI acceptance, and
the offline gate does not replace native acceptance.

## Qualification

Comprehensive verification combines the offline gate and all three VM suites
at one source revision, with its source, build and runtime identities
recorded. Results qualify only the exact source, build and runtime tested;
earlier passes do not qualify a later revision or installed package. A release
is qualified and published by CI ([CI](#ci), [BUILD](BUILD.md#releases)).

Retain a compact qualification record before disposable session staging or CI
artifacts expire: the source revision, runtime and build identities, the
selected cases, per-case results, and any missing or failed attempts. Results
combined across revisions must name each revision and the carry-forward
rationale; they are not a full run at one commit. Local records may live
under the ignored `docs/archive/`, which needs its own recoverable retention;
evidence for a shared release is supplied separately from the source snapshot.

## The offline gate

```sh
just test
```

This runs `sh tests/check.sh`, in order: `cargo fmt --all --check`;
`cargo test --workspace --locked --offline`; `cargo clippy --workspace
--all-targets --locked --offline -- -D warnings`, whose `clippy.toml` lets
production code launch a child only through the announcing wrapper in
`engine/native.rs`, and a grep that no other source lifts that rule; a dynamic build of `zboot-helpers`; the file-only Python suites in
`tests/tooling` (the distribution helpers, the package's pending-operation
gate, the signature probe, the key relink helper and the boot console
selection) and `tests/ci` (CI shard coverage and qualification checks);
`tests/acceptance/test_fixtures.py`; and `tests/acceptance/run.py list`, which
loads every case.

The gate passes Cargo's JSON artifact manifest to the tooling suite, selecting
the built helpers and matching `libc` artifact. The helper tests compile the
production Rust sources against independent C ABI fault fixtures, with no
device or ZFS operations. Cargo's dependencies must already be cached, and the
tooling suite needs `cc` with the libblkid development files, the host's
`libzfs_core.so.3` (zfsutils-linux), `/bin/busybox`, `dpkg-deb`, `readelf` and
`zstd`. `CHECK_JOBS` (default 8) sets Cargo's jobs and `RUST_TEST_THREADS`
(default 4) the test threads; keep both bounded on a shared host. Allow about
8 GiB for a fresh build. To keep all build output in caller-owned staging:

```sh
check_stage=$(mktemp -d /var/tmp/zfs-tools-check.XXXXXX)
TMPDIR="$check_stage" CARGO_TARGET_DIR="$check_stage/target" sh tests/check.sh
```

Remove that exact directory after reviewing the result, keeping any logs
needed for diagnosis.

Engine tests cut every effect and record write against in-memory fakes
(zboot's `restore/fake.rs`, `tree/fake.rs`, the pairs and transfer fakes) and
compare the whole normalized state with an uninterrupted run. The tests for
each of DESIGN.md's safety rules sit beside the engine they cover, in its
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

A session is prepared at an exact clean commit from one `dist/dist.sh`
output and, for the deploy and efi groups, a factory tar made with
[RECOVERY.md's rescue recipe](RECOVERY.md#rescue-sticks) (`RESCUE-STICK`
boots it as a rescue).

```sh
dist/dist.sh OUT
OUT/usr/bin/zboot factory ROOT.tar.zst --snapshot TIME --packages PKG,...
python3 -I tests/acceptance/run.py list
python3 -I tests/acceptance/run.py prepare FULL_OID --uki OUT --factory ROOT.tar.zst
python3 -I tests/acceptance/run.py run SESSION native efi
```

| Verb | Does |
|---|---|
| `list` | lists every case: id, group, time bound, boots |
| `prepare OID [CASE|GROUP|native...] --uki OUT [--factory TAR] [--distribution-tools --build-record JSON]` | makes a session under `STATE/runs/` for the selected cases (default: all). It checks that the checkout is clean at the full OID, takes OUT's kernel and the UKI's own initramfs, builds static release `zboot` and `zsnap` at OID, and builds the one acceptance initrd with `tests/acceptance/build-initrd.sh`. The fixtures share holds the UKI, the factory tar and the acceptance kernel and initrd. When a selected case boots firmware, it also writes a boot stick with the UKI as `EFI/BOOT/BOOTX64.EFI` and records the OVMF files' hashes; a later run refuses if they changed. The deploy and efi groups need `--factory`. `--distribution-tools --build-record JSON` verifies the build record's `source_oid` and its `files` hashes for the UKI, kernel and both tools (paths relative to the record), then copies OUT's tools instead of rebuilding; the session retains the record. Every direct boot runs the session's tools, and `RESCUE-STICK` checks that the deployed factory root carries the same `zboot`, so prepare it with the tools of the OUT the factory tar was made from. |
| `run SESSION CASE\|GROUP\|native... [--dev]` | runs the cases one VM at a time and prints PASS or FAIL, the time, the assertion count and the run directory for each, then the total; it exits 1 if any failed. `native` is every group but efi. It requires the checkout clean at the session's OID; `--dev` instead runs this tree's runner, cases and guest scripts as they are, and such a result is a diagnostic, not a qualification. |

VM tests require `/dev/kvm` and use the host CPU model; there is no
software-emulation fallback. Launch receipts record the QEMU argv and guest
RAM. Python
3.14 or newer is required (`tarfile` reads zstd from 3.14). Guest RAM uses
preallocated memfd pages. SMOKE defaults to 2048 MiB, other cases to 8192 MiB;
CI selects 4096 MiB. `ZBOOT_VM_MEMORY_MIB` overrides the default for cases
without their own memory hook. RAM-BOOT computes its allocation from the
actual tar, unpacked contents and kernel (1 GiB headroom, 2 GiB minimum,
recorded in `ram-inputs.json`), and keeps its negative leg below the product's
admission requirement; for it `ZBOOT_VM_MEMORY_MIB` is a ceiling (CI: 6144
MiB), and an oversized root fails preparation. Every launch also requires
1 GiB of host MemAvailable beyond the guest allocation.

Preparation needs space for the session's copies of the UKI, kernel, tools,
initrd, factory tar and stick, plus build staging; VM disk growth comes on
top. For a bounded first check, prepare `SMOKE` (or `small`). Stick images
need mtools and `sfdisk`; firmware boots need
`/usr/share/OVMF/OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`. One case runs at a
time per lock, under a shared `flock`; only `run` starts a VM.

Environment: `TMPDIR` (an existing disk-backed temporary directory; default
`/var/tmp`), `ZBOOT_ACCEPTANCE_STATE` (sessions; default
`TMPDIR/zboot-acceptance`), and `ZBOOT_ACCEPTANCE_LOCK` (default
`STATE/qemu.lock`). Separate lock paths allow concurrent runs; reserve CPU,
guest RAM and disk staging for each. Keep the state directory under the
selected `TMPDIR`: `build-initrd.sh` permits only new output and provenance
files beneath that resolved root, and refuses existing paths or symlink
escapes. Sessions and published fixtures belong to the caller and
are not deleted by the runner, with one exception: when a case passes, `run`
removes that case's VM disk images, sticks and per-boot kernel, initrd and
firmware copies, which the session's OID and OUT reproduce and which are
nearly all of a session's bytes. The case's `result.json` records the bytes
removed. A failed case keeps everything, and
`ZBOOT_ACCEPTANCE_KEEP_IMAGES=1` keeps a passed case's images too.

#### The build scope

Without `--distribution-tools`, `prepare` builds the tools with
`CARGO_BUILD_JOBS` (default 4), a 40-minute timeout and roughly 4 GiB of
staging, in its own process group, which is stopped when the build ends or
times out. A caller's `CARGO_TARGET_DIR` is used as given, so a host manager
can own the build scope by wrapping `prepare`; otherwise the build gets fresh
private staging under `TMPDIR`, removed after the artifact copy.

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
- **Firmware boots.** `Boot(n, efi=True)` boots the session's stick
  under OVMF with fresh variables, and the module's `stage_n(console)` drives
  the menu over ttyS0 (`host/console.py`), recording each exchange as
  evidence. `extra={'from': 'A'}` boots disk A's own ESP with no stick. With
  `target=m` the menu's handoff lands in the acceptance initrd inside a BE
  whose saved `zboot:cmdline` selects guest stage m. `network=True` adds one user-mode NIC with no outside access and a
  loopback SSH forward.
- **Result.** A case passes when every boot ended as declared (DONE, the
  named CUT, or a finished dialogue) and its verdict recorded no failure.
  `SESSION/cases/ID-UTC/` keeps `result.json`, the evidence (`out/`) and each
  boot's console, test channel and QEMU logs. A failed case also keeps its
  disk images and boot inputs; a passed one does not.

Direct boots run OUT's kernel with an initrd made of the UKI's own
initramfs, the guest scripts, the session's `zboot` and `zsnap` (which replace
the UKI's), and a few host tools. By default the tools are built at OID;
`--distribution-tools` instead copies them from the verified distribution,
which must be built at OID.
Every group but small gets the read-only fixtures share: the session's UKI as
the loader, the factory tar, and the acceptance kernel and initrd that a
handoff target BE boots. A native result claims the
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
| esp | `ESP-NATIVE` | one `esp` batch writes zboot's two fixed paths and keeps loader ownership on both imported-pool disks, reports an old-name zboot loader as stale and leaves it, leaves rescue media alone, installs after a typed answer and meets an ESP that turns read-only late; the files read back after a cold boot |
| deploy | `DEPLOY-NATIVE` | whole-disk `deploy` of the factory tar with a host overlay (a file and a hook): GPT, read-only import by GUID, `@factory` and `@deployed`, overlay owner and mode, identity; the deployed system then boots and erases a spare disk itself, with the probe its package installed |
| deploy | `DEPLOY-INTO` | `deploy into` adds a bootable sibling and keeps the defaults; a power cut at `@factory`, `drop`, a retry and a UKI handoff |
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
| efi | `EFI-FORK-ONCE` | a running Debian root arms a named fork, a key pauses its countdown, and two subsequent firmware boots mount the fork once and the original default next |
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

#### Run time

A full sequential run has taken roughly an hour and three quarters of KVM VM
time on a local host, plus image, factory and session preparation; hosted
runners and other hosts differ. The slow cases spend their time on what they
test: `EFI-CONNECT` (about 15 minutes) waits out the real ten-minute
remote-access window, and `RESTORE-PAIRED-NATIVE`, `MOVE-BY-PAIR`,
`RESTORE-MENU-RESUME-NATIVE` and each `GUIDED-*` case take 3 to 7 minutes.

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

QEMU has no NVMe Sanitize command, no USB sticks and no real firmware boot
order, so these paths were also run on a laptop with two NVMe disks and USB
sticks (2026-11-16 to 2026-11-19, nvme-cli 2.16, builds of that week); the
maintainer's qualification records hold the session logs.

- **Controllers.** An SK hynix Platinum P41 2 TB (PCIe `1c5c:1959`; block
  erase only, no namespace management) and an XPG GAMMIX S11 Pro 1 TB (PCIe
  `1cc1:8201`; crypto and block erase; the kernel ignores its subsystem NQN,
  the `IGNORE_DEV_SUBNQN` quirk). `wipe` completed by block erase on the P41
  (about 3.5 s), and `restore`'s erase by crypto erase on the XPG; lsblk,
  `blkid -p`, wipefs, sgdisk and raw reads found the P41 blank. A wipe started during a running
  sanitize waited it out and then observed its own; a stale token, and a wipe
  of the disk backing the imported root pool, were refused.
- **Boot.** Unattended reboots through the UKI on an ESP counted down and
  handed over with the adopted `spl.spl_hostid`, back in about 60 s, also
  after `primary` and `default` moved the boot default between the disks.
  `reboot --menu --key` brought up the menu's SSH by itself; from it,
  `primary`, `restore` and `boot --tar` ran.
- **Install and recovery.** `deploy DISK --empty`, `deploy DISK --tar`,
  `deploy --portable` onto a USB stick, `sync`, `unpair`, `drop`, `restore`
  keeping one dataset, and every other zboot and zsnap verb ran on the
  hardware. A stick that died mid-deploy stopped it with exit 4; two sticks
  reporting the same serial were both refused while attached together.
- **OpenZFS versions.** A pool written through `zfs receive` (a restore) by
  OpenZFS 2.4 stayed writable by 2.3, with block cloning only enabled; one a
  2.4 rescue deployed from a tar had block cloning active and imported only
  read-only there ([RECOVERY](RECOVERY.md#a-boot-environment-on-an-older-openzfs)).

## CI

The offline gate can run in CI. Install the host tooling listed above and run
`cargo fetch --locked` before `just test`, because the gate itself uses Cargo's
offline mode. A missing dependency must fail the job rather than skip tests.
A green offline job does not establish that the VM suites passed.

GitHub Actions has two workflows:

- `offline.yml` runs on pushes, pull requests and manual dispatch. It fetches
  locked dependencies before the offline gate, uses two Cargo workers, and
  optimizes test code with debug assertions and overflow checks enabled.
  Production build profiles are unchanged. A newer run cancels an obsolete
  offline run on the same branch.
- `qualification.yml` is manually dispatched. With `run_vm=false` it builds
  the pinned distribution and matching rescue factory root. With
  `run_vm=true` it also runs every acceptance case and both independent native
  proofs, in bounded KVM shards that all run at once, and requires complete
  results at one source and build identity. `EFI-CONNECT`, which waits out
  its real ten-minute window, has a shard of its own; the other cases are
  balanced by the minutes they took in a recorded run. Missing, failed,
  mixed-build or diagnostic results
  cannot produce a passing aggregate. With `release_tag=vX.Y.Z` (which needs
  `run_vm=true` and a new tag) a passing run publishes that release from the
  qualified build itself ([BUILD](BUILD.md#releases)).

```sh
gh workflow run qualification.yml --repo OWNER/REPO --ref BRANCH -f run_vm=true
gh workflow run qualification.yml --repo OWNER/REPO --ref BRANCH -f run_vm=true -f release_tag=vX.Y.Z
gh run list --repo OWNER/REPO
```

Qualification keeps two kinds of artifact. The build's record (logs, build
identity, hashes and package lists) and each shard's assertion evidence, setup
logs and source and runtime identities are kept for 14 days, uploaded even on
failure; raw VM disks and private login keys are excluded. With `run_vm=true`
the build also uploads a handoff for the shards and the release: the
mode-preserving distribution archive with its corresponding source (about
0.9 GB) and the factory tar (about 0.55 GB), whose hashes each consumer
verifies. A cleanup job deletes the handoff when the run ends; it expires after
one day otherwise. A failed run is repeated as a whole run; rerunning only its
failed jobs finds no handoff. On a private repository artifact storage is
billed by GB-hours accrued over the billing cycle, so a deleted artifact still
counts, and once the allowance is spent every upload fails, failing jobs whose
tests passed. Public repositories are not charged.

`tests/ci/runner-setup.sh` is only for disposable GitHub-hosted runners: it
uses sudo for package installation, KVM device permissions and user-namespace
setup, and must not be used as local host setup. QEMU and the distribution and
factory builders run as the ordinary user; no Docker or libvirt daemon is
needed. Acceptance shards use the distribution's tools and install no Rust;
the native proofs build their consumers from the matching source. A pinned
distribution and factory build grew a standard runner's filesystem by about
6.4 GiB, from about 12.5 GiB free.

## Updating OpenZFS

zboot carries no OpenZFS of its own: it runs the host's `zfs`, and the UKI
the one from the `build.lock` snapshot. After moving the snapshot to a new
OpenZFS, run `STOCK-RECEIVE-PROBE` first, for the facts the stock pipeline
relies on, then `STOCK-SYNC-NATIVE` and the native groups.
