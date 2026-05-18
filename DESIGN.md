# zboot — design

Locked decisions and the state catalog. README has the user-facing
view; this is what doesn't get re-litigated without a specific reason.

## Lineage

A re-implementation of
[zfsbootmenu](https://github.com/zbm-dev/zfsbootmenu), written in
Rust by an LLM with the upstream project in its context.

- **Bootloader** is zfsbootmenu's: EFI loader with full OpenZFS in
  initrd, kernels inside the BE (no bpool), property-driven discovery,
  built-in shell, `kexec` handoff, UKI built via `ukify`. Property
  namespace is renamed (`zboot:*` vs `org.zfsbootmenu:*`); meanings
  line up one-to-one.
- **Userspace verbs** are the standard BE-manager set: `snapshot` →
  `zfs snapshot`, `fork` → `zfs clone`, `default` → `zpool set bootfs=`,
  `rollback` = `fork + default`, `drop` → `zfs destroy` with auto-promote.

Local choices (not novel, just narrower defaults): debian-only,
multiple root pools (`zboot:role=root`) baked in, bundled `deploy` +
`overlay` so install ships in one binary, `mirror` between pools as
a first-class verb.

If you want a serious BE manager, use zfsbootmenu — battle-tested,
distro-agnostic, maintained. zboot's value is one Rust binary with
stricter defaults, not improvement over the original. zfsbootmenu is
MIT-licensed, zboot is Apache-2.0.

## Key decisions

One line each, with the reason that locked it in. Grouped by theme.

### Bootloader shape

- **Custom bootloader (`zboot-boot`), not GRUB.** Removes bpool, removes `update-grub`, full ZFS feature support, property-driven discovery. Cost: maintaining a kernel + initrd.
- **No bpool.** Kernels live inside the BE; full features apply (encryption, modern feature flags). Cost: bootloader needs OpenZFS userland in its initrd.
- **Property-driven, no per-pool config.** One EFI binary on every ESP; adding a root pool is a `zfs set`, not a code change. Bootloader artifacts derive from `bootfs`; on drift, regenerate.

### State and discovery

- **State of record is ZFS properties.** `bootfs`, `zboot:role`, `zboot:be`, `zboot:attached-to`, `zboot:kernel-cmdline`, native `canmount`/`mountpoint`/`readonly`. State travels with `send -R`; no sync between file and reality; external tooling can write properties from any source.
- **Discovery is property-driven, not layout-driven.** `<pool>/ROOT/<name>` is the creation default; any dataset tagged `zboot:be=true` is found, anywhere. Existing systems join by tagging only.
- **Lineage from ZFS `origin`, not zboot metadata.** `status` walks origins; `zfs promote` is captured automatically. Zero metadata to keep in sync.

### Active-BE resolution: booted vs bootfs

Two distinct meanings of "active BE" coexist; verbs use the appropriate one:

- **`bootfs`** = next-boot intent. Per-pool property set by `default`/`primary`. The bootloader's selection input.
- **Booted dataset** = the source of `/` in `/proc/self/mounts`. The actually-running root.

They agree in steady state. They differ between a `default` (or `primary`) and the next reboot — that's the whole point of `default` (queue a future switch).

- **Bootloader shell (`zboot-boot`)** uses `bootfs` exclusively. No userspace yet; nothing else is available pre-boot.
- **Userspace CLI (`zboot`)** uses the booted dataset for no-args verbs (`push`, `pull`, `snapshot`, bare-name resolution). `default`/`primary` write `bootfs` directly. `status` prints both: a `Booted: <dataset>` header and a per-pool `bootfs=...` row.

The operator workflow this enables: after `primary <peer>`, `push` (no args) still operates on what you're *actually* running, not the side you just told the system to boot into next. The post-reboot `push --force` then settles readonly from the new running root.

### Pools and hardware identity

- **Multiple root pools from day one.** Once the bootloader supports unified discovery, N pools is barely more code than 2; supporting it later would mean redesigning at the wrong time.
- **Same hostid per host.** `sha256(--hostname)[:4]`. Pools are software; hostid identifies hardware. Cross-machine restore explicitly regenerates (or `--keep-hostid`); no force-import on normal cross-pool operations.
- **Per-pool cachefile + `cachefile=none` for cross-pool ops.** Each root pool's `/etc/zfs/zpool.cache` only auto-imports its own pools. Zero modification to the running system's initramfs.

### Verb model

- **Fork model over transactional rollback.** Operations create or move tips. Rollback is a workflow over `fork + default + drop`. No state machine, no commit/abort verbs — recognizable from git / NixOS generations.
- **`default` writes losers before the winner.** Clear other root pools' `bootfs` first, set the target's `bootfs` last. Interrupted mid-write → zero pools have `bootfs` (recoverable: re-run), not two (ambiguous boot).
- **No `--yes`/`--force`.** Destructive ops (`drop`, `deploy`, `esp --replace`) require typed-target confirmation. Re-deploy on the same target is destructive, not idempotent — the typed prompt is the protection.
- **Deploy is one verb with mode flags; ESP-on-separate-disk is the `esp` verb.** `zboot deploy --target X` takes a single disk; `--no-efi` switches to whole-disk pool (no ESP); `--empty` skips BE installation. Separate ESP is `zboot esp --target Y` — pool-agnostic, scans `zboot:role=root` at boot. Splits "which disk" from "what gets installed".
- **Orphan datasets surfaced, never silently destroyed.** A dataset whose `zboot:attached-to` references no extant BE is reported by `status`; the user runs `zfs destroy` if appropriate.

### Verb-specific contracts

- **Datasets bind via `zboot:attached-to` (sibling-list); sharing is the default.** `fork` extends the list. Per-BE isolation requires a manual clone + rebind.
- **Replication is `push`/`pull` per BE; `mirror` is the bulk walker.** Each BE carries at most one `zboot:mirror` pointer. The typical case is mutual (`push --to <pool>` bootstraps both sides); 1:N topology has tracking-only pointers from N dests back to one source. `push --to <pool>/ROOT/<other>` is the ad-hoc unpaired form. Same-pool push warns and proceeds (full copy; use `fork` for the cheap clone).
- **Divergence refuses by default; `--force` runs `zfs receive -F`** with typed-target confirmation. Refusal message lists the snapshots that would be destroyed and the exact `zfs` command `--force` runs. The live-root pull recipe is `pull --name <fresh>` + `default <fresh>` + reboot + `drop <old>` + `rename <fresh> <old>`.
- **`zboot:primary` is the pair-direction marker**, separate from `bootfs` and `readonly`. Set by `primary <BE>`, bootstrap (`push --to`, `pair`), and fork/drop/unpair lifecycle points. `mirror` reads it to pick push direction. Multiple BEs can carry `=on` simultaneously (per-pair, not global).
- **`pair <BE> <peer>` sets `Mirror[BE]=peer`** and, if peer was unpaired, makes it mutual. Refuses on existing-different-pair or GUID-set divergence (`--force` skips the GUID check). **`unpair`** clears both sides if mutual, otherwise just the local one.
- **`rename` rewrites the peer's pair pointer atomically** with the `zfs rename`. Required so the live-root pull recipe doesn't dangle peer pointers.
- **Bounded `@<snap>` on `push`/`pull`.** Sends up to the named snapshot; newer snaps stay local. Rewind (named snap is older than dest's current position) refuses; `--force` runs `zfs rollback -r` against the dest.
- **Lifecycle pair-pointer bookkeeping.** `fork` clears `zboot:mirror` on the new BE; `drop` clears the surviving peer's pointer.
- **Chroot/overlay** mount the target RW and refuse on the live `/`. `chroot` is also a bootloader-shell verb for repair without booting the broken BE.

## State catalog

**Pool-level:**

| Property | Set by | Purpose |
|---|---|---|
| `bootfs` *(native)* | `default`, `deploy`, `rollback` | next-boot dataset; canonical "active BE" marker |
| `cachefile` *(native)* | `deploy` (= `none`) | suppresses auto-import recording |
| `zboot:role` | `deploy` (= `root`) | which pools host BEs (read by `default`, `mirror`, `zboot-boot`) |

**Dataset-level:**

| Property | Set by | Purpose |
|---|---|---|
| `origin` *(native)* | `zfs clone`/`promote` | clone parent — defines BE lineage |
| `mountpoint` *(native)* | `deploy` (`/` for BE, `/path` for attached) | mount path; not touched after deploy |
| `canmount` *(native)* | `deploy`, `default`, `attach` | `noauto` for BEs; `on`/`off` toggled by `default` for bound datasets |
| `readonly` *(native)* | `push`/`pull` (= `on` on receive side), `primary` (best-effort toggle on both sides; deferred on mounted root with operator-facing message), `default` (clears on winning pool's active BE) | failover-safety rail; readonly invariant for paired BEs (see § Replication invariants) |
| `zboot:be` | `fork`, `deploy`, `push`, `pull` | `true` marks a BE — required for discovery |
| `zboot:attached-to` | `attach`, `fork`, `drop`, `detach` | comma-list of `pool:BE` keys this dataset is bound to |
| `zboot:mirror` | `push --to`, `pull --name`, `pair`, `unpair`, `rename`, `fork`, `drop` | mutual peer pointer (`<other-pool>/ROOT/<be>`); one slot per BE; cross-pool only; inherited by attached datasets the same way |
| `zboot:primary` | `primary`, `pair`, `unpair`, `push --to` (bootstrap), `pull --name`, `fork`, `drop` | `on`/`off` marker for which side of a mutual pair is the writable canonical. Separate from `bootfs` (boot target) and `readonly` (safety rail); the three can diverge in transient states (live-root failover). Read by `mirror` to pick push direction. |
| `zboot:kernel-cmdline` | `cmdline set`, `deploy` | extra cmdline tokens; ZFS-inherited (set on `<pool>/ROOT` for pool-wide; override per-BE) |

**Files (not state-of-record):** `/etc/hostid` per BE (same value
per host); `/etc/zfs/zpool.cache` per pool (derived from imports);
`zboot-boot`'s baked-in initramfs (static, embedded in the EFI
binary).

## Binding mechanism

Datasets associate with BEs via `zboot:attached-to`. `default`
toggles each bound dataset's `canmount`:

| Category | Behavior at `default` |
|---|---|
| Bound to active BE | `canmount=on` — mounts |
| Bound to other BE(s) | `canmount=off` — doesn't mount |
| Unbound (no property) | zboot doesn't touch — always-on shared state |

Format:

```
zboot:attached-to=rpool:BE1                    one BE
zboot:attached-to=rpool:BE1,rpool:BE2          shared
zboot:attached-to=rpool:BE1,rpool2:BE1         cross-pool
(unset)                                        unbound, always mounted
```

### Operation defaults

- **fork** appends new BE to source's bound dataset lists. Sharing is the default. Per-BE isolation: manually `zfs clone` the bound dataset and edit `zboot:attached-to`.
- **drop** strips the dropped BE from each list. Empty list → orphan; user runs `zfs destroy`.
- **snapshot** captures the active BE only. Bound datasets are user data, deliberately out of scope.
- **default** toggles `canmount` as above; also clears `readonly=off` on the target BE (mirror dest → primary).
- **detach** drops local `zboot:attached-to`; leaves `canmount`/`mountpoint` as-is.
- **attach** validates each `pool:BE` resolves to an existing `zboot:be=true` dataset before writing the property.
- **mirror** replicates BEs across pools; bound-dataset replication is out of scope.

### Atomicity caveats

- `zfs snapshot` multi-arg is atomic *per pool* (one TXG). Cross-pool sets have sub-second skew.
- `default`'s `canmount` toggle is per-property atomic. Mid-crash inconsistency is recoverable via re-run (idempotent).

### Child-of-BE datasets — not supported

Datasets associate via `zboot:attached-to`, not via being children
of `<pool>/ROOT/<be>`. Sibling-bound covers everything child-of-BE
could express; avoiding children removes recursive-clone complexity.
For ephemeral data: directory inside BE root, tmpfs, or unbound
sibling dataset.

### Orphans

A dataset with `zboot:attached-to` is an "orphan" iff *every* entry
in the list references a non-extant BE. One live key + one dead key
→ not an orphan; the dead key sits as historical. zboot never
destroys orphans — the operator runs `zfs destroy` if appropriate.

## Bootloader internals

`zboot-boot.efi` is a Unified Kernel Image (kernel + initrd + cmdline
in PE sections), assembled by `boot/build.sh` via `ukify` (preferred)
or `objcopy --add-section` against `linuxx64.efi.stub` (fallback).
`boot/install.sh` writes it to the ESP and registers an NVRAM entry
via `efibootmgr`.

ESP layout (written by `deploy`, the `esp` verb, and `install.sh`):

```
<ESP>/EFI/zboot-boot/zboot-boot.efi    canonical install
<ESP>/EFI/BOOT/BOOTX64.EFI             default-search fallback (byte-identical copy)
```

The fallback at `/EFI/BOOT/BOOTX64.EFI` is what UEFI loads when no
NVRAM entry matches — the load-bearing piece, not the NVRAM entry.

**Pool import policy.** Preinit imports all root pools `readonly=on`.
The first mutating verb in the shell triggers a lazy re-import of
the relevant pool *without* `readonly=on`. Read path stays r/o;
only mutation pays the export+reimport cost. `zboot-boot` performs
no writes before kexec.

## Replication invariants

The replication layer is the project's "git transport without merge": stable
snapshot GUIDs play the role of commit SHAs, `zboot:mirror` plays the role of
mutual remote-tracking, divergence detection is set-difference on GUIDs, and
force-overwrite maps to `zfs receive -F`. No merge primitive, no rebase — the
absence simplifies the model enough that the always-succeed property below is
provable.

### State

For each BE (and each attached dataset, identically):

- `Snapshots(p, ds)` — set of snapshot GUIDs currently under the dataset
- `Mirror(p, ds)` — `(p', ds')` peer pointer or NULL
- `MirrorAnchor(p, ds)` — GUID of the last successful send-from snapshot
  (recorded by pruning all but the latest `@mirror-<utc-ns>` on each side)
- `Readonly(p, ds)` — boolean, native ZFS property
- `Origin(p, ds)` — `(p, ds', guid)` clone parent or NULL (intra-pool only;
  ZFS-native)
- `SnapAncestor(guid)` — lineage GUID; stable under promote

`BootFS(p)` — which BE is the next-boot target on pool `p` — sits on top
of `Snapshots`/`Mirror` but is what makes a dataset a BE and what makes one
side of a pair the rw one.

### Verbs that touch replication state

| Verb | Snapshots | Mirror | Anchor | Readonly | Origin |
|---|---|---|---|---|---|
| `snapshot <BE>` | add | — | — | — | — |
| `fork <new> --from <BE>@s` | new ds | clear on new | — | — | new clone-of |
| `rollback` | (fork + default) | clear on new | — | reconcile on winning pool | new clone-of |
| `drop <BE>` | destroy ds | clear on peer | — | — | promote if dependents |
| `pair <BE> <peer>` | — | set both | — | — | — |
| `unpair <BE>` | — | clear both | — | — | — |
| `rename <BE> <new>` | — | rewrite peer's pointer | — | — | — |
| `primary <BE>` | snap-if-mounted-root on demoted side | — | — | best-effort toggle (deferred on mounted root) | — |
| `default <BE>` (cross-pool) | snap-if-dirty on old-active | — | — | clear on winner, set on losers | — |
| `push <BE>` | — on local; mirror anchor on peer | set both if bootstrap | advance | dest = `on` after | — |
| `pull <BE>` | mirror anchor on local | set both if `--name` | advance | local = `on` if not active | — |
| `mirror` (bulk walker) | per-BE push to each `zboot:primary=on` BE's peer(s) | per-BE | per-BE advance | per-BE | — |

### Safety invariants (always)

- `PairSingleSlot`: each BE has at most one `Mirror` value. Asymmetric
  pointers are allowed (one-to-many tracking); mutuality is the typical
  case but not enforced.
- `PairIsCrossPool`: `Mirror(A) ≠ NULL ⟹ Mirror(A)` is on a different pool.
- `NoDanglingPairs`: `Mirror(A) ≠ NULL ⟹ Mirror(A)` refers to an extant
  dataset on an imported pool (otherwise: `status` flags `[target missing]`;
  `unpair` resolves)
- `PushDoesntDestroy`: `push` (no `--force`) never shrinks `Snapshots(dest)`
- `SnapshotIdentityStable`: no verb mutates `SnapAncestor` for existing GUIDs

### Readonly invariant

Under five preconditions — (1) one-to-one pair (single-slot mutual pointer);
(2) dest carries `readonly=on` while the source pool is bootfs; (3) no raw
`zfs` mutations on paired datasets; (4) `snapshot` refuses on a readonly BE;
(5) `primary` is one verb that snapshots-if-mounted, flips `zboot:primary`
and `readonly`, and follows `bootfs` (readonly deferred when the demoted
side is the live root; settled by the next `push --force` post-reboot) —
the invariant holds:

> For every pair `(A, B)` with `Readonly(B)=on`, `Snapshots(B) ⊆ Snapshots(A)`.

Consequence: `push(A → B)` is always in fast-forward mode; divergence is
unreachable. Violations require either multi-active pools (both BEs `rw`
simultaneously between syncs) or out-of-band `zfs` against a paired
dataset. Both surface in `status` as `[↑N ↓M diverged]` / `[asymmetric]` /
`[target missing]` and are resolved by `--force` in one direction.

### Promote: transient divergence, not a correctness break

`zfs promote` re-homes snapshots between datasets (GUIDs unchanged, dataset
membership shifts). For paired BEs, this can show as transient `[↓N]` in
status even though no data drift occurred — the missing snapshots moved
to a sibling BE on the same pool, GUIDs still match. The next `mirror`
or per-BE `push` resyncs because `zfs send -I` resolves anchors by GUID,
not by dataset path. Documented here so the status display behavior isn't
mistaken for a real bug. Promote-aware in-lockstep replication on the peer
is a follow-up (would require modeling clone-tree-correspondence across
pools; currently out of scope).

### ZFS substrate quirks

Empirically discovered. Reverting these in a refactor brings back the
bug they prevent.

- **Bootstrap of a clone source uses `zfs send -p`, not `-R`.** `-R`
  encodes the clone-origin GUID; the receiver fails if its pool doesn't
  have a matching snapshot. `-p` carries properties without the
  clone pointer. Cost: only the anchor's data crosses; earlier own
  snapshots of the clone don't. `push` warns when this applies.
- **Incremental sends use `zfs send -I` (no `-R`).** `-R -I` on a clone
  source returns `rc=1` silently from the receiver (intermediates land
  but the exit code lies). `-I` alone preserves intermediate snapshots
  cleanly; `zboot:*` properties are reapplied post-receive anyway.
- **`zfs receive -u` is required.** Without `-u`, receive mounts the
  new dataset at its `mountpoint` property even with `canmount=noauto`;
  for a stream from a paired BE this *overmounts* the live root.

### Topologies (all `mirror` walks correctly)

- **Mutual pair** — `push be1 --to rpool2` bootstraps both sides.
- **1:N fanout** — repeated `push be1 --to rpool<N>` creates asymmetric
  tracking pointers from each new dest back to source.
- **Switchable-primary shared slave** — slave on one pool, primary on
  any of several BEs on another pool; switch via `unpair` + `pair` +
  `push`.
- **Many-to-one central archive** — independent mutual pairs into a
  central pool, one per host slot.

### Failover

```sh
zboot primary rpool2/ROOT/be1   # flip pair; bootfs follows
reboot                          # land on new primary
zboot push --force              # settle old primary's readonly=on
```

The middle two steps are coupled: `primary` skips the readonly toggle
on the demoted side when it's the live root (mounted-rw → can't); the
post-reboot `push --force` is the catch-up. `primary` also auto-snaps
the demoted side as `@pre-primary-<ts>` if mounted; `push --force`
wipes it. To preserve, `pull` the auto-snap into a separate BE first.

### Status markers

`status` renders three orthogonal facets per BE: `*` (bootfs target),
`[rw]/[ro]` (native readonly), `[primary]/[mirror]` (`zboot:primary`,
shown only when paired). Plus mirror-relative state: `[in sync]`,
`[↑N ↓M]` snapshot-GUID delta (anchors excluded), `[diverged]`,
`[target missing]`, `[pool not imported]`, and `dirty <bytes>`.

The three facets normally agree but can diverge in transient states
(live-root failover, post-`default`-pre-reboot, manual `readonly`
flips); the display shows each independently so the operator sees
what's actually true vs what's expected.

## Hostid handling

ZFS stamps a hostid into each pool's label and refuses to import with
a mismatching hostid unless `-f` is passed. Three importing stages
need to agree on the same hostid: `zboot deploy` (live env), the BE's
own initramfs at boot, and `zboot-boot` (PID 1 in the EFI initrd).
The hostid is derived as `sha256(--hostname)[:4]`.

**The friction:** a factory-tar deploy can't regenerate the BE's
initramfs (would require chroot + `update-initramfs` per deploy,
~30s); the baked-in `/etc/hostid` is the build host's, not the
deployed host's. On first boot the initramfs's stale hostid would
mismatch the pool stamp.

**The fix:** `boot/src/kexec.rs::compose_cmdline` injects
`spl.spl_hostid=0x<HEX>` from `zboot-boot`'s adopted hostid into the
kexec'd cmdline. The kernel-parameter form bypasses the spl module's
fallback to reading `/etc/hostid`, so the boot succeeds with the
correct hostid. Any later `update-initramfs -u` in the BE bakes the
correct value and makes the cmdline injection redundant (still
harmless).

`zboot-boot`'s own hostid is bootstrapped via
`adopt_hostid_from_pool`: PID 1 imports pools read-only, mounts the
bootfs BE briefly, copies `/etc/hostid` into its in-memory
`/etc/hostid`. Without this, any RW reimport would re-stamp the pool
with `0` and break subsequent boots.

## PXE / network boot

`zboot-boot` only handles **local UEFI** — never PXE. When operators
want PXE, the iPXE menu offers two parallel entries:

- **Debian Live (UKI chain).** iPXE chainloads `debianlive.efi`
  (built by `zboot live`). The .efi binary holds the live kernel +
  initrd + cmdline as PE sections; live-boot fetches the squashfs at
  runtime via iPXE's `imgargs`. Lands at the live login; operator
  runs `zboot deploy`.
- **zboot-boot menu.** iPXE chainloads `zboot-boot.efi` bare.
  zboot-boot starts in disk mode, enumerates local ZFS pools, shows
  the BE menu, kexecs the chosen BE. Useful for PXE-booting into an
  already-deployed machine whose ESP is broken.

The split exists because combining a UKI with iPXE's `--name`
multi-named-initrd injection clashes on `LINUX_EFI_INITRD_MEDIA`
(`EFI_ALREADY_STARTED`). Two separate iPXE entries (each a single
chainload, no `--name`) avoid the clash.

## Out of scope

Each is "intentionally not done", with the reason.

- **Cross-machine restore, generic image build, restic-backed image store** — separable from the boot lifecycle; belong in surrounding tooling.
- **`linearize`, `prune`, `fork --isolate`** — needed only when forests grow or per-BE isolation is requested. Typical forests are 1–2 tips; manual `zfs clone` covers `--isolate`. Defer until friction.
- **Mirror auto-replay of promotes, bound-dataset replication via `mirror --include-bound`** — natural follow-ups; drift detection ships, replay does not. Bound datasets are user data, replicated separately.
- **GRUB fallback** — would re-add bpool or constrain rpool features; defeats the simplification. Recovery: multi-ESP redundancy + rescue USB + PXE.
- **Encryption-at-boot UX, live system rollback without reboot, auto-revert on boot failure, cross-pool merge** — either too speculative (no use case), fundamentally unsafe (live rollback), or unsupported by ZFS (merge).
