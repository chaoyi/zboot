# ZFS tools design

This document describes the zfs-tools library, zboot and zsnap as the source
implements them: the rules they keep and why. [CLI.md](CLI.md) owns the
syntax and the per-verb behavior, [BUILD.md](BUILD.md) the UKI build and root
tars, [TESTING.md](TESTING.md) the test suites and which QEMU cases exercise
each rule, and [RECOVERY.md](RECOVERY.md) the procedures.

Two words are used precisely. The **zboot UKI** is the file `zboot.efi`: a
kernel, a small initramfs and zboot, started by firmware from an ESP, a stick
or the network. The **menu** is the screen it shows.

## Boot implementation lineage

The early boot implementation used
[ZFSBootMenu's source](https://github.com/zbm-dev/zfsbootmenu) directly as a
reference for discovery, `kexec` handoff, startup and device readiness. This
was source-informed development, and the upstream copyright notice is retained
in [LICENSE](../LICENSE). [README](../README.md#origins-and-attribution)
provides the attribution.

The current boot path uses Debian kernel/initramfs layouts and a custom
bootstrap. It starts udev, triggers device events and runs `udevadm settle`
before the menu. During handoff it checks and stages the selected files in
RAM, unmounts the boot environment, loads the kernel and exports the read-only
pool before execution. The implementations are zboot's `handoff`,
`boot_environment` and `menu::hostid_adopt` modules and the UKI's bootstrap,
[`dist/initramfs/init.sh`](../dist/initramfs/init.sh).

## Product boundary

zboot manages boot environments, ordinary dataset trees, pairs, disks, ESPs
and whole-disk restore, both on a running system and in the menu. zsnap manages
snapshot policy and supervised readers of protected snapshots. The workspace
has four Cargo packages:

- **zfs-tools** (`crates/zfs-tools`): the supported Rust API (its `api`,
  `effects`, `inventory` and `reader` modules) and the private engine: native ZFS
  access, the writer lock, operation records, holds and streams. The non-default `internal`
  feature exposes the engine to zboot and zsnap only; it is unsupported and
  unstable.
- **zboot** (`crates/zboot`): the boot application.
- **zsnap** (`crates/zsnap`): the snapshot application, a library plus a
  binary; the library's root holds the retention policy API.
- **zboot-helpers** (`crates/zboot-helpers`): two internal, dynamically linked
  helpers, `zboot-probe-signatures` and `zboot-change-key`.

The library depends on neither application. zboot is standalone: recovery
needs no catalog, controller or network service. Its syntax, tokens, JSON and
exit statuses are compatibility contracts. The library targets Linux/OpenZFS;
boot and recovery target x86-64 UEFI/Debian. zboot ships no OpenZFS of its
own. Before a replacement activates, the old writer must be unable to write:
a known-offline device or a physical fence suffices, an acknowledgment that it
might be live does not.

The checkpoint API observes an object's current *incarnation*: that particular
instance, so a replacement at the same name is a different target.
Observations are evidence, not permission. A `WriterSession` admits exact
targets afresh under the writer lock, and before each effect the ZFS
observations and the caller's guard run again. Capture and deletion act on
exact members, never descendants, and report partial and uncertain outcomes
([library guide](../crates/zfs-tools/README.md)). The read-only inventory of a
dataset tree takes no lock; it reports absence only from successful queries
and refuses a tree or pool that changed between its queries.

## What the design rests on

1. zboot's state lives in ZFS properties. A boot environment is
   found, not registered. So one UKI serves every host, and an ESP, a stick
   and a network boot behave the same.
2. Stock Debian does the mounting and the kernel updates. zboot sets a
   dataset's role once, when it creates it, and a switch changes only
   `bootfs`.
3. One kind of artifact provisions everything: an ordinary root tar.
   `deploy` installs it as a host, or with `--portable` as a rescue stick;
   `boot --tar` runs it in RAM. Nothing about a tar is special to its use.
4. One grammar serves the operator, a script and the menu: the same verbs,
   `--dry-run`, `--confirm TOKEN`, `--json`. Confirmation exists only where
   data can be lost.
5. A normal boot never writes to a pool.

## Model

- A boot environment (BE) is a filesystem with `mountpoint=/` and a kernel and
  initrd under its `/boot`, unless a zboot role fences it
  ([Menu discovery](#menu-discovery)). Each host has exactly one boot default:
  the `bootfs` of one imported pool.
- A pair joins two leaf datasets (datasets with no children), each with at
  most one mutual peer, recorded in identity-bound `zboot:pair` records on
  both sides. Containers (`rpool/data`) are plain structure made on each
  side; a boot environment is one leaf, as is a volume. Only the primary
  mounts writable. The secondary is *fenced*: read-only, `canmount=noauto`,
  and for a volume a local `volmode=none`, so it is never written, mounted or
  exposed as a device by accident. Its own `readonly` and `canmount`, and for
  a volume a `volmode` set by hand, are saved in a local `zboot:placement`,
  which activation restores; with no saved `volmode`, activation inherits it
  ([Pairs](#pairs)).
- Every object is bound by pool GUID, GUID, `createtxg` and `objsetid`
  (snapshots also by parent) and re-read before each effect, so a renamed or
  replaced object never inherits stale consent. Unknown schemas and ambiguous
  observations refuse mutation.
- The history rule compares two leaves' snapshot GUIDs in creation order: they
  need a common snapshot, their common snapshots in the same order, and newer
  snapshots on one side at most. Older snapshots may differ, because either
  side may have pruned what the other keeps. Equal names are not ancestry.
  Raw encryption (cipher and the IV sets of common snapshots), clones and
  placement conflicts are checked. The ahead side starts as primary.
- `sync` never overwrites divergent receiver history; that needs a typed
  `primary` takeover. The tree verbs act only on unpaired datasets, except
  that `fork` also takes a pair's working copy.
- A pair's working copy may have clones of its snapshots; its fenced copy may
  not, and a paired leaf is never itself a clone. *Why:* a fork of the
  running system is the usual way to try an upgrade, and the root is the
  dataset most worth pairing. Sending is unaffected by clones. The risk is on
  the side that receives, or is rolled back: a receive with rollback, or a
  `rollback -r`, cannot remove a snapshot a clone depends on (zboot never
  passes `-R`, which would destroy the clone). So the receiving side must
  have none, deletions keep a snapshot that has a clone, and `primary`, which
  can fence and roll back the working copy, refuses while either side has
  one.
- Common snapshots stay held on both sides until a newer verified base
  replaces them. These held snapshots are the pair's *anchors*, the starting
  point of the next incremental transfer. Foreign holds are honoured.
- A peer that is gone (pool not imported, dataset absent, or no longer naming
  this side) strands its survivor until the operator says so, by a typed
  `unpair` or `primary` on the survivor.

## Command line

[CLI.md](CLI.md) is the interface. The rules behind it:

- **Names are resolved by how they are written, never by what exists.** A
  name with `/` is that dataset; a name without `/` is the boot environment
  beside the running one; `NAME/` is the root of pool NAME. The menu's
  shorthand is the numbers `status` shows, each bound to a native identity.
  *Why short names:* almost every daily command names the running boot
  environment or a sibling. *Why by spelling only:* a rule that asked "is
  there a sibling, else a pool, of this name?" would let the same line change
  meaning when a dataset is created, between a preview and its confirmation,
  or between two hosts. Plans and typed confirmations print full names.
- **Targets are resolved after parsing.** The grammar marks which arguments
  are targets; nothing else is rewritten, so quoted values and a `chroot --`
  tail pass through untouched. One clap definition parses both the command
  line and a menu line. *Why:* "the menu takes the same verbs" then holds by
  construction.
- **Shared options.** Every verb that changes a pool, a disk or an ESP takes
  `--dry-run` and `--confirm TOKEN`; every verb but the two interactive ones
  takes `--json`. *Why:* one sentence replaces a per-verb table, and a script
  can always run exactly what it previewed.
- **A token that no longer matches is refused**, with no new token. *Why:* a
  caller that retries with whatever token the output contains would otherwise
  confirm a plan nobody reviewed. Generated values (a snapshot name, a random
  hostid) are not bound; the result reports them.
- **Exit status 4** applies from the first durable effect on, an operation
  record included; verbs that keep no record (`wipe`, `deploy`, `esp`) count
  their first write. *Why:* a script can tell "nothing happened" (1, 3) from
  "needs `resume` or a rerun" (4) without parsing JSON.
- **Pool access follows the environment, not the prompt.** The UKI keeps
  every pool imported read-only. Any zboot command there, at the menu, in its
  shell or over SSH, plans on the read-only pools; only after the answer, under
  its writer lock, does it reopen writable the pools its plan names, by GUID,
  and then it returns them to read-only. A pool already imported writable is
  refused there; one the command exported stays exported until `rescan`.
  *Why:* an agent that got in over SSH runs `zboot deploy` or `zboot sync`
  directly; if only menu lines had this handling, those would fail. *Why the
  plan:* it already names every pool the verb writes.
- **`fork` forks only a boot environment**, one dataset with no children.
  `fork DEST` snapshots the running one and clones it in one resumable record.
  *Why:* the common upgrade flow takes one command, and the operator does not
  fork data trees (`zfs clone` remains for those). With one member the record
  stays under the 6000-byte limit, so fork keeps no separate receipt.
- **There is no cross-pool move.** Moving a leaf is `sync SRC DEST`,
  `primary DEST`, `unpair DEST --release-anchors`, `drop SRC`: each step is
  resumable with its own checks, and no record spans the four. MOVE-BY-PAIR
  checks the recipe.

## Consent

[CLI.md](CLI.md#confirmation) gives what the operator sees. The design adds:

- A disk is typed by serial or WWN, never by a `/dev` name.
- The token is 128 bits of a hash over a versioned canonical plan: the
  operation, native identities, loss scope, placement changes and artifact
  digests. Timestamps, operation ids and free space are excluded and
  rechecked instead.
- After the answer, or with `--confirm TOKEN`, the verb takes the writer lock,
  plans again, proceeds only if the token is unchanged, and executes that
  fresh plan.
- Read-only imports and exports and filesystem inspection are not durable
  effects. Inspection never makes an existing mount read-only.

## Writer lock

Only one cooperating zboot or zsnap writer runs at a time on a host: they share
one `flock` at `/run/zfs-tools/writer.lock`. It does not exclude another host
or direct `zfs` and `zpool` commands. Read-only and session commands never take
it. A zboot writer plans, previews and asks without it and takes it when it is
about to act, where its engine plans again. A zsnap writer takes it at entry,
except a `prune` that asks, which takes it after the answer and plans again
under it, refusing if what it would delete has changed. A preview or a
prompt never holds it, so a zsnap timer never waits on a prompt.

## Caller-owned effects

An application that keeps its own policy (Fleet's volumes, bound pools and
data preparation) runs its native effects through the library rather than
its own `zfs` and `zpool` children. `WriterSession::admit_effects` admits
exact targets: a dataset incarnation alone or with its subtree, an imported
pool by name and GUID (optionally its `load_guid`), a pool name no imported
pool has, or a pool GUID that is not imported. `EffectScope::dispatch` runs
one closed `Effect` ([library guide](../crates/zfs-tools/README.md#caller-owned-effects)
lists the shapes and the caller each was added for).

- **One constructor per shape, each argv pinned.** Required flags are part
  of the shape: import is `-N -o cachefile=none -d LEAF GUID`, create has no
  `-f`, destroy and rollback take no flags, set and clone are `-u`. *Why:* a general
  effect grammar would let each caller choose its own flags, and binding the
  operands of an arbitrary argv cannot be checked. zboot's typed verbs were
  rejected too: the library would absorb the caller's executors and policy.
- **Operands are admitted targets.** Each operand must be an admitted target
  or a member of an admitted subtree, with the same incarnation, and is
  bound against the observation made for this dispatch: a created name must
  be absent below an admitted filesystem parent, a clone origin must be the
  exact admitted snapshot and not marked for deferred destruction, a
  rollback point must be the newest snapshot, a key load needs an
  encryption root whose `keylocation` is `prompt`.
- **No management key.** No shape sets or inherits a `zboot:` or
  `org.zfs-tools:` key, and pool targets refuse a pool carrying one.
  *Why:* zboot refuses what it does not read in its namespace, so another
  writer's record there would block the host's boot (Fleet's records move to
  `org.fleet:`).
- **Inheritable changes admit the subtree.** Setting or inheriting any key
  that descendants can inherit (every key but `canmount`, `keylocation`,
  `quota`, `refquota`, `reservation`, `refreservation` and `volsize`) needs
  the target admitted with its subtree, so a descendant the caller did not
  review cannot change underneath it.
- **zboot's pairs and unfinished work are left alone.** Every dataset
  shape refuses a dataset that is paired, that another dataset's local pair
  record still names as its peer (a pair or `zboot unpair` stopped between
  its two records), or whose pool holds a `zboot:operation` record; pool
  export and sync refuse that record too. An inheritable change or an
  unmount checks every dataset below the target, a key load or unload every
  dataset sharing the key. *Why:* a set or unmount on a fenced secondary
  would unfence it, and `ownership` alone reads the cleared side of a
  half-done unpair as unpaired.
- **Destroy refuses what a flagless destroy must not take:** descendants,
  snapshots, a boot default and the last clone of an external origin marked
  for deferred destruction, the same rule as `zboot drop`
  (`engine::deferred_origin`).
- **`volsize` is never set.** OpenZFS truncates a volume set to a smaller
  size without refusing, so a set would lose a VM disk's tail; no caller
  resizes, so there is no grow shape.
- **Revalidation order.** Before each spawn: the caller's guard, a fresh
  observation under the session, the original admission again (the same
  members and incarnations, management included), operand binding against
  that observation, and the guard again with no observation between it and
  the spawn. The guard gets a `GuardCheck`: nothing at admission, the
  effect before the observation, and the effect with its bound argv before
  the spawn, so a caller's consent can name exactly one effect.
- **Custody from the session.** The child inherits the session's own flock
  open-file description, not the thread-local custody zboot's engine uses,
  so it holds the lock from any thread and after its caller dies. It runs in
  its own process group. Its pipes are read on the calling thread, as an
  observation's are (one bounded read per ready pipe per wakeup), so neither
  a busy writer nor a descendant that keeps one open can hold the caller past
  the deadline or leave a thread or descriptor behind; it only loses the
  stderr, which gets two seconds after the exit. A deadline kills the group
  and waits for the reap; a group signal or reap not confirmed within ten
  seconds poisons the session, which then refuses every admission and
  dispatch, because the child may still run, and the library keeps the
  unreaped leader.
- **A caller-set deadline bounds a whole observation, not each query.**
  `admit_effects_within` bounds the admission's and every dispatch's fresh
  observation, `InventoryRequest::within` and `observe_management_within`
  theirs; without them nothing has a deadline. One deadline covers every
  query, each query's pipe completion and exit, and the observation's own
  work on the output (checked before a query's output is accepted and
  before the result is returned). A query's stdout is capped at 64 MiB (parsing
  allocates well beyond the raw bytes; tens of thousands of snapshots are a
  few MiB), a typed stop rather than a truncated parse. *Why:* a fixed per-query
  bound is the wrong policy for a big or degraded pool, and only the caller
  knows its budget (Fleet sums it into its stop budget). zboot's and zsnap's
  own reads keep `native::run`, which has none.
- **A stop signals only a known child and owns the reap.** Pipes are polled
  on the calling thread, and the leader is waited for with `WNOWAIT` so its
  PID still names its group until the reap; on a stop the group is sent
  SIGKILL, the leader reaped within ten seconds, the query's output
  discarded and no later query started. The error is typed
  (`ObservationStop` with a `QueryCleanup` that claims only what was
  established: no query running, leader reaped after the group signal, or
  unconfirmed); an unreaped leader is kept by the library and reaped by a
  later bounded query, dropped only once it is reaped or no longer ours
  (ECHILD). Nothing is signalled once the leader is not known to be this
  process's unreaped child, and a bounded run refuses while SIGCHLD is
  ignored or `SA_NOCLDWAIT` is set, since the kernel would then reap the
  leader and free its PID; callers must not reap the library's children.
  *Why:* a runner that stops timing at
  the leader's exit, joins detached readers, or treats partial output as a
  result turns a hung `zpool` into a hung caller or a false observation. A
  read-only query holds no writer lock, so expiry does not poison the
  session.
- **The reply is what the command said:** `Succeeded`, `Failed{status,
  stderr}` or `Uncertain{why}`. A failed or uncertain command may still have
  changed ZFS; the caller reads back and never retries blindly. An effect
  that adds or removes a dataset or pool, or rolls one back, ends the
  admission; the caller admits again.
- **Devices are taken as given.** A `DevicePath` is checked only for shape.
  The library cannot tell which disk a path names: the caller sources it
  from its reviewed selection and keeps its own wrong-disk proof.

Key and passphrase bytes are borrowed and written once to the child's
standard input (at most 4096 bytes, one pipe write); the library keeps no
copy, so zeroizing them is the caller's. `observe_management` reads a
dataset's pair role and unfinished zboot work (an operation record on its
pool, a `zboot:pending` or `zboot:staging` mark) without a session.

## Operation records and resume

An operation that makes several lasting changes records what it intends to do
before its first change, in one record.

- **The intent record.** One versioned `zboot:operation` user property on the
  root of the pool that survives the operation. It holds roots, snapshot
  boundaries and digests rather than member lists, so it fits one atomic
  `zfs set`; an oversized record is refused before any effect. It is the
  pool's single operation slot, so a pool holds one operation at a time, and
  the only entry to `resume` and `abandon`. It holds the operation's whole
  progress: a transfer and its receive keep theirs in the record of the sync
  or `primary` they run in, and a bootstrap's nested pair its phases there
  too. A verb clears it right after its last effect; no step is left that
  only cleans up.
- **Attachments.** A payload too large for the record (a transfer's frozen
  plan, a bootstrap's nested pair plan, restore's receipt) is a write-once
  attachment: checksummed `zboot:attachment:ID:SLOT:NNNN` properties on one
  dataset in the record's pool, named in the record. The record names it
  from the write that commits it until a state that no longer reads it; only
  then are its chunks removed, and the record is cleared last, so a finished
  or abandoned operation leaves no property behind. The one exception is
  deliberate: an abandoned restore whose staging holds the only copy of the
  data keeps an archive of its receipt there. Chunks the record never named
  are a write cut before its commit and are discarded; a named attachment
  that does not read back refuses. An attachment whose operation no longer
  has a record (a write cut before its commit, then the record abandoned
  from elsewhere or cleared by hand) makes its dataset and every descendant
  refuse every operation: `status` lists it as an orphaned attachment, and
  it is never continued. It names the `zfs inherit` command that removes it
  only while the attachment's pool records no operation; on a pool whose
  record this build cannot read, the attachment may be that record's, and
  it is listed as such, never for removal.

After an uncertain result, zboot reads ZFS state to find what happened instead
of repeating a command that may have worked. Members are found again by native
marks (`zboot:pending=ID` on a fenced source, `zboot:staging=ID` on a copy or
clone until it is published), and a resume acts only on marked members and
planned identities, so anything made after an interruption is never destroyed.

Only records written by this build are resumed or abandoned; anything else is
refused before any effect: "ID is a KIND record from an earlier zboot; finish
or abandon it with the build that started it". `abandon` refuses the same way
when an attachment its record names does not read back, rather than
abandoning around it. Continuing within the recorded consent needs no new
answer; an erase still ahead or a changed loss needs fresh consent. `abandon`
never destroys the only copy of data. `wipe`, `deploy` and `esp` keep no
record; they are rerun.

## Safety rules

| # | Rule |
|---|---|
| 1 | Never write a disk that is in use (mounted, pool member, swap, holder, running root) or is not the confirmed one. |
| 2 | The zboot UKI imports read-only and reopens a pool writable only for a command, after its answer. |
| 3 | A secondary is fenced before the final capture; the new primary activates only after a verified transfer. |
| 4 | Loss is exactly the approved scope. |
| 5 | An interrupted operation resumes or is abandoned; its record, keys and media live off the disk being destroyed. |
| 6 | One boot default per host; kexec carries the BE's cmdline plus exactly one reviewed `spl.spl_hostid` when a hostid was adopted; the zboot UKI adopts one coherent host or none, and no write runs over a hibernation image. |
| 7 | Common anchors stay held on both sides until a newer verified base replaces them. |
| 8 | A secondary, an inactive boot environment's children and staging never mount by themselves. Roles set at creation and the host-wide automount check enforce it. |

The Rust tests for each rule sit beside the engines; they cut every effect and
record write against in-memory fakes and compare with an uninterrupted run.

## Pairs

zboot's `pairs` module implements `pair`, `sync`, `primary` and `unpair` with
the operation record and snapshot holds; `sync` runs the `transfer` engine
under that record.

- **A pair joins leaves.** `pair`, a bootstrapping `sync` and `primary` refuse
  a dataset with children and name them. A child that appears later under a
  paired leaf does not stop `sync`: refusing would stop the backup of data
  that is still fine, so `sync` copies the leaf and names the child, and
  `sync --all` exits 4. `primary` refuses while either side has a child: a
  child is `canmount=on` by default and inherits the leaf's path, so on the
  side that becomes dormant the next boot would mount it over the live copy.
  `status` lists every dataset below a paired leaf, whatever its `canmount`,
  so the operator moves it out before a switch needs that.
- **Only an absent DEST is created.** `sync SRC DEST` into an existing DEST
  needs DEST to be SRC's peer; an existing unpaired DEST is refused.
- **A takeover loses exactly what was reviewed.** It checks the digest of its
  planned peer loss again once the peer is fenced, so a write between plan and
  fence is never rolled back unconfirmed. Activation needs the peer fenced, so
  a resumed switch never activates both sides.
- **One stuck pair never holds its pool.** An interrupted `sync` can be
  abandoned until its data is verified. The copy stays fenced with the
  snapshots it received, a valid prefix of the source's history that the next
  `sync` continues from; a new copy stays fenced in its receive container.
  After its data is verified, `abandon` refuses: resume it.
- **A volume's `volmode` follows the working copy.** A fence saves a local
  `volmode` other than `none` in the volume's placement record, and
  activation sets it back. `primary` gives the new working copy the value
  the old one had, read before its fence, even over a value the new one
  saved earlier; the old one keeps its value saved for its next activation.
  The plan names the value, so the token binds it. *Why the old working
  copy's value:* it is the operator's latest intent. A survivor activated
  alone gets its own saved value. A local `none` is not saved, because at
  rest it cannot be told from the fence's: a volume hidden by hand stays
  hidden, but across `primary` the new working copy inherits. The field is
  omitted when absent, so a filesystem's record and every earlier record
  are unchanged; a build without the field refuses a record that carries it.
- **One host's disks.** `pair` refuses pools whose labels record different
  hostids, before any import or record.
- **Pruning happens on the working copy.** zsnap retention works there as on
  an unpaired dataset and skips the held anchor. A fenced copy refuses
  snapshot deletion and follows the working copy only through `sync`.
- **Pending deletions are reviewed.** A snapshot only on the copy and older
  than the anchor is deleted, before the transfer, only with `--confirm` or the
  typed summary; its identity is in the token, and the transfer runs either
  way. *Why a review:* the copy cannot tell why a snapshot vanished from the
  working copy (retention, a mistaken `zfs destroy`, or worse); until it is
  confirmed, the copy is the last place it exists. These deletions and the
  renames by GUID run from native state before the operation record, so a cut
  leaves only finished steps.
- **zboot cleans its own boundaries.** After a verified transfer zboot deletes
  its older boundary snapshots on both sides, those carrying its
  `zboot:capture` marker on the side that captured them.

### How a transfer runs

A transfer copies one leaf into one dataset through the host's own
`zfs send -w [-I BASE] SRC@BOUNDARY | zfs receive -u [-o K=V]...`. Without `-R`
or `-p` the stream carries no properties, so the receive changes no property
of an existing dataset: only the data, a volume's `volsize`, and for an
encrypted dataset its key material. zboot sets the copy's properties itself.
The usual direction is into the fenced copy; `sync SECONDARY PRIMARY` brings a
working copy that is behind up to date the same way, and the roles do not
change.

The steps: fence the receiver, its placement saved with the frozen plan
(local `readonly=on`, a volume `volmode=none`, a filesystem `canmount=noauto`
with its mountpoint unchanged, since changing it could remount an unfenced
child; a new copy is received only inside an inert container
`POOL/zboot-receive-ID`, where a filesystem also has `mountpoint=none` and
`volmode=none`, so a volume created beneath it has no device from its first
txg); rename common snapshots by GUID, since a non-recursive receive fails on
one the receiver names differently; reconcile properties and prove the key
wrapping; stream one incremental to the boundary; verify; publish. Publishing
restores a new copy's mountpoint and drops its filesystems' `volmode` (a copy
made by an earlier build keeps a local `volmode=none` until its next
`primary`), gives a fenced copy its at-rest role, and gives a working copy
that received its saved placement back, its `volmode` included, and mounts
it again. A new copy saves the source's placement, so activating it alone
gives it the source's `volmode` set by hand.

Every step before data runs again on every attempt. A retry recomputes the
stream from native state: OpenZFS discards a receive that a crash cut, and the
committed snapshots form a valid prefix of the source's history, so they are
not sent again. Nothing is forced, rolled back or destroyed.

**Copied properties.** The copy takes what `send -p` would carry: every
property the source sets locally or received, except placement keys, zboot's
own records and encryption keys. Copied values are local on the copy; a copied
key set by hand there is overwritten at the next sync, and a user property the
source lacks is removed. Write-time keys (`copies`, `compression`, ...) are set
before data, because only blocks written afterwards follow them. Space keys
(`quota`, `reservation`, ...) the source does not set become `none`; a
loosening change is made before data and a tightening one after, so no limit
can refuse a valid history, and a limit the copy cannot take is reported, not
a failure.

**Space review.** A copy holds a space key when it holds the working copy's
explicit (local or received) limit as a local value, or when neither sets a
limit; a value that sets none (`none`, `0`) is no limit on either side. One
rule finds every key a copy does not hold, and three places report it: a
sync's result when its transfer ends, `status` for each mutual pair whose
sides are both imported, and the `primary` plan for the side it activates
and its peer. *Why before `primary`:* afterwards the activated side's limits
are the pair's, and the next sync gives them to the peer, so a limit the copy
could not take is then gone from both. The differences are shown, not bound
into the token. *Why:* they lose no data, and the token covers loss scope and
placement ([Consent](#consent)); binding them would also make a plan stale
for a quota set while it waits.

**Encryption.** A raw receive into a new dataset makes it its own encryption
root; zboot gives it the key location of the source's root, so each copied
leaf opens the same way. A raw receive into an existing dataset replaces its
wrapped key with the sender's, and OpenZFS checks only the master key. So when
the copy takes its key from a root on its own side (the sync back after
`primary` into an installer-made dataset), zboot refuses before any stream
unless the two roots' wrapping is provably equal, because otherwise the copy
opens with neither key. A passphrase is proved by equal `keyformat`, salt and
iterations; a key file by `zfs load-key -n` opening both roots. A prompted raw
or hex key cannot be proved and refuses.

A new root-shaped copy gets an explicit empty `zboot:cmdline` when its source
sets none. A leftover `zboot:be`, the marker by which builds before the
markerless menu knew a boot environment, is ignored wherever it remains and
nothing writes it: a host that still carries it boots, and the marker can be
removed afterwards.

## Trees

zboot's `tree` module implements `rollback`, `drop`, `rename` and `fork` with
one operation record on the surviving pool. Rollback fences its tree and
restores the recorded placement afterwards. Rename carries inherited placement
onto the root, preserves identities and clone origins, and moves a boot
default inside the tree. Drop admits leftover staging only when its operation
has no live record.

Fork first creates and verifies an empty staging container that keeps its
contents from mounting or exposing a volume. *Why:* stock OpenZFS creates a
clone containing data before writing its properties, and those writes can
fail, so clone arguments alone cannot make an interruption safe. The record
fixes the reviewed placement before the first effect; before publication zboot
checks the clone's origin, identity, role and lack of children. OpenZFS
refuses to rename an encrypted clone under a parent with another encryption
root, so fork refuses such a fork at plan time instead of changing any
properties to get round it.

A snapshot of the clone or the container, even another tool's
`zfs snapshot -r POOL@x`, never stops a fork, its resume or its abandon, and
zboot leaves it in place. *Why:* a snapshot changes none of the identities
fork binds, and refusing it held the pool's one record until someone destroyed
the snapshot by hand. Fork destroys its container only when it is empty. One
that holds a snapshot or a dataset zboot did not make stays, still marked as
the fork's staging; the fork completes and names it, and `drop` lists what it
holds before removing it. An abandoned fork's unpublished clone stays staging
with its snapshots.

A fork destination cannot be below a `zboot:staging` or `zboot:pending` mark,
set on its parent or inherited by it. Fork refuses one when it plans, when it
continues, before the rename and before it retires each of the clone's own
marks, and checks again after the last. *Why:* once its own marks are retired
the boot environment inherits its parent's, and it would look like that
operation's staging: the menu fences it and `drop` could take it. Until the
retirement is recorded, a fork that meets such a mark keeps its own marks,
setting back one it already retired, so it is never another operation's
staging; abandoning it fences it again as unpublished staging.

## Mounting

Debian's normal root-on-ZFS tools mount the system. zboot writes no mount cache
and no `org.openzfs.systemd:ignore`; it controls placement through ZFS
properties. A boot environment is normally one dataset, `POOL/ROOT/BE` with
`mountpoint=/ canmount=noauto`; shared data lives outside `ROOT` with
`canmount=on`.

- The initramfs mounts the booted boot environment and its descendants (it
  skips only `canmount=off`). Stock `zfs mount -a` mounts every `canmount=on`
  dataset and skips `noauto`, so other boot environments never mount.
- **A boot environment boots with its children.** Boot admission accepts a
  boot environment with ordinary child datasets, whatever their `canmount`;
  a `canmount=on` one blocks only the *other* boot environments (below).
  *Why:* the initramfs mounts them with it, so they are part of the system
  that boots; refusing would stop a working host for a layout only some verbs
  cannot handle. Those verbs refuse it instead: `fork` and `pair` need one
  dataset. `status` lists every dataset below a boot environment, so the
  operator sees what they refuse before running them.
- Every creator sets the role at creation (`deploy` and `fork` make a BE
  `noauto`), only for recorded operation members; unrelated datasets are never
  swept, no stream carries placement, and every final role is verified before
  publication. *Why `noauto`:* otherwise the stock initramfs would mount a
  former container over live root content.
- A new copy, or a restored tree's root, gets its intended placement as local
  values, because its former external ancestor is not recreated. Restore
  keeps a local mountpoint on members whose final role is `canmount=on`,
  because OpenZFS has no `inherit -u` and an ordinary inherit would mount
  them; other restored descendants inherit from their new parents where that
  gives the intended value.
- A receive or fork destination cannot be strictly below another root-shaped
  or pool-default boot environment. *Why:* Debian's initramfs mounts
  descendants of the booted root even when they are `noauto`, and can fall
  back to `org.zol:mountpoint` for `none` or `legacy` mountpoints, so neither
  fence makes that placement safe.
- zboot never sweeps properties, so it has to notice a dataset someone made or
  received by hand. A `canmount=on` dataset in any boot environment would be
  mounted by `zfs mount -a` over whichever *other* boot environment is
  running. So the check is host-wide: `fork` and `default` refuse and name the
  dataset; the UKI refuses to boot another boot environment (the owner still
  boots, so the operator can fix it there); `status` lists it with the boot
  environment it is in.

## Kernel updates and other distributions

- Kernel updates need no zboot step: DKMS, the initramfs hook and Debian's
  `/vmlinuz` pointers update the boot environment, and the menu reads `/boot`
  at every boot. If DKMS fails for a new kernel, the previous one stays listed.
- No pool `compatibility=` restriction. If a newer OpenZFS enables a feature
  the UKI cannot import, the fix is a newer `zboot.efi`. An older OpenZFS
  elsewhere on the host (another boot environment) can still write a pool
  whose newer features are only enabled; it is shut out only once the newer
  one has used one. `restore` writes through `zfs receive` and
  `deploy --empty` writes no file, so both leave them unused, as does a
  later `sync` into the empty pool; a `deploy --tar` from a newer system
  can make one active (block cloning was, on hardware). Then the older boot
  environment imports its pool only read-only until its OpenZFS is updated
  ([RECOVERY](RECOVERY.md#a-boot-environment-on-an-older-openzfs)).
- New code avoids Debian-only assumptions where that costs nothing.

## The zboot UKI and its menu

The UKI runs entirely from RAM and checks that it depends on no disk before
starting `zboot menu`. The menu lists numbered boot environments and counts
down five seconds to one eligible default; any key pauses the countdown for
the session. Numbers keep the native identities shown, so a replaced dataset
invalidates an earlier number. The UKI is recognized by `zboot.recovery=` on
its command line, which the handoff strips, and native effects there are
admitted only after checking the actual command line, mount table and
executable. A rescue stick is listed and booted like any boot environment.

**Host identity.** The UKI starts with hostid 0 and adopts one coherent host
from active pool labels; exported pools join when their labels name that host
or record none. With no active pool it considers the default BE's
`/etc/hostid`, provided its pool labels record no other host. Missing,
malformed or conflicting identity is left for attended recovery. Handoff checks
all imported pools against the adoption. A writable import rewrites the vdev
labels' hostid (from `/etc/hostid`) and hostname (from the init UTS namespace,
which `unshare --uts` does not isolate); a `readonly=on` import writes
nothing, which is why the labels still name the last writer.

**Kernel command line.** Every handoff composes its command line in one place.
The saved line admits neither a hostid override nor a force alias
(`spl.spl_hostid`, `spl_hostid`, `zfs.force`, `zfs_force`, `zfsforce`); the
composer appends exactly one `spl.spl_hostid` with the adopted hostid, and none
when there is none. The kernel and initrd are staged and hashed in RAM before
the BE is unmounted; a failed unmount or export stops the handoff.

**Hazards.** A hibernation signature blocks writable actions until it is
resolved. The countdown also stays off when an unexamined LUKS, LVM, RAID or
filesystem location could hide a swap image, or when a member is outside local
NVMe/SATA storage under an adopted hostid. The menu prints `Automatic boot is
off: REASON` once per reason.

## Menu discovery

- No `zboot:be` marker. A boot environment is any filesystem with
  `mountpoint=/` and a kernel and initrd under `/boot`, unless a zboot role
  (`zboot:pair` secondary, `zboot:staging`, `zboot:pending`, unknown zboot
  state) fences it. The countdown follows `bootfs` only, so a received copy of
  a root is listed but never booted by it.
- One pool observation per listing. Each boot environment is mounted read-only
  to read its `/boot` and unmounted again; the chosen one is mounted once more
  at the handoff and must match what was listed. *Why not keep the mounts:*
  another zboot process in the UKI (the shell, SSH) must be able to reopen or
  export a pool, and a mount held by the menu would block it.
- Every pool is imported read-only in the background, and the listing never
  waits for a slow one (USB, emulated). The countdown starts once the local
  NVMe and SATA pools are in; a default that arrives during it cancels it. A
  handoff or any change of pool access first waits for or stops the imports
  in flight, so a late import cannot race an export or an erase.
- Labels copied onto separate devices are refused before import. A pool that
  cannot be imported is listed with the reason (name taken, another host's,
  damaged), so two copies of one stick show up instead of failing silently.
- If a refresh fails, the menu keeps its last validated state, disables the
  countdown and retries. A busy writer leaves the menu and SSH usable.

## Remote access

The menu supports wired networking only. SSH is off unless one-boot keys on the
ESP (`zboot/authorized_keys`), `zboot.ssh_key=` on the command line or
`connect` at the console turn it on;
[RECOVERY.md](RECOVERY.md#getting-in-remotely) says what each does.

- **Reading the file.** The menu accepts only `TYPE BASE64 [comment]` lines,
  deletes the file and syncs before the network starts; if it cannot delete
  the file, SSH does not start.
- **Where the request goes.** `reboot --menu` writes one ESP: the one `--esp`
  names, or else the one this boot came from, which must be on a fixed disk.
  *Why:* the menu deletes the file only from the ESP it started from, so a
  copy on any other ESP would stay live for a later boot.
- **The wait.** Unless a console key or a login holds the menu, SSH stops
  after ten minutes and the ordinary countdown runs. *Why:* a machine nobody
  can reach must not sit in the menu until someone walks to it. Only a
  successful authentication counts as a login.
- **The password** (12 characters, 60 random bits) exists for someone at the
  console; SSH that started by itself never offers it.
- **Trust.** Whoever can write the ESP or run the boot server can already
  replace the UKI, so a key they place adds no authority. Deleting the file is
  the one write a boot makes, to the ESP it started from; no boot writes to a
  pool.
- A DHCP lease with no router is accepted, with no default route. *Why:* an
  isolated wired segment is a normal place to repair a machine.
- SSH and its DHCP client run in their own cgroup, so stopping access ends
  every descendant, even reparented ones. Cleanup failure keeps the countdown
  off. When access ends, the menu observes ZFS again before counting down,
  because a repair may have changed the default.

## Provisioning: one flow for hosts, rescue sticks and images

zboot ships as the Debian package `zboot`: the `zboot` and `zsnap` binaries,
the two helpers and the UKI. The binary embeds two overlays, `builtin:rescue`
and the portable overlay that only `--portable` applies.

### factory

`factory` builds an ordinary root tar with `mmdebstrap --mode=unshare`, without
root or a VM: the kernel and headers, `zfs-dkms`, `zfs-initramfs`,
`systemd-sysv` and the `zboot` package built from the installation it runs
from. A host adds its network and firmware with `--packages`.

- All OpenZFS packages use one version; `--snapshot TIME` takes every archive
  from snapshot.debian.org.
- The build machine's identity (hostid, hostname, pool cache, machine ids,
  SSH host keys and more) is removed before any initrd is made, because the
  ZFS hook copies `/etc/hostid` and the pool cache. Every installed kernel,
  never the builder's own, gets its DKMS module and a checked initrd.
- Root's password is locked and nothing listens. With `openssh-server`,
  factory installs a unit that makes missing host keys at any boot. *Why not
  Debian's `sshd-keygen.service`:* it has `ConditionFirstBoot=yes`, and a
  deployed root with an empty machine-id does not count as a first boot.
- No `--rescue` preset and no mmdebstrap pass-through. *Why:* mmdebstrap's
  options can change the mode, the output format and which hooks run, so the
  finish step could not guarantee what it promises. Any other root goes to
  `deploy --tar`, which checks containment, member kinds and each kernel's
  initrd and ZFS module, and keeps owners, modes, xattrs and ACLs.

### Overlays

| Channel | Carries | Test |
|---|---|---|
| tar (`factory --packages`) | what dpkg, DKMS and initramfs produce | needs apt or an initrd rebuild |
| overlay `rootfs/` | a role (`builtin:rescue`) or a machine: console login, SSH keys and policy, network, services, host keys | a file copy expresses it |
| overlay `post-install` | what files cannot express | `deploy` only |
| `deploy` options | disk, pool, BE, ESP, swap, hostid, hostname, portable | zboot itself uses the value |

- Overlays apply left to right, files then hook; a later file replaces an
  earlier one, nothing is merged. The token binds every entry's digest,
  built-ins included. Writes never follow a symlink already in the root. After
  all hooks, `deploy` enforces `/etc/hostid` and an explicit `--hostname`.
  `builtin:` overlays are files only, so `boot --tar` applies them as deploy
  does.
- **`builtin:rescue`** gives root console autologin, DHCP on every ethernet
  link (client id from the MAC, since the machine-id is new at every rescue
  boot), `PermitRootLogin yes` and the IPv4 address on the console banner,
  with **no default password**. *Why no default password:* it would be the
  same published password on every rescue, while sshd answers on whatever
  network the machine is plugged into, with every disk attached. *Why no
  generated password printed at boot:* `passwd` at the autologin shell already
  does it, and consoles are often logged.

### deploy

`deploy` unpacks a root tar as a boot environment on a disk (erased, then
partitioned), on a new image file through a loop device, or in an existing
pool (`--into`). It sets only the new pool's `bootfs` and never clears
another's. A host deploy writes `/etc/hostid` and rebuilds no initrd, because
the UKI passes the hostid at every kexec.

- **Deploy keeps no record and has no resume.** The token binds the erase
  (disk, method, scope) and the selection (root tar, overlay and EFI digests,
  external ESP, geometry, hostid and hostname). After the erase, deploy plans
  again on the erased disk, which must still be bare and pass every usage
  guard, and proceeds only if the binding is unchanged. After a failure it is
  rerun with a fresh plan and confirmation. Its attempt directory under
  `/run/zboot/deploy/` holds only the post-install hook logs; `deploy --into`
  has no attempt directory and writes its hook logs directly in `/run`.
- **One zap before partitioning.** Deploy runs `sgdisk --zap-all` on the erased
  disk. *Why:* after an NVMe sanitize, LBA 0 holds whatever the controller
  returns, and a stray MBR boot signature (0x55AA) there is no partition table
  to the probe but makes sgdisk refuse to write a GPT.
- **Order.** Extract the tar and snapshot `BE@factory`; apply the identity and
  overlays; check the boot files, snapshot `BE@deployed` and set `bootfs`
  last. A hook runs in a chroot in its own PID namespace, with service starts
  refused and its output in a 0600 log, `deploy-ID-post-install-N.log`
  (`zboot-into-ID-post-install-N.log` for `--into`). A
  failed overlay or hook rolls the unpublished BE back to `@factory`; hooks
  are never replayed.
- `--image` creates its file exclusively and holds it throughout; on failure
  it removes the file only after proving its loop device detached.
- `--esp-partition PART` writes zboot's files on another disk's ESP as
  `esp PART` would, except that it never writes the fallback, and refuses when
  the canonical name or the fallback holds another system's file.

### deploy --portable

`deploy --portable` makes a system that boots on different machines without
writing to its pool; changes live in RAM until the next boot.

- *The constraint.* A pool opened for writing records the host that opened it
  and stays marked in use (a root pool is never exported at shutdown), so a
  stick booted the plain way on one machine would need a forced import on the
  next. A portable pool is therefore never opened for writing.
- *What it does.* It creates the pool under no hostid, writes no
  `/etc/hostid`, swap or `bootfs`, applies the portable overlay and exports
  the pool, which zboot afterwards imports only read-only (a host that
  scan-imports pools at boot does not, and records its hostid:
  [CLI](CLI.md#deploy)). The one write a boot
  makes to a stick is the EFI stub's `loader/random-seed` on its ESP;
  RESCUE-STICK checks the pool partition byte for byte.
- *Why no hostid, and how.* The menu keeps another host's pools closed, so a
  stick that recorded the machine it was made on would be hidden everywhere
  else. OpenZFS takes a pool's hostid from the `spl_hostid` parameter, else
  `/etc/hostid`, and omits a zero one, so zboot creates, imports and exports
  the pool in a private mount namespace with `/etc/hostid` covered and
  `spl_hostid` set to 0 for that time.
- *The portable overlay* imports the root pool read-only and puts a tmpfs
  (half of RAM) over it in the initramfs; its hook regenerates the initrds.
  *Why an overlay and not the tar:* the initrd imports the pool and mounts the
  root, so the settings must be inside it, and the overlay hook already runs
  where an initrd is regenerated. Any root tar can then become a stick. If the
  layer cannot be set up, the boot stops in the initramfs shell.

### esp

zboot's paths on an ESP are the firmware fallback `EFI/BOOT/BOOTX64.EFI` and
the files directly in `EFI/zboot/`. A file there is zboot's when it is a UKI
whose `.osrel` has `ID=zboot`.
Nothing else on the ESP is read or written; subdirectories of `EFI/zboot/` are
ignored.

- **Refresh (`esp`)** takes every ESP holding one of zboot's files on a disk
  that also holds an imported pool. That covers a pair's second disk and
  leaves a rescue stick alone, so the fallback medium is never updated in the
  same step. It also takes the ESP this boot came from when the root is on a
  writable pool and that ESP is on a fixed NVMe or SATA disk. *Why:* a host
  whose firmware starts the menu from another internal disk would otherwise
  keep booting the old menu, while a stick booted after a bad update is the
  fallback. On each ESP it rewrites zboot's files in `EFI/zboot/` under their
  names (firmware entries point at them) and the fallback when it is zboot's
  or empty, and leaves another system's file at either fixed path in place
  and names it. It needs no confirmation.
- **Install (`esp PART`).** On an ESP with none of zboot's files directly in
  `EFI/zboot/` it writes `EFI/zboot/zboot.efi` and the fallback; replacing
  another system's file at either is typed. The fallback is written first, so
  a rerun after a failure finishes the install. On an ESP that already has
  one of zboot's files there it refreshes, adding no second copy beside a
  loader firmware already boots. A zboot fallback alone does not count as
  installed.
- One plan covers all the ESPs and binds every partition, path and finding;
  free space is checked when it is made. Each file is replaced atomically. A
  failure after an earlier ESP changed is partial (exit 4); `esp` keeps no
  record and is rerun. It writes no firmware boot entry.

### Building the UKI

`dist/dist.sh OUT` builds the UKI, the package and the matching source archive
([BUILD.md](BUILD.md)). The same binary goes into the initramfs and the
package, so `builtin:rescue` is byte-identical in both. The package refuses to
install while any zboot operation is pending, because a new zboot neither
resumes nor abandons an earlier one's record.

## Wiping a disk

`wipe` erases a whole disk; `deploy DISK` and `restore` use it. The plan states
which method will run, why, and which devices it covers, and the token binds
the method. Both methods and the signature probe stay. *Why:* NVMe alone does
not guarantee a usable sanitize, and metadata clearing also serves virtual
disks.

**NVMe sanitize** is the default where it is safe. A sanitize erases a whole
NVM subsystem, so it is chosen only when that subsystem is the disk: the
kernel shows one PCIe controller of it, the controller reports no
multi-controller capability (CMIC 0), its active namespace list is the disk's
namespace alone, the namespace is not shareable (NMIC 0), and the subsystem can
hold no other namespace (without namespace management the controller supports
one namespace; with it, the allocated list is the disk's namespace alone). The
controller's sanitize capabilities pick crypto erase, else block erase.

**Metadata clearing** is used for every other disk, and the plan names the
reason: not NVMe, a fabric transport, possibly other controllers or
namespaces, or no sanitize or overwrite-only sanitize. Each saved partition,
then the disk, gets `zpool labelclear` where a ZFS label is present and
`wipefs --all`; the disk then gets `sgdisk --zap-all`. The data between those
structures stays, and the plan says so. Metadata clearing is chosen only
during review: a failed discovery query, a rejected sanitize command, a
sanitize failure or an uncertain outcome refuses and never falls back.

- **Binding the controller.** The sanitize goes to the controller's character
  device only when its device number is the one sysfs shows and it reports the
  serial that sysfs and the disk show and the subsystem NQN sysfs shows. The
  serial alone binds where the kernel shows no NQN or made its own (the
  `IGNORE_DEV_SUBNQN` quirk, as on ADATA SX8200-class controllers). Device
  number and serial are checked again right before the submission.
- **The sanitize log decides.** A sanitize already running (one resumes after
  power loss) is waited out first; failure mode and an unknown status refuse.
  Completion counts only when the log records this action and the operation
  was seen running or the log changed after the submission. An unchanged
  success is an earlier one and refuses, except for a crypto erase whose log
  stays unchanged for five polls and shows a successful crypto erase with
  Global Data Erased set: the report then says no new sanitize was observed
  and the controller reports no user data written since. zboot polls every
  2 s for up to 12 h, and reports what the controller reported, not that the
  data is erased. A sanitize cannot be aborted; the plan says so.
- **Verification** reads signatures and metadata, not every byte: no
  partitions, no signature found by `zboot-probe-signatures`, no ZFS label in
  the disk or any saved partition, no GPT header and an unchanged identity.
  The probe does not prove secure erasure. A system without it refuses every
  erase plan.

QEMU's emulated NVMe has no Sanitize command: WIPE-NATIVE covers metadata
clearing, and WIPE-SANITIZE-NATIVE runs the native sanitize path against a
fake `nvme`. [TESTING](TESTING.md#real-hardware) records real-hardware runs.

## Booting a root tar in RAM

`zboot boot --tar FILE|-` boots a full system in RAM from the UKI, which works
on a network-booted machine without a rescue stick. Any root tar works
unchanged, because zboot's own bootstrap replaces the tar's initrd: it unpacks
the tar and the overlays' files into a tmpfs and switches to the tar's init.

- An overlay's `post-install` has no step to run in, so zboot refuses it
  rather than silently skipping it.
- zboot passes only the UKI's consoles and the adopted hostid, no keys,
  passwords or network settings. *Why:* anything else ties zboot to how each
  root configures SSH and networking. The uploader is already root in the UKI,
  so booting the upload adds no authority.
- A `zfs send` stream cannot boot in RAM: the next kernel cannot see a pool
  made in the previous kernel's memory. The RAM check counts the larger of
  the booted system (the compressed tar plus the unpacked root) and the
  staging peak (three copies of the tar: the staged initramfs and what
  `kexec` holds while loading it; an upload is freed before the load).

## Network boot

A boot server serves only `zboot.efi`, one self-contained file, by UEFI HTTP
boot or a loader such as iPXE; it then boots as from a stick. Firmware HTTP
boot passes no arguments, so remote access is `connect`. A loader's arguments
replace the embedded line when Secure Boot is off, so they repeat
`zboot.recovery=1` and the consoles and may add `zboot.ssh_key=`, which has
unit tests only.

## Guided restore

Restore rebuilds disk A from a BE on surviving disk B while keeping selected
datasets of A. It saves the kept data on B, verifies it, erases A, then copies
the BE and the kept data back. Data moves one dataset at a time, parents
first, as raw streams without properties, `-R` or `-F`, so encrypted data
moves without keys. A saved *manifest* records the properties and key
information to check each copy against.

The steps ([RECOVERY.md](RECOVERY.md#restore-a-disk) lists them for the
operator): plan; snapshot and hold the source on B; stage the kept trees with
the receipt and manifest; verify staging without keys, hold it and scrub B;
erase A and deploy an empty pool and ESP; return the data, relink encryption,
apply the manifest and verify; make A the boot default and export it. Staging
stays on B until the operator drops it. Decryption is never exercised, so a
raw-send bug visible only in decrypted data's MAC would go undetected.

The source is an explicit recursive `BE@SNAP` or the running BE, snapshotted
now. Only the menu's picker chooses a snapshot for a bare BE, because the plan
it leads to names that snapshot to the person who then types the disk's
serial. A returns with the source BE's own `/etc/hostid`, and every import of
A runs under it.

State is one `zboot:operation` record on B. Staging is `B/zboot-restore-<id>`,
fenced and marked `zboot:staging=<id>`, with snapshots `@zboot-restore-<id>`
and holds `zboot:restore:<id>`. Keys are checked with `zfs load-key -n`,
which loads nothing, while nothing of A is mounted, so a key only A holds
fails. The token binds the disk, the source, the kept roots, everything of A
that is lost and every pair record restore ends.

- **The receipt** on B holds every source and kept dataset's placement,
  copied properties, encryption and pair role. Once A is erased it is the only
  record of these values: staged copies carry no property, and staging never
  gets one, such as `zsnap:policy`, that a timer could act on. It is captured
  from A once the kept trees are snapshotted and written once, as
  `zboot:attachment:<id>:receipt:` chunks on staging; the record advance that
  names its digest commits it, before any data moves. From then on every step
  reads it and refuses if it does not read exactly; it is never captured
  again. Completion removes it after the last step that reads it.
- **Destruction rule.** Restore destroys a dataset only when it lies in a
  scope this operation made and records (its staging, or the pool it deployed
  on A) and its content shows nothing was added since. Neither condition alone
  authorizes anything.
- **The erase gate.** Before the erase, the kept trees, staging, its key
  wrapping, every key file, the pair records to end, the key relink helper and
  A's identity and layout are all checked again; a resume with only the erase
  ahead repeats this. A kept tree whose key changed after staging stops the
  restore, because the new key may live only on A.
- **Keys.** On A, restore relinks each dataset to its copied encryption root
  through `zboot-change-key`. *Why a helper:* zboot is static, and glibc's
  static `dlopen` needs the build's own glibc at run time, so zboot never loads
  libzfs_core itself.
- **Pairs.** The restored BE is unpaired. A pair whose other side is on the
  erased pool ends one-sided, as `unpair` does for a gone peer; a kept paired
  dataset returns unpaired in its role with its anchor tag, so `pair` joins
  the two again without a full copy. A record whose peer's pool is not
  imported at plan time cannot be matched to the target disk and stays; the
  plan names the `unpair` that ends it.
- **Abandon** destroys nothing. From the erase until A is verified, staging
  may be the only good copy, so its holds and marker stay, with the original
  placement kept as `org.zfs-tools:restore-placement:<id>:` metadata on it:
  the receipt's chunks, then a manifest naming their digest. The receipt
  itself is removed only after that copy reads back.
- **The loader.** Restore installs the `zboot.efi` that SOURCE ships, read
  from the held snapshot and bound into the token. *Why no `restore --efi
  FILE`:* the held snapshot still has the loader for a resume after a reboot,
  and a named file would need its own copy on B and its own check. Whoever can
  write SOURCE already controls the restored system.

### Stock receive properties

The receive rules depend on this stock OpenZFS behavior, checked natively on
Debian's OpenZFS 2.4.4 by STOCK-RECEIVE-PROBE and, for restore's own streams,
RESTORE-PROPERTIES-NATIVE.

- Without `-R` or `-p` the receive gets no received property list, and without
  `-o` or `-x` no local one, so it changes no property of an existing dataset
  and never clears its local values. A stream that carries properties into a
  dataset made by `zfs create` clears every local value at its first receive.
- `receive -o` stores a local value before data arrives: `-o copies=2`
  doubles the received blocks. Received blocks follow the receiving dataset's
  own write-time settings.
- A new dataset inside the staging container inherits `readonly`,
  `mountpoint` and `volmode`, but not `canmount`; inherited values end when it
  is renamed out, local ones stay.
- A raw receive into a new dataset makes it its own encryption root with a
  local `keylocation=prompt`. Into an existing dataset it replaces the wrapped
  key, `keyformat`, salt and iterations with the sender's and checks only the
  master key, so after a key change on the sender a dataset that inherits its
  key accepts the stream and then fails to mount: zboot's wrapping proof is
  the only guard.
- A non-recursive receive fails with "destination already exists" when a
  common snapshot has another name on the copy.
- A volume with `volmode=none` has no device, also across an import.
- A `-R -b` stream from a staged encryption root has no keylocation and
  cannot be received, so restore never uses `-b`.

## Consumers and compatibility

- **Rust applications** use the supported checkpoint API and keep their own
  lifecycle policy, guards and recovery paths.
- **Snapshot timers and backup jobs** use zsnap's policy and supervised reader
  contracts.
- **Loader paths and the kernel command line** keep zboot's ESP paths and the
  handoff tokens (`boot=zfs`, `root=ZFS=`, `zboot.trace=`, `spl.spl_hostid=`).

All active writers touching the same target must be tested together, stay
compatible when changing shared state, and leave interrupted work recoverable
by its owning application; matching version numbers alone do not establish
that. An upgrade stops incompatible loaded writers first and needs a host with
no open operation; no persistent writer epoch enforces this across builds.

## Known limitations and follow-up

- **Space limits across `primary`.** `status` and the `primary` plan list the
  space limits a copy does not hold, but a lossless `primary` prints its plan
  only with `--dry-run`. After the switch the next sync, an unattended
  `sync --all` included, removes from the old side a limit the new working
  copy does not set. Read `status` before that sync.
- **A volume's `volmode`.** A `volmode=none` set by hand is not saved across
  `primary`, because at rest it cannot be told from the fence's own; the new
  working copy inherits `volmode`. A switch abandoned after its records were
  reversed, then finished with `primary TARGET`, gives the target its own
  saved value, not the old working copy's.
- **Frozen source.** A transfer freezes its source's snapshots, placement
  (`volmode` included) and copied properties. Changing one before the
  transfer ends makes its resume refuse, and once the data is verified an
  abandon refuses too. The refusal names what changed; set it back and
  resume.
- **Diverged copy.** A snapshot that only the fenced copy has after the last
  common one stops every sync. `primary` keeps that copy's side; keeping the
  working copy's has no verb, so destroy the snapshot by hand
  ([CLI](CLI.md#pairs)).
- **Key change.** After a key change on the working copy, a sync into an
  own-root copy makes it need the new key, with no dedicated notice.
- **Fork leftovers.** A fork leaves in place a staging container that holds
  something zboot did not make, another tool's snapshot for one, and names
  it; `drop` removes it after listing what it holds.
- **ESP copies elsewhere.** A zboot UKI outside `EFI/zboot/` and the fallback
  (in `EFI/Linux/`, say) is neither refreshed nor reported. Old
  `EFI/zboot/operations/*.json` files are inert; remove them by hand.
- **User property values in tab-separated output.** OpenZFS validates user
  property names, not values, and `zfs get -H` cannot delimit a value that
  holds a tab and a newline. The library's inventory keeps user properties
  out of its identity listing, so they cannot forge a member, an identity or
  an absence; with properties requested, such a value can forge a row for a
  property its dataset lacks (a copy of one it has is refused as a
  duplicate). The admission checks that read `zfs get all` share this limit:
  their writers are assumed to be root or delegated `userprop` holders the
  host trusts. JSON output (`-j`) would remove it, but it needs OpenZFS 2.3,
  and the package depends on an unversioned `zfsutils-linux` (Debian 12
  ships 2.1) and is qualified only on 2.4.4.
- **Qualification.** Results qualify only the exact source, runtime and
  application combination tested. NVMe sanitize has fake-backend tests,
  WIPE-SANITIZE-NATIVE and real-hardware runs on two controller models, a
  block erase on one and a crypto erase on the other.
  Engine tests alone, with no acceptance case yet, cover `primary` and an
  incremental sync on a volume, a `canmount=off` leaf in a pair, a power cut
  in the middle of a sync, and a restore whose boot environment is encrypted
  or holds a volume. `pair` publishes through the bootstrapping `sync`
  executor (4e1d4d88, fb1557c4); `PAIR-UNPAIR-NATIVE` and
  `PAIR-REFUSALS-NATIVE` cover it at qualification, but no case pairs a
  mounted receiver or resumes an interrupted pair. Not yet run on hardware:
  `chroot`'s resolver copy, `deploy` without root, and RECOVERY's shell
  recipes for an older OpenZFS and for an unread property.
  `EFI-HANDOFF-NATIVE` (a marked boot environment through the Menu)
  has not run since d4c0b240.
- **Caller-owned effects.** `EffectScope::dispatch` has offline tests for
  every shape's argv, its refusals, the revalidation order, custody from
  another thread, the deadline kill and poisoning, a descendant holding the
  child's pipes (descriptor and thread counts, in an isolated rerun of the
  test binary), and native guest cases
  (`tests/native-api`) for the volume, pool and key shapes, a target
  replaced between admission and spawn, a refused management key, a
  refused deferred origin and a child that keeps the lock after its caller
  is killed. An unreaped child is simulated only; no case puts a child in
  uninterruptible sleep. Between the last observation and the exec the
  argv names its operands by name: a writer outside the lock (a raw `zfs`
  command) that destroys a target and creates another at its name in that
  window gets the effect applied to the replacement; cooperating writers
  cannot, because they wait for the lock. The thread-local custody zboot's own engine uses
  still runs a writer without the lock on a thread that holds none.
- **Observation deadlines.** Offline tests run real shell queries: a leader
  that exits while its descendant keeps stdout, a leader that never exits, a
  writer that never stops (`yes`, for queries and effects), stdout over its
  cap, an exit seen only after the deadline, a deadline passed between
  queries and after the last, a leader reaped elsewhere (never signalled),
  SIGCHLD ignored (isolated reruns, and through the public API), an effect
  dispatch whose observation expires (no effect child), and an integration test (`tests/observation_deadline.rs`) through
  the public API that checks the process's descriptor, thread and child
  counts after expiry. An unreaped leader is simulated with an ignored
  signal; a guest case expires a real `zpool` whose wrapper's descendant
  keeps its pipe. No case holds a query in uninterruptible sleep, and the
  late reap needs a later bounded query: a caller that makes none keeps the
  zombie until it exits. Signal safety rests on two things the library checks
  only at the start of each query and dispatch: a stable SIGCHLD disposition
  and exclusive reaping of its children for the whole run. A disposition
  changed to ignored, or a competing reaper (`waitpid(-1)`, a reaping
  SIGCHLD handler), during the run can release the leader's PID between the
  `WNOWAIT` check and the kill, so the kill could reach a reused PID's
  group.
- **Review coverage.** The pre-publication audit of 8a742c28 did not read the
  bodies of `restore`, `handoff`, `device`, most of `menu`, the zsnap modules
  beyond unused code, CLI.md's pairs prose or RECOVERY.md's restore steps.

### Open questions and follow-ups

- Show a lossless `primary` the space limits it leaves behind without
  `--dry-run`. Let `sync` offer a copy-only snapshot newer than the anchor
  for review, as it does older ones.
- Not designed yet: booting a boot environment once and falling back to the
  default; non-Debian roots (kernel naming, `root=zfs:`, one QEMU case on a
  dracut root); reading boot environments without importing (`zdb -e`); signed
  UKIs under Secure Boot, where a key file on the ESP would need the same
  protection.
