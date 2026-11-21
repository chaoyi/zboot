# ZFS tools Rust library

`zfs-tools` lets Rust applications look up exact ZFS dataset and snapshot
identities, inventory a dataset tree, capture and delete checkpoints,
protect snapshots while readers use them, and run their own guarded native
effects. Writes use short writer sessions that coordinate cooperating local
applications.

This is a source API; it does not promise a stable Rust binary ABI or expose
private engine representations.

```toml
[dependencies]
zfs-tools = { path = "../zfs-tools/crates/zfs-tools" }
```

The supported API needs no feature. The non-default `internal` feature exists
only for this workspace's `zboot` and `zsnap` applications; it is unsupported
and unstable, and no other package should enable it. The supported native
platform is Linux/OpenZFS; the boot distribution additionally targets x86-64
UEFI/Debian.

## Inventory

`observe_inventory` reads one dataset tree without a writer session. An
`InventoryRequest` names the root (a pool name is allowed) and opts into
snapshot history (`with_snapshots`) and every native property with its source
(`with_properties`). The result lists each dataset's current incarnation,
kind, origin and mount facts (`mountpoint`, `mounted`, `canmount`,
`readonly`), and each snapshot's `SnapshotRef` with its deferred-destruction
flag, hold tags, clones and creation time.

Absence is a result only when successful native queries prove it: the root's
pool is not imported (`pool_guid()` is `None`), or a name-only listing of
that pool down to the root's depth lacks the name (`pool_guid()` names the
pool it is absent from). `dataset` and `snapshot` return `Ok(None)` for such
a name. Every failed or malformed query is an error. When snapshots or
properties are requested, the root's subtree and the pool are listed again
after them and must be unchanged, so a member created, destroyed or replaced
at its name between queries is an error, never a mismatched snapshot parent
or a destroyed dataset reported present. Lookups refuse names outside the
root, and history or properties that were not requested, so neither reads as
absence. Property sources are typed (`PropertySource`); an unknown native
source, or an inheritance from a dataset that is not an ancestor, is a
malformed observation. Snapshot properties are not inventoried.

A dataset the inventory lists and cannot read, such as a volume left without
a size by an incomplete or abandoned receive, fails the inventory with its
name. Datasets outside the root's subtree are listed by name only and only
to the root's depth, so they do not affect it.

User property values are free text that native tab-separated output cannot
delimit. The identity listing carries none, so they cannot forge a member,
an identity or an absence. With `with_properties`, a value holding a tab and
a newline can add a forged row for a property its dataset lacks; a forged
copy of a property it has is refused as a duplicate. Read properties only
where you trust every writer of user properties in the tree
([known limitations](../../docs/DESIGN.md#known-limitations-and-follow-up)).

An inventory is sequential evidence like the exact observations below; an
admission must bind and revalidate what it read.

## Composition

1. Read `observe_dataset`/`observe_snapshot`, or `observe_inventory` for a
   tree, to obtain exact names and native incarnations. These observations
   are sequential evidence, not admission.
2. Acquire one `WriterSession` for the necessary mutation critical section.
3. Construct immutable `DatasetTarget` values from the reviewed incarnations,
   requiring `DatasetKind::Volume` when checkpointing a zvol.
4. Use `admit_guarded` when an application must recheck its own lifecycle custody
   or idleness before observations/effects. The callback cannot provide a native
   backend, mutable ZFS state or executable commands to the library.
5. Capture through the borrowed exact scope, or obtain an in-memory `DeleteReview`
   and apply its matching loss token. Each operation performs fresh native
   revalidation. Neither scope borrowing nor a matching token replaces it.

An exact scope does not enroll descendants. Native creation remains atomic per
pool only. Inspect the typed complete/partial/uncertain outcome even when the
Rust call returns `Ok`; an uncertain reply is not success or permission to retry.
Snapshot deletion refuses changed incarnations, holds, clones, deferred destroy
and unsupported managed roles. Drop never silently deletes or releases data.

The session reuses one exclusive host flock. Native mutating children inherit
that exact open-file description so frontend death does not release the critical
section beneath a still-running writer. This coordinates cooperating local
writers, not raw external tools, application quiescence or another host.

`WriterSession`, admitted scopes and deletion reviews are opaque and are not
constructible from serialized private plans. Public identities and references
are data; knowing them does not grant native ZFS permissions. Application
lifecycle exclusion, physically enrolled pool ownership and private mount/view
custody remain the caller's responsibility.

Capture and deletion outcomes implement `serde::Serialize` for worker and audit
JSON, with snake_case status strings and decimal-string native identifiers. They
do not implement `Deserialize`; sessions, admitted scopes and deletion reviews
have no serialization interface.

## Observation deadlines

By default an observation's queries have no deadline. A caller that must
bound one sets a deadline for the **whole observation**:
`InventoryRequest::within(d)`, `observe_management_within(name, d)`, or
`WriterSession::admit_effects_within(targets, guard, d)`, which bounds the
admission's observation and each dispatch's fresh one, every observation
separately (not the guard or the effect child, whose deadline is
`dispatch`'s). The deadline starts when the observation does and covers every query it
runs, each until both of its pipes reach end of file and it exits, and the
observation's own work on the output: the clock is checked again before a
query's output is accepted and before the result is returned. Pipes are read
on the calling thread, one bounded read per ready pipe per wakeup, so
neither a busy writer nor a descendant that keeps a pipe open can hold the
caller past the deadline, and no reader thread is left behind. A query's
standard output is capped at `MAX_QUERY_OUTPUT` (64 MiB): parsing allocates
rows and fields well beyond the raw bytes, and a host with tens of thousands
of snapshots emits a few MiB.

A stopped observation returns no result, not even absence: the running
query's output is discarded, never parsed, no later query starts, and the
error's `observation_stop()` says why: `Deadline`, `OutputLimit`,
`QueryFailed` (a pipe or wait error; each with a `QueryCleanup`) or
`ChildrenNotWaitable`. `QueryCleanup` says exactly what
was established: `NoneRunning` (the deadline passed between queries or after
the last; nothing was signalled), `LeaderReaped` (SIGKILL was sent to the
running query's process group and its leader reaped; members that left the
group are not proven gone) or `Unconfirmed` (the signal or the reap within
ten seconds could not be confirmed; the library keeps a leader that is still
its child and reaps it during later bounded queries, and the error's text
names the failed step). A read-only query holds no writer lock, so a stop
does not poison a session. A zero deadline is refused.

The leader is waited for unreaped until its output is complete, so its PID
still names its group for the kill. That needs this process to keep its
children waitable: a bounded observation (and a dispatch) refuses before any
spawn while SIGCHLD is ignored or `SA_NOCLDWAIT` is set
(`ChildrenNotWaitable`), and nothing is signalled once the leader is not
known to be this process's unreaped child. **Do not reap the library's
children yourself** (`waitpid(-1)`, a SIGCHLD handler that reaps): the
library then cannot vouch for what it stopped. The `-v` announcement is
written to your stderr before each spawn; its time counts against the
deadline, but a blocked stderr is not interrupted; the deadline is checked
again after it, before the spawn. zboot's and zsnap's own
reads never have a deadline: on a large or degraded pool a slow read is not
a failure there.

## Caller-owned effects

An application that keeps its own policy runs its native ZFS effects through
`WriterSession::admit_effects` and `EffectScope::dispatch` instead of its own
`zfs` and `zpool` children.

1. Admit `EffectTarget`s: `dataset` (one incarnation), `subtree` (with every
   descendant, fixed at admission), `pool` (a `PoolTarget` by name and GUID,
   optionally `with_load_guid` to bind one import instance), `absent_pool`
   (a name to create) or `exported_pool` (a GUID to import). The guard runs
   before the admission's observation.
2. Build an `Effect` from one closed constructor. Each pins its argv
   (`Effect::argv`, fixed by its operands, so a caller can compare it with
   the command it consents to offline); the operands it names must be
   admitted when it is dispatched.
3. `dispatch(&effect, deadline)` runs the guard, observes afresh, repeats the
   original admission, binds the operands to that observation, runs the
   guard again and spawns the child, which inherits the session's own lock
   (from any thread; it keeps the lock if the caller dies). `Err` means no
   child started. The reply is `Succeeded`, `Failed { status, stderr }` or
   `Uncertain { why }`: what the command said, never what ZFS now holds, so
   read back before continuing and never retry blindly.

The deadline kills the child's process group and waits for the reap. The
child's pipes are read on the calling thread, a bounded read at a time, so
the deadline holds whatever the child writes: a descendant that keeps one
open leaves nothing behind, and only costs the reply's stderr (two seconds
after the exit, then `(stderr unavailable)`). A kill whose group signal or
leader reap is not confirmed poisons the session, which then refuses every
later admission, dispatch and reader protection, release or recovery; its
holds stay in place. An effect that adds or removes a dataset or pool, or
rolls one back, ends its admission. No shape sets or inherits a `zboot:` or
`org.zfs-tools:` key or sets `volsize`; an inheritable key needs a subtree
admission. Every shape refuses a paired dataset, one another pair record
still names as its peer, and a pool holding a zboot operation record.

The guard takes a `GuardCheck`: no effect at admission, then the effect
before its observation, then the effect with its bound argv (`argv()`)
right before the spawn. Compare `check.effect()` with the effect your
consent names.

`DevicePath` is taken as given: the library checks its shape, not which disk
it names. Source it only from your reviewed device selection and keep your
own wrong-disk proof. Key and passphrase bytes are borrowed, written once to
the child's standard input and never copied; zeroize them yourself.

Each shape exists for a named caller in Fleet (paths in Fleet's
`engine/fleet-data/src` unless noted):

| Constructor | Argv | Fleet caller |
|---|---|---|
| `create_volume` | `zfs create -s -V SIZE -o volblocksize=N [-o K=V]... NAME` | `volume.rs` (VM volume create) |
| `create_filesystem` | `zfs create -u [-o K=V]... NAME` | `preparation.rs` (`create_dataset`) |
| `clone_snapshot` | `zfs clone -u SNAPSHOT NAME` | `volume_lifecycle.rs` (`clone_volume`), from `engine/src/vm/storage.rs` |
| `destroy` | `zfs destroy NAME` | `volume_lifecycle.rs` (`destroy_volume`) |
| `rollback` | `zfs rollback SNAPSHOT` | `volume_lifecycle.rs` (`rollback_volume`) |
| `set_properties` | `zfs set -u K=V... NAME` (never `volsize`) | `preparation.rs` (`reconcile`), `placement/metadata.rs`, `placement/root.rs` (`set_noauto`), `bound_pool/adopt.rs` (`set_canmount_off`) |
| `inherit_property` | `zfs inherit KEY NAME` | `placement/metadata.rs` (`InheritMountpoint`), `bound_pool/create.rs` (`clear_pending`, as `org.fleet:pending`) |
| `load_key` | `zfs load-key NAME`, key on stdin | `bound_pool/unlock.rs` (through `create.rs` `run_load_key`) |
| `unload_key` | `zfs unload-key NAME` | `bound_pool/root_unmount.rs` |
| `unmount` | `zfs unmount NAME` | `bound_pool/root_unmount.rs` |
| `create_pool` | `zpool create [-o K=V]... [-O K=V]... NAME DEVICE`, passphrase on stdin | `bound_pool/create.rs` (`run_create`) |
| `import_pool` | `zpool import -N -o cachefile=none -d LEAF GUID` | `bound_pool/native.rs` (`import`), `preparation.rs` (`import_pool`) |
| `import_pool_readonly` | `zpool import -N -o readonly=on -o cachefile=none -d LEAF GUID` | `pool_access.rs` (DATA restore of a read-only bound pool) |
| `export_pool` | `zpool export NAME` | `bound_pool/native.rs` (`export`), `bound_pool/create.rs` (`export_record`, bound to `load_guid`), `preparation.rs` (`export_pool`) |
| `sync_pool` | `zpool sync NAME` | `bound_pool/create.rs` (`sync_pool`) |

Snapshot destruction is not a shape: `volume_lifecycle.rs`'s
`destroy_snapshot` uses the reviewed checkpoint deletion above. Mounts and
namespaces for views and maintenance (`view.rs`, `mounted_view.rs`,
`maintenance.rs`) stay the caller's.

`observe_management(name)` reads a dataset's `Role` (`Unpaired`, `Primary`
or `Secondary` with its `Peer`) and its `Unfinished` zboot work (its pool's
operation record, a `zboot:pending` or `zboot:staging` mark and its holder)
without a session (`observe_management_within` bounds it, above).
`InventoryRequest::with_pool_properties` adds the root's
pool properties (`load_guid` among them) to an inventory. A busy writer lock
is an error whose `busy_holder()` names the holder.

## Protected readers

`WriterSession::protect_reader` records the complete intended receipt through
the caller's durable persistence callback before the first native observation
or hold. Its owned `ReaderProtection` survives the acquiring session, cannot be
cloned or deserialized, and retains protection when dropped. Partial or
uncertain acquisition returns structured evidence and performs no compensating
release.

Do not hold a writer session throughout a long read. Before starting a reader,
use a fresh session's `revalidate_reader` to check the exact protected snapshots;
the application must separately establish private view and reader custody.
After every reader and descendant has ended, use `end_reader` with a lifecycle
guard. `ReleasePolicy::PreserveSnapshots` refuses release that could complete
deferred deletion; `EndProtection` requires an explicit caller decision.

`ReaderReceipt` is validated, serializable recovery data using the existing
schema-2 receipt format. It does not prove reader death. `recover_reader`
requires the caller to establish and retain lifecycle custody; it reconciles
proven absence and already-released points before releasing remaining owned
holds. Changed or uncertain identities refuse pending release effects. A
parsed receipt, writer lock or missing application record grants no lifecycle
authority.

Applications needing a complete Linux supervised task can use `zsnap protect`
and `zsnap recover` instead of implementing custody themselves. Their
[reader task contract](../zsnap/README.md#protected-snapshot-readers) covers
cgroup-v2 process custody, private read-only views, immutable reader manifests
and recovery.

## Applications and compatibility

`zboot` (`crates/zboot`) and `zsnap` (`crates/zsnap`) are separate application
packages in this workspace. They use the private engine through the `internal`
feature; their grammar, menu, JSON and exit statuses are compatibility
contracts. zsnap's pure snapshot policy values and calculations are the root
API of the `zsnap` library crate; its native transport and property modules
stay private.

This library builds no command binary and enables no feature by default.
Reader receipts keep the schema-2 `zctl1:` hold-tag format. Only `zboot:`
properties are management state; a `zboot:` property this build does not
read refuses the dataset. Effects also never write the reserved
`org.zfs-tools:` namespace. Upgrade consumers together with their
persistent state and recovery paths. There is no public inherited-lock
protocol (only a closed effect's child inherits the lock), generic RPC
service or mirrored plumbing CLI.

The [checkpoint example](examples/checkpoint.rs) uses only the supported API.
The [native SDK proof](../../tests/native-api/README.md) runs it against real
OpenZFS in a disposable guest and lists what that proof does and does not
qualify. Offline child-custody and uncertain-outcome tests provide separate
coverage.

Active writers that touch the same target need qualified shared-state
compatibility; a matching version is not enough.
[The design](../../docs/DESIGN.md#consumers-and-compatibility) gives the full rule.
Qualification applies to the exact source revision, native runtime and
application combination tested ([testing](../../docs/TESTING.md)).
