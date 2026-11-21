# Zsnap

`zsnap` captures snapshots, applies retention policies and runs commands over
protected snapshots. Use `snap` for an immediate capture, `run` and `prune` for
scheduled retention, and `protect` for a reader such as a backup command that
needs its snapshots to remain available until it finishes.

This package is a library and the `zsnap` command. The library's root holds the
pure retention policy API: policy and duration parsing, the keep plan and
snapshot naming. The commands use the [zfs-tools](../zfs-tools/README.md)
engine through its unsupported `internal` feature, so every write uses the
library's shared capture and exact-deletion operations and safety checks.

```text
zsnap status [DATASET] [--config FILE] [--json]
zsnap snap DATASET... [--dry-run]
zsnap run [--config FILE] [--dry-run]
zsnap prune [DATASET] [--config FILE] [--within DURATION] [--last N] [--hourly N]
            [--daily N] [--weekly N] [--monthly N] [--yearly N] [-y|--yes] [--dry-run]
zsnap assign DATASET POLICY [--config FILE] [--dry-run | --request-json FILE]
zsnap unassign DATASET [--dry-run | --request-json FILE]
zsnap protect ([--capture] SOURCE... [--end-protection] | --request-json FILE)
              [--user ACCOUNT] [--env NAME]... [--view DIR] [--consumer NAME]
              [--result FILE] [--state-dir DIR] [--stop-timeout SECONDS]
              (-- COMMAND... | --dry-run [-- COMMAND...])
zsnap recover [JOB [--stop]] [--dry-run | --confirm TOKEN] [--json]
              [--state-dir DIR] [--stop-timeout SECONDS]
```

`-c` is short for `--config`. `--confirm` needs JOB.

`protect` and `recover` require root and a supported cgroup-v2 hierarchy. Their
[protected snapshot reader contract](#protected-snapshot-readers) is below.

## Capture and retention

`snap` captures the exact dataset set, independently of assignment and frequency.
It does not recursively enroll children. Capture reports effects per pool; a
cross-pool request can report a partial outcome. No capture or retention
workflow provides multi-command atomicity. Names use UTC seconds in
`DATASET@zsnap_YYYY-MM-DD-HHMMSS`; a manual capture retries only pre-effect
same-second collisions, at most twice. Uncertain effects are never retried.

`run` discovers effective `zsnap:policy` assignments. An empty stream is due
immediately. Existing streams are throttled by frequency, then queried for
referenced newly written bytes; zero skips capture. This metric is a scheduling
heuristic, not proof of a quiescent application. The timer prunes each assigned
stream independently and returns failure if any dataset fails.

`prune` previews exact local snapshot incarnations before confirmation; `-y`
accepts that preview. Without `-y` it asks on the terminal, and only when both
stdin and stderr are terminals; otherwise it prints the preview, changes
nothing, never reads stdin, and exits 3 asking for `-y`. It holds no writer
lock while it waits for the answer; afterwards it takes the lock, plans again
and deletes only if the plan is unchanged. Overrides replace the whole keep
policy for that invocation.
Only canonical Zsnap names on each exact dataset become candidates. Holds,
dependent clones, managed roles and pending operations remain shared-executor
guards. `--last 0` selects the entire owned stream without bypassing those guards.
Shared deletion works on a pair's working copy and refuses its fenced copy.
Uncertain/partial execution returns a failing exit status and the observed
per-point outcomes.

Policy commands (`status`, `snap`, `run`, `prune`, `assign`, `unassign`) exit
0 on success, 1 on refusal or failure and 2 on a usage error. `prune` without
`-y` and without a terminal to ask exits 3: not confirmed, nothing changed, as
for zboot's unconfirmed loss verbs.

`assign DATASET none` creates a local disabled value. `unassign` clears the local
override and reports the resulting effective value/source: an ancestor's policy
may become active. Assignment never writes boot/pair metadata.

Config precedence is explicit `--config`, then `ZSNAP_CONFIG`, then
`/etc/zsnap/zsnap.toml`. Only a missing default file uses built-ins silently. Named
definitions replace complete built-in definitions; unknown fields and invalid
retention refuse loading. Built-ins are in [policies.toml](src/policies.toml).

Writes take the shared host writer lock;
[DESIGN.md](../../docs/DESIGN.md#writer-lock) gives its scope. Capture and
retention also use native ZFS outcomes, holds, and fresh identity checks.
Concurrent conflicts can fail or leave partial results; sequential observations
and commands are not atomic. Stateful storage restructuring and temporary
import/export workflows require exclusive ownership of their affected resources;
these executors provide no application freeze. This crate installs no timer
service.

`cargo test -p zsnap --offline` runs this package's unit tests and its policy,
configuration and CLI integration tests (`tests/retention.rs`,
`tests/config.rs`, `tests/cli.rs`) without ZFS or root.
Native capture and retention protections are checked in a disposable guest by
`RET-02-NATIVE` ([TESTING.md](../../docs/TESTING.md#qemu-acceptance)).

## Policy JSON (schema 1)

`zsnap status [DATASET] --json` produces a typed, read-only report: `schema_version`,
`observed_at` (UTC epoch seconds), `non_atomic`, policy definitions (frequency and
retention durations in seconds), and `datasets`. Each dataset contains `expected`,
snapshot count, oldest/newest ages in seconds, `used_by_snapshots_bytes`, accounting
errors, optional written-since-newest bytes, and a scheduling diagnostic. Null
accounting means unknown, never zero. Role/pending/unknown-management blockers are
reported separately; old unchanged heads are `unchanged`, not overdue work.
A read-only dataset is not a blocker but an ordinary state: its diagnostic is
`fenced` for a pair's fenced copy, which follows its working copy through
`zboot sync`, and `read_only` otherwise; `expected.blocker` still carries the
admission refusal, which the text view omits.
The overdue warning requires an age strictly greater than twice the policy
frequency; ordinary capture scheduling still starts at one frequency.

Copy the chosen row's entire `expected` into a request:

```json
{"schema_version":1,"expected":{"dataset":"tank/data","identity":{"pool_guid":"1","guid":"2","createtxg":"3","objsetid":"4"},"policy":{"value":"none","source":"local"},"local_value":"none","inherited_policy":null,"authority":{},"blocker":null},"change":{"set":"guard"}}
```

The identity and empty authority above are illustrative, not valid substitutes
for a real status observation. `expected` binds name/incarnation, effective policy
and source, local assignment, intended inherited policy, management authority and
admission. The entire ancestor policy value/source chain is bound, including
absence. Unassign completes only when readback matches the reviewed inherited
value/source. Authority also binds ancestors and pair peers, and conservatively
includes every observed management, identity and posture record, so an
unrelated management change can require a fresh review. A request cannot
assert admission: native admission runs again.

Use `zsnap assign tank/data guard --request-json request.json` or
`zsnap unassign tank/data --request-json request.json`; the latter request has
`"change":"inherit"`. `--request-json -` reads stdin. The dataset and change must
match the conventional positional arguments. Requests reject unknown fields and
versions, and input is limited to 4 MiB. Assignment still validates the target's
policy configuration. This flag conflicts with `--dry-run`; use status to plan.

Both forms emit `{ "schema_version": 1, "outcome": ... }` using the policy
executor's complete/uncertain outcome and verified effective value/source. A
nonzero exit or uncertain result is unfinished; pre-effect refusal emits an error
on stderr without a result. Reobserve before further reconciliation. Neither a
zero native command exit nor an uncertain partial observation proves convergence.

Controllers use the status/request JSON contract above. Its transport and
property executor are private modules of this crate, not an external backend
API. Both pre-effect observations must match the expected state before the
effect. This transport accepts no arbitrary property names or commands. Pure
policy values and calculations are the `zsnap` library's root API.

## Protected snapshot readers

`zsnap protect` runs a command over exact filesystem snapshots and keeps ZFS
holds on them until the command and all its descendants have ended. It creates
private read-only views for the command, then tears them down before releasing
protection. `zsnap recover` reviews interrupted tasks before confirmed cleanup;
a live owner or unproven reader death retains protection.

The calling application still owns job and repository policy, credentials,
application consistency and authorization of installed workers. For example,
protecting a snapshot keeps it available for a backup command; it does not
make the application data in that snapshot consistent. The
[library guide](../zfs-tools/README.md#protected-readers) covers Rust integration
for applications that manage reader lifetimes themselves.

`zboot snapshot` makes a recursive tree checkpoint for boot/tree workflows.
`zsnap snap` captures exactly the named datasets independently of policy
scheduling. `zsnap protect --capture` captures and protects the sources for one
reader command.

### Running a reader

Run these tasks as root:

```sh
# Preserve an existing exact filesystem snapshot through a non-root reader.
zsnap protect --user backup --result /run/backup-result.json \
  tank/home@nightly -- restic backup /run/zsnap/view/tank/home

# Capture and protect an exact, nonrecursive set for this complete command.
zsnap protect --capture tank/home tank/srv -- \
  restic backup /run/zsnap/view/tank/home /run/zsnap/view/tank/srv

# Explicitly permit cleanup to complete a deferred deletion.
zsnap protect --end-protection tank/home@nightly -- \
  restic backup /run/zsnap/view/tank/home

zsnap recover --json
zsnap recover JOB --dry-run --json
zsnap recover JOB --confirm TOKEN --json
```

`--dry-run` checks the reviewed identities and view layout without creating
snapshots or holds.

Without `--json`, `recover` prints plain text: one line per outstanding job with
its id, phase and failure; for `JOB --dry-run` the status, each reviewed
snapshot, the next command and its token; for a stop or cleanup the outcome.
`--json` prints the single-line JSON result, which scripts should parse.

### Request JSON (schema 1)

`--request-json FILE` is the bounded, versioned machine alternative to argv
sources. It is not combined with argv sources or `--end-protection`; the request
states the policy. A file is read once, with no symlink leaf and a 4 MiB bound;
stdin remains available to the reader. Unknown fields, invalid identities,
non-filesystem sources, traversal, duplicate or overlapping aliases refuse.
There is no shell expansion or source-placeholder language.

Illustrative request (identity values must come from real observations):

```json
{
  "schema_version": 1,
  "sources": [
    {
      "dataset": "tank/home",
      "identity": {"pool_guid":"1","guid":"2","createtxg":"3","objsetid":"4"},
      "alias": "home"
    }
  ],
  "release": "end_protection"
}
```

A source has either `dataset` plus expected dataset `identity` for capture, or
`snapshot` containing a full `SnapshotRef` for an existing snapshot. An optional
relative `alias` selects its view path. Default aliases are full dataset names;
explicit nonoverlapping aliases support nested dataset selections. Volumes are
not filesystem reader sources. Capture is exact and nonrecursive, atomic only
within one pool; partial or uncertain capture never starts a reader.

### Read-only views and the reader process

The stable default view is `/run/zsnap/view/ALIAS`. A root-trusted `--view DIR`
can select another safe namespace-local root beneath `/run`. Each task uses its
own private mount namespace and tmpfs directory substrate, so simultaneous jobs
can use the same lexical paths with different snapshots. Views are verified
read-only, `nosuid,nodev` and exact snapshot incarnations. No source mode or
ownership is rewritten to grant the reader access.

The child receives `ZSNAP_VIEW`, `ZSNAP_JOB` and a read-only descriptor named by
`ZSNAP_MANIFEST_FD`. Its immutable version-1 JSON contains `job`, `consumer`,
`view_root`, and ordered `sources` with exact `snapshot` and `alias` fields.
This is data for the scoped reader, not a writer-lock descriptor or authority
handle. The reader's argv and stdin/stdout/stderr remain unchanged. Diagnostics
use stderr; optional final JSON is atomically written to `--result FILE`.
Neither command argv, environment contents nor credentials enter job evidence.

`--user ACCOUNT` chooses the reader UID, primary GID and supplementary groups,
then sets `no_new_privs`. HOME/USER/LOGNAME follow that account and PATH is fixed.
Only explicitly approved nonsecret account paths/locales may be copied with
`--env`; credentials use approved files/descriptors. The default root reader is
trusted configured job code, not a hostile-container security boundary.

Do not grant wildcard sudo access to `zsnap protect -- arbitrary COMMAND`.
An application granting unprivileged access needs a fixed, root-owned worker
that authenticates its caller and restricts admitted jobs and sources before
launching the configured reader as that caller.

### Protection and process ownership

Adding and releasing holds use short writer sessions. No writer lock spans a
long reader, and the reader can invoke another task that takes that lock.
The complete intended tag and snapshot incarnations are fsynced before the
first hold; persistence failure performs no acquisition. Incomplete acquisition
retains known and uncertain holds without compensation.

The task holds the library's owned `ReaderProtection`. The
[library guide](../zfs-tools/README.md#protected-readers) gives its
lifetime and recovery rules and explains how native children keep the writer
lock if the calling process dies. Release
preserves snapshots by default; `--end-protection` (or
`"release": "end_protection"`) permits it to complete a deferred deletion.

The task uses cgroup v2 to track the supervisor, helpers, reader and all their
descendants, in two groups beneath `/sys/fs/cgroup/zsnap-protect`. Before any
snapshot or hold effect, each job checks once that `/sys/fs/cgroup` is cgroup
v2, that it and that parent, with their `cgroup.procs` files, are root-owned
without group or other write, and that the task shares PID 1's cgroup
namespace. Later control access goes through the held group descriptors.
Unsupported environments refuse before snapshot/hold effects. Root processes
that rename, replace, alias or re-permission these groups during a job are
outside this contract.

Two authenticated cgroups account for every process that can keep the private
mount namespace alive:

- **Setup:** the supervisor enters before capture, holds or namespace creation;
  its own `/proc/self/cgroup` entry then proves the group's place in the global
  hierarchy. Every native query, mutator and blocked helper inherits it
  atomically at fork.
- **Readers:** the blocked helper is moved here before its launch barrier opens;
  all reader descendants remain contained even after `setsid` or double-fork.

Normal release requires an empty reader group, no setup process other than the
supervisor, and verified non-lazy teardown of snapshots and the private substrate.
Recovery requires the dead owner's setup and reader groups both empty. It opens
each recorded group by name beneath the parent and requires its recorded inode,
so a reused name cannot redirect a kill. Successful `cgroup.kill`
never substitutes for subsequent emptiness proof. The kernel's recursive
population contract is documented in [cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

This process ownership contract covers trusted configured readers and their
descendants. Delegating reads, namespace handles or view FDs to outside managers/processes is unsupported;
UID dropping and `no_new_privs` alone do not prevent such a handoff. Private
namespace disappearance is not general proof against arbitrary same-UID outsiders.

### Recovery

There is no force or `--readers-stopped` override. A live owner refuses recovery.
A populated orphan group first needs a separately confirmed stop:

```sh
zsnap recover JOB --stop --dry-run --json
zsnap recover JOB --stop --confirm STOP_TOKEN --json
# A stop does not end protection. Review the resulting native state again.
zsnap recover JOB --dry-run --json
zsnap recover JOB --confirm CLEANUP_TOKEN --json
```

The stop acts only on the recorded, authenticated groups. This phase does not
wait behind an in-flight native writer lock; cleanup subsequently acquires a new
session and rechecks exact native state. Missing/replaced group provenance is
uncertainty, not proof of emptiness. An authenticated preboot task record on the
same host permits new-boot recovery because preboot processes and their FDs have
ended. Missing intent never proves that an unrecorded reader has ended.

Holds keep the schema-2 `zctl1:CONSUMER:ID` tag and identity grammar that
receipts record; do not change it while any host may hold such a hold. A job
record that is not a current cgroup-v2 task record is listed as unknown
custody, and `zsnap recover JOB` refuses it; either way its protection is
retained. The record format is one-way: an older build lists this build's
records as unknown custody, retaining their protection, until a newer build
returns.

State defaults to root-owned `/var/lib/zsnap/protect`, with per-job exclusion,
bounded immutable reader manifests and atomic fsynced records. It must survive
relevant source/BE rollback. Fsync is not rollback protection. Losing/restoring
control state leaves unproven holds retained for separate owner recovery.

One recovery limitation is conservative: if final cgroup retirement
partly succeeds, or the final completion record cannot be saved after retirement,
same-boot recovery can no longer authenticate both groups. It retains unfinished
evidence even if native release was already verified. A later boot with the
trusted preboot record can establish that those old processes have ended; there
is no override that treats a missing group as empty in the recording boot.

### Reader task exit statuses

| Exit | Meaning for these tasks |
|---|---|
| 0 | Complete task or successful preview |
| 1 | Refusal or reader failure with confirmed cleanup; inspect structured result |
| 2 | Usage error |
| 3 | Missing/stale confirmation or stopped orphan requiring a fresh cleanup review |
| 4 | Incomplete/uncertain task, protection or custody retained |

The actual child exit/signal is a separate result field. Missing final evidence
is not success. These codes do not alter existing zsnap policy-command exits.
