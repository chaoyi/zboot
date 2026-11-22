# Zsnap

`zsnap` captures snapshots, applies retention policies and runs commands over
protected snapshots. Use `snap` for an immediate capture, `run` and `prune` for
scheduled retention, and `protect` for a reader such as a backup command that
needs its snapshots to remain available until it finishes.

This package is a library and the `zsnap` command. The library's root holds the
pure retention policy API: policy and duration parsing, the keep plan and
snapshot naming. The commands use the [zfs-tools](../zfs-tools/README.md)
engine through its hidden, unsupported `engine` module, so every write uses the
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
              [--result FILE] [--state-dir DIR] -- COMMAND...
zsnap recover [JOB [--stop]] [--dry-run | --confirm TOKEN] [--json]
              [--state-dir DIR]
```

`-c` is short for `--config`. `--confirm` needs JOB.

`protect` and `recover` require root and a supported cgroup-v2 hierarchy. Their
[protected snapshot reader contract](#protected-snapshot-readers) is below.

## Capture and retention

`snap` captures the exact dataset set, independently of assignment and
frequency; it does not enroll children. Names use UTC seconds,
`DATASET@zsnap_YYYY-MM-DD-HHMMSS`; a manual capture retries only pre-effect
same-second collisions, at most twice, and never an uncertain effect.
Capture reports effects per pool, so a cross-pool request can report a
partial outcome; no capture or retention workflow is atomic across commands.

`run` discovers effective `zsnap:policy` assignments. An empty stream is due
immediately. Existing streams are throttled by frequency, then queried for
newly written bytes; zero skips capture (a scheduling heuristic, not proof of
a quiescent application). It prunes each assigned stream independently and
fails if any dataset fails. This crate installs no timer service.

`prune` previews exact local snapshot incarnations; `-y` accepts that
preview. Without `-y` it asks only when both stdin and stderr are terminals;
otherwise it prints the preview, changes nothing and exits 3. It holds no
writer lock while it waits; afterwards it takes the lock, plans again and
deletes only if the plan is unchanged. Overrides replace the whole keep policy
for that invocation, and `--last 0` selects the entire owned stream. Only
canonical zsnap names on each exact dataset are candidates; holds, dependent
clones, managed roles and pending operations still refuse deletion. A pair's
working copy is pruned like any dataset, and its fenced copy refuses.
Uncertain or partial execution fails with the observed per-point outcomes.

`assign DATASET none` creates a local disabled value. `unassign` clears the
local override and reports the resulting effective value and source: an
ancestor's policy may become active. Assignment never writes boot or pair
metadata.

`status` prints one diagnostic row per dataset, the configured policies and a
legend. `status DATASET` instead starts with that dataset's policy and the
retention decision for each owned snapshot, then its row and the legend.

Policy commands exit 0 on success, 1 on refusal or failure, 2 on a usage
error, and 3 for a `prune` not confirmed (nothing changed).

The config is `--config FILE`, else `/etc/zsnap/zsnap.toml`. Only a missing
default file uses the built-ins ([policies.toml](src/policies.toml)) silently.
Named definitions replace whole built-in definitions; unknown fields and
invalid retention refuse loading.

Writes take the shared host writer lock
([DESIGN.md](../../docs/DESIGN.md#writer-lock)) and use native outcomes,
holds and fresh identity checks; they provide no application freeze, and
concurrent conflicts can fail or leave partial results. Storage restructuring
and temporary import/export workflows need exclusive ownership of the
resources they affect.

`cargo test -p zsnap --offline` runs the unit tests and the policy,
configuration and CLI integration tests without ZFS or root. `RET-02-NATIVE`
checks native capture and retention in a disposable guest
([TESTING.md](../../docs/TESTING.md#qemu-acceptance)).

## Policy JSON (schema 1)

`zsnap status [DATASET] --json` produces a typed, read-only report:
`schema_version`, `observed_at` (UTC epoch seconds), `non_atomic`, policy
definitions (frequency and retention in seconds), and `datasets`. Each dataset
has `expected`, snapshot count, oldest and newest ages in seconds,
`used_by_snapshots_bytes`, accounting errors, optional written-since-newest
bytes, and a scheduling diagnostic. Null accounting means unknown, never zero.
Role, pending and unknown-management blockers are reported separately; old
unchanged heads are `unchanged`, not overdue. A read-only dataset is an
ordinary state, not a blocker: its diagnostic is `fenced` for a pair's fenced
copy and `read_only` otherwise, and `expected.blocker` still carries the
admission refusal. The overdue warning needs an age over twice the policy
frequency.

Copy the chosen row's entire `expected` into a request:

```json
{"schema_version":1,"expected":{"dataset":"tank/data","identity":{"pool_guid":"1","guid":"2","createtxg":"3","objsetid":"4"},"policy":{"value":"none","source":"local"},"local_value":"none","inherited_policy":null,"authority":{},"blocker":null},"change":{"set":"guard"}}
```

The identity and empty authority above are illustrative; use a real status
observation. `expected` binds the name and incarnation, effective policy and
source, local assignment, intended inherited policy (the whole ancestor chain,
absence included), management authority (ancestors, pair peers and every
observed management, identity and posture record, so an unrelated management
change can require a fresh review) and admission, which runs again natively
and cannot be asserted. Unassign completes only when readback matches the
reviewed inherited value and source.

Use `zsnap assign tank/data guard --request-json request.json` or
`zsnap unassign tank/data --request-json request.json` (whose request has
`"change":"inherit"`); `-` reads stdin. The dataset and change must match the
positional arguments. Requests reject unknown fields and versions, input is
limited to 4 MiB, and the flag conflicts with `--dry-run`: use `status` to
plan. Both forms emit `{ "schema_version": 1, "outcome": ... }` with the
complete or uncertain outcome and the verified effective value and source. A
nonzero exit or uncertain result is unfinished, and a pre-effect refusal
prints an error on stderr with no result; observe again before reconciling.
This transport accepts no arbitrary property names or commands, and is a
private module of this crate, not a backend API.

## Protected snapshot readers

`zsnap protect` runs a command over exact filesystem snapshots and keeps ZFS
holds on them until the command and all its descendants have ended. It creates
private read-only views for the command, then tears them down before releasing
protection. `zsnap recover` reviews interrupted tasks before confirmed cleanup;
a live owner or unproven reader death retains protection.

The calling application still owns job and repository policy, credentials,
application consistency and authorization of installed workers: protecting a
snapshot keeps it available for a backup command, not consistent. The
[library guide](../zfs-tools/README.md#protected-readers) covers Rust
integration for applications that manage reader lifetimes themselves.
`zsnap protect --capture` captures and protects the sources for one reader
command; `zsnap snap` and `zboot snapshot` only capture.

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

`recover JOB --dry-run` reviews the job and changes nothing. Without `--json`,
`recover` prints one line per outstanding job (id, phase, failure); for
`JOB --dry-run` the status, each reviewed snapshot, the next command and its
token; for a stop or cleanup the outcome. Scripts should parse `--json`.

### Request JSON (schema 1)

`--request-json FILE` is the bounded, versioned machine alternative to argv
sources, not combined with them or with `--end-protection`: the request states
the release policy. The file is read once, with no symlink leaf and a 4 MiB
bound; stdin remains the reader's. Unknown fields, invalid identities,
non-filesystem sources, traversal, and duplicate or overlapping aliases
refuse. There is no shell expansion or placeholder language.

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

A source has either `dataset` plus its expected `identity` (from a real
observation) for capture, or `snapshot` with a full `SnapshotRef` for an
existing snapshot. An optional relative `alias` selects its view path; the
default is the full dataset name, and explicit nonoverlapping aliases allow
nested selections. Volumes are not reader sources. Capture is exact and
nonrecursive, atomic only within one pool; a partial or uncertain capture
never starts a reader.

### Read-only views and the reader process

The default view is `/run/zsnap/view/ALIAS`; a root-trusted `--view DIR`
selects another namespace-local root beneath `/run`. Each task has its own
private mount namespace and tmpfs substrate, so simultaneous jobs can use the
same paths with different snapshots. Views are verified read-only,
`nosuid,nodev` and exact snapshot incarnations; no source mode or ownership is
rewritten to grant access.

The child receives `ZSNAP_VIEW`, `ZSNAP_JOB` and a read-only descriptor named
by `ZSNAP_MANIFEST_FD`, whose immutable version-1 JSON has `job`, `consumer`,
`view_root` and ordered `sources` with exact `snapshot` and `alias`. It is
data for the reader, not a lock or authority handle. The reader's argv and
standard streams are unchanged; optional final JSON is written atomically to
`--result FILE`. Command argv, environment contents and credentials never
enter job evidence.

`--user ACCOUNT` chooses the reader UID, primary GID and supplementary groups,
then sets `no_new_privs`; HOME, USER and LOGNAME follow that account and PATH
is fixed. `--env` copies only approved nonsecret names; credentials use
approved files or descriptors. The default root reader is trusted job code,
not a container boundary. Do not grant wildcard sudo access to
`zsnap protect -- COMMAND`: unprivileged access needs a fixed, root-owned
worker that authenticates its caller and restricts the jobs and sources it
admits.

### Protection and process ownership

Holds are added and released in short writer sessions; no writer lock spans a
long reader, which may itself run a task that takes the lock. The intended
tag and snapshot incarnations are fsynced before the first hold, and an
incomplete acquisition keeps known and uncertain holds without compensation.
The task holds the library's `ReaderProtection`
([lifetime and recovery rules](../zfs-tools/README.md#protected-readers)).
Release preserves snapshots by default; `--end-protection` (or
`"release": "end_protection"`) lets it complete a deferred deletion.

The task tracks the supervisor, helpers, reader and all their descendants in
two cgroup-v2 groups beneath `/sys/fs/cgroup/zsnap-protect`:

- **Setup:** the supervisor enters before capture, holds or namespace
  creation; its own `/proc/self/cgroup` entry proves the group's place in the
  hierarchy, and every native query, mutator and blocked helper inherits it
  at fork.
- **Readers:** the blocked helper moves here before its launch barrier opens,
  so all reader descendants stay contained even after `setsid` or
  double-fork.

Before any snapshot or hold effect, each job checks that `/sys/fs/cgroup` is
cgroup v2, that it and the parent group, with their `cgroup.procs` files, are
root-owned without group or other write, and that the task shares PID 1's
cgroup namespace; unsupported environments refuse. Later access goes through
the held group descriptors. Root processes that rename, replace, alias or
re-permission these groups during a job are outside this contract, as is
delegating reads, namespace handles or view descriptors to outside processes
(UID dropping and `no_new_privs` do not prevent such a handoff).

Normal release needs an empty reader group, no setup process but the
supervisor, and verified non-lazy teardown of snapshots and the private
substrate. Recovery needs the dead owner's setup and reader groups both
empty; it opens each recorded group by name and requires its recorded inode,
so a reused name cannot redirect a kill. A successful `cgroup.kill` never
substitutes for a later emptiness proof
([cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)).

### Recovery

There is no force or `--readers-stopped` override. A live owner refuses
recovery. A populated orphan group first needs a separately confirmed stop:

```sh
zsnap recover JOB --stop --dry-run --json
zsnap recover JOB --stop --confirm STOP_TOKEN --json
# A stop does not end protection. Review the resulting native state again.
zsnap recover JOB --dry-run --json
zsnap recover JOB --confirm CLEANUP_TOKEN --json
```

The stop acts only on the recorded, authenticated groups and does not wait
for an in-flight writer lock; cleanup then takes a new session and rechecks
the exact native state. Missing or replaced group provenance is uncertainty,
not proof of emptiness. An authenticated preboot task record on the same host
permits recovery in a new boot, because preboot processes and their
descriptors have ended; missing intent never proves that an unrecorded reader
has ended.

Holds keep the schema-2 `zctl1:CONSUMER:ID` tag and identity grammar that
receipts record; do not change it while any host may hold such a hold. A job
record that is not a current cgroup-v2 task record is listed as unknown
custody and `zsnap recover JOB` refuses it, retaining its protection; an
older build lists this build's records that way until a newer build returns.

State defaults to root-owned `/var/lib/zsnap/protect`, with per-job
exclusion, bounded immutable reader manifests and atomic fsynced records. It
must survive rollback of the relevant source or boot environment; fsync is not
rollback protection, and losing or restoring control state leaves unproven
holds for separate owner recovery. If final cgroup retirement partly
succeeds, or the final completion record cannot be saved after it, same-boot
recovery can no longer authenticate both groups and keeps the unfinished
evidence, even if native release was verified; a later boot with the trusted
preboot record can establish that the old processes have ended.

### Reader task exit statuses

| Exit | Meaning for these tasks |
|---|---|
| 0 | Complete task or successful preview |
| 1 | Refusal or reader failure with confirmed cleanup; inspect structured result |
| 2 | Usage error |
| 3 | Missing/stale confirmation or stopped orphan requiring a fresh cleanup review |
| 4 | Incomplete/uncertain task, protection or custody retained |

The child's own exit or signal is a separate result field. Missing final
evidence is not success.
