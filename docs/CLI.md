# zboot command line

Use zboot to manage boot environments, keep copies on another disk, and
recover a system. Start with the examples below, or use `zboot --help` to
list commands. [DESIGN.md](DESIGN.md#command-line) explains the design choices.

The boot menu runs from a unified kernel image (UKI). The EFI system
partition (ESP) holds this loader. Some commands run only in the UKI;
others run on an ordinary system, as listed below.

```
zboot VERB [TARGET...] [OPTIONS]
```

## The verbs

| Job | Verbs |
|---|---|
| Look | `status` |
| Boot environments and trees | `snapshot`, `fork`, `default`, `cmdline`, `chroot`, `rename`, `rollback` †, `drop` † |
| Pairs | `pair`, `sync` (†), `primary` (†), `unpair` (†) |
| Install | `factory`, `deploy` (†), `esp` (†), `wipe` † |
| Recover | `restore` †, `resume` (†), `abandon` † |
| Menu | `reboot --menu`, and in the zboot UKI `boot` and `menu` |

† can lose data and needs confirmation. (†) needs confirmation only in the
cases described in that command's section.

Where each runs:

| Environment | Verbs |
|---|---|
| A running system | all but `boot` and `menu` |
| The zboot UKI (its menu, its shell, an SSH session into it) | all but `factory`, `reboot --menu` and `menu` |

A command run in the wrong environment is refused (exit 1); the message
says where to run it.

## Everyday use

```sh
# Try an upgrade in a copy of the running system.
zboot fork try                  # snapshot the running system now, then clone it
zboot chroot try -- /usr/bin/apt full-upgrade
zboot default try               # reboot; the old one stays in the menu

# See boot environments, pairs, interrupted operations and what needs attention.
zboot status
zboot status --devices          # adds disks and ESPs

# Keep a second disk in step.
zboot deploy /dev/disk/by-id/nvme-B --empty --pool bpool
zpool import bpool                                  # deploy leaves the new pool exported
zboot sync rpool/ROOT/default bpool/ROOT/default    # creates it and pairs the two
zboot sync --all                                    # later, from a timer

# Install a host.
zboot factory host.tar.zst --packages openssh-server
zboot deploy /dev/disk/by-id/nvme-A --tar host.tar.zst --overlay ./host --hostname box

# Make a rescue stick (RECOVERY.md has the full package list).
zboot factory rescue.tar.zst --packages openssh-server,systemd-resolved
zboot deploy /dev/disk/by-id/usb-STICK --tar rescue.tar.zst --portable --overlay builtin:rescue

# Run a verb that needs confirmation from a script.
token=$(zboot drop rpool/ROOT/old --dry-run --json | jq -r .token)
zboot drop rpool/ROOT/old --confirm "$token"

# After a zboot update, rewrite the loaders on this host's ESPs.
zboot esp

# Get into a remote machine's menu.
zboot reboot --menu --key ~/.ssh/id_ed25519.pub
```

## Names

How you write a name determines what it means. zboot does not guess from
the datasets that exist, so a name keeps the same meaning after a change.

| Written | Means |
|---|---|
| `rpool/ROOT/be1` (contains `/`) | that dataset |
| `rpool/` (ends in `/`) | the root dataset of pool `rpool` |
| `try` (no `/`) | the boot environment beside the running one: with `rpool/ROOT/be1` running, `rpool/ROOT/try` |
| `@SNAP` | that snapshot of the running boot environment |
| `NAME@SNAP` | split at the first `@`; NAME is then resolved by the rows above |
| nothing, where a synopsis shows `[BE]` or `[DATASET]` | for `snapshot`, `fork` and `cmdline`, the running boot environment; `default` prints the current default, `boot` takes it and `status` reports everything |

- Short names, `@SNAP` and omitted targets need a running boot environment
  whose root filesystem is a ZFS dataset with a parent. Without one (the UKI,
  a system booted in RAM, a rescue stick) they are refused, and the message
  says to write the full name, or `NAME/` for a pool. Explicit dataset and
  snapshot names and `NAME/` work in those environments.
- The rule also covers a destination that does not exist yet (`fork`,
  `rename`, `sync`): `try` is a new sibling.
- Plans, results and typed confirmations always print full names.
- In the menu, a target may be the number `N` that the menu and `status`
  show there for a boot environment (`N@SNAP` for its snapshot); other
  datasets take their full names. Each number is bound to the boot
  environment's native identity when it is shown, so a number that no longer
  names the same dataset is refused.
- Dataset and boot-environment target arguments are resolved, including
  `--keep`. Other option values and everything after `--` pass through untouched.

Other argument kinds: `DISK` is a whole-disk path (prefer
`/dev/disk/by-id/...`). `PART` is a partition path. `SIZE` is a number with
an optional binary suffix `K`, `M`, `G` or `T` (`512M`, `1G`). `HOSTID` is
eight lowercase hex digits, not `00000000` or `ffffffff`. `TOKEN` is 32
lowercase hex digits. `ID` is an operation id as `status` prints it.

## Options every verb shares

- `--dry-run`: print the plan and change nothing. Exit 0. Accepted by
  every command that changes a pool, a disk or an ESP: `snapshot`, `fork`,
  `default BE`, `cmdline --set|--clear`, `rename`, `rollback`, `drop`,
  `pair`, `sync`, `primary`, `unpair`, `deploy`, `esp`, `wipe`,
  `restore`, `resume`, `abandon` and `reboot --menu`. `chroot` opens a
  session and takes neither option.
- `--confirm TOKEN`: run only if the plan still has this token (see
  [Confirmation](#confirmation)). Accepted only by the verbs that can lose
  data, always or in some cases: `rollback`, `drop`, `sync`, `primary`,
  `unpair`, `deploy DISK`, `esp`, `wipe`, `restore`, `resume` and
  `abandon`. Such a verb checks a token it is given even when this plan
  loses nothing, so a script can run exactly what it previewed. It cannot
  be combined with `--dry-run`.
- `--json`: accepted by every command except `chroot` and `menu`. Stdout then
  contains exactly one object (see [Output and exit status](#output-and-exit-status)),
  and prompts and other dialogue go to stderr. A terminal on stdin and
  stderr still allows typed confirmation. A successful `boot` replaces the kernel and ends
  the stream. `boot --json` reports returned refusals and failures.
- `-v`: taken by every verb. Each native command (`zfs`, `zpool`, `sgdisk`,
  ...) is printed to stderr as a `+ ...` line before it runs. `boot -v` also
  prints each stage of the handoff as a `ZBOOT_HANDOFF_...` line. A zboot
  that zboot starts gets `ZBOOT_VERBOSE=1` in its environment, which has the
  same effect.

## Confirmation

zboot asks for confirmation when a command can lose data. Other commands
run and print what they did: they plan once under the writer lock and act
on that plan, take no `--confirm` and print no token.

A verb that can lose data prints its plan and a token and changes nothing
until confirmed:

- **On a terminal** it asks you to type the thing that loses data. It then
  plans again and proceeds only if the token is unchanged.
- **In a script** pass `--confirm TOKEN` from an earlier `--dry-run`.
- Without a terminal and without `--confirm` it prints the plan, never
  waits, changes nothing and exits 3. `sync` is the exception: its transfer
  loses nothing and runs anyway, and only its deletions wait (see
  [Pairs](#pairs)).
- A token that no longer matches is refused. zboot says the plan changed and
  prints no new token. It exits 3 before the first durable effect and 4 after
  that effect. A UKI writable pool import counts as an effect. Preview again
  to see the new plan.

The token is a hash of what you consent to: native identities, what is lost,
and the digests of the files used. It does not cover values zboot makes when
the verb runs (a default snapshot name, a random hostid, an operation id);
the plan says they will be generated and the result reports them.

What you type:

| Verb | You type |
|---|---|
| `wipe`, `deploy DISK`, `restore` | the disk's serial, else its WWN |
| `esp PART` | the serial (else WWN) of the disk that holds the partition; for several partitions, the summary the plan prints |
| `rollback` | `DATASET@SNAP` |
| `drop` | the target; for several, the summary the plan prints (`2 snapshots and 1 tree in rpool`) |
| `primary` | the dataset whose changes are lost, or the surviving dataset when the peer is gone |
| `sync`, to delete snapshots only the copy keeps | the summary the plan prints (`3 snapshots on bpool/data`; for several pairs `5 snapshots on 2 copies`) |
| `unpair` | the dataset |
| `resume`, when it asks | what the interrupted verb asked for |
| `abandon` | the operation id |

A disk must have a name to type, so these refuse to plan at all, even with
`--dry-run` or `--confirm`:

- `wipe`, `deploy DISK`, `restore` and `esp PART` refuse a disk with no
  serial and no WWN (`stable serial or WWN required`).
- `wipe`, `deploy DISK` and `restore` refuse a disk whose WWN another
  attached disk also reports or, when it has no WWN, whose serial another
  attached disk also reports, as some USB sticks do. Both disks are refused,
  and the message names the other one; attach only one of them.

`status --devices` gives the reason on each such disk's line.
`deploy --image` creates its own loop device, which needs no typed name.

## Output and exit status

| Status | Meaning | `"mode"` with `--json` |
|---|---|---|
| 0 | Done, or previewed because of `--dry-run`. | `applied`, `preview` |
| 1 | Refused or failed before changing anything. | `refused` |
| 2 | Usage error. Nothing on stdout. | none |
| 3 | Not confirmed; nothing changed. | `preview`; `refused` for a stale token before any effect |
| 4 | Changed something but did not finish, counted from the first durable effect (an operation record is one). The message names the next step: `zboot resume ID`, or run the verb again. | `partial` |

The object `--json` prints:

```
{"schema_version": 1,
 "mode": "preview" | "applied" | "partial" | "refused",
 "operation": ID,        only when an operation record was written
 "token": TOKEN,         only from a verb that takes --confirm, when a plan was made
 "result": ...}
```

- `result` is the plan for `preview` and the outcome for `applied` and
  `partial`. Each verb's fields are its own and are stable within
  `schema_version` 1.
- For `refused`, `result` is `{"reason": CODE, "message": TEXT}`. CODE is
  `stale_token`, or `error` for every other refusal or failure.
- A verb that only reads (`status`, `default` and `cmdline` without
  a change) prints `applied` with its report as `result`.
- Without `--json`, every verb prints plain text.

## Look

```
zboot status [DATASET...] [--all] [--snapshots] [--devices]
```

`status` is short by default:

```
Boot environments
  rpool/ROOT/default  running, default, primary of bpool/ROOT/default, snapshots level, candidate, kernels unprobed
  rpool/ROOT/try  candidate, kernels unprobed
  bpool/ROOT/default  secondary of rpool/ROOT/default, snapshots level, boot blocked (see Attention)
Pairs
  rpool/home -> bpool/home  secondary behind
Interrupted
  sync 6f1c0b9e-... on rpool after step 1  zboot resume 6f1c0b9e-...
Attention
  bpool/ROOT/default: boot candidate blocked: secondary cannot boot as a writable environment
  rpool/ROOT/try/var has canmount=on inside boot environment rpool/ROOT/try
  boot environment rpool/ROOT/try has child dataset rpool/ROOT/try/var: fork and pair refuse a boot environment with children
  rpool/home -> bpool/home: secondary behind
  rpool/home -> bpool/home: quota 100G on rpool/home, none on bpool/home; a sync applies it when bpool/home can take it
```

- The report has these four sections in this order, leaving out empty
  sections. With nothing to show, `status` says so in one line. Spacing may
  vary.
- **Boot environments**: every one found on the imported pools, marked
  `running` and `default`, with its pair role or clone origin.
- **Pairs**: every pair that is not a boot environment, with its direction
  and whether the secondary is level, behind or diverged. `snapshots level`
  means the copy has every snapshot and the working copy has changed since
  its last one, as a running system always has.
- **Interrupted**: every operation record, with the command that continues
  it, and every orphaned attachment: `zboot:attachment:ID:SLOT` chunks of
  an operation that no longer has a record, with the `zfs inherit` command
  that removes them while their pool records no operation. One on a pool
  whose record this zboot cannot read belongs to that record and is not to
  be removed. Neither is continued (see
  [RECOVERY](RECOVERY.md#interrupted-operations)).
- **Attention**: a second boot default; a `canmount=on` dataset inside a boot
  environment, which it names; a pair that is behind or diverged; a pair
  whose peer is gone; snapshots only on a fenced copy that await review; a
  space limit a pair's fenced copy does not hold as its working copy sets
  it, with both values (see [Pairs](#pairs)); clones of a working copy's
  snapshots, which make `primary` refuse; and an anchor hold that an
  earlier pair left on a dataset now in another one, with the `zfs release`
  command that frees it. It also lists, whatever their
  `canmount`, the datasets below each boot environment (`fork` and `pair`
  refuse it; it still boots) and below each paired leaf (a sync does not
  copy them, and a `primary` switch refuses while either side has one). Short
  `status` reads ZFS state only; it mounts nothing.
- `DATASET...` limits the report to those trees and adds, for each, its
  zboot records (`--json` carries every property) and, for a boot
  environment, its kernels (the names `boot --kernel` takes).
- `--all` lists every dataset of every imported pool. `--snapshots` adds
  snapshots. `--devices` adds disks (model, serial, size, what uses them,
  how `wipe` would erase them and why) and ESPs (`EFI/zboot/zboot.efi` and
  the fallback `EFI/BOOT/BOOTX64.EFI`, whose each is and whether zboot's match
  the installed `zboot.efi`, then each [stale](#esp) zboot loader in
  `EFI/zboot/`; loaders elsewhere are not read); an ESP with an older or a
  stale zboot loader is then listed under Attention.
- `--json` always carries the whole inventory of the selection plus
  `attention`; "short" applies to the text only. Two lists repeat attention
  items as data: `space_differences`, one entry per key with `working_copy`,
  `copy`, `key`, `working_value` and `copy_value` (as `zfs get -p` shows
  them, `null` for no limit) and the copy's `copy_source` when it holds a
  limit; and `child_datasets`, one entry per boot environment or paired leaf
  with `parent`, `boot_environment`, `paired_with` (its peer, when paired)
  and `children`.

## Boot environments and trees

```
zboot snapshot [DATASET[@NAME] | @NAME]...
zboot fork [[BE]@SNAP] DEST
zboot default [BE]
zboot cmdline [BE] [--set ARGS | --clear]
zboot chroot BE [-- COMMAND...]
zboot rename SRC DEST
zboot rollback DATASET@SNAP                                                †
zboot drop TARGET...                                                       †
```

- `snapshot` snapshots each tree recursively. With no target it snapshots
  the running boot environment. Without `@NAME` the name is
  `zboot-YYYYMMDDTHHMMSSZ` (UTC), made when the verb runs and reported in
  the result. An existing name is refused. With more than one target each
  must name its dataset, so `snapshot a @x` is a usage error. With `--json`,
  `result` is an array of capture outcomes, one for each snapshot-label group.
  Each outcome reports its capture marker, status and verified snapshot points.
- `fork` clones a snapshot of a boot environment as a new boot environment
  in the same pool. With only DEST, it snapshots the running boot
  environment now and clones that snapshot. The snapshot name is generated
  when the verb runs, as for `snapshot`, and reported with its full name in
  the result; a preview makes no snapshot. A source written explicitly must
  include `@SNAP`. The new boot environment is `canmount=noauto` (`off` when
  its source is `off`) and keeps its source's saved kernel arguments. The
  capture and clone share one resumable operation; abandoning it keeps the
  snapshot and destroys nothing.
- Snapshots other tools take of the new clone or of the fork's staging
  container `POOL/zboot-fork-ID` never stop `fork`, `resume` or `abandon`,
  and zboot leaves them in place. A staging container that holds anything
  zboot did not make is left, still marked as the fork's staging, when the
  fork completes; the result names it, and `zboot drop` on it lists what it
  holds. `abandon` leaves an unpublished clone, with its snapshots, as staging
  for `drop`.
- `fork` refuses a destination below a `zboot:staging` or `zboot:pending`
  mark, on its parent or inherited by it, when it plans and again before it
  publishes: the new boot environment would inherit the mark and look like
  that operation's staging. Finish or abandon that operation, or drop its
  staging, first.
- `fork` takes only a boot environment, and a boot environment is one
  dataset with no children. It refuses any other source (copy a data tree
  with `zfs clone`) and a boot environment with child datasets, which it
  names; datasets mounted below a boot environment belong outside
  `POOL/ROOT`. The source may be unpaired or a pair's working copy; the
  pair keeps syncing (see [Pairs](#pairs)). A fenced copy is refused: fork
  the working copy.
- `default BE` makes BE the host's one boot default: it sets its pool's
  `bootfs` and clears `bootfs` on every other imported pool. Without BE it
  prints the current default, or says there is none or more than one.
- `fork` and `default BE` refuse while any boot environment on the host
  holds a `canmount=on` dataset (its root or anything below it), and name
  that dataset: stock mounting would mount it over whichever other boot
  environment is running. The fix is `zfs set canmount=noauto DATASET`.
  Until then the menu boots only the boot environment that owns the dataset
  and refuses the others.
- `cmdline` prints the kernel arguments saved for BE, which the menu adds
  when it boots BE. `--set ARGS` replaces them (one argument; quote it),
  `--clear` removes them. `--set` refuses what the menu itself decides
  (`root`, `boot`, `ro`, `rw`, `init`, `rdinit`, a hostid or a ZFS force
  argument, `zboot.recovery`, `zboot.trace`), any quote or backslash, and a
  resulting command line over 2047 bytes.
- `chroot` opens a shell, or runs COMMAND, inside BE with BE mounted
  writable. BE must be a working copy or unpaired, and not the running boot
  environment. COMMAND is an absolute path inside BE (`/usr/bin/apt`, not
  `apt`); it defaults to BE's `/bin/bash`, else `/bin/sh`. Its exit status
  is COMMAND's. Inside, `/run` is new and empty. When BE's
  `/etc/resolv.conf` is a symlink into `/run` (as `systemd-resolved`
  installs), `chroot` puts a copy of the running system's resolver where it
  points, so `apt` there resolves names as the host does.
- `rename` renames an unpaired tree inside its pool. It refuses another
  pool. To move a dataset to another pool: `sync SRC DEST`, `primary DEST`,
  `unpair DEST --release-anchors`, `drop SRC`. A tree moves leaf by leaf:
  make its containers on the other pool with `zfs create`, then move each
  leaf.
- `rollback` rewinds an unpaired tree and every descendant to `@SNAP`, which
  each must have. The plan lists the newer snapshots destroyed and says that
  changes not in a snapshot are lost. The running boot environment cannot be
  rewound in place: `fork @SNAP NEW`, `default NEW`, reboot.
- `drop` deletes snapshots and whole unpaired trees, all in one pool,
  including leftover staging. It refuses a pool's root, the running boot
  environment, the boot default, and a tree with clones outside itself.

## Pairs

A pair is two copies of one dataset, normally on two pools. One is the
working copy (primary). The other (secondary) is fenced: read-only, never
mounted by itself, and a volume has no device (`volmode=none`). Snapshots
flow from the working copy to the fenced one.

A pair joins two datasets with no children, called leaves. Create containers
such as `rpool/data` on each side with `zfs create`, then pair each leaf
separately. A boot environment is one leaf, and so is a volume. Snapshots of
separate leaves are not guaranteed to capture the same moment.

Clones of a working copy's snapshots, such as a `fork` of a paired boot
environment, stay with the working copy: syncs go on, a snapshot a clone
depends on is kept rather than deleted, and `status` lists the clones.
`primary` refuses while either side has one: drop the clone first. To
keep a fork instead, unpair before `zfs promote`: promoting takes the
paired leaf's older snapshots, its anchor among them, to the fork. The fenced copy receives every sync, so `pair` and
`sync` refuse clones of its snapshots. A leaf that is itself a clone cannot
be paired or copied to a new pair; `zfs promote` it first.

`pair`, `sync` and `primary` refuse pools imported with an alternate root
(`zpool import -R`); export and import without `-R` before using them. An
interrupted sync also refuses to continue while either pool is imported with
`-R`.

```
zboot pair PRIMARY SECONDARY
zboot sync (DATASET | SRC DEST | --all)          † when it deletes snapshots only the copy keeps
zboot primary DATASET                            † when the peer loses changes or is gone
zboot unpair DATASET [--release-anchors]         † with --release-anchors or a gone peer
```

`pair` records two existing datasets as a pair, fences SECONDARY and holds
their common snapshots. It transfers and deletes nothing. It needs a common
snapshot, and refuses when SECONDARY is ahead of PRIMARY and says to swap
them. It refuses a dataset with children and names them. Snapshots older
than the newest common one may differ: either side may have pruned some.

`sync` copies new snapshots one way. It never overwrites history on the
receiving side that the sender lacks. `primary` on the receiving side keeps
that history instead; to keep the sender's, remove by hand what only the
receiver has after their last common snapshot (`zfs destroy` its newer
snapshots, `zfs rollback` its unsnapshotted changes), then sync.

| Form | Needs | Does |
|---|---|---|
| `sync DATASET` | DATASET is one side of a pair whose peer is reachable | Transfers from the working copy to the fenced one, whichever was named. |
| `sync SRC DEST`, DEST absent | SRC is unpaired and has no children; DEST's parent exists and is not in a pair | Creates DEST, transfers everything and pairs the two with SRC as the working copy. Says so. |
| `sync SRC DEST`, DEST exists | SRC is the working copy and DEST its pair peer | Transfers from SRC to DEST. With SRC the fenced copy it refuses before any effect: `zboot primary SRC` makes SRC the working copy. An unpaired DEST is refused: `pair` it first. |
| `sync --all` | at least one pair imported | Syncs every pair and reports each. One failure does not stop the rest; the exit status is then 4. |

A sync copies one dataset as a raw stream into the host's own `zfs receive`;
no key is loaded or asked for. The stream carries no properties: zboot sets
them on the copy itself.

- Properties the working copy sets (locally or received) are set locally on
  the copy, so `zfs get` there shows `local`. Placement (`mountpoint`,
  `canmount`, `readonly`, `volmode`), zboot's own records and encryption
  settings are not copied. Write-time properties (`copies`, `compression`,
  `recordsize`, ...) are set before data, so the received blocks follow
  them. A copied property set by hand on the copy is overwritten at the
  next sync, and a user property the working copy lacks is removed. Space
  limits (`quota`, `refquota`, `reservation`, ...) that the working copy
  does not set become `none` on the copy. A limit the copy cannot take does
  not fail the sync: the result lists it as `NOT applied`, and the copy
  keeps its own value. The copy holds a limit when it is the working copy's
  value set locally, or when neither sets one (`none` and `0` are no limit).
  `status` lists every key a copy does not hold this way, with both values,
  and the `primary` plan lists them before a switch. Where the working copy
  sets none and the copy still has one, `status` says that the next sync
  removes it: set it on the working copy first to keep it.
- A new copy of an encrypted dataset is its own encryption root with the
  key location of the working copy's root; each copy loads its key
  separately (a `file://` location does it automatically). After changing
  the working copy's key, a sync into a copy that is its own encryption
  root makes that copy need the new key too; there is no dedicated
  key-change notification in the sync result. A sync into a
  copy that takes its key from a root on its own side, as after `primary`
  into an installer-made dataset, needs the two roots wrapped alike: the same
  passphrase setting (format, salt and iterations), or the same key file
  that opens both. Otherwise it refuses before any data, because the copy
  would then open with neither key; make the copy its own encryption root
  first (`zfs change-key`). A raw or hex key entered at a prompt cannot be
  checked and refuses.
- A child dataset under a paired leaf is not copied. `sync` still copies
  the leaf and names the child as not mirrored; `sync --all` then exits 4.
  `status` lists it under Attention.
- Snapshots are pruned on the working copy: zsnap retention and `zsnap
  prune` work there, and skip the newest common snapshot, which is held on
  both sides. A fenced copy refuses snapshot deletion; it follows the
  working copy through `sync`, which deletes only after review (below).
- An interrupted sync can be abandoned (`zboot abandon ID`) until its data
  is verified: the copy stays fenced with the snapshots it received, and the
  next sync continues from them. A new copy stays fenced in its receive
  container, which the message names. After its data is verified, resume
  it.

Around the transfer of a pair:

- A snapshot both sides have (same GUID) that the copy names differently is
  first renamed on the copy to the working copy's name, through a
  temporary `zboot_rename_GUID` when two names swap.
- **Pending deletions** are snapshots only on the copy, older than the
  newest common snapshot: the working copy no longer has them, so after
  deletion they exist nowhere. The plan lists each with its creation time
  and the space it frees, and its token binds them (the copy's identity and
  each snapshot's name, GUID and creation txg). They are deleted before the
  transfer, and only when you type the summary the plan prints
  (`2 snapshots on bpool/data`) on a terminal, or pass `--confirm TOKEN`
  from `sync ... --dry-run`. Enter keeps them; the transfer runs either way.
  `sync --all` asks once for every pair, and its `--confirm` takes the
  token of `sync --all --dry-run`. Without a terminal and a token (a timer)
  nothing is deleted: the transfer runs, the result lists the pending
  deletions with the command to review them, and the exit status is the
  transfer's. `status` lists them under attention.

  A reviewed snapshot is deleted only while it is still exactly that
  snapshot, still absent from the working copy and older than the newest
  common snapshot, whose `zboot:anchor:PAIR` hold is on both sides. One that
  is held (a reader task, a hand hold) is kept and reported.
- A pending deletion whose name a newer snapshot from the working copy
  needs stops that pair before anything changes, unless it was reviewed;
  then it is deleted first. The message gives the review command. `sync
  --all` goes on with the other pairs.
- After a verified transfer, zboot deletes its own older boundary snapshots
  (`@zboot_transfer_*`, `@zboot_primary_*`) on both sides without review,
  keeping the newest. One is zboot's when the side that captured it carries
  zboot's capture marker on it; the other side's goes first. Held ones are
  kept.

`primary` makes DATASET's side the working copy:

| DATASET is | Its peer is | What happens | Typed |
|---|---|---|---|
| already the working copy, or unpaired | any | Nothing switches. A dataset still fenced from an earlier pairing is activated again, and a boot default left on the other side moves here. | no |
| the fenced copy, level with or behind the peer | reachable | The peer is fenced, snapshotted once more and transferred; then the roles swap. Nothing is lost. | no |
| ahead of the peer, or the two have diverged | reachable | The peer is rolled back to the newest common snapshot and becomes the fenced copy. The plan lists the peer's snapshots and unsaved changes that are lost. | † the peer |
| either | gone | DATASET's pair record is removed, its holds are kept, and DATASET is activated alone. You are stating that the peer is offline. | † DATASET |

- A peer is *gone* when its pool is not imported, the dataset is absent, or
  it no longer names this side.
- When the pair's dataset is the boot default, `primary` moves the default
  to the new working copy.
- A `primary` switch between pair members refuses while either side has a
  child dataset: the child would mount over the live copy's path at the next
  boot. Move it out first.
- With a reachable peer, the plan lists the space limits the fenced side
  does not hold, as `status` does (`space_differences` with `--json`).
  After the switch the activated side's limits are the pair's, and the next
  sync gives them to the peer; a catch-up first applies the working copy's
  where the activated side can take them. They do not make `primary` typed
  and are not in its token, so a lossless switch shows them only with
  `--dry-run`; `status` lists what is left afterwards.
- Snapshots only on the fenced copy that `sync` has not deleted after review
  make `primary` typed: afterwards they exist only on the new working copy,
  whose own retention may delete them.
- A `volmode` set by hand on a volume, any value but `none`, is saved when
  zboot fences the volume and set again when it is activated. Without one,
  activation inherits `volmode`, and the inherited value determines whether
  the volume has a device. The new working copy gets the value the old one
  had, and the old one keeps its own saved for its next activation. A
  volume hidden by hand with `volmode=none` stays hidden, but that value is
  not carried: after `primary` the new working copy inherits.

`unpair` removes both pair records and keeps data, roles and the holds on
the common snapshots. The former secondary stays fenced; `primary` on it
activates it.

- `--release-anchors` also releases those holds on both sides. It works
  after an earlier plain `unpair` too. A deferred destroy or a retention
  job may then delete the snapshots, so it is †.
- With a gone peer, `unpair` removes only this side's record and keeps its
  holds. It is †.

## Install

```
zboot factory TAR [--packages PKG,...] [--suite NAME]
              [--mirror URL] [--snapshot TIME]
zboot deploy DISK (--tar TAR [--overlay OVERLAY]... [--be NAME] [--hostname NAME] | --empty)
             [--pool NAME] [--hostid HOSTID] [--esp SIZE | --esp-partition PART]
             [--swap SIZE] [--efi FILE]                                       †
zboot deploy --image FILE (--tar TAR [--overlay OVERLAY]... [--be NAME] [--hostname NAME] | --empty)
             [--pool NAME] [--hostid HOSTID] [--esp SIZE] [--swap SIZE] [--efi FILE]
zboot deploy (DISK | --image FILE) --portable --tar TAR [--overlay OVERLAY]...
             [--be NAME] [--hostname NAME] [--pool NAME] [--esp SIZE] [--efi FILE]  † with DISK
zboot deploy into POOL --tar TAR [--overlay OVERLAY]... [--be NAME] [--hostname NAME]
zboot esp [--efi FILE]
zboot esp PART... [--efi FILE]              † when it replaces a loader that is not zboot's
zboot wipe DISK                                                               †
```

### factory

`factory` writes a Debian root tar that boots from ZFS and belongs to no
host, with `TAR.packages` (the installed packages) beside it. Neither file
may exist. It needs no root and no VM. The tar is zstd-compressed whatever
its name; `deploy --tar` and `boot --tar` tell by its content.

- `--packages` adds packages. `--suite` defaults to `forky`. `--mirror` is
  the archive the root updates from.
- `--snapshot YYYYMMDDTHHMMSSZ` takes every archive from snapshot.debian.org
  at that time. When the live suite cannot build, for example when its
  kernel and OpenZFS disagree and DKMS fails, `--snapshot` pins an archive
  state that still worked.
- The base system includes the kernel and its headers, OpenZFS with
  initramfs support, systemd and the tools zboot runs. It has no network manager, firmware
  set or listening daemon; added packages may install daemons. Root's
  password is locked, with no default password. A role or machine gets its
  network and access policy from overlays.
- The finish step removes build-machine identity and SSH host keys and
  regenerates every initrd. It removes a regular `/etc/resolv.conf` but
  preserves a symlink into `/run`, as `systemd-resolved` installs.
- It installs the zboot it runs from as the package `zboot`
  ([BUILD.md](BUILD.md#root-tars) lists the files it takes). A missing piece
  is refused by path before any work.
- Only when `openssh-server` is installed, factory installs zboot's
  missing-host-key generator, ordered before SSH. It runs at any boot
  where the keys are missing; overlay-supplied host keys stay.
- There is no rescue preset or mmdebstrap pass-through. For a rescue, add
  packages and use `builtin:rescue` as
  [RECOVERY.md](RECOVERY.md#rescue-sticks) shows.
  Roots built by other means can go straight to `deploy --tar`.

### deploy

`deploy` installs a boot environment from a root tar, or prepares an empty
pool for a second copy, on a whole disk or a new image file;
[`deploy into`](#deploy-into) adds one to an imported pool. Anything but
`--dry-run` needs root, and says so when run without.
Choose one target and one content option:

| Target | What happens | Confirmation |
|---|---|---|
| `DISK` | Erases DISK as `wipe` does, partitions it (ESP, optional swap, pool), creates the pool, installs the content, writes `zboot.efi` to the ESP, sets the new pool's `bootfs` and exports the pool. | typed disk serial |
| `--image FILE` | The same onto a new file through a loop device. FILE must not exist. It is sized to the ESP plus swap plus the unpacked tar with headroom, rounded up to a whole GiB. | none, and no `--confirm` |

| Content | What is installed |
|---|---|
| `--tar TAR` | TAR unpacked as the boot environment `POOL/ROOT/NAME`, then each `--overlay` in order, then with `--portable` zboot's portable overlay. |
| `--empty` | Only `POOL` and `POOL/ROOT`, with no boot default. It prepares the second disk of a pair. |

The synopsis lines are the accepted combinations; any other is a usage
error. `--overlay`, `--be` and `--hostname` go with `--tar`;
`--esp-partition` only with DISK; `--portable` needs `--tar` and refuses
`--hostid`, `--swap` and `--esp-partition`. The defaults: `--pool rpool`
(`stick` with `--portable`), `--be default`, the tar's hostname, the running
host's hostid (else a random one), `--esp 1G`, no swap and the shipped
`zboot.efi`.

- `--tar` takes a root tar (plain or zstd) with matching
  `boot/vmlinuz-RELEASE`, `boot/initrd.img-RELEASE` and a ZFS module for that
  kernel; normally one `zboot factory` wrote. Debian roots are the tested
  input. Other roots may pass the file checks without their boot arguments,
  mounting or initrd tools being qualified.
- `--overlay OVERLAY` adds files and may run a hook in the new root. It
  may be repeated; see [Overlays](#overlays).
- An existing pool name is refused.
- `deploy` sets only the new pool's `bootfs`. It never clears another
  pool's. If another imported pool also has a default, the plan says so: the
  host then has two, and the menu does not count down until `zboot default`
  picks one.
- `--hostid`: the new system's `/etc/hostid`, and the hostid the pool is
  created under. A random one is made when the verb runs and reported in
  the result. Related deployments (a disk and its pair) must use the same.
  `deploy` refuses while `ZFS_HOSTID` is set in its environment, which would
  override it.
- `--esp-partition` puts the loader on an existing ESP on another disk
  instead of making one; the plan names that partition and the files it
  writes. It writes `EFI/zboot/zboot.efi` there, never the fallback
  `EFI/BOOT/BOOTX64.EFI`. It is refused when another system's file is at
  `EFI/zboot/zboot.efi` or the fallback. On such an ESP, run `zboot esp PART`
  first, which replaces it after a typed answer. Where zboot's loader is
  already installed beside another system's fallback, `esp` leaves that
  fallback in place: choose another ESP, or remove the fallback yourself.
- `--efi FILE` is the `zboot.efi` to install. The default is
  `../lib/zboot/zboot.efi` from the binary's directory:
  `/usr/lib/zboot/zboot.efi` when installed. The zboot UKI ships none: give
  `--efi FILE` there.
- With DISK, `deploy` plans again on the erased disk, which must still be
  bare and unused, and goes on only if that plan binds what you confirmed.
  Before partitioning it clears any partition-table signature left on the
  erased disk (`sgdisk --zap-all`).
- An interrupted or failed deploy is not resumed and keeps no operation
  record. Run it again; it plans and confirms afresh. A failed overlay or
  hook rolls the unfinished boot environment back to `@factory`. Each
  `post-install` hook's output goes only to a log (mode 0600):
  `deploy-ID-post-install-N.log` in a new directory under `/run/zboot/deploy/`.
  ID is the deploy's run ID, which a failure message names.
- While it builds, deploy marks the pool, `POOL/ROOT` and the boot
  environment `zboot:pending=ID` and clears each mark as it finishes. A
  deploy interrupted after it created the pool (the disk vanished, say)
  leaves marks, and `status` then says a dataset is left from an interrupted
  deploy. Run the deploy again, which erases the disk, or `zboot drop` the
  marked dataset; a mark on the pool's root needs the pool destroyed
  (`zpool destroy POOL`) or the deploy run again.
- A failed image deployment removes its created file after verifying that
  its loop device has detached. A busy or unverified attachment retains the
  image and reports its path. Inspect that attachment before removing the
  retained file or reusing its name.

`--portable` makes a system that belongs to no machine, which is how a
rescue stick is made:

- It gets no hostid, no swap and no boot default. After all your overlays
  and hooks zboot
  removes `/etc/hostid` from the new root, then configures portable boot:
  the root pool is imported read-only, a RAM layer takes all writes, and
  the initrds are regenerated to do both.
  `deploy` checks every initrd and fails if one lacks either.
- The pool is exported when `deploy` ends, and zboot's own environments
  (the UKI and the system on the stick) import it only read-only, so they
  record no host in it and need no forced import. Other systems may not: a
  host that imports pools by scanning at boot (`zfs-import-scan.service`)
  imports the stick writable and records its hostid in the stick's labels.
  Until that host exports it, another machine needs a forced import; after
  that the labels still name that host, and a zboot menu that adopted
  another host keeps the pool closed. Export the stick there
  (`zpool export stick`) before you move it, and disable scan import on
  hosts it is plugged into, or make the stick again.
- Portable deployment needs an initramfs-tools root with `update-initramfs`,
  `unmkinitramfs` and `lsinitramfs`; it is tested with Debian roots. A rescue
  uses extra packages and `--overlay builtin:rescue`
  ([RECOVERY.md](RECOVERY.md#rescue-sticks)).
  A factory-produced root with SSH regenerates missing host keys at every
  portable boot; overlay-supplied keys pin them. Other root tars use their own key setup.
- The menu lists the result like any boot environment and never counts it
  down.
- With `--image` the result is a stick image to copy with `dd`. Sticks
  copied from one image share a pool identity: plug in one at a time (the
  menu says so when it sees two).

### deploy into

`deploy into POOL` adds a boot environment `POOL/ROOT/NAME` (`--be`, default
`default`) to an imported pool from a root tar, as `deploy --tar` does: the
tar, then each `--overlay` in order. It erases nothing, writes no ESP and
changes no boot default; `zboot default` selects the new boot environment.
It loses nothing, so it takes `--dry-run` but no `--confirm`. Anything but
`--dry-run` needs root.

- POOL's root dataset must be unpaired, and `POOL/ROOT`, when it exists, an
  unmounted container (`canmount=off`, `mountpoint=none`); `deploy into`
  creates it otherwise. An existing boot environment name is refused.
- The new system gets the hostid of the pool's host, which must be this
  host; in the zboot UKI, the hostid the menu adopted for that pool.
- `--tar`, `--overlay` and `--hostname` are as for `deploy`. It takes none
  of the other `deploy` options.
- An interrupted or failed `deploy into` is not resumed and keeps no operation
  record. Its boot environment stays fenced (`canmount=off`,
  `mountpoint=none`, `zboot:pending=ID`) and is never a boot candidate:
  `zboot drop` it, then run `deploy into` again. Each `post-install` hook's
  output goes only to `/run/zboot-deploy-into-ID-post-install-N.log` (mode
  0600).

### Overlays

`OVERLAY` is `DIR`, `TAR` or `builtin:NAME`. A directory or tar holds
`rootfs/`, copied over the new root, and an optional executable
`post-install`, run once in the new root's chroot. A tar keeps owners and
modes; a directory is installed `root:root` with its modes. Existing
directories keep their owner and mode. Unknown top-level entries and a
non-executable `post-install` are refused. A path that starts with `builtin:` is never a file (write `./builtin:x` for one).

- Packages, the kernel and the initrd come from the tar
  (`factory --packages`); a role or a machine (console login, SSH keys and
  policy, network, services, host keys) comes from overlays; the disk, pool,
  BE, ESP, swap, hostid, hostname and portable mode are `deploy` options,
  which win after all overlays and hooks: deploy enforces `/etc/hostid`
  and an explicit `--hostname` then, or removes `/etc/hostid` in portable
  mode. It leaves overlay-supplied SSH host keys alone.
- Overlays apply left to right: one overlay's files, then its
  `post-install`, then the next. A later file replaces an earlier one at the
  same path; nothing is merged. The mandatory portable overlay comes after
  all of them and cannot be selected with `--overlay`. Every regenerated
  initrd is checked.
- The plan lists every overlay's entries and digests in order, never
  contents, and a `deploy DISK` token binds their order and contents,
  built-ins included.
- `boot --tar` takes overlays too, but only their files
  ([Menu and remote access](#menu-and-remote-access)).
- zboot has one named overlay, `builtin:rescue`, files only, built into the
  binary and the UKI. An unknown name is refused with the list of names.
  It holds exactly:

  ```
  etc/systemd/system/getty@.service.d/zboot-rescue.conf         root autologin on the consoles
  etc/systemd/system/serial-getty@.service.d/zboot-rescue.conf  and on serial consoles
  etc/systemd/network/89-zboot-rescue.network                    DHCP on every ethernet link,
                                                                 client id from the MAC
  etc/systemd/system/multi-user.target.wants/systemd-networkd.service  enables networkd
  etc/ssh/sshd_config.d/zboot-rescue.conf                        PermitRootLogin yes
  etc/issue                                                      console banner with the IPv4 address
  ```

  Root has no default password. With `openssh-server` in the tar, SSH lets
  root in with a key an overlay brings (`rootfs/root/.ssh/authorized_keys`), or with a password once someone at
  the console has set one with `passwd`; on a stick or in RAM that lasts
  until the next boot. `systemd-networkd-wait-online` is not enabled, so an
  unplugged cable does not hold up the boot.

A rescue, on a stick or in RAM, is a factory tar with SSH and DNS packages
(the overlay installs neither) plus `--overlay builtin:rescue`.
[RECOVERY.md](RECOVERY.md#rescue-sticks) has the recipe and
[the RAM form](RECOVERY.md#a-rescue-in-ram).
A factory root with SSH generates missing host keys at boot. On a stick or
in RAM they change every boot unless an overlay supplies them. Arbitrary
root tars use their own host-key setup; zboot adds no generator at deploy
or RAM boot.

A host normally needs a network: add `--packages network-manager` (or
configure networkd in an overlay), plus `firmware-*` packages for its
hardware; the factory has `main contrib non-free-firmware`.

### esp

`esp` writes zboot's loader to EFI system partitions. zboot writes exactly
two paths on an ESP: `EFI/zboot/zboot.efi`, which firmware entries point at,
and the firmware fallback `EFI/BOOT/BOOTX64.EFI`. A file is *zboot's* when it
is a UKI whose `.osrel` section has `ID=zboot`. Any other file, or one that
cannot be read as a UKI, belongs to another system. Nothing else on an ESP is
written.

- `esp` without PART refreshes after a zboot update. It takes every ESP
  that holds one of zboot's loaders and is on a disk that also holds an
  imported pool, which covers the second disk of a pair. It also takes the
  ESP this boot was loaded from (systemd-stub's `LoaderDevicePartUUID`) when
  the host itself is running, with its root on a writable pool, and that ESP
  is directly on a fixed NVMe or SATA disk, so a menu on a separate internal
  disk stays current. A stick you booted from stays the untouched fallback,
  and in a stick system or a rescue in RAM this second rule adds nothing;
  the first still covers every disk whose pool is imported there, the
  stick's own included. When the booted ESP
  is left alone, for any of these reasons or because two partitions carry its
  PARTUUID, `esp` names it and still refreshes the rest. Any other ESP, such
  as a rescue stick, is left alone, and `status --devices` shows it as older
  until you name it.
- On each ESP it refreshes, `esp` writes each of the two paths that holds
  zboot's loader or nothing. Another system's file at either stays in place,
  and the result names it (`left_in_place` with `--json`). It needs no
  confirmation.
- `esp PART...` installs. Where `EFI/zboot/zboot.efi` is not zboot's, it
  writes both paths; replacing another system's file at either is †. The
  fallback is written first, so running it again after a failure finishes
  the install. Where zboot is installed, it refreshes as `esp` does, and a
  foreign fallback stays in place and is named. A zboot fallback alone does
  not count as installed.
- A *stale* loader is one of zboot's own UKIs directly in `EFI/zboot/` under
  another name, such as `zboot-recovery.efi`, which earlier builds wrote and
  refreshed. `esp` no longer refreshes it, so a firmware entry that still
  points at it boots an old loader. `esp` (plan and result, `stale_loaders`
  with `--json`) and `status --devices` name each one:

  ```
  ESP /dev/nvme0n1p1: EFI/zboot/zboot-recovery.efi is a stale zboot loader; zboot no longer refreshes it. Point the firmware boot entry at EFI/zboot/zboot.efi (efibootmgr), then remove EFI/zboot/zboot-recovery.efi.
  ```

  An ESP that holds only a stale loader still counts as zboot's: `esp` adds
  `EFI/zboot/zboot.efi` beside it. zboot never removes or rewrites a stale
  loader.
- One plan covers all the ESPs; free space is checked when it is made. If
  one ESP fails after another changed, the result is partial (exit 4) and
  names what remains. `esp` writes no firmware boot entry and keeps no
  operation record: run it again.
- A zboot UKI copied elsewhere on an ESP, such as `EFI/Linux/` or a
  subdirectory of `EFI/zboot/`, is neither refreshed nor reported. Files that
  earlier builds left in `EFI/zboot/operations/` are inert; remove them by
  hand if you like.
- `--efi FILE` as for `deploy`.

### wipe

`wipe` erases a whole disk by one of two methods. The plan names the method,
why it was chosen and everything it touches, and confirmation covers that
method; `status --devices` shows the method beforehand. A disk that holds an
imported pool or a mounted filesystem is refused.

- **NVMe sanitize** of the disk's whole NVM subsystem: crypto erase when the
  controller supports it, else block erase. It is chosen only when that
  subsystem is the disk alone: one PCIe controller of it, not shared, with
  the disk's namespace as its only one. A sanitize cannot be aborted and
  resumes after power loss; the plan says so. A sanitize already running is
  waited out first, and the result says what the controller reported.
- **Metadata clearing** for every other disk: ZFS labels, signatures and
  partition tables are cleared, and the data itself stays in place. The plan
  says so and names the reason: not NVMe, NVMe over a fabric, a subsystem
  that may have other controllers or namespaces, or a controller with no
  sanitize or only overwrite sanitize.

Metadata clearing is chosen only during review, for a stated reason. A failed
query of the disk or controller, a sanitize command the controller rejects, a
failed sanitize or an uncertain outcome stops the operation; none triggers a
fallback to metadata clearing. A controller left in sanitize failure mode is
refused until you resolve it with `nvme sanitize --sanact=exit-failure`.
Either way a fresh probe then checks that the disk shows no partitions,
signatures, ZFS labels or GPT; this checks what is visible and does not by
itself prove secure erasure.

## Recover

```
zboot restore SOURCE DISK [--keep DATASET]... [--pool NAME] [--esp SIZE]
              [--swap SIZE]                                                   †
zboot resume [ID]                       † when an erase is still ahead or the loss changed
zboot abandon [ID]                                                            †
```

- `restore` rebuilds DISK from SOURCE on another disk. SOURCE is `BE@SNAP`,
  recursive over the BE, or a bare BE. A bare BE must be the running one,
  and it is snapshotted now; in the zboot UKI no BE is running, so name the
  snapshot (`status BE --snapshots` lists them). It keeps each `--keep`
  dataset of DISK with its descendants (none without `--keep`) and refuses
  while anything on DISK is in use. The new pool keeps DISK's current pool
  name, ESP size and swap size when they can be read, else the `deploy`
  defaults; the flags override (`--swap 0` for none). The restored boot
  environment ends unpaired and is the boot default. A kept dataset that is
  paired comes back unpaired in its role (a fenced copy fenced, a working
  copy active); the plan names each peer whose pair record restore ends
  after the erase, and `pair` joins the two again without a full copy.
- Data moves dataset by dataset as raw streams into the host's own
  `zfs receive`; no key is loaded or asked for. A kept tree with a clone, or
  a raw or hex key entered at a prompt, is refused. A dataset made under the
  source BE after the plan stops restore before the BE is snapshotted, with
  nothing erased; one made afterwards is left out and reported.
- The new ESP gets the `zboot.efi` SOURCE ships (`/usr/lib/zboot/zboot.efi`
  in it). The plan shows its SHA-256; a SOURCE without one, or without a
  kernel and initrd to boot, is refused.
- `resume` continues an interrupted operation; `status` lists them.
  Continuing inside the recorded consent needs no new confirmation. An erase
  still ahead, or a loss that changed, asks again for what the interrupted
  verb asked for.
- `abandon` ends an interrupted operation without finishing it. It prints
  what it leaves behind and destroys nothing.
- Both take only operations this zboot started; an earlier zboot's record is
  refused, to be finished or abandoned with the build that started it.
- Without ID, both take the one interrupted operation. With none they
  refuse; with several, or with an orphaned attachment listed beside it, they
  refuse and list them.

## Menu and remote access

```
zboot reboot --menu [--key FILE] [--esp PART]  on a running system
zboot boot [BE] [--kernel NAME]              in the zboot UKI
zboot boot --tar FILE|- [--overlay OVERLAY]...  in the zboot UKI
zboot menu [--no-autoboot]                   the UKI's own start-up
```

- `reboot --menu` restarts into the menu and holds it there once: it writes
  `zboot/authorized_keys` on one ESP, then reboots. The menu reads it only
  from the ESP the next boot loads zboot from. That is the ESP this system
  booted from, unless that ESP is not directly on a fixed NVMe or SATA disk,
  as after a one-time boot from a stick: the next ordinary boot follows the
  firmware's boot order and is unlikely to load it, so `reboot --menu`
  refuses and lists every zboot ESP on this host's fixed disks, with the
  disk's model: zboot cannot tell which of them the firmware loads next.
  `--esp PART` writes to PART instead, which must be an ESP holding
  zboot's loader; name the stick's ESP to keep using the stick. The plan
  names the ESP and says which way it was chosen.
  With `--key FILE` the menu also starts SSH for those keys; FILE must hold
  at least one OpenSSH public key and no key options. Without `--key` the
  file is empty: the menu waits, with no SSH. `--menu` is required; a plain
  restart is `systemctl reboot`. A system that was booted from the network
  has no such ESP; name one with `--esp`.
- `boot` hands over to a boot environment with `kexec`. With no BE it takes
  the boot default, and refuses when there is none or more than one.
  `--kernel NAME` picks another installed kernel by the name `status BE`
  lists (its version, such as `7.2.15+deb14-amd64`).
- `boot --tar` boots a root tar in RAM: zboot builds a small initramfs
  containing the tar and the `rootfs/` of each `--overlay` in order, then
  starts the tar's kernel. Nothing is written to a disk. The tar needs exactly one kernel, that kernel's modules and an
  init. An overlay with a `post-install` is refused before staging or
  handoff, rather than skipped. Access to the booted system is whatever the
  tar and overlays set up, normally `builtin:rescue` and an overlay with SSH
  keys. This is how a rescue runs on a network-booted machine, or when an
  agent uploads one. `-` reads the tar from stdin.
  It refuses before staging when the available RAM is less than 256 MiB
  plus the larger of the tar with its unpacked size (the booted system) and
  three copies of the tar (staging and `kexec`). Uploaded bytes are freed
  before `kexec` loads them.
- `menu` is what the UKI runs at start-up. `--no-autoboot` disables the
  countdown. `menu -v` makes every command typed in it verbose.

### In the menu

The prompt is `zboot> `. The menu takes the same verbs with the same
arguments and options; a leading `zboot` is accepted and ignored.
Differences:

- A target may be a boot environment's number `N` as `status` shows it, or
  `N@SNAP`; other datasets take their full names.
- The UKI keeps every pool imported read-only. Any zboot command there (a
  menu line, the shell, an SSH session) plans on the read-only pools; only
  after the answer does it reopen the pools its plan names, writable, and
  it returns them to read-only when done. A pool the command exported stays
  exported; `rescan` imports it again. A pool already imported writable (from
  the shell) is refused after the preview.

Menu-only commands:

| Command | Does |
|---|---|
| `N`, `N.M` | Boot environment N; `.M` picks its M-th kernel. Same as `boot N`. Options need the long form: `boot N -v`. |
| `connect` | Start wired DHCP and SSH; print the address, the host key fingerprint and a one-time password, valid until its first login or the end of that session. It needs exactly one wired interface with a link ([RECOVERY](RECOVERY.md#getting-in-remotely)), and a UKI built with the SSH tools; the shipped one has them. |
| `rescan` | Look for pools again and import new ones read-only. |
| `ls` | Same as `status`. |
| `shell` | A root shell; `exit` returns. |
| `reboot`, `poweroff` | Restart or power off. |
| `help` | List the commands. `help COMMAND` prints that command's options. |

A key during the five-second countdown cancels it. It never restarts.

### Getting in remotely

One-boot keys on the ESP (`reboot --menu --key`), `zboot.ssh_key=` from a
network loader, or `connect` at the console:
[RECOVERY.md](RECOVERY.md#getting-in-remotely) says what each does and how
long the menu waits.
