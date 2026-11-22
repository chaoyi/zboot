# Recovery

Use this guide to reach a failed system's boot menu, boot another boot
environment or a rescue system, restore a disk from its pair, or install
afresh. [CLI.md](CLI.md) lists every command and option.

The examples call the disk to rebuild **A**, the surviving disk that holds
the source boot environment **B**, and a rescue stick **C**. Every name,
device path, operation id and token you use must come from the machine in
front of you. Never type a copied device path or a sample token as consent.

## The menu

The boot menu runs from zboot's unified kernel image (UKI). It starts the
same way from the host's ESP (`EFI/zboot/zboot.efi`, or the firmware's
fallback `EFI/BOOT/BOOTX64.EFI`), from a rescue stick or from a boot server.
It imports every pool it can read-only, without force and without mounting
anything, then lists the boot environments it found, numbered, with their
kernels; interrupted operations; and pools it could not import, with the
reason (another host's, a name already taken, damaged).

It prints `ZBOOT_MENU_READY`, and the prompt is `zboot> `. With exactly one
boot default on the host it counts down five seconds and boots it; a key
cancels the countdown for good. With no default or more than one it waits.
When something makes automatic boot unsafe it prints
`Automatic boot is off: REASON` and waits: a `canmount=on` dataset inside a
boot environment, a hibernation image or a device that could hide one,
devices it cannot read, or an adopted host's active pool that is not
entirely on local NVMe or SATA disks (so a host whose pool is on USB, SAS or
virtio never counts down). A `canmount=on` dataset inside one boot
environment also makes the menu refuse every other boot environment: boot
the one that owns it and run the `zfs set canmount=noauto` command the
refusal prints.

`N` boots boot environment N, `N.M` its M-th kernel; `boot N -v` prints each
stage of the handoff. The menu takes the same verbs as the command line, plus
its own commands ([CLI.md](CLI.md#in-the-menu)). Every zboot command in the
UKI plans on the read-only pools and reopens the pools it needs writable only
after your answer; a pool it exported stays exported until `rescan`, and
`wipe` and `deploy DISK` export the pools on their disk after the answer.
The UKI has no hostid of its own: it adopts the one host
whose active pool labels agree and imports that host's pools and pools that
record no host; another host's pools stay closed and are listed. The menu runs
on the screen. Firmware must allow an unsigned loader.

`shell` opens a root shell; `exit` returns to the menu. The shell and zboot
run from RAM: do not mount disk-backed filesystems over `/usr`, `/bin`,
`/sbin`, `/lib`, `/lib64` or `/etc`. zboot does not manage pool changes you
make by hand in this shell. To inspect the disks and pools before changing
anything:

```sh
lsblk -b -o NAME,PATH,SIZE,MODEL,SERIAL,TYPE,FSTYPE,MOUNTPOINTS
zboot status --devices --snapshots
zpool list -H -o name,guid,health
```

Identify A and B by pool GUID and physical disk before any restore or wipe.

## Getting in remotely

The menu accepts SSH connections over wired Ethernet only, as `root`. It
uses the one wired interface that has a link. With two or more linked it
refuses to choose, and with none after ten seconds it gives up; either way
no SSH starts and the reason shows only on the console. On a host with
several cabled interfaces, leave one connected.

| Situation | What to do |
|---|---|
| The host still runs | `zboot reboot --menu --key FILE` writes the keys in FILE to `zboot/authorized_keys` on the ESP the next boot loads and reboots ([CLI](CLI.md#menu-and-remote-access) says which ESP, and when to add `--esp PART`). The menu then waits ten minutes instead of counting down, and starts wired DHCP and SSH for those keys only, never a password. It deletes the file before anything starts, so this happens once; if the file cannot be deleted, SSH does not start. |
| A stick | Write plain OpenSSH public keys (no key options) to `zboot/authorized_keys` on the stick's ESP. The next boot from it behaves as above. |
| Network boot | Have the loader (iPXE, say) pass `zboot.ssh_key=TYPE:BASE64` (repeatable). Its arguments replace the UKI's embedded command line, so repeat that line too: `zboot.recovery=1` and the consoles ([BUILD](BUILD.md)). Firmware HTTP boot passes no arguments, and under Secure Boot the stub ignores them; use `connect` then. |
| Someone at the console | They type `connect`, which prints the address, the host key fingerprint and a one-time password. Check the fingerprint before you accept the key. The password is valid until its first login or the end of that session. |

A key pressed at the console cancels automatic boot for the rest of that menu
run, and a successful SSH login pauses it until its session ends. Otherwise,
after ten minutes, or when that session ends with nobody at the console, the
menu stops SSH and counts down under its usual conditions. A session ends
before half the DHCP lease has passed, at most six hours. Over SSH, run zboot
verbs directly (`zboot status`, `zboot restore ...`); they follow the same
rules as menu lines. The menu allows one session per connection and stops
SSH for good once the last one closes, so `ssh HOST COMMAND` runs exactly one
command: keep an interactive shell open for the whole visit.

The menu takes plain public keys only. A FIDO key created with
`no-touch-required` needs that option in `authorized_keys`, so it cannot get
into the menu; use a key that asks for a touch, or `connect`. A rescue
overlay's own `authorized_keys` can carry the option.

## Rescue sticks

To make a rescue stick, build a root tar with the tools you need, then
install it with `--portable` and the rescue overlay:

```sh
zboot factory rescue.tar --packages openssh-server,systemd-resolved,ca-certificates,curl,rsync,less,vim-tiny,pciutils,usbutils,smartmontools,cryptsetup,jq
zboot deploy /dev/disk/by-id/usb-C --tar rescue.tar --portable --overlay builtin:rescue --overlay ./access
```

`./access/rootfs/root/.ssh/authorized_keys` lets your key in; leave
`--overlay ./access` out for console-only access. `deploy` asks for C's
serial. With `--image stick.img` in place of the disk it writes an image to
copy with `dd`; sticks copied from one image share a pool identity, so plug
in one at a time.

Firmware starts the zboot UKI from C's ESP. Choose `stick/ROOT/default`
from the menu to start the rescue system. The menu never boots it
on a countdown; it may count down to the host's own default, so press a key.
The rescue system provides:

- root logged in automatically on the console and serial consoles; root has
  no password;
- DHCP on every ethernet link, and its IPv4 address on the console banner;
- SSH for a key an overlay brought, or with a password once someone at the
  console has set one with `passwd`;
- a read-only pool: writes go to RAM and are gone at the next boot, and so
  are SSH host keys unless an overlay supplies them;
- no other pool imported. It is handed the adopted hostid, so importing the
  host's pools needs no force.

Boot C once and reach the menu before you rely on it to erase anything.
`zboot esp` on the host leaves a stick alone, since the stick's pool is not
imported there; to give C a newer UKI, name its ESP with `zboot esp PART`,
or make the stick again.

## A rescue in RAM

On a machine with no stick (network-booted, or reached over SSH), the UKI
boots the same rescue tar in RAM and writes nothing to a disk:

```sh
zboot boot --tar FILE --overlay builtin:rescue --overlay ./access
```

FILE is the tar on a plugged-in medium or copied into the UKI's RAM; `-`
reads it from standard input. zboot passes no keys, passwords or network
settings; access is what the tar and overlays set up. Overlays are files
only, and RAM must hold the tar and its unpacked root;
[CLI.md](CLI.md#menu-and-remote-access) lists what `boot --tar` refuses.

## Boot the other side of a pair

When A has failed and B holds the fenced copy of its boot environment, make
B's copy the working one and the boot default, then boot it:

```text
zboot> primary bpool/ROOT/default
zboot> default bpool/ROOT/default
zboot> boot bpool/ROOT/default
```

With A's pool gone, `primary` asks you to type `bpool/ROOT/default`: you are
stating that the peer is offline. It removes B's pair record, keeps its holds
and activates it. With A reachable and B level with it or behind, `primary`
fences A, transfers its last changes and swaps the roles, losing nothing.
Rebuild A later with `restore`, or with `deploy --empty`, `zpool import` and
`sync` as in [CLI.md](CLI.md#everyday-use).

## Restore a disk

`restore` rebuilds A from a boot environment on B and keeps the datasets of A
you select. The boot environment is copied from a snapshot on B; the kept
datasets are staged on B first and return to their own names on A.
Everything else on A, its ESP included, is erased. The rules are in
[DESIGN.md](DESIGN.md#guided-restore).

`status --devices --snapshots` lists the boot environments on B with their
snapshots, and the disks with model, serial and size. Device names change
between boots: identify A by model, serial and size. Then, in the menu, the
shell or over SSH:

```sh
zboot restore bpool/ROOT/be1@SNAP /dev/disk/by-id/nvme-A --keep rpool/home
```

Each `--keep` names a dataset of A to keep, with its descendants; without one
nothing is kept. The new pool keeps A's pool name, else `rpool`; `--pool NAME`
sets it.

The plan shows the source snapshot, A's identity and everything it erases,
the new layout (pool name, ESP and swap sizes, and the hostid A gets: the
source's own `/etc/hostid`), the SHA-256 of the `zboot.efi` the source ships,
which goes on A's ESP, each kept dataset with its staging path on B, the space
needed on both disks, and the token. Type A's serial (its WWN when it has no
serial). The menu then reopens B and A's old pool writable, plans again and
goes on only if nothing changed. It:

1. snapshots the source on B, or takes the snapshot you named, and holds it;
2. snapshots each kept tree on A, records every kept dataset's properties,
   keys and placement on B, and sends each dataset raw into
   `B/zboot-restore-ID`, where it has no property of its own;
3. verifies the staging against that record, proves the staged keys match
   A's without asking for any, and runs a scrub of B, accepting only a clean,
   finished one;
4. checks A and the keys once more, erases A as `wipe` does and makes an
   empty pool under the source's hostid and an ESP with the source's
   `zboot.efi`;
5. sends the boot environment and the staged trees to A dataset by dataset,
   links each encrypted dataset to its encryption root again, and restores
   their properties and placement from the record;
6. makes A's boot environment the host's one boot default, exports A and
   clears the operation record.

It ends with `Restored BE on pool POOL; it is the boot default.` If A does
not boot, choose B's boot environment in the menu, or run `default`, to undo
that. The staging stays on B; once A boots and the kept data is usable, remove
it with `drop B/zboot-restore-ID`.

Restore refuses without changing anything, and explains why, if:

- A shares a device with B, A's pool spans other disks, or anything on A is
  mounted, in use or the running root;
- B lacks room for staging, or A lacks room for the result;
- a kept tree has a clone, an encryption root outside it, an unencrypted
  dataset under an encrypted one, or a partial receive;
- a kept tree overlaps the boot environment;
- B or A's pool already has an operation in progress;
- the source has no usable `/etc/hostid` or no `usr/lib/zboot/zboot.efi`;
- the running hostid belongs to another host, or any disk has a
  hibernation image.

For a source without a loader, use `deploy A --empty --efi FILE`, import the
new pool (`zpool import`, or `rescan` in the menu), then `sync`, `primary` and
`default`.

- **Encryption.** Kept trees move as raw streams; no key is loaded, and
  restore never asks for one. A raw or hex key of a kept encryption root must
  be in a file (`keylocation=file://...`) that unlocks it from off A (the
  plan checks with `zfs load-key -n`), so a key held only on A, or entered
  at a prompt, is refused. A passphrase is checked by its salt. Before the
  erase restore checks again that every key file is still where it was
  staged from and opens from off A. If you change a kept tree's key after it
  was staged, restore stops before erasing anything: change it back, or
  abandon and plan again (a changed passphrase cannot be changed back).
  Datasets that take their key from a kept encryption root are linked to it
  again. Booting A needs an encrypted source's key as booting B does.
- **Pairs.** A paired secondary must be named with a snapshot. The restored
  boot environment is unpaired. When the source's peer was on A, restore
  ends the source's side of that pair as `unpair` does for a gone peer: it
  stays read-only with its holds; `primary` makes it writable and
  `unpair --release-anchors` releases the holds. A kept dataset that is
  paired comes back unpaired, a fenced copy still fenced and a working copy
  active, its pair's anchor held as on its peer, and restore ends its peer's
  record on B the same way; `pair` joins them again without a full copy. A
  peer missing when A is about to be erased stops the restore before the
  erase; one that goes missing after it is reported.
- **New datasets under the source.** A dataset made under the source boot
  environment after restore snapshotted it is not copied; restore says so
  when it ends.
- **Hostid.** Every import of A runs under the source's hostid, so A's pools
  record it. The menu never force-imports and returns the pools it opened to
  read-only.

On a running system booted from B the same restore is:

```sh
zboot restore bpool/ROOT/be1 /dev/disk/by-id/nvme-A --keep rpool/home --dry-run
zboot restore bpool/ROOT/be1 /dev/disk/by-id/nvme-A --keep rpool/home --confirm TOKEN
```

There a bare boot environment must be the running one, and it is snapshotted
now; any other source is `BE@SNAP`. The pool name, ESP and swap sizes default
to A's, else `rpool`, 1G and no swap. On a terminal it asks for A's serial
instead of a token.

**A damaged receipt.** Restore records every copied dataset's properties,
keys and placement in a receipt on B: the `zboot:attachment:ID:receipt:NNNN`
properties of `B/zboot-restore-ID`. zboot never discards it unread. If it
does not read back exactly, `resume`, `abandon` and the last step refuse and
name those properties and the dataset.

- Before A is erased, once A's properties are restored, and whenever restore
  keeps nothing of A, the receipt is not the only copy of what it records.
  Check its properties with `zfs get -H -s local all B/zboot-restore-ID`,
  remove each with `zfs inherit PROPERTY B/zboot-restore-ID`, and run the
  command the refusal names: `zboot abandon ID`, or `zboot resume ID` at the
  last step.
- From the erase until A's properties are restored, it is the only record of
  A's original properties: never remove its chunks. If an abandon stopped
  while removing it, after copying it to `org.zfs-tools:restore-placement:ID:`,
  run `zboot abandon ID` again; it finishes from that copy. Otherwise zboot
  neither continues nor abandons the restore: end it by hand, below.
- A record that names no receipt from staging on was not left by zboot.
  Where the receipt would not be the only copy, as above, `zboot abandon ID`
  ends it. Otherwise staging may be the only copy of the kept data: end it
  by hand, below.

**Ending a restore by hand.** Where zboot neither continues nor abandons a
restore, the staging may hold the only copy of the kept data and the
receipt the only record of A's original properties. In this order:

1. Save what is left of the receipt on a disk other than A and B, not in
   RAM, where the zboot menu and a rescue shell run:
   `zfs get -H -s local all B/zboot-restore-ID >
   /PATH/ON/ANOTHER/DISK/restore-ID.properties`.
   Each `zboot:attachment:ID:receipt:NNNN` value there is a part of its
   hex-encoded JSON, in order.
2. Copy the kept data from `B/zboot-restore-ID` elsewhere, and check the
   copy.
3. Only then end the operation: `zfs inherit zboot:operation B`,
   `zfs release zboot:restore:ID` on each source snapshot that `zfs holds`
   shows it on, `zfs inherit` each `zboot:attachment:ID:` property left on
   the staging, then `zboot drop B/zboot-restore-ID`.

## Interrupted operations

`zboot status` and the menu list each interrupted operation with the command
that continues it. `zboot resume [ID]` continues it; without ID it takes the
only one. Before repeating a step, zboot checks what ZFS and the disks
show: the step may have succeeded even if its result was lost. Continuing
within what you confirmed needs no new answer; an erase still ahead, or a
loss that changed, asks again.

`zboot abandon [ID]` ends an operation without finishing it. It prints what
it leaves and destroys nothing. For a restore, from the erase until the kept
trees are back on A and verified, the staging may be the only copy, so it
keeps its holds.
For a sync whose data is not yet verified, the copy stays fenced with the
snapshots it received and the next `sync` continues from them; a new copy
stays fenced in its receive container, which the message names. Abandoning
one stuck sync frees its pool for the other pairs there; a sync whose data
was verified is resumed instead: a copy renamed since is renamed back first,
and a copy whose pool is not imported is imported. If that copy is gone, was
replaced or was released from the sync by hand, or its pool is lost for
good, there is nothing to resume: `abandon` refuses and prints the commands
that end the sync on the source alone. Each runs only if the one before
succeeded: they release its `zboot:transfer:ID` holds, remove its
`zboot:pending` marker (for a new copy, its nested pair's) and its
`zboot:attachment:ID` properties there, and last the pool's
`zboot:operation` record while it still names the sync. They touch
neither the copy nor the pair's anchors. A source left naming that copy as
its peer is then unpaired on its own with `zboot unpair SRC`. A sync whose
source is gone is abandoned once its destination's pool is imported and no
dataset carries a marker of it.

A `primary` catch-up interrupted while its transfer from the old primary is
part way is resumed, never abandoned, and its resume needs that peer: a peer
renamed since is renamed back, and a peer whose pool is not imported is
imported. If the peer is gone or its pool is lost for good, `abandon` refuses
and prints the commands that end the catch-up on the target alone, while the
target is still the pair's fenced secondary: they remove its `zboot:pending`
and `zboot:staging` markers and its `zboot:attachment:ID` properties there,
and last the pool's `zboot:operation` record while it still names the
catch-up. The target keeps what it received: until the transfer verified
its data, without the catch-up's final capture of the peer, which the
message says. It stays fenced and still names its lost peer;
`zboot primary TARGET` then activates it without that peer. A peer declared
lost that comes back later is still fenced and may keep the catch-up's
`zboot:pending=ID` marker and `zboot:transfer:ID` holds: remove them with
`zfs inherit zboot:pending PEER` and `zfs list -H -t snapshot -o name PEER |
xargs zfs holds -H | awk '$2 == "zboot:transfer:ID" {print $1}' | xargs -rn1
zfs release zboot:transfer:ID`, then unpair it on its own with
`zboot unpair PEER`.

An interrupted fork resumes or is abandoned whatever snapshots other tools
took of it meanwhile. Abandoned before it is published, its clone stays
fenced and marked as staging, with those snapshots; `zboot drop` lists them
and removes it. A staging container `POOL/zboot-fork-ID` that a fork names
when it completes holds something zboot did not make: inspect it, then drop
it. If the destination's parent has meanwhile gained another operation's
`zboot:staging` or `zboot:pending` mark, `resume` refuses and names it:
finish or abandon that operation, then resume, or abandon the fork. A pool
records one operation at a time, so a `drop` of leftover staging on the
fork's pool is refused until the fork is abandoned. A fork whose published
clone was destroyed or renamed by hand is ended by abandoning it.

Both take only operations this zboot started. One started by an earlier zboot
is refused ("ID is a KIND record from an earlier zboot; finish or abandon it
with the build that started it"): boot or install that build and resume or
abandon it there. The package refuses to install over a zboot while any
operation is pending on an imported pool, and lists them, so an upgrade
never strands one.

`wipe`, `deploy` and `esp` keep no operation record and are not resumed: run
them again; they plan and confirm afresh. A `wipe` run again waits out a
sanitize the controller is still running, then sanitizes and checks the disk.

`status` may also list an orphaned attachment: `zboot:attachment:ID:SLOT`
chunks of an operation that no longer has a record, left when a write cut
before its commit is followed by an abandon from elsewhere or a record
cleared by hand. Until they go, that dataset and every one below it refuse
every operation. zboot never continues them, and gives the `zfs inherit`
command that removes them only while their pool records no operation. An
attachment on a pool whose record this zboot cannot read, such as one a
later zboot wrote, is listed as belonging to that record: it may be the
only record of a restore's original properties, so leave it to the build
that wrote it.

## Install afresh

To replace A without keeping any of its data, deploy a root tar (normally
one made by `zboot factory`) to A. The tar and any host overlay come from
another medium or the network. Boot C's rescue system, mount that medium read-only,
and run:

```sh
zboot deploy /dev/disk/by-id/nvme-A --tar /mnt/host.tar.zst --overlay /mnt/host-overlay --hostname box
```

It erases A as `wipe` does, creates the ESP, the pool (`rpool` unless
`--pool`) and the boot environment, and makes it the pool's boot default,
after the same typed serial. It keeps nothing of A; use `restore` for that.
The rescue system's zboot installs its own `zboot.efi`. In the UKI instead,
add `--efi FILE`, a `zboot.efi` from a medium: the UKI ships none.

The host overlay (`rootfs/` and an optional `post-install`, a directory or a
tar) carries the host's identity, services and logins; the plan lists every
entry and digest. The boot environment keeps `@factory` (the bare root) and
`@deployed`, so `rollback` to either undoes later changes.

## A boot environment on an older OpenZFS

A pool is created with every feature of the OpenZFS that makes it. If a newer
one (a rescue, the UKI) also used a new feature while deploying, a boot
environment whose OpenZFS predates that feature can import the pool only
read-only, and `zpool import` says which feature it lacks. Update that boot
environment's OpenZFS from the newer system, which can write the pool:

```sh
zboot chroot rpool/ROOT/old -- /usr/bin/apt install zfs-dkms zfsutils-linux
zboot chroot rpool/ROOT/old -- /usr/sbin/update-initramfs -u -k all
```

Its apt sources must offer that OpenZFS (for Debian stable, backports or the
next release). Then boot it. `restore` and `deploy --empty` leave new
features unused, so this follows only a `deploy --tar` from a newer system.

## A boot environment blocked by a property zboot does not read

The menu shows a boot environment as `blocked: unsupported management
property KEY on DATASET` when it, a dataset above or below it, or its pair
peer carries a `zboot:` property this zboot does not read: a later zboot's,
or one left by a build from before the first release (`zboot:be`, say). The
menu does not boot it and does not count down; on a running system every
zboot verb on it is refused the same way. The message names the
`zfs inherit KEY HOLDER` that removes the property. Run it only when you know
the state is obsolete; a later zboot's mark is there for a reason.

On a running system that command works as printed. In the menu the pools are
read-only, so reopen the pool in `shell` first:

```sh
zpool export POOL
zpool import -N POOL
zfs inherit KEY HOLDER
zpool export POOL
```

Then `exit` and `rescan`.

## Import a pool another host left active

The menu imports without force a pool its own host left active: it adopts
that host's hostid. When it reports a foreign or ambiguous pool instead, make
sure the previous writer is stopped for good (powered off, its disk attached
to no other machine), then in `shell`:

```sh
zpool import -f -o readonly=on -N POOL     # inspect first
zpool export POOL
zpool import -f POOL                       # take it over
```

Forcing an import is your decision; zboot never does it.
