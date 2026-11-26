# Test the public API with native ZFS

This test runs [`checkpoint.rs`](../../crates/zfs-tools/examples/checkpoint.rs)
against real ZFS in a disposable virtual machine. The example uses the
supported API exported by the crate and builds with `--no-default-features`.
It does not import the private engine or call the zboot or zsnap application.
Its direct `zfs` calls set up test cases and independently check the results
inside the guest.

The runner requires Linux x86-64, Cargo with cached dependencies, `readelf`,
`zstd`, QEMU/KVM and a zboot UKI: `OUT/usr/lib/zboot/zboot.efi` from
`dist/dist.sh`, or an installed `/usr/lib/zboot/zboot.efi`. The runner copies
it and refuses a copy that differs from its publisher's record: `OUT/SHA256SUMS`,
or the installed `zboot` package's dpkg md5sums (which catch a stale or damaged
file, not a forged one); any other path is refused.

The guest always runs under KVM with the host CPU model; there is no software
emulation fallback. `--jobs N` bounds Cargo workers (default
`CARGO_BUILD_JOBS`, otherwise 4); `--timeout N` bounds the guest runtime.
This runner and [the native reader proof](../native-readers/README.md) share
their host side, [`tests/native_proof.py`](../native_proof.py).

The guest uses that UKI's kernel, initramfs, modules and ZFS tools.
`provenance.json` records the UKI, kernel and initramfs digests, the checksum
record checked and the UKI's `.osrel` (which must say `ID=zboot`).
The guest's `zboot` and `zsnap` commands are replaced with stubs that exit 125,
so the example cannot accidentally use an application instead of the API.

This test does not boot firmware or validate the full zboot or zsnap
applications, a newly built UKI, or the set of writers installed on a host.

## Run the test

```sh
TMPDIR=/your/disposable/staging CARGO_TARGET_DIR=/your/owned/target \
  python3 tests/native-api/run.py --uki OUT/usr/lib/zboot/zboot.efi \
  --evidence /your/retained/evidence/new-run
```

Both environment variables are optional. Without them, the runner allocates
private staging under `TMPDIR` (default `/var/tmp`). Choose disk-backed storage
and budget approximately 8 GiB for the build and guest files. The runner uses
four Cargo workers, a statically linked debug build of the example, 2 GiB guest
RAM and one new sparse 2 GiB raw disk. The default guest deadline is 300
seconds. The evidence directory must be empty.
Fixtures are a read-only 9P share; the only writable guest block device is the
private disk. There is no network or host pool/device passthrough.

If you use an external build manager, run the **whole** command under it,
including QEMU and every process that uses the Cargo output. Keep its staging
until the runner exits; do not reuse build output after its managed scope ends. Put evidence in a retained directory you own, outside
disposable staging.

Successful runs copy small logs, structured results, checksummed provenance and
raw final inventory into the evidence directory, then clean private staging.
Failures preserve the same evidence and their owned staging for diagnosis. The
runner waits for its recorded QEMU child and stops only that child on timeout.

## What it checks

The test checks:

- the read-only inventory of a tree: exact members, kinds, identities, mount
  facts, an inherited property source, a captured snapshot's identity, and
  absence of a missing dataset and of a pool that is not imported;
- capture of exactly the requested zvol or filesystem, without descendants;
- ZFS holds present before or after review, clone protection, and a held
  snapshot marked for deferred destruction;
- rejection of an incorrect loss token and deletion of exactly the reviewed
  snapshot;
- snapshot and dataset renaming and name reuse;
- changes to management state made by the same holder;
- lifecycle callbacks that refuse before changes or during result checking;
- sequential reuse of one writer session;
- caller-owned effects: filesystem and sparse volume create, clone,
  rollback and destroy through their pinned shapes; an encrypted file-backed
  pool created with its passphrase on standard input, synced, its key
  unloaded and loaded, exported, imported from one leaf, and an export
  refused for an import instance that changed; an unmount of an unmounted
  root reported as `Failed`;
- a target replaced at its name between admission and spawn, a `zboot:` or
  `org.zfs-tools:` key and a narrow admission for an inheritable key, all
  refused; destroying the last clone of an origin marked for deferred
  destruction refused, with both kept;
- an effect refused while its pool holds a `zboot:operation` record, and
  while another dataset's pair record still names its target as a peer
  (the management query refuses to name a role then);
- the read-only management query, unpaired and with a `zboot:pending` mark;
- caller-set observation deadlines: a generous one on an inventory, a
  management query and an effect admission and dispatch changes nothing; a
  2 s inventory deadline in a child process, whose `zpool` wrapper leaves a
  background `sleep` holding the real query's stdout, expires as
  `ObservationStop::Deadline(QueryCleanup::LeaderReaped)` with the exact message and kills that `sleep`;
- an effect child that keeps the writer lock after the process that
  dispatched it is killed, and completes its effect (a `zfs` wrapper on the
  guest's PATH holds the `set` until released).

Finishing within the deadline also catches a nested writer-lock deadlock.
The final raw ZFS inventory checks that the original dataset identity and
unrelated snapshots survived. The deferred-destruction case has both a real hold and
`defer_destroy=on`: it checks that both survive, without testing the deferred
flag's refusal separately.

These guest checks complement the offline tests for lifetimes, scopes, roles,
pair relationships, uncertain ZFS command results and ownership of child
processes. Apart from the effect child above, they do not kill the calling
application while its ZFS mutation child is still alive; they do not
simulate lost kernel replies, a child that cannot be reaped, or prove
protection from writers on other hosts or consistency within an
application.
