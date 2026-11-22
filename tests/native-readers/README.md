# Supervised reader native proof

This driver checks [`zsnap protect` and `zsnap recover`](../../crates/zsnap/README.md#protected-snapshot-readers)
against real ZFS in a disposable QEMU/KVM guest. It builds the current `zsnap`
package (`cargo build -p zsnap --bin zsnap`). It does not write host pools,
pass through physical devices or use the network. The UKI's own `zboot` is
replaced by a stub that exits with status 125 in the guest. A fixture `zfs`
wrapper can pause a hold after it succeeds; that hook exists only in the guest
fixture.

Run from the repository root with a zboot UKI, as for the
[native SDK proof](../native-api/README.md):

```sh
python3 tests/native-readers/run.py --uki OUT/usr/lib/zboot/zboot.efi \
  --evidence /your/retained/evidence/new-attempt
```

Prerequisites are x86-64 Linux with KVM, Cargo and cached dependencies, QEMU,
`zstd`, `readelf`, and host Python with its standard library and matching loader.
The host Python fixture and its loader and libraries are supplied on a
read-only 9P share. They do not replace the UKI's libc or native ZFS tools.
The guest always runs under KVM with the host CPU model; there is no software
emulation fallback. Each guest command has a fixed 20-second liveness guard,
separate from the eight-second writer-lock assertion and the product's
one-second stop timeout. The outer `--timeout` bounds the whole guest.

The runner honors caller-owned `CARGO_TARGET_DIR` and `TMPDIR`, while keeping
Cargo intermediate output in its private staging directory. With no caller
paths it owns a private directory under `TMPDIR` (default `/var/tmp`). An external execution
scope must cover the entire build and guest lifetime:

```sh
CARGO_TARGET_DIR=/your/build/scope/target TMPDIR=/your/build/scope \
  python3 tests/native-readers/run.py \
  --uki /usr/lib/zboot/zboot.efi --evidence /your/retained/evidence/new-attempt
```

Create the caller-owned directory before running. Budget 8 GiB for a
four-worker static build, host fixture closure and
guest staging; each guest has 2 GiB RAM and one new sparse 2 GiB disk. A single
300-second deadline (configurable with `--timeout`) bounds the guest. The runner can stop only the QEMU
children it tracks. It removes successful private staging after guest exit;
on failure it retains that staging and copies diagnostic evidence before
returning failure.

`--jobs` controls Cargo workers, defaulting to `CARGO_BUILD_JOBS` or four when
unset. It accepts 1 through 64 and is recorded in build provenance. CI can use
two workers to leave memory for the runner.

The cases check exact read-only snapshots, account credentials and
selected environment, an immutable manifest FD, nonrecursive capture, short
writer-lock custody during a long reader, simultaneous independent namespaces at
the same view path, setsid/double-fork descendants after owner SIGKILL, a paused
native hold child in Setup custody, authenticated orphan stop followed by a new
release review, an unaffected sibling cgroup and both deferred-release
policies.

Source hashes cover every file of the zfs-tools and zsnap crates (including
`include_str!` inputs such as `crates/zsnap/src/policies.toml`), Cargo manifests/lockfile,
this harness, the shared runner `tests/native_proof.py` and `tests/acceptance/host/uki.py`, which takes the kernel and
initramfs out of the UKI. The source manifest is checked after compilation and
native execution.
Evidence contains commands, reader identity/view facts, JSON results, retained
job records, final inventory, hold state, serial output and exact runtime/build
provenance. On case failure, `failure-processes.json` captures live guest process
commands, wait channels, syscalls, kernel stacks, cgroups and mount tables before
cleanup, with job records saved as `*-failure-record.json`.
This does not qualify a rebuilt UKI, a writer cohort or any actual
backup service migration.
