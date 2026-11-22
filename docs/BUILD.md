# Building

`dist/dist.sh OUT` builds the zboot UKI, Debian package `zboot` and matching
source archive from the pinned inputs in `dist/build.lock`. Use the resulting
`zboot factory` to make root tar archives containing that same package. See
[CLI.md](CLI.md).

## The distribution

```sh
dist/dist.sh OUT
```

Run it from a checkout as an ordinary user. It needs:

- `mmdebstrap`, which it runs in unshare mode, so the user needs subordinate
  uid and gid ranges;
- about 24 GiB under `$TMPDIR` (default `/var/tmp`). Every ancestor of that
  directory must be searchable by others, so the namespace's root can reach
  it;
- network access: the lock's snapshot on snapshot.debian.org, the Rust
  release on static.rust-lang.org, and the crates in `Cargo.lock`.

`ZBOOT_JOBS` (default 8) bounds the compilers, DKMS and make. OUT must not
exist. The build writes `OUT.partial` and renames it to OUT when every output
is there; a failed build removes it, and its work directory is always
removed. Nothing is cached between builds.

The build first copies `Cargo.toml`, `Cargo.lock`, `crates/`, `dist/`, `LICENSE`
and this guide into a private directory and adds `dist/source-time`, the UTC
time of the last commit that changed those inputs (see the package version
below). A SHA-256 digest of the copy, leaving out `dist/source-time`,
identifies the source: the same files give the same digest whichever
history they were built from. It then creates a private Debian root using the snapshot and packages
in `dist/build.lock`, and:

1. installs the locked Rust; each component must match the digest published
   beside it;
2. checks that the root's only kernel is the locked one and that it has a ZFS
   module (DKMS builds one when needed; modules are left unsigned);
3. fetches the locked crates, then builds the `zboot-helpers` package's
   `zboot-probe-signatures` and `zboot-change-key` with Cargo, both dynamically
   linked for the GNU target (against the root's libblkid and the
   libzfs_core.so.3 that zfsutils-linux brings), and stages the runtime with
   `dist/initramfs/stage-runtime.sh` as the initramfs root: the named tools, their
   required shared libraries and loaders, the selected firmware and the kernel's module tree;
4. collects the actual Debian package/source identities, notices and matching
   source archives, the crate and pinned Rust runtime notices, and local copies
   of the crates for rebuilding;
5. builds `zboot` and `zsnap` with `cargo build --locked --offline
   --release`, statically linked; `zboot` carries the source digest;
6. completes the initramfs: the two tools, the notices,
   `dist/initramfs/init.sh` as `/init` and its helpers `console.sh` and `menu-dhcp.sh`;
7. builds the UKI with `ukify`: that kernel and initramfs, the command line
   `zboot.recovery=1 console=ttyS0,115200n8 console=tty0 quiet loglevel=3
   fbcon=font:TER16x32`, and an `.osrel` with `ID=zboot`. Both payloads are
   read back from the UKI and compared;
8. writes OUT, builds the package from `OUT/usr` with `dist/deb/control` and
   the install gate `dist/deb/preinst`, and writes a separate
   `corresponding-source.tar.zst` release asset.

| Output | What |
|---|---|
| `OUT/usr/bin/{zboot,zsnap}` | the same files the UKI carries |
| `OUT/usr/sbin/zboot-probe-signatures` | the probe that verifies an erase, as the UKI carries it |
| `OUT/usr/sbin/zboot-change-key` | restore's key relink helper (`lzc_change_key` FORCE_INHERIT/FORCE_NEW_KEY), as the UKI carries it |
| `OUT/usr/lib/zboot/zboot.efi` | the zboot UKI |
| `OUT/usr/lib/tmpfiles.d/zfs-tools.conf` | creates `/run/zfs-tools/writer.lock` at boot |
| `OUT/usr/share/doc/zboot/` | project and bundled-component notices and component metadata |
| `OUT/components.json` | exact Debian runtime input and source-package inventory |
| `OUT/corresponding-source.tar.zst` | matching Debian source archives, vendored crates and project build inputs |
| `OUT/vmlinuz` | the UKI's kernel, for the acceptance harness |
| `OUT/zboot_V_amd64.deb` | `OUT/usr` as the package `zboot` |
| `OUT/SHA256SUMS` | digests of the source archive, `components.json`, the package and the UKI |

V is `CRATE+gitTIME.SOURCE`: the crate version, the source time as
`YYYYMMDDHHMMSS` (UTC) and the first 12 hex digits of the source digest, for
example `0.2.0+git20261119191621.943cb044d0ef`. dpkg compares TIME as a
number, so a build from a later commit sorts later and installs as an
upgrade; the `git` prefix also puts every V above the earlier `CRATE+SOURCE`
versions. The same inputs give the same V: TIME is the committer time of
`git log -1 -- INPUTS`, so a commit outside the inputs changes neither TIME
nor the digest. Uncommitted changes to the inputs keep their last commit's
TIME and only change the digest, which orders them arbitrarily against
each other. A tree that has `dist/source-time` (one `YYYYMMDDHHMMSS` line)
uses that file as is, so the project copy in `corresponding-source.tar.zst`
rebuilds at its own version; without it, dist.sh refuses a tree outside Git
and a shallow clone. The `zboot` executable embeds V, and `zboot factory`
packages itself at it. `zboot --version` prints `zboot CRATE (source SOURCE)`. The
package's other fields, including `Depends`, are `dist/deb/control`.
`dist/deb/preinst` refuses to install or upgrade the package while any zboot
operation is pending on an imported pool (a `zboot:operation` record), and
lists them: finish or abandon them with the installed zboot first. When there is no `zfs` command, or `zfs get` fails (no
module loaded), it lets the install proceed.

`SOURCE_DATE_EPOCH` is the snapshot time, and the initramfs is a sorted cpio
with zeroed times. Nothing is signed: not the UKI, not the DKMS modules.
Firmware must allow an unsigned loader.

The UKI holds no password and no SSH host key. When SSH starts, the menu
makes a host key in RAM, and `connect` makes a one-time password. The menu
runs on one terminal, the screen (`tty0`). A QEMU guest moves it to serial
with `-fw_cfg name=opt/zboot/console,string=ttyS0`; no other setting does.

## dist/build.lock

Plain lines; the first is the format, `zboot-build-lock 6`.

```
suite forky
snapshot 20261108T022935Z
components main contrib non-free non-free-firmware
set uki buildd PACKAGE...
rust 1.97.1
kernel 7.2.15+deb14-amd64
```

- `snapshot` fixes every Debian input: packages come from snapshot.debian.org
  at that time, and apt checks them against the suite's signed `InRelease`.
  Moving to a newer Debian is editing it, and `kernel` with it.
- `set uki` is the mmdebstrap variant and the packages of the one root:
  `ukify` and the EFI stub, the kernel, and the packages the initramfs takes
  its programs from.
- `firmware PATH` selects a firmware file relative to `/usr/lib/firmware` in
  that root. Repeat the line to add files. The build dereferences contained
  packaged symlinks and stages bytes at `/lib/firmware/PATH`, where Linux looks.
  Absolute paths, traversal, missing files and symlinks escaping the firmware
  root are refused. Add the supplying Debian firmware package to `set uki` too.
  The defaults select the two RTL8156 images; this is not a claim of support
  for all hardware whose kernel modules are present.
- `rust` is the Rust release.
- `kernel` is the release the snapshot's `linux-image-amd64` installs. The
  build refuses any other.

For example, to include a further Realtek image supplied by the selected
snapshot, add its installed relative name:

```
firmware rtl_nic/rtl8125b-2.fw
```

Other vendors also require their supplying package in `set uki`. Firmware
availability alone does not activate an additional driver: networking currently
loads an explicit wired-driver list in zboot's
`crates/zboot/src/menu/menu_connect.rs`, while storage has its own list in
`dist/initramfs/init.sh`.

Publish the source asset alongside the UKI and Debian package. No dependency
source tree belongs in Git. The source asset also contains the kernel config
and local copies of Cargo dependencies; its project `.cargo/config.toml` selects that
sibling vendor directory for offline Cargo rebuilds. Source collection uses
`deb-src` from the same signed snapshot; missing exact versions fail the
build. See [Licenses and source access](#licenses-and-source-access) for
notice scope and distribution requirements.

For a general source snapshot, `git archive` exports the tracked files.
The distribution builder instead selects the inputs listed above; it includes
only this guide from `docs/`. To share source without private development
history, use a fresh publication repository as described below.

Crates come from `cargo fetch --locked`, so Cargo checks each one against
`Cargo.lock`; the compile itself is offline.

## Licenses and source access

The project terms and retained ZFSBootMenu notice are in [LICENSE](../LICENSE).
The [README](../README.md#origins-and-attribution) credits the early boot
implementation's use of ZFSBootMenu source. Snapshot retention also follows
restic's ApplyPolicy style, without claiming compatibility with a particular
restic release.

The distribution copies `LICENSE` to `usr/share/doc/zboot/copyright` in the
UKI and Debian package. Build-generated dependency notices remain under
`usr/share/doc/zboot/LICENCES`: Debian notices retain their per-file terms and
the complete common-license texts they reference. Rust notices cover the
resolved crates, including ones that may not be linked, and the pinned standard
library. `debian/components.json` records actual
runtime inputs, binary versions and matching source-package identities.
The project license does not replace these dependencies' licenses; a complete
UKI is a collection of separately licensed components.

When distributing binaries, share `corresponding-source.tar.zst` with the
matching UKI or Debian package and keep it available alongside binary
downloads. Preserve bundled license notices, including firmware notices.
The supplied sources and build instructions must support rebuilding the
static programs with modified LGPL libraries. The build stops if required
notices or sources cannot be collected. These extra release steps are not
needed for source-only publication.

## Releases

Releases are published only by CI, from the build it qualified. Dispatch
`qualification.yml` in the public repository with `run_vm=true` and a new
`release_tag=vX.Y.Z` ([TESTING](TESTING.md#ci)). When every acceptance case and
both native proofs pass, its release job re-verifies the shards' distribution
archive and the distribution's own `SHA256SUMS`, requires the build record to
name the dispatched commit, and creates the tag and release on that commit with:

| Asset | From the distribution |
|---|---|
| `zboot_V_amd64.deb` | the package |
| `zboot.efi` | `usr/lib/zboot/zboot.efi`, the UKI the package also carries |
| `corresponding-source.tar.zst` | the matching sources |
| `SHA256SUMS` | digests of the three assets |

A failed run publishes nothing. The package version's TIME comes from the
public repository's history, so a local build of the same tree from this
development repository carries a different version and is not a release.

## Publishing a source snapshot

Keep private development evidence separate from the publication repository.
Ignoring or untracking a file does not remove it from earlier commits.

Keep development history locally. To publish the current source without that
history, export a committed revision into a new, empty directory, initialize
a separate Git repository there and make its first commit:

```sh
# Run from this development repository; select a new destination.
(
    set -eu
    public_dir=/path/to/new/zfs-tools-public
    mkdir "$public_dir"
    git archive --format=tar HEAD | tar -xf - -C "$public_dir"
    git -C "$public_dir" init -b main
    git -C "$public_dir" add .
    git -C "$public_dir" commit -m 'Initial public source snapshot'
)
```

The destination must be outside this repository and empty before extraction.
Verify it has one root commit, no tracked `docs/archive/`, and no development
remote before adding the intended public remote. Push from that repository.
Do not clone or push the development repository for this handoff: its older
commits still contain archived material. Untracking files or amending the
latest commit does not remove them from earlier history.

Publish each later revision as one ordinary commit on top of the public
history, holding exactly that revision's tree:

```sh
# Run from this development repository; DIR must be new and empty.
oid=$(git rev-parse --short=8 HEAD)
git clone https://github.com/OWNER/REPO.git DIR
git -C DIR rm -q -r .
git archive HEAD | tar -xf - -C DIR
git -C DIR add -A
git -C DIR commit -m "Source snapshot of zfs-tools $oid"
test "$(git -C DIR rev-parse HEAD^{tree})" = "$(git rev-parse HEAD^{tree})"
git -C DIR push origin HEAD
```

The push sends only the new tree, never this repository's history. Do not
rewrite public history once a release tag names a commit.

The source snapshot and the distribution's `corresponding-source.tar.zst`
have different scopes. Publish matching distribution source and notices
alongside any UKI or Debian package, as described above.

## Root tars

```sh
OUT/usr/bin/zboot factory ROOT.tar.zst [--packages PKG,...] [--snapshot TIME]
```

`factory` writes a Debian root tar and `ROOT.tar.zst.packages` beside it, as
an ordinary user on a running system (it refuses to run in the UKI). Neither
file may exist. CLI.md lists its options, its package floor and what its
finish step removes and regenerates. `ZBOOT_JOBS` bounds the factory root's DKMS
compiler jobs, using the same 1–99 range and default of 8 as the distribution
build. An empty value also uses the default; invalid values are refused before
staging begins.

It needs:

- the installation it runs from. Beside the executable: `zboot` and
  `zsnap`. Under `../sbin`: `zboot-probe-signatures` and
  `zboot-change-key`. Under `../lib`:
  `zboot/zboot.efi` and `tmpfiles.d/zfs-tools.conf`. Under
  `../share/doc`: `zboot/` with its notices and component inventory. A
  missing piece is refused by its path before any work. Run `OUT/usr/bin/zboot` from a `dist/dist.sh` output, or
  the installed `/usr/bin/zboot`;
- `mmdebstrap` (unshare mode, as above) and `dpkg-deb`;
- a work directory under `$TMPDIR` (default `/var/tmp`) that other users can
  traverse;
- the archive: `--mirror` (default `https://deb.debian.org/debian`) and
  Debian's security archive, or snapshot.debian.org with `--snapshot`.

It builds the package `zboot` from that installation, at the version above,
and installs it in the root with `dpkg -i`; mmdebstrap installs the package's
`Depends` first. The root's OpenZFS packages must be one version.

A deployed root keeps Debian's kernel, its `zfs-initramfs` initrds and the
stock `zfs-mount.service`, ZED and mount generator. A kernel update runs
Debian's own hooks. `deploy` writes the BE's `/etc/hostid` and rebuilds no
initrd: the menu passes `spl.spl_hostid` at every handoff.

## Source layout and entry points

Run commands from the repository root. `justfile` supplies optional shortcuts
for builds, tests and formatting. `just test` runs the offline suite. The
recipes call Cargo and the scripts below rather than duplicating their logic.

| Owner | Entry points and helpers |
|---|---|
| `crates/` | the `zfs-tools` library, the `zboot` and `zsnap` applications and the internal `zboot-helpers` package; build with Cargo. The helper sources are `zboot-helpers/src/bin/probe-signatures.rs` and `zboot-helpers/src/bin/change-key.rs` |
| `dist/` | `dist.sh OUT` builds the distribution from `build.lock`. `initramfs/` holds startup and runtime-staging scripts; `licences/` collects dependency notices; `deb/` holds package metadata (`control`) and the installation check (`preinst`) |
| `tests/` | `check.sh` runs the offline gate; `tooling/` holds its file-only tests of the distribution helpers, the package gate, the signature probe, the key relink helper and console selection; `acceptance/run.py` owns QEMU sessions and uses `acceptance/build-initrd.sh` internally; `native-api/run.py` and `native-readers/run.py` own the independent library and reader proofs |
| `docs/` | this guide, [CLI](CLI.md), [DESIGN](DESIGN.md), [RECOVERY](RECOVERY.md) and [TESTING](TESTING.md). Protected reader jobs are covered in the [zsnap guide](../crates/zsnap/README.md#protected-snapshot-readers) |

`stage-runtime.sh` also lists the programs a RAM boot takes in
`usr/lib/zboot/ram-boot.files`. See [TESTING.md](TESTING.md) for test prerequisites.
