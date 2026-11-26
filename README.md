# ZFS tools

A personal project for managing my own Debian ZFS-root machines on x86-64
UEFI. I share the source for others to study and adapt; development, defaults
and testing follow my own setup.

- **zboot** manages boot environments (BEs) and other dataset trees, pairs of
  dataset copies on two pools, disks, EFI system partitions (ESPs) and
  whole-disk restore. It ships with **the zboot UKI**, `zboot.efi`: a kernel,
  a small initramfs and zboot in one EFI file, which firmware starts from an
  ESP, a stick or the network. The UKI shows **the menu**: the boot
  environments it found, a countdown to the one-time selection or the default, and the same verbs as
  the command line.
- **zfs-tools** is the Rust library (`zfs_tools`). It lets applications inspect
  imported datasets, create and delete exact checkpoints, and protect snapshots
  while readers use them ([library guide](crates/zfs-tools/README.md)).
- **zsnap** takes snapshots, applies retention and supervises protected readers
  ([crates/zsnap/README.md](crates/zsnap/README.md)).

The two user-facing commands are `zboot` and `zsnap`. The workspace also builds
their internal helpers, `zboot-probe-signatures` and `zboot-change-key`, for four
executables in total. Rust consumers use the supported `zfs-tools` API; complete
reader jobs use `zsnap protect` and `zsnap recover`.

zboot keeps its state in ZFS properties and nothing else. A boot environment
is found, not registered, so one UKI serves every host. Stock Debian handles mounting and kernel updates. The menu discovers BEs
read-only. When a one-time boot is armed and visible, the menu clears its
marker on disk before handing off to the selected kernel.

## Origins and attribution

This started with my own A/B boot and recovery needs. An AI assistant pointed
me to [ZFSBootMenu](https://github.com/zbm-dev/zfsbootmenu) during early design.
I chose to build a personal tool and used its source directly as a reference,
especially for `kexec` arguments, kernel/initramfs discovery, and boot-runtime
startup and device readiness. Its menu and EFI-installation code were also
consulted.

Thank you to the ZFSBootMenu contributors. Their copyright notice and MIT
permission text are retained in [LICENSE](LICENSE), alongside the notice for
this project's original work and changes. ZFS tools is independently
maintained; its support and testing claims belong to this project.

## Common commands

```sh
# Try an upgrade in a copy of the running system.
zboot fork try --boot           # clone the running BE and select the fork once
zboot chroot try -- /usr/bin/apt full-upgrade
systemctl reboot                # boot try; the following reboot uses the usual default

# To keep booting try after a successful test, make it the persistent default.
zboot default try

# See boot environments, pairs, interrupted operations and what needs attention.
zboot status
```

[CLI.md](docs/CLI.md#everyday-use) has more: a second disk, a new host, a rescue
stick, remote access.

A verb that can lose data prints its plan and a token and changes nothing
until confirmed: on a terminal you type what it loses (a disk's serial, a
dataset name); a script passes the token from an earlier `--dry-run`
([Confirmation](docs/CLI.md#confirmation)). `--json` prints one result object.
Exit status 3 means not confirmed and nothing changed; 4 means it changed
something and did not finish, and the message names the next step
([exit statuses](docs/CLI.md#output-and-exit-status)).

## Developer entry points

The four Cargo packages are the `zfs-tools` library (`crates/zfs-tools`), the
`zboot` and `zsnap` applications (`crates/zboot`, `crates/zsnap`) and the
internal helpers (`crates/zboot-helpers`). The applications use the library's
private engine through its hidden, unsupported `engine` module; other
consumers use the supported API at the crate root. The helper package uses the host's dynamic libblkid and
libzfs_core libraries.

| Job | Command | Output or scope |
|---|---|---|
| Build developer binaries | `just build` or `cargo build --workspace --bins --locked` | zboot, zsnap and their two internal helpers |
| Build only the native library | `cargo build -p zfs-tools --lib --locked` | the supported API, without the applications or the engine feature |
| Run offline checks | `just test` or `sh tests/check.sh` | Rust, Clippy, formatting and file-only suites |
| Build the pinned distribution | `just dist OUT` or `dist/dist.sh OUT` | UKI, Debian package, matching source archive and unpacked installation; see [BUILD](docs/BUILD.md) |
| Run VM tests | follow [TESTING](docs/TESTING.md#vm-tests) | application acceptance, native library API and protected readers; requires KVM and build artifacts |

`just` is optional. Builds and VM tests stage under `TMPDIR`; choose
disk-backed storage ([TESTING](docs/TESTING.md)).

## Documents

| Document | Owns |
|---|---|
| [CLI.md](docs/CLI.md) | zboot verbs, options, refusals, exit statuses and menu commands |
| [zsnap guide](crates/zsnap/README.md) | snapshots, retention, [protected readers](crates/zsnap/README.md#protected-snapshot-readers) and the zsnap command line |
| [Library guide](crates/zfs-tools/README.md) | the supported `zfs_tools` API, its composition rules, reader protection and compatibility |
| [DESIGN.md](docs/DESIGN.md) | the design rules, safety checks and known limitations |
| [RECOVERY.md](docs/RECOVERY.md) | getting to the menu, rescue sticks, restoring and reinstalling a disk |
| [BUILD.md](docs/BUILD.md) | building the zboot UKI and the `zboot` package; making root tars |
| [TESTING.md](docs/TESTING.md) | the offline gate and the QEMU acceptance cases |

These guides are the maintained product documentation; development records
are kept separately ([publishing](docs/BUILD.md#publishing-a-source-snapshot)).

## OpenZFS dependency

On an installed system, zboot runs the host's OpenZFS commands. The UKI bundles
stock Debian OpenZFS tools and kernel modules. Neither uses a private OpenZFS fork.
Pairs and restore copy one dataset at a time as raw streams that carry no
properties (`zfs send -w` into `zfs receive -u`). A receive then changes only
data and, for an encrypted dataset, its key material; zboot sets the copy's
properties itself ([DESIGN](docs/DESIGN.md#pairs)). Restore also relinks
encryption keys with a small helper, `zboot-change-key`, linked against the
host's `libzfs_core.so.3`.

## Limits

- The native library and snapshot tools target Linux/OpenZFS. The boot
  image, `factory`, deployment and recovery workflows are developed and
  tested for my Debian x86-64 UEFI setup.
- `factory` makes the standard Debian root. `deploy` can take a root prepared
  elsewhere with the required kernel, initrd and ZFS module layout; passing
  those checks does not qualify another distribution's boot or initrd tools.
- New pairs and forked boot environments use single datasets. Pair each
  data leaf separately; snapshots across leaves promise no common capture
  moment.
- The UKI is not signed. Firmware must allow an unsigned loader.
- The [writer lock](docs/DESIGN.md#writer-lock) orders zboot and zsnap
  writers on one host. It is not a fence between hosts, and plain `zfs` and
  `zpool` commands do not take it.
- [DESIGN](docs/DESIGN.md#known-limitations-and-follow-up) lists the other
  current limits, including space limits across a `primary`, a diverged copy
  and what only engine tests cover.

## License

[LICENSE](LICENSE) contains the project terms and retained ZFSBootMenu notice.
Bundled dependencies keep their own terms and notices; see
[BUILD](docs/BUILD.md#licenses-and-source-access).
