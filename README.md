# zboot

A boot environment manager for debian on ZFS root.

## What's a boot environment?

A **boot environment** (BE) is a complete bootable copy of your root
filesystem. With ZFS, multiple BEs share unchanged blocks, so a dozen
of them typically cost just the differences between them. zboot lets
you snapshot before risky changes, fork experiments, roll back bad
upgrades, and mirror to a second disk for failover.

## How it works

Two Rust binaries from one workspace:

- **`zboot-boot.efi`** — EFI loader. Imports root pools, renders a BE
  menu, `kexec`s into the chosen one.
- **`zboot`** — the userspace CLI.

State lives in ZFS properties (no sidecar files, no `update-grub`). A
BE is a dataset under `<pool>/ROOT/` tagged `zboot:be=true`; the pool's
`bootfs` names the BE that boots next time.

## Install

```sh
cargo build --release -p zboot-cli           # → target/release/zboot
zboot deploy --target /dev/X --hostname H    # debootstrap + ZFS + EFI
reboot                                       # lands in the boot menu
```

## Daily use

```sh
zboot snapshot --name pre-upgrade
apt full-upgrade                              # ... regrets
zboot fork pre-upgrade-be --from pre-upgrade
zboot default pre-upgrade-be
reboot                                        # back to pre-upgrade state
```

Mirror to a second disk for failover:

```sh
zboot deploy --target /dev/Y --hostname H --no-efi --empty
zboot push be1 --to rpool2                    # bootstrap mutual pair
zboot mirror                                  # daily sync
```

Failover when the primary disk is dying:

```sh
zboot primary rpool2/ROOT/be1                 # flip pair; bootfs follows
reboot                                        # land on the now-primary
zboot push --force                            # settle peer readonly
```

## Verbs

```
snapshot      mark a rollback point on the running BE
fork          clone a snapshot into a new BE
default       set the next-boot BE
rollback      fork (auto-named) + default
drop          destroy a BE (auto-promotes dependent clones)
status        print the BE forest
attach/detach bind a dataset to one or more BEs (e.g. share /home)
cmdline       read/write zboot:kernel-cmdline (per-BE or pool-wide)
push          send a BE to its paired peer (or --to <pool> to bootstrap)
pull          receive from a paired peer (or --name <new> for initial pull)
primary       flip the pair-direction marker; bootfs follows
pair/unpair   declare/clear peers (metadata only)
rename        rename a BE; rewrite peer's pointer
mirror        bulk push every zboot:primary=on BE to its peers
chroot        mount a BE RW + drop into a shell
overlay       apply a host-specific data tar (rootfs + post-install.sh)
deploy        fresh-disk install (--no-efi / --empty / --mirror-from)
esp           install zboot-boot.efi on a separate ESP
factory       build a host-agnostic BE tar
live          build a Debian Live image (PXE-bootable for deploy)
```

Every run echoes its underlying `zfs`/`zpool` commands as `+ ...`
lines on stderr — copy any line and run it by hand.

For multi-pool deployments, disambiguate BE names with the full
dataset path (`zboot default rpool2/ROOT/be1`); bare names refuse on
ambiguity.

## Tests

```sh
cargo test --workspace      # data layer
bash scripts/run-all.sh     # every verb against real ZFS in QEMU
```

## See also

- [DESIGN.md](DESIGN.md) — decisions, state catalog, replication invariants
- [zfsbootmenu](https://github.com/zbm-dev/zfsbootmenu) — more mature, distro-agnostic prior art
