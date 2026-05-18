//! `zboot` — userspace CLI binary.

#![doc(html_no_source)]

use anyhow::Result;
use clap::{Parser, Subcommand};

use zboot_cli::cmd;

/// Multi-slot ZFS-based boot environment manager.
#[derive(Debug, Parser)]
#[command(
    name = "zboot",
    version,
    about = "Manage ZFS-based boot environments",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the current BE forest.
    Status(cmd::status::StatusArgs),
    /// Mark a rollback point on the running BE (`zfs snapshot` underneath).
    Snapshot(cmd::snapshot::SnapshotArgs),
    /// Create a new bootable BE by cloning a snapshot.
    Fork(cmd::fork::ForkArgs),
    /// Set the next-boot BE; reconcile mapped-dataset mountpoints.
    Default(cmd::default::DefaultArgs),
    /// Fork from a snapshot + set as default — one command.
    Rollback(cmd::rollback::RollbackArgs),
    /// Destroy a BE.
    Drop(cmd::drop::DropArgs),
    /// Get/set the kernel cmdline saved in ZFS properties.
    Cmdline(cmd::cmdline::CmdlineArgs),
    /// Fresh-disk install: partition + pool + rootfs + EFI.
    Deploy(cmd::deploy::DeployArgs),
    /// Install `zboot-boot.efi` onto a separate ESP (disk or partition)
    /// and register an `efibootmgr` entry. Pairs with `deploy --no-efi`
    /// for "pool here, EFI there" topologies (USB / SD / small SSD).
    Esp(cmd::esp::EspArgs),
    /// Attach a dataset to one or more BEs (e.g. share `/home`). Sets
    /// `zboot:attached-to=<pool:be>,...` and toggles `canmount` so the
    /// dataset is only auto-mounted when one of the bound BEs is active.
    Attach(cmd::attach::AttachArgs),
    /// Detach a dataset from all BE bindings — clears `zboot:attached-to`.
    /// To remove one BE from a multi-BE binding, re-run `attach` with a
    /// smaller `--to` list instead.
    Detach(cmd::attach::DetachArgs),
    /// Send a BE's snapshot stream to its paired peer (or `--to <pool>`
    /// to bootstrap a new pair; `--to <pool>/ROOT/<name>` for ad-hoc).
    Push(cmd::push::PushArgs),
    /// Receive from a paired peer (or `--name <new>` for initial pull
    /// into a fresh local BE).
    Pull(cmd::pull::PullArgs),
    /// Promote this BE to be the primary side of its mutual pair: flip
    /// `zboot:primary` and `readonly` on both sides, follow bootfs.
    /// Metadata-only; no data motion.
    Primary(cmd::primary::PrimaryArgs),
    /// Declare two extant BEs as peers without sending bytes (metadata
    /// only). Refuses on GUID-set divergence unless `--force`.
    Pair(cmd::pair::PairArgs),
    /// Clear `zboot:mirror` on a BE (and on the peer if mutual).
    Unpair(cmd::pair::UnpairArgs),
    /// Rename a BE and update any peer's `zboot:mirror` that pointed at
    /// the old name.
    Rename(cmd::rename::RenameArgs),
    /// Bulk-walk every BE with `zboot:primary=on` and push to its
    /// `zboot:mirror` peer + any incoming asymmetric trackers.
    /// One-shot daily-sync verb; see DESIGN.md § Topologies.
    Mirror(cmd::mirror::MirrorArgs),
    /// Mount a BE RW + drop into an interactive shell inside it.
    Chroot(cmd::chroot::ChrootArgs),
    /// Apply a host-specific data tar (rootfs + post-install.sh) to a deployed BE.
    Overlay(cmd::overlay::OverlayArgs),
    /// Build a host-agnostic factory BE tar that `deploy --source tar://` consumes.
    /// No `--packages` → stock factory tar (zboot's own e2e fixture);
    /// downstream wrappers layer the production package set via `--packages`.
    Factory(cmd::factory::FactoryArgs),
    /// Build a minimal Debian Live image (vmlinuz/initrd.img/filesystem.squashfs)
    /// usable both for PXE-booting `zboot deploy` and as a recovery medium.
    /// Callers layer extras via `--packages`/`--hooks-dir`/`--includes-dir`.
    Live(cmd::live::LiveArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut stdout = std::io::stdout();
    match cli.command {
        Command::Status(args) => cmd::status::run(&args, &mut stdout),
        Command::Snapshot(args) => cmd::snapshot::run(&args, &mut stdout),
        Command::Fork(args) => cmd::fork::run(&args, &mut stdout),
        Command::Default(args) => cmd::default::run(&args, &mut stdout),
        Command::Rollback(args) => cmd::rollback::run(&args, &mut stdout),
        Command::Drop(args) => cmd::drop::run(&args, &mut stdout),
        Command::Cmdline(args) => cmd::cmdline::run(&args, &mut stdout),
        Command::Deploy(args) => cmd::deploy::run(&args, &mut stdout),
        Command::Esp(args) => cmd::esp::run(&args, &mut stdout),
        Command::Attach(args) => cmd::attach::run(&args, &mut stdout),
        Command::Detach(args) => cmd::attach::detach(&args, &mut stdout),
        Command::Push(args) => cmd::push::run(&args, &mut stdout),
        Command::Pull(args) => cmd::pull::run(&args, &mut stdout),
        Command::Primary(args) => cmd::primary::run(&args, &mut stdout),
        Command::Pair(args) => cmd::pair::run_pair(&args, &mut stdout),
        Command::Unpair(args) => cmd::pair::run_unpair(&args, &mut stdout),
        Command::Rename(args) => cmd::rename::run(&args, &mut stdout),
        Command::Mirror(args) => cmd::mirror::run(&args, &mut stdout),
        Command::Chroot(args) => cmd::chroot::run(&args, &mut stdout),
        Command::Overlay(args) => cmd::overlay::run(&args, &mut stdout),
        Command::Factory(args) => cmd::factory::run(&args, &mut stdout),
        Command::Live(args) => cmd::live::run(&args, &mut stdout),
    }
}
