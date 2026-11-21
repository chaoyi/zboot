use clap::{FromArgMatches, Parser, Subcommand};

#[derive(Debug, PartialEq, Eq, Parser)]
#[command(
    name = "zboot",
    version = crate::build_identity::VERSION,
    about = "Standalone ZFS boot and data management"
)]
pub(crate) struct Cli {
    /// Print native commands and diagnostic details to stderr.
    #[arg(short = 'v', global = true)]
    pub(crate) verbose: bool,
    #[command(subcommand)]
    pub(crate) command: Verb,
}
#[derive(Debug, PartialEq, Eq, Subcommand)]
pub(crate) enum Verb {
    /// Install a root tar on a disk, a new image, or an imported pool.
    /// Disk and image targets create an ESP and pool or an empty POOL/ROOT.
    /// --into adds a BE while preserving every boot default.
    /// An interrupted deploy is rerun, never resumed.
    #[command(group(clap::ArgGroup::new("deploy_target").args(["disk","image","into"]).required(true).multiple(false)))]
    Deploy {
        /// Whole-disk device, e.g. /dev/disk/by-id/nvme-...
        disk: Option<String>,
        /// Create a new image file; an existing file is refused.
        #[arg(long, value_name = "FILE")]
        image: Option<std::path::PathBuf>,
        /// Add a BE to an imported pool, preserving all boot defaults.
        #[arg(long, value_name = "POOL", conflicts_with_all = ["pool", "hostid", "esp", "esp_partition", "swap", "efi", "size", "portable", "empty"])]
        into: Option<String>,
        /// Image size (default: content plus headroom, rounded to GiB).
        #[arg(long,value_parser=parse_size,requires="image")]
        size: Option<u64>,
        /// No host identity, swap or boot default; read-only root with RAM writes.
        #[arg(long,conflicts_with_all=["hostid","swap","esp_partition","empty"])]
        portable: bool,
        /// zboot UKI file (default: ../lib/zboot/zboot.efi from zboot's directory).
        #[arg(long, value_name = "FILE")]
        efi: Option<std::path::PathBuf>,
        /// Root tar (`zboot factory` writes one); creates the BE POOL/ROOT/NAME.
        #[arg(
            long,
            value_name = "TAR",
            conflicts_with = "empty",
            required_unless_present = "empty"
        )]
        tar: Option<std::path::PathBuf>,
        /// Host overlay: `rootfs/` copied over the BE and an optional
        /// `post-install` run in it, as a directory or tar.
        #[arg(
            long,
            value_name = "DIR|TAR|builtin:NAME",
            value_parser = parse_overlay,
            requires = "tar",
            conflicts_with = "empty"
        )]
        overlay: Vec<std::path::PathBuf>,
        /// BE name (default: default).
        #[arg(long, value_name = "NAME", requires = "tar", conflicts_with = "empty")]
        be: Option<String>,
        /// Create only POOL and POOL/ROOT, with no boot default.
        #[arg(long)]
        empty: bool,
        /// Pool name (default: rpool); an existing pool name is refused.
        #[arg(long, value_name = "NAME")]
        pool: Option<String>,
        /// Hostid of the new system, eight lowercase hex digits (default: the
        /// running host's effective hostid, else a new random one).
        #[arg(long, value_parser = parse_hostid)]
        hostid: Option<String>,
        /// The new system's /etc/hostname (default: the factory's).
        #[arg(long, value_name = "NAME", requires = "tar", value_parser = parse_hostname)]
        hostname: Option<String>,
        /// ESP size on DISK, e.g. 1G (default: 1G).
        #[arg(long, value_parser = parse_size, conflicts_with = "esp_partition")]
        esp: Option<u64>,
        /// Install the loader on this existing ESP on another disk instead.
        #[arg(long, value_name = "PART", conflicts_with = "image")]
        esp_partition: Option<String>,
        /// Swap partition size, e.g. 8G (default: none).
        #[arg(long, value_parser = parse_size)]
        swap: Option<u64>,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview of this plan printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan (with its token) or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Rebuild disk A from a boot environment on surviving disk B, keeping
    /// selected dataset trees of A; erases A after typed confirmation.
    Restore {
        /// `POOL/ROOT/BE` (snapshotted now; the running root only) or `BE@SNAP`.
        source: Option<String>,
        /// Whole-disk device of A, e.g. /dev/disk/by-id/nvme-...
        disk: Option<String>,
        /// A dataset root on A to keep, with its descendants; repeatable.
        #[arg(long = "keep", value_name = "DATASET")]
        keep: Vec<String>,
        /// Name of A's new pool (default: A's current pool name, else rpool).
        #[arg(long)]
        pool: Option<String>,
        /// ESP size, e.g. 1G (default: A's current ESP, else 1G).
        #[arg(long, value_parser = parse_size)]
        esp: Option<u64>,
        /// Swap size, e.g. 8G, or 0 (default: A's current swap, else none).
        #[arg(long, value_parser = parse_size)]
        swap: Option<u64>,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview of this plan printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan (with its token) or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Continue an interrupted operation, selected by ID or as the only record.
    Resume {
        id: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// End an interrupted operation without destroying data.
    Abandon {
        id: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Build a host-agnostic Debian root tar that boots from ZFS, rootless.
    Factory {
        /// The tar to write, zstd-compressed whatever its name; TAR.packages
        /// lists the installed packages.
        #[arg(value_name = "TAR")]
        output: std::path::PathBuf,
        /// Debian suite.
        #[arg(long, default_value = crate::factory::DEFAULT_SUITE)]
        suite: String,
        /// Debian archive the root updates from (default: deb.debian.org);
        /// with --snapshot the build itself reads snapshot.debian.org.
        #[arg(long, value_name = "URL")]
        mirror: Option<String>,
        /// Pin every archive to this snapshot.debian.org time, YYYYMMDDTHHMMSSZ.
        #[arg(long, value_name = "TIME")]
        snapshot: Option<String>,
        /// More packages, e.g. openssh-server.
        #[arg(long, value_name = "PKG,...", value_delimiter = ',')]
        packages: Vec<String>,
        /// Take only the OpenZFS packages from this suite.
        #[arg(long, value_name = "SUITE")]
        zfs_from_suite: Option<String>,
        /// Print the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Internal factory construction stage.
    #[command(hide = true)]
    FactoryFinish {
        root: std::path::PathBuf,
        stage: std::path::PathBuf,
    },
    /// Refresh zboot loaders on imported-pool disks and the local ESP this boot came from, or install on named ESPs.
    Esp {
        #[arg(value_name = "PART", value_parser = parse_partition)]
        partitions: Vec<String>,
        /// The zboot UKI, otherwise the shipped zboot.efi.
        #[arg(long, value_name = "FILE")]
        efi: Option<std::path::PathBuf>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Decode the stage timings and asset hashes carried by the last handoff.
    Trace {
        /// Kernel command-line file to decode.
        #[arg(long, default_value = "/proc/cmdline")]
        cmdline: std::path::PathBuf,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Rename an unpaired tree within its pool. Across pools use sync,
    /// primary, unpair --release-anchors, then drop.
    Rename {
        source: String,
        #[arg(value_name = "DEST")]
        destination: String,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Rewind a tree to a snapshot every member has (loss-capable).
    Rollback {
        #[arg(value_name = "DATASET@SNAP")]
        target: String,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview of this plan printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan (with its token) or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Make DATASET's side the working copy: fence a reachable peer and catch
    /// up from it, or take over when DATASET is ahead or diverged (the peer's
    /// later changes are lost), or activate DATASET alone when its peer is gone.
    /// Moves the boot default with it.
    Primary {
        /// Pair root, or an unpaired dataset to activate from its saved placement.
        dataset: String,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview of this plan printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan (with its token) or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open writable maintenance in an eligible working or standalone BE.
    Chroot {
        dataset: String,
        /// Verb inside the selected BE; defaults to its bash or sh.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Erase an unused whole disk: NVMe sanitize where that is safe, else clear its labels, signatures and partition tables.
    Wipe {
        /// Whole-disk device path, preferably /dev/disk/by-id/...
        disk: Option<String>,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview of this plan printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan (with its token) or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Copy new snapshots one way, never overwriting the receiver's history:
    /// a pair from its working copy, SRC into DEST (an absent DEST is created
    /// and paired with SRC), or every imported pair.
    Sync {
        /// Pair root, or the source when DEST is given.
        #[arg(value_name = "DATASET|SRC", required_unless_present = "all")]
        source: Option<String>,
        #[arg(value_name = "DEST")]
        destination: Option<String>,
        /// Sync every imported pair from its working copy.
        #[arg(long, conflicts_with = "source")]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Select the pool's default boot environment after validating ownership.
    Default {
        #[arg(value_name = "BE")]
        dataset: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Read or replace saved kernel argument additions.
    Cmdline {
        #[arg(value_name = "BE")]
        dataset: Option<String>,
        #[arg(long)]
        json: bool,
        /// Replace the saved additions.
        #[arg(long, allow_hyphen_values = true, value_name = "ARGS")]
        set: Option<String>,
        /// Remove the saved additions.
        #[arg(long, conflicts_with = "set")]
        clear: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
    },
    /// Clone a BE's snapshot, or capture the running BE and clone it, as a new BE in one pool.
    #[command(allow_missing_positional = true)]
    Fork {
        /// Explicit source snapshot BE@SNAP or @SNAP.
        #[arg(value_name = "BE@SNAP", num_args = 0..=1)]
        snapshot: Option<String>,
        #[arg(value_name = "DEST")]
        destination: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Destroy snapshots, whole unpaired trees or leftover staging (loss-capable).
    Drop {
        /// Snapshots (DATASET@SNAP) and dataset trees, all in one pool.
        #[arg(required = true, value_name = "TARGET")]
        targets: Vec<String>,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview of this plan printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan (with its token) or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Boot a boot environment, using the boot default when BE is omitted,
    /// or a root tar in RAM.
    Boot {
        #[arg(value_name = "BE")]
        dataset: Option<String>,
        /// Installed kernel version from the selected boot environment's inventory.
        #[arg(long, value_name = "NAME")]
        kernel: Option<String>,
        /// Root tar to boot in RAM; `-` reads it from stdin.
        #[arg(long, value_name = "FILE|-", conflicts_with_all = ["dataset", "kernel"])]
        tar: Option<std::path::PathBuf>,
        /// Overlay whose `rootfs/` files the RAM root gets, in order.
        #[arg(
            long,
            value_name = "DIR|TAR|builtin:NAME",
            value_parser = parse_overlay,
            requires = "tar",
            // clap drops `requires` for an argument that conflicts with one
            // present (`--tar` with BE), so the conflict is stated here too.
            conflicts_with_all = ["dataset", "kernel"]
        )]
        overlay: Vec<std::path::PathBuf>,
        /// Print the boot result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reboot into the loader ESP's menu, requesting a one-boot remote wait.
    Reboot {
        /// Enter the menu; an ordinary reboot uses systemctl reboot.
        #[arg(long, required = true)]
        menu: bool,
        /// Plain OpenSSH public key file; omit for a wait without SSH.
        #[arg(long, value_name = "FILE")]
        key: Option<std::path::PathBuf>,
        /// Write the request to this ESP, which holds zboot's loader, instead
        /// of the one this boot was loaded from.
        #[arg(long, value_name = "PART", value_parser = parse_partition)]
        esp: Option<String>,
        /// Show the selected ESP and key fingerprints without changing it.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Enter the zboot menu in the self-contained UKI.
    Menu {
        /// Wait for a command instead of starting the automatic boot countdown.
        #[arg(long)]
        no_autoboot: bool,
    },
    /// Disconnect a pair, keeping data, mounts, read-only settings and anchor
    /// holds. When the peer is gone, only DATASET's record is removed, on the
    /// operator's word.
    Unpair {
        dataset: String,
        /// Also release zboot's common-snapshot holds on both sides (works
        /// after an earlier unpair too).
        #[arg(long)]
        release_anchors: bool,
        /// Show the plan and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed with the token an earlier preview of this plan printed.
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        /// Print the plan (with its token) or the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Establish a mutual pair: fence the receiver and hold the common
    /// snapshots; nothing is transferred or deleted.
    Pair {
        #[arg(value_name = "PRIMARY")]
        left: String,
        #[arg(value_name = "SECONDARY")]
        right: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Capture a recursive point on a working or unpaired tree.
    Snapshot {
        /// Recursive targets, each optionally naming its snapshot after @.
        #[arg(value_name = "DATASET[@NAME]|@NAME")]
        datasets: Vec<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        confirm: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show storage, boot selection and observed management state.
    Status {
        #[arg(value_name = "DATASET")]
        datasets: Vec<String>,
        /// List every dataset in the text report.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        snapshots: bool,
        #[arg(long)]
        devices: bool,
        #[arg(long)]
        json: bool,
    },
}

impl Cli {
    /// Parse a complete external command line, including its program name.
    pub(crate) fn parse_from_args<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Self::parse_for_menu(args)?;
        cli.validate_complete()?;
        Ok(cli)
    }

    /// Parse the same argv grammar, including its program name, allowing the
    /// menu to fill omitted restore/wipe operands with its identity-bound pickers.
    pub(crate) fn parse_for_menu<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let matches = super::help::command().try_get_matches_from(args)?;
        let cli = Self::from_arg_matches(&matches)?;
        cli.validate()?;
        Ok(cli)
    }

    /// Check the final command after any menu pickers have supplied operands.
    pub(crate) fn validate_complete(&self) -> Result<(), clap::Error> {
        self.validate()?;
        let missing = match &self.command {
            Verb::Restore {
                source: None,
                disk: None,
                ..
            } => Some("restore requires SOURCE and DISK"),
            Verb::Restore { source: None, .. } => Some("restore requires SOURCE"),
            Verb::Restore { disk: None, .. } => Some("restore requires DISK"),
            Verb::Wipe { disk: None, .. } => Some("wipe requires DISK"),
            _ => None,
        };
        match missing {
            Some(message) => Err(super::help::command()
                .error(clap::error::ErrorKind::MissingRequiredArgument, message)),
            None => Ok(()),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), clap::Error> {
        let message = match &self.command {
            // Clap's required target group can satisfy the image dependency
            // through its disk alternative; keep this relation semantic too.
            Verb::Deploy {
                image: None,
                size: Some(_),
                ..
            } => Some("deploy --size requires --image"),
            Verb::Default {
                dataset: None,
                dry_run,
                confirm,
                ..
            } if *dry_run || confirm.is_some() => {
                Some("default --dry-run and --confirm require a BE to change")
            }
            Verb::Cmdline {
                set: None,
                clear: false,
                dry_run,
                confirm,
                ..
            } if *dry_run || confirm.is_some() => {
                Some("cmdline --dry-run and --confirm require --set or --clear")
            }
            Verb::Fork {
                snapshot: Some(source),
                ..
            } if !source.contains('@') => Some("an explicit fork source must include @SNAP"),
            Verb::Fork { destination, .. } if destination.contains('@') => {
                Some("fork DEST names a dataset, so DEST cannot contain @")
            }
            Verb::Snapshot { datasets, .. }
                if datasets.len() > 1 && datasets.iter().any(|target| target.starts_with('@')) =>
            {
                Some("with multiple snapshot targets, each must name its dataset; use DATASET@NAME")
            }
            _ => None,
        };
        match message {
            Some(message) => {
                Err(super::help::command().error(clap::error::ErrorKind::ArgumentConflict, message))
            }
            None => Ok(()),
        }
    }
}

impl Verb {
    pub(crate) fn targets_mut(&mut self) -> Vec<&mut String> {
        match self {
            Self::Status { datasets, .. } | Self::Snapshot { datasets, .. } => {
                datasets.iter_mut().collect()
            }
            Self::Fork {
                snapshot,
                destination,
                ..
            } => snapshot
                .iter_mut()
                .chain(std::iter::once(destination))
                .collect(),
            Self::Rename {
                source,
                destination,
                ..
            } => vec![source, destination],
            Self::Rollback {
                target: dataset, ..
            }
            | Self::Chroot { dataset, .. }
            | Self::Primary { dataset, .. }
            | Self::Unpair { dataset, .. } => vec![dataset],
            Self::Default { dataset, .. }
            | Self::Cmdline { dataset, .. }
            | Self::Boot { dataset, .. } => dataset.iter_mut().collect(),
            Self::Drop { targets, .. } => targets.iter_mut().collect(),
            Self::Pair { left, right, .. } => vec![left, right],
            Self::Sync {
                source,
                destination,
                ..
            } => source.iter_mut().chain(destination.iter_mut()).collect(),
            Self::Restore { source, keep, .. } => {
                source.iter_mut().chain(keep.iter_mut()).collect()
            }
            Self::Deploy { .. }
            | Self::Resume { .. }
            | Self::Abandon { .. }
            | Self::Factory { .. }
            | Self::FactoryFinish { .. }
            | Self::Esp { .. }
            | Self::Trace { .. }
            | Self::Wipe { .. }
            | Self::Reboot { .. }
            | Self::Menu { .. } => Vec::new(),
        }
    }
}

fn parse_partition(value: &str) -> Result<String, String> {
    if std::path::Path::new(value).is_absolute() {
        Ok(value.into())
    } else {
        Err("an ESP partition needs an absolute device path".into())
    }
}

fn parse_overlay(value: &str) -> Result<std::path::PathBuf, String> {
    let path = std::path::PathBuf::from(value);
    crate::deploy::overlay::validate_builtin_name(&path).map_err(|error| error.to_string())?;
    Ok(path)
}

fn parse_hostname(value: &str) -> Result<String, String> {
    if crate::deploy::request::valid_hostname(value) {
        Ok(value.into())
    } else {
        Err("a hostname is dot-separated letters, digits and inner hyphens".into())
    }
}

/// Eight lowercase hex digits, excluding `00000000` and `ffffffff`.
fn parse_hostid(value: &str) -> Result<String, String> {
    if value.len() == 8
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value != "00000000"
        && value != "ffffffff"
    {
        Ok(value.into())
    } else {
        Err("a hostid is eight lowercase hex digits, not 00000000 or ffffffff".into())
    }
}

/// `N`, `NK`, `NM`, `NG` or `NT` (binary multiples).
fn parse_size(value: &str) -> Result<u64, String> {
    let (digits, shift) = match value.char_indices().last() {
        Some((i, 'K' | 'k')) => (&value[..i], 10),
        Some((i, 'M' | 'm')) => (&value[..i], 20),
        Some((i, 'G' | 'g')) => (&value[..i], 30),
        Some((i, 'T' | 't')) => (&value[..i], 40),
        _ => (value, 0),
    };
    let number: u64 = digits
        .parse()
        .map_err(|_| format!("invalid size {value:?}; use e.g. 512M or 8G"))?;
    number
        .checked_mul(1 << shift)
        .ok_or_else(|| format!("size {value:?} is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::parse_from_args(std::iter::once("zboot").chain(args.iter().copied()))
    }

    fn parse_menu(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::parse_for_menu(std::iter::once("zboot").chain(args.iter().copied()))
    }

    #[test]
    fn reboot_menu_requires_menu_and_accepts_normal_preview_options() {
        let cli = Cli::parse_from_args([
            "zboot",
            "reboot",
            "--menu",
            "--key",
            "keys",
            "--esp",
            "/dev/nvme0n1p1",
            "--dry-run",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Verb::Reboot {
                menu: true,
                key: Some(_),
                esp: Some(ref esp),
                dry_run: true,
                json: true,
                ..
            } if esp == "/dev/nvme0n1p1"
        ));
        assert!(Cli::parse_from_args(["zboot", "reboot", "--menu", "--esp", "sda1"]).is_err());
        assert_eq!(
            Cli::parse_from_args(["zboot", "reboot"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(
            Cli::parse_from_args([
                "zboot",
                "reboot",
                "--menu",
                "--dry-run",
                "--confirm",
                "token"
            ])
            .is_err()
        );
    }

    #[test]
    fn a_menu_line_and_a_command_line_parse_to_the_same_command() {
        for args in [
            &["status", "a/ROOT/be", "--json"][..],
            &["boot"],
            &[
                "boot",
                "a/ROOT/be",
                "--kernel",
                "6.12.1-amd64",
                "--json",
                "-v",
            ],
            &["menu", "--no-autoboot"],
            &[
                "restore",
                "b/ROOT/be@s",
                "/dev/disk",
                "--keep",
                "a/home",
                "--dry-run",
            ],
            &["wipe", "/dev/disk", "--confirm", "token"],
            &["resume"],
            &["abandon", "operation"],
            &["cmdline", "a/ROOT/be", "--set", "console=ttyS0 d1 3"],
            &["chroot", "a/ROOT/be", "--", "printf", "%s", "d1"],
        ] {
            assert_eq!(parse(args).unwrap(), parse_menu(args).unwrap(), "{args:?}");
        }
    }

    #[test]
    fn only_menu_parsing_allows_picker_operands_to_be_omitted() {
        for args in [
            &["restore"][..],
            &["restore", "b/ROOT/be@s"],
            &["restore", "--keep", "a/home", "--dry-run"],
            &["wipe"],
            &["wipe", "--confirm", "token"],
        ] {
            let mut cli = parse_menu(args).unwrap();
            for error in [
                parse(args).unwrap_err(),
                cli.validate_complete().unwrap_err(),
            ] {
                assert_eq!(
                    error.kind(),
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "{args:?}: {error}"
                );
                assert_eq!(error.exit_code(), 2);
            }
            match &mut cli.command {
                Verb::Restore { source, disk, .. } => {
                    *source = Some("b/ROOT/be@s".into());
                    *disk = Some("/dev/disk".into());
                }
                Verb::Wipe { disk, .. } => *disk = Some("/dev/disk".into()),
                _ => panic!("unexpected picker fixture"),
            }
            cli.validate_complete().unwrap();
        }
        let mut cli = parse_menu(&["restore"]).unwrap();
        let Verb::Restore { disk, .. } = &mut cli.command else {
            unreachable!()
        };
        *disk = Some("/dev/disk".into());
        let error = cli.validate_complete().unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(
            error.to_string().contains("restore requires SOURCE"),
            "{error}"
        );
    }

    #[test]
    fn menu_parsing_keeps_syntax_and_semantic_usage_errors() {
        for args in [
            &["restore", "--dry-run", "--confirm", "token"][..],
            &["wipe", "--dry-run", "--confirm", "token"],
            &["cmdline", "--set", "A", "--clear"],
            &["default", "--dry-run"],
            &["fork", "source", "destination"],
            &["snapshot", "a", "@name"],
            &["sync", "a", "b", "--all"],
            &["drop"],
            &["recovery", "status"],
            &["menu", "--json"],
            &["menu", "--debug"],
        ] {
            for error in [parse(args).unwrap_err(), parse_menu(args).unwrap_err()] {
                assert_eq!(error.exit_code(), 2, "{args:?}: {error}");
            }
        }
    }

    #[test]
    fn boot_names_a_kernel_version_or_a_root_tar() {
        let cli = parse(&["boot", "a/ROOT/be", "--kernel", "6.12.1-amd64", "--json"]).unwrap();
        assert!(matches!(cli.command, Verb::Boot {
            dataset: Some(dataset), kernel: Some(kernel), tar: None, json: true, ..
        } if dataset == "a/ROOT/be" && kernel == "6.12.1-amd64"));
        assert!(matches!(
            parse(&["boot"]).unwrap().command,
            Verb::Boot {
                dataset: None,
                kernel: None,
                tar: None,
                json: false,
                ..
            }
        ));
        assert!(matches!(
            parse(&["boot", "--kernel", "6.12.1-amd64"]).unwrap().command,
            Verb::Boot { dataset: None, kernel: Some(kernel), json: false, .. }
                if kernel == "6.12.1-amd64"
        ));
        let ram = [
            "boot",
            "--tar",
            "-",
            "--overlay",
            "builtin:rescue",
            "--overlay",
            "/access",
        ];
        for parsed in [parse(&ram), parse_menu(&ram)] {
            let Verb::Boot {
                dataset: None,
                kernel: None,
                tar: Some(tar),
                overlay,
                json: false,
            } = parsed.unwrap().command
            else {
                panic!("boot --tar did not parse as a RAM boot");
            };
            assert_eq!(tar, std::path::Path::new("-"));
            assert_eq!(
                overlay,
                [
                    std::path::PathBuf::from("builtin:rescue"),
                    std::path::PathBuf::from("/access")
                ]
            );
        }
        assert!(matches!(
            parse(&["menu"]).unwrap().command,
            Verb::Menu { no_autoboot: false }
        ));
        assert!(matches!(
            parse(&["menu", "--no-autoboot"]).unwrap().command,
            Verb::Menu { no_autoboot: true }
        ));
        for args in [
            &["boot", "--kernel"][..],
            &[
                "boot",
                "a/ROOT/be",
                "--kernel",
                "6.12.1-amd64",
                "--initrd",
                "/boot/initrd",
            ],
            &["boot", "--tar"],
            &["boot", "a/ROOT/be", "--tar", "/root.tar"],
            &["boot", "--kernel", "6.12.1-amd64", "--tar", "/root.tar"],
            &["boot", "--overlay", "/access"],
            &["boot", "a/ROOT/be", "--overlay", "/access"],
            &["boot", "--tar", "/root.tar", "--overlay", "builtin:base"],
        ] {
            assert_eq!(parse(args).unwrap_err().exit_code(), 2, "{args:?}");
            assert_eq!(parse_menu(args).unwrap_err().exit_code(), 2, "{args:?}");
        }
    }

    #[test]
    fn verbose_is_one_global_short_flag() {
        assert!(!parse(&["status"]).unwrap().verbose);
        for args in [
            &["-v", "status"][..],
            &["status", "-v"],
            &["esp", "/dev/test", "--efi", "/zboot.efi", "-v"],
        ] {
            assert!(parse(args).unwrap().verbose, "{args:?}");
        }
        assert!(parse(&["status", "--verbose"]).is_err());
    }

    #[test]
    fn only_target_arguments_are_resolved() {
        let cases: &[(&[&str], &[&str])] = &[
            (
                &["status", "work", "cpool/home"],
                &["rpool/ROOT/work", "cpool/home"],
            ),
            (
                &["snapshot", "work@day", "next"],
                &["rpool/ROOT/work@day", "rpool/ROOT/next"],
            ),
            (&["snapshot", "@day"], &["rpool/ROOT/current@day"]),
            (
                &["fork", "work@day", "next"],
                &["rpool/ROOT/work@day", "rpool/ROOT/next"],
            ),
            (&["fork", "next"], &["rpool/ROOT/next"]),
            (
                &["rename", "work", "next"],
                &["rpool/ROOT/work", "rpool/ROOT/next"],
            ),
            (&["rollback", "@day"], &["rpool/ROOT/current@day"]),
            (
                &["drop", "work@day", "cpool/home"],
                &["rpool/ROOT/work@day", "cpool/home"],
            ),
            (&["default", "work"], &["rpool/ROOT/work"]),
            (&["default"], &[]),
            (&["cmdline"], &[]),
            (
                &["cmdline", "work", "--set", "work@day"],
                &["rpool/ROOT/work"],
            ),
            (
                &["chroot", "work", "--", "work", "@day", "/dev/test"],
                &["rpool/ROOT/work"],
            ),
            (&["primary", "work"], &["rpool/ROOT/work"]),
            (&["unpair", "work"], &["rpool/ROOT/work"]),
            (
                &["pair", "work", "next"],
                &["rpool/ROOT/work", "rpool/ROOT/next"],
            ),
            (
                &["sync", "work", "next"],
                &["rpool/ROOT/work", "rpool/ROOT/next"],
            ),
            (&["sync", "work"], &["rpool/ROOT/work"]),
            (&["sync", "--all"], &[]),
            (
                &[
                    "restore",
                    "work@day",
                    "/dev/disk",
                    "--keep",
                    "home",
                    "--keep",
                    "cpool/home",
                    "--pool",
                    "work",
                ],
                &["rpool/ROOT/work@day", "rpool/ROOT/home", "cpool/home"],
            ),
            (
                &[
                    "deploy",
                    "/dev/disk",
                    "--tar",
                    "/input/root.tar",
                    "--pool",
                    "work",
                    "--be",
                    "work",
                    "--efi",
                    "/input/boot.efi",
                    "--esp-partition",
                    "/dev/esp",
                ],
                &[],
            ),
            (&["resume", "work", "--confirm", "token"], &[]),
            (&["abandon", "work", "--confirm", "token"], &[]),
            (&["wipe", "/dev/disk"], &[]),
            (&["esp", "/dev/esp", "--efi", "/input/recovery.efi"], &[]),
            (&["factory", "/output/root.tar"], &[]),
            (&["factory-finish", "/private/root", "/private/stage"], &[]),
            (&["trace", "--cmdline", "/input/cmdline"], &[]),
            (
                &["boot", "work", "--kernel", "6.12-work", "--json"],
                &["rpool/ROOT/work"],
            ),
            (&["boot"], &[]),
            (&["menu", "--no-autoboot"], &[]),
        ];
        for (arguments, expected) in cases {
            let mut cli = parse(arguments).unwrap();
            for target in cli.command.targets_mut() {
                *target =
                    super::super::names::resolve(Some(target.as_str()), Some("rpool/ROOT/current"))
                        .unwrap();
            }
            let actual: Vec<_> = cli
                .command
                .targets_mut()
                .into_iter()
                .map(|target| target.as_str())
                .collect();
            assert_eq!(actual, *expected, "{arguments:?}");
            match cli.command {
                Verb::Chroot { command, .. } => assert_eq!(command, ["work", "@day", "/dev/test"]),
                Verb::Cmdline {
                    set: Some(value), ..
                } => assert_eq!(value, "work@day"),
                Verb::Restore { disk, pool, .. } => {
                    assert_eq!(disk.as_deref(), Some("/dev/disk"));
                    assert_eq!(pool.as_deref(), Some("work"));
                }
                Verb::Deploy {
                    disk,
                    tar,
                    efi,
                    pool,
                    be,
                    esp_partition,
                    ..
                } => {
                    assert_eq!(disk.as_deref(), Some("/dev/disk"));
                    assert_eq!(
                        tar.as_deref(),
                        Some(std::path::Path::new("/input/root.tar"))
                    );
                    assert_eq!(
                        efi.as_deref(),
                        Some(std::path::Path::new("/input/boot.efi"))
                    );
                    assert_eq!(pool.as_deref(), Some("work"));
                    assert_eq!(be.as_deref(), Some("work"));
                    assert_eq!(esp_partition.as_deref(), Some("/dev/esp"));
                }
                Verb::Resume { id, confirm, .. } | Verb::Abandon { id, confirm, .. } => {
                    assert_eq!(id.as_deref(), Some("work"));
                    assert_eq!(confirm.as_deref(), Some("token"));
                }
                Verb::Wipe { disk, .. } => assert_eq!(disk.as_deref(), Some("/dev/disk")),
                Verb::Esp {
                    partitions, efi, ..
                } => {
                    assert_eq!(partitions, ["/dev/esp"]);
                    assert_eq!(
                        efi.as_deref(),
                        Some(std::path::Path::new("/input/recovery.efi"))
                    );
                }
                Verb::Factory { output, .. } => {
                    assert_eq!(output, std::path::Path::new("/output/root.tar"))
                }
                Verb::FactoryFinish { root, stage } => {
                    assert_eq!(root, std::path::Path::new("/private/root"));
                    assert_eq!(stage, std::path::Path::new("/private/stage"));
                }
                Verb::Boot { kernel, .. } => {
                    assert!(kernel.is_none() || kernel.as_deref() == Some("6.12-work"));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn conflicting_and_missing_arguments_are_usage_errors() {
        let cases: &[(&[&str], &[&str])] = &[
            (&["snapshot", "a", "@x"], &["snapshot", "a@x", "b@y"]),
            (
                &["cmdline", "--set", "A", "--clear"],
                &["cmdline", "--set", "A"],
            ),
            (&["drop"], &["drop", "a"]),
            (&["sync"], &["sync", "a"]),
            (&["sync", "a", "b", "--all"], &["sync", "a", "b"]),
            (&["wipe"], &["wipe", "/dev/sdz"]),
            (&["restore"], &["restore", "a/ROOT/be@s", "/dev/sdz"]),
            (
                &["restore", "a/ROOT/be@s"],
                &["restore", "a/ROOT/be@s", "/dev/sdz"],
            ),
            (&["fork", "a", "b"], &["fork", "a@x", "b"]),
            (&["fork", "@x"], &["fork", "@x", "b"]),
            (&["resume", "--abandon"], &["abandon"]),
            (
                &["pair", "a", "b", "--primary", "left"],
                &["pair", "a", "b"],
            ),
            (&["default", "--dry-run"], &["default", "a", "--dry-run"]),
            (
                &["default", "--confirm", "t"],
                &["default", "a", "--confirm", "t"],
            ),
            (
                &["cmdline", "--dry-run"],
                &["cmdline", "--set", "quiet", "--dry-run"],
            ),
            (
                &["cmdline", "a", "--confirm", "t"],
                &["cmdline", "a", "--clear", "--confirm", "t"],
            ),
        ];
        for (invalid, valid) in cases {
            let error = parse(invalid)
                .err()
                .unwrap_or_else(|| panic!("accepted {invalid:?}"));
            assert_eq!(error.exit_code(), 2, "{invalid:?}: {error}");
            assert!(parse(valid).is_ok(), "valid neighbor {valid:?}");
        }
        assert!(parse(&["restore", "--keep", "x", "SRC", "DISK"]).is_ok());
        assert!(parse(&["snapshot", "a", "b@x"]).is_ok());
        assert!(parse(&["snapshot", "a@x", "b@y"]).is_ok());
        assert!(parse(&["snapshot", "@x"]).is_ok());
    }

    fn changing_forms() -> Vec<Vec<&'static str>> {
        vec![
            vec!["snapshot"],
            vec!["fork", "next"],
            vec!["default", "a"],
            vec!["cmdline", "a", "--set", "quiet"],
            vec!["cmdline", "a", "--clear"],
            vec!["rename", "a", "b"],
            vec!["rollback", "a@x"],
            vec!["drop", "a"],
            vec!["pair", "a", "b"],
            vec!["sync", "a"],
            vec!["sync", "a", "b"],
            vec!["sync", "--all"],
            vec!["primary", "a"],
            vec!["unpair", "a"],
            vec!["deploy", "/dev/sdz", "--empty"],
            vec!["esp", "/dev/sdz1"],
            vec!["wipe", "/dev/sdz"],
            vec!["restore", "a@x", "/dev/sdz"],
            vec!["resume"],
            vec!["abandon"],
        ]
    }

    #[test]
    fn every_changing_verb_takes_dry_run_and_confirm() {
        for args in changing_forms() {
            for flags in [&["--dry-run"][..], &["--confirm", "token"]] {
                let command = [args.as_slice(), flags].concat();
                assert!(parse(&command).is_ok(), "{command:?}");
            }
            let conflicting = [args.as_slice(), &["--dry-run", "--confirm", "token"]].concat();
            assert_eq!(
                parse(&conflicting).err().unwrap().exit_code(),
                2,
                "{conflicting:?}"
            );
        }
        for args in [
            &["factory", "/root.tar", "--dry-run"][..],
            &["chroot", "a", "--dry-run"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn command_definitions_and_help_are_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        super::super::help::command().debug_assert();
        let mut command = super::super::help::command();
        let help = command
            .find_subcommand_mut("rollback")
            .unwrap()
            .render_help()
            .to_string();
        assert!(help.contains("<DATASET@SNAP>"), "{help}");
        let help = command
            .find_subcommand_mut("pair")
            .unwrap()
            .render_help()
            .to_string();
        assert!(help.contains("<PRIMARY> <SECONDARY>"), "{help}");
        assert!(!help.contains("--primary"), "{help}");
        let help = command
            .find_subcommand_mut("factory")
            .unwrap()
            .render_help()
            .to_string();
        assert!(help.contains("<TAR>"), "{help}");
        assert!(!help.contains("--zboot-bin"), "{help}");
    }

    #[test]
    fn version_flag_uses_assembled_source_identity() {
        let error = parse(&["--version"]).err().unwrap();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(
            error.to_string(),
            format!("zboot {}\n", crate::build_identity::VERSION)
        );
    }

    #[test]
    fn restore_and_resume_parse() {
        let cli = parse(&[
            "restore",
            "b/ROOT/be@s",
            "/dev/sdz",
            "--keep",
            "a/home",
            "--keep",
            "a/srv",
            "--esp",
            "512M",
            "--swap",
            "0",
            "--dry-run",
        ])
        .unwrap();
        let Verb::Restore {
            keep,
            esp,
            swap,
            dry_run,
            ..
        } = cli.command
        else {
            panic!("restore fixture")
        };
        assert_eq!(keep, ["a/home", "a/srv"]);
        assert_eq!((esp, swap, dry_run), (Some(512 << 20), Some(0), true));
        assert!(parse_size("1G").is_ok_and(|n| n == 1 << 30));
        assert!(parse_size("1.5G").is_err());
        assert!(parse(&["resume", "--dry-run"]).is_ok());
        assert!(parse(&["abandon", "--confirm", "t"]).is_ok());
    }

    #[test]
    fn factory_takes_its_cli_md_forms() {
        assert!(
            parse(&[
                "factory",
                "/root.tar.zst",
                "--suite",
                "trixie",
                "--mirror",
                "http://m/debian",
                "--snapshot",
                "20261108T022935Z",
                "--packages",
                "openssh-server,vim",
                "--zfs-from-suite",
                "sid",
                "--json"
            ])
            .is_ok()
        );
        assert!(parse(&["factory"]).is_err());
        assert!(parse(&["factory-finish", "/root", "/stage"]).is_ok());
        assert!(parse(&["factory-finish", "/root"]).is_err());
    }

    #[test]
    fn deploy_image_portable_and_ordered_overlays_are_six_a_forms() {
        for args in [
            vec!["deploy", "--image", "/new.img", "--empty"],
            vec![
                "deploy",
                "--image",
                "/new.img",
                "--size",
                "8G",
                "--tar",
                "/root.tar",
                "--portable",
                "--overlay",
                "builtin:rescue",
                "--overlay",
                "/access",
            ],
            vec!["deploy", "/dev/sdz", "--tar", "/root.tar", "--portable"],
        ] {
            assert!(parse(&args).is_ok(), "{args:?}");
        }
        for args in [
            vec!["deploy", "--empty"],
            vec!["deploy", "/dev/sdz", "--image", "/new.img", "--empty"],
            vec!["deploy", "/dev/sdz", "--empty", "--size", "8G"],
            vec![
                "deploy",
                "--image",
                "/new.img",
                "--empty",
                "--esp-partition",
                "/dev/sda1",
            ],
            vec!["deploy", "/dev/sdz", "--empty", "--portable"],
            vec![
                "deploy",
                "/dev/sdz",
                "--tar",
                "/root.tar",
                "--portable",
                "--hostid",
                "01020304",
            ],
            vec![
                "deploy",
                "/dev/sdz",
                "--tar",
                "/root.tar",
                "--portable",
                "--swap",
                "0",
            ],
            vec![
                "deploy",
                "/dev/sdz",
                "--tar",
                "/root.tar",
                "--portable",
                "--esp-partition",
                "/dev/sda1",
            ],
            vec![
                "deploy",
                "/dev/sdz",
                "--tar",
                "/root.tar",
                "--overlay",
                "builtin:unknown",
            ],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
        let Verb::Deploy { overlay, .. } = parse(&[
            "deploy",
            "/dev/sdz",
            "--tar",
            "/root.tar",
            "--overlay",
            "/first",
            "--overlay",
            "/second",
        ])
        .unwrap()
        .command
        else {
            panic!("deploy");
        };
        assert_eq!(
            overlay,
            [
                std::path::PathBuf::from("/first"),
                std::path::PathBuf::from("/second")
            ]
        );
    }

    #[test]
    fn deploy_esp_and_status_take_their_current_forms() {
        for tail in [
            vec!["--tar", "/root.tar"],
            vec!["--empty"],
            vec![
                "--tar",
                "/root.tar",
                "--overlay",
                "/host",
                "--hostname",
                "box",
                "--efi",
                "/boot.efi",
            ],
            vec!["--empty", "--esp-partition", "/dev/sda1", "--confirm", "t"],
        ] {
            let args = [&["deploy", "/dev/sdz"][..], tail.as_slice()].concat();
            assert!(parse(&args).is_ok(), "{args:?}");
        }
        for tail in [
            vec![],
            vec!["--empty", "--tar", "/root.tar"],
            vec!["--empty", "--be", "os"],
            vec!["--empty", "--overlay", "/host"],
            vec!["--tar", "/root.tar", "--hostid", "00000000"],
            vec!["--tar", "/root.tar", "--hostid", "0A0B0C0D"],
            vec!["--empty", "--esp", "1G", "--esp-partition", "/dev/sda1"],
        ] {
            let args = [&["deploy", "/dev/sdz"][..], tail.as_slice()].concat();
            assert!(parse(&args).is_err(), "{args:?}");
        }
        assert!(parse(&["status", "--all", "--snapshots", "--devices", "--json"]).is_ok());
    }

    #[test]
    fn esp_uses_one_batch_with_optional_explicit_partitions_and_one_efi_file() {
        for args in [
            &["esp"][..],
            &["esp", "--efi", "/new.efi"],
            &["esp", "/dev/a1", "/dev/b1", "--dry-run"],
        ] {
            assert!(parse(args).is_ok(), "{args:?}");
        }
        for args in [
            &["esp", "install", "/dev/a1"][..],
            &["esp", "/dev/a1", "--uki", "/old.efi"],
            &["esp", "--dry-run", "--confirm", "token"],
        ] {
            assert_eq!(parse(args).unwrap_err().exit_code(), 2, "{args:?}");
        }
    }

    #[test]
    fn source_less_and_explicit_fork_positions_are_distinct() {
        for args in [
            &["fork", "next"][..],
            &["fork", "next", "--dry-run"],
            &["fork", "--confirm", "t", "next"],
        ] {
            let Verb::Fork {
                snapshot,
                destination,
                ..
            } = parse(args).unwrap().command
            else {
                panic!("fork fixture")
            };
            assert!(snapshot.is_none(), "{args:?}");
            assert_eq!(destination, "next");
        }
        for source in ["@base", "a/tree@base"] {
            let Verb::Fork {
                snapshot,
                destination,
                ..
            } = parse(&["fork", source, "next"]).unwrap().command
            else {
                panic!("fork fixture")
            };
            assert_eq!(snapshot.as_deref(), Some(source));
            assert_eq!(destination, "next");
        }
    }

    // Expand the synopsis notation itself, including nested optional pieces,
    // choices and up to two repetitions, before substituting concrete values.
    fn expand(expression: &str) -> Vec<String> {
        let mut depth = 0;
        let mut alternatives = Vec::new();
        let mut start = 0;
        for (at, ch) in expression.char_indices() {
            match ch {
                '[' | '(' => depth += 1,
                ']' | ')' => depth -= 1,
                '|' if depth == 0 => {
                    alternatives.extend(expand(&expression[start..at]));
                    start = at + 1;
                }
                _ => {}
            }
        }
        if start != 0 {
            alternatives.extend(expand(&expression[start..]));
            return alternatives;
        }
        let Some((at, open)) = expression
            .char_indices()
            .find(|(_, ch)| matches!(ch, '[' | '('))
        else {
            return vec![expression.into()];
        };
        let close = if open == '[' { ']' } else { ')' };
        let mut nesting = 0;
        let end = expression[at..]
            .char_indices()
            .find_map(|(offset, ch)| {
                if ch == open {
                    nesting += 1;
                }
                if ch == close {
                    nesting -= 1;
                    if nesting == 0 {
                        return Some(at + offset);
                    }
                }
                None
            })
            .expect("balanced synopsis group");
        let mut middle = expand(&expression[at + 1..end]);
        if open == '[' {
            middle.push(String::new());
        }
        let mut suffix = &expression[end + 1..];
        if let Some(after) = suffix.strip_prefix("...") {
            let nonempty: Vec<_> = middle
                .iter()
                .filter(|part| !part.trim().is_empty())
                .cloned()
                .collect();
            for first in &nonempty {
                for second in &nonempty {
                    middle.push(format!("{first} {second}"));
                }
            }
            suffix = after;
        }
        let tails = expand(suffix);
        let mut expanded = Vec::new();
        for middle in middle {
            for tail in &tails {
                expanded.push(format!("{}{middle}{tail}", &expression[..at]));
            }
        }
        expanded
    }

    fn synopses() -> Vec<String> {
        let mut fenced = None;
        let mut current = String::new();
        let mut result = Vec::new();
        for line in include_str!("../../../../docs/CLI.md").lines() {
            if line.starts_with("```") {
                if fenced.take().is_some() {
                    if !current.is_empty() {
                        result.push(std::mem::take(&mut current));
                    }
                } else {
                    fenced = Some(line == "```");
                }
                continue;
            }
            if fenced != Some(true) {
                continue;
            }
            let mut line = line.split('†').next().unwrap();
            for note in [
                "on a running system",
                "in the zboot UKI",
                "the UKI's own start-up",
            ] {
                line = line.split(note).next().unwrap();
            }
            let line = line.trim();
            if line.starts_with("zboot ") {
                if !current.is_empty() {
                    result.push(std::mem::take(&mut current));
                }
                current = line.into();
            } else if !current.is_empty() && !line.is_empty() {
                current.push(' ');
                current.push_str(line);
            }
        }
        result
    }

    fn concrete(expression: &str) -> Vec<String> {
        let mut expression = expression.to_owned();
        for (placeholder, value) in [
            ("SECONDARY", "b/tree"),
            ("PRIMARY", "a/tree"),
            ("DATASET", "a/tree"),
            ("SOURCE", "b/ROOT/be@base"),
            ("TARGET", "a/tree"),
            ("COMMAND", "/bin/true"),
            ("HOSTID", "0a0b0c0d"),
            ("DISK", "/dev/sdz"),
            ("DEST", "a/new"),
            ("SNAP", "base"),
            ("NAME", "example"),
            ("FILE", "/input/file"),
            ("ARGS", "quiet"),
            ("SIZE", "512M"),
            ("TIME", "20261108T022935Z"),
            ("SUITE", "sid"),
            ("URL", "https://deb.example"),
            ("TAR", "/root.tar.zst"),
            ("PKG", "openssh-server"),
            ("POOL", "targetpool"),
            ("PART", "/dev/sdz1"),
            ("OVERLAY", "/overlay"),
            ("BE", "a/ROOT/be"),
            ("SRC", "a/tree"),
            ("ID", "00112233445566778899aabbccddeeff"),
        ] {
            expression = expression.replace(placeholder, value);
        }
        expression.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn deploy_into_uses_only_its_documented_options() {
        let cli = parse(&[
            "deploy",
            "--into",
            "pool",
            "--tar",
            "/root.tar",
            "--be",
            "new",
            "--hostname",
            "host",
            "--overlay",
            "/one",
            "--overlay",
            "/two",
            "--dry-run",
            "--json",
        ])
        .unwrap();
        assert!(matches!(cli.command, Verb::Deploy { into: Some(ref pool), .. } if pool == "pool"));
        for extra in [
            vec!["/dev/sdz"],
            vec!["--image", "/new.raw"],
            vec!["--empty"],
            vec!["--portable"],
            vec!["--pool", "other"],
            vec!["--hostid", "01020304"],
            vec!["--efi", "/boot.efi"],
            vec!["--esp", "1G"],
            vec!["--esp-partition", "/dev/sda1"],
            vec!["--swap", "1G"],
            vec!["--size", "4G"],
        ] {
            let mut args = vec!["deploy", "--into", "pool", "--tar", "/root.tar"];
            args.extend(extra);
            assert!(parse(&args).is_err(), "{args:?}");
        }
        assert!(parse(&["deploy", "--into", "pool"]).is_err());
    }

    fn deploy_option_table() -> Vec<(String, [bool; 5])> {
        let mut rows = include_str!("../../../../docs/CLI.md")
            .lines()
            .skip_while(|line| {
                !line.starts_with("| Option | Default | `DISK` | `--image` | `--into` |")
            });
        assert!(
            rows.next().is_some(),
            "the documented deploy option table exists"
        );
        rows.next().expect("table separator");
        let mut rules = Vec::new();
        for row in rows.take_while(|line| line.starts_with('|')) {
            let cells: Vec<_> = row.trim_matches('|').split('|').map(str::trim).collect();
            assert_eq!(cells.len(), 7, "{row}");
            let allowed = std::array::from_fn(|index| cells[index + 2] != "-");
            for option in cells[0].split('`').skip(1).step_by(2) {
                let flag = option.split_whitespace().next().unwrap();
                assert!(flag.starts_with("--"), "{row}");
                rules.push((flag.to_owned(), allowed));
            }
        }
        assert_eq!(rules.len(), 12, "every documented option has a rule");
        rules
    }

    fn documented_deploy_combination(args: &[String], rules: &[(String, [bool; 5])]) -> bool {
        if args.get(1).is_none_or(|verb| verb != "deploy") {
            return true;
        }
        let has = |flag: &str| args.iter().any(|arg| arg == flag);
        let target = if has("--into") {
            2
        } else {
            usize::from(has("--image"))
        };
        rules.iter().all(|(flag, allowed)| {
            !has(flag)
                || (allowed[target]
                    && (!has("--portable") || allowed[3])
                    && (!has("--empty") || allowed[4]))
        })
    }

    #[test]
    fn every_cli_md_synopsis_parses() {
        let mut parsed_synopses = 0;
        let mut parsed_lines = 0;
        let deploy_rules = deploy_option_table();
        let mut refused_deploy_combinations = 0;
        let mut delivered_deploy_forms = std::collections::BTreeSet::new();
        let mut delivered_deploy_options = std::collections::BTreeSet::new();
        let mut delivered_disk_tar = false;
        let mut delivered_disk_empty = false;
        for synopsis in synopses() {
            if synopsis.starts_with("zboot VERB ") {
                continue;
            }
            let synopsis = synopsis
                .replace("PKG,...", "PKG")
                .replace("DATASET...", "(DATASET)...")
                .replace("TARGET...", "(TARGET)...")
                .replace("COMMAND...", "(COMMAND)...")
                .replace("PART...", "(PART)...")
                .replace("FILE|-", "(FILE|-)");
            let mut parsed_this_synopsis = false;
            for expanded in expand(&synopsis) {
                let args = concrete(&expanded);
                // The prose requires a dataset on every target in a multi-
                // target snapshot. A lone @NAME is its single-target form.
                if args.get(1).is_some_and(|verb| verb == "snapshot")
                    && args.len() > 3
                    && args[2..].iter().any(|arg| arg.starts_with('@'))
                {
                    continue;
                }
                // The consolidated synopsis shares an option tail. The table
                // supplies the documented target/content restrictions.
                if !documented_deploy_combination(&args, &deploy_rules) {
                    assert!(
                        Cli::parse_from_args(args.iter().map(String::as_str)).is_err(),
                        "documented invalid combination must refuse: {args:?}"
                    );
                    refused_deploy_combinations += 1;
                    continue;
                }
                let refs: Vec<_> = args.iter().map(String::as_str).collect();
                assert!(
                    Cli::parse_from_args(refs.iter().copied()).is_ok(),
                    "{synopsis}\n  {refs:?}"
                );
                if args.get(1).is_some_and(|verb| verb == "deploy") {
                    let has = |flag: &str| args.iter().any(|arg| arg == flag);
                    let form = match (has("--into"), has("--image"), has("--empty")) {
                        (true, _, _) => "into-tar",
                        (_, true, true) => "image-empty",
                        (_, true, false) => "image-tar",
                        (_, _, true) => "disk-empty",
                        _ => "disk-tar",
                    };
                    delivered_deploy_forms.insert(form);
                    if has("--portable") {
                        delivered_deploy_forms.insert("portable-tar");
                    }
                }
                if args.get(1).is_some_and(|verb| verb == "deploy")
                    && args.get(2).is_some_and(|target| target == "/dev/sdz")
                {
                    delivered_disk_tar |= args.iter().any(|arg| arg == "--tar");
                    delivered_disk_empty |= args.iter().any(|arg| arg == "--empty");
                    delivered_deploy_options
                        .extend(args.iter().filter(|arg| arg.starts_with("--")).cloned());
                }
                parsed_this_synopsis = true;
                parsed_lines += 1;
            }
            parsed_synopses += usize::from(parsed_this_synopsis);
        }
        assert!(refused_deploy_combinations > 0);
        for form in [
            "disk-tar",
            "disk-empty",
            "image-tar",
            "image-empty",
            "into-tar",
            "portable-tar",
        ] {
            assert!(
                delivered_deploy_forms.contains(form),
                "documented {form} parses"
            );
        }
        assert!(
            delivered_disk_tar && delivered_disk_empty,
            "both delivered DISK forms parse"
        );
        for flag in [
            "--tar",
            "--empty",
            "--efi",
            "--overlay",
            "--be",
            "--hostname",
            "--pool",
            "--hostid",
            "--esp",
            "--esp-partition",
            "--swap",
        ] {
            assert!(
                delivered_deploy_options.contains(flag),
                "delivered DISK option {flag} parses"
            );
        }
        assert!(parsed_synopses >= 20, "{parsed_synopses} synopses");
        assert!(parsed_lines >= 100, "{parsed_lines} concrete lines");
    }
}
