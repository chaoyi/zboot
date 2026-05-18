//! `Plan` — the deploy operation list rendered before execution.

use anyhow::{Context, Result, bail};

use super::DeployArgs;
use super::esp::partition_number;
use super::source::{
    DEBOOTSTRAP_COMPONENTS, DEBOOTSTRAP_PACKAGES, DEFAULT_DEBOOTSTRAP_MIRROR, Source,
};

/// What populates the BE on the new pool. Mutually exclusive at the CLI
/// level (`--source` xor `--mirror-from` xor `--empty`).
#[derive(Debug, Clone)]
pub(super) enum Mode {
    /// Bootstrap a fresh BE from a tar / debootstrap source.
    Source(Source),
    /// Replicate BEs from an existing root pool via `zboot mirror`.
    MirrorFrom(String),
    /// No BE — pool + ROOT container only.
    Empty,
}

#[derive(Debug)]
pub(super) struct Plan {
    /// The single target disk.
    pub(super) disk: String,
    /// Disk basename — what the typed-target confirmation expects.
    pub(super) target_basename: String,
    /// What `zpool create rpool <X>` is invoked with: the whole disk
    /// (when `no_efi`) or the root partition (otherwise).
    pub(super) pool_partition: String,
    /// ESP partition path. `None` when `--no-efi` strips the ESP.
    pub(super) esp_partition: Option<String>,
    pub(super) pool: String,
    pub(super) be_dataset: String,
    pub(super) be_mountpoint: String,
    pub(super) hostname: String,
    pub(super) hostid_hex: String,
    pub(super) mode: Mode,
    pub(super) cmdline: Option<String>,
}

impl Plan {
    pub(super) fn compose(args: &DeployArgs) -> Result<Self> {
        let disk = args
            .target
            .as_deref()
            .context("--target /dev/X is required")?;
        let target_basename = basename_of(disk)?;

        let (pool_partition, esp_partition) = if args.no_efi {
            (disk.to_owned(), None)
        } else {
            (partition_path(disk, 2), Some(partition_path(disk, 1)))
        };

        let mode = resolve_mode(args)?;
        let hostid_hex = hostid_from_hostname(&args.hostname);

        Ok(Plan {
            disk: disk.to_owned(),
            target_basename,
            pool_partition,
            esp_partition,
            pool: args.pool.clone(),
            be_dataset: format!("{}/ROOT/{}", args.pool, args.be),
            be_mountpoint: "/".to_owned(),
            hostname: args.hostname.clone(),
            hostid_hex,
            mode,
            cmdline: args.cmdline.clone(),
        })
    }

    /// The disk to run `ensure_disk_empty` against — the only one we wipe.
    pub(super) fn pool_disk_for_preflight(&self) -> &str {
        &self.disk
    }

    /// True when this layout has an ESP and writes a bootloader.
    pub(super) fn has_esp(&self) -> bool {
        self.esp_partition.is_some()
    }

    /// True when the plan installs/populates a BE dataset. `--empty` flips
    /// this off; the pool ends at `<pool>/ROOT`.
    pub(super) fn installs_be(&self) -> bool {
        !matches!(self.mode, Mode::Empty)
    }
}

/// Decide which mode the args resolve to. Mutex enforcement:
/// `--empty` mutex with `--source` / `--mirror-from` / `--cmdline`,
/// `--source` mutex with `--mirror-from` (handled by clap too).
fn resolve_mode(args: &DeployArgs) -> Result<Mode> {
    if args.empty {
        if args.source.is_some() {
            bail!("--empty is incompatible with --source");
        }
        if args.mirror_from.is_some() {
            bail!("--empty is incompatible with --mirror-from");
        }
        if args.cmdline.is_some() {
            bail!("--empty is incompatible with --cmdline (no BE to apply it to)");
        }
        return Ok(Mode::Empty);
    }
    if let Some(src_pool) = &args.mirror_from {
        return Ok(Mode::MirrorFrom(src_pool.clone()));
    }
    let url = args
        .source
        .clone()
        .unwrap_or_else(|| format!("debootstrap://{}", args.suite));
    Ok(Mode::Source(Source::parse(&url)?))
}

pub(super) fn basename_of(disk: &str) -> Result<String> {
    std::path::Path::new(disk)
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
        .with_context(|| format!("disk {disk:?} has no basename"))
}

/// `hostid = sha256(hostname)[:4]`, rendered as 8-hex. The raw 4 bytes
/// (written to `/etc/hostid`) are this hex value little-endian.
fn hostid_from_hostname(hostname: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(hostname.as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

/// Compose a partition path. `NVMe` and loop devices (whose name ends in
/// a digit) need a `p` separator: `/dev/nvme0n1` → `/dev/nvme0n1p1`.
/// SATA/virtio (`/dev/sda`, `/dev/vda`) get the partition number
/// concatenated directly: `/dev/vda` → `/dev/vda1`.
pub(crate) fn partition_path(disk: &str, n: u8) -> String {
    let needs_p = disk.chars().last().is_some_and(|c| c.is_ascii_digit());
    if needs_p {
        format!("{disk}p{n}")
    } else {
        format!("{disk}{n}")
    }
}

impl std::fmt::Display for Plan {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "zboot deploy — plan")?;
        writeln!(
            f,
            "================================================================"
        )?;
        let layout_label = if self.has_esp() {
            "partition ESP+root"
        } else {
            "whole-disk pool (--no-efi)"
        };
        writeln!(f, "  target         : {} ({layout_label})", self.disk)?;
        writeln!(f, "  hostname       : {}", self.hostname)?;
        writeln!(f, "  hostid (hex)   : {}", self.hostid_hex)?;
        writeln!(f, "  pool           : {}", self.pool)?;
        match &self.mode {
            Mode::Source(src) => {
                writeln!(
                    f,
                    "  BE dataset     : {} (mountpoint {})",
                    self.be_dataset, self.be_mountpoint
                )?;
                writeln!(f, "  source         : {}", src.render())?;
            }
            Mode::MirrorFrom(src_pool) => {
                writeln!(
                    f,
                    "  populate via   : zboot mirror --to {} (from {src_pool})",
                    self.pool
                )?;
            }
            Mode::Empty => {
                writeln!(f, "  BE             : <none — --empty>")?;
            }
        }
        if let Some(c) = &self.cmdline {
            writeln!(f, "  cmdline (ROOT) : {c}")?;
        }
        writeln!(
            f,
            "----------------------------------------------------------------"
        )?;
        writeln!(f, "  operations (in order):")?;

        let mut step = 1u8;
        if self.has_esp() {
            writeln!(
                f,
                "    {step}. wipefs -a {disk} ; sfdisk {disk} (GPT: ESP 512MiB + root)",
                disk = self.disk
            )?;
        } else {
            writeln!(
                f,
                "    {step}. wipefs -a {disk} (whole-disk pool — no partitioning)",
                disk = self.disk
            )?;
        }
        step += 1;
        writeln!(
            f,
            "    {step}. write 4 raw hostid bytes to /etc/hostid (host side)"
        )?;
        step += 1;
        writeln!(f, "    {step}. zpool create -o ashift=12 -o cachefile=none \\")?;
        writeln!(f, "         -o compatibility=openzfs-2.1-linux \\")?;
        writeln!(
            f,
            "         -O canmount=off -O mountpoint=none -O compression=zstd \\"
        )?;
        writeln!(f, "         -O xattr=sa -O acltype=posixacl \\")?;
        writeln!(f, "         {} {}", self.pool, self.pool_partition)?;
        step += 1;
        writeln!(f, "    {step}. zpool set zboot:role=root {}", self.pool)?;
        step += 1;
        writeln!(
            f,
            "    {step}. zfs create -o canmount=off -o mountpoint=none {}/ROOT",
            self.pool
        )?;
        step += 1;

        match &self.mode {
            Mode::MirrorFrom(src_pool) => {
                writeln!(
                    f,
                    "    {step}. zboot mirror --to {} (replicates BEs from {src_pool})",
                    self.pool
                )?;
                step += 1;
            }
            Mode::Source(src) => {
                writeln!(
                    f,
                    "    {step}. zfs create -o canmount=noauto -o mountpoint=/ {}",
                    self.be_dataset
                )?;
                step += 1;
                writeln!(f, "    {step}. zfs set zboot:be=true {}", self.be_dataset)?;
                step += 1;
                writeln!(
                    f,
                    "    {step}. mount {} → temp dir; populate from source",
                    self.be_dataset
                )?;
                match src {
                    Source::Tar { path } => {
                        writeln!(f, "         tar: zstd -dc {path} | tar -xf - -C <be>")?;
                    }
                    Source::Debootstrap { suite, mirror } => {
                        let m = mirror.as_deref().unwrap_or(DEFAULT_DEBOOTSTRAP_MIRROR);
                        writeln!(
                            f,
                            "         debootstrap --variant=minbase --components={DEBOOTSTRAP_COMPONENTS} \\",
                        )?;
                        writeln!(f, "                     {suite} <be> {m}")?;
                        writeln!(
                            f,
                            "         + chroot apt install {} (DKMS builds zfs.ko)",
                            DEBOOTSTRAP_PACKAGES.replace(',', " "),
                        )?;
                    }
                }
                step += 1;
                writeln!(f, "    {step}. write hostid + /etc/hostname inside BE")?;
                step += 1;
                if self.cmdline.is_some() {
                    writeln!(
                        f,
                        "    {step}. zfs set zboot:kernel-cmdline=\"...\" {}/ROOT",
                        self.pool
                    )?;
                    step += 1;
                }
            }
            Mode::Empty => {
                // ROOT container alone — no BE, no populate, no identity, no bootfs.
            }
        }

        if let Some(esp) = &self.esp_partition {
            writeln!(
                f,
                "    {step}. install zboot-boot.efi to {esp} (mount ESP, copy bundle)"
            )?;
            step += 1;
            writeln!(
                f,
                "    {step}. efibootmgr --create --disk {} --part {} \\",
                self.disk,
                partition_number(esp),
            )?;
            writeln!(
                f,
                "         --label \"zboot-boot\" --loader '\\EFI\\zboot-boot\\zboot-boot.efi'"
            )?;
            step += 1;
        } else {
            writeln!(
                f,
                "    -. ESP/bootloader skipped (--no-efi — recover via another disk's bootloader)"
            )?;
        }

        if self.installs_be() {
            writeln!(
                f,
                "    {step}. zpool set bootfs={} {}",
                self.be_dataset, self.pool
            )?;
        } else {
            writeln!(f, "    -. bootfs left unset (--empty — set manually after BE attach)")?;
        }
        writeln!(
            f,
            "================================================================"
        )?;
        Ok(())
    }
}
