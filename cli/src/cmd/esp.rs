//! `zboot esp` — install `zboot-boot.efi` onto an ESP on a separate disk
//! and register an `efibootmgr` entry.
//!
//! Pairs with `zboot deploy --target X --no-efi` for the "pool on this
//! disk, EFI on that disk" topology (USB stick / SD card / small SSD).
//! The loader is pool-agnostic — it scans for `zboot:role=root` pools at
//! boot time and reads each one's `bootfs` — so no `--pool` argument is
//! needed.
//!
//! `--target` is disk-smart:
//!
//! | target shape           | content       | action                            |
//! | ---------------------- | ------------- | --------------------------------- |
//! | whole disk (`/dev/sdb`)| empty         | partition (512MiB ESP) + format + write |
//! | whole disk             | non-empty     | reject; `--replace` repartitions  |
//! | partition (`/dev/sdb1`)| FAT32         | write (idempotent re-runs cheap)  |
//! | partition              | other FS      | reject; `--replace` reformats     |
//! | partition              | empty         | format as FAT32 + write           |
//!
//! `--replace` requires the same typed-target confirmation as `deploy`.

use std::io::{BufRead, Write};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::cmd::deploy::esp::{
    install_efi_to_esp, mount_esp, partition_number, register_efi, resolve_efi_bundle,
};
use crate::cmd::deploy::{spawn, unmount_be};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct EspArgs {
    /// Target device: either a whole disk (`/dev/sdb`) — gets
    /// partitioned with a single 512MiB ESP — or an existing partition
    /// (`/dev/sdb1`) — written to directly.
    #[arg(long)]
    pub target: String,

    /// NVRAM entry label. Default `zboot-boot`.
    #[arg(long, default_value = "zboot-boot")]
    pub label: String,

    /// Overwrite non-empty target. Without this, the run refuses on:
    /// (a) whole disks carrying any partition/signature; (b) partitions
    /// with a filesystem other than FAT32. Requires typed-target
    /// confirmation (same as `deploy`'s wipe protection).
    #[arg(long)]
    pub replace: bool,

    /// Print the plan and exit 0. No disk writes.
    #[arg(long)]
    pub check: bool,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

pub fn run(args: &EspArgs, w: &mut impl Write) -> Result<()> {
    let stdin = std::io::stdin();
    let mut locked = stdin.lock();
    run_inner(args, &mut locked, w)
}

fn run_inner<R: BufRead, W: Write>(args: &EspArgs, stdin: &mut R, out: &mut W) -> Result<()> {
    let plan = Plan::probe(&args.target)?;
    writeln!(out, "{}", plan.render(&args.label, args.replace))
        .context("write esp plan")?;

    if args.check {
        return Ok(());
    }

    // Refuse if the target needs overwriting and the operator hasn't
    // opted in. Typed confirmation is symmetric with deploy: wiping an
    // EFI partition (or carving a new partition table over data) is the
    // same scale of destructive as wiping a root disk.
    if plan.needs_replace() {
        if !args.replace {
            bail!(
                "target {} is not empty/FAT32 — pass --replace to overwrite. \
                 (signatures: {})",
                args.target,
                plan.existing_signatures(),
            );
        }
        let env_bypass = std::env::var("ZBOOT_ESP_CONFIRM_TARGET").ok();
        confirm_target(
            &basename_of(&args.target)?,
            env_bypass.as_deref(),
            stdin,
            out,
        )?;
    }

    execute(&plan, &args.label, out)
}

// ---------------------------------------------------------------------------
// Plan probing — read-only inspection of the target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Whole disk (`disk` per `lsblk -no TYPE`).
    WholeDisk,
    /// Single partition (`part`).
    Partition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Content {
    /// Empty: no `lsblk` children, no `wipefs` signature.
    Empty,
    /// FAT32 (vfat) — idempotent re-write target.
    Fat32,
    /// Any other state — partitions on a disk, non-FAT32 fs on a
    /// partition, etc. Carries the signatures string for the error msg.
    Other(String),
}

#[derive(Debug)]
struct Plan {
    target: String,
    shape: Shape,
    content: Content,
    /// For partition targets: the parent disk (e.g. `/dev/sdb`). Used
    /// for efibootmgr's `--disk` argument.
    parent_disk: Option<String>,
    /// For partition targets: the partition number (1, 2, ...). Used
    /// for efibootmgr's `--part` argument.
    part_number: Option<u8>,
}

impl Plan {
    fn probe(target: &str) -> Result<Self> {
        let shape = detect_shape(target)?;
        let content = detect_content(target, shape)?;
        let (parent_disk, part_number) = match shape {
            Shape::WholeDisk => (None, None),
            Shape::Partition => {
                let pk = lsblk_pkname(target)?;
                let disk = if pk.starts_with("/dev/") {
                    pk.clone()
                } else {
                    format!("/dev/{pk}")
                };
                (Some(disk), Some(partition_number(target)))
            }
        };
        Ok(Plan {
            target: target.to_owned(),
            shape,
            content,
            parent_disk,
            part_number,
        })
    }

    fn needs_replace(&self) -> bool {
        !matches!(
            (self.shape, &self.content),
            (Shape::WholeDisk, Content::Empty)
                | (Shape::Partition, Content::Empty | Content::Fat32)
        )
    }

    /// True iff the ESP partition needs `mkfs.vfat`. Skip for an
    /// already-FAT32 partition so re-runs preserve existing `\EFI\`
    /// entries and stay cheap.
    fn needs_mkfs(&self) -> bool {
        !matches!(
            (self.shape, &self.content),
            (Shape::Partition, Content::Fat32)
        )
    }

    fn existing_signatures(&self) -> String {
        match &self.content {
            Content::Empty => "<empty>".to_owned(),
            Content::Fat32 => "vfat".to_owned(),
            Content::Other(s) => s.clone(),
        }
    }

    /// The effective ESP partition to write the bundle into. For whole-disk
    /// targets, that's the partition we'll create at step 1; for partition
    /// targets it's the target itself.
    fn esp_partition(&self) -> String {
        match self.shape {
            Shape::WholeDisk => crate::cmd::deploy::plan::partition_path(&self.target, 1),
            Shape::Partition => self.target.clone(),
        }
    }

    /// efibootmgr's `--disk` argument.
    fn efibootmgr_disk(&self) -> String {
        match self.shape {
            Shape::WholeDisk => self.target.clone(),
            Shape::Partition => self
                .parent_disk
                .clone()
                .unwrap_or_else(|| self.target.clone()),
        }
    }

    /// efibootmgr's `--part` number.
    fn efibootmgr_part(&self) -> u8 {
        match self.shape {
            Shape::WholeDisk => 1,
            Shape::Partition => self.part_number.unwrap_or(1),
        }
    }

    fn render(&self, label: &str, replace: bool) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "zboot esp — plan");
        let _ = writeln!(
            s,
            "================================================================"
        );
        let _ = writeln!(s, "  target         : {}", self.target);
        let _ = writeln!(
            s,
            "  shape          : {}",
            match self.shape {
                Shape::WholeDisk => "whole disk",
                Shape::Partition => "partition",
            }
        );
        let _ = writeln!(
            s,
            "  content        : {}",
            self.existing_signatures()
        );
        let _ = writeln!(s, "  label          : {label}");
        if self.needs_replace() {
            let _ = writeln!(
                s,
                "  replace        : {}",
                if replace { "yes (--replace given)" } else { "REQUIRED but not given" }
            );
        }
        let _ = writeln!(
            s,
            "----------------------------------------------------------------"
        );
        let _ = writeln!(s, "  operations (in order):");
        let mut n = 1u8;
        if self.shape == Shape::WholeDisk {
            let _ = writeln!(
                s,
                "    {n}. wipefs -a {} ; sfdisk {} (GPT: 512MiB ESP)",
                self.target, self.target,
            );
            n += 1;
        }
        if self.needs_mkfs() {
            let _ = writeln!(
                s,
                "    {n}. mkfs.vfat -F32 {}",
                self.esp_partition()
            );
            n += 1;
        } else {
            let _ = writeln!(
                s,
                "    -. mkfs.vfat skipped (target already FAT32 — preserves existing \\EFI\\ entries)"
            );
        }
        let _ = writeln!(
            s,
            "    {n}. mount {} → /tmp/zboot-esp-<pid>",
            self.esp_partition()
        );
        n += 1;
        let _ = writeln!(
            s,
            "    {n}. copy zboot-boot.efi → \\EFI\\zboot-boot\\zboot-boot.efi (+ BOOTX64.EFI)"
        );
        n += 1;
        let _ = writeln!(
            s,
            "    {n}. efibootmgr --create --disk {} --part {} --label {label:?} \\",
            self.efibootmgr_disk(),
            self.efibootmgr_part(),
        );
        let _ = writeln!(
            s,
            "         --loader '\\EFI\\zboot-boot\\zboot-boot.efi'"
        );
        let _ = writeln!(
            s,
            "================================================================"
        );
        s
    }
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

fn detect_shape(target: &str) -> Result<Shape> {
    let out = Command::new("lsblk")
        .args(["-no", "TYPE", target])
        .output()
        .with_context(|| format!("spawn `lsblk -no TYPE {target}`"))?;
    if !out.status.success() {
        bail!(
            "lsblk {target} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    let kind = String::from_utf8(out.stdout)
        .context("non-utf8 lsblk output")?
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    match kind.as_str() {
        "disk" | "loop" => Ok(Shape::WholeDisk),
        "part" => Ok(Shape::Partition),
        other => bail!("target {target} has unsupported lsblk type {other:?} (expected disk/loop/part)"),
    }
}

fn detect_content(target: &str, shape: Shape) -> Result<Content> {
    // Run wipefs(8) for filesystem/partition-table signatures.
    let sig = wipefs_signature(target)?;
    let children = lsblk_children(target)?;
    if shape == Shape::WholeDisk {
        if children.is_empty() && sig.is_none() {
            return Ok(Content::Empty);
        }
        let mut bits = Vec::new();
        if !children.is_empty() {
            bits.push(format!("partitions: {}", children.join(", ")));
        }
        if let Some(s) = sig {
            bits.push(s);
        }
        return Ok(Content::Other(bits.join("; ")));
    }
    // partition
    match sig.as_deref() {
        None => Ok(Content::Empty),
        Some("vfat") => Ok(Content::Fat32),
        Some(s) => Ok(Content::Other(s.to_owned())),
    }
}

fn wipefs_signature(target: &str) -> Result<Option<String>> {
    let out = Command::new("wipefs")
        .args(["--noheadings", "--output=TYPE", "-n", target])
        .output()
        .context("spawn wipefs")?;
    if !out.status.success() {
        bail!(
            "wipefs -n {target} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    // Dedupe: FAT32 reports the same signature at multiple offsets
    // (boot sector, BPB, backup BPB) — collapse to a single token so
    // downstream comparisons (e.g. `Some("vfat")`) work.
    let text = String::from_utf8(out.stdout).context("non-utf8 wipefs output")?;
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if !t.is_empty() {
            seen.insert(t.to_owned());
        }
    }
    if seen.is_empty() {
        Ok(None)
    } else {
        Ok(Some(seen.into_iter().collect::<Vec<_>>().join(",")))
    }
}

fn lsblk_children(target: &str) -> Result<Vec<String>> {
    let out = Command::new("lsblk")
        .args(["-nro", "NAME", target])
        .output()
        .context("spawn lsblk")?;
    if !out.status.success() {
        bail!(
            "lsblk {target} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    let text = String::from_utf8(out.stdout).context("non-utf8 lsblk output")?;
    Ok(text
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

fn lsblk_pkname(partition: &str) -> Result<String> {
    let out = Command::new("lsblk")
        .args(["-no", "PKNAME", partition])
        .output()
        .with_context(|| format!("spawn `lsblk -no PKNAME {partition}`"))?;
    if !out.status.success() {
        bail!(
            "lsblk {partition} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    let pk = String::from_utf8(out.stdout)
        .context("non-utf8 lsblk output")?
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    if pk.is_empty() {
        bail!("lsblk -no PKNAME {partition} returned empty — not a partition?");
    }
    Ok(pk)
}

fn basename_of(path: &str) -> Result<String> {
    std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
        .with_context(|| format!("path {path:?} has no basename"))
}

// ---------------------------------------------------------------------------
// Typed-target confirmation (mirrors deploy's protection)
// ---------------------------------------------------------------------------

fn confirm_target<R: BufRead, W: Write>(
    expected: &str,
    env_bypass: Option<&str>,
    stdin: &mut R,
    out: &mut W,
) -> Result<()> {
    if let Some(v) = env_bypass {
        if v == expected {
            writeln!(out, "[confirmed via ZBOOT_ESP_CONFIRM_TARGET={expected}]").ok();
            return Ok(());
        }
        bail!("ZBOOT_ESP_CONFIRM_TARGET={v:?} does not match target basename {expected:?}");
    }
    writeln!(
        out,
        "This will OVERWRITE the target. Type {expected:?} to proceed (Ctrl-C to abort):",
    )
    .ok();
    let mut line = String::new();
    stdin.read_line(&mut line).context("read confirmation")?;
    let got = line.trim();
    if got != expected {
        bail!("confirmation mismatch: expected exactly {expected:?}, got {got:?}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

fn execute<W: Write>(plan: &Plan, label: &str, out: &mut W) -> Result<()> {
    writeln!(out, "\n=== executing esp ===").ok();

    if plan.shape == Shape::WholeDisk {
        wipe_and_partition_for_esp(&plan.target, out)?;
    }

    let esp_part = plan.esp_partition();
    if plan.needs_mkfs() {
        writeln!(out, "[ ] mkfs.vfat ESP ({esp_part})").ok();
        spawn("mkfs.vfat", &["-F32", "-n", "ESP", &esp_part])?;
        writeln!(out, "[x] mkfs.vfat ESP").ok();
    } else {
        writeln!(
            out,
            "[ ] mkfs.vfat skipped ({esp_part} already FAT32; preserving \\EFI\\ entries)"
        )
        .ok();
    }

    let mount = format!("/tmp/zboot-esp-{}", std::process::id());
    writeln!(out, "[ ] mount ESP at {mount}").ok();
    mount_esp(&esp_part, &mount)?;
    writeln!(out, "[x] mount ESP").ok();

    let bundle = resolve_efi_bundle().context("resolve zboot-boot.efi bundle")?;
    writeln!(out, "[ ] copy zboot-boot.efi (from {})", bundle.display()).ok();
    install_efi_to_esp(&bundle, &mount).inspect_err(|_| {
        let _ = unmount_be(&mount);
    })?;
    writeln!(out, "[x] copy zboot-boot.efi").ok();

    writeln!(out, "[ ] unmount ESP").ok();
    unmount_be(&mount)?;
    writeln!(out, "[x] unmount ESP").ok();

    let disk = plan.efibootmgr_disk();
    let part = plan.efibootmgr_part();
    writeln!(out, "[ ] efibootmgr --create --label {label:?}").ok();
    register_efi(&disk, part, label)?;
    writeln!(out, "[x] efibootmgr register").ok();

    writeln!(out, "\n=== esp complete ===").ok();
    Ok(())
}

fn wipe_and_partition_for_esp<W: Write>(disk: &str, out: &mut W) -> Result<()> {
    writeln!(out, "[ ] wipefs -a {disk} ; sfdisk {disk} (single 512MiB ESP)").ok();
    spawn("wipefs", &["-a", disk])?;
    spawn("sgdisk", &["-Z", disk])?;
    // One ESP partition spanning the first 512MiB. Type `U` = EFI system.
    let script = "label: gpt\n,512MiB,U\n";
    let mut child = Command::new("sfdisk")
        .arg(disk)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawn sfdisk")?;
    {
        let stdin_pipe = child.stdin.as_mut().context("sfdisk has no stdin")?;
        stdin_pipe
            .write_all(script.as_bytes())
            .context("write sfdisk script")?;
    }
    let st = child.wait().context("wait sfdisk")?;
    if !st.success() {
        bail!("sfdisk {disk} rc={:?}", st.code());
    }
    let _ = spawn("partprobe", &[disk]).or_else(|_| spawn("partx", &["-u", disk]));
    let _ = spawn("udevadm", &["settle", "--timeout=30"]);
    writeln!(out, "[x] partition").ok();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_for(target: &str, shape: Shape, content: Content) -> Plan {
        let (parent_disk, part_number) = match shape {
            Shape::WholeDisk => (None, None),
            Shape::Partition => (Some("/dev/sdb".to_owned()), Some(partition_number(target))),
        };
        Plan {
            target: target.to_owned(),
            shape,
            content,
            parent_disk,
            part_number,
        }
    }

    #[test]
    fn whole_disk_empty_doesnt_need_replace() {
        let p = plan_for("/dev/sdb", Shape::WholeDisk, Content::Empty);
        assert!(!p.needs_replace());
        assert_eq!(p.esp_partition(), "/dev/sdb1");
        assert_eq!(p.efibootmgr_disk(), "/dev/sdb");
        assert_eq!(p.efibootmgr_part(), 1);
    }

    #[test]
    fn whole_disk_non_empty_needs_replace() {
        let p = plan_for(
            "/dev/sdb",
            Shape::WholeDisk,
            Content::Other("partitions: sdb1, sdb2".into()),
        );
        assert!(p.needs_replace());
    }

    #[test]
    fn partition_fat32_no_replace() {
        let p = plan_for("/dev/sdb1", Shape::Partition, Content::Fat32);
        assert!(!p.needs_replace());
        assert_eq!(p.esp_partition(), "/dev/sdb1");
        assert_eq!(p.efibootmgr_disk(), "/dev/sdb");
        assert_eq!(p.efibootmgr_part(), 1);
    }

    #[test]
    fn partition_empty_no_replace() {
        let p = plan_for("/dev/sdb1", Shape::Partition, Content::Empty);
        assert!(!p.needs_replace());
    }

    #[test]
    fn partition_other_fs_needs_replace() {
        let p = plan_for("/dev/sdb1", Shape::Partition, Content::Other("ntfs".into()));
        assert!(p.needs_replace());
    }

    #[test]
    fn partition_efibootmgr_uses_parent_disk() {
        let p = plan_for("/dev/nvme0n1p3", Shape::Partition, Content::Fat32);
        assert_eq!(p.efibootmgr_disk(), "/dev/sdb"); // mocked parent in fixture
        assert_eq!(p.efibootmgr_part(), 3);
    }

    #[test]
    fn whole_disk_renders_partition_step() {
        let p = plan_for("/dev/sdb", Shape::WholeDisk, Content::Empty);
        let s = p.render("zboot-boot", false);
        assert!(s.contains("wipefs -a /dev/sdb"));
        assert!(s.contains("sfdisk /dev/sdb"));
        assert!(s.contains("mkfs.vfat -F32 /dev/sdb1"));
        assert!(s.contains("efibootmgr"));
    }

    #[test]
    fn partition_skips_partition_step() {
        let p = plan_for("/dev/sdb1", Shape::Partition, Content::Empty);
        let s = p.render("zboot-boot", false);
        assert!(!s.contains("sfdisk"));
        assert!(s.contains("mkfs.vfat -F32 /dev/sdb1"));
    }

    #[test]
    fn confirm_via_env() {
        let mut out = Vec::new();
        let mut stdin = std::io::Cursor::new(Vec::new());
        confirm_target("sdb", Some("sdb"), &mut stdin, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("[confirmed via ZBOOT_ESP_CONFIRM_TARGET=sdb]"));
    }

    #[test]
    fn confirm_env_mismatch_errors() {
        let mut out = Vec::new();
        let mut stdin = std::io::Cursor::new(Vec::new());
        let e = confirm_target("sdb", Some("sda"), &mut stdin, &mut out).unwrap_err();
        assert!(format!("{e:#}").contains("does not match"));
    }

    #[test]
    fn confirm_via_stdin() {
        let mut out = Vec::new();
        let mut stdin = std::io::Cursor::new(b"sdb\n".to_vec());
        confirm_target("sdb", None, &mut stdin, &mut out).unwrap();
    }
}
