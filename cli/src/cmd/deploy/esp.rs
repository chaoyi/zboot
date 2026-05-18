//! ESP install + NVRAM (`efibootmgr`) registration.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use super::plan::Plan;
use super::{spawn, step, unmount_be};

use crate::cmd::efi::{EMBEDDED_EFI_BYTES, extract_to_tmp};

/// Resolve where `zboot-boot.efi` lives on this host. Discovery order:
///
/// 1. `ZBOOT_EFI_BUNDLE` env var — explicit override; the e2e scripts use this.
/// 2. **Embedded copy** — bytes baked into this binary by `cli/build.rs`.
///    Extracted to `/tmp/zboot-boot-<pid>.efi` lazily on first call.
/// 3. `/usr/share/zboot/zboot-boot.efi` — debian-package canonical home.
/// 4. `/usr/lib/zboot/zboot-boot.efi` — alt-distro fallback.
/// 5. `${exe_dir}/zboot-boot.efi` — sibling of the running binary
///    (handy when running directly out of `boot/out/` for development).
pub(crate) fn resolve_efi_bundle() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("ZBOOT_EFI_BUNDLE") {
        let path = PathBuf::from(&p);
        if path.is_file() {
            return Ok(path);
        }
        bail!("ZBOOT_EFI_BUNDLE={p:?} is not a regular file");
    }
    if !EMBEDDED_EFI_BYTES.is_empty() {
        return extract_to_tmp();
    }
    let mut candidates = vec![
        PathBuf::from("/usr/share/zboot/zboot-boot.efi"),
        PathBuf::from("/usr/lib/zboot/zboot-boot.efi"),
    ];
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("zboot-boot.efi"));
    }
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }
    bail!(
        "zboot-boot.efi not found — embedded copy is empty placeholder \
         (build with `bash boot/build.sh && cargo build --release` to embed), \
         and not present at any of: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" / "),
    )
}

pub(crate) fn mount_esp(partition: &str, mountpoint: &str) -> Result<()> {
    std::fs::create_dir_all(mountpoint).with_context(|| format!("mkdir {mountpoint}"))?;
    spawn("mount", &["-t", "vfat", partition, mountpoint])
}

/// Copy the EFI bundle to both:
/// - `<ESP>/EFI/zboot-boot/zboot-boot.efi` — canonical NVRAM target
/// - `<ESP>/EFI/BOOT/BOOTX64.EFI` — UEFI default-search fallback
pub(crate) fn install_efi_to_esp(bundle: &Path, esp: &str) -> Result<()> {
    let canonical = format!("{esp}/EFI/zboot-boot");
    let fallback = format!("{esp}/EFI/BOOT");
    std::fs::create_dir_all(&canonical).context("mkdir EFI/zboot-boot")?;
    std::fs::create_dir_all(&fallback).context("mkdir EFI/BOOT")?;
    std::fs::copy(bundle, format!("{canonical}/zboot-boot.efi"))
        .context("copy zboot-boot.efi (canonical)")?;
    std::fs::copy(bundle, format!("{fallback}/BOOTX64.EFI"))
        .context("copy BOOTX64.EFI (fallback)")?;
    Ok(())
}

/// ESP install: format the freshly-partitioned ESP, mount, copy the
/// bundle, register the NVRAM entry. Always reformats because the
/// partition was carved out by this same deploy run — there's no
/// existing `\EFI\` content worth preserving on it.
pub(super) fn install_efi_for_layout<W: Write>(
    plan: &Plan,
    bundle: &Path,
    out: &mut W,
) -> Result<()> {
    let esp = plan
        .esp_partition
        .clone()
        .context("internal: install_efi_for_layout called without an ESP partition")?;
    let esp_for_format = esp.clone();
    step(out, "mkfs.vfat ESP", move || {
        spawn("mkfs.vfat", &["-F32", "-n", "ESP", &esp_for_format])
    })?;
    let esp_mount = format!("/tmp/zboot-esp-{}", std::process::id());
    let esp_part = esp.clone();
    let mount_label = format!("mount ESP at {esp_mount}");
    let esp_mount_for_step = esp_mount.clone();
    step(out, &mount_label, move || {
        mount_esp(&esp_part, &esp_mount_for_step)
    })?;
    let bundle_owned = bundle.to_path_buf();
    let esp_mount_for_install = esp_mount.clone();
    step(out, "copy zboot-boot.efi to ESP", move || {
        install_efi_to_esp(&bundle_owned, &esp_mount_for_install)
    })?;
    let esp_mount_for_unmount = esp_mount.clone();
    step(out, "unmount ESP", move || {
        unmount_be(&esp_mount_for_unmount)
    })?;
    let esp_disk = plan.disk.clone();
    let part_n = partition_number(&esp);
    step(out, "efibootmgr register", move || {
        register_efi(&esp_disk, part_n, "zboot-boot")
    })?;
    Ok(())
}

/// Pull the trailing partition number off a partition path:
/// `/dev/vda1` → 1, `/dev/nvme0n1p2` → 2.
pub(crate) fn partition_number(part: &str) -> u8 {
    let digits: String = part
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    let digits: String = digits.chars().rev().collect();
    digits.parse().unwrap_or(1)
}

/// Register a labelled NVRAM entry pointing at `\EFI\zboot-boot\zboot-boot.efi`.
/// Idempotent: any existing entry with the same label is dropped first.
pub(crate) fn register_efi(disk: &str, part: u8, label: &str) -> Result<()> {
    if let Ok(existing) = list_efi_entries() {
        for id in existing
            .iter()
            .filter(|e| e.label == label)
            .map(|e| e.id.clone())
        {
            spawn("efibootmgr", &["-b", &id, "-B"]).ok();
        }
    }
    let part_str = part.to_string();
    spawn(
        "efibootmgr",
        &[
            "--create",
            "--disk",
            disk,
            "--part",
            &part_str,
            "--label",
            label,
            "--loader",
            r"\EFI\zboot-boot\zboot-boot.efi",
        ],
    )
}

pub(crate) struct EfiEntry {
    pub id: String,
    pub label: String,
}

/// Parse `efibootmgr`'s default output for `BootNNNN* Label` rows.
pub(crate) fn list_efi_entries() -> Result<Vec<EfiEntry>> {
    let out = Command::new("efibootmgr")
        .output()
        .context("spawn efibootmgr")?;
    if !out.status.success() {
        bail!(
            "efibootmgr rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    let text = String::from_utf8(out.stdout).context("non-utf8 efibootmgr output")?;
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("Boot") else {
            continue;
        };
        let (id_part, label_part) = rest.split_once(' ').unwrap_or((rest, ""));
        let id_clean = id_part.trim_end_matches('*');
        if id_clean.len() != 4 || !id_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let label = label_part
            .split('\t')
            .next()
            .unwrap_or("")
            .trim()
            .to_owned();
        entries.push(EfiEntry {
            id: id_clean.to_owned(),
            label,
        });
    }
    Ok(entries)
}
