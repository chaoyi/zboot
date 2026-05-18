//! `zboot cmdline` — manage the `zboot:kernel-cmdline` ZFS user-property.
//!
//! The property is read by `zboot-boot` at kexec time and appended to the
//! kernel command line. Two-level scoping via ZFS inheritance: set on the
//! ROOT container (`<pool>/ROOT`) for a slot-wide default, override on a
//! specific BE.
//!
//! Subcommands:
//!
//! - `get` (default) — show the effective value with source annotation
//! - `set VALUE` — write `zboot:kernel-cmdline=VALUE` on the target
//! - `clear` — `zfs inherit zboot:kernel-cmdline` on the target (drop local value)
//! - `edit` — open `$EDITOR` with the current value; on save, set or clear

use std::io::Write;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};

use crate::sub;

#[derive(Debug, Args)]
pub struct CmdlineArgs {
    #[command(subcommand)]
    pub action: Option<CmdlineAction>,

    /// Target this BE dataset (full path, e.g. `rpool/ROOT/be1`).
    /// Mutually exclusive with `--root`.
    #[arg(long, global = true, conflicts_with = "root")]
    pub be: Option<String>,

    /// Target this pool's ROOT container (slot-wide default).
    /// Pool name only; the `/ROOT` suffix is appended.
    #[arg(long, global = true)]
    pub root: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum CmdlineAction {
    /// Show the effective cmdline with source (local vs inherited).
    Get,
    /// Write `zboot:kernel-cmdline=VALUE`.
    Set {
        /// Cmdline tokens, e.g. `"quiet splash nomodeset"`.
        value: String,
    },
    /// Drop the local property; revert to inherited (or unset).
    Clear,
    /// Open `$EDITOR` with the current value; save to set, blank to clear.
    Edit,
}

pub fn run(args: &CmdlineArgs, mut w: &mut dyn Write) -> Result<()> {
    let target = resolve_target(args)?;
    // `&mut w` makes each helper see a Sized `&mut (&mut dyn Write)` —
    // satisfies `&mut impl Write` without changing the helpers' shapes.
    match &args.action {
        None | Some(CmdlineAction::Get) => get(&target, &mut w),
        Some(CmdlineAction::Set { value }) => set(&target, value, &mut w),
        Some(CmdlineAction::Clear) => clear(&target, &mut w),
        Some(CmdlineAction::Edit) => edit(&target, &mut w),
    }
}

/// Pick the dataset to read/write the property on.
///
/// Precedence: `--be` > `--root` > active BE (auto-detect).
fn resolve_target(args: &CmdlineArgs) -> Result<String> {
    if let Some(be) = &args.be {
        return Ok(be.clone());
    }
    if let Some(pool) = &args.root {
        return Ok(format!("{pool}/ROOT"));
    }
    active_be().context("no --be / --root given and no active BE detected")
}

/// Determine the running system's active BE dataset by inspecting `/`.
/// Returns the ZFS source of `/` (e.g. `rpool/ROOT/be1`).
fn active_be() -> Result<String> {
    let out = Command::new("findmnt")
        .args(["-n", "-o", "source", "/"])
        .output()
        .context("spawn findmnt")?;
    if !out.status.success() {
        bail!("findmnt / exited {:?}", out.status.code());
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if s.is_empty() {
        bail!("findmnt produced no output for /");
    }
    // findmnt prints the dataset directly when / is ZFS; reject otherwise.
    if s.starts_with('/') {
        bail!("/ is not a ZFS dataset (got {s:?}); pass --be or --root");
    }
    Ok(s)
}

fn get(ds: &str, w: &mut impl Write) -> Result<()> {
    let (value, source) = read_property(ds)?;
    let display_value = if value == "-" {
        "(unset)"
    } else {
        value.as_str()
    };
    writeln!(w, "{ds}: {display_value}  [{source}]").context("write get output")?;
    Ok(())
}

fn set(ds: &str, value: &str, w: &mut impl Write) -> Result<()> {
    let arg = format!("zboot:kernel-cmdline={value}");
    sub::zfs(&["set", &arg, ds])
        .with_context(|| format!("zfs set zboot:kernel-cmdline on {ds}"))?;
    writeln!(w, "set zboot:kernel-cmdline on {ds}: {value}").context("write set output")?;
    Ok(())
}

fn clear(ds: &str, w: &mut impl Write) -> Result<()> {
    sub::zfs(&["inherit", "zboot:kernel-cmdline", ds])
        .with_context(|| format!("zfs inherit zboot:kernel-cmdline on {ds}"))?;
    writeln!(w, "cleared local zboot:kernel-cmdline on {ds}").context("write clear output")?;
    Ok(())
}

fn edit(ds: &str, w: &mut impl Write) -> Result<()> {
    let (current, _) = read_property(ds)?;
    let initial = if current == "-" {
        String::new()
    } else {
        current
    };

    // Use a unique-ish path under /tmp; no extra deps.
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp_path = std::path::PathBuf::from(format!("/tmp/zboot-cmdline-{pid}-{now}"));
    std::fs::write(&tmp_path, format!("{initial}\n"))
        .with_context(|| format!("write {}", tmp_path.display()))?;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_owned());
    let status = Command::new(&editor)
        .arg(&tmp_path)
        .status()
        .with_context(|| format!("spawn editor {editor}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp_path);
        bail!("{editor} exited {:?}", status.code());
    }
    let new_text = std::fs::read_to_string(&tmp_path)
        .with_context(|| format!("read {}", tmp_path.display()))?;
    let _ = std::fs::remove_file(&tmp_path);

    let new_value = new_text.trim().to_owned();
    if new_value == initial {
        writeln!(w, "no change").context("write no-change")?;
        return Ok(());
    }
    if new_value.is_empty() {
        clear(ds, w)
    } else {
        set(ds, &new_value, w)
    }
}

/// Read `(value, source)` for `zboot:kernel-cmdline` on `ds`. Source is `local`,
/// `inherited from <parent>`, `default`, or `-` (unset).
fn read_property(ds: &str) -> Result<(String, String)> {
    let stdout = sub::zfs_capture(&[
        "get",
        "-H",
        "-o",
        "value,source",
        "zboot:kernel-cmdline",
        ds,
    ])?;
    let line = stdout
        .lines()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("zfs get returned no output for {ds}"))?;
    let mut parts = line.splitn(2, '\t');
    let value = parts.next().unwrap_or("-").to_owned();
    let source = parts.next().unwrap_or("-").to_owned();
    Ok((value, source))
}
