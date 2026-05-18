//! Idempotent pool auto-import helpers.
//!
//! zboot's userspace verbs operate on the imported-pool working set —
//! a pool that's importable but not yet imported is invisible to
//! `zfs list` / `zpool list` and so to `status`. For a personal-use
//! tool this is friction: the operator has to manually
//! `zpool import` every `zboot:role=root` pool before zboot can show
//! its BEs.
//!
//! This module provides idempotent helpers:
//! - [`ensure_zboot_root_pools_imported`] — readonly auto-import all
//!   `zboot:role=root` pools on local disks. Called by `status` so the
//!   forest view is complete. Safe (readonly: no hostid stamp update,
//!   no ZIL replay, no write transactions).
//! - [`is_pool_imported`] / [`importable_pools`] — primitive queries
//!   used by `deploy`'s collision preflight and shell verbs.
//!
//! What this DOESN'T do:
//! - Touch pools without `zboot:role=root`. We scan, briefly readonly-
//!   import to read the role property, and export if it's not "root".
//!   Operator's USB stick / backup pool stays untouched.
//! - Export pools we imported. Asymmetry by design: we add visibility,
//!   we don't take it away. Operator can `zpool export` if they want.

use std::io::Write;
use std::process::Command;

use anyhow::{Context, Result};

/// Ensure `pool` is currently imported AND has pool-level
/// `readonly=off`. Idempotent:
/// - Not imported → import without `-o readonly=on` (R/W).
/// - Imported R/W → no-op.
/// - Imported R/O (e.g., auto-imported via `status`'s scan) → export
///   + reimport without `-o readonly=on`.
///
/// Required before any `zpool set` / `zfs set` that targets `pool` or
/// its datasets — `status`'s auto-import policy is read-only, so
/// secondary pools may need this promotion before mutation.
pub fn ensure_pool_imported_rw(pool: &str) -> Result<()> {
    if is_pool_imported(pool)? {
        let ro = pool_readonly(pool)?;
        if !ro {
            return Ok(());
        }
        Command::new("zpool")
            .args(["export", pool])
            .status()
            .with_context(|| format!("export {pool} to clear readonly"))?
            .success()
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("zpool export {pool} failed"))?;
    }
    Command::new("zpool")
        .args(["import", "-N", "-f", pool])
        .status()
        .with_context(|| format!("import {pool} (rw)"))?
        .success()
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("zpool import -N -f {pool} failed"))?;
    Ok(())
}

/// Read pool-level `readonly` property.
fn pool_readonly(pool: &str) -> Result<bool> {
    let out = Command::new("zpool")
        .args(["get", "-Hp", "-o", "value", "readonly", pool])
        .output()
        .context("spawn `zpool get readonly`")?;
    if !out.status.success() {
        anyhow::bail!("zpool get readonly {pool}: rc={:?}", out.status.code());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim() == "on")
}

/// Names of pools currently imported (`zpool list -H -o name`).
pub fn currently_imported() -> Result<Vec<String>> {
    let out = Command::new("zpool")
        .args(["list", "-H", "-o", "name"])
        .output()
        .context("spawn `zpool list`")?;
    // Non-zero exit when no pools are imported — that's just "empty list".
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect())
}

/// True iff `pool` is currently imported.
pub fn is_pool_imported(pool: &str) -> Result<bool> {
    Ok(currently_imported()?.iter().any(|n| n == pool))
}

/// Names of pools importable from `/dev` (not currently imported).
/// `zpool import -d /dev` (no pool name) scans labels and prints
/// `pool: <name>` / `id: <guid>` blocks. We extract just the names.
pub fn importable_pools() -> Result<Vec<String>> {
    let out = Command::new("zpool")
        .args(["import", "-d", "/dev"])
        .output()
        .context("spawn `zpool import -d /dev`")?;
    // Non-zero is normal when no pools are importable.
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("pool: ").map(|s| s.to_owned()))
        .collect())
}

/// Read `zboot:role` from an already-imported pool. Returns `Some` if
/// the property is set locally (e.g., `"root"`); `None` if absent.
fn read_zboot_role(pool: &str) -> Option<String> {
    let out = Command::new("zpool")
        .args(["get", "-Hp", "-o", "value", "zboot:role", pool])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    // `zpool get` prints `-` for unset properties.
    if value.is_empty() || value == "-" {
        None
    } else {
        Some(value)
    }
}

/// Idempotent: ensure all `zboot:role=root` pools visible on local
/// disks are imported (readonly). Returns names of pools we newly
/// imported in this call — useful for callers that want to log or
/// later export.
///
/// Algorithm:
/// 1. List importable pools (read-only scan, no side effects).
/// 2. For each NOT already imported:
///    a. Try readonly import with `-f` (matches preinit semantics).
///    b. Check `zboot:role` — if not "root", export immediately so we
///       don't hold a foreign pool open.
///    c. If "root", keep it imported, add to the returned list.
///
/// Readonly import is safe to do unconditionally:
/// - No hostid stamp update → no drift if PID-1's hostid differs.
/// - No ZIL replay → can't trigger replay-time bugs.
/// - No write transactions → can't corrupt the pool.
pub fn ensure_zboot_root_pools_imported<W: Write>(out: &mut W) -> Result<Vec<String>> {
    let already = currently_imported().unwrap_or_default();
    let candidates = importable_pools().unwrap_or_default();
    let mut newly_imported: Vec<String> = Vec::new();

    // Multiple importable pools with the SAME name are reported as
    // duplicates by `zpool import` (one block per GUID). Importing by
    // name then fails with "more than one matching pool". Track names
    // we've already seen and warn instead of silently skipping.
    let mut seen_names: std::collections::HashSet<&str> = Default::default();
    for pool in &candidates {
        if already.iter().any(|n| n == pool) {
            continue;
        }
        if !seen_names.insert(pool.as_str()) {
            writeln!(
                out,
                "[!] skipping `{pool}` — multiple importable pools share this name; \
                 import by GUID with `zpool import <guid>` to disambiguate"
            )
            .ok();
            continue;
        }
        // Readonly import, then check role. `-f` matches preinit — the
        // pool's stamped hostid may not equal our runtime hostid, which
        // is benign for readonly.
        let import_rc = Command::new("zpool")
            .args(["import", "-N", "-f", "-o", "readonly=on", pool])
            .output()
            .ok();
        match import_rc {
            Some(o) if o.status.success() => {}
            Some(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                let err = err.trim();
                if !err.is_empty() {
                    writeln!(out, "[!] auto-import of `{pool}` failed: {err}").ok();
                }
                continue;
            }
            None => continue,
        }

        match read_zboot_role(pool).as_deref() {
            Some("root") => {
                writeln!(
                    out,
                    "[ ] auto-imported `{pool}` (readonly, zboot:role=root)"
                )
                .ok();
                newly_imported.push(pool.clone());
            }
            _ => {
                // Not a zboot-managed pool — export so we don't hold it.
                let _ = Command::new("zpool").args(["export", pool]).status();
            }
        }
    }
    Ok(newly_imported)
}
