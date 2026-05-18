//! ZFS-domain helpers shared across verbs.
//!
//! Wraps `zfs(8)` and `zpool(8)` to answer questions ("does this
//! dataset exist?", "what's `bootfs` on this pool?", "what GUIDs sit
//! under this dataset?") and to perform standard mutations (set a
//! property tolerant of mountpoint-overlap warnings, run a
//! `zfs send | zfs receive` pipe).
//!
//! Builds on `sub.rs` (`Runner` / `zfs_capture`). These helpers always
//! shell out to the real `SystemRunner`; verbs that thread a runner
//! for unit-testability use `sub::*` directly.

use std::collections::BTreeSet;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};

use crate::sub;

// ---------------------------------------------------------------------------
// Existence / introspection
// ---------------------------------------------------------------------------

/// True iff `dataset` is a known ZFS dataset on an imported pool.
pub fn dataset_exists(ds: &str) -> Result<bool> {
    let out = Command::new("zfs")
        .args(["list", "-H", "-o", "name", ds])
        .output()
        .context("spawning zfs list")?;
    Ok(out.status.success())
}

/// Read a property of a dataset. Trims trailing newline. Fails if the
/// dataset is missing or the property is unknown.
pub fn dataset_property(ds: &str, prop: &str) -> Result<String> {
    let out = Command::new("zfs")
        .args(["get", "-Hp", "-o", "value", prop, ds])
        .output()
        .with_context(|| format!("spawning zfs get {prop} {ds}"))?;
    if !out.status.success() {
        bail!(
            "zfs get {prop} {ds} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)
        .context("non-utf8 from zfs get")?
        .trim()
        .to_owned())
}

/// Read a pool property (`zpool get`). Same shape as `dataset_property`.
pub fn pool_property(pool: &str, prop: &str) -> Result<String> {
    let out = Command::new("zpool")
        .args(["get", "-H", "-o", "value", prop, pool])
        .output()
        .with_context(|| format!("spawning zpool get {prop} {pool}"))?;
    if !out.status.success() {
        bail!(
            "zpool get {prop} {pool} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)
        .context("non-utf8 from zpool get")?
        .trim()
        .to_owned())
}

/// True iff `<dataset>@<name>` exists as a ZFS snapshot.
pub fn snapshot_exists(full_path: &str) -> anyhow::Result<bool> {
    let out = std::process::Command::new("zfs")
        .args(["list", "-H", "-t", "snapshot", "-o", "name", full_path])
        .output()
        .with_context(|| format!("spawning zfs list snapshot {full_path}"))?;
    Ok(out.status.success())
}

/// `bootfs` on a pool, or `None` for unset (`-`).
pub fn pool_bootfs(pool: &str) -> Result<Option<String>> {
    let val = pool_property(pool, "bootfs")?;
    if val == "-" || val.is_empty() {
        Ok(None)
    } else {
        Ok(Some(val))
    }
}

/// Whichever pool currently has a non-empty `bootfs`. Fails if zero or
/// more than one pool is active (the cross-pool boundary `default`
/// crosses, but the steady state is always exactly one).
///
/// Use this when the question is "where is the *next-boot* target?".
/// For "where am I *actually running from?*", use [`discover_booted_dataset`]
/// (reads `/proc/self/mounts`). The two can differ briefly between a
/// `default`/`primary` flip and the next reboot.
pub fn discover_active_pool() -> Result<String> {
    let text = sub::zpool_capture(&["list", "-Hp", "-o", "name,bootfs"])?;
    for line in text.lines() {
        let mut parts = line.split('\t');
        let pool = parts.next().unwrap_or("");
        let bootfs = parts.next().unwrap_or("-");
        if bootfs != "-" && !bootfs.is_empty() {
            return Ok(pool.to_owned());
        }
    }
    bail!("no pool has a bootfs set; can't determine active pool")
}

/// The ZFS dataset currently mounted at `/` — the actually-running BE.
/// Reads `/proc/self/mounts` directly; the source field of the row whose
/// target is `/` is the dataset name.
///
/// This is what userspace verbs should use when they need "my current
/// BE" (push/pull with no args, snapshot, etc.). It differs from
/// [`discover_active_pool`] + [`pool_bootfs`] when a `default` or
/// `primary` flip has set the next-boot target but the operator hasn't
/// rebooted yet. The bootloader-shell side of zboot can't use this
/// (no userspace yet) and falls back to `bootfs` there.
pub fn discover_booted_dataset() -> Result<String> {
    let mounts = std::fs::read_to_string("/proc/self/mounts")
        .context("reading /proc/self/mounts to find the booted BE")?;
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let source = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        if target == "/" {
            if source.contains('/') {
                return Ok(source.to_owned());
            } else {
                bail!(
                    "root mount source {source:?} doesn't look like a ZFS dataset \
                     (expected `<pool>/...`); not a zboot-managed system?"
                );
            }
        }
    }
    bail!("no `/` mount found in /proc/self/mounts; can't determine booted BE")
}

/// Pool of the actually-booted BE. Userspace counterpart of
/// [`discover_active_pool`].
pub fn discover_booted_pool() -> Result<String> {
    let ds = discover_booted_dataset()?;
    ds.split('/')
        .next()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("bad booted dataset {ds}"))
}

/// Fail unless `pool` is tagged `zboot:role=root`.
pub fn require_role_root(pool: &str) -> Result<()> {
    let role = pool_property(pool, "zboot:role")?;
    if role != "root" {
        bail!(
            "pool {pool:?} is not tagged zboot:role=root (got {role:?}). \
             Run `zpool set zboot:role=root {pool}` first."
        );
    }
    Ok(())
}

/// Snapshots under a dataset, paired with GUID, in `zfs list` creation
/// order. Empty Vec on missing dataset (rather than error).
pub fn list_snapshots_with_guids(dataset: &str) -> Result<Vec<(String, String)>> {
    let out = Command::new("zfs")
        .args([
            "list", "-Hp", "-t", "snapshot", "-o", "name,guid", "-d", "1", "-s", "creation",
            dataset,
        ])
        .output()
        .context("spawning zfs list -t snapshot")?;
    if !out.status.success() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8(out.stdout).context("non-utf8")?;
    let mut out_vec = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let name = parts.next().unwrap_or("");
        let guid = parts.next().unwrap_or("");
        out_vec.push((name.to_owned(), guid.to_owned()));
    }
    Ok(out_vec)
}

/// GUID set under a dataset, excluding replication anchors. Used by
/// status (ahead/behind) and divergence detection.
pub fn snapshot_guid_set(dataset: &str) -> Result<BTreeSet<String>> {
    let pairs = list_snapshots_with_guids(dataset)?;
    Ok(pairs
        .into_iter()
        .filter(|(n, _)| !zboot_core::is_replication_anchor(n))
        .map(|(_, g)| g)
        .collect())
}

/// `zfs get -p written <dataset>@latest` — bytes written since the
/// latest snapshot. Returns `None` if no snapshots, the dataset is
/// missing, or the property isn't readable.
pub fn dirty_bytes_since_latest(dataset: &str) -> Option<u64> {
    let pairs = list_snapshots_with_guids(dataset).ok()?;
    let latest = pairs.last()?;
    // `latest.0` is `<dataset>@<name>`.
    let out = Command::new("zfs")
        .args(["get", "-Hp", "-o", "value", "written", &latest.0])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let val = String::from_utf8(out.stdout).ok()?;
    val.trim().parse::<u64>().ok()
}

/// True iff `dataset` is currently mounted (per `zfs get mounted`).
pub fn is_mounted(dataset: &str) -> bool {
    let Ok(val) = dataset_property(dataset, "mounted") else {
        return false;
    };
    val == "yes"
}

// ---------------------------------------------------------------------------
// Tolerant property setters
//
// ZFS occasionally emits stderr noise (mountpoint-overlap warnings, e.g.
// for BEs with mountpoint=/) and returns rc=255 even when the property
// was written successfully. The pattern: ignore rc, read the property
// back, bail only if the read disagrees with the requested value.
// ---------------------------------------------------------------------------

/// Set a property with `zfs set -u` (no remount). Verifies via readback.
pub fn set_property_tolerant(ds: &str, prop: &str, value: &str) -> Result<()> {
    eprintln!("+ zfs set -u {prop}={value} {ds}");
    let _ = Command::new("zfs")
        .args(["set", "-u", &format!("{prop}={value}"), ds])
        .stderr(Stdio::null())
        .status();
    let actual = dataset_property(ds, prop)?;
    if actual != value {
        bail!("zfs set {prop}={value} on {ds} did not take effect (actual={actual})");
    }
    Ok(())
}

/// `zfs set readonly=on|off` with the tolerance pattern above.
pub fn set_readonly_tolerant(ds: &str, value: &str) -> Result<()> {
    set_property_tolerant(ds, "readonly", value)
}

/// Inherit a property (`zfs inherit <prop> <ds>`). Tolerant of "not
/// previously set" — that's a no-op, not an error.
pub fn inherit_property_tolerant(ds: &str, prop: &str) -> Result<()> {
    eprintln!("+ zfs inherit {prop} {ds}");
    let _ = Command::new("zfs")
        .args(["inherit", prop, ds])
        .stderr(Stdio::null())
        .status();
    // Read back: should be inherited (`-`) or the inherited default.
    // We don't have a strong assertion here — best-effort is fine for
    // pair-pointer clearing since the verb's caller verifies via the
    // peer's perspective.
    Ok(())
}

// ---------------------------------------------------------------------------
// Send / receive
// ---------------------------------------------------------------------------

/// Mint a fresh replication-anchor snapshot name.
pub fn fresh_anchor_name() -> String {
    let utc_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("mirror-{utc_ns}")
}

/// True iff `dataset` is a ZFS clone (has a non-empty `origin` property).
/// Used by push to detect when the bootstrap of a freshly-forked BE
/// would carry a clone-origin reference across pools — which fails if
/// the dest pool doesn't have the origin snapshot. See
/// `send_recv_full_standalone` for the workaround.
pub fn dataset_is_clone(ds: &str) -> Result<bool> {
    let origin = dataset_property(ds, "origin")?;
    Ok(!origin.is_empty() && origin != "-")
}

/// Standalone full send: `zfs send -p <anchor> | zfs receive -F -u <dest>`.
/// Unlike the `-R` form, this carries the dataset's user properties but
/// does NOT carry the clone-origin pointer or earlier snapshots in the
/// chain. Use for bootstrapping a clone source to a peer pool that lacks
/// the origin's lineage — the receive treats it as a fresh standalone
/// dataset (no origin), with all `zboot:*` properties intact.
pub fn send_recv_full_standalone(anchor: &str, dest: &str) -> Result<()> {
    eprintln!("+ zfs send -p {anchor} | zfs receive -F -u {dest}");
    let mut send = Command::new("zfs")
        .args(["send", "-p", anchor])
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning zfs send -p")?;
    let send_stdout = send
        .stdout
        .take()
        .ok_or_else(|| anyhow!("zfs send produced no stdout"))?;
    let mut recv = Command::new("zfs")
        .args(["receive", "-F", "-u", dest])
        .stdin(Stdio::from(send_stdout))
        .spawn()
        .context("spawning zfs receive")?;
    let send_status = send.wait().context("waiting for zfs send -p")?;
    let recv_status = recv.wait().context("waiting for zfs receive")?;
    if !send_status.success() {
        bail!("zfs send -p rc={:?}", send_status.code());
    }
    if !recv_status.success() {
        bail!("zfs receive rc={:?}", recv_status.code());
    }
    Ok(())
}

/// Full send: `zfs send -R <anchor> | zfs receive -F -u <dest>`.
pub fn send_recv_full(anchor: &str, dest: &str) -> Result<()> {
    eprintln!("+ zfs send -R {anchor} | zfs receive -F -u {dest}");
    let mut send = Command::new("zfs")
        .args(["send", "-R", anchor])
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning zfs send")?;
    let send_stdout = send
        .stdout
        .take()
        .ok_or_else(|| anyhow!("zfs send produced no stdout"))?;
    let mut recv = Command::new("zfs")
        .args(["receive", "-F", "-u", dest])
        .stdin(Stdio::from(send_stdout))
        .spawn()
        .context("spawning zfs receive")?;
    let send_status = send.wait().context("waiting for zfs send")?;
    let recv_status = recv.wait().context("waiting for zfs receive")?;
    if !send_status.success() {
        bail!("zfs send rc={:?}", send_status.code());
    }
    if !recv_status.success() {
        bail!("zfs receive rc={:?}", recv_status.code());
    }
    Ok(())
}

/// Roll a dataset back to a specific snapshot, destroying any snapshots
/// taken after it (`zfs rollback -r <dest>@<snap>`). Used by bounded
/// push/pull `--force` to rewind a peer to the operator-named bound.
/// `-r` (not `-R`) — destroys newer snapshots but **refuses** if any
/// clones depend on them, which is the right behavior (don't silently
/// orphan clones; operator drops them first).
pub fn zfs_rollback_recursive(dest_snap: &str) -> Result<()> {
    eprintln!("+ zfs rollback -r {dest_snap}");
    let out = Command::new("zfs")
        .args(["rollback", "-r", dest_snap])
        .output()
        .context("spawning zfs rollback")?;
    if !out.status.success() {
        bail!(
            "zfs rollback -r {dest_snap} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Incremental send: `zfs send -I <prev> <new> | zfs receive -F -u <dest>`.
///
/// **No `-R`.** Empirically, `zfs send -R -I` on a *clone* source causes
/// `zfs receive` to exit with rc=1 even though all data and intermediate
/// snapshots transfer successfully (no error printed to stderr). `-I`
/// alone is enough: it still carries intermediate snapshots between
/// `prev` and `new`. We re-apply the BE-contract user properties
/// (`zboot:be`, `zboot:mirror`, `zboot:primary`, `mountpoint`, etc.)
/// explicitly after receive (see `set_be_contract` and the pair-pointer
/// writes in push.rs), so `-R`'s dataset-property carry isn't load-bearing.
pub fn send_recv_incremental(prev: &str, new_anchor: &str, dest: &str) -> Result<()> {
    eprintln!("+ zfs send -I {prev} {new_anchor} | zfs receive -F -u {dest}");
    let mut send = Command::new("zfs")
        .args(["send", "-I", prev, new_anchor])
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning zfs send -I")?;
    let send_stdout = send
        .stdout
        .take()
        .ok_or_else(|| anyhow!("zfs send produced no stdout"))?;
    let mut recv = Command::new("zfs")
        .args(["receive", "-F", "-u", dest])
        .stdin(Stdio::from(send_stdout))
        .spawn()
        .context("spawning zfs receive")?;
    let send_status = send.wait()?;
    let recv_status = recv.wait()?;
    if !send_status.success() {
        bail!("zfs send -I rc={:?}", send_status.code());
    }
    if !recv_status.success() {
        bail!("zfs receive rc={:?}", recv_status.code());
    }
    Ok(())
}

/// Find the most recent source snapshot whose GUID also exists on
/// `dest_dataset` — the `-i` base for the next incremental send.
pub fn previous_anchor_on_dest(source_dataset: &str, dest_dataset: &str) -> Result<Option<String>> {
    let src = list_snapshots_with_guids(source_dataset)?;
    let dest = list_snapshots_with_guids(dest_dataset)?;
    let dest_guids: BTreeSet<String> = dest.iter().map(|(_, g)| g.clone()).collect();
    let mut latest_match: Option<String> = None;
    for (snap, guid) in &src {
        if dest_guids.contains(guid) {
            latest_match = Some(snap.clone());
        }
    }
    Ok(latest_match)
}

/// Destroy all `<dataset>@mirror-*` snapshots except `keep`. Best-effort
/// — failures are logged to stderr but don't abort.
pub fn prune_old_anchors(dataset: &str, keep: &str) {
    let prefix = format!("{dataset}@mirror-");
    let listing = Command::new("zfs")
        .args(["list", "-Hp", "-t", "snapshot", "-o", "name", "-r", dataset])
        .output();
    let Ok(out) = listing else { return };
    if !out.status.success() {
        return;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let snap = line.trim();
        if !snap.starts_with(&prefix) || snap == keep {
            continue;
        }
        eprintln!("+ zfs destroy {snap}");
        let _ = Command::new("zfs")
            .args(["destroy", snap])
            .stderr(Stdio::null())
            .status();
    }
}

/// Snapshot a dataset (`zfs snapshot <dataset>@<name>`).
pub fn take_snapshot(dataset: &str, name: &str) -> Result<String> {
    let full = format!("{dataset}@{name}");
    sub::zfs(&["snapshot", &full]).with_context(|| format!("zfs snapshot {full}"))?;
    Ok(full)
}

// ---------------------------------------------------------------------------
// Pair pointer property
// ---------------------------------------------------------------------------

/// Read `zboot:mirror` on `ds`. Returns `None` for unset (`-` / empty).
pub fn read_pair_pointer(ds: &str) -> Result<Option<zboot_core::PairPointer>> {
    let val = dataset_property(ds, "zboot:mirror")?;
    Ok(zboot_core::PairPointer::parse_dataset(&val))
}

/// Write `zboot:mirror=<peer>` on `ds`.
pub fn write_pair_pointer(ds: &str, peer: &zboot_core::PairPointer) -> Result<()> {
    set_property_tolerant(ds, "zboot:mirror", &peer.render())
}

/// Clear `zboot:mirror` (inherit). Tolerant of not-currently-set.
pub fn clear_pair_pointer(ds: &str) -> Result<()> {
    inherit_property_tolerant(ds, "zboot:mirror")
}

/// Set the BE-contract properties expected on a freshly-received or
/// bootstrapped dest BE. `-u` suppresses remount; we use the tolerant
/// setter to ignore mountpoint-overlap warnings.
pub fn set_be_contract(ds: &str) -> Result<()> {
    set_property_tolerant(ds, "canmount", "noauto")?;
    set_property_tolerant(ds, "mountpoint", "/")?;
    set_property_tolerant(ds, "zboot:be", "true")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Divergence detection — shared by push/pull/mirror.
// ---------------------------------------------------------------------------

/// Snapshots present on `right` but not on `left`. Excludes replication
/// anchors (`@mirror-*`) from both sides — those are pruning lag, not
/// divergence. Used by push/pull/mirror's divergence checks.
pub fn snapshots_only_on_right(left: &str, right: &str) -> anyhow::Result<Vec<String>> {
    let left_pairs = list_snapshots_with_guids(left)?;
    let right_pairs = list_snapshots_with_guids(right)?;
    let left_guids: std::collections::BTreeSet<&str> = left_pairs
        .iter()
        .filter(|(n, _)| !zboot_core::is_replication_anchor(n))
        .map(|(_, g)| g.as_str())
        .collect();
    Ok(right_pairs
        .into_iter()
        .filter(|(n, _)| !zboot_core::is_replication_anchor(n))
        .filter(|(_, g)| !left_guids.contains(g.as_str()))
        .map(|(n, _)| n)
        .collect())
}

/// Pure helper: given the source and dest `(name, guid)` lists (creation
/// order) and the full bound snapshot name (`<src_ds>@<snap>`), return
/// the dest snapshot names whose GUIDs match snapshots on src **after**
/// the bound. These are what a bounded push/pull would destroy via
/// `zfs rollback -r <dest>@<bound>`. Replication anchors are excluded
/// from the result (pruning lag, not operator-meaningful).
pub fn snapshots_after_bound_pure(
    src_pairs: &[(String, String)],
    dest_pairs: &[(String, String)],
    bound_full: &str,
) -> Vec<String> {
    let Some(bound_pos) = src_pairs.iter().position(|(n, _)| n == bound_full) else {
        return Vec::new();
    };
    let after_bound_guids: BTreeSet<&str> = src_pairs[bound_pos + 1..]
        .iter()
        .filter(|(n, _)| !zboot_core::is_replication_anchor(n))
        .map(|(_, g)| g.as_str())
        .collect();
    dest_pairs
        .iter()
        .filter(|(n, _)| !zboot_core::is_replication_anchor(n))
        .filter(|(_, g)| after_bound_guids.contains(g.as_str()))
        .map(|(n, _)| n.clone())
        .collect()
}

/// Wrapper that loads src and dest snapshot lists and applies
/// `snapshots_after_bound_pure`. Used by push/pull bounded rewind
/// detection.
pub fn dest_snapshots_after_bound(
    src_dataset: &str,
    dest_dataset: &str,
    bound_name: &str,
) -> Result<Vec<String>> {
    let src_pairs = list_snapshots_with_guids(src_dataset)?;
    let dest_pairs = list_snapshots_with_guids(dest_dataset)?;
    let bound_full = format!("{src_dataset}@{bound_name}");
    Ok(snapshots_after_bound_pure(&src_pairs, &dest_pairs, &bound_full))
}

// ---------------------------------------------------------------------------
// Typed-confirmation prompt — matches the deploy/drop pattern.
// ---------------------------------------------------------------------------

/// Format a bullet preview of up to 5 snapshot names, joined by
/// `\n      ` (six-space indent matching the surrounding refusal-message
/// format), with a trailing `... (N more)` line when truncated. Used by
/// the divergence/rewind refusal builders in push/pull.
pub fn format_snapshot_preview(snapshots: &[String]) -> String {
    let preview_n = std::cmp::min(5, snapshots.len());
    let mut body = snapshots[..preview_n].join("\n      ");
    if snapshots.len() > preview_n {
        body.push_str(&format!("\n      ... ({} more)", snapshots.len() - preview_n));
    }
    body
}

/// Print a preview of snapshots about to be destroyed, then require the
/// operator to type `expected` on stdin (newline-terminated) to confirm.
/// Returns Ok(()) on match, Err otherwise.
///
/// Lists up to 5 snapshots; appends "(N more)" if there are more.
pub fn confirm_destructive_truncate(
    label: &str,
    target_dataset: &str,
    snapshots_to_destroy: &[String],
) -> anyhow::Result<()> {
    use std::io::{BufRead, Write};
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{label}:");
    let preview_n = std::cmp::min(5, snapshots_to_destroy.len());
    for s in &snapshots_to_destroy[..preview_n] {
        let _ = writeln!(stderr, "    {s}");
    }
    if snapshots_to_destroy.len() > preview_n {
        let _ = writeln!(
            stderr,
            "    ... ({} more)",
            snapshots_to_destroy.len() - preview_n
        );
    }
    let _ = writeln!(
        stderr,
        "Type '{target_dataset}' to confirm overwrite (or anything else to abort):"
    );
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("reading confirmation from stdin")?;
    let got = line.trim();
    if got != target_dataset {
        anyhow::bail!(
            "confirmation mismatch (got {got:?}, expected {target_dataset:?}); aborting"
        );
    }
    Ok(())
}

/// Ensure `<pool>/ROOT` exists with canmount=off/mountpoint=none.
pub fn ensure_root_container(pool: &str) -> Result<()> {
    let root = format!("{pool}/ROOT");
    if !dataset_exists(&root).unwrap_or(false) {
        sub::zfs(&[
            "create",
            "-o",
            "canmount=off",
            "-o",
            "mountpoint=none",
            &root,
        ])
        .with_context(|| format!("creating ROOT container {root}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(name: &str, guid: &str) -> (String, String) {
        (name.to_owned(), guid.to_owned())
    }

    #[test]
    fn after_bound_empty_when_dest_at_bound() {
        // src has @A @B, dest has @A @B; bound = @B → nothing past it.
        let src = vec![
            pair("rpool/ROOT/be1@A", "1"),
            pair("rpool/ROOT/be1@B", "2"),
        ];
        let dest = vec![
            pair("rpool2/ROOT/be1@A", "1"),
            pair("rpool2/ROOT/be1@B", "2"),
        ];
        let out = snapshots_after_bound_pure(&src, &dest, "rpool/ROOT/be1@B");
        assert!(out.is_empty());
    }

    #[test]
    fn after_bound_finds_dest_past_bound() {
        // src has @A @B @C, dest has @A @B @C; bound = @B → dest @C is past.
        let src = vec![
            pair("rpool/ROOT/be1@A", "1"),
            pair("rpool/ROOT/be1@B", "2"),
            pair("rpool/ROOT/be1@C", "3"),
        ];
        let dest = vec![
            pair("rpool2/ROOT/be1@A", "1"),
            pair("rpool2/ROOT/be1@B", "2"),
            pair("rpool2/ROOT/be1@C", "3"),
        ];
        let out = snapshots_after_bound_pure(&src, &dest, "rpool/ROOT/be1@B");
        assert_eq!(out, vec!["rpool2/ROOT/be1@C"]);
    }

    #[test]
    fn after_bound_ignores_anchors() {
        // src has @A @B @mirror-99 @C; bound = @B. Anchor @mirror-99 must
        // not appear in the destroy list even if dest has it.
        let src = vec![
            pair("rpool/ROOT/be1@A", "1"),
            pair("rpool/ROOT/be1@B", "2"),
            pair("rpool/ROOT/be1@mirror-99", "9"),
            pair("rpool/ROOT/be1@C", "3"),
        ];
        let dest = vec![
            pair("rpool2/ROOT/be1@A", "1"),
            pair("rpool2/ROOT/be1@B", "2"),
            pair("rpool2/ROOT/be1@mirror-99", "9"),
            pair("rpool2/ROOT/be1@C", "3"),
        ];
        let out = snapshots_after_bound_pure(&src, &dest, "rpool/ROOT/be1@B");
        assert_eq!(out, vec!["rpool2/ROOT/be1@C"]);
    }

    #[test]
    fn after_bound_empty_when_bound_not_on_src() {
        // bound name doesn't match anything on src → empty (caller's
        // snapshot_exists check fires earlier in the real flow).
        let src = vec![pair("rpool/ROOT/be1@A", "1")];
        let dest = vec![pair("rpool2/ROOT/be1@A", "1")];
        let out = snapshots_after_bound_pure(&src, &dest, "rpool/ROOT/be1@missing");
        assert!(out.is_empty());
    }

    #[test]
    fn after_bound_skips_dest_only_snaps() {
        // dest has a snap whose GUID isn't on src — that's divergence
        // (handled separately), not "past the bound". Excluded here.
        let src = vec![
            pair("rpool/ROOT/be1@A", "1"),
            pair("rpool/ROOT/be1@B", "2"),
        ];
        let dest = vec![
            pair("rpool2/ROOT/be1@A", "1"),
            pair("rpool2/ROOT/be1@X", "99"),
        ];
        let out = snapshots_after_bound_pure(&src, &dest, "rpool/ROOT/be1@A");
        // @X's GUID 99 isn't on src, so it's not "past the bound on src".
        assert!(out.is_empty());
    }
}
