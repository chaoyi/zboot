//! `zboot snapshot` — snapshot the active BE.
//!
//! Pipeline: find the active BE (the one whose dataset matches its
//! pool's `bootfs`) → `zfs snapshot <bootfs-dataset>@<name>`. That's it.
//!
//! Bound datasets (e.g. `/home`) are intentionally out of scope —
//! they're user data, not OS state. For multi-dataset point-in-time,
//! use `zfs snapshot ds1@n ds2@n …` directly.
//!
//! Default name: `snapshot-<UTC-timestamp>` (e.g.
//! `snapshot-20260509T143000Z`) — second-resolution, ZFS-safe.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use clap::Args;

use crate::sub;

use zboot_core::{
    BootEnvironment, Canmount, Mountpoint, Pool, Property, SnapshotRef, parse_zfs_get,
    parse_zpool_list,
};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct SnapshotArgs {
    /// Explicit snapshot name; default is `snapshot-<UTC-timestamp>`.
    #[arg(long)]
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: &SnapshotArgs, _out: &mut impl Write) -> Result<()> {
    let snap = pick_snapshot(args, &SystemClock)?;
    // Trace from `sub::zfs` is the success signal: `+ zfs snapshot <ds>@<name>`
    // (and a non-zero exit if it fails). No separate "Created ..." echo.
    sub::zfs(&["snapshot", &snap.render()])
        .with_context(|| format!("creating snapshot {}", snap.render()))
}

// ---------------------------------------------------------------------------
// Snapshot picking — pure logic, given a state snapshot + clock + name.
// Split from I/O so cargo tests don't need `zfs(8)`.
// ---------------------------------------------------------------------------

/// Minimal observed-state struct for snapshot picking.
#[derive(Debug, Clone, Default)]
struct Observed {
    pools: Vec<Pool>,
    bes: Vec<BootEnvironment>,
}

trait Clock {
    /// Seconds since UNIX epoch — leap-seconds ignored, same as ZFS itself.
    fn unix_secs(&self) -> u64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// I/O entry: collect state, then call [`pick_from_observed`].
fn pick_snapshot(args: &SnapshotArgs, clock: &impl Clock) -> Result<SnapshotRef> {
    let observed = collect_state()?;
    let snap_name = args
        .name
        .clone()
        .unwrap_or_else(|| default_snap_name(clock.unix_secs()));
    pick_from_observed(&observed, &snap_name)
}

fn pick_from_observed(observed: &Observed, snap_name: &str) -> Result<SnapshotRef> {
    let active = find_active_be(observed).ok_or_else(|| {
        anyhow!(
            "no active BE: no pool has `bootfs` set to a dataset tagged `zboot:be=true`. \
             Set `zpool set bootfs=<dataset> <pool>` and `zfs set zboot:be=true <dataset>` first."
        )
    })?;
    Ok(SnapshotRef {
        dataset: active.dataset.clone(),
        name: snap_name.to_owned(),
    })
}

fn find_active_be(observed: &Observed) -> Option<&BootEnvironment> {
    for pool in &observed.pools {
        let Some(bootfs) = pool.bootfs.as_deref() else {
            continue;
        };
        if let Some(be) = observed
            .bes
            .iter()
            .find(|b| b.pool == pool.name && b.dataset == bootfs)
        {
            return Some(be);
        }
    }
    None
}

/// Compact RFC-3339 UTC: `YYYYMMDDTHHMMSSZ`. Filesystem-friendly (no `:`),
/// pipeline-friendly (lexicographically sortable).
fn default_snap_name(unix_secs: u64) -> String {
    let (year, month, day, hour, minute, second) = civil_from_unix(unix_secs);
    format!("snapshot-{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// Convert UNIX seconds → (year, month, day, hour, minute, second) UTC.
///
/// Howard Hinnant's `days_from_civil` inverse, adapted to seconds. Valid
/// for the entire UNIX-epoch range; doesn't depend on `chrono` / `time`.
/// Operates in unsigned arithmetic for the post-1970 range we care about
/// (`SystemTime::now` since UNIX epoch is always non-negative); the era
/// shift is encoded as an offset rather than a signed split.
fn civil_from_unix(unix_secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    const SECS_PER_DAY: u64 = 86_400;
    let days = unix_secs / SECS_PER_DAY;
    let secs_of_day = u32::try_from(unix_secs % SECS_PER_DAY).unwrap_or(0);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Days since 1970-01-01 → civil date. Algorithm: shift epoch to
    // 0000-03-01, work in 400-year eras, derive year/month/day. We add
    // the constant 719_468 (days from 0000-03-01 to 1970-01-01) to keep
    // arithmetic in `u64`.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y_civil = i64::try_from(yoe + era * 400).unwrap_or(0);
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1); // [1, 31]
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1); // [1, 12]
    let year = if month <= 2 { y_civil + 1 } else { y_civil };

    (year, month, day, hour, minute, second)
}

// ---------------------------------------------------------------------------
// I/O — collect state via `zfs(8)` / `zpool(8)`.
//
// Mirrors `cmd::status::collect_state` shape. We don't import that function
// because (a) `status` builds a full `Forest` for orphan analysis we don't
// need here, (b) keeping verb modules independent matches the pattern the
// `cli/README.md` documents.
// ---------------------------------------------------------------------------

const ZFS_PROPS: &str = "origin,mountpoint,canmount,zboot:be,zboot:attached-to";
const POOL_PROPS: &str = "zboot:role";

fn collect_state() -> Result<Observed> {
    let pools_text = sub::cmd_capture("zpool", &["list", "-Hp", "-o", "name,bootfs,guid"])?;
    let mut pools = parse_zpool_list(&pools_text).context("parsing `zpool list`")?;

    if !pools.is_empty() {
        let pool_names: Vec<&str> = pools.iter().map(|p| p.name.as_str()).collect();
        let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", POOL_PROPS];
        args.extend(pool_names.iter().copied());
        let role_text = sub::cmd_capture("zpool", &args)?;
        let role_props = parse_zfs_get(&role_text).context("parsing `zpool get zboot:role`")?;
        annotate_pool_roles(&mut pools, &role_props);
    }

    let datasets_text = sub::cmd_capture("zfs", &["list", "-Hp", "-o", "name", "-t", "filesystem"])?;
    let datasets: Vec<String> = datasets_text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let zfs_props = if datasets.is_empty() {
        Vec::new()
    } else {
        let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", ZFS_PROPS];
        args.extend(datasets.iter().map(String::as_str));
        let text = sub::cmd_capture("zfs", &args)?;
        parse_zfs_get(&text).context("parsing `zfs get` for datasets")?
    };

    let bes = bes_from_props(&datasets, &zfs_props);

    Ok(Observed { pools, bes })
}

/// Collect just the BE list. Snapshot only acts on the active BE — no
/// need to enumerate bound datasets like `cmd::status` does.
fn bes_from_props(datasets: &[String], props: &[(String, Property)]) -> Vec<BootEnvironment> {
    use std::collections::HashMap;

    #[derive(Default)]
    struct Acc {
        is_be: bool,
        origin: Option<SnapshotRef>,
        mountpoint: Option<Mountpoint>,
        canmount: Option<Canmount>,
    }

    let mut by_ds: HashMap<&str, Acc> = datasets
        .iter()
        .map(|d| (d.as_str(), Acc::default()))
        .collect();

    for (name, prop) in props {
        let Some(acc) = by_ds.get_mut(name.as_str()) else {
            continue;
        };
        match prop {
            Property::ZbootBe(b) => acc.is_be = *b,
            Property::Origin(o) => acc.origin.clone_from(o),
            Property::Mountpoint(m) => acc.mountpoint = Some(m.clone()),
            Property::Canmount(c) => acc.canmount = Some(*c),
            _ => {}
        }
    }

    let mut bes = Vec::new();
    for ds in datasets {
        let Some(acc) = by_ds.get(ds.as_str()) else {
            continue;
        };
        if acc.is_be {
            let pool = ds.split('/').next().unwrap_or(ds);
            let name = ds.rsplit('/').next().unwrap_or(ds);
            let mut be = BootEnvironment::new(pool, name);
            be.dataset.clone_from(ds);
            be.origin.clone_from(&acc.origin);
            be.mountpoint.clone_from(&acc.mountpoint);
            be.canmount = acc.canmount;
            bes.push(be);
        }
    }
    bes
}

fn annotate_pool_roles(pools: &mut [Pool], props: &[(String, Property)]) {
    for (name, prop) in props {
        if let Property::ZbootRole(role) = prop
            && let Some(p) = pools.iter_mut().find(|p| &p.name == name)
        {
            p.role = Some(*role);
        }
    }
}

// Tests — pure-data picking + civil-time conversion. I/O is exercised
// by `scripts/lifecycle.sh`.

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(name: &str, bootfs: Option<&str>) -> Pool {
        let mut p = Pool::new(name);
        p.bootfs = bootfs.map(str::to_owned);
        p
    }

    fn be(pool: &str, name: &str) -> BootEnvironment {
        BootEnvironment::new(pool, name)
    }

    #[test]
    fn picks_active_be_dataset() {
        let observed = Observed {
            pools: vec![pool("rpool", Some("rpool/ROOT/be1"))],
            bes: vec![be("rpool", "be1")],
        };
        let snap = pick_from_observed(&observed, "snap-x").unwrap();
        assert_eq!(snap.dataset, "rpool/ROOT/be1");
        assert_eq!(snap.name, "snap-x");
    }

    #[test]
    fn fails_with_no_active_be() {
        let observed = Observed {
            pools: vec![pool("rpool", None)],
            bes: vec![be("rpool", "be1")],
        };
        let err = pick_from_observed(&observed, "snap").unwrap_err();
        assert!(err.to_string().contains("no active BE"), "{err}");
    }

    #[test]
    fn fails_when_bootfs_does_not_point_at_a_be() {
        let observed = Observed {
            pools: vec![pool("rpool", Some("rpool/ROOT/missing"))],
            bes: vec![be("rpool", "be1")],
        };
        assert!(pick_from_observed(&observed, "snap").is_err());
    }

    #[test]
    fn explicit_name_used_verbatim() {
        let observed = Observed {
            pools: vec![pool("rpool", Some("rpool/ROOT/be1"))],
            bes: vec![be("rpool", "be1")],
        };
        let snap = pick_from_observed(&observed, "my-named-snap").unwrap();
        assert_eq!(snap.name, "my-named-snap");
    }

    #[test]
    fn default_snap_name_format() {
        assert_eq!(default_snap_name(0), "snapshot-19700101T000000Z");
        let name = default_snap_name(1_700_000_000);
        assert!(name.starts_with("snapshot-"));
        assert!(name.ends_with('Z'));
        assert_eq!(name.len(), "snapshot-".len() + "YYYYMMDDTHHMMSSZ".len());
    }
}
