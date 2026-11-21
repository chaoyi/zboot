use crate::{Decision, Keep, owned_snap_time, plan, snap_name};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use std::fmt;

/// The proposed second-precision name is already present in the observation.
/// Re-observe before capture; a selection does not freeze native state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotNameCollision {
    pub name: String,
}
impl fmt::Display for SnapshotNameCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "snapshot name already exists: {}", self.name)
    }
}
impl std::error::Error for SnapshotNameCollision {}

/// Pure capture-name selection, in sorted dataset order. Detects collisions for
/// previews as well as real requests. No retry, sleeping or mutation occurs.
pub fn capture_names(
    datasets: &[String],
    existing_names: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<String>> {
    if datasets.is_empty() {
        bail!("refusing an empty snapshot set");
    }
    let mut seen = BTreeSet::new();
    for dataset in datasets {
        zfs_tools::engine::validate_dataset_name(dataset)?;
        if !seen.insert(dataset) {
            bail!("duplicate dataset in snapshot set: {dataset}");
        }
    }
    let existing: BTreeSet<_> = existing_names.iter().collect();
    let names: Vec<_> = seen.into_iter().map(|d| snap_name(d, now)).collect();
    for name in &names {
        if existing.contains(name) {
            return Err(SnapshotNameCollision { name: name.clone() }.into());
        }
    }
    Ok(names)
}

/// Plan one exact dataset's owned stream from observed full snapshot names.
/// Foreign namespaces, malformed timestamps and descendants are excluded.
/// Duplicate owned observations refuse planning. Native identities, roles,
/// holds, clone dependencies and pending operations must still be checked by
/// shared private engine before acting on any returned candidate.
pub fn dataset_plan(
    dataset: &str,
    observed_names: &[String],
    keep: &Keep,
    now: DateTime<Utc>,
) -> Result<Vec<Decision>> {
    zfs_tools::engine::validate_dataset_name(dataset)?;
    keep.validate_prune_override()?;
    let mut seen = BTreeSet::new();
    let mut snapshots = Vec::new();
    for name in observed_names {
        let Some(time) = owned_snap_time(name, dataset) else {
            continue;
        };
        if !seen.insert(name) {
            bail!("duplicate snapshot observation: {name}");
        }
        snapshots.push((name.clone(), time));
    }
    Ok(plan(&snapshots, keep, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    #[test]
    fn capture_set_collision_and_same_second_are_deterministic() {
        let datasets = vec!["p/b".into(), "p/a".into()];
        let names = capture_names(&datasets, &[], now()).unwrap();
        assert_eq!(
            names,
            vec![snap_name("p/a", now()), snap_name("p/b", now())]
        );
        let error = capture_names(&datasets, &names, now()).unwrap_err();
        assert_eq!(
            error.downcast_ref::<SnapshotNameCollision>().unwrap().name,
            names[0]
        );
        assert!(
            capture_names(
                &datasets,
                &names,
                now() + chrono::Duration::milliseconds(999)
            )
            .is_err()
        );
        assert!(capture_names(&datasets, &names, now() + chrono::Duration::seconds(1)).is_ok());
        assert!(capture_names(&[], &[], now()).is_err());
        assert!(capture_names(&["p/a".into(), "p/a".into()], &[], now()).is_err());
    }

    #[test]
    fn exact_dataset_namespace_and_ambiguous_observations() {
        let own = snap_name("p/a", now());
        let names = vec![
            own.clone(),
            snap_name("p/a/child", now()),
            snap_name("p/ab", now()),
            "p/a@manual".into(),
            "p/a@zsnap_invalid".into(),
        ];
        let keep = Keep {
            last: Some(0),
            ..Default::default()
        };
        let decisions = dataset_plan("p/a", &names, &keep, now()).unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].name, own);
        assert!(!decisions[0].kept());
        assert!(dataset_plan("p/a", &[own.clone(), own], &keep, now()).is_err());
        assert!(dataset_plan("p/a", &names, &Keep::default(), now()).is_err());
    }

    #[test]
    fn dataset_validation_matches_engine_for_spaces_and_leading_dash_components() {
        let spaced = "tank/a space";
        let captured = capture_names(&[spaced.into()], &[], now()).unwrap();
        assert_eq!(captured, vec![snap_name(spaced, now())]);
        let keep = Keep {
            last: Some(0),
            ..Default::default()
        };
        let decisions = dataset_plan(spaced, &captured, &keep, now()).unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].name, captured[0]);
        assert!(capture_names(&["tank/-flag".into()], &[], now()).is_err());
        assert!(dataset_plan("tank/-flag", &[], &keep, now()).is_err());
    }
}
