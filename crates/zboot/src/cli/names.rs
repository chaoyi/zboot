//! Pure target resolution from CLI spelling and one running-root context.
use zfs_tools::engine::Error;

/// Whether a valid target spelling needs the running boot environment.
/// `resolve` rejects invalid spellings before requesting running context.
pub(super) fn needs_running(written: Option<&str>) -> bool {
    match parts(written) {
        Ok((None, _)) => true,
        Ok((Some(dataset), _)) => !dataset.contains('/'),
        Err(_) => false,
    }
}

/// Resolve a target before planning, preserving explicit names and labels.
/// The running context is a ZFS root dataset with a parent. Its parent supplies
/// siblings. Both inputs determine the resolved name.
pub(crate) fn resolve(written: Option<&str>, running: Option<&str>) -> Result<String, Error> {
    let (dataset, snapshot) = parts(written)?;
    let dataset = match dataset {
        None => running_be(running)?.to_owned(),
        Some(dataset) if dataset.ends_with('/') => dataset[..dataset.len() - 1].to_owned(),
        Some(dataset) if dataset.contains('/') => dataset.to_owned(),
        Some(dataset) => {
            let running = running_be(running)?;
            let (parent, _) = running.rsplit_once('/').expect("running BE has a parent");
            format!("{parent}/{dataset}")
        }
    };
    match snapshot {
        Some(snapshot) => {
            let target = format!("{dataset}@{snapshot}");
            zfs_tools::engine::validate_snapshot_name(&target)?;
            Ok(target)
        }
        None => {
            zfs_tools::engine::validate_dataset_name(&dataset)?;
            Ok(dataset)
        }
    }
}

fn parts(written: Option<&str>) -> Result<(Option<&str>, Option<&str>), Error> {
    let Some(written) = written else {
        return Ok((None, None));
    };
    if written.is_empty() {
        return Err(Error::InvalidScope(written.into()));
    }
    let (dataset, snapshot) = match written.split_once('@') {
        Some((dataset, snapshot)) => {
            // Validate the label independently, before requesting running-root
            // context. The final snapshot validation binds its resolved base.
            zfs_tools::engine::validate_snapshot_name(&format!("validation@{snapshot}"))?;
            (dataset, Some(snapshot))
        }
        None => (written, None),
    };
    if dataset.is_empty() {
        return Ok((None, snapshot));
    }
    if let Some(pool) = dataset.strip_suffix('/') {
        if pool.contains('/') {
            return Err(Error::InvalidScope(written.into()));
        }
        zfs_tools::engine::validate_dataset_name(pool)?;
    } else {
        zfs_tools::engine::validate_dataset_name(dataset)?;
    }
    Ok((Some(dataset), snapshot))
}

fn running_be(running: Option<&str>) -> Result<&str, Error> {
    running
        .filter(|running| {
            running.contains('/') && zfs_tools::engine::validate_dataset_name(running).is_ok()
        })
        .ok_or_else(|| {
            Error::Refused(
                "this target needs a running ZFS boot environment with a parent. Write a full dataset name or NAME/ for a pool".into(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: Option<&str> = Some("a/ROOT/current");

    #[test]
    fn a_short_name_is_a_sibling_of_the_running_be() {
        assert_eq!(resolve(Some("try"), RUNNING).unwrap(), "a/ROOT/try");
        assert_eq!(resolve(None, RUNNING).unwrap(), "a/ROOT/current");
        assert_eq!(
            resolve(Some("@base"), RUNNING).unwrap(),
            "a/ROOT/current@base"
        );
        assert_eq!(resolve(Some("Try Now"), RUNNING).unwrap(), "a/ROOT/Try Now");
        assert_eq!(resolve(Some("try"), Some("a/current")).unwrap(), "a/try");
        assert!(needs_running(Some("try")));
        assert!(needs_running(None));
        assert!(needs_running(Some("@base")));
    }

    #[test]
    fn a_name_with_a_trailing_slash_is_the_pool_root() {
        assert_eq!(resolve(Some("a/"), None).unwrap(), "a");
        assert_eq!(resolve(Some("a/@base"), None).unwrap(), "a@base");
        assert!(!needs_running(Some("a/")));
        assert!(!needs_running(Some("a/@base")));
        for target in ["/", "a//", "a/ROOT/", "a/ROOT//@base", "a//@base"] {
            assert!(resolve(Some(target), RUNNING).is_err(), "{target}");
            assert!(!needs_running(Some(target)), "{target}");
        }
    }

    #[test]
    fn resolution_never_looks_at_what_exists() {
        let before = resolve(Some("try"), RUNNING).unwrap();
        let mut fake = crate::tree::fake::Fake::new();
        fake.pool("try", 3);
        fake.create("a/ROOT");
        fake.create("a/ROOT/try");
        assert_eq!(resolve(Some("try"), RUNNING).unwrap(), before);
        assert_eq!(resolve(Some("try/"), RUNNING).unwrap(), "try");
        fake.datasets.remove("a/ROOT/try");
        assert_eq!(resolve(Some("try"), RUNNING).unwrap(), before);
        assert_eq!(resolve(Some("b/new/child"), None).unwrap(), "b/new/child");
        assert!(!needs_running(Some("b/new/child")));
    }

    #[test]
    fn name_at_snap_is_split_before_it_is_resolved() {
        assert_eq!(
            resolve(Some("try@base"), RUNNING).unwrap(),
            "a/ROOT/try@base"
        );
        assert_eq!(
            resolve(Some("b/tree@Base Now"), None).unwrap(),
            "b/tree@Base Now"
        );
        assert!(!needs_running(Some("b/tree@Base Now")));
        assert!(needs_running(Some("try@base")));
        for target in [
            "",
            "@",
            "try@",
            "try@one@two",
            "try@one/two",
            "try@-base",
            "try@one#two",
            "a//child",
            "a/./child",
            "a/../child",
            "-try",
            "try\n",
        ] {
            assert!(resolve(Some(target), RUNNING).is_err(), "{target:?}");
            assert!(!needs_running(Some(target)), "{target:?}");
        }
    }

    #[test]
    fn short_names_are_refused_without_a_running_be() {
        for running in [
            None,
            Some("a"),
            Some("a/"),
            Some("a//current"),
            Some("a/ROOT/current@base"),
        ] {
            for written in [None, Some("try"), Some("@base"), Some("try@base")] {
                let error = resolve(written, running).unwrap_err().to_string();
                assert!(error.contains("full dataset name"), "{error}");
                assert!(error.contains("NAME/"), "{error}");
            }
            assert_eq!(
                resolve(Some("b/tree@base"), running).unwrap(),
                "b/tree@base"
            );
            assert_eq!(resolve(Some("b/"), running).unwrap(), "b");
        }
    }

    #[test]
    fn plans_and_typed_answers_use_full_names() {
        use crate::{
            consent,
            tree::{fake::Fake, rollback},
        };
        let mut fake = Fake::new();
        fake.create("a/ROOT");
        fake.create("a/ROOT/current");
        fake.create("a/ROOT/try");
        fake.create("a/ROOT/try/child");
        fake.running = RUNNING.map(str::to_owned);
        for dataset in ["a/ROOT/try", "a/ROOT/try/child"] {
            fake.snap(&format!("{dataset}@base"));
            fake.write(dataset);
            fake.snap(&format!("{dataset}@later"));
        }
        let resolved = resolve(Some("try@base"), RUNNING).unwrap();
        let plan = rollback::plan_with(&mut fake, &resolved).unwrap();
        let full_plan = rollback::plan_with(&mut fake, "a/ROOT/try@base").unwrap();
        assert_eq!(plan, full_plan);
        assert_eq!(plan.root.name, "a/ROOT/try");
        assert!(
            plan.members
                .iter()
                .all(|member| member.dataset.name.starts_with("a/ROOT/try")
                    && member.target.name.starts_with("a/ROOT/try"))
        );
        let token = rollback::consent(&plan).unwrap();
        assert_eq!(token, rollback::consent(&full_plan).unwrap());
        assert_eq!(token, consent::token(&(rollback::KIND, &plan)).unwrap());
        let shown = rollback::describe(&plan, &token);
        assert!(shown.contains("a/ROOT/try"), "{shown}");
        assert!(shown.contains("a/ROOT/try/child@later"), "{shown}");
        let typed = rollback::typed(&plan);
        assert_eq!(typed.text, "a/ROOT/try@base");
        let mut prompt = Vec::new();
        assert_eq!(
            consent::decide(
                &consent::Mode::Interactive,
                &token,
                &typed,
                &mut "a/ROOT/try@base\n".as_bytes(),
                &mut prompt
            )
            .unwrap(),
            consent::Decision::Proceed { replan: true }
        );
        assert!(
            String::from_utf8(prompt)
                .unwrap()
                .contains("a/ROOT/try@base")
        );
        assert_eq!(
            consent::decide(
                &consent::Mode::Interactive,
                &token,
                &typed,
                &mut "try@base\n".as_bytes(),
                &mut Vec::new()
            )
            .unwrap(),
            consent::Decision::Unconfirmed
        );
        assert_eq!(fake.writes, 0);
    }
}
