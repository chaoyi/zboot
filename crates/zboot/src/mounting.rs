//! Native automount hazards inside boot environments.

use zfs_tools::engine::{CanMount, DatasetKind, state::NativeState};

/// Every `canmount=on` filesystem inside a boot environment, including its
/// root, sorted by dataset name. Filesystem mountpoint=/ shape or a native
/// default establishes a root, even when boot roles fence that candidate.
#[cfg(test)]
pub(crate) fn automount_in_boot_environments(state: &NativeState) -> Vec<String> {
    owned_automounts(state)
        .into_iter()
        .map(|(_, dataset)| dataset.to_owned())
        .collect()
}

/// Explain the hazards owned by boot environments other than `except`.
/// An explicitly booted owner may still boot so its own properties can be fixed.
pub(crate) fn refusal(state: &NativeState, except: Option<&str>) -> Option<String> {
    let hazards: Vec<_> = owned_automounts(state)
        .into_iter()
        .filter(|(root, _)| Some(*root) != except)
        .map(|(_, dataset)| {
            let dataset = zfs_tools::engine::escape_display(dataset);
            let consequence = match except {
                Some(target) => format!("would mount over {}", zfs_tools::engine::escape_display(target)),
                None => "would mount over another boot environment".into(),
            };
            format!(
                "{dataset} has canmount=on and {consequence}; fix with `zfs set canmount=noauto {dataset}`"
            )
        })
        .collect();
    (!hazards.is_empty()).then(|| hazards.join("; "))
}

/// Hazard ownership uses shape, independently of boot-role eligibility. Native
/// defaults remain visible even when their shape is invalid.
pub(crate) fn boot_environment_roots(state: &NativeState) -> Vec<&str> {
    crate::boot_environment::roots(state)
        .into_iter()
        .map(|dataset| dataset.name.as_str())
        .collect()
}

/// The nearest shaped/default boot root strictly above `name`. Stock
/// initramfs scripts mount every descendant except canmount=off, including
/// noauto filesystems whose mountpoint=none falls back to org.zol:mountpoint.
/// A destination equal to a BE root retains its own role and is allowed.
pub(crate) fn ancestor_boot_environment<'a>(state: &'a NativeState, name: &str) -> Option<&'a str> {
    boot_environment_roots(state)
        .into_iter()
        .filter(|root| *root != name && crate::history::contains_dataset(root, name))
        .max_by_key(|root| root.len())
}

/// Admit a destination whose data will not be traversed while another BE
/// boots. Roles are applied only to owned members; unrelated ancestors stay
/// untouched.
pub(crate) fn require_outside_boot_environment(
    state: &NativeState,
    name: &str,
) -> Result<(), zfs_tools::engine::Error> {
    if let Some(root) = ancestor_boot_environment(state, name) {
        return Err(zfs_tools::engine::Error::Refused(format!(
            "destination {} is inside boot environment {}; stock initramfs mounts descendants even with canmount=noauto; choose a destination outside that boot environment",
            zfs_tools::engine::escape_display(name),
            zfs_tools::engine::escape_display(root)
        )));
    }
    Ok(())
}

/// Each `canmount=on` filesystem inside a boot environment, with the nearest
/// boot environment it is inside: (root, dataset), by dataset.
pub(crate) fn owned_automounts(state: &NativeState) -> Vec<(&str, &str)> {
    let roots = boot_environment_roots(state);
    let mut hazards: Vec<_> = state
        .inspection
        .datasets
        .iter()
        .filter(|dataset| {
            dataset.kind == DatasetKind::Filesystem && dataset.canmount == Some(CanMount::On)
        })
        .filter_map(|dataset| {
            let name = dataset.name.as_str();
            roots
                .iter()
                .copied()
                .filter(|root| crate::history::contains_dataset(root, name))
                .max_by_key(|root| root.len())
                .map(|root| (root, name))
        })
        .collect();
    hazards.sort_unstable_by_key(|(_, dataset)| *dataset);
    hazards
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Backend, fake::Fake};

    fn fixture() -> Fake {
        let mut fake = Fake::new();
        for name in [
            "a/ROOT",
            "a/ROOT/be",
            "a/ROOT/be/var",
            "a/ROOT/be/var/log",
            "a/ROOT/b",
            "a/data",
            "a/data/files",
        ] {
            fake.create(name);
            fake.set(name, "canmount", "noauto");
        }
        fake.set("a/ROOT/be", "mountpoint", "/");
        fake.set("a/ROOT/b", "mountpoint", "/");
        fake
    }

    #[test]
    fn ancestor_checks_share_shape_roots_and_exclude_the_destination_itself() {
        let mut fake = fixture();
        let mut state = fake.observe().unwrap();
        assert_eq!(ancestor_boot_environment(&state, "a/ROOT/be"), None);
        assert_eq!(
            ancestor_boot_environment(&state, "a/ROOT/be/var"),
            Some("a/ROOT/be")
        );
        assert_eq!(
            ancestor_boot_environment(&state, "a/ROOT/between/var"),
            None
        );
        assert_eq!(ancestor_boot_environment(&state, "a/data/files"), None);
        fake.set("a/ROOT/be/var", "mountpoint", "/");
        state = fake.observe().unwrap();
        assert_eq!(
            ancestor_boot_environment(&state, "a/ROOT/be/var/log"),
            Some("a/ROOT/be/var")
        );
    }

    #[test]
    fn default_roots_count_and_guided_workspaces_count_only_when_default() {
        let mut fake = fixture();
        let guided = "a/zboot-restore-1111111111114111";
        fake.create(guided);
        fake.set(guided, "mountpoint", "/");
        let mut state = fake.observe().unwrap();
        assert_eq!(
            ancestor_boot_environment(&state, &format!("{guided}/child")),
            None
        );
        fake.pools.get_mut("a").unwrap().bootfs = Some(guided.into());
        state = fake.observe().unwrap();
        assert_eq!(
            ancestor_boot_environment(&state, &format!("{guided}/child")),
            Some(guided)
        );
        assert_eq!(ancestor_boot_environment(&state, guided), None);
        assert!(
            require_outside_boot_environment(&state, &format!("{guided}/child"))
                .unwrap_err()
                .to_string()
                .contains("stock initramfs mounts descendants")
        );
        fake.pools.get_mut("a").unwrap().bootfs = Some("a/data".into());
        state = fake.observe().unwrap();
        assert_eq!(
            ancestor_boot_environment(&state, "a/data/files"),
            Some("a/data")
        );
    }

    #[test]
    fn roots_and_descendants_count_but_unrelated_data_and_volumes_do_not() {
        let mut fake = fixture();
        for name in ["a/ROOT/be", "a/ROOT/be/var", "a/data", "a/data/files"] {
            fake.set(name, "canmount", "on");
        }
        fake.datasets.get_mut("a/ROOT/be/var/log").unwrap().volume = true;
        let state = fake.observe().unwrap();
        assert_eq!(
            automount_in_boot_environments(&state),
            ["a/ROOT/be", "a/ROOT/be/var"]
        );
        assert_eq!(refusal(&state, Some("a/ROOT/be")), None);
        let reason = refusal(&state, Some("a/ROOT/b")).unwrap();
        assert!(reason.contains("a/ROOT/be/var has canmount=on and would mount over a/ROOT/b"));
        assert!(reason.contains("`zfs set canmount=noauto a/ROOT/be/var`"));
    }

    #[test]
    fn the_nearest_nested_shape_root_owns_its_hazards() {
        let mut fake = fixture();
        fake.set("a/ROOT/be/var", "mountpoint", "/");
        fake.set("a/ROOT/be/var", "canmount", "on");
        fake.set("a/ROOT/be/var/log", "canmount", "on");
        let state = fake.observe().unwrap();
        assert_eq!(refusal(&state, Some("a/ROOT/be/var")), None);
        assert!(refusal(&state, Some("a/ROOT/be")).is_some());
        assert_eq!(
            owned_automounts(&state),
            [
                ("a/ROOT/be/var", "a/ROOT/be/var"),
                ("a/ROOT/be/var", "a/ROOT/be/var/log")
            ]
        );
    }

    #[test]
    fn fenced_root_shapes_keep_their_automount_hazards() {
        for property in ["zboot:pending", "zboot:staging", "zboot:future-role"] {
            let mut fake = fixture();
            fake.set("a/ROOT/be", property, "fenced");
            fake.set("a/ROOT/be/var/log", "canmount", "on");
            let state = fake.observe().unwrap();
            assert!(crate::boot_environment::admit(&state, "a/ROOT/be").is_err());
            assert_eq!(
                automount_in_boot_environments(&state),
                ["a/ROOT/be/var/log"]
            );
            assert!(
                refusal(&state, Some("a/ROOT/b"))
                    .unwrap()
                    .contains("a/ROOT/be/var/log")
            );
        }
    }

    #[test]
    fn inventory_and_refusals_are_sorted_independently_of_observation_order() {
        let mut fake = fixture();
        for name in ["a/ROOT/be", "a/ROOT/be/var/log", "a/ROOT/b"] {
            fake.set(name, "canmount", "on");
        }
        let mut state = fake.observe().unwrap();
        let reason = refusal(&state, None);
        state.inspection.datasets.reverse();
        assert_eq!(
            automount_in_boot_environments(&state),
            ["a/ROOT/b", "a/ROOT/be", "a/ROOT/be/var/log"]
        );
        assert_eq!(refusal(&state, None), reason);
    }

    #[test]
    fn pool_defaults_establish_roots_even_without_root_shape() {
        let mut fake = fixture();
        fake.pools.get_mut("a").unwrap().bootfs = Some("a/data".into());
        fake.set("a/data/files", "canmount", "on");
        let state = fake.observe().unwrap();
        assert_eq!(automount_in_boot_environments(&state), ["a/data/files"]);
        assert_eq!(refusal(&state, Some("a/data")), None);
    }

    #[test]
    fn guided_restore_workspaces_are_excluded_unless_they_are_pool_defaults() {
        let mut fake = fixture();
        let workspace = "a/zboot-restore-0123456789abcdef";
        let root = format!("{workspace}/be");
        let child = format!("{root}/var");
        for name in [workspace, &root, &child] {
            fake.create(name);
            fake.set(name, "canmount", "on");
        }
        fake.set(&root, "mountpoint", "/");
        assert!(automount_in_boot_environments(&fake.observe().unwrap()).is_empty());
        fake.pools.get_mut("a").unwrap().bootfs = Some(root.clone());
        let state = fake.observe().unwrap();
        assert_eq!(
            automount_in_boot_environments(&state),
            [root.as_str(), &child]
        );
        assert_eq!(refusal(&state, Some(&root)), None);
    }
}
