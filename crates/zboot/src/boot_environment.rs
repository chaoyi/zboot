//! Shared, mount-free boot-root discovery and native role admission.
//!
//! A root-shaped dataset is a candidate, not proof of boot assets. Consumers
//! separately inspect its kernel/initrd pairs and apply command-line policy.
use crate::menu::RecoveryError as Error;
use zfs_tools::engine::{
    Dataset, DatasetKind,
    management::{self, Ownership},
    operation::SnapshotScope,
    pool_of,
    state::NativeState,
};

/// Shape also establishes ownership of automount hazards. A fenced root must
/// not disappear from that accounting merely because it cannot currently boot.
/// Native displayed mountpoints include the bound pool altroot; remove it once.
pub(crate) fn is_root(state: &NativeState, dataset: &Dataset) -> bool {
    if dataset.kind != DatasetKind::Filesystem {
        return false;
    }
    let altroot = state
        .pool_properties
        .get(pool_of(&dataset.name))
        .and_then(|properties| properties.get("altroot"))
        .map(|property| property.value.as_str());
    dataset.mountpoint.as_deref().is_some_and(|mountpoint| {
        crate::placement::mountpoint_without_altroot(mountpoint, altroot)
            .is_ok_and(|mountpoint| mountpoint == "/")
    })
}

/// Imported root candidates plus observed native defaults, including blocked
/// defaults whose shape is invalid. Private restore workspaces are excluded
/// unless a native default points into one, which must remain diagnosable.
pub(crate) fn roots(state: &NativeState) -> Vec<&Dataset> {
    let mut roots: Vec<_> = state
        .inspection
        .datasets
        .iter()
        .filter(|dataset| {
            let default = state
                .inspection
                .pools
                .iter()
                .any(|pool| pool.bootfs.as_ref() == Some(&dataset.name));
            default
                || (is_root(state, dataset)
                    && !crate::handoff::is_guided_restore_workspace_dataset(&dataset.name))
        })
        .collect();
    roots.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    roots
}

/// Admit only native identity and supported boot roles. This performs no I/O
/// and grants no kernel or command-line evidence.
/// The returned scope binds the complete recursive tree for later revalidation.
pub(crate) fn admit(state: &NativeState, name: &str) -> Result<(SnapshotScope, Ownership), Error> {
    // Report the intentional secondary role before working-tree admission.
    let ownership = root_ownership(state, name)?;
    if matches!(ownership, Ownership::Secondary { .. }) {
        return Err(Error::Refused(
            "secondary cannot boot as a writable environment".into(),
        ));
    }
    let scope = SnapshotScope::plan_readonly_working(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
        &[name.to_owned()],
    )?;
    Ok((scope, ownership))
}

/// Restore may read a valid secondary as a copy source, without granting it a
/// writable boot role. Restore still binds its recursive identities/snapshots
/// independently; this helper validates shape and every member's native role.
pub(crate) fn admit_restore_source(state: &NativeState, name: &str) -> Result<Ownership, Error> {
    let ownership = root_ownership(state, name)?;
    if matches!(ownership, Ownership::Secondary { .. }) {
        for dataset in state
            .inspection
            .datasets
            .iter()
            .filter(|dataset| crate::history::contains_dataset(name, &dataset.name))
        {
            management::ownership(state, &dataset.name)?;
        }
        Ok(ownership)
    } else {
        admit(state, name).map(|(_, ownership)| ownership)
    }
}

fn root_ownership(state: &NativeState, name: &str) -> Result<Ownership, Error> {
    if crate::handoff::is_guided_restore_workspace_dataset(name) {
        return Err(Error::Refused(
            "guided restore workspace cannot boot".into(),
        ));
    }
    let dataset = state
        .inspection
        .datasets
        .iter()
        .find(|dataset| dataset.name == name)
        .ok_or_else(|| Error::Refused("selected BE was not observed".into()))?;
    if !is_root(state, dataset) {
        return Err(Error::Refused(
            "boot eligibility requires a filesystem with mountpoint=/".into(),
        ));
    }
    Ok(management::ownership(state, name)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Backend, fake::Fake};
    use zfs_tools::engine::native::NativeProperty;

    fn fixture() -> Fake {
        let mut fake = Fake::new();
        fake.create("a/root");
        fake.create("a/root/var");
        fake.create("a/data");
        fake.set("a/root", "mountpoint", "/");
        fake.set("a/root", "canmount", "noauto");
        fake
    }

    #[test]
    fn a_root_without_a_marker_is_listed_and_a_fenced_one_is_not() {
        let mut fake = fixture();
        fake.create("a/fenced");
        fake.set("a/fenced", "mountpoint", "/");
        fake.set("a/fenced", "zboot:pending", "unfinished");
        let state = fake.observe().unwrap();
        // Mount-free candidates retain the fence for diagnosis and hazards;
        // only admitted roots may proceed to a consumer's kernel inspection.
        assert_eq!(roots(&state).len(), 2);
        let admitted: Vec<_> = roots(&state)
            .into_iter()
            .filter(|dataset| admit(&state, &dataset.name).is_ok())
            .map(|dataset| dataset.name.as_str())
            .collect();
        assert_eq!(admitted, ["a/root"]);
        assert!(
            admit(&state, "a/data")
                .unwrap_err()
                .to_string()
                .contains("mountpoint=/")
        );
    }

    #[test]
    fn a_dataset_with_an_unknown_zboot_property_is_not_bootable() {
        let mut fake = fixture();
        fake.set("a/root/var", "zboot:future-role", "unknown");
        let state = fake.observe().unwrap();
        assert!(
            admit(&state, "a/root")
                .unwrap_err()
                .to_string()
                .contains("zboot:future-role")
        );
        assert_eq!(&roots(&state)[0].name, "a/root");
    }

    #[test]
    fn legacy_marker_values_and_sources_do_not_change_classification() {
        let mut fake = fixture();
        fake.set("a/root", "zboot:be", "1");
        fake.set("a/data", "zboot:be", "1");
        for (value, source) in [
            ("1", "local"),
            ("0", "local"),
            ("arbitrary legacy value", "received"),
            ("1", "inherited from a"),
        ] {
            let mut state = fake.observe().unwrap();
            for name in ["a/root", "a/data"] {
                state.dataset_properties.get_mut(name).unwrap().insert(
                    "zboot:be".into(),
                    NativeProperty {
                        value: value.into(),
                        source: source.into(),
                    },
                );
            }
            assert_eq!(
                roots(&state)
                    .iter()
                    .map(|dataset| dataset.name.as_str())
                    .collect::<Vec<_>>(),
                ["a/root"]
            );
            admit(&state, "a/root").unwrap();
        }
    }

    #[test]
    fn native_identity_and_descendant_roles_are_revalidated_without_mounting() {
        let fake = fixture();
        let mut state = fake.state().unwrap();
        state
            .dataset_properties
            .get_mut("a/root")
            .unwrap()
            .get_mut("guid")
            .unwrap()
            .value = "999999".into();
        assert!(admit(&state, "a/root").is_err());
        let mut state = fake.state().unwrap();
        state
            .dataset_properties
            .get_mut("a/root/var")
            .unwrap()
            .insert(
                "zboot:staging".into(),
                NativeProperty {
                    value: "private".into(),
                    source: "local".into(),
                },
            );
        assert!(
            admit(&state, "a/root")
                .unwrap_err()
                .to_string()
                .contains("staging")
        );
        assert_eq!(fake.writes, 0);
    }

    #[test]
    fn root_shape_removes_only_its_bound_native_pool_altroot() {
        let fake = fixture();
        let mut state = fake.state().unwrap();
        state.pool_properties.get_mut("a").unwrap().insert(
            "altroot".into(),
            NativeProperty {
                value: "/ram/import".into(),
                source: "local".into(),
            },
        );
        let dataset = state
            .inspection
            .datasets
            .iter_mut()
            .find(|dataset| dataset.name == "a/root")
            .unwrap();
        dataset.mountpoint = Some("/ram/import".into());
        assert_eq!(
            roots(&state)
                .iter()
                .map(|dataset| dataset.name.as_str())
                .collect::<Vec<_>>(),
            ["a/root"]
        );
        admit(&state, "a/root").unwrap();
        for mountpoint in [
            "/ram/import/var",
            "/ram/imported",
            "/ram/import/ram/import",
            "/",
        ] {
            state
                .inspection
                .datasets
                .iter_mut()
                .find(|dataset| dataset.name == "a/root")
                .unwrap()
                .mountpoint = Some(mountpoint.into());
            assert!(roots(&state).is_empty(), "{mountpoint}");
            assert!(admit(&state, "a/root").is_err(), "{mountpoint}");
        }
    }

    #[test]
    fn secondary_role_refuses_assets_but_keeps_the_root_candidate() {
        let mut fake = fixture();
        fake.create("b/primary");
        fake.set("a/root", "readonly", "on");
        fake.set("a/root/var", "canmount", "noauto");
        let record = management::PairRecord {
            schema_version: 1,
            pair_id: uuid::Uuid::new_v4().to_string(),
            endpoint: management::Endpoint {
                name: "a/root".into(),
                identity: fake.identity("a/root"),
            },
            peer: management::Endpoint {
                name: "b/primary".into(),
                identity: fake.identity("b/primary"),
            },
            role: management::Role::Secondary,
        };
        fake.set(
            "a/root",
            management::PAIR_PROPERTY,
            &record.encode().unwrap(),
        );
        fake.set(
            "b/primary",
            management::PAIR_PROPERTY,
            &record.counterpart().encode().unwrap(),
        );
        let state = fake.observe().unwrap();
        assert_eq!(&roots(&state)[0].name, "a/root");
        assert!(
            admit(&state, "a/root")
                .unwrap_err()
                .to_string()
                .contains("secondary cannot boot")
        );
        assert!(matches!(
            admit_restore_source(&state, "a/root").unwrap(),
            Ownership::Secondary { .. }
        ));
        fake.set("a/root/var", "zboot:pending", "unfinished");
        assert!(admit_restore_source(&fake.observe().unwrap(), "a/root").is_err());
    }

    #[test]
    fn workspace_and_invalid_defaults_remain_blocked_diagnostic_roots() {
        let mut fake = fixture();
        let workspace = "a/zboot-restore-1111111111114111";
        fake.create(workspace);
        fake.set(workspace, "mountpoint", "/");
        assert_eq!(roots(&fake.observe().unwrap()).len(), 1);
        fake.pools.get_mut("a").unwrap().bootfs = Some(workspace.into());
        let state = fake.observe().unwrap();
        assert_eq!(roots(&state).len(), 2);
        assert!(
            admit(&state, workspace)
                .unwrap_err()
                .to_string()
                .contains("workspace")
        );
        fake.pools.get_mut("a").unwrap().bootfs = Some("a/data".into());
        let state = fake.observe().unwrap();
        assert!(roots(&state).iter().any(|dataset| dataset.name == "a/data"));
        assert!(admit(&state, "a/data").is_err());
    }
}
