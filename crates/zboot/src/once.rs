//! A one-time boot request lives on the BE itself. Only imported pools
//! participate; a detached disk retains its request until it is seen again.
use crate::menu::{Result, refuse};
use zfs_tools::engine::{Dataset, DatasetIdentity, management, state::NativeState};

pub(crate) use management::ONCE_PROPERTY as PROPERTY;

pub(crate) fn value(identity: &DatasetIdentity) -> String {
    format!("{}:{}", identity.pool_guid, identity.guid)
}

/// Return the one local request, retaining blocked BEs for the menu to
/// diagnose. Neither inherited properties nor received copies are requests.
pub(crate) fn selected(state: &NativeState) -> Result<Option<&Dataset>> {
    let mut target: Option<&Dataset> = None;
    for dataset in &state.inspection.datasets {
        let Some(mark) = state
            .dataset_properties
            .get(&dataset.name)
            .and_then(|properties| properties.get(PROPERTY))
            .filter(|property| property.source == "local")
        else {
            continue;
        };
        management::bound_properties(state, &dataset.name)?;
        if mark.value != value(&dataset.identity)
            || crate::handoff::is_guided_restore_workspace_dataset(&dataset.name)
            || !crate::boot_environment::is_root(state, dataset)
        {
            return Err(refuse(format!(
                "invalid one-time boot marker on {}; inspect this dataset before clearing its request",
                dataset.name
            )));
        }
        if let Some(other) = target {
            return Err(refuse(format!(
                "conflicting one-time boot requests on {} and {}; clear the unwanted request",
                other.name, dataset.name
            )));
        }
        target = Some(dataset);
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::fake::Fake;

    #[test]
    fn only_the_unique_locally_marked_boot_identity_is_selected() {
        let mut fake = Fake::new();
        for name in ["a/first", "a/second"] {
            fake.create(name);
            fake.set(name, "mountpoint", "/");
        }
        let mut state = fake.state().unwrap();
        let identity = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == "a/first")
            .unwrap()
            .identity
            .clone();
        let mark = zfs_tools::engine::native::NativeProperty {
            value: value(&identity),
            source: "local".into(),
        };
        state
            .dataset_properties
            .get_mut("a/first")
            .unwrap()
            .insert(PROPERTY.into(), mark.clone());
        for source in ["inherited from a/first", "received"] {
            let mut copy = mark.clone();
            copy.source = source.into();
            state
                .dataset_properties
                .get_mut("a/second")
                .unwrap()
                .insert(PROPERTY.into(), copy);
            assert_eq!(selected(&state).unwrap().unwrap().name, "a/first");
        }
        state
            .dataset_properties
            .get_mut("a/second")
            .unwrap()
            .insert(PROPERTY.into(), mark);
        assert!(
            selected(&state)
                .unwrap_err()
                .to_string()
                .contains("invalid")
        );
        let second = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == "a/second")
            .unwrap();
        state
            .dataset_properties
            .get_mut("a/second")
            .unwrap()
            .get_mut(PROPERTY)
            .unwrap()
            .value = value(&second.identity);
        assert!(
            selected(&state)
                .unwrap_err()
                .to_string()
                .contains("conflicting")
        );
    }
}
