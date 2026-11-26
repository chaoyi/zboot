//! Arm, cancel and consume a one-time boot selection under the writer lock.
use super::{BootSetting, metadata_admit};
use crate::{
    menu::{Result, cleanup_error, pool_access::Writable, refuse},
    once::{PROPERTY, selected, value},
    tree::{self, Backend, Effect},
};
use serde::Serialize;
use zfs_tools::engine::{escape_display, management::Endpoint, pool_of, state::NativeState};

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Plan {
    target: Endpoint,
    clear: bool,
    prior: Option<String>,
    /// The admitted recursive scope and ownership when arming.
    binding: Option<String>,
}

pub(crate) fn describe(plan: &Plan) -> String {
    let name = escape_display(&plan.target.name);
    if plan.clear {
        format!("Clear the one-time boot selection on {name}.\n")
    } else {
        format!("Select {name} for the next automatic boot.\n")
    }
}

pub(crate) fn available(state: &NativeState, target: &str) -> Result<()> {
    if let Some(other) = selected(state)?
        && other.name != target
    {
        let other = escape_display(&other.name);
        return Err(refuse(format!(
            "{other} is already selected for one boot; cancel it with zboot default {other} --clear-once first"
        )));
    }
    Ok(())
}

fn from_state(state: &NativeState, name: &str, clear: bool) -> Result<Plan> {
    let target = tree::endpoint(tree::dataset(state, name)?);
    super::default::bound(state, &target)?;
    let binding = if clear {
        // A fork may have written the request just before its publication
        // checkpoint. Only its resume or abandon may retire it in that window.
        if tree::local(state, name, PROPERTY).is_some()
            && [
                zfs_tools::engine::management::PENDING_PROPERTY,
                zfs_tools::engine::management::STAGING_PROPERTY,
            ]
            .iter()
            .any(|key| tree::property(state, name, key).is_some())
        {
            return Err(refuse(
                "one-time boot target is staging or pending; resume or abandon its operation first",
            ));
        }
        None
    } else {
        available(state, name)?;
        let (scope, owner, cmdline) = metadata_admit(state, name, &BootSetting::Default)?;
        Some(tree::digest(&(scope, owner, cmdline))?)
    };
    Ok(Plan {
        target,
        clear,
        prior: tree::local(state, name, PROPERTY).map(str::to_owned),
        binding,
    })
}

fn plan_with(backend: &mut impl Backend, name: &str, clear: bool) -> Result<Plan> {
    let before = from_state(&backend.observe()?, name, clear)?;
    if !clear {
        backend.verify_boot_assets(name)?;
        if from_state(&backend.observe()?, name, clear)? != before {
            return Err(refuse(
                "one-time boot target changed during kernel inspection",
            ));
        }
    }
    Ok(before)
}

pub(crate) fn plan(name: &str, clear: bool) -> Result<Plan> {
    plan_with(&mut tree::Native, name, clear)
}

pub(crate) fn execute(plan: &Plan) -> Result<()> {
    execute_with(&mut tree::Native, plan)
}

fn execute_with(backend: &mut impl Backend, plan: &Plan) -> Result<()> {
    let name = &plan.target.name;
    if plan_with(backend, name, plan.clear)? != *plan {
        return Err(refuse(
            "one-time boot target or selection changed; preview again",
        ));
    }
    let desired = (!plan.clear).then(|| value(&plan.target.identity));
    if plan.prior == desired {
        return Ok(());
    }
    let effect = match &desired {
        Some(value) => Effect::Set {
            at: plan.target.clone(),
            key: PROPERTY.into(),
            value: value.clone(),
        },
        None => Effect::Inherit {
            at: plan.target.clone(),
            key: PROPERTY.into(),
        },
    };
    let outcome = backend.apply(&effect);
    let state = backend.observe()?;
    super::default::bound(&state, &plan.target)?;
    if tree::local(&state, name, PROPERTY) != desired.as_deref() {
        outcome?;
        return Err(refuse("one-time boot property change was not verified"));
    }
    if !plan.clear {
        available(&state, name)?;
    }
    Ok(())
}

fn consumption_plan(state: &NativeState, expected: &Endpoint) -> Result<Plan> {
    if selected(state)?.map(tree::endpoint).as_ref() != Some(expected) {
        return Err(refuse("one-time boot selection changed before consumption"));
    }
    from_state(state, &expected.name, true)
}

fn consume_with(backend: &mut impl Backend, expected: &Endpoint) -> Result<()> {
    let plan = consumption_plan(&backend.observe()?, expected)?;
    execute_with(backend, &plan)?;
    if selected(&backend.observe()?)?.is_some() {
        return Err(refuse(
            "another one-time boot selection appeared during consumption",
        ));
    }
    Ok(())
}

/// Called after kexec staging has released every mount, under the handoff lock.
pub(crate) fn consume(expected: &Endpoint) -> Result<()> {
    consumption_plan(&tree::Native.observe()?, expected)?;
    crate::handoff::require_no_hibernation_image()?;
    let mut writable = Writable::new();
    let result = writable
        .open(
            &[(
                pool_of(&expected.name).to_owned(),
                expected.identity.pool_guid,
            )]
            .into(),
        )
        .and_then(|()| consume_with(&mut tree::Native, expected));
    if let Err(error) = writable.close() {
        return Err(cleanup_error(
            result,
            "restore read-only pool import after one-time selection",
            error,
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::fake::Fake;

    fn fixture() -> Fake {
        let mut fake = Fake::new();
        for name in ["a/stable", "a/trial"] {
            fake.create(name);
            fake.set(name, "mountpoint", "/");
            fake.set(name, "canmount", "noauto");
        }
        fake.pools.get_mut("a").unwrap().bootfs = Some("a/stable".into());
        fake
    }

    #[test]
    fn arm_and_consume_only_the_exact_target_and_keep_bootfs() {
        let mut fake = fixture();
        let plan = plan_with(&mut fake, "a/trial", false).unwrap();
        assert!(selected(&fake.state().unwrap()).unwrap().is_none());
        execute_with(&mut fake, &plan).unwrap();
        assert!(plan_with(&mut fake, "a/stable", false).is_err());
        let stable = tree::endpoint(tree::dataset(&fake.state().unwrap(), "a/stable").unwrap());
        assert!(consume_with(&mut fake, &stable).is_err());
        consume_with(&mut fake, &plan.target).unwrap();
        assert!(consume_with(&mut fake, &plan.target).is_err());
        assert_eq!(fake.pools["a"].bootfs.as_deref(), Some("a/stable"));
    }

    #[test]
    fn cancel_can_repair_a_malformed_local_mark_without_probing_assets() {
        let mut fake = fixture();
        fake.missing_boot_assets.insert("a/trial".into());
        assert!(plan_with(&mut fake, "a/trial", false).is_err());
        fake.set("a/trial", PROPERTY, "broken");
        let plan = plan_with(&mut fake, "a/trial", true).unwrap();
        fake.set("a/trial", PROPERTY, "changed");
        assert!(execute_with(&mut fake, &plan).is_err());
        let fresh = plan_with(&mut fake, "a/trial", true).unwrap();
        execute_with(&mut fake, &fresh).unwrap();
        assert!(selected(&fake.state().unwrap()).unwrap().is_none());
    }
}
