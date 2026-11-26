//! Destination placement and command lines are frozen local authority.
//! Native filesystem shape identifies roots. A new root always gets an
//! explicit command line, empty unless its source sets one.
use super::*;

pub(super) fn key(key: &str) -> bool {
    key == "zboot:cmdline"
}

pub(super) fn root(member: &Member) -> bool {
    member.kind == history::Kind::Filesystem && member.bound.mountpoint.as_deref() == Some("/")
}

fn authority<'a>(source: &'a Tree, destination: Option<&'a Tree>, relative: &str) -> &'a Member {
    destination
        .and_then(|tree| tree.members.get(relative))
        .unwrap_or(&source.members[relative])
}

/// Existing receiving placement wins; new members take frozen source shape.
/// Reject nested roots without requiring a kernel probe for a placement hazard.
pub(super) fn validate_publication(
    source: &Tree,
    destination: Option<&Tree>,
    destination_name: &str,
) -> Result<(), Error> {
    let mut roots = Vec::new();
    for relative in source.members.keys() {
        if root(authority(source, destination, relative)) {
            roots.push(mapped(destination_name, relative));
        }
    }
    for child in &roots {
        if let Some(parent) = roots
            .iter()
            .filter(|parent| *parent != child && history::contains_dataset(parent, child))
            .max_by_key(|parent| parent.len())
        {
            return Err(refuse(format!(
                "transfer would reproduce nested boot environment {} inside {}; select a scope that does not publish nested boot roots",
                zfs_tools::engine::escape_display(child),
                zfs_tools::engine::escape_display(parent)
            )));
        }
    }
    Ok(())
}

fn expected<'a>(operation: &'a TransferOperation, relative: &str) -> Option<&'a Member> {
    Some(authority(
        &operation.plan.source,
        operation.plan.destination.existing(),
        relative,
    ))
}

pub(super) fn verify(
    state: &NativeState,
    operation: &TransferOperation,
    relative: &str,
    received: &Member,
    inert: bool,
) -> Result<(), Error> {
    let intended = expected(operation, relative);
    let mut wanted: BTreeMap<String, String> = intended
        .into_iter()
        .flat_map(|m| m.properties.iter())
        .filter(|(k, _)| key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if operation
        .plan
        .destination
        .existing()
        .is_none_or(|t| !t.members.contains_key(relative))
        && root(intended.unwrap())
    {
        wanted
            .entry("zboot:cmdline".into())
            .or_insert_with(|| property_evidence("zboot:cmdline", ""));
    }
    let actual: BTreeMap<String, String> = received
        .properties
        .iter()
        .filter(|(k, _)| key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if actual != wanted {
        return Err(refuse(
            "received boot policy differs from frozen destination authority",
        ));
    }
    if let Some(intended) = intended {
        if (operation
            .plan
            .destination
            .existing()
            .is_some_and(|t| t.members.contains_key(relative))
            || root(intended))
            && !inert
            && received.bound.mountpoint != intended.bound.mountpoint
        {
            return Err(refuse("received mountpoint differs from frozen placement"));
        }
        if root(intended) {
            let props = management::bound_properties(state, &received.bound.endpoint.name)?;
            crate::handoff::compose_cmdline(
                &received.bound.endpoint.name,
                props.get("zboot:cmdline").map_or("", |p| p.value.as_str()),
            )
            .map_err(|e| refuse(e.to_string()))?;
        }
    }
    Ok(())
}

pub(super) fn preserve_existing(
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let Some(tree) = operation.plan.destination.existing() else {
        return Ok(());
    };
    for member in tree.members.values() {
        let fresh = PairBackend::observe(backend)?;
        verify_original_target(&fresh, operation, id, backend)?;
        verify_fenced(&fresh, tree)?;
        let props = backend.properties(&member.bound.endpoint)?;
        // OpenZFS receive -x forces inheritance for RECEIVED properties. Pin
        // only the receiver's same captured value; local and inherited values
        // already remain authoritative under the native receive contract.
        let values: Vec<_> = props
            .iter()
            .filter(|(k, p)| key(k) && p.source == "received")
            .map(|(k, p)| (k.clone(), p.value.clone()))
            .collect();
        if !values.is_empty() {
            if values
                .iter()
                .any(|(k, v)| member.properties.get(k) != Some(&property_evidence(k, v)))
            {
                return Err(refuse("receiver placement changed before localization"));
            }
            set_properties(backend, &member.bound.endpoint, &values)?;
            backend.sync(&member.bound.endpoint)?;
            let after = PairBackend::observe(backend)?;
            verify_original_target(&after, operation, id, backend)?;
            verify_fenced(&after, tree)?;
            let props = backend.properties(&member.bound.endpoint)?;
            if values.iter().any(|(k, v)| {
                props
                    .get(k)
                    .is_none_or(|p| &p.value != v || p.source != "local")
            }) {
                return Err(refuse("receiver placement localization was not verified"));
            }
        }
    }
    Ok(())
}

pub(super) fn reconcile(
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
    inert: bool,
) -> Result<(), Error> {
    for (relative, source) in &operation.plan.source.members {
        if operation
            .plan
            .destination
            .existing()
            .is_some_and(|t| t.members.contains_key(relative))
            || !root(source)
        {
            continue;
        }
        let fresh = PairBackend::observe(backend)?;
        verify_source(&fresh, operation, id, backend)?;
        let received = verify_received_mode(&fresh, operation, id, backend, false)?;
        let target = &received.members[relative];
        let source_props = backend.properties(&source.bound.endpoint)?;
        if source.bound.mountpoint.as_deref() != Some("/")
            || source.bound.placement.canmount != Some(MountMode::NoAuto)
        {
            return Err(refuse(
                "bootstrap root policy requires an inactive-placement source root",
            ));
        }
        let extras = source_props
            .get("zboot:cmdline")
            .filter(|_| source.properties.contains_key("zboot:cmdline"))
            .map_or("", |p| p.value.as_str());
        crate::handoff::compose_cmdline(&target.bound.endpoint.name, extras)
            .map_err(|e| refuse(e.to_string()))?;
        let mut values = Vec::new();
        if !inert {
            values.push(("mountpoint".to_owned(), "/".to_owned()));
        }
        if !source.properties.contains_key("zboot:cmdline") {
            values.push(("zboot:cmdline".into(), String::new()));
        }
        for (k, hash) in source.properties.iter().filter(|(k, _)| key(k)) {
            let p = source_props
                .get(k)
                .ok_or_else(|| refuse("source boot policy disappeared"))?;
            if property_evidence(k, &p.value) != *hash {
                return Err(refuse("source boot policy changed"));
            }
            values.push((k.clone(), p.value.clone()));
        }
        let props = backend.properties(&target.bound.endpoint)?;
        for (k, value) in &values {
            if props.get(k).is_some_and(|p| {
                p.value != *value
                    && p.source != "default"
                    && !p.source.starts_with("inherited from ")
            }) {
                return Err(refuse(
                    "bootstrap boot policy conflicts with receiver property",
                ));
            }
        }
        if values.iter().any(|(k, v)| {
            props
                .get(k)
                .is_none_or(|p| p.value != *v || p.source != "local")
        }) {
            // A new receive excludes canmount, leaving its default "on".
            // Publishing even an unchanged mountpoint locally can auto-mount
            // that filesystem; establish inactive placement before this write.
            backend.set_property(
                &target.bound.endpoint,
                &PropertyValue::Canmount(MountMode::NoAuto),
            )?;
            set_properties(backend, &target.bound.endpoint, &values)?;
            backend.sync(&target.bound.endpoint)?;
        }
        let after = PairBackend::observe(backend)?;
        verify_source(&after, operation, id, backend)?;
        let target = verify_received_mode(&after, operation, id, backend, false)?;
        verify(
            &after,
            operation,
            relative,
            &target.members[relative],
            inert,
        )?;
    }
    Ok(())
}

fn set_properties(
    backend: &mut impl TransferBackend,
    endpoint: &Endpoint,
    values: &[(String, String)],
) -> Result<(), Error> {
    for (key, value) in values {
        let property = match key.as_str() {
            "mountpoint" => PropertyValue::Mountpoint(value.clone()),
            "zboot:cmdline" => PropertyValue::Cmdline(value.clone()),
            _ => return Err(refuse("unsupported transfer boot property")),
        };
        backend.set_property(endpoint, &property)?;
    }
    Ok(())
}
