//! The receive inside a transfer. Its native placement is captured with the
//! frozen plan (the session); its checkpoints are one ordered step in the
//! transfer's progress, in the caller's intent record.
use super::*;
use crate::placement::{Posture, ReceivePlacement, SavedProperty};
use zfs_tools::engine::pool_of;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub source: BTreeMap<String, ReceivePlacement>,
    pub container: Option<Container>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    pub name: String,
    pub parent: Endpoint,
    pub final_parent: Endpoint,
}
/// How far the receive got, in the order it proceeds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Recorded with the plan; nothing received or fenced for it yet.
    #[default]
    Started,
    /// A new copy's container exists and is bound; an existing copy is fenced.
    Prepared,
    /// The stream completed into its fenced stage: `stage` is its identity.
    Adopted,
    /// The copy is at its final name.
    Renamed,
    /// Data properties and boot policy verified while every member is inert.
    Verified,
    /// Naming restored; every role is still inactive.
    Exposed,
    /// The container is gone.
    Retired,
}
/// The receive's checkpoints, kept in its transfer's progress.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receive {
    /// A new copy's bound container, from `Prepared`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<Endpoint>,
    pub step: Step,
    /// The name-free identity digest of the tree adopted at the stage, from
    /// `Adopted`; the rename keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}
/// The inert container a new copy of operation ID is received in.
pub(super) fn container_name(pool: &str, id: &str) -> String {
    format!("{pool}/zboot-receive-{}", id.replace('-', ""))
}
pub(super) fn capture(
    plan: &TransferPlan,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<Session, Error> {
    fn tree(
        tree: &Tree,
        backend: &mut impl TransferBackend,
    ) -> Result<BTreeMap<String, ReceivePlacement>, Error> {
        tree.members
            .iter()
            .map(|(relative, member)| {
                let before = PairBackend::observe(backend)?;
                refuse_altroot(&before, &member.bound.endpoint.name)?;
                if endpoint(&before, &member.bound.endpoint.name)? != member.bound.endpoint {
                    return Err(refuse("placement source import view changed"));
                }
                let props = backend.properties(&member.bound.endpoint)?;
                let after = PairBackend::observe(backend)?;
                refuse_altroot(&after, &member.bound.endpoint.name)?;
                if endpoint(&after, &member.bound.endpoint.name)? != member.bound.endpoint {
                    return Err(refuse(
                        "placement source import view changed while capturing receipt",
                    ));
                }
                Ok((
                    relative.clone(),
                    ReceivePlacement::capture(member.kind == history::Kind::Volume, &props)?,
                ))
            })
            .collect()
    }
    // An existing receiver is the one the plan bound, on a pool without an
    // altroot, before the commit records anything; only that is read of it.
    if let Some(receiver) = plan.destination.existing() {
        let state = PairBackend::observe(backend)?;
        for member in receiver.members.values() {
            refuse_altroot(&state, &member.bound.endpoint.name)?;
            if endpoint(&state, &member.bound.endpoint.name)? != member.bound.endpoint {
                return Err(refuse(
                    "the receiving copy was replaced since the plan; nothing was recorded",
                ));
            }
        }
    }
    let container = match &plan.destination {
        Destination::Existing { .. } => None,
        Destination::Absent { name, parent } => {
            let pool = pool_of(name);
            let state = PairBackend::observe(backend)?;
            let staging = container_name(pool, id);
            destination_outside_boot_environment(&state, &staging)?;
            Some(Container {
                name: staging,
                parent: endpoint(&state, pool)?,
                final_parent: parent.clone(),
            })
        }
    };
    Ok(Session {
        source: tree(&plan.source, backend)?,
        container,
    })
}
/// SESSION is PLAN's under operation ID, and RECEIVE's checkpoints agree
/// with it and with each other.
pub(super) fn validate(
    session: &Session,
    receive: &Receive,
    plan: &TransferPlan,
    id: &str,
) -> Result<(), Error> {
    let container_matches = match (&plan.destination, &session.container) {
        (Destination::Existing { .. }, None) => true,
        (Destination::Absent { name, parent }, Some(container)) => {
            let pool = pool_of(name);
            container.name == container_name(pool, id)
                && container.parent.name == pool
                && container.parent.identity.pool_guid == parent.identity.pool_guid
                && container.final_parent == *parent
        }
        _ => false,
    };
    if session.source.keys().ne(plan.source.members.keys()) || !container_matches {
        return Err(refuse(
            "receive session differs from the frozen transfer scope",
        ));
    }
    if receive.stage.is_some() != (receive.step >= Step::Adopted)
        || receive.stage.as_deref().is_some_and(|d| !valid_digest(d))
        || receive.container.is_some()
            != (receive.step >= Step::Prepared && session.container.is_some())
    {
        return Err(refuse("receive progress has inconsistent checkpoints"));
    }
    if let (Some(container), Some(spec)) = (&receive.container, &session.container)
        && (container.name != spec.name
            || container.identity.pool_guid != spec.parent.identity.pool_guid)
    {
        return Err(refuse("receive container binding differs"));
    }
    Ok(())
}
/// The posture data is received in: a new copy inherits its container's
/// inert one (read-only, no mountpoint, no device); an existing copy stays
/// fenced in place, read-only and not mountable, its mountpoint untouched:
/// setting or inheriting `mountpoint` remounts every mountable descendant
/// (`libzfs_changelist.c`), and a child under a pair leaf is not fenced.
/// `zfs receive -u` mounts nothing, and `canmount=noauto` keeps the copy
/// unmounted at boot.
pub(super) fn receiving(existing: bool) -> Posture {
    if existing {
        Posture::AtRest
    } else {
        Posture::Inert { parent: false }
    }
}
fn verify_container(
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<Endpoint, Error> {
    let spec = operation.receive.container.as_ref().unwrap();
    let bound = operation.progress.receive.container.as_ref();
    let state = PairBackend::observe(backend)?;
    destination_outside_boot_environment(&state, &spec.name)?;
    destination_outside_boot_environment(&state, operation.plan.destination.name())?;
    refuse_altroot(&state, &spec.name)?;
    if endpoint(&state, &spec.parent.name)? != spec.parent
        || endpoint(&state, &spec.final_parent.name)? != spec.final_parent
    {
        return Err(refuse("receive container or final parent changed"));
    }
    let ep = endpoint(&state, &spec.name)?;
    if bound.is_some_and(|bound| *bound != ep) {
        return Err(refuse("receive container was replaced"));
    }
    let props = backend.properties(&ep)?;
    for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
        if props
            .get(key)
            .is_none_or(|p| p.source != "local" || p.value != id)
        {
            return Err(refuse(
                "foreign receive container occupies the reserved name",
            ));
        }
    }
    if state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == ep.name)
        .unwrap()
        .encryptionroot
        .is_some()
        || state
            .inspection
            .snapshots
            .as_ref()
            .unwrap()
            .iter()
            .any(|s| {
                s.name
                    .split_once('@')
                    .is_some_and(|(owner, _)| owner == ep.name)
            })
        || state.inspection.datasets.iter().any(|d| {
            history::contains_dataset(&ep.name, &d.name)
                && d.name != ep.name
                && (bound.is_none()
                    || !history::contains_dataset(&format!("{}/root", ep.name), &d.name))
        })
    {
        return Err(refuse(
            "receive preparation container is not the bound empty workspace",
        ));
    }
    crate::pairs::verify_posture(backend, &ep, Posture::Inert { parent: true })?;
    Ok(ep)
}
pub(super) fn prepare(
    record: &mut impl Record,
    operation: &mut TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<String, Error> {
    let destination = operation.plan.destination.name().to_owned();
    if let Some(spec) = operation.receive.container.clone() {
        let state = PairBackend::observe(backend)?;
        if operation.progress.receive.step >= Step::Renamed {
            return Ok(destination);
        }
        if !state
            .inspection
            .datasets
            .iter()
            .any(|d| d.name == spec.name)
        {
            if operation.progress.receive.container.is_some() {
                return Err(refuse("recorded receive container disappeared"));
            }
            backend.create_inert_container(&spec.parent, &spec.name, id)?;
        }
        let container = verify_container(operation, id, backend)?;
        if operation.progress.receive.container.is_none() {
            operation.progress.receive.container = Some(container.clone());
            operation.progress.receive.step = Step::Prepared;
            save(record, operation, backend)?;
        }
        let root = format!("{}/root", spec.name);
        if operation.progress.receive.stage.is_none() {
            let state = PairBackend::observe(backend)?;
            let members: Vec<_> = state
                .inspection
                .datasets
                .iter()
                .filter(|dataset| history::contains_dataset(&root, &dataset.name))
                .map(|dataset| Endpoint {
                    name: dataset.name.clone(),
                    identity: dataset.identity.clone(),
                })
                .collect();
            for ep in members.iter().rev() {
                if !owned(&backend.properties(ep)?, id, &root, Some(&spec.name)) {
                    return Err(refuse("partial receive workspace has foreign ownership"));
                }
                crate::pairs::fence(backend, ep, None, Posture::Inert { parent: true })?;
            }
        }
        backend.quiesce_receive_scope(&container, id)?;
        Ok(root)
    } else {
        if operation.progress.receive.stage.is_none() {
            let tree = operation.plan.destination.existing().unwrap();
            fence(tree, backend)?;
            // Only a volume has a device to drain; a fenced filesystem copy
            // keeps its own mountpoint and is not an inert scope.
            if tree
                .members
                .values()
                .any(|member| member.kind == history::Kind::Volume)
            {
                backend.quiesce_receive_scope(&tree.endpoint, id)?;
            }
            for member in tree
                .members
                .values()
                .filter(|member| member.kind == history::Kind::Volume)
            {
                if !backend.volume_unavailable(&member.bound.endpoint)? {
                    return Err(refuse(
                        "existing receive volume remains available after quiescence",
                    ));
                }
            }
            if operation.progress.receive.step < Step::Prepared {
                operation.progress.receive.step = Step::Prepared;
                save(record, operation, backend)?;
            }
        }
        Ok(destination)
    }
}
/// Remove only control metadata already proved to belong to this receive.
/// The native history observer deliberately refuses active management state.
fn clean_view(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
) -> Result<NativeState, Error> {
    let mut clean = clean_state(state, operation, id)?;
    if let Some(spec) = &operation.receive.container {
        let container = operation
            .progress
            .receive
            .container
            .as_ref()
            .ok_or_else(|| refuse("receive container has no durable native binding"))?;
        refuse_altroot(state, &spec.name)?;
        if endpoint(state, &spec.name)? != *container
            || endpoint(state, &spec.parent.name)? != spec.parent
            || endpoint(state, &spec.final_parent.name)? != spec.final_parent
        {
            return Err(refuse("receive preparation scope identity changed"));
        }
        for (name, props) in &mut clean.dataset_properties {
            if !history::contains_dataset(&spec.name, name) {
                continue;
            }
            for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
                let property = props
                    .get(key)
                    .ok_or_else(|| refuse("receive workspace lost ownership"))?;
                if property.value != id
                    || !(property.source == "local"
                        || (name != &spec.name
                            && property.source.strip_prefix("inherited from ").is_some_and(
                                |owner| {
                                    history::contains_dataset(&spec.name, owner)
                                        && history::contains_dataset(owner, name)
                                },
                            )))
                {
                    return Err(refuse("receive workspace has foreign control metadata"));
                }
                props.remove(key);
            }
        }
    }
    Ok(clean)
}
/// This operation owns a received dataset: it carries the operation's pending
/// and staging markers, set locally, inherited inside ROOT, or inherited from
/// the bound receive CONTAINER a new copy is created in.
fn owned(
    props: &BTreeMap<String, NativeProperty>,
    id: &str,
    root: &str,
    container: Option<&str>,
) -> bool {
    [management::PENDING_PROPERTY, management::STAGING_PROPERTY]
        .iter()
        .all(|key| {
            props.get(*key).is_some_and(|p| {
                p.value == id
                    && (p.source == "local"
                        || p.source
                            .strip_prefix("inherited from ")
                            .is_some_and(|owner| {
                                history::contains_dataset(root, owner) || Some(owner) == container
                            }))
            })
        })
}
fn bound_received(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
    root: &str,
    backend: &mut impl TransferBackend,
) -> Result<Tree, Error> {
    bind(
        &clean_view(state, operation, id)?,
        root,
        backend,
        End::Receiver,
    )
}
fn inspect_received(
    operation: &TransferOperation,
    id: &str,
    root: &str,
    backend: &mut impl TransferBackend,
) -> Result<Tree, Error> {
    let state = PairBackend::observe(backend)?;
    let target = bound_received(&state, operation, id, root, backend)?;
    if target
        .members
        .keys()
        .ne(operation.plan.source.members.keys())
    {
        return Err(refuse(
            "inert receive is incomplete; no placement was exposed",
        ));
    }
    for (relative, member) in &target.members {
        let source = &operation.plan.source.members[relative];
        if member.kind != source.kind
            || history_of(&member.bound.snapshots)? != expected_history(&operation.plan, relative)?
        {
            return Err(refuse(
                "inert received history differs from its frozen source",
            ));
        }
        let container = operation
            .receive
            .container
            .as_ref()
            .map(|c| c.name.as_str());
        let props = backend.properties(&member.bound.endpoint)?;
        if !owned(&props, id, root, container) {
            return Err(refuse("received member lacks trusted stream ownership"));
        }
        if let Some(old) = operation
            .plan
            .destination
            .existing()
            .and_then(|t| t.members.get(relative))
            && member.bound.endpoint != old.bound.endpoint
        {
            return Err(refuse("existing receiver member was replaced"));
        }
        verify_encryption(
            &source.encryption,
            &member.encryption,
            &member.bound.snapshots,
        )?;
        if member.encryption_root != expected_encryption_root(&operation.plan, root) {
            return Err(refuse("inert received encryption hierarchy differs"));
        }
        let dataset = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == member.bound.endpoint.name)
            .unwrap();
        if backend.written(dataset, member.bound.snapshots.last().unwrap())? != 0 {
            return Err(refuse("inert received head was written"));
        }
        let volume = member.kind == history::Kind::Volume;
        let posture = receiving(operation.plan.destination.existing().is_some()).holds(
            volume,
            member.mounted,
            |key| {
                props
                    .get(key)
                    .map(|p| (p.value.as_str(), p.source == "local"))
            },
        );
        if !posture || (volume && !backend.volume_unavailable(&member.bound.endpoint)?) {
            return Err(refuse("data-bearing receive escaped its fence"));
        }
    }
    Ok(target)
}
/// Complete data verification and every final inactive role before the first
/// rename/exposure. Returns false only while no complete stream exists.
pub(super) fn finish(
    record: &mut impl Record,
    operation: &mut TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
    complete_required: bool,
) -> Result<bool, Error> {
    verify_receive_destinations(&PairBackend::observe(backend)?, operation)?;
    let destination = operation.plan.destination.name().to_owned();
    let stage = operation
        .receive
        .container
        .as_ref()
        .map(|s| format!("{}/root", s.name))
        .unwrap_or_else(|| destination.clone());
    if operation.progress.receive.stage.is_none() {
        // Completion is native: the copy holds exactly its expected history
        // (inspect_received), with no snapshot of this transfer missing.
        let state = PairBackend::observe(backend)?;
        if !state.inspection.datasets.iter().any(|d| d.name == stage) {
            return if complete_required {
                Err(refuse("native stream did not create its bound inert root"))
            } else {
                Ok(false)
            };
        }
        let tree = match inspect_received(operation, id, &stage, backend) {
            Ok(tree) => tree,
            Err(error) if complete_required => return Err(error),
            Err(_) => return Ok(false),
        };
        let existing = operation.plan.destination.existing().is_some();
        let posture = if existing {
            Posture::AtRest
        } else {
            Posture::Inert { parent: true }
        };
        for member in tree.members.values().rev() {
            crate::pairs::fence(backend, &member.bound.endpoint, None, posture)?;
            if existing {
                continue;
            }
            if operation.receive.container.is_some() {
                // A new copy inherits fences and ownership from the container;
                // both become local before the rename takes it out.
                for value in [
                    PropertyValue::Pending(id.into()),
                    PropertyValue::Staging(id.into()),
                ] {
                    backend.set_property(&member.bound.endpoint, &value)?;
                }
            }
            if member.kind == history::Kind::Filesystem {
                backend.set_property(
                    &member.bound.endpoint,
                    &PropertyValue::Canmount(MountMode::NoAuto),
                )?;
            }
        }
        for member in tree.members.values() {
            crate::pairs::verify_posture(backend, &member.bound.endpoint, posture)?;
        }
        if !existing
            || tree
                .members
                .values()
                .any(|member| member.kind == history::Kind::Volume)
        {
            backend.quiesce_receive_scope(&tree.endpoint, id)?;
        }
        for member in tree
            .members
            .values()
            .filter(|member| member.kind == history::Kind::Volume)
        {
            if !backend.volume_unavailable(&member.bound.endpoint)? {
                return Err(refuse("received volume remains available before adoption"));
            }
        }
        // Adopting the tree records that the stream completed: its history
        // and every fence were verified above.
        let adopted = bound_received(
            &PairBackend::observe(backend)?,
            operation,
            id,
            &stage,
            backend,
        )?;
        operation.progress.receive.stage = Some(identity_digest(&adopted)?);
        operation.progress.receive.step = Step::Adopted;
        save(record, operation, backend)?;
    }
    let adopted = operation.progress.receive.stage.clone().unwrap();
    let state = PairBackend::observe(backend)?;
    if let Some(container) = operation.receive.container.clone() {
        verify_container(operation, id, backend)?;
        let at = |name: &str| state.inspection.datasets.iter().any(|d| d.name == name);
        match (at(&stage), at(&destination)) {
            (true, false) if operation.progress.receive.step < Step::Renamed => {
                let observed = bound_received(&state, operation, id, &stage, backend)?;
                if identity_digest(&observed)? != adopted {
                    return Err(refuse("received tree or rename identity changed"));
                }
                backend.rename_received(
                    &observed.endpoint,
                    &container.final_parent,
                    &destination,
                )?;
            }
            // Renamed, the reply lost or not: the final name is checked below.
            (false, true) => {}
            _ => {
                return Err(refuse(
                    "receive rename source, destination or intruder differs from the recorded identity",
                ));
            }
        }
    }
    let current = bound_received(
        &PairBackend::observe(backend)?,
        operation,
        id,
        &destination,
        backend,
    )?;
    if identity_digest(&current)? != adopted {
        return Err(refuse("received tree or rename identity changed"));
    }
    if operation.progress.receive.step < Step::Renamed {
        operation.progress.receive.step = Step::Renamed;
        save(record, operation, backend)?;
    }
    if operation.progress.receive.step < Step::Verified {
        // Restore stream-owned data properties and final boot policy while
        // every member still has inert placement and an inactive role. A
        // mismatch must never first become visible through a mount or zvol.
        reconcile_external_mode(operation, id, backend, true)?;
        // This checkpoint authorizes resuming a partially restored placement
        // after a lost effect reply. Without it the whole tree must be inert.
        operation.progress.receive.step = Step::Verified;
        save(record, operation, backend)?;
    }
    if operation.progress.receive.step < Step::Exposed {
        verify_receive_destinations(&PairBackend::observe(backend)?, operation)?;
        for member in current.members.values() {
            let props = backend.properties(&member.bound.endpoint)?;
            if props
                .get("readonly")
                .is_none_or(|property| property.value != "on")
                || member.mounted
                || (member.kind == history::Kind::Filesystem
                    && props
                        .get("canmount")
                        .is_none_or(|property| property.value != "noauto"))
            {
                return Err(refuse(
                    "verified inactive receive role changed before exposure",
                ));
            }
        }
        // All members already have readonly=on and inactive canmount. Only
        // now restore naming; role activation comes later. A volume keeps
        // its local volmode=none: a fenced copy has no device at rest. A new
        // filesystem drops it: nothing more is received beneath it.
        let mut points: BTreeMap<String, SavedProperty> = BTreeMap::new();
        for (relative, member) in &current.members {
            let parent = (!relative.is_empty())
                .then(|| relative.rsplit_once('/').map_or("", |(parent, _)| parent));
            let parent_name = parent.map(|p| mapped(&destination, p));
            if operation
                .plan
                .destination
                .existing()
                .is_some_and(|tree| tree.members.contains_key(relative))
            {
                // An existing copy's mountpoint was never changed.
                continue;
            }
            if let Some(point) = &operation.receive.source[relative].mountpoint {
                let value = crate::placement::new_member_property(
                    "mountpoint",
                    point,
                    &point.value,
                    &member.bound.endpoint.name,
                    parent.and_then(|p| {
                        points
                            .get(p)
                            .map(|value| (parent_name.as_deref().unwrap(), value))
                    }),
                );
                backend.publish_mountpoint(&member.bound.endpoint, &value)?;
                points.insert(relative.clone(), value);
            }
            let e = &member.bound.endpoint;
            let staged = |props: BTreeMap<String, NativeProperty>| {
                props
                    .get("volmode")
                    .is_some_and(|p| p.source == "local" && p.value == "none")
            };
            if member.kind == history::Kind::Filesystem && staged(backend.properties(e)?) {
                let result = backend.inherit_property(e, PropertyKey::Volmode, "none");
                if staged(backend.properties(e)?) {
                    return Err(result.err().unwrap_or_else(|| {
                        refuse("a published filesystem kept its staged volmode")
                    }));
                }
            }
        }
        operation.progress.receive.step = Step::Exposed;
        save(record, operation, backend)?;
    }
    Ok(true)
}
/// Abandon a receive before its transfer adopted the data. An existing copy stays
/// fenced with the snapshots it received: its at-rest role and saved
/// mountpoint come back. A new copy stays fenced where it is, inside its
/// container or, once renamed, at its final name, unpaired; that name is
/// returned for the operator, if anything was created. Its checkpoints go
/// with the transfer's.
pub(super) fn abandon(
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<Option<String>, Error> {
    // Verified data changes nothing here: the copy stays fenced with what it
    // received, and the next sync finds nothing more to send. Only a transfer
    // past its Received phase refuses (`abandon_between_with`).
    let progress = &operation.progress.receive;
    let destination = operation.plan.destination.name();
    if let Some(existing) = operation.plan.destination.existing() {
        let member = &existing.members[""];
        let ep = &member.bound.endpoint;
        let state = PairBackend::observe(backend)?;
        if endpoint(&state, &ep.name)? != *ep {
            return Err(refuse("the receiving copy was replaced; nothing abandoned"));
        }
        crate::pairs::fence(backend, ep, None, Posture::AtRest)?;
    }
    // Renamed out of its container already, recorded or not (a cut right
    // after the rename): the tree at the final name is the one adopted at
    // the stage, by its name-free identity. Its markers do not show it, as
    // an abandon cut while removing them leaves one or none. A tree there
    // that cannot be read (its pool imported with an altroot, say) may be
    // the copy: that refuses, rather than leave it marked.
    let state = PairBackend::observe(backend)?;
    let renamed = progress.step >= Step::Renamed
        || match &progress.stage {
            Some(stage) if endpoint(&state, destination).is_ok() => {
                // Its container may be gone already, so not `bound_received`.
                let clean = clean_state(&state, operation, id)?;
                identity_digest(&bind(&clean, destination, backend, End::Receiver)?)? == *stage
            }
            _ => false,
        };
    Ok(match &operation.receive.container {
        None => None,
        // The new copy is at its final name with local fences; it only
        // loses this operation's markers.
        Some(spec) if renamed => {
            // Its container is empty now and this operation's own: it goes.
            if let Some(container) = &progress.container
                && state
                    .inspection
                    .datasets
                    .iter()
                    .any(|d| d.name == spec.name)
            {
                verify_container(operation, id, backend)?;
                backend.destroy_empty_container(container, id)?;
            }
            let copy = endpoint(&state, destination)?;
            for key in [PropertyKey::Pending, PropertyKey::Staging] {
                if backend
                    .properties(&copy)?
                    .get(key.native())
                    .is_some_and(|p| p.value == id && p.source == "local")
                {
                    backend.inherit_property(&copy, key, id)?;
                }
            }
            Some(destination.to_owned())
        }
        // A container not created yet leaves nothing behind.
        Some(container) => state
            .inspection
            .datasets
            .iter()
            .any(|d| d.name == container.name)
            .then(|| container.name.clone()),
    })
}
/// Retire the receive once the copy's placement is exposed: a new copy's
/// empty container goes.
pub(super) fn retire(
    record: &mut impl Record,
    operation: &mut TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    if operation.progress.receive.step < Step::Exposed {
        return Err(refuse("receive placement was not completely exposed"));
    }
    if operation.progress.receive.step < Step::Retired {
        if let Some(container) = operation.progress.receive.container.clone() {
            let state = PairBackend::observe(backend)?;
            if state
                .inspection
                .datasets
                .iter()
                .any(|d| d.name == container.name)
            {
                verify_container(operation, id, backend)?;
                backend.destroy_empty_container(&container, id)?;
            }
            let state = PairBackend::observe(backend)?;
            if state
                .inspection
                .datasets
                .iter()
                .any(|d| d.name == container.name)
            {
                return Err(refuse("receive container retirement was not verified"));
            }
        }
        operation.progress.receive.step = Step::Retired;
        save(record, operation, backend)?;
    }
    Ok(())
}
