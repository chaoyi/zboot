//! Versioned native management records. Local incarnation identity prevents a
//! received copy or reused name from inheriting authority from a stale record.
use crate::engine::{
    Dataset, DatasetIdentity, Error, is_canonical_uuid_v4,
    native::{NativeProperty, PropertyInventory},
    state::NativeState,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PAIR_PROPERTY: &str = "zboot:pair";
pub const PENDING_PROPERTY: &str = "zboot:pending";
pub const STAGING_PROPERTY: &str = "zboot:staging";
/// The one operation record of a pool, on its root dataset (`intent`).
pub const OPERATION_PROPERTY: &str = "zboot:operation";
pub const PLACEMENT_PROPERTY: &str = "zboot:placement";

/// A key in zboot's namespace: it carries management state, never ordinary
/// user data.
pub fn managed_key(key: &str) -> bool {
    key.starts_with("zboot:")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    On,
    Off,
    NoAuto,
}
impl MountMode {
    #[cfg(feature = "internal")]
    pub fn native(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::NoAuto => "noauto",
        }
    }
}
/// The role a fence saved, which activation gives back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub schema_version: u32,
    pub identity: DatasetIdentity,
    pub readonly: bool,
    pub canmount: Option<MountMode>,
    /// A volume's local `volmode` other than `none`, set by hand. Absent
    /// otherwise, so a filesystem's record and a record without one encode
    /// as before; a build that predates the field refuses a record with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volmode: Option<String>,
}
impl Placement {
    /// The dataset's `readonly` and `canmount`, without its `volmode`.
    #[cfg(feature = "internal")]
    pub fn from_dataset(dataset: &crate::engine::Dataset) -> Self {
        Self {
            schema_version: 1,
            identity: dataset.identity.clone(),
            readonly: dataset.readonly,
            canmount: dataset.canmount.map(|mode| match mode {
                crate::engine::CanMount::On => MountMode::On,
                crate::engine::CanMount::Off => MountMode::Off,
                crate::engine::CanMount::NoAuto => MountMode::NoAuto,
            }),
            volmode: None,
        }
    }
    /// What a fence saves of the dataset now: [`Self::from_dataset`] and,
    /// for a volume, a `volmode` set by hand. A local `none` is not saved:
    /// at rest it cannot be told from the fence's own.
    #[cfg(feature = "internal")]
    pub fn observed(
        dataset: &crate::engine::Dataset,
        properties: &BTreeMap<String, NativeProperty>,
    ) -> Self {
        Self {
            volmode: properties
                .get("volmode")
                .filter(|p| {
                    dataset.kind == crate::engine::DatasetKind::Volume
                        && p.source == "local"
                        && p.value != "none"
                })
                .map(|p| p.value.clone()),
            ..Self::from_dataset(dataset)
        }
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() > 2048 {
            return Err(refuse("placement record too large"));
        }
        let record: Self =
            serde_json::from_str(value).map_err(|e| refuse(format!("invalid placement: {e}")))?;
        if record.schema_version != 1 || !record.identity.is_complete() {
            return Err(refuse("unsupported or incomplete placement record"));
        }
        // Only a volume (no canmount) saves a volmode, and never `none`.
        if record.volmode.as_deref().is_some_and(|mode| {
            record.canmount.is_some() || !matches!(mode, "default" | "full" | "dev")
        }) {
            return Err(refuse("invalid saved volmode in placement record"));
        }
        Ok(record)
    }
    #[cfg(feature = "internal")]
    pub fn encode(&self) -> Result<String, Error> {
        let encoded = serde_json::to_string(self).map_err(|e| refuse(e.to_string()))?;
        Self::parse(&encoded)?;
        Ok(encoded)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub identity: DatasetIdentity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Primary,
    Secondary,
}
impl Role {
    pub fn opposite(self) -> Self {
        match self {
            Self::Primary => Self::Secondary,
            Self::Secondary => Self::Primary,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRecord {
    pub schema_version: u32,
    pub pair_id: String,
    pub endpoint: Endpoint,
    pub peer: Endpoint,
    pub role: Role,
}
impl PairRecord {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 {
            return Err(refuse("unsupported pair schema"));
        }
        if !is_canonical_uuid_v4(&self.pair_id) {
            return Err(refuse("pair ID must be a canonical UUID v4"));
        }
        for endpoint in [&self.endpoint, &self.peer] {
            crate::engine::validate_dataset_name(&endpoint.name)?;
            if !endpoint.identity.is_complete() {
                return Err(refuse("pair endpoint identity is incomplete"));
            }
        }
        if contains(&self.endpoint.name, &self.peer.name)
            || contains(&self.peer.name, &self.endpoint.name)
            || self.endpoint.identity == self.peer.identity
        {
            return Err(refuse("pair endpoints overlap or identify the same object"));
        }
        Ok(())
    }
    pub fn counterpart(&self) -> Self {
        Self {
            schema_version: self.schema_version,
            pair_id: self.pair_id.clone(),
            endpoint: self.peer.clone(),
            peer: self.endpoint.clone(),
            role: self.role.opposite(),
        }
    }
    #[cfg(feature = "internal")]
    pub fn encode(&self) -> Result<String, Error> {
        self.validate()?;
        serde_json::to_string(self).map_err(|e| refuse(e.to_string()))
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() > 16 * 1024 {
            return Err(refuse("pair property exceeds supported size"));
        }
        let record: Self = serde_json::from_str(value)
            .map_err(|e| refuse(format!("invalid pair property: {e}")))?;
        record.validate()?;
        Ok(record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Ownership {
    Unpaired,
    Primary { record: PairRecord },
    Secondary { record: PairRecord },
}

/// Validate supported properties and their native sources. A record on a child
/// must be inherited from its actual owning root, never copied locally.
pub fn ownership(state: &NativeState, name: &str) -> Result<Ownership, Error> {
    ownership_in(
        &state.inspection.datasets,
        &state.dataset_properties,
        name,
        false,
    )
}

pub(crate) fn ownership_ignoring_unfinished(
    state: &NativeState,
    name: &str,
) -> Result<Ownership, Error> {
    ownership_in(
        &state.inspection.datasets,
        &state.dataset_properties,
        name,
        true,
    )
}

fn ownership_in(
    datasets: &[Dataset],
    dataset_properties: &PropertyInventory,
    name: &str,
    ignore_unfinished: bool,
) -> Result<Ownership, Error> {
    let mut pair: Option<PairRecord> = None;
    let mut path = Some(name);
    while let Some(current) = path {
        let properties = bound_properties_in(datasets, dataset_properties, current)?;
        validate_supported_properties_mode(properties, current, ignore_unfinished)?;
        if let Some(property) = properties.get(PAIR_PROPERTY) {
            let record = PairRecord::parse(&property.value)?;
            let expected_source = if record.endpoint.name == current {
                "local".into()
            } else {
                format!("inherited from {}", record.endpoint.name)
            };
            if !contains(&record.endpoint.name, current) || property.source != expected_source {
                return Err(refuse(format!("invalid pair owner/source on {current}")));
            }
            let root = datasets
                .iter()
                .find(|d| d.name == record.endpoint.name)
                .ok_or_else(|| refuse("pair owner was not observed"))?;
            if root.identity != record.endpoint.identity {
                return Err(refuse("pair owner incarnation changed"));
            }
            if let Some(previous) = &pair {
                if previous != &record {
                    return Err(refuse("overlapping or inconsistent pair scopes"));
                }
            } else {
                pair = Some(record);
            }
        } else if pair
            .as_ref()
            .is_some_and(|record| contains(&record.endpoint.name, current))
        {
            return Err(refuse("pair inheritance or root publication is incomplete"));
        }
        path = current.rsplit_once('/').map(|(parent, _)| parent);
    }
    let Some(record) = pair else {
        return Ok(Ownership::Unpaired);
    };
    let mut current = name;
    loop {
        let props = bound_properties_in(datasets, dataset_properties, current)?;
        let property = props
            .get(PAIR_PROPERTY)
            .ok_or_else(|| refuse("effective pair inheritance missing"))?;
        let source = if current == record.endpoint.name {
            "local".into()
        } else {
            format!("inherited from {}", record.endpoint.name)
        };
        if property.source != source || PairRecord::parse(&property.value)? != record {
            return Err(refuse("pair inheritance differs from owning root"));
        }
        if current == record.endpoint.name {
            break;
        }
        current = current
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .ok_or_else(|| refuse("pair owner is not an ancestor"))?;
    }
    let peer = datasets
        .iter()
        .find(|d| d.name == record.peer.name)
        .ok_or_else(|| {
            refuse(format!(
                "peer unavailable for ownership validation: {}",
                record.peer.name
            ))
        })?;
    if peer.identity != record.peer.identity {
        return Err(refuse("peer incarnation changed"));
    }
    let peer_properties = bound_properties_in(datasets, dataset_properties, &record.peer.name)?;
    validate_supported_properties_mode(peer_properties, &record.peer.name, ignore_unfinished)?;
    let property = peer_properties
        .get(PAIR_PROPERTY)
        .ok_or_else(|| refuse("mutual pair publication is incomplete"))?;
    if property.source != "local" || PairRecord::parse(&property.value)? != record.counterpart() {
        return Err(refuse("pair records are not mutual"));
    }
    // A pair joins leaf datasets: the secondary leaf itself must be fenced.
    // A child under it is outside the pair; sync reports it, `primary` refuses.
    let secondary = if record.role == Role::Primary {
        &record.peer.name
    } else {
        &record.endpoint.name
    };
    for dataset in datasets.iter().filter(|d| d.name == *secondary) {
        if !dataset.readonly
            || dataset
                .canmount
                .is_some_and(|mode| mode == crate::engine::CanMount::On)
        {
            return Err(refuse(format!("secondary is not fenced: {}", dataset.name)));
        }
        let props = bound_properties_in(datasets, dataset_properties, &dataset.name)?;
        validate_supported_properties_mode(props, &dataset.name, ignore_unfinished)?;
        let observed = props
            .get(PAIR_PROPERTY)
            .ok_or_else(|| refuse("secondary pair inheritance missing"))?;
        let secondary_record = if record.role == Role::Secondary {
            record.clone()
        } else {
            record.counterpart()
        };
        if observed.source != "local" || PairRecord::parse(&observed.value)? != secondary_record {
            return Err(refuse("overlapping secondary management scope"));
        }
    }
    Ok(match record.role {
        Role::Primary => Ownership::Primary { record },
        Role::Secondary => Ownership::Secondary { record },
    })
}

/// Datasets other than `name` whose own local pair record names `name` as
/// its peer. A mutual pair has exactly its peer here; anything else is a
/// pair or unpair that stopped between its two records (`zboot unpair`
/// removes one side, then the other), which `ownership` alone reads as
/// unpaired on the side already cleared.
pub(crate) fn peer_references(state: &NativeState, name: &str) -> Vec<String> {
    state
        .dataset_properties
        .iter()
        .filter(|(holder, _)| holder.as_str() != name)
        .filter_map(|(holder, properties)| {
            let property = properties.get(PAIR_PROPERTY)?;
            let record = PairRecord::parse(&property.value).ok()?;
            (property.source == "local"
                && record.endpoint.name == *holder
                && record.peer.name == name)
                .then(|| holder.clone())
        })
        .collect()
}

#[cfg(all(test, feature = "internal"))]
fn admit_working(state: &NativeState, name: &str) -> Result<(), Error> {
    admit_working_parts(&state.inspection.datasets, &state.dataset_properties, name)
}

pub(crate) fn admit_working_parts(
    datasets: &[Dataset],
    dataset_properties: &PropertyInventory,
    name: &str,
) -> Result<(), Error> {
    match ownership_in(datasets, dataset_properties, name, false)? {
        Ownership::Unpaired | Ownership::Primary { .. } => Ok(()),
        Ownership::Secondary { .. } => Err(refuse(format!(
            "secondary cannot capture, retain or receive writable maintenance: {name}"
        ))),
    }
}

pub fn bound_properties<'a>(
    state: &'a NativeState,
    name: &str,
) -> Result<&'a BTreeMap<String, NativeProperty>, Error> {
    bound_properties_in(&state.inspection.datasets, &state.dataset_properties, name)
}

fn bound_properties_in<'a>(
    datasets: &'a [Dataset],
    dataset_properties: &'a PropertyInventory,
    name: &str,
) -> Result<&'a BTreeMap<String, NativeProperty>, Error> {
    let dataset = datasets
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| refuse(format!("dataset missing: {name}")))?;
    let properties = dataset_properties
        .get(name)
        .ok_or_else(|| refuse(format!("complete properties missing: {name}")))?;
    for (key, value) in [
        ("guid", dataset.identity.guid.get()),
        ("createtxg", dataset.identity.createtxg.get()),
        ("objsetid", dataset.identity.objsetid.get()),
    ] {
        if properties.get(key).map(|p| p.value.as_str()) != Some(value.to_string().as_str()) {
            return Err(refuse(format!("property identity changed: {name} {key}")));
        }
    }
    if let Some(property) = properties.get(PLACEMENT_PROPERTY) {
        let placement = Placement::parse(&property.value)?;
        let owner = if property.source == "local" {
            Some(dataset)
        } else {
            property
                .source
                .strip_prefix("inherited from ")
                .and_then(|owner| {
                    datasets
                        .iter()
                        .find(|d| d.name == owner && contains(owner, name) && owner != name)
                })
        };
        if owner.is_none_or(|owner| {
            placement.identity != owner.identity
                || placement.canmount.is_some() != owner.canmount.is_some()
        }) {
            return Err(refuse(format!(
                "placement identity or source changed: {name}"
            )));
        }
    }
    Ok(properties)
}

pub fn validate_supported_properties(
    properties: &BTreeMap<String, NativeProperty>,
    name: &str,
) -> Result<(), Error> {
    validate_supported_properties_mode(properties, name, false)
}

fn validate_supported_properties_mode(
    properties: &BTreeMap<String, NativeProperty>,
    name: &str,
    ignore_unfinished: bool,
) -> Result<(), Error> {
    for (key, property) in properties {
        if !managed_key(key) {
            continue;
        }
        match key.as_str() {
            PLACEMENT_PROPERTY => {
                Placement::parse(&property.value)?;
            }
            PAIR_PROPERTY => {
                PairRecord::parse(&property.value)?;
            }
            // An operation record lives on its pool's root; descendants
            // inherit it. It is inert here: `resume` reads it, nothing else.
            OPERATION_PROPERTY if pool_root_source(&property.source, name) => {}
            "zboot:cmdline"
                if !property.value.chars().any(char::is_control)
                    && trusted_source(&property.source) => {}
            PENDING_PROPERTY | STAGING_PROPERTY if ignore_unfinished => {}
            PENDING_PROPERTY | STAGING_PROPERTY => {
                return Err(refuse(unfinished(properties, name, key, &property.value)));
            }
            // Another operation's attachment: it is refused as before, but
            // named as what it is, so the reader knows where to go next.
            _ if key.starts_with("zboot:attachment:") => {
                let id = key["zboot:attachment:".len()..]
                    .split(':')
                    .next()
                    .unwrap_or_default();
                return Err(Error::Refused(format!(
                    "{name} carries {key}, part of operation {id}; `zboot status` says \
                     whether to resume or abandon it, or how to remove an orphaned one"
                )));
            }
            // A key this build does not read is a plain refusal, not a sign
            // of a damaged observation: say so without that prefix.
            _ => {
                let holder = property
                    .source
                    .strip_prefix("inherited from ")
                    .unwrap_or(name);
                return Err(Error::Refused(format!(
                    "unsupported management property {key} on {name}: this zboot does not \
                     read it. Use the zboot that wrote it, or, once that state is known to be \
                     obsolete, remove it with `zfs inherit {key} {holder}`"
                )));
            }
        }
    }
    Ok(())
}
/// Why `name` carries `key=value`, and what to do about it. Every operation
/// records on the pool its marks are in (descendants inherit that record),
/// except a cross-pool move, whose fenced source keeps a local placement and
/// is recorded on the destination pool. `deploy` keeps no record at all: a
/// `zboot:pending` with neither was left by an interrupted deploy, or by an
/// operation that ended without clearing it.
fn unfinished(
    properties: &BTreeMap<String, NativeProperty>,
    name: &str,
    key: &str,
    value: &str,
) -> String {
    let recorded = properties
        .get(OPERATION_PROPERTY)
        .is_some_and(|record| pool_root_source(&record.source, name));
    let moved = properties
        .get(PLACEMENT_PROPERTY)
        .is_some_and(|placement| placement.source == "local");
    if key != PENDING_PROPERTY || recorded || moved {
        return format!("unfinished operation or staging on {name}: {key}={value}");
    }
    let remedy = if name.contains('/') {
        format!("or `zboot drop {name}` destroys what it left")
    } else {
        format!("or, if nothing on pool {name} is wanted, `zpool destroy {name}` removes it")
    };
    format!(
        "{name} carries {key}={value} with no operation record on its pool: it is left from an \
         interrupted deploy (which keeps no record) or another operation that ended without \
         clearing it; run that deploy again, which erases its disk, {remedy}"
    )
}
fn trusted_source(source: &str) -> bool {
    source == "local" || source.starts_with("inherited from ")
}
pub(crate) fn pool_root_source(source: &str, name: &str) -> bool {
    match source.strip_prefix("inherited from ") {
        Some(root) => !root.is_empty() && !root.contains('/') && contains(root, name),
        None => source == "local" && !name.contains('/'),
    }
}
use crate::engine::contains_dataset as contains;
fn refuse(detail: impl Into<String>) -> Error {
    Error::Inconsistent(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_pending_mark_without_a_record_reads_as_a_left_deploy() {
        let id = "29c4aaaa-1111-4111-8111-111111111111";
        let pending = |source: &str| NativeProperty {
            value: id.into(),
            source: source.into(),
        };
        let error = |properties: &BTreeMap<String, NativeProperty>, name: &str| {
            validate_supported_properties(properties, name)
                .unwrap_err()
                .to_string()
        };
        let mut properties = BTreeMap::from([(PENDING_PROPERTY.into(), pending("local"))]);
        let left = error(&properties, "stick/ROOT/default");
        assert!(
            left.contains(&format!(
                "stick/ROOT/default carries zboot:pending={id} with no operation record on its \
                 pool: it is left from an interrupted deploy"
            )) && left.ends_with(
                "run that deploy again, which erases its disk, or `zboot drop stick/ROOT/default` \
                 destroys what it left"
            ),
            "{left}"
        );
        let root = error(&properties, "stick");
        assert!(root.ends_with("`zpool destroy stick` removes it"), "{root}");
        // A record on the pool, or a move's fenced source, keeps the old text.
        properties.insert(OPERATION_PROPERTY.into(), pending("inherited from stick"));
        assert!(
            error(&properties, "stick/ROOT/default").contains("unfinished operation or staging"),
        );
        properties.remove(OPERATION_PROPERTY);
        properties.insert(PLACEMENT_PROPERTY.into(), pending("local"));
        assert!(!error(&properties, "stick/ROOT/default").contains("interrupted deploy"),);
    }
    #[cfg(feature = "internal")]
    #[test]
    fn an_operation_record_is_inert_only_on_and_below_its_pool_root() {
        let property = |source: &str| {
            BTreeMap::from([(
                OPERATION_PROPERTY.into(),
                NativeProperty {
                    value: "{}".into(),
                    source: source.into(),
                },
            )])
        };
        validate_supported_properties(&property("local"), "tank").unwrap();
        validate_supported_properties(&property("inherited from tank"), "tank/work/child").unwrap();
        for (source, name) in [
            ("local", "tank/work"),
            ("inherited from tank/work", "tank/work/child"),
            ("inherited from other", "tank/work"),
            ("received", "tank"),
        ] {
            assert!(
                validate_supported_properties(&property(source), name).is_err(),
                "{source} on {name}"
            );
        }
    }
    #[cfg(feature = "internal")]
    fn fixture() -> NativeState {
        use crate::engine::{InspectRequest, native};
        let rows = [
            ("tank", 1, false),
            ("tank/data", 2, false),
            ("tank/data/child", 3, false),
            ("tank/peer", 4, true),
        ];
        let output = rows.iter().map(|(name,id,readonly)|format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t/{name}\t-\t{}\t{}\tno\t{}\t{}\t-\toff\t-\t-\t-\t-\n",id+10,id+20,if *readonly{"on"}else{"off"},if *readonly{"noauto"}else{"on"})).collect::<String>();
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    "tank\t100\t1000\t0\t1000\tONLINE\ttank/data\n".into()
                } else {
                    output.clone()
                })
            },
        )
        .unwrap();
        let dataset_properties = inspection
            .datasets
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), prop(d.identity.guid.to_string(), "-")),
                        (
                            "createtxg".into(),
                            prop(d.identity.createtxg.to_string(), "-"),
                        ),
                        (
                            "objsetid".into(),
                            prop(d.identity.objsetid.to_string(), "-"),
                        ),
                    ]),
                )
            })
            .collect();
        NativeState {
            inspection,
            dataset_properties,
            pool_properties: PropertyInventory::from([(
                "tank".into(),
                BTreeMap::from([("guid".into(), prop("100", "-"))]),
            )]),
        }
    }
    fn prop(value: impl Into<String>, source: &str) -> NativeProperty {
        NativeProperty {
            value: value.into(),
            source: source.into(),
        }
    }
    #[cfg(feature = "internal")]
    fn paired() -> (NativeState, PairRecord) {
        let mut state = fixture();
        let endpoint = |name: &str| Endpoint {
            name: name.into(),
            identity: state
                .inspection
                .datasets
                .iter()
                .find(|d| d.name == name)
                .unwrap()
                .identity
                .clone(),
        };
        let record = PairRecord {
            schema_version: 1,
            pair_id: uuid::Uuid::new_v4().to_string(),
            endpoint: endpoint("tank/data"),
            peer: endpoint("tank/peer"),
            role: Role::Primary,
        };
        state
            .dataset_properties
            .get_mut("tank/data")
            .unwrap()
            .insert(
                PAIR_PROPERTY.into(),
                prop(record.encode().unwrap(), "local"),
            );
        state
            .dataset_properties
            .get_mut("tank/data/child")
            .unwrap()
            .insert(
                PAIR_PROPERTY.into(),
                prop(record.encode().unwrap(), "inherited from tank/data"),
            );
        state
            .dataset_properties
            .get_mut("tank/peer")
            .unwrap()
            .insert(
                PAIR_PROPERTY.into(),
                prop(record.counterpart().encode().unwrap(), "local"),
            );
        (state, record)
    }
    #[cfg(feature = "internal")]
    #[test]
    fn native_incarnations_and_mutual_fencing_admit_only_primary() {
        let (state, record) = paired();
        assert_eq!(
            ownership(&state, "tank/data/child").unwrap(),
            Ownership::Primary {
                record: record.clone()
            }
        );
        admit_working(&state, "tank/data/child").unwrap();
        assert_eq!(
            ownership(&state, "tank/peer").unwrap(),
            Ownership::Secondary {
                record: record.counterpart()
            }
        );
        assert!(admit_working(&state, "tank/peer").is_err());
        crate::engine::operation::SnapshotScope::plan(
            &state.inspection,
            &state.dataset_properties,
            &state.pool_properties,
            &["tank/data".into()],
        )
        .unwrap();
    }
    #[cfg(feature = "internal")]
    #[test]
    fn absent_peer_refuses_ownership_instead_of_assuming_a_role() {
        let (mut state, _) = paired();
        // The peer pool is exported or the peer dataset is otherwise missing.
        state.inspection.datasets.retain(|d| d.name != "tank/peer");
        state.dataset_properties.remove("tank/peer");
        for name in ["tank/data", "tank/data/child"] {
            let error = ownership(&state, name).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("peer unavailable for ownership validation: tank/peer"),
                "{name}: {error}"
            );
            assert!(admit_working(&state, name).is_err(), "{name}");
        }
    }
    #[test]
    fn a_management_property_this_build_does_not_read_refuses_and_names_its_holder() {
        // Keys of a later zboot and of earlier ones alike; a plain refusal,
        // with no "inconsistent ZFS observation" prefix.
        for key in ["zboot:future", "zboot:be", "zboot:journal:0b8f2c1e:header"] {
            for (source, holder) in [("local", "tank/data"), ("inherited from tank", "tank")] {
                let properties = BTreeMap::from([(key.into(), prop("1", source))]);
                let message = validate_supported_properties(&properties, "tank/data")
                    .unwrap_err()
                    .to_string();
                assert!(
                    message.starts_with(&format!(
                        "unsupported management property {key} on tank/data: this zboot does not read it"
                    )) && message.ends_with(&format!("`zfs inherit {key} {holder}`")),
                    "{message}"
                );
            }
        }
        // Another namespace is ordinary user data.
        let properties = BTreeMap::from([("zctl:role".into(), prop("1", "local"))]);
        validate_supported_properties(&properties, "tank/data").unwrap();
    }
    #[cfg(feature = "internal")]
    #[test]
    fn partial_publication_unknown_schema_stale_identity_and_source_refuse() {
        for case in 0..7 {
            let (mut state, mut record) = paired();
            match case {
                0 => {
                    state
                        .dataset_properties
                        .get_mut("tank/peer")
                        .unwrap()
                        .remove(PAIR_PROPERTY);
                }
                1 => {
                    record.schema_version = 99;
                    state
                        .dataset_properties
                        .get_mut("tank/data")
                        .unwrap()
                        .get_mut(PAIR_PROPERTY)
                        .unwrap()
                        .value = serde_json::to_string(&record).unwrap();
                }
                2 => {
                    record.endpoint.identity.objsetid = crate::engine::ObjsetId::new(999);
                    state
                        .dataset_properties
                        .get_mut("tank/data")
                        .unwrap()
                        .get_mut(PAIR_PROPERTY)
                        .unwrap()
                        .value = record.encode().unwrap();
                }
                3 => {
                    state
                        .dataset_properties
                        .get_mut("tank/data/child")
                        .unwrap()
                        .get_mut(PAIR_PROPERTY)
                        .unwrap()
                        .source = "local".into();
                }
                4 => {
                    state
                        .dataset_properties
                        .get_mut("tank/data/child")
                        .unwrap()
                        .remove(PAIR_PROPERTY);
                }
                5 => {
                    state
                        .dataset_properties
                        .get_mut("tank/peer")
                        .unwrap()
                        .insert(PENDING_PROPERTY.into(), prop("pending-id", "local"));
                }
                _ => {
                    state
                        .inspection
                        .datasets
                        .iter_mut()
                        .find(|d| d.name == "tank/peer")
                        .unwrap()
                        .readonly = false;
                }
            }
            assert!(ownership(&state, "tank/data/child").is_err(), "case {case}");
        }
    }
    #[cfg(feature = "internal")]
    #[test]
    fn foreign_fields_and_invalid_ids_cannot_become_management_authority() {
        let (_, record) = paired();
        let encoded = record.encode().unwrap();
        assert_eq!(PairRecord::parse(&encoded).unwrap(), record);
        let malicious = encoded.replacen('{', "{\"command\":\"destroy tank\",", 1);
        assert!(PairRecord::parse(&malicious).is_err());
        let mut record = record;
        record.peer = record.endpoint.clone();
        assert!(record.encode().is_err());
    }
}
