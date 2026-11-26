//! Caller-owned native effects under a writer session.
//!
//! An application admits the exact targets it will change, then dispatches
//! closed effects: one constructor per effect shape, each with a pinned argv
//! whose operands must be admitted targets. Before each spawn the library
//! runs the caller's guard, observes ZFS afresh, repeats the original
//! admission, binds the operands to that observation and runs the guard
//! again; only then does the child start, holding the session's own lock.
//! The reply says what the command reported, never what ZFS now holds: the
//! caller reads back before it continues and never retries blindly.
use crate::api::{DatasetTarget, Error, WriterSession, bind_targets, observe_within};
use crate::engine::{
    self, DatasetKind, Guid,
    dispatch::{self, Ran},
    lock, management,
    native::{self, NativeProperty},
    operation::{DatasetRef, SnapshotScope},
    state::{self, NativeState},
};
use crate::{DatasetIdentity, SnapshotRef};
use std::{collections::BTreeSet, time::Duration};

/// One imported pool by name and GUID, optionally bound to the import
/// instance its `load_guid` names. `load_guid` changes on every import, so a
/// target with one refuses a pool exported and imported again since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTarget {
    name: String,
    guid: Guid,
    load_guid: Option<Guid>,
}
impl PoolTarget {
    pub fn new(name: impl Into<String>, guid: Guid) -> Result<Self, Error> {
        let name = name.into();
        validate_pool_name(&name)?;
        if guid.get() == 0 {
            return Err(Error::new("pool target requires a nonzero GUID"));
        }
        Ok(Self {
            name,
            guid,
            load_guid: None,
        })
    }
    pub fn with_load_guid(mut self, load_guid: Guid) -> Result<Self, Error> {
        if load_guid.get() == 0 {
            return Err(Error::new("pool target requires a nonzero load_guid"));
        }
        self.load_guid = Some(load_guid);
        Ok(self)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn guid(&self) -> Guid {
        self.guid
    }
    pub fn load_guid(&self) -> Option<Guid> {
        self.load_guid
    }
}

/// One target of an effect admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectTarget(Target);
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Dataset(DatasetTarget),
    Subtree(DatasetTarget),
    Pool(PoolTarget),
    AbsentPool(String),
    ExportedPool(Guid),
}
impl EffectTarget {
    /// Exactly this dataset incarnation, without its descendants.
    pub fn dataset(target: DatasetTarget) -> Self {
        Self(Target::Dataset(target))
    }
    /// This dataset and every descendant. Membership is fixed at admission:
    /// a descendant created, destroyed or replaced since refuses dispatch.
    /// Changing an inheritable property requires this.
    pub fn subtree(target: DatasetTarget) -> Self {
        Self(Target::Subtree(target))
    }
    /// This imported pool incarnation.
    pub fn pool(target: PoolTarget) -> Self {
        Self(Target::Pool(target))
    }
    /// A pool name no imported pool has, for a pool create.
    pub fn absent_pool(name: impl Into<String>) -> Result<Self, Error> {
        let name = name.into();
        validate_pool_name(&name)?;
        Ok(Self(Target::AbsentPool(name)))
    }
    /// A pool GUID no imported pool has, for an import.
    pub fn exported_pool(guid: Guid) -> Result<Self, Error> {
        if guid.get() == 0 {
            return Err(Error::new("exported pool target requires a nonzero GUID"));
        }
        Ok(Self(Target::ExportedPool(guid)))
    }
}

/// A device path taken as given. The library cannot verify which disk a
/// path names: callers must take it only from their own reviewed device
/// selection and keep their own wrong-disk proof. Only its shape is checked
/// (absolute, normalized, no controls, nothing option-like).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePath(String);
impl DevicePath {
    pub fn new(path: impl Into<String>) -> Result<Self, Error> {
        let path = path.into();
        if !path.starts_with('/')
            || path.len() > 4096
            || path.chars().any(char::is_control)
            || path[1..]
                .split('/')
                .any(|part| part.is_empty() || part.starts_with('-') || matches!(part, "." | ".."))
        {
            return Err(Error::new(format!(
                "device path must be absolute and normalized: {path}"
            )));
        }
        Ok(Self(path))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One `key=value` property for a set or a create. Keys in zboot's
/// `zboot:` namespace and the library's `org.zfs-tools:` namespace are
/// refused: they are management state, written only by the applications
/// that read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyAssignment {
    key: String,
    value: String,
}
impl PropertyAssignment {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, Error> {
        let (key, value) = (key.into(), value.into());
        validate_key(&key)?;
        if value.len() > 8192 || value.chars().any(char::is_control) {
            return Err(Error::new(format!(
                "property value for {key} is too long or holds a control character"
            )));
        }
        Ok(Self { key, value })
    }
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    fn word(&self) -> String {
        format!("{}={}", self.key, self.value)
    }
}

/// Properties whose value no descendant inherits. Every other key, user
/// properties included, is treated as inheritable.
const NON_INHERITABLE: &[&str] = &[
    "canmount",
    "keylocation",
    "quota",
    "refquota",
    "refreservation",
    "reservation",
    "volsize",
];

fn reserved_key(key: &str) -> bool {
    key.starts_with("zboot:") || key.starts_with("org.zfs-tools:")
}

fn validate_key(key: &str) -> Result<(), Error> {
    if reserved_key(key) {
        return Err(Error::new(format!(
            "{key} is management state: effects never set or inherit zboot: or org.zfs-tools: keys"
        )));
    }
    if key.is_empty()
        || key.len() > 256
        || !key.starts_with(|c: char| c.is_ascii_lowercase())
        || !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.:@-".contains(c))
    {
        return Err(Error::new(format!("invalid property key: {key}")));
    }
    Ok(())
}

fn validate_assignments(assignments: &[PropertyAssignment]) -> Result<(), Error> {
    let mut keys = BTreeSet::new();
    for assignment in assignments {
        // Constructed values are valid; this repeats the namespace rule.
        validate_key(&assignment.key)?;
        if !keys.insert(assignment.key.as_str()) {
            return Err(Error::new(format!(
                "duplicate property key: {}",
                assignment.key
            )));
        }
    }
    Ok(())
}

fn validate_pool_name(name: &str) -> Result<(), Error> {
    engine::validate_pool_name(name).map_err(|_| {
        if name.contains('/') && engine::validate_dataset_name(name).is_ok() {
            Error::new(format!("pool name has a dataset component: {name}"))
        } else {
            Error::new(format!("invalid dataset selector: {name}"))
        }
    })
}

fn validate_input(input: &[u8]) -> Result<(), Error> {
    if input.is_empty() || input.len() > dispatch::MAX_INPUT {
        return Err(Error::new(format!(
            "effect input must be 1 to {} bytes",
            dispatch::MAX_INPUT
        )));
    }
    Ok(())
}

fn child_of(parent: &DatasetTarget, name: &str) -> Result<String, Error> {
    engine::validate_dataset_name(name)?;
    if name.rsplit_once('/').map(|(head, _)| head) != Some(parent.name()) {
        return Err(Error::new(format!(
            "{name} is not an immediate child of {}",
            parent.name()
        )));
    }
    Ok(name.into())
}

/// One closed native effect. Each constructor pins its argv; operands are
/// bound to admitted targets when it is dispatched. Input bytes (a key or
/// passphrase) are borrowed and written to the child's standard input; the
/// library keeps no copy, so the caller owns their zeroization.
#[derive(Clone, PartialEq, Eq)]
pub struct Effect<'a> {
    kind: Kind,
    input: Option<&'a [u8]>,
}
/// Input bytes are a key or passphrase: their length only.
impl std::fmt::Debug for Effect<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Effect")
            .field("kind", &self.kind)
            .field("input_bytes", &self.input.map(<[u8]>::len))
            .finish()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    CreateVolume {
        parent: DatasetTarget,
        name: String,
        size_bytes: u64,
        volblocksize: u64,
        properties: Vec<PropertyAssignment>,
    },
    CreateFilesystem {
        parent: DatasetTarget,
        name: String,
        properties: Vec<PropertyAssignment>,
    },
    Clone {
        origin: SnapshotRef,
        parent: DatasetTarget,
        name: String,
    },
    Destroy {
        target: DatasetTarget,
    },
    Rollback {
        target: DatasetTarget,
        point: SnapshotRef,
    },
    Set {
        target: DatasetTarget,
        properties: Vec<PropertyAssignment>,
    },
    Inherit {
        target: DatasetTarget,
        key: String,
    },
    LoadKey {
        root: DatasetTarget,
    },
    UnloadKey {
        root: DatasetTarget,
    },
    Unmount {
        target: DatasetTarget,
    },
    CreatePool {
        name: String,
        device: DevicePath,
        pool: Vec<PropertyAssignment>,
        filesystem: Vec<PropertyAssignment>,
    },
    ImportPool {
        guid: Guid,
        leaf: DevicePath,
        readonly: bool,
    },
    ExportPool {
        pool: PoolTarget,
    },
    SyncPool {
        pool: PoolTarget,
    },
}

impl<'a> Effect<'a> {
    fn new(kind: Kind) -> Self {
        Self { kind, input: None }
    }
    /// `zfs create -s -V SIZE -o volblocksize=N [-o KEY=VALUE]... NAME`: a
    /// sparse volume, an immediate child of `parent`, which must be absent.
    pub fn create_volume(
        parent: &DatasetTarget,
        name: &str,
        size_bytes: u64,
        volblocksize: u64,
        properties: &[PropertyAssignment],
    ) -> Result<Self, Error> {
        let name = child_of(parent, name)?;
        if size_bytes == 0
            || !volblocksize.is_power_of_two()
            || !(512..=16 * 1024 * 1024).contains(&volblocksize)
            || !size_bytes.is_multiple_of(volblocksize)
        {
            return Err(Error::new(
                "volume size must be a nonzero multiple of a power-of-two volblocksize",
            ));
        }
        validate_assignments(properties)?;
        if properties
            .iter()
            .any(|p| matches!(p.key.as_str(), "volblocksize" | "volsize"))
        {
            return Err(Error::new("volume geometry is given by its own operands"));
        }
        Ok(Self::new(Kind::CreateVolume {
            parent: parent.clone(),
            name,
            size_bytes,
            volblocksize,
            properties: properties.to_vec(),
        }))
    }
    /// `zfs create -u [-o KEY=VALUE]... NAME`: an unmounted filesystem, an
    /// immediate child of `parent`, which must be absent.
    pub fn create_filesystem(
        parent: &DatasetTarget,
        name: &str,
        properties: &[PropertyAssignment],
    ) -> Result<Self, Error> {
        let name = child_of(parent, name)?;
        validate_assignments(properties)?;
        Ok(Self::new(Kind::CreateFilesystem {
            parent: parent.clone(),
            name,
            properties: properties.to_vec(),
        }))
    }
    /// `zfs clone -u SNAPSHOT NAME` (not mounted): the origin's dataset and `parent` must be
    /// admitted, the origin not marked for deferred destruction, and `name`
    /// an absent immediate child of `parent` in the origin's pool.
    pub fn clone_snapshot(
        origin: &SnapshotRef,
        parent: &DatasetTarget,
        name: &str,
    ) -> Result<Self, Error> {
        engine::validate_snapshot_name(&origin.name)?;
        let name = child_of(parent, name)?;
        Ok(Self::new(Kind::Clone {
            origin: origin.clone(),
            parent: parent.clone(),
            name,
        }))
    }
    /// `zfs destroy NAME`, with no flags: an unpaired dataset with no
    /// descendants and no snapshots, which is not its pool's boot default
    /// and is not the last clone of an external origin marked for deferred
    /// destruction (destroying it would destroy that origin too).
    pub fn destroy(target: &DatasetTarget) -> Result<Self, Error> {
        if !target.name().contains('/') {
            return Err(Error::new("a pool's root dataset is not destroyed"));
        }
        Ok(Self::new(Kind::Destroy {
            target: target.clone(),
        }))
    }
    /// `zfs rollback SNAPSHOT`, with no flags: to the target's newest
    /// snapshot, of an unpaired dataset.
    pub fn rollback(target: &DatasetTarget, point: &SnapshotRef) -> Result<Self, Error> {
        engine::validate_snapshot_name(&point.name)?;
        bind_point(target, point)?;
        Ok(Self::new(Kind::Rollback {
            target: target.clone(),
            point: point.clone(),
        }))
    }
    /// `zfs set -u KEY=VALUE... NAME`, never `volsize`. An inheritable key
    /// needs the target admitted as a subtree.
    pub fn set_properties(
        target: &DatasetTarget,
        properties: &[PropertyAssignment],
    ) -> Result<Self, Error> {
        if properties.is_empty() {
            return Err(Error::new("a property set needs at least one property"));
        }
        validate_assignments(properties)?;
        if properties.iter().any(|p| p.key == "volsize") {
            // OpenZFS truncates a volume set to a smaller size.
            return Err(Error::new(
                "volsize is never set: a smaller size truncates the volume",
            ));
        }
        Ok(Self::new(Kind::Set {
            target: target.clone(),
            properties: properties.to_vec(),
        }))
    }
    /// `zfs inherit KEY NAME`, without `-r` or `-S`. An inheritable key
    /// needs the target admitted as a subtree.
    pub fn inherit_property(target: &DatasetTarget, key: &str) -> Result<Self, Error> {
        validate_key(key)?;
        Ok(Self::new(Kind::Inherit {
            target: target.clone(),
            key: key.into(),
        }))
    }
    /// `zfs load-key NAME`, with `key` on standard input: an encryption root
    /// whose `keylocation` is `prompt`, so the input is the key it reads.
    pub fn load_key(root: &DatasetTarget, key: &'a [u8]) -> Result<Self, Error> {
        validate_input(key)?;
        Ok(Self {
            kind: Kind::LoadKey { root: root.clone() },
            input: Some(key),
        })
    }
    /// `zfs unload-key NAME`: an encryption root.
    pub fn unload_key(root: &DatasetTarget) -> Self {
        Self::new(Kind::UnloadKey { root: root.clone() })
    }
    /// `zfs unmount NAME`, without `-f`: a filesystem.
    pub fn unmount(target: &DatasetTarget) -> Self {
        Self::new(Kind::Unmount {
            target: target.clone(),
        })
    }
    /// `zpool create [-o KEY=VALUE]... [-O KEY=VALUE]... NAME DEVICE`,
    /// without `-f`: one device, a name admitted as absent, and `input`
    /// (a passphrase for `keylocation=prompt`) on standard input.
    pub fn create_pool(
        name: &str,
        device: &DevicePath,
        pool_properties: &[PropertyAssignment],
        filesystem_properties: &[PropertyAssignment],
        input: Option<&'a [u8]>,
    ) -> Result<Self, Error> {
        validate_pool_name(name)?;
        validate_assignments(pool_properties)?;
        validate_assignments(filesystem_properties)?;
        if let Some(input) = input {
            validate_input(input)?;
        }
        Ok(Self {
            kind: Kind::CreatePool {
                name: name.into(),
                device: device.clone(),
                pool: pool_properties.to_vec(),
                filesystem: filesystem_properties.to_vec(),
            },
            input,
        })
    }
    /// `zpool import -N -o cachefile=none -d LEAF GUID`: one device, no
    /// mounts, no cache file, and a GUID admitted as not imported.
    pub fn import_pool(guid: Guid, leaf: &DevicePath) -> Result<Self, Error> {
        Self::import_pool_mode(guid, leaf, false)
    }
    /// `zpool import -N -o readonly=on -o cachefile=none -d LEAF GUID`: as
    /// [`Effect::import_pool`], imported read-only, so nothing in the pool
    /// can be written until it is exported and imported again.
    pub fn import_pool_readonly(guid: Guid, leaf: &DevicePath) -> Result<Self, Error> {
        Self::import_pool_mode(guid, leaf, true)
    }
    fn import_pool_mode(guid: Guid, leaf: &DevicePath, readonly: bool) -> Result<Self, Error> {
        if guid.get() == 0 {
            return Err(Error::new("pool import requires a nonzero GUID"));
        }
        Ok(Self::new(Kind::ImportPool {
            guid,
            leaf: leaf.clone(),
            readonly,
        }))
    }

    /// The program and arguments a dispatch of this effect runs when its
    /// admission and operand binding pass. It is fixed by the constructor's
    /// operands, so a caller can compare it with the command it consents to
    /// before any session or observation exists.
    pub fn argv(&self) -> (&'static str, Vec<String>) {
        match &self.kind {
            Kind::CreateVolume {
                name,
                size_bytes,
                volblocksize,
                properties,
                ..
            } => {
                let mut args = words(&["create", "-s", "-V"]);
                args.push(size_bytes.to_string());
                args.extend(["-o".into(), format!("volblocksize={volblocksize}")]);
                args.extend(options("-o", properties));
                args.push(name.clone());
                ("zfs", args)
            }
            Kind::CreateFilesystem {
                name, properties, ..
            } => {
                let mut args = words(&["create", "-u"]);
                args.extend(options("-o", properties));
                args.push(name.clone());
                ("zfs", args)
            }
            Kind::Clone { origin, name, .. } => {
                ("zfs", words(&["clone", "-u", &origin.name, name]))
            }
            Kind::Destroy { target } => ("zfs", vec!["destroy".into(), target.name().into()]),
            Kind::Rollback { point, .. } => ("zfs", vec!["rollback".into(), point.name.clone()]),
            Kind::Set { target, properties } => {
                let mut args = words(&["set", "-u"]);
                args.extend(properties.iter().map(PropertyAssignment::word));
                args.push(target.name().into());
                ("zfs", args)
            }
            Kind::Inherit { target, key } => (
                "zfs",
                vec!["inherit".into(), key.clone(), target.name().into()],
            ),
            Kind::LoadKey { root } => ("zfs", vec!["load-key".into(), root.name().into()]),
            Kind::UnloadKey { root } => ("zfs", vec!["unload-key".into(), root.name().into()]),
            Kind::Unmount { target } => ("zfs", vec!["unmount".into(), target.name().into()]),
            Kind::CreatePool {
                name,
                device,
                pool,
                filesystem,
            } => {
                let mut args = vec!["create".into()];
                args.extend(options("-o", pool));
                args.extend(options("-O", filesystem));
                args.extend([name.clone(), device.0.clone()]);
                ("zpool", args)
            }
            Kind::ImportPool {
                guid,
                leaf,
                readonly,
            } => {
                let mut args = words(&["import", "-N"]);
                if *readonly {
                    args.extend(words(&["-o", "readonly=on"]));
                }
                args.extend(words(&["-o", "cachefile=none", "-d"]));
                args.extend([leaf.0.clone(), guid.to_string()]);
                ("zpool", args)
            }
            Kind::ExportPool { pool } => ("zpool", vec!["export".into(), pool.name.clone()]),
            Kind::SyncPool { pool } => ("zpool", vec!["sync".into(), pool.name.clone()]),
        }
    }
    /// `zpool export NAME`, without `-f`: an admitted pool, bound to its
    /// import instance when the target names a `load_guid`.
    pub fn export_pool(pool: &PoolTarget) -> Self {
        Self::new(Kind::ExportPool { pool: pool.clone() })
    }
    /// `zpool sync NAME`: an admitted pool.
    pub fn sync_pool(pool: &PoolTarget) -> Self {
        Self::new(Kind::SyncPool { pool: pool.clone() })
    }

    /// An effect that adds or removes a dataset or pool, or may replace a
    /// dataset's contents, ends its admission: membership the admission
    /// bound no longer describes what is there.
    fn changes_membership(&self) -> bool {
        !matches!(
            self.kind,
            Kind::Set { .. }
                | Kind::Inherit { .. }
                | Kind::LoadKey { .. }
                | Kind::UnloadKey { .. }
                | Kind::Unmount { .. }
                | Kind::SyncPool { .. }
        )
    }
}

fn bind_point(target: &DatasetTarget, point: &SnapshotRef) -> Result<(), Error> {
    let parent = point.name.split_once('@').map(|(head, _)| head);
    if parent != Some(target.name())
        || point.dataset_guid != target.identity().guid
        || point.identity.pool_guid != target.identity().pool_guid
    {
        return Err(Error::new(format!(
            "snapshot {} is not a snapshot of the target {}",
            point.name,
            target.name()
        )));
    }
    Ok(())
}

/// What the dispatched command reported. `Failed` and `Uncertain` may still
/// have changed ZFS; read back before continuing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum EffectReply {
    Succeeded,
    Failed { status: i32, stderr: String },
    Uncertain { why: String },
}

/// The guarded admission of effect targets, borrowed from a writer session.
pub struct EffectScope<'a> {
    session: &'a mut WriterSession,
    targets: Vec<EffectTarget>,
    admission: Admission,
    guard: Box<Guard<'a>>,
    ended: Option<String>,
    /// The deadline of each observation this scope makes, if the caller set one.
    within: Option<Duration>,
}

type Guard<'a> = dyn FnMut(&GuardCheck<'_>) -> Result<(), Error> + 'a;

/// What the caller's guard is asked to approve: the admission (no effect),
/// one effect before its fresh observation, or that effect with the argv it
/// was bound to, immediately before the spawn. Compare `effect()` with the
/// effect your consent names so a consent cannot carry over to another.
pub struct GuardCheck<'a> {
    effect: Option<&'a Effect<'a>>,
    argv: Option<(&'a str, &'a [String])>,
}
impl<'a> GuardCheck<'a> {
    pub fn effect(&self) -> Option<&'a Effect<'a>> {
        self.effect
    }
    /// The program and arguments about to run; `None` before binding.
    pub fn argv(&self) -> Option<(&'a str, &'a [String])> {
        self.argv
    }
}

impl WriterSession {
    /// Admit fresh native evidence for these effect targets. The guard runs
    /// before this observation and twice around every dispatch's binding.
    /// Its observations have no deadline; see [`Self::admit_effects_within`].
    pub fn admit_effects<'a>(
        &'a mut self,
        targets: &[EffectTarget],
        guard: impl FnMut(&GuardCheck<'_>) -> Result<(), Error> + 'a,
    ) -> Result<EffectScope<'a>, Error> {
        self.admit_effects_with(targets, guard, None, &mut NativeEffects)
    }

    /// [`Self::admit_effects`] with every observation of the scope (this
    /// admission's and each dispatch's fresh one) bounded by `within`: one
    /// deadline per observation, covering all its queries and the completion
    /// of their output, not the guard or the effect. On expiry the running
    /// query's group is sent SIGKILL and its leader reaped, nothing is admitted or
    /// dispatched, and the error carries [`Error::observation_stop`]. A zero
    /// deadline is refused.
    pub fn admit_effects_within<'a>(
        &'a mut self,
        targets: &[EffectTarget],
        guard: impl FnMut(&GuardCheck<'_>) -> Result<(), Error> + 'a,
        within: Duration,
    ) -> Result<EffectScope<'a>, Error> {
        self.admit_effects_with(targets, guard, Some(within), &mut NativeEffects)
    }

    fn admit_effects_with<'a>(
        &'a mut self,
        targets: &[EffectTarget],
        mut guard: impl FnMut(&GuardCheck<'_>) -> Result<(), Error> + 'a,
        within: Option<Duration>,
        backend: &mut impl Backend,
    ) -> Result<EffectScope<'a>, Error> {
        self.usable()?;
        if targets.is_empty() {
            return Err(Error::new("empty effect admission"));
        }
        if within.is_some_and(|within| within.is_zero()) {
            return Err(Error::new("an observation deadline must be nonzero"));
        }
        for (index, target) in targets.iter().enumerate() {
            if targets[..index].contains(target) {
                return Err(Error::new("duplicate effect target"));
            }
        }
        guarded(
            &mut guard,
            &GuardCheck {
                effect: None,
                argv: None,
            },
        )?;
        let observed = backend.observe(within)?;
        let admission = admit(targets, &observed)?;
        Ok(EffectScope {
            session: self,
            targets: targets.to_vec(),
            admission,
            guard: Box::new(guard),
            ended: None,
            within,
        })
    }
}

fn guarded(
    guard: &mut dyn FnMut(&GuardCheck<'_>) -> Result<(), Error>,
    check: &GuardCheck<'_>,
) -> Result<(), Error> {
    guard(check)
        .map_err(|error| Error::new(format!("application lifecycle guard refused: {error}")))
}

impl EffectScope<'_> {
    /// Dispatch one effect, killing its process group at `deadline`. An
    /// `Err` means no effect child was started; the fresh observation before
    /// the spawn has the scope's own deadline, if any. A child whose reap cannot be
    /// confirmed after the kill poisons the session: it refuses every later
    /// admission and dispatch.
    pub fn dispatch(
        &mut self,
        effect: &Effect<'_>,
        deadline: Duration,
    ) -> Result<EffectReply, Error> {
        self.dispatch_with(effect, deadline, &mut NativeEffects)
    }

    fn dispatch_with(
        &mut self,
        effect: &Effect<'_>,
        deadline: Duration,
        backend: &mut impl Backend,
    ) -> Result<EffectReply, Error> {
        self.session.usable()?;
        if let Some(why) = &self.ended {
            return Err(Error::new(format!(
                "this admission ended when {why} changed its membership; admit again"
            )));
        }
        if deadline.is_zero() {
            return Err(Error::new("an effect needs a nonzero deadline"));
        }
        guarded(
            &mut *self.guard,
            &GuardCheck {
                effect: Some(effect),
                argv: None,
            },
        )?;
        let observed = backend.observe(self.within)?;
        if admit(&self.targets, &observed)? != self.admission {
            return Err(Error::new(
                "admitted targets or their management changed since admission",
            ));
        }
        let (program, args) = bind(effect, &self.admission, &self.targets, &observed)?;
        guarded(
            &mut *self.guard,
            &GuardCheck {
                effect: Some(effect),
                argv: Some((program, &args)),
            },
        )?;
        let ran = backend.run(&self.session.held, program, &args, effect.input, deadline);
        if effect.changes_membership() && !matches!(ran, Ran::NotStarted(_)) {
            self.ended = Some(format!("{program} {}", args[0]));
        }
        Ok(match ran {
            Ran::NotStarted(why) => {
                return Err(Error::new(format!(
                    "{program} {} did not start: {why}",
                    args[0]
                )));
            }
            Ran::Exited { code: 0, .. } => EffectReply::Succeeded,
            Ran::Exited { code, stderr } => EffectReply::Failed {
                status: code,
                stderr,
            },
            Ran::Uncertain(why) => EffectReply::Uncertain { why },
            Ran::Unreaped(why) => {
                self.session.poisoned = Some(why.clone());
                EffectReply::Uncertain {
                    why: format!("{why}; the writer session is poisoned"),
                }
            }
        })
    }
}

/// The admitted evidence a dispatch must find again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Admission {
    exact: Option<SnapshotScope>,
    subtree: Option<SnapshotScope>,
}
impl Admission {
    /// Whether `operand` is admitted, and whether with all its descendants.
    fn member(&self, operand: &DatasetTarget) -> Result<bool, engine::Error> {
        self.member_by(operand.name(), operand.identity())
    }
    fn member_by(&self, name: &str, identity: &DatasetIdentity) -> Result<bool, engine::Error> {
        fn find<'s>(scope: &'s Option<SnapshotScope>, name: &str) -> Option<&'s DatasetRef> {
            scope
                .as_ref()
                .and_then(|scope| scope.datasets().iter().find(|d| d.name == name))
        }
        let (subtree, exact) = (find(&self.subtree, name), find(&self.exact, name));
        if subtree.or(exact).is_none() {
            return Err(refuse(format!("operand {name} is not an admitted target")));
        }
        if [subtree, exact]
            .into_iter()
            .flatten()
            .any(|d| &d.identity != identity)
        {
            return Err(refuse(format!(
                "operand {name} is another incarnation than the admitted one"
            )));
        }
        Ok(subtree.is_some())
    }
}

fn refuse(detail: impl Into<String>) -> engine::Error {
    engine::Error::Refused(detail.into())
}

fn admit(targets: &[EffectTarget], s: &NativeState) -> Result<Admission, engine::Error> {
    let (mut exact, mut subtree, mut datasets) = (vec![], vec![], vec![]);
    for target in targets {
        match &target.0 {
            Target::Dataset(t) => {
                exact.push(t.name().to_string());
                datasets.push(t.clone());
            }
            Target::Subtree(t) => {
                subtree.push(t.name().to_string());
                datasets.push(t.clone());
            }
            Target::Pool(pool) => {
                let mut matching = s.inspection.pools.iter().filter(|p| p.name == pool.name);
                let found = matching.next();
                if matching.next().is_some() || found.is_none_or(|p| p.guid != pool.guid) {
                    return Err(refuse(format!(
                        "pool {} is not imported as the admitted GUID {}",
                        pool.name, pool.guid
                    )));
                }
                let properties = s
                    .pool_properties
                    .get(&pool.name)
                    .ok_or_else(|| refuse(format!("pool properties missing: {}", pool.name)))?;
                if properties.get("guid").map(|p| p.value.as_str())
                    != Some(pool.guid.to_string().as_str())
                {
                    return Err(refuse(format!("pool property GUID changed: {}", pool.name)));
                }
                if let Some(expected) = pool.load_guid
                    && properties.get("load_guid").map(|p| p.value.as_str())
                        != Some(expected.to_string().as_str())
                {
                    return Err(refuse(format!(
                        "pool {} is not the admitted import instance (load_guid)",
                        pool.name
                    )));
                }
                if let Some(key) = properties.keys().find(|key| management::managed_key(key)) {
                    return Err(refuse(format!(
                        "pool {} carries management property {key}",
                        pool.name
                    )));
                }
            }
            Target::AbsentPool(name) => {
                if s.inspection.pools.iter().any(|p| &p.name == name) {
                    return Err(refuse(format!("a pool named {name} is imported")));
                }
            }
            Target::ExportedPool(guid) => {
                if s.inspection.pools.iter().any(|p| p.guid == *guid) {
                    return Err(refuse(format!("pool GUID {guid} is imported")));
                }
            }
        }
    }
    bind_targets(&datasets, s)?;
    let plan = |roots: &[String], recursive| {
        (!roots.is_empty())
            .then(|| {
                SnapshotScope::plan_effect(
                    &s.inspection,
                    &s.dataset_properties,
                    &s.pool_properties,
                    roots,
                    recursive,
                )
            })
            .transpose()
    };
    Ok(Admission {
        exact: plan(&exact, false)?,
        subtree: plan(&subtree, true)?,
    })
}

fn find<'s>(s: &'s NativeState, name: &str) -> Option<&'s engine::Dataset> {
    s.inspection.datasets.iter().find(|d| d.name == name)
}
fn snapshots(s: &NativeState) -> Result<&[engine::Snapshot], engine::Error> {
    s.inspection
        .snapshots
        .as_deref()
        .ok_or_else(|| refuse("native observation lacks snapshots"))
}
fn absent(s: &NativeState, name: &str) -> Result<(), engine::Error> {
    if s.inspection
        .datasets
        .iter()
        .any(|d| engine::contains_dataset(name, &d.name))
    {
        return Err(refuse(format!("{name} already exists")));
    }
    Ok(())
}
fn kind_of<'s>(
    s: &'s NativeState,
    target: &DatasetTarget,
    kind: DatasetKind,
) -> Result<&'s engine::Dataset, engine::Error> {
    let dataset = find(s, target.name())
        .filter(|d| &d.identity == target.identity())
        .ok_or_else(|| refuse(format!("{} was not observed as admitted", target.name())))?;
    if dataset.kind != kind {
        return Err(refuse(format!("{} is not a {kind:?}", target.name())));
    }
    Ok(dataset)
}
/// A dataset no zboot pair or unfinished zboot operation touches: unpaired,
/// named as a peer by no other pair record, and in a pool without an
/// operation record.
fn settled(s: &NativeState, name: &str) -> Result<(), engine::Error> {
    settled_pool(s, name.split('/').next().unwrap_or(name))?;
    if !matches!(
        management::ownership(s, name)?,
        management::Ownership::Unpaired
    ) {
        return Err(refuse(format!(
            "{name} is paired; zboot's pair verbs own it"
        )));
    }
    if let Some(holder) = management::peer_references(s, name).first() {
        return Err(refuse(format!(
            "{holder}'s pair record names {name} as its peer: a pair or unpair \
             is unfinished; finish it with zboot first"
        )));
    }
    Ok(())
}
/// Every dataset at or below `root`.
fn settled_tree(s: &NativeState, root: &str) -> Result<(), engine::Error> {
    for dataset in &s.inspection.datasets {
        if engine::contains_dataset(root, &dataset.name) {
            settled(s, &dataset.name)?;
        }
    }
    Ok(())
}
fn settled_pool(s: &NativeState, pool: &str) -> Result<(), engine::Error> {
    if property(s, pool, management::OPERATION_PROPERTY).is_some() {
        return Err(refuse(format!(
            "pool {pool} holds a zboot operation record; resume or abandon it with zboot first"
        )));
    }
    Ok(())
}
/// Every dataset whose key is `root`'s.
fn settled_keys(s: &NativeState, root: &str) -> Result<(), engine::Error> {
    for dataset in &s.inspection.datasets {
        if dataset.encryptionroot.as_deref() == Some(root) || dataset.name == root {
            settled(s, &dataset.name)?;
        }
    }
    Ok(())
}
fn property<'s>(s: &'s NativeState, name: &str, key: &str) -> Option<&'s NativeProperty> {
    s.dataset_properties.get(name).and_then(|p| p.get(key))
}
fn encryption_root(s: &NativeState, target: &DatasetTarget) -> Result<(), engine::Error> {
    let dataset = find(s, target.name())
        .filter(|d| &d.identity == target.identity())
        .ok_or_else(|| refuse(format!("{} was not observed as admitted", target.name())))?;
    if dataset.encryptionroot.as_deref() != Some(target.name()) {
        return Err(refuse(format!(
            "{} is not an encryption root",
            target.name()
        )));
    }
    Ok(())
}
fn inheritance(
    admission: &Admission,
    target: &DatasetTarget,
    keys: &[&str],
    s: &NativeState,
) -> Result<(), engine::Error> {
    let subtree = admission.member(target)?;
    if keys.iter().any(|key| !NON_INHERITABLE.contains(key)) {
        if !subtree {
            return Err(refuse(format!(
                "an inheritable property change on {} needs its subtree admitted",
                target.name()
            )));
        }
        settled_tree(s, target.name())
    } else {
        settled(s, target.name())
    }
}
fn words(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).into()).collect()
}
fn options(flag: &str, properties: &[PropertyAssignment]) -> Vec<String> {
    properties
        .iter()
        .flat_map(|p| [flag.to_string(), p.word()])
        .collect()
}

/// Bind the effect's operands to the fresh observation and its argv.
fn bind(
    effect: &Effect<'_>,
    admission: &Admission,
    targets: &[EffectTarget],
    s: &NativeState,
) -> Result<(&'static str, Vec<String>), engine::Error> {
    match &effect.kind {
        Kind::CreateVolume { parent, name, .. } | Kind::CreateFilesystem { parent, name, .. } => {
            admission.member(parent)?;
            kind_of(s, parent, DatasetKind::Filesystem)?;
            settled(s, parent.name())?;
            absent(s, name)?;
        }
        Kind::Clone {
            origin,
            parent,
            name,
        } => {
            let source = origin
                .name
                .split_once('@')
                .map(|(head, _)| head)
                .unwrap_or_default();
            let source = find(s, source)
                .filter(|d| d.identity.guid == origin.dataset_guid)
                .ok_or_else(|| refuse(format!("origin dataset of {} changed", origin.name)))?;
            admission.member_by(&source.name, &source.identity)?;
            let point = snapshots(s)?
                .iter()
                .find(|p| p.name == origin.name && p.point() == *origin)
                .ok_or_else(|| refuse(format!("origin {} changed or is gone", origin.name)))?;
            if point.defer_destroy {
                return Err(refuse(format!(
                    "origin {} is marked for deferred destruction",
                    origin.name
                )));
            }
            admission.member(parent)?;
            kind_of(s, parent, DatasetKind::Filesystem)?;
            settled(s, &source.name)?;
            settled(s, parent.name())?;
            if parent.identity().pool_guid != origin.identity.pool_guid {
                return Err(refuse("a clone stays in its origin's pool"));
            }
            absent(s, name)?;
        }
        Kind::Destroy { target } => {
            admission.member(target)?;
            let dataset = find(s, target.name())
                .filter(|d| &d.identity == target.identity())
                .ok_or_else(|| refuse(format!("{} was not observed as admitted", target.name())))?;
            if s.inspection.datasets.iter().any(|d| {
                d.name != target.name() && engine::contains_dataset(target.name(), &d.name)
            }) {
                return Err(refuse(format!("{} has descendants", target.name())));
            }
            let all = snapshots(s)?;
            if all
                .iter()
                .any(|p| p.name.split_once('@').map(|(head, _)| head) == Some(target.name()))
            {
                return Err(refuse(format!(
                    "{} has snapshots; delete them through a reviewed checkpoint deletion first",
                    target.name()
                )));
            }
            if s.inspection
                .pools
                .iter()
                .any(|p| p.bootfs.as_deref() == Some(target.name()))
            {
                return Err(refuse(format!(
                    "{} is its pool's boot default",
                    target.name()
                )));
            }
            settled(s, target.name())?;
            if let Some(origin) = engine::deferred_origin(dataset, target.name(), all) {
                return Err(refuse(format!(
                    "destroying {} would also destroy its deferred origin {origin}",
                    target.name()
                )));
            }
        }
        Kind::Rollback { target, point } => {
            admission.member(target)?;
            let all = snapshots(s)?;
            let current = all
                .iter()
                .find(|p| p.name == point.name && p.point() == *point)
                .ok_or_else(|| refuse(format!("snapshot {} changed or is gone", point.name)))?;
            if all.iter().any(|p| {
                p.name.split_once('@').map(|(head, _)| head) == Some(target.name())
                    && p.identity.createtxg > current.identity.createtxg
            }) {
                return Err(refuse(format!(
                    "{} is not the newest snapshot of {}; a rollback destroys nothing",
                    point.name,
                    target.name()
                )));
            }
            settled(s, target.name())?;
        }
        Kind::Set { target, properties } => {
            let keys: Vec<_> = properties.iter().map(|p| p.key.as_str()).collect();
            inheritance(admission, target, &keys, s)?;
        }
        Kind::Inherit { target, key } => {
            inheritance(admission, target, &[key], s)?;
        }
        Kind::LoadKey { root } => {
            admission.member(root)?;
            encryption_root(s, root)?;
            settled_keys(s, root.name())?;
            if property(s, root.name(), "keylocation").map(|p| p.value.as_str()) != Some("prompt") {
                return Err(refuse(format!(
                    "{} does not read its key from a prompt",
                    root.name()
                )));
            }
        }
        Kind::UnloadKey { root } => {
            admission.member(root)?;
            encryption_root(s, root)?;
            settled_keys(s, root.name())?;
        }
        Kind::Unmount { target } => {
            admission.member(target)?;
            kind_of(s, target, DatasetKind::Filesystem)?;
            settled_tree(s, target.name())?;
        }
        Kind::CreatePool { name, .. } => {
            if !targets
                .iter()
                .any(|t| matches!(&t.0, Target::AbsentPool(p) if p == name))
            {
                return Err(refuse(format!(
                    "pool name {name} is not admitted as absent"
                )));
            }
        }
        Kind::ImportPool { guid, .. } => {
            if !targets
                .iter()
                .any(|t| matches!(&t.0, Target::ExportedPool(g) if g == guid))
            {
                return Err(refuse(format!(
                    "pool GUID {guid} is not admitted as exported"
                )));
            }
        }
        Kind::ExportPool { pool } | Kind::SyncPool { pool } => {
            if !targets
                .iter()
                .any(|t| matches!(&t.0, Target::Pool(p) if p == pool))
            {
                return Err(refuse(format!("pool {} is not admitted", pool.name)));
            }
            settled_pool(s, &pool.name)?;
        }
    }
    Ok(effect.argv())
}

/// Observation and spawn seam; the native one is the only production one.
trait Backend {
    fn observe(&mut self, within: Option<Duration>) -> Result<NativeState, Error>;
    fn run(
        &mut self,
        held: &lock::WriterLock,
        program: &'static str,
        args: &[String],
        input: Option<&[u8]>,
        deadline: Duration,
    ) -> Ran;
}
struct NativeEffects;
impl Backend for NativeEffects {
    fn observe(&mut self, within: Option<Duration>) -> Result<NativeState, Error> {
        observe_within(within, |mut run| {
            state::observe_with(&mut run).map_err(Error::from)
        })
    }
    fn run(
        &mut self,
        held: &lock::WriterLock,
        program: &'static str,
        args: &[String],
        input: Option<&[u8]>,
        deadline: Duration,
    ) -> Ran {
        dispatch::run_in_custody(held, program, args, input, deadline, dispatch::REAP_GRACE)
    }
}

/// A dataset's pair peer as its pair record names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    name: String,
    identity: DatasetIdentity,
}
impl Peer {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn identity(&self) -> &DatasetIdentity {
        &self.identity
    }
}

/// A dataset's role in a zboot pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    Unpaired,
    Primary { peer: Peer },
    Secondary { peer: Peer },
}

/// Unfinished zboot work that bears on a dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unfinished {
    /// Its pool's root holds a `zboot:operation` record.
    OperationRecord { pool: String },
    /// A `zboot:pending` mark, set on `holder` (the dataset or an ancestor).
    Pending { id: String, holder: String },
    /// A `zboot:staging` mark, set on `holder`.
    Staging { id: String, holder: String },
}

/// The management facts of one dataset: its pair role and any unfinished
/// zboot work. Sequential read evidence, not admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Management {
    role: Role,
    unfinished: Vec<Unfinished>,
}
impl Management {
    pub fn role(&self) -> &Role {
        &self.role
    }
    /// Empty when nothing is unfinished. A mark and its pool's record can
    /// both be present, so this is a list.
    pub fn unfinished(&self) -> &[Unfinished] {
        &self.unfinished
    }
}

/// Read a dataset's management facts without a writer session. A management
/// property this build does not read, an invalid pair record, or a peer that
/// is not imported is an error, never a reported role. Its queries have no
/// deadline; see [`observe_management_within`].
pub fn observe_management(name: &str) -> Result<Management, Error> {
    observe_management_with(name, &mut native::run)
}

/// [`observe_management`] with the whole observation bounded by `within`,
/// as [`crate::InventoryRequest::within`] bounds an inventory.
pub fn observe_management_within(name: &str, within: Duration) -> Result<Management, Error> {
    observe_within(Some(within), |mut run| {
        observe_management_with(name, &mut run)
    })
}

fn observe_management_with(
    name: &str,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, engine::Error>,
) -> Result<Management, Error> {
    engine::validate_dataset_name(name)?;
    management_of(&state::observe_with(run)?, name)
}

fn management_of(s: &NativeState, name: &str) -> Result<Management, Error> {
    let properties = management::bound_properties(s, name)?;
    let holder = |p: &NativeProperty| {
        p.source
            .strip_prefix("inherited from ")
            .unwrap_or(name)
            .to_string()
    };
    let mut unfinished = vec![];
    if let Some(record) = properties.get(management::OPERATION_PROPERTY) {
        let pool = engine::pool_of(name);
        if !management::pool_root_source(&record.source, name) {
            return Err(Error::new(format!(
                "{name} carries an operation record that is not its pool root's"
            )));
        }
        unfinished.push(Unfinished::OperationRecord { pool: pool.into() });
    }
    for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
        if let Some(p) = properties.get(key) {
            let (id, holder) = (p.value.clone(), holder(p));
            unfinished.push(if key == management::PENDING_PROPERTY {
                Unfinished::Pending { id, holder }
            } else {
                Unfinished::Staging { id, holder }
            });
        }
    }
    // Ownership refuses unfinished marks; they are reported above instead.
    let peer = |record: management::PairRecord| Peer {
        name: record.peer.name,
        identity: record.peer.identity,
    };
    let references = management::peer_references(s, name);
    let role = match management::ownership_ignoring_unfinished(s, name)? {
        management::Ownership::Unpaired => Role::Unpaired,
        management::Ownership::Primary { record } => Role::Primary { peer: peer(record) },
        management::Ownership::Secondary { record } => Role::Secondary { peer: peer(record) },
    };
    let expected = match &role {
        Role::Unpaired => None,
        Role::Primary { peer } | Role::Secondary { peer } => Some(peer.name.as_str()),
    };
    if let Some(holder) = references
        .iter()
        .find(|holder| Some(holder.as_str()) != expected)
    {
        return Err(Error::new(format!(
            "{holder}'s pair record names {name} as its peer: a pair or unpair is \
             unfinished, so {name}'s role is not known"
        )));
    }
    Ok(Management { role, unfinished })
}

#[cfg(test)]
#[path = "effects_tests.rs"]
mod tests;
