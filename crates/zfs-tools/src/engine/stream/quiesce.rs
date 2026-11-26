//! Drain a pool's queued zvol work before trusting device absence.
//!
//! A property read or a single absent /sys entry does not fence an allocator
//! which already read the old volmode. A fresh empty volume beneath a verified
//! volmode=none parent cannot have an early minor. Its later explicit dev
//! request runs through the pool's serial zvol task queue. Observing that minor
//! establishes passage through earlier tasks; target absence is checked after
//! that barrier. All temporary objects are empty and identity-bound.

use super::require_endpoint;
use crate::engine::{DatasetKind, Error, InspectRequest, management::Endpoint, native};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    thread,
    time::Duration,
};

const OWNER: &str = "org.zfs-tools:receive-barrier";
const PROBE_PREFIX: &str = "zboot-receive-probe-";
const NAME_BYTES: usize = 256;
// OpenZFS sys/fs/zfs.h: _IOR(0x12, 125, char[256]). Linux generic ioctl ABI.
const BLKZNAME: libc::c_ulong = 0x8100_127d;

fn refuse(message: impl Into<String>) -> Error {
    Error::Inconsistent(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    endpoint: Endpoint,
    volume: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    operation_id: String,
    scope: Endpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    schema_version: u32,
    authority: Authority,
    endpoint: Endpoint,
    volume: bool,
}
impl Ownership {
    fn new(endpoint: &Endpoint, volume: bool, owner: &Authority) -> Self {
        Self {
            schema_version: 1,
            authority: owner.clone(),
            endpoint: endpoint.clone(),
            volume,
        }
    }
    fn encoded(&self) -> Result<String, Error> {
        let value = serde_json::to_string(self).map_err(|error| refuse(error.to_string()))?;
        if value.len() > 1024 {
            return Err(refuse("receive barrier ownership exceeds 1KiB"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone)]
struct Probe {
    authority: Authority,
    container: Endpoint,
    sentinel: Option<Endpoint>,
}

trait Backend {
    /// Only identity-bound objects with this operation's local authority;
    /// unknown children or snapshots prevent returning a recovery candidate.
    fn probes(&mut self, endpoint: &Endpoint, owner: &str) -> Result<Vec<Probe>, Error>;
    fn scope(&mut self, endpoint: &Endpoint) -> Result<Vec<Member>, Error>;
    fn create(&mut self, name: &str, volume: bool, owner: &Authority) -> Result<Endpoint, Error>;
    fn verify(&mut self, endpoint: &Endpoint, volume: bool, owner: &Authority)
    -> Result<(), Error>;
    fn mode(&mut self, endpoint: &Endpoint, owner: &Authority, mode: &str) -> Result<(), Error>;
    fn minor(&mut self, endpoint: &Endpoint) -> Result<bool, Error>;
    fn remove(&mut self, endpoint: &Endpoint, volume: bool, owner: &Authority)
    -> Result<(), Error>;
    fn pause(&mut self);
}

/// The caller holds the writer lock, has recorded original placement, and has
/// finished every preceding import/receive call. No existing data enters the
/// empty preparation objects. An interrupted call may leave those objects;
/// a retry retires only bound owned probes before inspecting its data scope,
/// then uses fresh names. Unbound inert preparation objects are not adopted.
pub fn quiesce_inert(endpoint: &Endpoint, operation_id: &str) -> Result<(), Error> {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    quiesce_with(endpoint, operation_id, &nonce, &mut Native)
}

/// Exact raw-device absence for a volume and all of its snapshot/partition
/// minors. This alone is not the task-queue drain barrier.
pub fn volume_unavailable(endpoint: &Endpoint) -> Result<bool, Error> {
    Ok(!Native.minor(endpoint)?)
}

fn quiesce_with(
    endpoint: &Endpoint,
    operation_id: &str,
    nonce: &str,
    backend: &mut impl Backend,
) -> Result<(), Error> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        || nonce.len() != 32
        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(refuse("invalid inert-receive barrier ownership"));
    }
    // This must precede scope: a crash after DEV can leave an owned probe
    // inside a pool-root scope, which correctly refuses non-inert members.
    for probe in backend.probes(endpoint, operation_id)? {
        if let Some(sentinel) = probe.sentinel {
            backend.verify(&sentinel, true, &probe.authority)?;
            backend.remove(&sentinel, true, &probe.authority)?;
        }
        backend.verify(&probe.container, false, &probe.authority)?;
        backend.remove(&probe.container, false, &probe.authority)?;
    }
    let before = backend.scope(endpoint)?;
    let volumes: Vec<_> = before.iter().filter(|member| member.volume).collect();
    if volumes.is_empty() {
        return Ok(());
    }
    let pool = endpoint.name.split('/').next().unwrap();
    let owner = Authority {
        operation_id: operation_id.into(),
        scope: endpoint.clone(),
    };
    let container = format!("{pool}/{PROBE_PREFIX}{nonce}");
    let container = backend.create(&container, false, &owner)?;
    backend.verify(&container, false, &owner)?;
    let sentinel = backend.create(&format!("{}/probe", container.name), true, &owner)?;
    backend.verify(&sentinel, true, &owner)?;
    if backend.minor(&sentinel)? {
        return Err(refuse(
            "fresh inert barrier volume unexpectedly has a device",
        ));
    }
    backend.mode(&sentinel, &owner, "dev")?;
    let mut observed = false;
    for _ in 0..100 {
        if backend.minor(&sentinel)? {
            observed = true;
            break;
        }
        backend.pause();
    }
    if !observed {
        return Err(refuse(
            "inert-receive volume queue barrier did not become observable",
        ));
    }
    // Removal can still be deferred behind a queued task (OpenZFS 2.3 did),
    // so the barrier alone is not the absence proof; check every actual raw
    // minor after it has passed.
    for member in volumes {
        if backend.minor(&member.endpoint)? {
            return Err(refuse(format!(
                "volume {} still has a live device; receive remains stopped",
                member.endpoint.name
            )));
        }
    }
    backend.remove(&sentinel, true, &owner)?;
    backend.remove(&container, false, &owner)?;
    if backend.scope(endpoint)? != before {
        return Err(refuse(
            "inert receive scope changed while draining volume devices",
        ));
    }
    Ok(())
}

struct Native;

fn owns(
    endpoint: &Endpoint,
    volume: bool,
    owner: &Authority,
    marker: Option<&native::NativeProperty>,
) -> Result<bool, Error> {
    let Some(marker) = marker.filter(|p| p.source == "local") else {
        return Ok(false);
    };
    let Ok(proof) = serde_json::from_str::<Ownership>(&marker.value) else {
        return Ok(false);
    };
    if proof.authority != *owner {
        return Ok(false);
    }
    if proof != Ownership::new(endpoint, volume, owner) {
        return Err(refuse(
            "receive barrier marker belongs to another incarnation or type",
        ));
    }
    Ok(true)
}

fn raw_device(name: &str) -> bool {
    let Some(number) = name.strip_prefix("zd") else {
        return false;
    };
    let (disk, partition) = number
        .split_once('p')
        .map_or((number, None), |(d, p)| (d, Some(p)));
    !disk.is_empty()
        && disk.bytes().all(|b| b.is_ascii_digit())
        && partition.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn names_volume(raw: &str, volume: &str) -> bool {
    raw == volume
        || raw
            .strip_prefix(volume)
            .is_some_and(|tail| tail.starts_with('@'))
}

fn raw_name(file: &File) -> Result<String, Error> {
    let mut name = [0u8; NAME_BYTES];
    // SAFETY: BLKZNAME writes exactly MAXNAMELEN (256) bytes into the valid
    // writable array, using a live borrowed Linux block-device descriptor.
    #[allow(
        unsafe_code,
        reason = "Linux BLKZNAME ioctl on a ZFS volume descriptor"
    )]
    let status = unsafe { libc::ioctl(file.as_raw_fd(), BLKZNAME, name.as_mut_ptr()) };
    if status != 0 {
        return Err(refuse(format!(
            "cannot identify raw volume: {}",
            std::io::Error::last_os_error()
        )));
    }
    decode_raw_name(&name)
}

fn decode_raw_name(name: &[u8; NAME_BYTES]) -> Result<String, Error> {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| refuse("unterminated raw volume name"))?;
    let name = std::str::from_utf8(&name[..end]).map_err(|_| refuse("invalid raw volume name"))?;
    if name.contains('@') {
        crate::engine::validate_snapshot_name(name)?;
    } else {
        crate::engine::validate_dataset_name(name)?;
    }
    Ok(name.into())
}

/// `-u` suppresses filesystem mounting; OpenZFS rejects it for volumes.
/// The sentinel's already verified parent supplies volmode=none from the first
/// instant of creation, before the new volume's explicit inert properties and
/// identity-bound ownership marker are observed. No DEV request precedes both.
fn create_args(name: &str, volume: bool) -> Result<Vec<String>, Error> {
    crate::engine::validate_dataset_name(name)?;
    let mut args = vec!["create".into()];
    if volume {
        args.extend([
            "-V".into(),
            "16K".into(),
            "-b".into(),
            "8K".into(),
            "-o".into(),
            "refreservation=none".into(),
        ]);
    } else {
        args.push("-u".into());
        for property in ["mountpoint=none", "canmount=off", "encryption=off"] {
            args.extend(["-o".into(), property.into()]);
        }
    }
    for property in ["readonly=on", "volmode=none"] {
        args.extend(["-o".into(), property.into()]);
    }
    args.push(name.into());
    Ok(args)
}

impl Native {
    fn dataset(endpoint: &Endpoint) -> Result<crate::engine::Dataset, Error> {
        require_endpoint(endpoint)?;
        crate::engine::inspect(&InspectRequest::new(vec![endpoint.name.clone()], false)?)?
            .datasets
            .iter()
            .find(|dataset| dataset.name == endpoint.name)
            .cloned()
            .ok_or_else(|| refuse("inert barrier dataset disappeared"))
    }
    fn properties(
        endpoint: &Endpoint,
    ) -> Result<std::collections::BTreeMap<String, native::NativeProperty>, Error> {
        require_endpoint(endpoint)?;
        let mut properties =
            native::dataset_properties_with(std::slice::from_ref(&endpoint.name), native::run)?;
        require_endpoint(endpoint)?;
        properties
            .remove(&endpoint.name)
            .ok_or_else(|| refuse("inert barrier properties disappeared"))
    }
}

impl Backend for Native {
    fn probes(&mut self, endpoint: &Endpoint, owner: &str) -> Result<Vec<Probe>, Error> {
        require_endpoint(endpoint)?;
        let pool = endpoint.name.split('/').next().unwrap();
        let inspection = crate::engine::inspect(&InspectRequest::new(vec![pool.into()], true)?)?;
        let mut probes = Vec::new();
        for dataset in &inspection.datasets {
            let Some(tail) = dataset.name.strip_prefix(&format!("{pool}/{PROBE_PREFIX}")) else {
                continue;
            };
            if tail.len() != 32 || !tail.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let container = Endpoint {
                name: dataset.name.clone(),
                identity: dataset.identity.clone(),
            };
            let properties = Self::properties(&container)?;
            let Some(marker) = properties.get(OWNER).filter(|p| p.source == "local") else {
                continue;
            };
            let Ok(proof) = serde_json::from_str::<Ownership>(&marker.value) else {
                continue;
            };
            if proof.authority.operation_id != owner {
                continue;
            }
            let authority = proof.authority;
            if authority.scope.identity.pool_guid != endpoint.identity.pool_guid {
                return Err(refuse("receive barrier scope belongs to another pool"));
            }
            require_endpoint(&authority.scope)?;
            if !owns(&container, false, &authority, properties.get(OWNER))? {
                continue;
            }
            if inspection
                .snapshots
                .as_ref()
                .unwrap()
                .iter()
                .any(|snapshot| {
                    snapshot
                        .name
                        .strip_prefix(&container.name)
                        .is_some_and(|tail| tail.starts_with('@') || tail.starts_with('/'))
                })
            {
                return Err(refuse(
                    "owned receive barrier has snapshots; nothing removed",
                ));
            }
            let children: Vec<_> = inspection
                .datasets
                .iter()
                .filter(|child| {
                    child
                        .name
                        .strip_prefix(&container.name)
                        .is_some_and(|tail| tail.starts_with('/'))
                })
                .collect();
            let sentinel = match children.as_slice() {
                [] => None,
                [child]
                    if child.name == format!("{}/probe", container.name)
                        && child.kind == DatasetKind::Volume =>
                {
                    let sentinel = Endpoint {
                        name: child.name.clone(),
                        identity: child.identity.clone(),
                    };
                    let properties = Self::properties(&sentinel)?;
                    if !owns(&sentinel, true, &authority, properties.get(OWNER))? {
                        // Creation can be cut before binding. This expected,
                        // inert child has never been allowed a DEV request.
                        if properties
                            .get("readonly")
                            .is_none_or(|p| p.source != "local" || p.value != "on")
                            || properties
                                .get("volmode")
                                .is_none_or(|p| p.source != "local" || p.value != "none")
                        {
                            return Err(refuse("unbound receive barrier child is not inert"));
                        }
                        continue;
                    }
                    self.verify(&sentinel, true, &authority)?;
                    Some(sentinel)
                }
                _ => {
                    return Err(refuse(
                        "owned receive barrier has unknown children; nothing removed",
                    ));
                }
            };
            self.verify(&container, false, &authority)?;
            probes.push(Probe {
                authority,
                container,
                sentinel,
            });
        }
        require_endpoint(endpoint)?;
        Ok(probes)
    }
    fn scope(&mut self, endpoint: &Endpoint) -> Result<Vec<Member>, Error> {
        require_endpoint(endpoint)?;
        let inspection =
            crate::engine::inspect(&InspectRequest::new(vec![endpoint.name.clone()], false)?)?;
        let names: Vec<_> = inspection
            .datasets
            .iter()
            .map(|dataset| dataset.name.clone())
            .collect();
        let properties = native::dataset_properties_with(&names, native::run)?;
        let mut members = Vec::new();
        for dataset in &inspection.datasets {
            let props = properties
                .get(&dataset.name)
                .ok_or_else(|| refuse("inert scope properties missing"))?;
            let value = |key: &str| props.get(key).map(|property| property.value.as_str());
            let volume = dataset.kind == DatasetKind::Volume;
            if value("readonly") != Some("on")
                || value("volmode") != Some("none")
                || (!volume
                    && (value("mountpoint") != Some("none") || dataset.mounted != Some(false)))
            {
                return Err(refuse(format!(
                    "{} is not an inert receive scope",
                    dataset.name
                )));
            }
            members.push(Member {
                endpoint: Endpoint {
                    name: dataset.name.clone(),
                    identity: dataset.identity.clone(),
                },
                volume,
            });
        }
        require_endpoint(endpoint)?;
        members.sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
        Ok(members)
    }
    fn create(&mut self, name: &str, volume: bool, owner: &Authority) -> Result<Endpoint, Error> {
        native::run_mutating("zfs", &create_args(name, volume)?)?;
        let inspection = crate::engine::inspect(&InspectRequest::new(vec![name.into()], false)?)?;
        let dataset = inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == name)
            .ok_or_else(|| refuse("new empty barrier object was not observed"))?;
        let endpoint = Endpoint {
            name: name.into(),
            identity: dataset.identity.clone(),
        };
        // A cut before this binding leaves only inert empty preparation;
        // no DEV request is possible without verifying this exact marker.
        require_endpoint(&endpoint)?;
        native::run_mutating(
            "zfs",
            &[
                "set".into(),
                "-u".into(),
                format!(
                    "{OWNER}={}",
                    Ownership::new(&endpoint, volume, owner).encoded()?
                ),
                name.into(),
            ],
        )?;
        self.verify(&endpoint, volume, owner)?;
        if Self::properties(&endpoint)?
            .get("volmode")
            .is_none_or(|property| property.value != "none")
        {
            return Err(refuse(
                "new empty barrier object was not created with inert device policy",
            ));
        }
        Ok(endpoint)
    }
    fn verify(
        &mut self,
        endpoint: &Endpoint,
        volume: bool,
        owner: &Authority,
    ) -> Result<(), Error> {
        require_endpoint(&owner.scope)?;
        let dataset = Self::dataset(endpoint)?;
        let properties = Self::properties(endpoint)?;
        let marker = properties.get(OWNER);
        if (dataset.kind == DatasetKind::Volume) != volume
            || !owns(endpoint, volume, owner, marker)?
            || properties
                .get("readonly")
                .is_none_or(|property| property.source != "local" || property.value != "on")
            || (volume
                && properties
                    .get("volsize")
                    .is_none_or(|property| property.value != "16384"))
            || (volume
                && properties.get("volmode").is_none_or(|property| {
                    property.source != "local" || !matches!(property.value.as_str(), "none" | "dev")
                }))
            || (!volume
                && (properties
                    .get("mountpoint")
                    .is_none_or(|property| property.source != "local" || property.value != "none")
                    || properties.get("canmount").is_none_or(|property| {
                        property.source != "local" || property.value != "off"
                    })
                    || properties.get("volmode").is_none_or(|property| {
                        property.source != "local" || property.value != "none"
                    })))
        {
            return Err(refuse("empty receive barrier ownership or posture changed"));
        }
        let inspection =
            crate::engine::inspect(&InspectRequest::new(vec![endpoint.name.clone()], true)?)?;
        if !inspection.snapshots.as_ref().unwrap().is_empty() {
            return Err(refuse("owned receive barrier has snapshots"));
        }
        require_endpoint(endpoint)?;
        require_endpoint(&owner.scope)?;
        Ok(())
    }
    fn mode(&mut self, endpoint: &Endpoint, owner: &Authority, mode: &str) -> Result<(), Error> {
        self.verify(endpoint, true, owner)?;
        native::run_mutating(
            "zfs",
            &[
                "set".into(),
                "-u".into(),
                format!("volmode={mode}"),
                endpoint.name.clone(),
            ],
        )?;
        self.verify(endpoint, true, owner)
    }
    fn minor(&mut self, endpoint: &Endpoint) -> Result<bool, Error> {
        require_endpoint(endpoint)?;
        let mut found = false;
        for entry in
            std::fs::read_dir("/sys/class/block").map_err(|error| refuse(error.to_string()))?
        {
            let entry = entry.map_err(|error| refuse(error.to_string()))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !raw_device(name) {
                continue;
            }
            let device = Path::new("/dev").join(name);
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&device)
                .map_err(|error| {
                    refuse(format!(
                        "cannot open raw volume {}: {error}",
                        device.display()
                    ))
                })?;
            let metadata = file.metadata().map_err(|error| refuse(error.to_string()))?;
            let expected = std::fs::read_to_string(entry.path().join("dev"))
                .map_err(|error| refuse(error.to_string()))?;
            let actual = format!(
                "{}:{}",
                libc::major(metadata.rdev()),
                libc::minor(metadata.rdev())
            );
            if !metadata.file_type().is_block_device() || expected.trim() != actual {
                return Err(refuse("raw volume device does not match sysfs inventory"));
            }
            // BLKZNAME preserves spaces and punctuation. It returns the head
            // or snapshot name unchanged even for a partition descriptor.
            found |= names_volume(&raw_name(&file)?, &endpoint.name);
        }
        require_endpoint(endpoint)?;
        Ok(found)
    }
    fn remove(
        &mut self,
        endpoint: &Endpoint,
        volume: bool,
        owner: &Authority,
    ) -> Result<(), Error> {
        self.verify(endpoint, volume, owner)?;
        // No -r/-f: foreign children, snapshots and users prevent deletion.
        native::run_mutating("zfs", &["destroy".into(), endpoint.name.clone()])?;
        Ok(())
    }
    fn pause(&mut self) {
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DatasetIdentity, Guid, ObjsetId, Txg};
    use std::collections::BTreeMap;

    const OP: &str = "0123456789abcdef";
    const NONCE: &str = "0123456789abcdef0123456789abcdef";
    const NEXT: &str = "1123456789abcdef0123456789abcdef";

    #[derive(Clone)]
    struct Object {
        endpoint: Endpoint,
        volume: bool,
        marker: Option<native::NativeProperty>,
        mode: String,
        snapshot: bool,
    }
    #[derive(Clone, Copy, Debug)]
    enum Cut {
        Before,
        After,
        Lost,
    }
    #[derive(Clone)]
    struct Fake {
        root: Endpoint,
        target: Endpoint,
        objects: BTreeMap<String, Object>,
        effects: Vec<String>,
        fail: Option<(usize, Cut)>,
        tick: usize,
        barrier: bool,
        live_target: bool,
        next: u64,
        removed: Vec<String>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                root: endpoint("tank", 1),
                target: endpoint("tank/data/vol", 2),
                objects: BTreeMap::new(),
                effects: vec![],
                fail: None,
                tick: 0,
                barrier: false,
                live_target: false,
                next: 10,
                removed: vec![],
            }
        }
        fn effect<T>(
            &mut self,
            label: String,
            change: impl FnOnce(&mut Self) -> Result<T, Error>,
        ) -> Result<T, Error> {
            let index = self.effects.len();
            self.effects.push(label);
            let cut = self.fail.filter(|(at, _)| *at == index).map(|(_, cut)| cut);
            if matches!(cut, Some(Cut::Before)) {
                return Err(refuse("cut before"));
            }
            let result = change(self)?;
            if matches!(cut, Some(Cut::After | Cut::Lost)) {
                return Err(refuse("cut after or lost reply"));
            }
            Ok(result)
        }
        fn run(&mut self, nonce: &str) -> Result<(), Error> {
            let root = self.root.clone();
            quiesce_with(&root, OP, nonce, self)
        }
        fn owned(&self, ep: &Endpoint, volume: bool, owner: &Authority) -> Result<(), Error> {
            let object = self
                .objects
                .get(&ep.name)
                .ok_or_else(|| refuse("absent probe"))?;
            if object.endpoint != *ep
                || object.volume != volume
                || object.snapshot
                || !owns(ep, volume, owner, object.marker.as_ref())?
            {
                return Err(refuse("probe authority changed"));
            }
            Ok(())
        }
    }
    fn endpoint(name: &str, guid: u64) -> Endpoint {
        Endpoint {
            name: name.into(),
            identity: DatasetIdentity {
                pool_guid: Guid::new(10),
                guid: Guid::new(guid),
                createtxg: Txg::new(guid),
                objsetid: ObjsetId::new(guid),
            },
        }
    }
    impl Backend for Fake {
        fn probes(&mut self, ep: &Endpoint, operation: &str) -> Result<Vec<Probe>, Error> {
            assert_eq!(ep, &self.root);
            self.effect("recover inventory".into(), |f| {
                let mut probes = vec![];
                for object in f.objects.values().filter(|o| !o.volume) {
                    let Some(marker) = object.marker.as_ref().filter(|p| p.source == "local")
                    else {
                        continue;
                    };
                    let proof: Ownership =
                        serde_json::from_str(&marker.value).map_err(|e| refuse(e.to_string()))?;
                    if proof.authority.operation_id != operation {
                        continue;
                    }
                    f.owned(&object.endpoint, false, &proof.authority)?;
                    let children: Vec<_> = f
                        .objects
                        .values()
                        .filter(|child| {
                            child
                                .endpoint
                                .name
                                .starts_with(&format!("{}/", object.endpoint.name))
                        })
                        .collect();
                    let sentinel = match children.as_slice() {
                        [] => None,
                        [child]
                            if child.volume
                                && child.endpoint.name
                                    == format!("{}/probe", object.endpoint.name) =>
                        {
                            if child.marker.is_none() && child.mode == "none" {
                                continue;
                            }
                            f.owned(&child.endpoint, true, &proof.authority)?;
                            Some(child.endpoint.clone())
                        }
                        _ => return Err(refuse("unknown children")),
                    };
                    probes.push(Probe {
                        authority: proof.authority,
                        container: object.endpoint.clone(),
                        sentinel,
                    });
                }
                Ok(probes)
            })
        }
        fn scope(&mut self, ep: &Endpoint) -> Result<Vec<Member>, Error> {
            assert_eq!(ep, &self.root);
            self.effect("scope".into(), |f| {
                if f.objects.values().any(|o| o.mode != "none") {
                    return Err(refuse("DEV probe poisons scope"));
                }
                let mut scope = vec![
                    Member {
                        endpoint: f.root.clone(),
                        volume: false,
                    },
                    Member {
                        endpoint: f.target.clone(),
                        volume: true,
                    },
                ];
                scope.extend(f.objects.values().map(|o| Member {
                    endpoint: o.endpoint.clone(),
                    volume: o.volume,
                }));
                scope.sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
                Ok(scope)
            })
        }
        fn create(
            &mut self,
            name: &str,
            volume: bool,
            owner: &Authority,
        ) -> Result<Endpoint, Error> {
            let name = name.to_owned();
            let ep = self.effect(format!("create {name}"), |f| {
                f.next += 1;
                let ep = endpoint(&name, f.next);
                if f.objects.contains_key(&name) {
                    return Err(refuse("already exists"));
                }
                f.objects.insert(
                    name.clone(),
                    Object {
                        endpoint: ep.clone(),
                        volume,
                        marker: None,
                        mode: "none".into(),
                        snapshot: false,
                    },
                );
                Ok(ep)
            })?;
            self.effect(format!("bind {name}"), |f| {
                f.objects.get_mut(&name).unwrap().marker = Some(native::NativeProperty {
                    value: Ownership::new(&ep, volume, owner).encoded()?,
                    source: "local".into(),
                });
                Ok(())
            })?;
            Ok(ep)
        }
        fn verify(&mut self, ep: &Endpoint, volume: bool, owner: &Authority) -> Result<(), Error> {
            self.effect(format!("verify {}", ep.name), |f| {
                f.owned(ep, volume, owner)
            })
        }
        fn mode(&mut self, ep: &Endpoint, owner: &Authority, mode: &str) -> Result<(), Error> {
            self.effect(format!("mode {mode} {}", ep.name), |f| {
                f.owned(ep, true, owner)?;
                assert_eq!(mode, "dev");
                f.objects.get_mut(&ep.name).unwrap().mode = mode.into();
                f.barrier = true;
                f.tick = 0;
                Ok(())
            })
        }
        fn minor(&mut self, ep: &Endpoint) -> Result<bool, Error> {
            self.effect(format!("minor {}", ep.name), |f| {
                if let Some(object) = f.objects.get(&ep.name) {
                    if object.mode == "dev" {
                        f.tick += 1;
                        return Ok(f.tick >= 2);
                    }
                    return Ok(false);
                }
                assert!(
                    f.barrier && f.tick >= 2,
                    "absence cannot precede queue barrier"
                );
                Ok(ep == &f.target && f.live_target)
            })
        }
        fn remove(&mut self, ep: &Endpoint, volume: bool, owner: &Authority) -> Result<(), Error> {
            self.effect(format!("remove {}", ep.name), |f| {
                f.owned(ep, volume, owner)?;
                if f.objects
                    .keys()
                    .any(|name| name.starts_with(&format!("{}/", ep.name)))
                {
                    return Err(refuse("has children"));
                }
                f.objects.remove(&ep.name);
                f.removed.push(ep.name.clone());
                Ok(())
            })
        }
        fn pause(&mut self) {}
    }

    #[test]
    fn native_probe_creation_uses_filesystem_only_u_and_inert_volume_policy() {
        let container = "tank/zboot-receive-probe-0123456789abcdef0123456789abcdef";
        assert_eq!(
            create_args(container, false).unwrap(),
            [
                "create",
                "-u",
                "-o",
                "mountpoint=none",
                "-o",
                "canmount=off",
                "-o",
                "encryption=off",
                "-o",
                "readonly=on",
                "-o",
                "volmode=none",
                container,
            ],
        );
        let sentinel = format!("{container}/probe");
        assert_eq!(
            create_args(&sentinel, true).unwrap(),
            [
                "create",
                "-V",
                "16K",
                "-b",
                "8K",
                "-o",
                "refreservation=none",
                "-o",
                "readonly=on",
                "-o",
                "volmode=none",
                &sentinel,
            ],
            "volumes require -V without filesystem-only -u; their device policy remains none",
        );
        for volume in [false, true] {
            assert!(create_args("tank/probe@snapshot", volume).is_err());
        }
    }

    #[test]
    fn raw_head_snapshot_and_partition_names_keep_spaces_and_plus_distinct() {
        for name in [
            "tank/my volume",
            "tank/my+volume",
            "tank/my volume@daily copy",
        ] {
            let mut bytes = [0; NAME_BYTES];
            bytes[..name.len()].copy_from_slice(name.as_bytes());
            assert_eq!(decode_raw_name(&bytes).unwrap(), name);
        }
        assert!(names_volume("tank/my volume@daily copy", "tank/my volume"));
        assert!(!names_volume("tank/my+volume", "tank/my volume"));
        assert!(!names_volume("tank/volume-extra@s", "tank/volume"));
        for name in ["zd0", "zd16p1", "zd999p123"] {
            assert!(raw_device(name));
        }
        for name in ["zd", "zdp1", "zd1p", "zd1p2p3", "sda1"] {
            assert!(!raw_device(name));
        }
    }

    #[test]
    fn ownership_is_local_and_bound_to_operation_scope_and_temp_incarnation() {
        let scope = endpoint("tank", 1);
        let ep = endpoint("tank/zboot-receive-probe-a/probe", 20);
        let owner = Authority {
            operation_id: OP.into(),
            scope,
        };
        let marker = native::NativeProperty {
            value: Ownership::new(&ep, true, &owner).encoded().unwrap(),
            source: "local".into(),
        };
        assert!(owns(&ep, true, &owner, Some(&marker)).unwrap());
        let mut replaced = ep.clone();
        replaced.identity.guid = Guid::new(21);
        assert!(owns(&replaced, true, &owner, Some(&marker)).is_err());
        let mut other_scope = owner.clone();
        other_scope.scope.identity.guid = Guid::new(99);
        assert!(!owns(&ep, true, &other_scope, Some(&marker)).unwrap());
        for source in ["received", "inherited from tank"] {
            let mut marker = marker.clone();
            marker.source = source.into();
            assert!(!owns(&ep, true, &owner, Some(&marker)).unwrap());
        }
    }

    #[test]
    fn target_absence_follows_barrier_and_live_devices_stop_the_call() {
        let mut fake = Fake::new();
        fake.run(NONCE).unwrap();
        assert!(fake.objects.is_empty());
        fake.live_target = true;
        assert!(
            fake.run(NEXT)
                .unwrap_err()
                .to_string()
                .contains("live device")
        );
    }

    #[test]
    fn every_preparation_cut_or_lost_reply_recovers_before_pool_root_admission() {
        let mut reference = Fake::new();
        reference.run(NONCE).unwrap();
        for at in 0..reference.effects.len() {
            for cut in [Cut::Before, Cut::After, Cut::Lost] {
                let mut fake = Fake::new();
                fake.fail = Some((at, cut));
                assert!(fake.run(NONCE).is_err(), "{at} {cut:?}");
                fake.fail = None;
                fake.run(NEXT)
                    .unwrap_or_else(|e| panic!("{at} {cut:?}: {e}"));
                assert!(
                    fake.objects.values().all(|o| o.mode == "none"),
                    "{at} {cut:?}"
                );
                assert!(
                    fake.removed
                        .iter()
                        .all(|name| name.starts_with("tank/zboot-receive-probe-"))
                );
                assert_eq!(fake.target, endpoint("tank/data/vol", 2));
            }
        }
    }

    #[test]
    fn cuts_during_recovery_retry_without_deleting_unknown_children_or_snapshots() {
        let mut done = Fake::new();
        done.run(NONCE).unwrap();
        let dev = done
            .effects
            .iter()
            .position(|e| e.starts_with("mode dev"))
            .unwrap();
        let mut stopped = Fake::new();
        stopped.fail = Some((dev, Cut::After));
        assert!(stopped.run(NONCE).is_err());
        stopped.fail = None;
        assert!(stopped.objects.values().any(|o| o.mode == "dev"));
        let mut recovered = stopped.clone();
        let start = recovered.effects.len();
        recovered.run(NEXT).unwrap();
        let end = recovered
            .effects
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, e)| e.as_str() == "scope")
            .unwrap()
            .0;
        for at in start..=end {
            for cut in [Cut::Before, Cut::After, Cut::Lost] {
                let mut fake = stopped.clone();
                fake.fail = Some((at, cut));
                assert!(fake.run(NEXT).is_err());
                fake.fail = None;
                fake.run("2123456789abcdef0123456789abcdef").unwrap();
                assert!(fake.objects.is_empty());
            }
        }
        for attack in 0..3 {
            let mut fake = stopped.clone();
            let container = fake
                .objects
                .values()
                .find(|o| !o.volume)
                .unwrap()
                .endpoint
                .name
                .clone();
            let sentinel = format!("{container}/probe");
            match attack {
                0 => {
                    let ep = endpoint(&format!("{container}/foreign"), 99);
                    fake.objects.insert(
                        ep.name.clone(),
                        Object {
                            endpoint: ep,
                            volume: false,
                            marker: None,
                            mode: "none".into(),
                            snapshot: false,
                        },
                    );
                }
                1 => fake.objects.get_mut(&sentinel).unwrap().snapshot = true,
                2 => {
                    fake.objects
                        .get_mut(&sentinel)
                        .unwrap()
                        .endpoint
                        .identity
                        .guid = Guid::new(999)
                }
                _ => unreachable!(),
            }
            let before = fake.objects.len();
            assert!(fake.run(NEXT).is_err());
            assert_eq!(fake.objects.len(), before);
            assert!(fake.removed.is_empty());
        }
    }
}
