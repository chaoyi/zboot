//! `zboot deploy into POOL`: add one fenced boot environment to an imported pool.
//! It has no restart journal. A surviving pending dataset is removed through
//! an explicit Drop.
use super::{identity, overlay, refuse};
use crate::factory::{self, ImageFile, root_tar::RootTar};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};
use zfs_tools::engine::{
    CanMount, DatasetKind,
    management::{self, Endpoint, Ownership},
    native,
    state::{self, NativeState},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Request {
    pub pool: String,
    pub be: String,
    pub tar: PathBuf,
    pub overlays: Vec<PathBuf>,
    pub hostname: Option<String>,
}
impl Request {
    pub fn dataset(&self) -> String {
        format!("{}/ROOT/{}", self.pool, self.be)
    }
    fn validate(&self) -> io::Result<()> {
        super::validate_names(&self.pool, &self.dataset(), true)?;
        if self
            .hostname
            .as_deref()
            .is_some_and(|value| !super::request::valid_hostname(value))
        {
            return Err(refuse(
                "deploy hostname must be dot-separated letters, digits and inner hyphens",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub request: Request,
    pub pool: Endpoint,
    pub container: Option<Endpoint>,
    pub hostid: u32,
    pub factory: RootTar,
    pub overlays: Vec<overlay::Overlay>,
    pub defaults: BTreeMap<String, Option<String>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub operation_id: String,
    pub pool: Endpoint,
    pub dataset: Endpoint,
    pub complete: bool,
    pub boot_files: BTreeMap<String, ImageFile>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Container,
    Create,
    Extract,
    FactorySnapshot,
    Overlay(usize),
    Identity,
    DeployedSnapshot,
    Publish,
    ClearPending,
}
/// The real backend and cut-injectable unit model share the same protocol.
pub trait Backend {
    fn observe(&mut self) -> io::Result<NativeState>;
    fn hostid(&mut self, pool: &Endpoint) -> io::Result<u32>;
    fn tar(&mut self, path: &Path) -> io::Result<RootTar>;
    fn overlay(&mut self, path: &Path) -> io::Result<overlay::Overlay>;
    fn action(
        &mut self,
        plan: &Plan,
        dataset: Option<&Endpoint>,
        id: &str,
        action: Action,
    ) -> io::Result<()>;
    fn boot_files(
        &mut self,
        plan: &Plan,
        dataset: &Endpoint,
        id: &str,
    ) -> io::Result<BTreeMap<String, ImageFile>>;
}
fn endpoint(state: &NativeState, name: &str) -> io::Result<Endpoint> {
    let dataset = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| refuse(format!("deploy into dataset is missing: {name}")))?;
    Ok(Endpoint {
        name: name.into(),
        identity: dataset.identity.clone(),
    })
}
fn defaults(state: &NativeState) -> BTreeMap<String, Option<String>> {
    state
        .inspection
        .pools
        .iter()
        .map(|p| (p.name.clone(), p.bootfs.clone()))
        .collect()
}
fn container(state: &NativeState, name: &str) -> io::Result<Endpoint> {
    let point = endpoint(state, name)?;
    let d = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == name)
        .unwrap();
    if d.kind != DatasetKind::Filesystem
        || d.mounted != Some(false)
        || d.canmount != Some(CanMount::Off)
        || d.mountpoint.as_deref() != Some("none")
        || !matches!(
            management::ownership(state, name).map_err(refuse)?,
            Ownership::Unpaired
        )
    {
        return Err(refuse(format!(
            "deploy into needs an unmounted plain container: {name}"
        )));
    }
    Ok(point)
}
fn forbidden_child_property(key: &str) -> bool {
    management::managed_key(key) && key != management::PENDING_PROPERTY
}
fn admit_inherited_properties(state: &NativeState, parent: &str) -> io::Result<()> {
    let properties = state.dataset_properties.get(parent).ok_or_else(|| {
        refuse(format!(
            "deploy into parent properties are missing: {parent}"
        ))
    })?;
    if let Some(key) = properties.keys().find(|key| forbidden_child_property(key)) {
        return Err(refuse(format!(
            "deploy into target would inherit unsupported property {key} from {parent}"
        )));
    }
    Ok(())
}
fn admission(request: &Request, state: &NativeState) -> io::Result<(Endpoint, Option<Endpoint>)> {
    request.validate()?;
    let pool = state
        .inspection
        .pools
        .iter()
        .find(|p| p.name == request.pool)
        .ok_or_else(|| refuse("the pool is not imported"))?;
    let point = endpoint(state, &request.pool)?;
    if point.identity.pool_guid != pool.guid {
        return Err(refuse("pool root identity changed"));
    }
    if !matches!(
        management::ownership(state, &request.pool).map_err(refuse)?,
        Ownership::Unpaired
    ) {
        return Err(refuse("deploy into requires a plain pool root"));
    }
    crate::mounting::require_outside_boot_environment(state, &request.dataset()).map_err(refuse)?;
    if state
        .inspection
        .datasets
        .iter()
        .any(|d| d.name == request.dataset())
    {
        return Err(refuse(format!(
            "{} already exists. Drop an interrupted pending deployment explicitly before retrying",
            request.dataset()
        )));
    }
    let name = format!("{}/ROOT", request.pool);
    let root = if state.inspection.datasets.iter().any(|d| d.name == name) {
        Some(container(state, &name)?)
    } else {
        None
    };
    admit_inherited_properties(state, if root.is_some() { &name } else { &request.pool })?;
    Ok((point, root))
}
pub fn plan_with(request: &Request, backend: &mut impl Backend) -> io::Result<Plan> {
    let state = backend.observe()?;
    let (pool, container) = admission(request, &state)?;
    let hostid = backend.hostid(&pool)?;
    crate::hostid::parse(&crate::hostid::format(hostid))?;
    let factory = backend.tar(&request.tar)?;
    let overlays = request
        .overlays
        .iter()
        .map(|path| backend.overlay(path))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Plan {
        schema_version: 1,
        request: request.clone(),
        pool,
        container,
        hostid,
        factory,
        overlays,
        defaults: defaults(&state),
    })
}
pub fn describe(plan: &Plan) -> String {
    let mut text = format!(
        "Deploy into imported pool\n  BE: {}\n  Hostid: {}\n  Root: {} {}\n  Boot defaults remain unchanged\n",
        zfs_tools::engine::escape_display(&plan.request.dataset()),
        crate::hostid::format(plan.hostid),
        zfs_tools::engine::escape_display(&plan.factory.path.display().to_string()),
        plan.factory.sha256
    );
    for item in &plan.overlays {
        text.push_str(&format!(
            "  Overlay: {} {}\n",
            zfs_tools::engine::escape_display(&item.source.display().to_string()),
            item.sha256
        ));
    }
    text
}
fn bound(
    plan: &Plan,
    state: &NativeState,
    expected: Option<&Endpoint>,
    id: &str,
    published: bool,
) -> io::Result<Option<Endpoint>> {
    if endpoint(state, &plan.pool.name)? != plan.pool || defaults(state) != plan.defaults {
        return Err(refuse(
            "deploy into pool identity or a boot default changed",
        ));
    }
    let root = format!("{}/ROOT", plan.pool.name);
    if let Some(point) = &plan.container {
        if container(state, &root)? != *point {
            return Err(refuse("deploy into ROOT container changed"));
        }
    } else {
        container(state, &root)?;
    }
    admit_inherited_properties(state, &root)?;
    let name = plan.request.dataset();
    if expected.is_none() && !state.inspection.datasets.iter().any(|d| d.name == name) {
        return Ok(None);
    }
    let point = endpoint(state, &name)?;
    if expected.is_some_and(|wanted| wanted != &point) {
        return Err(refuse("deploy into BE incarnation changed"));
    }
    if state
        .inspection
        .datasets
        .iter()
        .any(|d| d.name != name && crate::history::contains_dataset(&name, &d.name))
    {
        return Err(refuse("deploy into BE acquired unexpected descendants"));
    }
    let d = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == name)
        .unwrap();
    let properties = state
        .dataset_properties
        .get(&name)
        .ok_or_else(|| refuse("deploy into properties are missing"))?;
    if d.kind != DatasetKind::Filesystem
        || d.mounted != Some(false)
        || d.readonly
        || d.origin.is_some()
        || d.canmount
            != Some(if published {
                CanMount::NoAuto
            } else {
                CanMount::Off
            })
        || d.mountpoint.as_deref() != Some(if published { "/" } else { "none" })
        || properties
            .get(management::PENDING_PROPERTY)
            .is_none_or(|p| p.value != id || p.source != "local")
        || [
            ("mountpoint", if published { "/" } else { "none" }),
            ("canmount", if published { "noauto" } else { "off" }),
            ("readonly", "off"),
        ]
        .iter()
        .any(|(key, value)| {
            properties
                .get(*key)
                .is_none_or(|p| p.value != *value || p.source != "local")
        })
        || properties.keys().any(|key| forbidden_child_property(key))
    {
        return Err(refuse("deploy into lost its exact pending role"));
    }
    Ok(Some(point))
}
fn has_snapshot(state: &NativeState, dataset: &Endpoint, name: &str) -> bool {
    state.inspection.snapshots.iter().flatten().any(|s| {
        s.name == format!("{}@{name}", dataset.name)
            && s.point().dataset_guid == dataset.identity.guid
    })
}
pub fn apply_with(plan: &Plan, backend: &mut impl Backend) -> io::Result<Outcome> {
    if plan_with(&plan.request, backend)? != *plan {
        return Err(refuse("deploy into plan changed before application"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let result = (|| {
        let mut runtime = plan.clone();
        if runtime.container.is_none() {
            backend.action(plan, None, &id, Action::Container)?;
            runtime.container = Some(container(
                &backend.observe()?,
                &format!("{}/ROOT", plan.pool.name),
            )?);
        }
        let plan = &runtime;
        bound(plan, &backend.observe()?, None, &id, false)?;
        backend.action(plan, None, &id, Action::Create)?;
        let be = bound(plan, &backend.observe()?, None, &id, false)?
            .ok_or_else(|| refuse("new pending BE is absent"))?;
        for action in [Action::Extract, Action::FactorySnapshot] {
            bound(plan, &backend.observe()?, Some(&be), &id, false)?;
            backend.action(plan, Some(&be), &id, action)?;
        }
        if !has_snapshot(&backend.observe()?, &be, "factory") {
            return Err(refuse("deploy into lacks its @factory boundary"));
        }
        for index in 0..plan.overlays.len() {
            bound(plan, &backend.observe()?, Some(&be), &id, false)?;
            backend.action(plan, Some(&be), &id, Action::Overlay(index))?;
        }
        bound(plan, &backend.observe()?, Some(&be), &id, false)?;
        backend.action(plan, Some(&be), &id, Action::Identity)?;
        bound(plan, &backend.observe()?, Some(&be), &id, false)?;
        let boot_files = backend.boot_files(plan, &be, &id)?;
        bound(plan, &backend.observe()?, Some(&be), &id, false)?;
        backend.action(plan, Some(&be), &id, Action::DeployedSnapshot)?;
        if !has_snapshot(&backend.observe()?, &be, "deployed") {
            return Err(refuse("deploy into lacks its @deployed boundary"));
        }
        bound(plan, &backend.observe()?, Some(&be), &id, false)?;
        backend.action(plan, Some(&be), &id, Action::Publish)?;
        bound(plan, &backend.observe()?, Some(&be), &id, true)?;
        if backend.boot_files(plan, &be, &id)? != boot_files {
            return Err(refuse("deployed boot files changed before publication"));
        }
        let clear = backend.action(plan, Some(&be), &id, Action::ClearPending);
        let state = backend.observe()?;
        let properties = state
            .dataset_properties
            .get(&be.name)
            .ok_or_else(|| refuse("deploy into BE disappeared during publication"))?;
        if properties.contains_key(management::PENDING_PROPERTY) {
            clear?;
            return Err(refuse("deploy into pending marker did not clear"));
        }
        if endpoint(&state, &be.name)? != be || defaults(&state) != plan.defaults {
            return Err(refuse("deploy into final identity or defaults changed"));
        }
        if backend.hostid(&plan.pool)? != plan.hostid {
            return Err(refuse("deploy into final host identity changed"));
        }
        crate::boot_environment::admit(&state, &be.name).map_err(refuse)?;
        Ok(Outcome {
            operation_id: id.clone(),
            pool: plan.pool.clone(),
            dataset: be,
            complete: true,
            boot_files,
        })
    })();
    result.map_err(|error: io::Error| refuse(format!("{error}. Inspect {}. To reuse an existing name, explicitly drop it before retrying an interrupted deploy", plan.request.dataset())))
}

pub struct Native;
impl Backend for Native {
    fn observe(&mut self) -> io::Result<NativeState> {
        state::observe().map_err(refuse)
    }
    fn hostid(&mut self, pool: &Endpoint) -> io::Result<u32> {
        let effective = crate::hostid::effective()?;
        let recorded = crate::hostid::recorded(&pool.name, pool.identity.pool_guid)?;
        crate::hostid::require_one_host((&pool.name, recorded), ("running host", effective))?;
        if crate::handoff::prove_ram().is_ok() {
            crate::handoff::deployment_hostid(pool.identity.pool_guid).map_err(refuse)
        } else {
            Ok(effective)
        }
    }
    fn tar(&mut self, path: &Path) -> io::Result<RootTar> {
        factory::root_tar::inspect(path)
    }
    fn overlay(&mut self, path: &Path) -> io::Result<overlay::Overlay> {
        overlay::review(path)
    }
    fn action(
        &mut self,
        plan: &Plan,
        dataset: Option<&Endpoint>,
        id: &str,
        action: Action,
    ) -> io::Result<()> {
        let name = plan.request.dataset();
        let run = |program, values: Vec<String>| {
            let current = state::observe().map_err(refuse)?;
            if crate::hostid::effective()? != plan.hostid {
                return Err(refuse("deploy into host identity changed"));
            }
            if action == Action::Container {
                let (pool, existing) = admission(&plan.request, &current)?;
                if pool != plan.pool || existing.is_some() || defaults(&current) != plan.defaults {
                    return Err(refuse("deploy into ROOT creation binding changed"));
                }
            } else {
                let observed = bound(plan, &current, dataset, id, action == Action::ClearPending)?;
                if action == Action::Create && observed.is_some() {
                    return Err(refuse("deploy into name became occupied"));
                }
            }
            native::run_mutating(program, &values)
                .map(|_| ())
                .map_err(refuse)
        };
        let args = |v: &[&str]| v.iter().map(|v| (*v).to_owned()).collect();
        match action {
            Action::Container => run(
                "zfs",
                args(&[
                    "create",
                    "-u",
                    "-o",
                    "mountpoint=none",
                    "-o",
                    "canmount=off",
                    "-o",
                    "readonly=on",
                    &format!("{}/ROOT", plan.pool.name),
                ]),
            ),
            Action::Create => run(
                "zfs",
                args(&[
                    "create",
                    "-u",
                    "-o",
                    "mountpoint=none",
                    "-o",
                    "canmount=off",
                    "-o",
                    "readonly=off",
                    "-o",
                    "volmode=none",
                    "-o",
                    "acltype=posixacl",
                    "-o",
                    "xattr=sa",
                    "-o",
                    &format!("zboot:pending={id}"),
                    &name,
                ]),
            ),
            Action::FactorySnapshot | Action::DeployedSnapshot => {
                run("zpool", args(&["sync", &plan.pool.name]))?;
                run(
                    "zfs",
                    args(&[
                        "snapshot",
                        &format!(
                            "{name}@{}",
                            if action == Action::FactorySnapshot {
                                "factory"
                            } else {
                                "deployed"
                            }
                        ),
                    ]),
                )
            }
            Action::Publish => {
                run("zfs", args(&["inherit", "volmode", &name]))?;
                run(
                    "zfs",
                    args(&["set", "canmount=noauto", "mountpoint=/", &name]),
                )
            }
            Action::ClearPending => {
                run("zpool", args(&["sync", &plan.pool.name]))?;
                run("zfs", args(&["inherit", "zboot:pending", &name]))
            }
            Action::Extract | Action::Overlay(_) | Action::Identity => {
                let point = dataset.ok_or_else(|| refuse("deploy into has no bound BE"))?;
                private_root(point, true, |root| match action {
                    Action::Extract => factory::root_tar::extract(&plan.factory, root),
                    Action::Overlay(index) => {
                        let item = &plan.overlays[index];
                        if overlay::again(item)? != *item {
                            return Err(refuse("deploy into overlay changed"));
                        }
                        overlay::apply(root, item)?;
                        if item.post_install.is_some() {
                            overlay::post_install(
                                root,
                                item,
                                &[
                                    ("ZBOOT_HOSTID", crate::hostid::format(plan.hostid)),
                                    ("ZBOOT_POOL", plan.pool.name.clone()),
                                    ("ZBOOT_BE", name.clone()),
                                ],
                                &Path::new("/run").join(format!(
                                    "zboot-deploy-into-{id}-post-install-{index}.log"
                                )),
                            )?;
                        }
                        Ok(())
                    }
                    Action::Identity => {
                        identity::enforce(root, plan.hostid, plan.request.hostname.as_deref())
                    }
                    _ => unreachable!(),
                })
            }
        }
    }
    fn boot_files(
        &mut self,
        plan: &Plan,
        dataset: &Endpoint,
        _: &str,
    ) -> io::Result<BTreeMap<String, ImageFile>> {
        private_root(dataset, false, |root| {
            verify_boot_files(&plan.factory, root)
        })
    }
}
/// Repeat ordinary root-tar admission against the actual resulting file tree.
/// Internal module symlinks resolve inside the held root, including merged /usr.
fn verify_boot_files(factory: &RootTar, root: &Path) -> io::Result<BTreeMap<String, ImageFile>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use std::os::fd::AsRawFd;
    let directory = fs::File::open(root)?;
    if !directory.metadata()?.is_dir() {
        return Err(refuse("deployed root is not a directory"));
    }
    let boot = fs::File::from(crate::openat2_scoped(
        &directory,
        "boot",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    // The held directory supplies the root member of this filesystem-derived
    // index. Keep the shared tar validator's required-root admission intact.
    let mut names = BTreeMap::from([(String::new(), tar::EntryType::Directory)]);
    for entry in fs::read_dir(format!("/proc/self/fd/{}", boot.as_raw_fd()))? {
        let entry = entry?;
        let file = entry.file_name();
        let Some(name) = file.to_str() else {
            return Err(refuse("deployed boot filename is not UTF-8"));
        };
        if !name.starts_with("vmlinuz-") && !name.starts_with("initrd.img-") {
            continue;
        }
        let kind = if entry.file_type()?.is_file() {
            tar::EntryType::Regular
        } else {
            tar::EntryType::Symlink
        };
        names.insert(format!("boot/{name}"), kind);
        if let Some(release) = name.strip_prefix("vmlinuz-") {
            if !factory::atom(release) {
                return Err(refuse("deployed kernel release is invalid"));
            }
            if has_zfs_module(&directory, release)? {
                names.insert(
                    format!("lib/modules/{release}/zfs.ko"),
                    tar::EntryType::Regular,
                );
            }
        }
        if names.len() > 2_000_000 {
            return Err(refuse("deployed boot inventory exceeds root-tar bound"));
        }
    }
    let mut reviewed = factory.clone();
    reviewed.kernels = factory::root_tar::boot_checks(&names)?;
    factory::root_tar::boot_files(&reviewed, root)
}
fn has_zfs_module(root: &fs::File, release: &str) -> io::Result<bool> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use std::{
        collections::BTreeSet,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };
    let mut pending = vec![
        format!("lib/modules/{release}"),
        format!("usr/lib/modules/{release}"),
    ];
    let mut visited = BTreeSet::new();
    let mut count = 0;
    while let Some(relative) = pending.pop() {
        let opened = crate::openat2_scoped(
            root,
            relative.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        );
        let directory = match opened {
            Ok(fd) => fs::File::from(fd),
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        let metadata = directory.metadata()?;
        if !visited.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            let entry = entry?;
            count += 1;
            if count > 2_000_000 {
                return Err(refuse("deployed module inventory exceeds root-tar bound"));
            }
            let file = entry.file_name();
            let Some(name) = file.to_str() else {
                return Err(refuse("deployed module filename is not UTF-8"));
            };
            let path = format!("{relative}/{name}");
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else if name
                .split_once('.')
                .is_some_and(|(stem, extension)| stem == "zfs" && extension.starts_with("ko"))
            {
                let file = fs::File::from(crate::openat2_scoped(
                    root,
                    path.as_str(),
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
                )?);
                if file.metadata()?.is_file() {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn private_root<T: Send>(
    dataset: &Endpoint,
    writable: bool,
    work: impl FnOnce(&Path) -> io::Result<T> + Send,
) -> io::Result<T> {
    use nix::mount::{MsFlags, mount};
    let flags = MsFlags::MS_NOSUID
        | MsFlags::MS_NODEV
        | if writable {
            MsFlags::empty()
        } else {
            MsFlags::MS_RDONLY | MsFlags::MS_NOEXEC
        };
    crate::mount_view::with_private_mount(
        "into",
        || {
            if endpoint(&state::observe().map_err(refuse)?, &dataset.name)? != *dataset {
                return Err(refuse("deploy into mount source incarnation changed"));
            }
            Ok(())
        },
        |root| {
            mount(
                Some(dataset.name.as_str()),
                root,
                Some("zfs"),
                flags,
                Some("zfsutil"),
            )
            .map_err(refuse)
        },
        work,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Backend as TreeBackend, fake::Fake as Tree};

    struct Fake {
        tree: Tree,
        events: Vec<Action>,
        interrupt: Option<(usize, bool)>,
        tar: RootTar,
    }
    impl Fake {
        fn new() -> Self {
            let mut tree = Tree::new();
            for name in ["a", "b"] {
                tree.datasets.get_mut(name).unwrap().mounted = false;
                tree.set(name, "mountpoint", "none");
                tree.set(name, "canmount", "off");
                tree.create(&format!("{name}/ROOT"));
                tree.datasets
                    .get_mut(&format!("{name}/ROOT"))
                    .unwrap()
                    .mounted = false;
                tree.set(&format!("{name}/ROOT"), "mountpoint", "none");
                tree.set(&format!("{name}/ROOT"), "canmount", "off");
                let be = format!("{name}/ROOT/old");
                tree.create(&be);
                tree.datasets.get_mut(&be).unwrap().mounted = false;
                tree.set(&be, "mountpoint", "/");
                tree.set(&be, "canmount", "noauto");
                tree.pools.get_mut(name).unwrap().bootfs = Some(be);
            }
            Self {
                tree,
                events: Vec::new(),
                interrupt: None,
                tar: RootTar {
                    path: PathBuf::from("/root.tar"),
                    sha256: "a".repeat(64),
                    bytes: 1024,
                    zstd: false,
                    kernels: vec!["test".into()],
                    entries: 4,
                    logical_bytes: 1024,
                },
            }
        }
    }
    fn request() -> Request {
        Request {
            pool: "a".into(),
            be: "new".into(),
            tar: "/root.tar".into(),
            overlays: vec![],
            hostname: Some("new-host".into()),
        }
    }
    impl Backend for Fake {
        fn observe(&mut self) -> io::Result<NativeState> {
            TreeBackend::observe(&mut self.tree).map_err(refuse)
        }
        fn hostid(&mut self, _: &Endpoint) -> io::Result<u32> {
            Ok(0x01020304)
        }
        fn tar(&mut self, _: &Path) -> io::Result<RootTar> {
            Ok(self.tar.clone())
        }
        fn overlay(&mut self, path: &Path) -> io::Result<overlay::Overlay> {
            overlay::review(path)
        }
        fn action(
            &mut self,
            plan: &Plan,
            _: Option<&Endpoint>,
            id: &str,
            action: Action,
        ) -> io::Result<()> {
            let n = self.events.len();
            if self.interrupt == Some((n, false)) {
                return Err(refuse("cut before"));
            }
            let name = plan.request.dataset();
            match action {
                Action::Container => {
                    let root = format!("{}/ROOT", plan.pool.name);
                    self.tree.create(&root);
                    self.tree.datasets.get_mut(&root).unwrap().mounted = false;
                    self.tree.set(&root, "mountpoint", "none");
                    self.tree.set(&root, "canmount", "off");
                }
                Action::Create => {
                    self.tree.create(&name);
                    self.tree.datasets.get_mut(&name).unwrap().mounted = false;
                    for (key, value) in [
                        ("mountpoint", "none"),
                        ("canmount", "off"),
                        ("readonly", "off"),
                        ("volmode", "none"),
                        ("zboot:pending", id),
                    ] {
                        self.tree.set(&name, key, value);
                    }
                }
                Action::FactorySnapshot => self.tree.snap(&format!("{name}@factory")),
                Action::DeployedSnapshot => self.tree.snap(&format!("{name}@deployed")),
                Action::Publish => {
                    self.tree.set(&name, "mountpoint", "/");
                    self.tree.set(&name, "canmount", "noauto");
                    self.tree
                        .datasets
                        .get_mut(&name)
                        .unwrap()
                        .props
                        .remove("volmode");
                }
                Action::ClearPending => {
                    self.tree
                        .datasets
                        .get_mut(&name)
                        .unwrap()
                        .props
                        .remove("zboot:pending");
                }
                Action::Extract | Action::Overlay(_) | Action::Identity => {}
            }
            self.events.push(action);
            if self.interrupt == Some((n, true)) {
                return Err(refuse("lost reply"));
            }
            Ok(())
        }
        fn boot_files(
            &mut self,
            _: &Plan,
            _: &Endpoint,
            _: &str,
        ) -> io::Result<BTreeMap<String, ImageFile>> {
            Ok(BTreeMap::from([(
                "boot/vmlinuz-test".into(),
                ImageFile {
                    sha256: "b".repeat(64),
                    bytes: 8,
                },
            )]))
        }
    }
    #[test]
    fn inherited_operation_properties_refuse_before_creating_a_target() {
        for has_container in [false, true] {
            let mut fake = Fake::new();
            if !has_container {
                fake.tree
                    .datasets
                    .retain(|name, _| !crate::history::contains_dataset("a/ROOT", name));
                fake.tree.pools.get_mut("a").unwrap().bootfs = None;
            }
            let key = zfs_tools::engine::intent::PROPERTY;
            fake.tree.set("a", key, "interrupted-operation");
            let state = fake.observe().unwrap();
            let parent = if has_container { "a/ROOT" } else { "a" };
            // A pool-root operation is inert to shared ownership admission.
            assert!(matches!(
                management::ownership(&state, parent).unwrap(),
                Ownership::Unpaired
            ));
            if has_container {
                assert_eq!(
                    state.dataset_properties[parent][key].source,
                    "inherited from a"
                );
            }
            let error = plan_with(&request(), &mut fake).unwrap_err().to_string();
            assert!(error.contains(key), "{error}");
            assert!(error.contains(parent), "{error}");
            assert!(fake.events.is_empty());
            assert!(!fake.tree.datasets.contains_key("a/ROOT/new"));
        }
    }

    #[test]
    fn inherited_property_drift_refuses_before_the_missing_target_can_be_created() {
        let mut fake = Fake::new();
        let plan = plan_with(&request(), &mut fake).unwrap();
        let key = "zboot:cmdline";
        fake.tree.set("a/ROOT", key, "console=ttyS0");
        let state = fake.observe().unwrap();
        let error = bound(&plan, &state, None, "not-created", false)
            .unwrap_err()
            .to_string();
        assert!(error.contains(key), "{error}");
        let error = apply_with(&plan, &mut fake).unwrap_err().to_string();
        assert!(error.contains(key), "{error}");
        assert!(fake.events.is_empty());
        assert!(!fake.tree.datasets.contains_key("a/ROOT/new"));
    }

    #[test]
    fn deploy_into_erases_nothing_and_leaves_every_default() {
        let mut fake = Fake::new();
        let before = defaults(&fake.observe().unwrap());
        let plan = plan_with(&request(), &mut fake).unwrap();
        assert!(fake.events.is_empty());
        let result = apply_with(&plan, &mut fake).unwrap();
        assert!(result.complete);
        assert_eq!(result.dataset.name, "a/ROOT/new");
        assert_eq!(defaults(&fake.observe().unwrap()), before);
        assert_eq!(
            fake.events,
            [
                Action::Create,
                Action::Extract,
                Action::FactorySnapshot,
                Action::Identity,
                Action::DeployedSnapshot,
                Action::Publish,
                Action::ClearPending
            ]
        );
        assert!(
            plan_with(&request(), &mut fake)
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
    }
    #[test]
    fn a_half_made_boot_environment_is_fenced_until_complete() {
        let mut successful = Fake::new();
        let plan = plan_with(&request(), &mut successful).unwrap();
        apply_with(&plan, &mut successful).unwrap();
        for n in 0..successful.events.len() {
            for after in [false, true] {
                let mut fake = Fake::new();
                let plan = plan_with(&request(), &mut fake).unwrap();
                fake.interrupt = Some((n, after));
                let result = apply_with(&plan, &mut fake);
                if let Some(be) = fake.tree.datasets.get("a/ROOT/new") {
                    let pending = be.props.contains_key("zboot:pending");
                    if result.is_err() {
                        assert!(pending, "cut {n}/{after}");
                    }
                    if pending {
                        let state = fake.observe().unwrap();
                        assert!(crate::boot_environment::admit(&state, "a/ROOT/new").is_err());
                        assert!(plan_with(&request(), &mut fake).is_err());
                    }
                }
                assert_eq!(defaults(&fake.observe().unwrap()), plan.defaults);
            }
        }
    }
    #[test]
    fn deploy_never_clears_another_pools_default() {
        let mut fake = Fake::new();
        let plan = plan_with(&request(), &mut fake).unwrap();
        let other = fake.tree.pools["b"].clone();
        apply_with(&plan, &mut fake).unwrap();
        assert_eq!(fake.tree.pools["b"].bootfs, other.bootfs);
        assert_eq!(fake.tree.pools["a"].bootfs.as_deref(), Some("a/ROOT/old"));
        // Disk and image publication has exactly the new-pool scope. This
        // native argv is shared with the actual executor.
        assert_eq!(
            super::super::publish_default_args("newpool", "newpool/ROOT/be"),
            ["set", "bootfs=newpool/ROOT/be", "newpool"]
        );
    }
    #[test]
    fn reordering_overlays_changes_the_plan() {
        let scratch = crate::factory::tests::Scratch::new();
        let mut req = request();
        for (name, value) in [("one", "1"), ("two", "2")] {
            let path = scratch.0.join(name);
            fs::create_dir_all(path.join("rootfs/etc")).unwrap();
            fs::write(path.join("rootfs/etc/value"), value).unwrap();
            req.overlays.push(path);
        }
        let mut fake = Fake::new();
        let first = plan_with(&req, &mut fake).unwrap();
        req.overlays.reverse();
        let second = plan_with(&req, &mut fake).unwrap();
        assert_ne!(first, second);
        assert_ne!(first.overlays[0].sha256, second.overlays[0].sha256);
    }
    #[test]
    fn every_resulting_kernel_has_a_contained_module_and_paired_file() {
        let scratch = crate::factory::tests::Scratch::new();
        let root = &scratch.0;
        fs::create_dir_all(root.join("boot")).unwrap();
        for release in ["test", "overlay-added"] {
            fs::create_dir_all(root.join(format!("usr/lib/modules/{release}/updates/dkms")))
                .unwrap();
            fs::write(
                root.join(format!("usr/lib/modules/{release}/updates/dkms/zfs.ko.zst")),
                b"module",
            )
            .unwrap();
            fs::write(root.join(format!("boot/vmlinuz-{release}")), b"kernel").unwrap();
            fs::write(root.join(format!("boot/initrd.img-{release}")), b"initrd").unwrap();
        }
        let factory = Fake::new().tar;
        let files = verify_boot_files(&factory, root).unwrap();
        assert_eq!(files.len(), 4);
        assert!(files.contains_key("boot/vmlinuz-overlay-added"));
        assert!(root.metadata().unwrap().is_dir());
        fs::remove_file(root.join("boot/initrd.img-overlay-added")).unwrap();
        assert!(verify_boot_files(&factory, root).is_err());
        fs::write(root.join("boot/initrd.img-overlay-added"), b"initrd").unwrap();
        fs::remove_file(root.join("usr/lib/modules/overlay-added/updates/dkms/zfs.ko.zst"))
            .unwrap();
        assert!(verify_boot_files(&factory, root).is_err());
        // A host file outside the held root cannot satisfy module admission.
        let outside = crate::factory::tests::Scratch::new();
        let module = outside.0.join("zfs.ko");
        fs::write(&module, b"outside module").unwrap();
        let target = root.join("usr/lib/modules/overlay-added/updates/dkms/zfs.ko.zst");
        std::os::unix::fs::symlink(&module, &target).unwrap();
        assert!(verify_boot_files(&factory, root).is_err());
        fs::remove_file(&target).unwrap();
        fs::write(target, b"module").unwrap();
        // Kernel/initrd inventory keeps its regular-file requirement too.
        fs::remove_file(root.join("boot/initrd.img-overlay-added")).unwrap();
        std::os::unix::fs::symlink(
            "initrd.img-test",
            root.join("boot/initrd.img-overlay-added"),
        )
        .unwrap();
        assert!(verify_boot_files(&factory, root).is_err());
    }

    #[test]
    fn an_into_plan_names_exactly_the_pools_it_writes() {
        let mut fake = Fake::new();
        let state = Backend::observe(&mut fake).unwrap();
        let plan = plan_with(&request(), &mut fake).unwrap();
        assert_eq!(
            crate::cli::access::tests::reopened(
                &state,
                crate::cli::access::plan_pools(&serde_json::to_value(&plan).unwrap())
            ),
            ["a"]
        );
    }
}
