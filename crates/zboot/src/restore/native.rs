//! The native backend: fixed `zfs`/`zpool` argument vectors, the host's own
//! `zfs send | zfs receive` for streams, the helper `zboot-change-key` for
//! the one key command the CLI lacks, and the existing device, deploy and
//! boot code.
use super::{
    Backend, Candidate, DatasetView, DeploySpec, PoolRef, PoolView, Property, Scrub, SnapshotView,
    View, refuse,
};
use crate::{
    deploy,
    device::{self, DiskIdentity, DiskReview},
    esp::FileIdentity,
    hostid, loader,
    menu::Result,
};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
use zfs_tools::engine::{
    DatasetKind, Encryption, Guid, KeyStatus, SnapshotRef, hold, intent,
    management::{Endpoint, Ownership},
    native::{self, NativeProperty},
    stream::{self, LeafStream, StreamOutcome},
};

/// Native effects.
#[derive(Default)]
pub struct Native {
    // Run imports only the newly deployed A. Remember dispatch, not its later
    // checkpoint, so a lost reply cannot leave that writable pool unaccounted for.
    imported_target: Option<Guid>,
}

impl Drop for Native {
    fn drop(&mut self) {
        if std::thread::panicking()
            && crate::handoff::uki_marker()
            && let Err(error) = self.cleanup_imported_target()
        {
            eprintln!(
                "zboot: restore target cleanup failed: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
        }
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

fn zfs(values: Vec<String>) -> Result<String> {
    Ok(native::run("zfs", &values)?)
}
fn zpool(values: Vec<String>) -> Result<String> {
    Ok(native::run("zpool", &values)?)
}

fn zfs_mutating(values: Vec<String>) -> Result<String> {
    Ok(native::run_mutating("zfs", &values)?)
}
fn zpool_mutating(values: Vec<String>) -> Result<String> {
    Ok(native::run_mutating("zpool", &values)?)
}

fn property(native: &NativeProperty) -> Property {
    Property {
        value: native.value.clone(),
        source: native.source.clone(),
    }
}

fn number(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::String(s) => s.parse().unwrap_or(0),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
        _ => 0,
    }
}

/// `zpool status -j -p POOL`: its scan statistics and error count.
pub(crate) fn parse_scrub(text: &str, pool: &str) -> Result<Scrub> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| refuse(format!("zpool status -j: {e}")))?;
    let item = value
        .get("pools")
        .and_then(|p| p.get(pool))
        .ok_or_else(|| refuse(format!("zpool status -j lacks pool {pool}")))?;
    let pool_errors = item.get("error_count").map_or(0, number);
    let Some(scan) = item.get("scan_stats") else {
        return Ok(Scrub {
            state: "NONE".into(),
            paused: false,
            start_time: 0,
            end_time: 0,
            examined: 0,
            to_examine: 0,
            errors: 0,
            pool_errors,
        });
    };
    let text = |key: &str| scan.get(key).and_then(|v| v.as_str()).unwrap_or("NONE");
    let function = text("function");
    let mut state = text("state").to_owned();
    if function != "SCRUB" {
        // A resilver or error scrub is not the scrub restore asks for.
        state = if state == "SCANNING" { "BUSY" } else { "NONE" }.into();
    }
    let get = |key: &str| scan.get(key).map_or(0, number);
    Ok(Scrub {
        state,
        paused: get("scrub_pause") != 0,
        start_time: get("start_time"),
        end_time: get("end_time"),
        examined: get("examined"),
        to_examine: get("to_examine"),
        errors: get("errors"),
        pool_errors,
    })
}

/// `zfs set -u`: setting `mountpoint` on a `canmount=on` dataset would
/// otherwise mount it (and its inheriting children) over the running system.
fn set_args(dataset: &str, key: &str, value: &str) -> Result<Vec<String>> {
    zfs_tools::engine::validate_dataset_name(dataset)?;
    Ok(vec![
        "set".into(),
        "-u".into(),
        format!("{key}={value}"),
        dataset.into(),
    ])
}

/// `zfs load-key -n -L LOCATION ROOT`: checks the key, loads nothing; works
/// with the key already loaded and on a read-only pool.
fn check_key_args(dataset: &str, keylocation: &str) -> Result<Vec<String>> {
    zfs_tools::engine::validate_dataset_name(dataset)?;
    if !keylocation.starts_with("file:///") || keylocation.chars().any(char::is_control) {
        return Err(refuse(format!(
            "{keylocation} is not a file:// key location"
        )));
    }
    Ok(args(&["load-key", "-n", "-L", keylocation, dataset]))
}

/// The key relink helper (`crates/zboot-helpers/src/bin/change-key.rs`): `inherit` or
/// `new-key` DATASET is `lzc_change_key` with DCP_CMD_FORCE_INHERIT or
/// FORCE_NEW_KEY, and `--check` initializes libzfs_core. It is a separate,
/// dynamically linked program because zboot is static, and glibc's static
/// `dlopen` needs the build's own glibc at run time. The package installs it
/// beside the signature probe, and the UKI carries it at the same path.
pub(crate) const CHANGE_KEY: &str = "/sbin/zboot-change-key";
/// What the helper prints on success, and only then.
const CHANGE_KEY_DONE: &[u8] = b"zboot-change-key-v1:ok\n";

fn change_key_helper(args: &[&str], mutating: bool) -> Result<()> {
    let args = args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    let output = if mutating {
        crate::native_run::run_status_mutating(CHANGE_KEY, &args, 4096, 60)?
    } else {
        crate::native_run::run_status(CHANGE_KEY, &args, 4096, 60)?
    };
    if output.status.success() && output.stdout == CHANGE_KEY_DONE {
        return Ok(());
    }
    Err(refuse(format!(
        "{CHANGE_KEY} {} failed ({}): {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Restore reads an admitted source without probing or mounting it here.
/// The shared classifier validates paired secondary copy sources separately
/// from writable boot roles. Snapshot and recursive identities remain bound by
/// restore's own plan and receipt.
fn source_candidate(state: &zfs_tools::engine::state::NativeState, dataset: &str) -> Candidate {
    let admission = crate::boot_environment::admit_restore_source(state, dataset);
    let secondary = matches!(&admission, Ok(Ownership::Secondary { .. }));
    let refusal = admission.err().map(|error| error.to_string()).or_else(|| {
        if dataset.chars().any(char::is_whitespace) {
            return Some(
                "boot dataset names with whitespace are unsupported in kernel root arguments"
                    .into(),
            );
        }
        let extras = state
            .dataset_properties
            .get(dataset)
            .and_then(|properties| properties.get("zboot:cmdline"))
            .map_or("", |property| property.value.as_str());
        crate::handoff::compose_cmdline(dataset, extras)
            .err()
            .map(|error| error.to_string())
            .or_else(|| {
                (!secondary)
                    .then(|| crate::mounting::refusal(state, Some(dataset)))
                    .flatten()
            })
    });
    Candidate {
        dataset: dataset.into(),
        refusal,
        writable_head: !secondary,
    }
}

/// The boot default is set only when every other imported pool's default
/// was verifiably cleared; anything less leaves the step to be resumed.
fn judge_default(be: &str, change: &crate::boot_support::DefaultChange) -> Result<()> {
    if change.complete {
        return Ok(());
    }
    Err(refuse(format!(
        "{be} is not yet the host's one boot default: {}; make that pool writable or export it, then resume",
        change
            .detail
            .as_deref()
            .unwrap_or("the change was not verified")
    )))
}

/// Resolve only the GUID this backend attempted to import. An old name or a
/// restore record alone never grants cleanup authority over another pool.
fn cleanup_target(backend: &mut impl Backend, guid: Guid) -> Result<()> {
    let view = backend.view()?;
    let Some(pool) = view.pools.iter().find(|pool| pool.guid == guid) else {
        return Ok(());
    };
    let bound = PoolRef {
        name: pool.name.clone(),
        guid,
    };
    export_target(backend, &bound)
}

fn export_target(backend: &mut impl Backend, bound: &PoolRef) -> Result<()> {
    let before = backend.view()?;
    if before.pool(&bound.name).is_none()
        && !before.pools.iter().any(|pool| pool.guid == bound.guid)
    {
        return Ok(());
    }
    if before
        .pool(&bound.name)
        .is_none_or(|pool| pool.guid != bound.guid)
    {
        return Err(refuse(format!(
            "restore cleanup pool identity changed: {} (guid {})",
            bound.name, bound.guid
        )));
    }
    let exported = backend.export(&bound.name);
    let after = backend.view();
    exported?;
    let after = after?;
    if after.pool(&bound.name).is_some() || after.pools.iter().any(|pool| pool.guid == bound.guid) {
        return Err(refuse(format!(
            "restore cleanup did not verify export of {} (guid {})",
            bound.name, bound.guid
        )));
    }
    Ok(())
}

impl Native {
    pub fn new() -> Self {
        Self {
            imported_target: None,
        }
    }

    /// Explicit UKI cleanup after Run returns, before shared pool access closes.
    /// A panic reaches the same cleanup through `Drop`.
    /// Host callers retain their existing behavior by not requesting cleanup.
    pub(crate) fn cleanup_imported_target(&mut self) -> Result<()> {
        if let Some(guid) = self.imported_target {
            cleanup_target(self, guid)?;
            self.imported_target = None;
        }
        Ok(())
    }

    fn import_with(&mut self, guid: Guid, dispatch: impl FnOnce() -> Result<()>) -> Result<()> {
        self.imported_target = Some(guid);
        dispatch()
    }

    /// The planned loader, copied out of the source snapshot into the
    /// restore's run directory and checked again against the plan there.
    fn stage_loader(spec: &DeploySpec) -> Result<PathBuf> {
        let point = &spec.snapshot;
        zfs_tools::engine::validate_snapshot_name(&point.name)?;
        if zfs_tools::engine::observe_snapshot(&point.name)?.point() != *point {
            return Err(refuse(
                "the source snapshot changed since the plan; abandon this restore",
            ));
        }
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&spec.journal_directory)?;
        }
        let copy = spec.journal_directory.join("zboot.efi");
        if let Err(error) = std::fs::remove_file(&copy)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
        let target = copy.clone();
        let shipped = hostid::readonly_view(&point.name, move |root| {
            let (mut source, identity) = loader::shipped(&File::open(root)?)?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&target)?;
            std::io::copy(&mut source, &mut output)?;
            output.sync_all()?;
            Ok(identity)
        })?;
        let staged = loader::EfiFile::inspect(&copy)?;
        if shipped != spec.loader || staged.identity()? != spec.loader {
            let _ = std::fs::remove_file(&copy);
            return Err(refuse(format!(
                "{} ships another zboot loader than planned; abandon this restore",
                point.name
            )));
        }
        Ok(copy)
    }

    fn journal(directory: &std::path::Path) -> Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700).recursive(true);
        builder.create(directory)?;
        // A fresh directory per attempt for the deploy's own logs; a deploy
        // is never resumed.
        let attempt = directory.join(format!(
            "deploy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&attempt)?;
        Ok(attempt)
    }
}

impl Backend for Native {
    fn view(&mut self) -> Result<View> {
        let state = zfs_tools::engine::state::observe()?;
        let none = BTreeMap::new();
        let pools = state
            .inspection
            .pools
            .iter()
            .map(|pool| {
                let props = state.pool_properties.get(&pool.name).unwrap_or(&none);
                let value = |key: &str| props.get(key).map(|p| p.value.clone());
                PoolView {
                    name: pool.name.clone(),
                    guid: pool.guid,
                    readonly: value("readonly").as_deref() == Some("on"),
                    altroot: value("altroot").filter(|v| v != "-" && !v.is_empty()),
                    bootfs: pool.bootfs.clone(),
                }
            })
            .collect();
        let datasets = state
            .inspection
            .datasets
            .iter()
            .map(|dataset| {
                let props = state.dataset_properties.get(&dataset.name).unwrap_or(&none);
                let properties: BTreeMap<_, _> = props
                    .iter()
                    .map(|(k, v)| (k.clone(), property(v)))
                    .collect();
                DatasetView {
                    name: dataset.name.clone(),
                    identity: dataset.identity.clone(),
                    volume: dataset.kind == DatasetKind::Volume,
                    used: dataset.used_bytes,
                    available: dataset.available_bytes,
                    mounted: dataset.mounted.unwrap_or(false),
                    origin: dataset.origin.clone(),
                    encrypted: dataset.encryption != Encryption::Off,
                    encryption_root: dataset.encryptionroot.clone(),
                    resume_token: properties
                        .get("receive_resume_token")
                        .is_some_and(|p| p.value != "-" && !p.value.is_empty()),
                    properties,
                }
            })
            .collect();
        let snapshots = state
            .inspection
            .snapshots
            .as_ref()
            .ok_or_else(|| refuse("snapshot inventory missing"))?
            .iter()
            .map(|snapshot| SnapshotView {
                point: snapshot.point(),
                holds: snapshot.holds.clone(),
                defer_destroy: snapshot.defer_destroy,
            })
            .collect();
        let candidates = crate::boot_environment::roots(&state)
            .into_iter()
            .map(|dataset| source_candidate(&state, &dataset.name))
            .collect();
        Ok(View {
            pools,
            datasets,
            snapshots,
            candidates,
            running_root: crate::status::running_root()?,
        })
    }

    fn received(
        &mut self,
        root: &str,
        properties: &[&str],
    ) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
        zfs_tools::engine::validate_dataset_name(root)?;
        let out = zfs(vec![
            "get".into(),
            "-H".into(),
            "-p".into(),
            "-r".into(),
            "-t".into(),
            "filesystem,volume".into(),
            "-o".into(),
            "name,property,received".into(),
            properties.join(","),
            root.into(),
        ])?;
        let mut result: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for line in out.lines() {
            let mut fields = line.splitn(3, '\t');
            let (Some(name), Some(key), Some(value)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(refuse("zfs get received: malformed line"));
            };
            if value != "-" {
                result
                    .entry(name.into())
                    .or_default()
                    .insert(key.into(), value.into());
            }
        }
        Ok(result)
    }

    fn disk_identity(&mut self, path: &str) -> Result<DiskIdentity> {
        Ok(device::observe_identity(path)?)
    }
    fn disk(&mut self, path: &str, owned: Option<&str>) -> Result<DiskReview> {
        Ok(device::plan_owned(path, owned)?)
    }
    fn label_extents(&mut self, review: &DiskReview) -> Result<Vec<device::Extent>> {
        Ok(device::label_extents(review)?)
    }
    fn labels_present(&mut self, disk: &DiskIdentity, regions: &[device::Extent]) -> Result<bool> {
        Ok(device::labels_present(disk, regions)?)
    }
    fn pool_disks(&mut self, pool: &str, guid: Guid) -> Result<Vec<DiskIdentity>> {
        Ok(device::observe_pool_storage(pool, &guid)?.disks)
    }
    fn scrub_status(&mut self, pool: &str) -> Result<Scrub> {
        zfs_tools::engine::validate_dataset_name(pool)?;
        parse_scrub(&zpool(args(&["status", "-j", "-p", pool]))?, pool)
    }
    fn snapshot_hostid(&mut self, point: &SnapshotRef) -> Result<String> {
        zfs_tools::engine::validate_snapshot_name(&point.name)?;
        if zfs_tools::engine::observe_snapshot(&point.name)?.point() != *point {
            return Err(refuse("selected source snapshot identity changed"));
        }
        let found = hostid::installed_in(&point.name).require(&point.name)?;
        Ok(hostid::format(found))
    }
    fn running_hostid(&mut self) -> Result<String> {
        let root = std::fs::File::open("/")?;
        let found = hostid::installed(&root).require("the running BE")?;
        Ok(hostid::format(found))
    }
    fn effective_hostid(&mut self) -> Result<String> {
        Ok(hostid::format(hostid::effective()?))
    }
    fn loader(&mut self, snapshot: Option<&SnapshotRef>) -> Result<FileIdentity> {
        // The last step makes the restored BE the boot default, which needs a
        // kernel and initrd; a source without them is refused before any erase.
        let shipped = |root: &std::path::Path| {
            crate::menu::inventory::kernel_choices(root).map_err(|error| {
                std::io::Error::other(format!(
                    "{error}; the source cannot become the boot default"
                ))
            })?;
            loader::shipped(&File::open(root)?).map(|(_, identity)| identity)
        };
        let Some(point) = snapshot else {
            return Ok(shipped(std::path::Path::new("/"))?);
        };
        zfs_tools::engine::validate_snapshot_name(&point.name)?;
        if zfs_tools::engine::observe_snapshot(&point.name)?.point() != *point {
            return Err(refuse("selected source snapshot identity changed"));
        }
        Ok(hostid::readonly_view(&point.name, shipped)?)
    }
    fn require_no_image(&mut self) -> Result<()> {
        crate::handoff::require_no_hibernation_image()
    }
    fn now(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
    fn pause(&mut self) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    fn record_pools(&mut self) -> Result<Vec<String>> {
        Ok(intent::Backend::pools(&mut intent::Native)?)
    }
    fn record_read(&mut self, pool: &str) -> Result<Option<String>> {
        Ok(intent::Backend::read(&mut intent::Native, pool)?)
    }
    fn record_write(&mut self, pool: &str, value: &str) -> Result<()> {
        Ok(intent::Backend::write(&mut intent::Native, pool, value)?)
    }
    fn record_remove(&mut self, pool: &str) -> Result<()> {
        Ok(intent::Backend::remove(&mut intent::Native, pool)?)
    }

    fn hold_resolve(&mut self, point: &SnapshotRef) -> Result<Option<hold::Seen>> {
        Ok(hold::Backend::resolve(&mut hold::Native, point)?)
    }
    fn hold(&mut self, name: &str, tag: &str) -> Result<()> {
        Ok(hold::Backend::hold(&mut hold::Native, name, tag)?)
    }
    fn release(&mut self, name: &str, tag: &str) -> Result<()> {
        Ok(hold::Backend::release(&mut hold::Native, name, tag)?)
    }

    fn snapshot(&mut self, name: &str, recursive: bool) -> Result<()> {
        zfs_tools::engine::validate_snapshot_name(name)?;
        let mut argv = vec!["snapshot".to_string()];
        if recursive {
            argv.push("-r".into());
        }
        argv.push(name.into());
        zfs_mutating(argv).map(drop)
    }
    fn create(&mut self, dataset: &str, properties: &[(String, String)]) -> Result<()> {
        zfs_tools::engine::validate_dataset_name(dataset)?;
        let mut argv = vec!["create".to_string(), "-u".to_string()];
        for (key, value) in properties {
            argv.extend(["-o".into(), format!("{key}={value}")]);
        }
        argv.push(dataset.into());
        zfs_mutating(argv).map(drop)
    }
    fn check_key(&mut self, dataset: &str, keylocation: &str) -> Result<()> {
        zfs(check_key_args(dataset, keylocation)?).map(drop)
    }
    fn wrapping(&mut self, endpoint: &Endpoint) -> Result<crate::transfer::Wrapping> {
        use crate::transfer::TransferBackend;
        Ok(crate::transfer::NativeTransfer::new().wrapping(endpoint)?)
    }
    fn change_key(&mut self, endpoint: &Endpoint, inherit: bool) -> Result<()> {
        zfs_tools::engine::validate_dataset_name(&endpoint.name)?;
        let current = zfs_tools::engine::inspect(&zfs_tools::engine::InspectRequest::new(
            vec![endpoint.name.clone()],
            false,
        )?)?;
        let dataset = current
            .datasets
            .iter()
            .find(|d| d.name == endpoint.name && d.identity == endpoint.identity)
            .ok_or_else(|| {
                refuse(format!(
                    "{} changed before its key was relinked",
                    endpoint.name
                ))
            })?;
        // A raw receive leaves the key unloaded. A loaded one means someone
        // else is using the dataset, and repointing it then is not restore's.
        if dataset.keystatus != KeyStatus::Unavailable {
            return Err(refuse(format!(
                "{}'s key is {}; restore relinks only a dataset whose key is not loaded",
                endpoint.name,
                match dataset.keystatus {
                    KeyStatus::Available => "loaded",
                    _ => "not an encryption key",
                }
            )));
        }
        change_key_helper(
            &[if inherit { "inherit" } else { "new-key" }, &endpoint.name],
            true,
        )
    }
    fn change_key_ready(&mut self) -> Result<()> {
        change_key_helper(&["--check"], false)
    }
    fn set(&mut self, dataset: &str, key: &str, value: &str) -> Result<()> {
        zfs_mutating(set_args(dataset, key, value)?).map(drop)
    }
    fn inherit(&mut self, dataset: &str, key: &str) -> Result<()> {
        zfs_tools::engine::validate_dataset_name(dataset)?;
        zfs_mutating(args(&["inherit", key, dataset])).map(drop)
    }
    fn receive_quiesce(&mut self, endpoint: &Endpoint, operation_id: &str) -> Result<()> {
        Ok(zfs_tools::engine::stream::quiesce_inert(
            endpoint,
            operation_id,
        )?)
    }
    fn destroy_tree(&mut self, dataset: &str) -> Result<()> {
        zfs_tools::engine::validate_dataset_name(dataset)?;
        if !dataset.contains('/') {
            return Err(refuse("refusing to destroy a pool root"));
        }
        zfs_mutating(args(&["destroy", "-r", dataset])).map(drop)
    }
    fn destroy_snapshot(&mut self, point: &SnapshotRef) -> Result<()> {
        zfs_tools::engine::validate_snapshot_name(&point.name)?;
        if zfs_tools::engine::observe_snapshot(&point.name)?.point() != *point {
            return Err(refuse(format!(
                "{} changed before its deletion",
                point.name
            )));
        }
        zfs_mutating(args(&["destroy", &point.name])).map(drop)
    }
    fn stream(&mut self, stream: &LeafStream) -> Result<StreamOutcome> {
        Ok(stream::leaf_replicate(stream)?)
    }
    fn scrub(&mut self, pool: &str) -> Result<()> {
        zfs_tools::engine::validate_dataset_name(pool)?;
        zpool_mutating(args(&["scrub", pool])).map(drop)
    }
    fn export(&mut self, pool: &str) -> Result<()> {
        zfs_tools::engine::validate_dataset_name(pool)?;
        let properties = native::pool_properties_with(&[pool.to_owned()], native::run)?;
        match properties
            .get(pool)
            .and_then(|properties| properties.get("readonly"))
            .map(|property| property.value.as_str())
        {
            Some("on") => zpool(args(&["export", pool])).map(drop),
            Some("off") => zpool_mutating(args(&["export", pool])).map(drop),
            _ => Err(refuse(format!(
                "pool readonly property was not observed before export: {pool}"
            ))),
        }
    }
    fn import(&mut self, guid: Guid, hostid: &str) -> Result<()> {
        // OpenZFS records the importing hostid; set the BE's for this import.
        let hostid = hostid::parse(hostid)?;
        self.import_with(guid, || {
            Ok(deploy::create_with_hostid(hostid, || {
                zpool_mutating(vec![
                    "import".into(),
                    "-N".into(),
                    "-o".into(),
                    "cachefile=none".into(),
                    guid.to_string(),
                ])
                .map(drop)
                .map_err(|error| std::io::Error::other(error.to_string()))
            })?)
        })
    }
    fn wipe(&mut self, review: &DiskReview) -> Result<()> {
        device::wipe(review, &review.loss_token)?;
        Ok(())
    }
    fn deploy(&mut self, spec: &DeploySpec) -> Result<Guid> {
        let efi = Self::stage_loader(spec)?;
        let result = (|| {
            let request = deploy::request::DeployRequest {
                schema_version: 3,
                overlays: Vec::new(),
                portable: false,
                fresh_image: false,
                disk: spec.disk.path.clone(),
                pool: spec.pool.clone(),
                hostid: Some(spec.hostid.clone()),
                hostname: None,
                purpose: deploy::request::Purpose::EmptyRoot {
                    container: format!("{}/ROOT", spec.pool),
                },
                boot: deploy::request::Boot::OnTarget {
                    esp_bytes: spec.esp_bytes,
                },
                swap: match spec.swap_bytes {
                    0 => deploy::request::Swap::None,
                    bytes => deploy::request::Swap::Create { bytes },
                },
                boot_artifact_directory: efi.clone(),
                journal_directory: Self::journal(&spec.journal_directory)?,
            };
            let review = deploy::request::plan(&request)?;
            if !device::same_disk_stable(&spec.disk, &review.disk) {
                return Err(refuse("deploy reviewed another disk than the one erased"));
            }
            let outcome = deploy::request::apply(&review, &review.loss_token)?;
            if !outcome.complete {
                return Err(refuse("deploy did not complete"));
            }
            Ok(outcome.pool.identity.pool_guid)
        })();
        let removed = std::fs::remove_file(&efi);
        let guid = result?;
        removed?;
        Ok(guid)
    }
    fn boot(&mut self, be: &str) -> Result<()> {
        judge_default(be, &crate::boot_support::set_default_with(be)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_world() -> (super::super::fake::Fake, PoolRef) {
        let mut fake = super::super::fake::Fake::world();
        let view = fake.view().unwrap();
        let pool = view.pool("rpool").unwrap();
        let bound = PoolRef {
            name: pool.name.clone(),
            guid: pool.guid,
        };
        (fake, bound)
    }

    #[test]
    fn cleanup_exports_only_the_attempted_target_guid() {
        let (mut fake, bound) = cleanup_world();
        let source = fake.view().unwrap().pool("bpool").unwrap().clone();
        cleanup_target(&mut fake, bound.guid).unwrap();
        let after = fake.view().unwrap();
        assert!(!after.pools.iter().any(|pool| pool.guid == bound.guid));
        assert_eq!(after.pool("bpool"), Some(&source));
        assert_eq!(fake.effects, ["export rpool"]);
    }

    #[test]
    fn cleanup_without_an_attempt_or_with_an_absent_guid_is_a_noop() {
        Native::new().cleanup_imported_target().unwrap();
        let (mut fake, bound) = cleanup_world();
        fake.pools
            .iter_mut()
            .find(|pool| pool.name == bound.name)
            .unwrap()
            .imported = false;
        let before = fake.view().unwrap();
        cleanup_target(&mut fake, bound.guid).unwrap();
        assert_eq!(fake.view().unwrap().pools, before.pools);
        assert!(fake.effects.is_empty());
    }

    #[test]
    fn cleanup_refuses_a_replaced_or_renamed_binding_before_export() {
        for replaced in [false, true] {
            let (mut fake, bound) = cleanup_world();
            let pool = fake
                .pools
                .iter_mut()
                .find(|pool| pool.name == bound.name)
                .unwrap();
            if replaced {
                pool.guid += 10_000;
            } else {
                pool.name = "renamed".into();
            }
            let error = export_target(&mut fake, &bound).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("restore cleanup pool identity changed"),
                "{error}"
            );
            assert!(fake.effects.is_empty());
            assert!(fake.pools.iter().all(|pool| pool.imported));
        }
    }

    #[test]
    fn cleanup_surfaces_export_failure_and_can_be_retried() {
        let (mut fake, bound) = cleanup_world();
        fake.export_error = true;
        let error = cleanup_target(&mut fake, bound.guid).unwrap_err();
        assert!(
            error.to_string().contains("injected export failure"),
            "{error}"
        );
        assert!(
            fake.view()
                .unwrap()
                .pools
                .iter()
                .any(|pool| pool.guid == bound.guid)
        );
        fake.export_error = false;
        cleanup_target(&mut fake, bound.guid).unwrap();
        assert!(
            !fake
                .view()
                .unwrap()
                .pools
                .iter()
                .any(|pool| pool.guid == bound.guid)
        );
        assert_eq!(fake.effects, ["export rpool", "export rpool"]);
    }

    #[test]
    fn an_import_lost_reply_is_tracked_before_any_new_pool_checkpoint() {
        let (mut fake, bound) = cleanup_world();
        fake.pools
            .iter_mut()
            .find(|pool| pool.name == bound.name)
            .unwrap()
            .imported = false;
        let mut native = Native::new();
        let error = native
            .import_with(bound.guid, || {
                fake.import(bound.guid, super::super::fake::HOSTID)?;
                Err(refuse("import reply was lost before checkpoint"))
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("import reply was lost"),
            "{error}"
        );
        assert_eq!(native.imported_target, Some(bound.guid));
        assert!(fake.record_read("bpool").unwrap().is_none());
        assert!(fake.record_read("rpool").unwrap().is_none());
        assert!(
            fake.view()
                .unwrap()
                .pools
                .iter()
                .any(|pool| pool.guid == bound.guid)
        );
        cleanup_target(&mut fake, native.imported_target.unwrap()).unwrap();
        assert!(
            !fake
                .view()
                .unwrap()
                .pools
                .iter()
                .any(|pool| pool.guid == bound.guid)
        );
        assert_eq!(
            fake.effects,
            [format!("import {}", bound.guid), "export rpool".into()]
        );
    }

    #[test]
    fn restore_source_admission_ignores_legacy_markers_and_keeps_shape_and_cmdline_checks() {
        let mut fake = crate::tree::fake::Fake::new();
        let be = "a/ROOT/os";
        fake.create("a/ROOT");
        fake.create(be);
        fake.create("a/ROOT/os/var");
        fake.set(be, "mountpoint", "/");
        fake.set(be, "canmount", "noauto");
        fake.set("a/ROOT/os/var", "canmount", "noauto");
        for legacy in [
            None,
            Some(("0", "received")),
            Some(("arbitrary", "inherited from a")),
        ] {
            let mut state = fake.state().unwrap();
            if let Some((value, source)) = legacy {
                state.dataset_properties.get_mut(be).unwrap().insert(
                    "zboot:be".into(),
                    NativeProperty {
                        value: value.into(),
                        source: source.into(),
                    },
                );
            }
            let source = source_candidate(&state, be);
            assert_eq!((source.refusal, source.writable_head), (None, true));
        }
        fake.set(be, "zboot:cmdline", "root=evil");
        let source = source_candidate(&fake.state().unwrap(), be);
        assert!(
            source
                .refusal
                .unwrap()
                .contains("conflicts with safe boot handoff")
        );
        fake.set(be, "zboot:cmdline", "console=ttyS0");
        fake.set("a/ROOT/os/var", "zboot:future-role", "unknown");
        let source = source_candidate(&fake.state().unwrap(), be);
        assert!(source.refusal.unwrap().contains("zboot:future-role"));
        fake.datasets
            .get_mut("a/ROOT/os/var")
            .unwrap()
            .props
            .remove("zboot:future-role");
        fake.set(be, "mountpoint", "/data");
        let source = source_candidate(&fake.state().unwrap(), be);
        assert!(source.refusal.unwrap().contains("mountpoint=/"));
    }

    #[test]
    fn a_secondary_is_a_restore_source_but_not_a_writable_head() {
        use zfs_tools::engine::management::{PairRecord, Role};
        let mut fake = crate::tree::fake::Fake::new();
        let be = "a/ROOT/os";
        fake.create("a/ROOT");
        fake.create(be);
        fake.create("a/ROOT/os/var");
        fake.create("b/primary");
        fake.set(be, "mountpoint", "/");
        fake.set(be, "canmount", "noauto");
        fake.set(be, "readonly", "on");
        fake.set("a/ROOT/os/var", "canmount", "noauto");
        let pair = PairRecord {
            schema_version: 1,
            pair_id: uuid::Uuid::new_v4().to_string(),
            endpoint: Endpoint {
                name: be.into(),
                identity: fake.identity(be),
            },
            peer: Endpoint {
                name: "b/primary".into(),
                identity: fake.identity("b/primary"),
            },
            role: Role::Secondary,
        };
        fake.set(
            be,
            zfs_tools::engine::management::PAIR_PROPERTY,
            &pair.encode().unwrap(),
        );
        fake.set(
            "b/primary",
            zfs_tools::engine::management::PAIR_PROPERTY,
            &pair.counterpart().encode().unwrap(),
        );
        let source = source_candidate(&fake.state().unwrap(), be);
        assert_eq!((source.refusal, source.writable_head), (None, false));
        fake.set(be, "zboot:cmdline", "root=evil");
        let source = source_candidate(&fake.state().unwrap(), be);
        assert!(!source.writable_head);
        assert!(
            source
                .refusal
                .unwrap()
                .contains("conflicts with safe boot handoff")
        );
        fake.set(be, "zboot:cmdline", "console=ttyS0");
        fake.set("a/ROOT/os/var", "zboot:future-role", "unknown");
        let source = source_candidate(&fake.state().unwrap(), be);
        assert!(source.refusal.unwrap().contains("zboot:future-role"));
    }

    #[test]
    fn scrub_status_parses_literal_json() {
        let text = r#"{"output_version":{"command":"zpool status","vers_major":0,"vers_minor":1},
            "pools":{"tank":{"name":"tank","state":"ONLINE","error_count":"0",
            "scan_stats":{"function":"SCRUB","state":"SCANNING","start_time":"1700000000",
            "end_time":"0","to_examine":"1000","examined":"250","errors":"0","scrub_pause":"0"}}}}"#;
        let scrub = parse_scrub(text, "tank").unwrap();
        assert_eq!(scrub.state, "SCANNING");
        assert_eq!((scrub.examined, scrub.to_examine), (250, 1000));
        assert!(!scrub.paused);
        let resilver = text.replace("\"SCRUB\"", "\"RESILVER\"");
        assert_eq!(parse_scrub(&resilver, "tank").unwrap().state, "BUSY");
        let none = r#"{"pools":{"tank":{"error_count":"3"}}}"#;
        let scrub = parse_scrub(none, "tank").unwrap();
        assert_eq!((scrub.state.as_str(), scrub.pool_errors), ("NONE", 3));
        assert!(parse_scrub(none, "other").is_err());
    }

    #[test]
    fn configuration_never_mounts_and_keys_are_only_checked() {
        assert_eq!(
            set_args("rpool/home", "mountpoint", "/home").unwrap(),
            ["set", "-u", "mountpoint=/home", "rpool/home"]
        );
        assert_eq!(
            check_key_args("rpool/secret", "file:///etc/zfs/k").unwrap(),
            ["load-key", "-n", "-L", "file:///etc/zfs/k", "rpool/secret"]
        );
        assert!(check_key_args("rpool/secret", "prompt").is_err());
    }

    #[test]
    fn an_unverified_default_is_not_success() {
        use crate::boot_support::{BootChange, DefaultChange};
        let change = |complete| BootChange {
            dataset: "rpool/ROOT/debian".into(),
            property: "bootfs".into(),
            value: "rpool/ROOT/debian".into(),
            complete,
            detail: None,
        };
        let mut outcome = DefaultChange {
            dataset: "rpool/ROOT/debian".into(),
            selected: change(true),
            cleared: vec![change(false)],
            complete: false,
            detail: Some("cpool still names cpool/ROOT/x as its default".into()),
        };
        let error = judge_default("rpool/ROOT/debian", &outcome).unwrap_err();
        assert!(error.to_string().contains("cpool still names"), "{error}");
        outcome.complete = true;
        judge_default("rpool/ROOT/debian", &outcome).unwrap();
    }
}
