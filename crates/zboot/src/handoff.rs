//! Explicit, fenced kexec handoff and its admission: the independent RAM
//! runtime, boot environment eligibility, kernel command lines and staged,
//! hash-bound assets. The menu, `zboot boot`, RAM boot and deploy share these
//! safety rules.
use crate::menu::inventory::candidates;
use crate::menu::select::countdown_refusal;
use crate::menu::{RecoveryError, Result, after_imports, at, cleanup_error, hostid_adopt, refuse};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use zfs_tools::engine::{
    DatasetIdentity,
    management::Ownership,
    operation::SnapshotScope,
    pool_of,
    state::{self, NativeState},
};

fn identity_summary(identity: &DatasetIdentity) -> String {
    format!(
        "pool_guid={} guid={} createtxg={} objsetid={}",
        identity.pool_guid, identity.guid, identity.createtxg, identity.objsetid
    )
}

macro_rules! diagnostic {
    ($($argument:tt)*) => {
        if zfs_tools::engine::native::verbose() {
            eprintln!($($argument)*);
        }
    };
}
pub(crate) use diagnostic;

/// A guided restore's inert staging dataset may contain marked BE roots.
/// Match only the canonical, direct pool child the restore engine reserves.
pub(crate) fn is_guided_restore_workspace_dataset(dataset: &str) -> bool {
    let Some((_, path)) = dataset.split_once('/') else {
        return false;
    };
    let root = path.split('/').next().unwrap_or("");
    root.strip_prefix("zboot-restore-")
        .is_some_and(crate::restore::valid_id)
}

pub(crate) fn eligible(
    state: &NativeState,
    dataset: &str,
) -> Result<(SnapshotScope, Ownership, String)> {
    if is_guided_restore_workspace_dataset(dataset) {
        return Err(refuse("guided restore workspace cannot boot"));
    }
    if dataset.chars().any(char::is_whitespace) {
        return Err(refuse(
            "boot dataset names with whitespace are unsupported in kernel root arguments",
        ));
    }
    let (scope, ownership) = crate::boot_environment::admit(state, dataset)?;
    let properties = state
        .dataset_properties
        .get(dataset)
        .ok_or_else(|| refuse("BE properties were not observed"))?;
    let extras = properties
        .get("zboot:cmdline")
        .map_or("", |p| p.value.as_str());
    Ok((scope, ownership, compose_cmdline(dataset, extras)?))
}

fn key(token: &str) -> &str {
    token.split_once('=').map_or(token, |(key, _)| key)
}

/// The host identity and OpenZFS's import-force switch belong to the kexec
/// composer alone: a saved or shipped value never reaches the kernel.
fn identity_or_force(key: &str) -> bool {
    matches!(
        key,
        "spl.spl_hostid" | "spl_hostid" | "zfs.force" | "zfs_force" | "zfsforce"
    )
}

/// The BE's command line before its host identity: the root contract, then
/// the BE's saved `zboot:cmdline` arguments, none of which may override it.
pub(crate) fn compose_cmdline(dataset: &str, extras: &str) -> Result<String> {
    let mut command_line = format!("boot=zfs root=ZFS={dataset} ro");
    for token in extras.split_whitespace() {
        let key = key(token);
        if matches!(
            key,
            "root" | "boot" | "ro" | "rw" | "init" | "rdinit" | "zboot.recovery" | "zboot.trace"
        ) || identity_or_force(key)
            || token.contains(['\'', '"', '\\'])
            || token.chars().any(char::is_control)
        {
            return Err(refuse(format!(
                "saved kernel argument conflicts with safe boot handoff: {token}"
            )));
        }
        command_line.push(' ');
        command_line.push_str(token);
    }
    if command_line.len() > 2047 {
        return Err(refuse(
            "kernel command line exceeds the supported 2047-byte limit",
        ));
    }
    Ok(command_line)
}

/// Refuse an explicit writable action (a Menu action, restore, deploy) while
/// a hibernation image is present: resuming it later would damage every pool
/// written since. A normal boot writes nothing, so it needs no such check.
pub(crate) fn require_no_hibernation_image() -> Result<()> {
    hostid_adopt::require_no_image()
}

/// Compose the handoff command line with the adopted identity when present.
/// A pool-less portable boot leaves identity discovery to its own initrd.
pub(crate) fn kexec_cmdline(line: &str, hostid: Option<u32>) -> Result<String> {
    if let Some(token) = line
        .split_whitespace()
        .find(|token| identity_or_force(key(token)))
    {
        return Err(refuse(format!(
            "kernel argument {token} is reserved for the host identity zboot passes"
        )));
    }
    let command_line = match hostid {
        Some(hostid) => format!("{} spl.spl_hostid=0x{hostid:08x}", line.trim_end()),
        None => line.trim_end().to_owned(),
    };
    if command_line.len() > 2047 {
        return Err(refuse(
            "kernel command line exceeds the supported 2047-byte limit",
        ));
    }
    Ok(command_line)
}

/// Refuse overlay and every disk-backed runtime dependency. A RAM upper layer
/// over a disk-backed lower is not an independent recovery environment.
pub fn validate_ram_environment(
    cmdline: &str,
    mountinfo: &(impl AsRef<[u8]> + ?Sized),
    executable: &Path,
) -> Result<()> {
    let markers: Vec<_> = cmdline
        .split_whitespace()
        .filter(|t| t.starts_with("zboot.recovery="))
        .collect();
    if markers != ["zboot.recovery=1"] {
        return Err(refuse(
            "native menu effects require exactly zboot.recovery=1",
        ));
    }
    let mounts = zfs_tools::engine::mountinfo::table(mountinfo)?;
    let root = mounts
        .iter()
        .find(|m| m.mount_point == Path::new("/"))
        .ok_or_else(|| refuse("root mount was not observed"))?;
    if !matches!(root.filesystem.as_str(), "rootfs" | "ramfs" | "tmpfs") {
        return Err(refuse("menu root is not an independent RAM filesystem"));
    }
    for path in [
        Path::new("/run"),
        Path::new("/usr"),
        Path::new("/bin"),
        Path::new("/sbin"),
        Path::new("/lib"),
        Path::new("/lib64"),
        Path::new("/etc"),
        executable,
    ] {
        let containing = mounts
            .iter()
            .filter(|m| path.starts_with(&m.mount_point))
            .max_by_key(|m| m.mount_point.components().count())
            .ok_or_else(|| refuse("runtime path has no observed containing mount"))?;
        if !matches!(containing.filesystem.as_str(), "rootfs" | "ramfs" | "tmpfs") {
            return Err(refuse(format!(
                "runtime path {} depends on {}",
                path.display(),
                containing.filesystem
            )));
        }
        // /run may contain our explicitly verified read-only BE inspection mount;
        // staged assets are separately checked against their containing mount.
        if path != Path::new("/run")
            && mounts.iter().any(|m| {
                m.mount_point.starts_with(path)
                    && !matches!(m.filesystem.as_str(), "rootfs" | "ramfs" | "tmpfs")
            })
        {
            return Err(refuse(format!(
                "runtime subtree {} has a non-RAM mount",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Whether this kernel was started as the zboot UKI. The handoff strips the
/// marker, so a booted system never carries it.
pub(crate) fn uki_marker() -> bool {
    std::fs::read_to_string("/proc/cmdline").is_ok_and(|cmdline| has_uki_marker(&cmdline))
}

fn has_uki_marker(cmdline: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|token| token.starts_with("zboot.recovery="))
}

pub(crate) fn prove_ram() -> Result<()> {
    validate_ram_environment(
        &std::fs::read_to_string("/proc/cmdline")?,
        &std::fs::read("/proc/thread-self/mountinfo")?,
        &std::fs::canonicalize("/proc/self/exe")?,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetHashes {
    pub kernel_sha256: String,
    pub initrd_sha256: String,
}

/// The source of a displayed pair controls its fresh readback at handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSelection {
    Explicit,
    DefaultPair,
    PoolDefault,
    PoolDefaultKernel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffRequest {
    pub selection: PairSelection,
    /// Fingerprints from the displayed inventory, rechecked before loading.
    pub expected_assets: Option<AssetHashes>,
    pub dataset: String,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    /// When set, the request came from a displayed menu entry and must still
    /// refer to that exact native dataset incarnation.
    pub expected_identity: Option<DatasetIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StagedKernel {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub command_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    MountReadonly { dataset: String, target: PathBuf },
    Unmount { target: PathBuf },
    Export { pool: String },
    Load { assets: StagedKernel },
    Execute,
}

/// Injectable boundary for tests. Production does not expose the native backend;
/// only the admitted handoff and RAM-gated menu can issue these actions.
pub trait RecoveryBackend {
    fn prove_ram(&mut self) -> Result<()>;
    fn observe(&mut self) -> Result<NativeState>;
    /// Listing uses one global observation. Native implementations recheck
    /// only the selected tree and its frozen authority dependencies here.
    fn revalidate_inventory(
        &mut self,
        binding: &zfs_tools::engine::state::ReadonlyInventoryBinding,
        dataset: &str,
        scope: &SnapshotScope,
        ownership: &Ownership,
        command_line: &str,
    ) -> Result<()> {
        let _ = binding;
        revalidate_selection(&self.observe()?, dataset, scope, ownership, command_line)
    }
    /// The hostid to boot with (the effective SPL hostid) and, under an
    /// adoption, the GUIDs of its host's pools.
    fn identity(&mut self) -> Result<(Option<u32>, Option<BTreeSet<String>>)>;
    fn workspace(&mut self) -> Result<PathBuf>;
    fn action(&mut self, action: &Action) -> Result<()>;
    fn verify_mount(&mut self, dataset: &str, target: &Path) -> Result<()>;
    fn stage(
        &mut self,
        root: &Path,
        work: &Path,
        request: &HandoffRequest,
        command_line: &str,
    ) -> Result<StagedKernel>;
    fn cleanup(&mut self, work: &Path) -> Result<()>;
}

pub fn handoff(request: &HandoffRequest) -> Result<()> {
    prove_ram().map_err(|error| at("prove independent RAM runtime before boot", error))?;
    diagnostic!("ZBOOT_HANDOFF_LOCK_BEGIN");
    handoff_guarded(request, &mut NativeRecovery::new(), || {
        zfs_tools::engine::lock::for_command("zboot", "boot")
            .map_err(|error| refuse(error.to_string()))
    })
}

/// The countdown can finish while a removable pool is still importing. Recheck
/// defaults after draining that batch and taking the same writer barrier.
pub(crate) fn handoff_automatic(request: &HandoffRequest) -> Result<()> {
    prove_ram()?;
    let _writer = after_imports(|| {
        zfs_tools::engine::lock::for_command("zboot", "automatic boot")
            .map_err(|error| refuse(error.to_string()))
    })?;
    let observed = state::observe()?;
    if validate_native_default(&observed, request).is_err()
        || countdown_refusal(&observed, hostid_adopt::countdown_refusal()).is_some()
    {
        return Err(refuse(
            "boot default changed while waiting for pool imports; automatic boot cancelled",
        ));
    }
    handoff_with(request, &mut NativeRecovery::new())
}

fn handoff_guarded<G>(
    request: &HandoffRequest,
    backend: &mut impl RecoveryBackend,
    writer: impl FnOnce() -> Result<G>,
) -> Result<()> {
    let _writer = after_imports(writer)?;
    diagnostic!("ZBOOT_HANDOFF_READY");
    handoff_with(request, backend)
}

/// Load only after all identities/fences and staged hashes have been verified.
/// A failed unmount or non-force export blocks execution. A returning kexec is
/// always an error, never a simulated successful boot.
pub fn handoff_with(request: &HandoffRequest, backend: &mut impl RecoveryBackend) -> Result<()> {
    backend
        .prove_ram()
        .map_err(|error| at("prove independent RAM runtime before handoff", error))?;
    diagnostic!("ZBOOT_HANDOFF_OBSERVE_BEGIN");
    let before = backend
        .observe()
        .map_err(|error| at("observe selected BE before handoff", error))?;
    diagnostic!("ZBOOT_HANDOFF_OBSERVE_READY");
    if let Some(expected) = &request.expected_identity {
        let observed = before
            .inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == request.dataset)
            .ok_or_else(|| {
                refuse(format!(
                    "selected BE {} disappeared since menu inventory; type rescan to update the menu",
                    request.dataset
                ))
            })?;
        if &observed.identity != expected {
            return Err(refuse(format!(
                "selected BE {} identity changed since menu inventory; type rescan to update the menu (expected: {}; observed: {})",
                request.dataset,
                identity_summary(expected),
                identity_summary(&observed.identity)
            )));
        }
    }
    readonly_pools(&before)?;
    validate_native_default(&before, request)?;
    let (scope, ownership, saved_line) = eligible(&before, &request.dataset)?;
    if let Some(reason) = crate::mounting::refusal(&before, Some(&request.dataset)) {
        return Err(refuse(reason));
    }
    let identity = backend
        .identity()
        .map_err(|error| at("read the host identity before handoff", error))?;
    host_pools(&before, identity.1.as_ref())?;
    let command_line = kexec_cmdline(&saved_line, identity.0)?;
    let pool = pool_of(&request.dataset).to_owned();
    let guid = before
        .inspection
        .pools
        .iter()
        .find(|p| p.name == pool)
        .map(|p| p.guid.to_string())
        .ok_or_else(|| refuse("selected BE's pool was not observed"))?;
    diagnostic!("ZBOOT_HANDOFF_WORKSPACE_BEGIN");
    let work = backend
        .workspace()
        .map_err(|error| at("prepare RAM workspace", error))?;
    diagnostic!("ZBOOT_HANDOFF_WORKSPACE_READY");
    let mount = work.join("root");
    let mut mounted = false;
    let validate = |backend: &mut dyn RecoveryBackend, stage: &'static str| -> Result<()> {
        let current = backend
            .observe()
            .map_err(|error| at(stage, at("reobserve selected BE", error)))?;
        validate_native_default(&current, request)?;
        revalidate_selection(&current, &request.dataset, &scope, &ownership, &saved_line)
            .map_err(|error| at(stage, at("revalidate selected BE", error)))?;
        if backend
            .identity()
            .map_err(|error| at(stage, at("reread the host identity", error)))?
            != identity
        {
            return Err(at(
                stage,
                refuse("the host identity changed after selection"),
            ));
        }
        host_pools(&current, identity.1.as_ref()).map_err(|error| at(stage, error))?;
        backend
            .prove_ram()
            .map_err(|error| at(stage, at("prove independent RAM runtime", error)))?;
        Ok(())
    };
    // A normal boot writes nothing: every pool stays imported read-only, and
    // stock mounting in the booted system needs no state from zboot.
    let result = (|| {
        validate(backend, "before read-only BE mount")?;
        backend.action(&Action::MountReadonly {
            dataset: request.dataset.clone(),
            target: mount.clone(),
        })?;
        mounted = true;
        backend.verify_mount(&request.dataset, &mount)?;
        diagnostic!("ZBOOT_HANDOFF_STAGE_BEGIN");
        let assets = backend.stage(&mount, &work, request, &command_line)?;
        if request.expected_assets.as_ref().is_some_and(|expected| {
            expected.kernel_sha256 != assets.kernel_sha256
                || expected.initrd_sha256 != assets.initrd_sha256
        }) {
            return Err(refuse("boot assets changed since the listing; run rescan"));
        }
        diagnostic!("ZBOOT_HANDOFF_STAGE_READY");
        validate(backend, "after staging boot assets")?;
        backend.verify_mount(&request.dataset, &mount)?;
        backend.action(&Action::Unmount {
            target: mount.clone(),
        })?;
        mounted = false;
        // The loaded assets are the previously hash-bound copies on
        // independent RAM.
        backend
            .action(&Action::Load { assets })
            .map_err(|error| at("load staged kernel into kexec", error))?;
        validate(backend, "after kexec load")?;
        diagnostic!("ZBOOT_HANDOFF_EXPORT_BEGIN before-kexec-execute");
        backend
            .action(&Action::Export { pool: pool.clone() })
            .map_err(|error| at("export read-only pool before kexec execute", error))?;
        require_exported(
            &backend
                .observe()
                .map_err(|error| at("reobserve pool after final export", error))?,
            &pool,
            &guid,
        )
        .map_err(|error| at("prove final export before kexec execute", error))?;
        diagnostic!("ZBOOT_HANDOFF_EXPORT_READY before-kexec-execute");
        backend
            .prove_ram()
            .map_err(|error| at("prove independent RAM runtime before kexec execute", error))?;
        backend
            .action(&Action::Execute)
            .map_err(|error| at("execute loaded kexec kernel", error))?;
        Err(refuse("kexec returned; a new kernel was not verified"))
    })();
    if mounted && let Err(cleanup) = backend.action(&Action::Unmount { target: mount }) {
        return Err(cleanup_error(
            result,
            "release selected BE mount during handoff cleanup",
            cleanup,
        ));
    }
    if let Err(error) = backend.cleanup(&work) {
        return Err(cleanup_error(result, "remove RAM workspace", error));
    }
    result
}

/// Under an adoption every imported pool must be one of its host's: a pool
/// imported from outside the set (another host's) is never written.
fn host_pools(state: &NativeState, pools: Option<&BTreeSet<String>>) -> Result<()> {
    let Some(pools) = pools else {
        return Ok(());
    };
    if let Some(foreign) = state
        .inspection
        .pools
        .iter()
        .find(|pool| !pools.contains(&pool.guid.to_string()))
    {
        return Err(refuse(format!(
            "pool {} is not one of the adopted host's pools; export it before booting",
            zfs_tools::engine::escape_display(&foreign.name)
        )));
    }
    Ok(())
}

fn require_exported(state: &NativeState, name: &str, guid: &str) -> Result<()> {
    if state
        .inspection
        .pools
        .iter()
        .any(|p| p.name == name || p.guid.to_string() == guid)
    {
        return Err(refuse("selected pool is still imported after export"));
    }
    Ok(())
}

fn revalidate_selection(
    state: &NativeState,
    dataset: &str,
    scope: &SnapshotScope,
    ownership: &Ownership,
    command_line: &str,
) -> Result<()> {
    readonly_pools(state)?;
    scope.revalidate(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
    )?;
    let (_, current_owner, current_command_line) = eligible(state, dataset)?;
    if &current_owner != ownership || current_command_line != command_line {
        return Err(refuse(
            "boot ownership or kernel arguments changed after selection",
        ));
    }
    if let Some(reason) = crate::mounting::refusal(state, Some(dataset)) {
        return Err(refuse(reason));
    }
    Ok(())
}

pub(crate) fn readonly_pools(state: &NativeState) -> Result<()> {
    discovery_imports_allowed(state, false).map(|_| ())
}

/// Discovery cannot run beside an imported writable pool. Ordinary storage
/// commands may skip that discovery and let their selected-pool admission
/// decide independently; boot and menu discovery still require all pools RO.
pub(crate) fn discovery_imports_allowed(
    state: &NativeState,
    allow_existing_writable: bool,
) -> Result<bool> {
    let mut writable = false;
    for pool in &state.inspection.pools {
        let properties = state
            .pool_properties
            .get(&pool.name)
            .ok_or_else(|| refuse("pool properties were not observed"))?;
        let readonly = properties.get("readonly").map(|p| p.value.as_str());
        if properties.get("guid").map(|p| p.value.as_str()) != Some(pool.guid.to_string().as_str())
            || !matches!(readonly, Some("on" | "off"))
            || (readonly == Some("off") && !allow_existing_writable)
        {
            return Err(refuse(format!(
                "menu pool {} is not identity-bound and read-only imported",
                pool.name
            )));
        }
        writable |= readonly == Some("off");
    }
    Ok(!writable)
}

/// `deploy into` an imported pool uses the authenticated UKI adoption.
pub(crate) fn deployment_hostid(pool: zfs_tools::engine::Guid) -> Result<u32> {
    prove_ram()?;
    let (hostid, pools) = hostid_adopt::binding()?;
    match (hostid, pools) {
        (Some(hostid), Some(pools)) if pools.contains(&pool.to_string()) => Ok(hostid),
        _ => Err(refuse(
            "deploy into requires this pool in the adopted host identity",
        )),
    }
}

pub(crate) struct NativeRecovery {
    /// Booting a root tar in RAM (`boot --tar`), not an installed BE.
    ram_root: bool,
    /// Progress lines only with `-v`: the menu's background listing reads
    /// every BE's boot files after each pool event, and its console must
    /// not scroll the SSH lines away.
    quiet: bool,
}
impl NativeRecovery {
    pub(crate) fn new() -> Self {
        Self {
            ram_root: false,
            quiet: false,
        }
    }
    /// For `boot --tar`, whose progress names the tar, not an installed system.
    pub(crate) fn for_ram_root() -> Self {
        Self {
            ram_root: true,
            quiet: false,
        }
    }
    /// For the menu's own listing; failures still surface as errors.
    pub(crate) fn for_listing() -> Self {
        Self {
            ram_root: false,
            quiet: true,
        }
    }
}

/// The progress line for `action`; `ram_root` for a root tar booted in RAM.
fn describe_action(action: &Action, ram_root: bool) -> String {
    match action {
        Action::MountReadonly { dataset, .. } => {
            format!(
                "Reading boot files from {}",
                zfs_tools::engine::escape_display(dataset)
            )
        }
        Action::Unmount { .. } => "Unmounting the temporary boot view".to_owned(),
        Action::Export { pool } => {
            format!("Closing pool {}", zfs_tools::engine::escape_display(pool))
        }
        Action::Load { .. } if ram_root => "Loading the root tar's kernel and initrd".to_owned(),
        Action::Load { .. } => "Loading the installed kernel and initrd".to_owned(),
        Action::Execute if ram_root => "Starting the root tar's system in RAM".to_owned(),
        Action::Execute => "Starting the installed system".to_owned(),
    }
}
impl RecoveryBackend for NativeRecovery {
    fn prove_ram(&mut self) -> Result<()> {
        prove_ram()
    }
    fn observe(&mut self) -> Result<NativeState> {
        Ok(state::observe()?)
    }
    fn revalidate_inventory(
        &mut self,
        binding: &zfs_tools::engine::state::ReadonlyInventoryBinding,
        name: &str,
        _: &SnapshotScope,
        _: &Ownership,
        command_line: &str,
    ) -> Result<()> {
        let observed = state::observe_scope(binding)?;
        let dataset = observed
            .inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == name)
            .ok_or_else(|| refuse("selected inventory root disappeared"))?;
        if !crate::boot_environment::is_root(&observed, dataset) {
            return Err(refuse("selected inventory root shape changed"));
        }
        let extras = observed.dataset_properties[name]
            .get("zboot:cmdline")
            .map_or("", |property| property.value.as_str());
        if compose_cmdline(name, extras)? != command_line {
            return Err(refuse("selected inventory command line changed"));
        }
        Ok(())
    }
    fn identity(&mut self) -> Result<(Option<u32>, Option<BTreeSet<String>>)> {
        hostid_adopt::binding()
    }
    fn workspace(&mut self) -> Result<PathBuf> {
        prove_ram()?;
        let base = Path::new("/run/zboot-recovery");
        match std::fs::DirBuilder::new().mode(0o700).create(base) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(at("create /run/zboot-recovery", error.into())),
        }
        let metadata = std::fs::symlink_metadata(base)
            .map_err(|error| at("inspect /run/zboot-recovery", error.into()))?;
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(refuse(
                "menu workspace is not a private root-owned directory",
            ));
        }
        let work = base.join(uuid::Uuid::new_v4().to_string());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&work)
            .map_err(|error| at("create private RAM workspace", error.into()))?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(work.join("root"))
            .map_err(|error| at("create RAM boot mountpoint", error.into()))?;
        Ok(work)
    }
    fn action(&mut self, action: &Action) -> Result<()> {
        prove_ram()?;
        let description = describe_action(action, self.ram_root);
        let started = std::time::Instant::now();
        if self.quiet {
            diagnostic!("{description}...");
        } else {
            eprintln!("{description}...");
        }
        // The serial controller distinguishes a successful kexec disconnect
        // from a returned command.
        if matches!(action, Action::Execute) {
            diagnostic!("ZBOOT_HANDOFF_ACTION_BEGIN kexec-execute");
        }
        let (program, arguments) = match action {
            Action::MountReadonly { dataset, target } => {
                zfs_tools::engine::validate_dataset_name(dataset)?;
                (
                    "/bin/mount",
                    vec![
                        "-t".into(),
                        "zfs".into(),
                        "-o".into(),
                        "ro,zfsutil".into(),
                        dataset.clone(),
                        path_string(target)?,
                    ],
                )
            }
            Action::Unmount { target } => ("/bin/umount", vec![path_string(target)?]),
            Action::Export { pool } => {
                zfs_tools::engine::validate_dataset_name(pool)?;
                if pool.contains('/') {
                    return Err(refuse("pool export requires an exact pool name"));
                }
                ("/sbin/zpool", vec!["export".into(), pool.clone()])
            }
            Action::Load { assets } => {
                verify_staged(assets)?;
                diagnostic!(
                    "ZBOOT_HANDOFF_LOAD kernel_sha256={} initrd_sha256={}",
                    assets.kernel_sha256,
                    assets.initrd_sha256
                );
                (
                    "/sbin/kexec",
                    vec![
                        "--load".into(),
                        path_string(&assets.kernel)?,
                        format!("--initrd={}", path_string(&assets.initrd)?),
                        format!("--command-line={}", assets.command_line),
                    ],
                )
            }
            Action::Execute => ("/sbin/kexec", vec!["--exec".into()]),
        };
        let output = zfs_tools::engine::native::announced(
            Command::new(program).args(arguments).env("LC_ALL", "C"),
        )
        .output()?;
        if !output.status.success() {
            return Err(RecoveryError::Command {
                program: program.into(),
                detail: format!(
                    "status={}; {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        if self.quiet {
            diagnostic!("Done ({:.1}s).", started.elapsed().as_secs_f64());
        } else {
            eprintln!("Done ({:.1}s).", started.elapsed().as_secs_f64());
        }
        if matches!(action, Action::Execute) {
            diagnostic!("ZBOOT_HANDOFF_ACTION_READY kexec-execute");
        }
        Ok(())
    }
    fn verify_mount(&mut self, dataset: &str, target: &Path) -> Result<()> {
        let mounts = zfs_tools::engine::mountinfo::current()?;
        let matching: Vec<_> = mounts.iter().filter(|m| m.mount_point == target).collect();
        if matching.len() != 1
            || matching[0].filesystem != "zfs"
            || matching[0].source != dataset
            || !matching[0].has_option("ro")
        {
            return Err(refuse(
                "BE mount is not the exact selected dataset mounted read-only",
            ));
        }
        Ok(())
    }
    fn stage(
        &mut self,
        root: &Path,
        work: &Path,
        request: &HandoffRequest,
        command_line: &str,
    ) -> Result<StagedKernel> {
        if let Some(booted) = command_line
            .rsplit_once(" spl.spl_hostid=0x")
            .and_then(|(_, hex)| u32::from_str_radix(hex, 16).ok())
        {
            let installed = crate::hostid::installed(&std::fs::File::open(root)?);
            if let Some(note) = hostid_adopt::disagreement(&request.dataset, &installed, booted) {
                eprintln!("{note}");
            }
        }
        stage_kernel(root, work, request, command_line)
    }
    fn cleanup(&mut self, work: &Path) -> Result<()> {
        // Never recursively delete a directory that could still be a BE mount.
        for name in ["kernel", "initrd"] {
            match std::fs::remove_file(work.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        std::fs::remove_dir(work.join("root"))?;
        std::fs::remove_dir(work)?;
        Ok(())
    }
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| refuse("boot paths must be UTF-8"))
}

const MAX_BOOT_ASSET_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn bound_file(root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(refuse(
            "boot asset selection must be a normalized relative path",
        ));
    }
    let root = std::fs::canonicalize(root)?;
    let resolved = std::fs::canonicalize(root.join(relative))?;
    if !resolved.starts_with(&root) {
        return Err(refuse("boot asset symlink escapes the selected BE"));
    }
    let metadata = std::fs::metadata(&resolved)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BOOT_ASSET_BYTES {
        return Err(refuse(
            "boot asset must be a nonempty regular file no larger than 512 MiB",
        ));
    }
    Ok(resolved)
}

/// Scan `root/boot` for `vmlinuz-<version>` files that have a matching
/// `initrd.img-<version>`, ignoring signature/backup suffixes and enforcing the
/// 4096-entry bound. Returns `(PathBuf("boot/vmlinuz-..."), PathBuf("boot/initrd.img-..."))`.
pub(crate) fn scan_versioned_boot_pairs(
    root: &Path,
    limit_message: &str,
) -> Result<Vec<(PathBuf, PathBuf)>> {
    let boot = root.join("boot");
    let mut pairs = Vec::new();
    for (index, entry) in std::fs::read_dir(boot)?.enumerate() {
        if index >= 4096 {
            return Err(refuse(limit_message));
        }
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(version) = name.strip_prefix("vmlinuz-") else {
            continue;
        };
        if version.is_empty()
            || [".sig", ".dpkg-old", ".dpkg-new", ".bak"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
        {
            continue;
        }
        let initrd = Path::new("boot").join(format!("initrd.img-{version}"));
        if std::fs::symlink_metadata(root.join(&initrd)).is_ok() {
            pairs.push((Path::new("boot").join(&name), initrd));
        }
    }
    Ok(pairs)
}

pub(crate) fn default_assets(root: &Path) -> Result<(PathBuf, PathBuf)> {
    // Respect the BE's selected kernel pointers. Do not guess a newest filename
    // when multiple installed kernels have no explicit default.
    for (kernel, initrd) in [
        ("vmlinuz", "initrd.img"),
        ("boot/vmlinuz", "boot/initrd.img"),
    ] {
        if std::fs::symlink_metadata(root.join(kernel)).is_ok() {
            return Ok((
                bound_file(root, Path::new(kernel))?,
                bound_file(root, Path::new(initrd))?,
            ));
        }
    }
    let mut pairs = Vec::new();
    for (kernel, initrd) in
        scan_versioned_boot_pairs(root, "boot directory exceeds the 4096-entry limit")?
    {
        pairs.push((bound_file(root, &kernel)?, bound_file(root, &initrd)?));
    }
    if pairs.len() != 1 {
        return Err(refuse(
            "no unambiguous kernel/initrd pair; select explicit --kernel and --initrd paths",
        ));
    }
    Ok(pairs.remove(0))
}

/// Callers bound the size: a BE asset through `bound_file`, a RAM boot's
/// initramfs, which holds its root tar, by the RAM check.
pub(crate) fn digest_file(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(refuse("invalid staged boot asset"));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn copy_bound(source: &Path, destination: &Path) -> Result<String> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let before = input.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_BOOT_ASSET_BYTES {
        return Err(refuse("invalid source boot asset"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let written = io::copy(&mut input.take(MAX_BOOT_ASSET_BYTES + 1), &mut output)?;
    if written != before.len() {
        return Err(refuse("boot asset changed length while staging"));
    }
    diagnostic!("ZBOOT_HANDOFF_COPY_SYNC_BEGIN");
    output.sync_all()?;
    diagnostic!("ZBOOT_HANDOFF_COPY_SYNC_READY");
    diagnostic!("ZBOOT_HANDOFF_HASH_BEGIN");
    let digest = digest_file(destination)?;
    if digest_file(source)? != digest {
        return Err(refuse("boot asset changed while staging"));
    }
    diagnostic!("ZBOOT_HANDOFF_HASH_READY");
    Ok(digest)
}

fn selected_assets(root: &Path, request: &HandoffRequest) -> Result<(PathBuf, PathBuf)> {
    let selected = match (&request.kernel, &request.initrd) {
        (Some(kernel), Some(initrd)) => (bound_file(root, kernel)?, bound_file(root, initrd)?),
        (None, None) => default_assets(root)?,
        _ => return Err(refuse("kernel and initrd must be selected together")),
    };
    if matches!(
        request.selection,
        PairSelection::DefaultPair | PairSelection::PoolDefault
    ) && default_assets(root)? != selected
    {
        return Err(refuse(
            "default kernel/initrd pair changed since the listing",
        ));
    }
    Ok(selected)
}

fn stage_kernel(
    root: &Path,
    work: &Path,
    request: &HandoffRequest,
    command_line: &str,
) -> Result<StagedKernel> {
    let (source_kernel, source_initrd) = selected_assets(root, request)?;
    let kernel = work.join("kernel");
    let initrd = work.join("initrd");
    diagnostic!("ZBOOT_HANDOFF_COPY_BEGIN kernel");
    let kernel_sha256 = copy_bound(&source_kernel, &kernel)?;
    diagnostic!("ZBOOT_HANDOFF_COPY_READY kernel");
    diagnostic!("ZBOOT_HANDOFF_COPY_BEGIN initrd");
    let initrd_sha256 = copy_bound(&source_initrd, &initrd)?;
    if selected_assets(root, request)? != (source_kernel, source_initrd) {
        return Err(refuse("selected boot asset paths changed while staging"));
    }
    diagnostic!("ZBOOT_HANDOFF_COPY_READY initrd");
    Ok(StagedKernel {
        kernel,
        initrd,
        kernel_sha256,
        initrd_sha256,
        command_line: command_line.into(),
    })
}

fn verify_staged(assets: &StagedKernel) -> Result<()> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    let mountinfo = std::fs::read("/proc/thread-self/mountinfo")?;
    for path in [&assets.kernel, &assets.initrd] {
        validate_ram_environment(&cmdline, &mountinfo, &std::fs::canonicalize(path)?)?;
    }
    if digest_file(&assets.kernel)? != assets.kernel_sha256
        || digest_file(&assets.initrd)? != assets.initrd_sha256
    {
        return Err(refuse(
            "staged kernel/initrd identity changed before kexec load",
        ));
    }
    Ok(())
}

pub(crate) fn validate_native_default(state: &NativeState, request: &HandoffRequest) -> Result<()> {
    if !matches!(
        request.selection,
        PairSelection::PoolDefault | PairSelection::PoolDefaultKernel
    ) {
        return Ok(());
    }
    let defaults: Vec<_> = state
        .inspection
        .pools
        .iter()
        .filter_map(|pool| pool.bootfs.as_deref())
        .collect();
    let selected = candidates(state)
        .into_iter()
        .find(|candidate| candidate.dataset == request.dataset);
    if defaults.as_slice() != [request.dataset.as_str()]
        || selected.is_none_or(|selected| {
            selected.refusal.is_some()
                || request.expected_identity.as_ref() != Some(&selected.identity)
        })
    {
        return Err(refuse("native boot default changed since the listing"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::menu::inventory::candidates;
    use crate::menu::select::countdown_refusal;
    use crate::menu::{RecoveryError, Result, refuse};
    use std::collections::BTreeMap;
    use zfs_tools::engine::{
        InspectRequest, management,
        native::{self, NativeProperty},
    };

    #[test]
    fn a_ram_root_boot_says_it_starts_the_tar_not_an_installed_system() {
        let assets = StagedKernel {
            kernel: "/k".into(),
            initrd: "/i".into(),
            kernel_sha256: String::new(),
            initrd_sha256: String::new(),
            command_line: String::new(),
        };
        let load = Action::Load { assets };
        assert_eq!(
            describe_action(&load, false),
            "Loading the installed kernel and initrd"
        );
        assert_eq!(
            describe_action(&load, true),
            "Loading the root tar's kernel and initrd"
        );
        assert_eq!(
            describe_action(&Action::Execute, false),
            "Starting the installed system"
        );
        assert_eq!(
            describe_action(&Action::Execute, true),
            "Starting the root tar's system in RAM"
        );
    }

    #[test]
    fn storage_actions_skip_discovery_beside_a_bound_writable_pool_but_boot_stays_strict() {
        let readonly = fixture(true);
        assert!(discovery_imports_allowed(&readonly, false).unwrap());
        assert!(discovery_imports_allowed(&readonly, true).unwrap());
        readonly_pools(&readonly).unwrap();
        let writable = fixture(false);
        assert!(!discovery_imports_allowed(&writable, true).unwrap());
        assert!(discovery_imports_allowed(&writable, false).is_err());
        assert!(readonly_pools(&writable).is_err());
    }

    #[test]
    fn writable_pool_policy_preserves_later_observation_and_identity_refusals() {
        for missing in ["pool properties", "guid", "readonly"] {
            let mut fake = crate::tree::fake::Fake::new();
            fake.readonly_pools.insert("b".into());
            let mut state = fake.state().unwrap();
            if missing == "pool properties" {
                state.pool_properties.remove("b");
            } else {
                state.pool_properties.get_mut("b").unwrap().remove(missing);
            }
            let error = discovery_imports_allowed(&state, true).unwrap_err();
            assert!(
                error.to_string().contains(if missing == "pool properties" {
                    "pool properties were not observed"
                } else {
                    "not identity-bound and read-only imported"
                }),
                "{missing}: {error}"
            );
            assert_eq!(fake.writes, 0);
        }
        for (key, value) in [("guid", "999"), ("readonly", "unknown")] {
            let mut fake = crate::tree::fake::Fake::new();
            fake.readonly_pools.insert("b".into());
            let mut state = fake.state().unwrap();
            state
                .pool_properties
                .get_mut("b")
                .unwrap()
                .get_mut(key)
                .unwrap()
                .value = value.into();
            let error = discovery_imports_allowed(&state, true).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("not identity-bound and read-only imported"),
                "{key}: {error}"
            );
            assert_eq!(fake.writes, 0);
        }
    }

    /// A writable pool skips global discovery. A command that then selects it
    /// is refused at its lock (`pool_access`), before any pool is touched.
    #[test]
    fn a_writable_pool_skips_global_discovery() {
        let mut fake = crate::tree::fake::Fake::new();
        fake.create("a/data");
        fake.create("b/data");
        fake.readonly_pools.insert("b".into());
        let state = fake.state().unwrap();
        assert!(!discovery_imports_allowed(&state, true).unwrap());
        assert_eq!(fake.writes, 0);
    }

    pub(crate) fn fixture(readonly: bool) -> NativeState {
        fixture_with_be_guid(readonly, 3)
    }

    pub(crate) fn fixture_with_be_guid(readonly: bool, be_guid: u64) -> NativeState {
        fixture_rows(
            readonly,
            &[
                ("tank", "none", 1),
                ("tank/ROOT", "none", 2),
                ("tank/ROOT/be", "/", be_guid),
            ],
        )
    }

    /// Filesystems `(name, mountpoint, id)` in pool `tank`, which boots
    /// `tank/ROOT/be`.
    fn fixture_rows(readonly: bool, rows: &[(&str, &str, u64)]) -> NativeState {
        let output = rows.iter().map(|(name,mount,id)| format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t{mount}\t-\t{}\t{}\tno\toff\t{canmount}\t-\toff\t-\t-\t-\t-\n",id+10,id+20,canmount=if *mount=="/" {"noauto"} else {"on"})).collect::<String>();
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    "tank\t100\t1000\t0\t1000\tONLINE\ttank/ROOT/be\n".into()
                } else {
                    output.clone()
                })
            },
        )
        .unwrap();
        let mut dataset_properties: native::PropertyInventory = inspection
            .datasets
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), prop(d.identity.guid.to_string())),
                        ("createtxg".into(), prop(d.identity.createtxg.to_string())),
                        ("objsetid".into(), prop(d.identity.objsetid.to_string())),
                    ]),
                )
            })
            .collect();
        for (name, properties) in &mut dataset_properties {
            for key in &crate::boot_support::tests::FIXTURE_COLUMNS {
                properties.insert(
                    (*key).into(),
                    prop(match *key {
                        "mountpoint" => rows.iter().find(|r| r.0 == name).unwrap().1,
                        "canmount" => "on",
                        "readonly" | "nbmand" => "off",
                        "encryptionroot" | "keylocation" => "-",
                        _ => "on",
                    }),
                );
            }
        }
        NativeState {
            inspection,
            dataset_properties,
            pool_properties: BTreeMap::from([(
                "tank".into(),
                BTreeMap::from([
                    ("guid".into(), prop("100")),
                    ("readonly".into(), prop(if readonly { "on" } else { "off" })),
                ]),
            )]),
        }
    }

    pub(crate) fn fixture_with_extra_bes(extra_bes: &[String], default_be: &str) -> NativeState {
        let mut state = fixture(true);
        let be_properties = state.dataset_properties["tank/ROOT/be"].clone();
        let parent_properties = state.dataset_properties["tank/ROOT"].clone();
        let mut names = BTreeSet::from(["tank".to_owned(), "tank/ROOT".to_owned()]);
        names.insert("tank/ROOT/be".to_owned());
        for be in extra_bes {
            let mut ancestor = String::new();
            for component in be.split('/') {
                if !ancestor.is_empty() {
                    ancestor.push('/');
                }
                ancestor.push_str(component);
                names.insert(ancestor.clone());
            }
        }
        let rows = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let mount = if name == "tank/ROOT/be" || extra_bes.contains(name) {
                    "/"
                } else {
                    "none"
                };
                let id = index as u64 + 1;
                format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t{mount}\t-\t{}\t{}\tno\toff\t{canmount}\t-\toff\t-\t-\t-\t-\n", id + 10, id + 20, canmount = if mount == "/" { "noauto" } else { "on" })
            })
            .collect::<String>();
        let pool_row = format!("tank\t100\t1000\t0\t1000\tONLINE\t{default_be}\n");
        state.inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    pool_row.clone()
                } else {
                    rows.clone()
                })
            },
        )
        .unwrap();
        state.dataset_properties = state
            .inspection
            .datasets
            .iter()
            .map(|dataset| {
                let be = dataset.name == "tank/ROOT/be" || extra_bes.contains(&dataset.name);
                let mut properties = if be {
                    be_properties.clone()
                } else {
                    parent_properties.clone()
                };
                for (key, value) in [
                    ("guid", dataset.identity.guid.to_string()),
                    ("createtxg", dataset.identity.createtxg.to_string()),
                    ("objsetid", dataset.identity.objsetid.to_string()),
                    ("mountpoint", if be { "/" } else { "none" }.into()),
                ] {
                    properties.insert(key.into(), prop(value));
                }
                (dataset.name.clone(), properties)
            })
            .collect();
        state
    }

    #[test]
    fn explicit_boot_refuses_guided_restore_workspace_be() {
        let id = "0123456789abcdef";
        let staged = format!("tank/zboot-restore-{id}/layout/ROOT/be1");
        let legitimate = format!("tank/ROOT/zboot-restore-{id}");
        let state = fixture_with_extra_bes(&[staged.clone(), legitimate.clone()], "tank/ROOT/be");

        assert!(
            eligible(&state, &staged)
                .unwrap_err()
                .to_string()
                .contains("guided restore workspace cannot boot")
        );
        assert!(eligible(&state, &legitimate).is_ok());
    }

    #[test]
    fn frozen_secondary_reports_boot_role_after_pair_validation() {
        let mut state = fixture(true);
        let rows = [
            ("tank", "none", 1, "off", "on"),
            ("tank/ROOT", "none", 2, "off", "on"),
            ("tank/ROOT/be", "/", 3, "off", "on"),
            ("tank/ROOT/secondary", "/", 4, "on", "noauto"),
        ];
        let output = rows.iter().map(|(name,mount,id,readonly,canmount)| format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t{mount}\t-\t{}\t{}\tno\t{readonly}\t{canmount}\t-\toff\t-\t-\t-\t-\n",id+10,id+20)).collect::<String>();
        state.inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    "tank\t100\t1000\t0\t1000\tONLINE\ttank/ROOT/be\n".into()
                } else {
                    output.clone()
                })
            },
        )
        .unwrap();
        let endpoint = |name: &str| management::Endpoint {
            name: name.into(),
            identity: state
                .inspection
                .datasets
                .iter()
                .find(|dataset| dataset.name == name)
                .unwrap()
                .identity
                .clone(),
        };
        let record = management::PairRecord {
            schema_version: 1,
            pair_id: uuid::Uuid::new_v4().to_string(),
            endpoint: endpoint("tank/ROOT/be"),
            peer: endpoint("tank/ROOT/secondary"),
            role: management::Role::Primary,
        };
        let mut secondary = state.dataset_properties["tank/ROOT/be"].clone();
        for (key, value) in [
            ("guid", record.peer.identity.guid.to_string()),
            ("createtxg", record.peer.identity.createtxg.to_string()),
            ("objsetid", record.peer.identity.objsetid.to_string()),
            ("readonly", "on".into()),
            ("canmount", "noauto".into()),
            (
                management::PAIR_PROPERTY,
                record.counterpart().encode().unwrap(),
            ),
        ] {
            secondary.insert(key.into(), prop(value));
        }
        state
            .dataset_properties
            .insert(record.peer.name.clone(), secondary);
        state
            .dataset_properties
            .get_mut(&record.endpoint.name)
            .unwrap()
            .insert(
                management::PAIR_PROPERTY.into(),
                prop(record.encode().unwrap()),
            );

        assert!(matches!(
            eligible(&state, &record.endpoint.name).unwrap().1,
            Ownership::Primary { .. }
        ));
        let secondary_refusal = eligible(&state, &record.peer.name).unwrap_err().to_string();
        assert_eq!(
            secondary_refusal,
            "secondary cannot boot as a writable environment"
        );
        // A malformed peer must still fail pair validation, not masquerade as
        // a valid secondary with the friendlier boot-role refusal.
        state
            .dataset_properties
            .get_mut(&record.endpoint.name)
            .unwrap()
            .insert(management::PAIR_PROPERTY.into(), prop("not a pair record"));
        for dataset in [&record.endpoint.name, &record.peer.name] {
            let refusal = eligible(&state, dataset).unwrap_err().to_string();
            assert!(refusal.contains("invalid pair property"), "{refusal}");
            assert_ne!(refusal, secondary_refusal);
        }
    }

    pub(crate) fn prop(value: impl ToString) -> NativeProperty {
        NativeProperty {
            value: value.to_string(),
            source: "local".into(),
        }
    }
    pub(crate) fn empty() -> NativeState {
        NativeState {
            inspection: native::inspect_with(
                &InspectRequest::new(vec![], false).unwrap(),
                |_, _| Ok(String::new()),
            )
            .unwrap(),
            dataset_properties: BTreeMap::new(),
            pool_properties: BTreeMap::new(),
        }
    }
    pub(crate) struct Scratch(pub(crate) PathBuf);
    impl Scratch {
        pub(crate) fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("zboot-recovery-test-{}", uuid::Uuid::new_v4()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    pub(crate) struct Fake {
        pub(crate) state: NativeState,
        pub(crate) actions: Vec<Action>,
        pub(crate) ram: bool,
        pub(crate) fail_workspace: bool,
        pub(crate) fail_export: bool,
        pub(crate) fail_export_at: Option<usize>,
        pub(crate) fail_unmount: bool,
        pub(crate) fail_execute: bool,
        pub(crate) fail_observe_at: Option<usize>,
        pub(crate) fail_cleanup: bool,
        pub(crate) drift: bool,
        pub(crate) observations: usize,
        pub(crate) exports: usize,
        pub(crate) identity: (Option<u32>, Option<BTreeSet<String>>),
        pub(crate) asset_root: Option<PathBuf>,
    }
    impl Fake {
        pub(crate) fn new() -> Self {
            Self {
                state: fixture(true),
                actions: vec![],
                ram: true,
                fail_workspace: false,
                fail_export: false,
                fail_export_at: None,
                fail_unmount: false,
                fail_execute: false,
                fail_observe_at: None,
                fail_cleanup: false,
                drift: false,
                observations: 0,
                exports: 0,
                identity: (Some(0x0174627a), None),
                asset_root: None,
            }
        }
    }
    impl RecoveryBackend for Fake {
        fn prove_ram(&mut self) -> Result<()> {
            if self.ram {
                Ok(())
            } else {
                Err(refuse("not RAM"))
            }
        }
        fn observe(&mut self) -> Result<NativeState> {
            self.observations += 1;
            if self.fail_observe_at == Some(self.observations) {
                return Err(io::Error::from_raw_os_error(libc::EROFS).into());
            }
            let mut state = self.state.clone();
            if self.drift && self.observations >= 3 {
                state
                    .dataset_properties
                    .get_mut("tank/ROOT/be")
                    .unwrap()
                    .insert("zboot:pending".into(), prop("new"));
            }
            Ok(state)
        }
        fn identity(&mut self) -> Result<(Option<u32>, Option<BTreeSet<String>>)> {
            Ok(self.identity.clone())
        }
        fn workspace(&mut self) -> Result<PathBuf> {
            if self.fail_workspace {
                return Err(io::Error::from_raw_os_error(libc::EROFS).into());
            }
            Ok("/run/fake".into())
        }
        fn action(&mut self, action: &Action) -> Result<()> {
            self.actions.push(action.clone());
            if self.fail_unmount && matches!(action, Action::Unmount { .. }) {
                return Err(refuse("busy mount"));
            }
            if self.fail_execute && matches!(action, Action::Execute) {
                return Err(io::Error::from_raw_os_error(libc::EROFS).into());
            }
            if matches!(action, Action::Export { .. }) {
                self.exports += 1;
                if self.fail_export || self.fail_export_at == Some(self.exports) {
                    return Err(refuse("busy"));
                }
                self.state = empty();
            }
            Ok(())
        }
        fn verify_mount(&mut self, _: &str, _: &Path) -> Result<()> {
            Ok(())
        }
        fn stage(
            &mut self,
            _: &Path,
            _: &Path,
            request: &HandoffRequest,
            command_line: &str,
        ) -> Result<StagedKernel> {
            if let Some(root) = &self.asset_root {
                selected_assets(root, request)?;
            }
            Ok(StagedKernel {
                kernel: "/run/kernel".into(),
                initrd: "/run/initrd".into(),
                kernel_sha256: "a".repeat(64),
                initrd_sha256: "b".repeat(64),
                command_line: command_line.into(),
            })
        }
        fn cleanup(&mut self, _: &Path) -> Result<()> {
            if self.fail_cleanup {
                Err(refuse("workspace cleanup denied"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn menu_handoff_rejects_missing_dataset_before_any_action() {
        let mut backend = Fake::new();
        let expected = backend
            .state
            .inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == "tank/ROOT/be")
            .unwrap()
            .identity
            .clone();
        backend.state = empty();
        let error = handoff_with(
            &HandoffRequest {
                selection: PairSelection::Explicit,
                expected_assets: None,
                dataset: "tank/ROOT/be".into(),
                kernel: Some("boot/vmlinuz-1".into()),
                initrd: Some("boot/initrd.img-1".into()),
                expected_identity: Some(expected),
            },
            &mut backend,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("selected BE tank/ROOT/be disappeared"),
            "{error}"
        );
        assert!(error.contains("type rescan"), "{error}");
        assert!(backend.actions.is_empty());
    }

    #[test]
    fn menu_handoff_rejects_each_changed_identity_field_before_any_action() {
        let original = Fake::new()
            .state
            .inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == "tank/ROOT/be")
            .unwrap()
            .identity
            .clone();
        for field in ["pool_guid", "guid", "createtxg", "objsetid"] {
            let mut backend = Fake::new();
            let mut expected = original.clone();
            match field {
                "pool_guid" => {
                    expected.pool_guid = zfs_tools::engine::Guid::new(expected.pool_guid.get() + 1)
                }
                "guid" => expected.guid = zfs_tools::engine::Guid::new(expected.guid.get() + 1),
                "createtxg" => {
                    expected.createtxg = zfs_tools::engine::Txg::new(expected.createtxg.get() + 1)
                }
                "objsetid" => {
                    expected.objsetid =
                        zfs_tools::engine::ObjsetId::new(expected.objsetid.get() + 1)
                }
                _ => unreachable!(),
            }
            let error = handoff_with(
                &HandoffRequest {
                    selection: PairSelection::Explicit,
                    expected_assets: None,
                    dataset: "tank/ROOT/be".into(),
                    kernel: Some("boot/vmlinuz-1".into()),
                    initrd: Some("boot/initrd.img-1".into()),
                    expected_identity: Some(expected.clone()),
                },
                &mut backend,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("identity changed since menu inventory"),
                "{error}"
            );
            assert!(error.contains("type rescan"), "{error}");
            assert!(
                error.contains(&format!("expected: {}", identity_summary(&expected))),
                "{error}"
            );
            assert!(
                error.contains(&format!("observed: {}", identity_summary(&original))),
                "{error}"
            );
            assert!(backend.actions.is_empty(), "{field}");
        }
    }

    #[test]
    fn menu_handoff_reports_expected_and_observed_replacement_identities() {
        let mut backend = Fake::new();
        let expected = backend
            .state
            .inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == "tank/ROOT/be")
            .unwrap()
            .identity
            .clone();
        backend.state = fixture_with_be_guid(true, 4);
        let observed = backend
            .state
            .inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == "tank/ROOT/be")
            .unwrap()
            .identity
            .clone();
        assert_ne!(expected, observed);
        let error = handoff_with(
            &HandoffRequest {
                selection: PairSelection::Explicit,
                expected_assets: None,
                dataset: "tank/ROOT/be".into(),
                kernel: Some("boot/vmlinuz-1".into()),
                initrd: Some("boot/initrd.img-1".into()),
                expected_identity: Some(expected.clone()),
            },
            &mut backend,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(&format!("expected: {}", identity_summary(&expected))),
            "{error}"
        );
        assert!(
            error.contains(&format!("observed: {}", identity_summary(&observed))),
            "{error}"
        );
        assert!(backend.actions.is_empty());
    }

    pub(crate) fn request() -> HandoffRequest {
        HandoffRequest {
            selection: PairSelection::Explicit,
            expected_assets: None,
            dataset: "tank/ROOT/be".into(),
            kernel: None,
            initrd: None,
            expected_identity: None,
        }
    }
    #[test]
    fn ram_proof_rejects_overlay_disk_runtime_and_conflicting_markers() {
        let root = "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / /run rw - tmpfs tmpfs rw\n";
        assert!(
            validate_ram_environment("zboot.recovery=1", root, Path::new("/usr/bin/zboot")).is_ok()
        );
        // The marker alone names the UKI; a failed RAM proof never makes it a host.
        assert!(has_uki_marker("quiet zboot.recovery=1"));
        assert!(has_uki_marker("zboot.recovery=1 zboot.recovery=1"));
        assert!(!has_uki_marker("root=ZFS=rpool/ROOT/be quiet"));
        for marker in ["", "zboot.recovery=0", "zboot.recovery=1 zboot.recovery=1"] {
            assert!(validate_ram_environment(marker, root, Path::new("/usr/bin/zboot")).is_err());
        }
        assert!(
            validate_ram_environment(
                "zboot.recovery=1",
                &root.replace("rootfs rootfs", "overlay overlay"),
                Path::new("/usr/bin/zboot")
            )
            .is_err()
        );
        let disk = format!("{root}3 1 0:3 / /usr/lib rw - zfs tank/lib rw\n");
        assert!(
            validate_ram_environment("zboot.recovery=1", &disk, Path::new("/usr/bin/zboot"))
                .is_err()
        );
        let be = format!("{root}3 1 0:3 / /run/work/root ro - zfs tank/be ro\n");
        assert!(
            validate_ram_environment("zboot.recovery=1", &be, Path::new("/run/work/kernel"))
                .is_ok()
        );
        assert!(
            validate_ram_environment("zboot.recovery=1", &be, Path::new("/run/work/root/kernel"))
                .is_err()
        );
        let escape = format!("{root}3 1 0:3 / /bad\\777 rw - tmpfs tmpfs rw\n");
        assert!(
            validate_ram_environment("zboot.recovery=1", &escape, Path::new("/usr/bin/zboot"))
                .is_err()
        );
    }
    #[test]
    fn saved_cmdline_cannot_override_root_or_recovery_contract() {
        for extra in [
            "root=ZFS=other/be",
            "rw",
            "rdinit=/bin/sh",
            "init=/bin/sh",
            "boot=other",
            "zfs.force=1",
            "zfs_force=1",
            "zfsforce=1",
            "spl.spl_hostid=0x01020304",
            "spl_hostid=1",
            "zboot.recovery=1",
            "console=\"ttyS0\"",
        ] {
            assert!(compose_cmdline("tank/ROOT/be", extra).is_err(), "{extra}");
        }
        assert_eq!(
            compose_cmdline("tank/ROOT/be", "console=ttyS0 quiet").unwrap(),
            "boot=zfs root=ZFS=tank/ROOT/be ro console=ttyS0 quiet"
        );
    }
    #[test]
    fn one_composer_gives_every_handoff_exactly_one_reviewed_hostid() {
        let be = compose_cmdline("tank/ROOT/be", "quiet").unwrap();
        assert_eq!(
            kexec_cmdline(&be, Some(0x0174627a)).unwrap(),
            "boot=zfs root=ZFS=tank/ROOT/be ro quiet spl.spl_hostid=0x0174627a"
        );
        // A line that names no boot environment gets the same treatment.
        assert_eq!(
            kexec_cmdline("console=ttyS0 zboot.recovery=rescue\n", Some(0)).unwrap(),
            "console=ttyS0 zboot.recovery=rescue spl.spl_hostid=0x00000000"
        );
        for shipped in [
            "console=ttyS0 spl.spl_hostid=0x01020304",
            "spl_hostid=5",
            "zfs.force=1",
            "zfs_force=yes",
            "zfsforce",
        ] {
            assert!(kexec_cmdline(shipped, Some(1)).is_err(), "{shipped}");
        }
        assert!(kexec_cmdline(&"x".repeat(2030), Some(1)).is_err());
        let line = kexec_cmdline(&be, Some(7)).unwrap();
        assert_eq!(line.matches("spl.spl_hostid=").count(), 1);
    }
    #[test]
    fn a_handoff_without_an_adopted_hostid_passes_none() {
        let mut backend = Fake::new();
        backend.identity = (None, None);
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(error.to_string().contains("kexec returned"), "{error}");
        let loaded = backend
            .actions
            .iter()
            .find_map(|action| match action {
                Action::Load { assets } => Some(assets.command_line.as_str()),
                _ => None,
            })
            .unwrap();
        assert!(loaded.contains("root=ZFS=tank/ROOT/be"), "{loaded}");
        assert!(!loaded.contains("spl.spl_hostid="), "{loaded}");
        assert_eq!(kexec_cmdline("quiet\n", None).unwrap(), "quiet");
        assert!(kexec_cmdline("spl.spl_hostid=0x1", None).is_err());
        assert!(kexec_cmdline(&"x".repeat(2048), None).is_err());
    }

    #[test]
    fn a_handoff_boots_with_the_running_hostid_and_refuses_another_hosts_pool() {
        let mut backend = Fake::new();
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(error.to_string().contains("kexec returned"), "{error}");
        let loaded = backend
            .actions
            .iter()
            .find_map(|action| match action {
                Action::Load { assets } => Some(assets.command_line.clone()),
                _ => None,
            })
            .unwrap();
        assert!(loaded.ends_with(" spl.spl_hostid=0x0174627a"), "{loaded}");
        let guid = Fake::new().state.inspection.pools[0].guid.to_string();
        let mut bound = Fake::new();
        bound.identity.1 = Some([guid].into());
        assert!(
            handoff_with(&request(), &mut bound)
                .unwrap_err()
                .to_string()
                .contains("kexec returned")
        );
        let mut foreign = Fake::new();
        foreign.identity.1 = Some(["99".to_string()].into());
        let error = handoff_with(&request(), &mut foreign).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not one of the adopted host's pools"),
            "{error}"
        );
        assert!(foreign.actions.is_empty(), "{:?}", foreign.actions);
    }
    #[test]
    fn handoff_writer_refusal_precedes_any_pool_transition() {
        let mut backend = Fake::new();
        let error = handoff_guarded(&request(), &mut backend, || {
            Err::<(), _>(refuse("writer unavailable"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("writer unavailable"));
        assert!(backend.actions.is_empty());
    }

    #[test]
    fn the_handoff_refuses_a_be_that_changed_since_the_listing() {
        for changed in ["kernel", "initrd"] {
            let mut backend = Fake::new();
            let mut request = request();
            request.expected_assets = Some(AssetHashes {
                kernel_sha256: if changed == "kernel" { "c" } else { "a" }.repeat(64),
                initrd_sha256: if changed == "initrd" { "d" } else { "b" }.repeat(64),
            });
            let error = handoff_with(&request, &mut backend).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("assets changed since the listing"),
                "{error}"
            );
            assert!(matches!(
                backend.actions.as_slice(),
                [Action::MountReadonly { .. }, Action::Unmount { .. }]
            ));
        }
    }

    #[test]
    fn handoff_orders_staging_unmount_load_export_and_never_claims_return_success() {
        let mut backend = Fake::new();
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(error.to_string().contains("kexec returned"), "{error}");
        assert!(
            matches!(backend.actions.as_slice(),[Action::MountReadonly{..},Action::Unmount{..},Action::Load{..},Action::Export{pool},Action::Execute] if pool=="tank"),
            "{:?}",
            backend.actions
        );
    }
    /// A BE root `be` with a child, beside BE `b` with its own; every
    /// dataset `noauto` except `be/var` when `on_child`.
    pub(crate) fn two_bes(on_child: bool) -> NativeState {
        two_bes_on(if on_child { &["tank/ROOT/be/var"] } else { &[] })
    }
    /// The same, with exactly the datasets in `on` set `canmount=on`.
    pub(crate) fn two_bes_on(on: &[&str]) -> NativeState {
        let mut state = fixture_rows(
            true,
            &[
                ("tank", "none", 1),
                ("tank/ROOT", "none", 2),
                ("tank/ROOT/be", "/", 3),
                ("tank/ROOT/be/var", "/var", 4),
                ("tank/ROOT/b", "/", 5),
                ("tank/ROOT/b/var", "/var", 6),
            ],
        );
        for dataset in &mut state.inspection.datasets {
            let (canmount, native) = if on.contains(&dataset.name.as_str()) {
                (zfs_tools::engine::CanMount::On, "on")
            } else {
                (zfs_tools::engine::CanMount::NoAuto, "noauto")
            };
            dataset.canmount = Some(canmount);
            state
                .dataset_properties
                .get_mut(&dataset.name)
                .unwrap()
                .insert("canmount".into(), prop(native));
        }
        state
    }
    #[test]
    fn a_normal_handoff_never_opens_a_pool_writable() {
        for selected in ["tank/ROOT/be", "tank/ROOT/b"] {
            let mut backend = Fake::new();
            backend.state = two_bes(false);
            let request = HandoffRequest {
                selection: PairSelection::Explicit,
                expected_assets: None,
                dataset: selected.into(),
                ..request()
            };
            let error = handoff_with(&request, &mut backend).unwrap_err();
            assert!(error.to_string().contains("kexec returned"), "{error}");
            // Only read-only mounts and exports: no import at all, so no
            // pool is ever reopened, and nothing is written into the BE.
            assert!(
                matches!(backend.actions.as_slice(),[Action::MountReadonly{dataset,..},Action::Unmount{..},Action::Load{..},Action::Export{..},Action::Execute] if dataset==selected),
                "{:?}",
                backend.actions
            );
        }
        // A pool imported writable is refused before any action.
        let mut backend = Fake::new();
        backend.state = fixture(false);
        assert!(handoff_with(&request(), &mut backend).is_err());
        assert!(backend.actions.is_empty());
    }
    #[test]
    fn the_uki_refuses_to_boot_b_while_a_has_a_canmount_on_dataset_and_still_boots_a() {
        let state = two_bes(true);
        let refusal = |name: &str| {
            candidates(&state)
                .into_iter()
                .find(|c| c.dataset == name)
                .unwrap()
                .refusal
        };
        // B is refused, naming A's child; A, which owns it, is not.
        let b = refusal("tank/ROOT/b").expect("B is refused");
        assert!(b.contains("tank/ROOT/be/var"), "{b}");
        assert_eq!(refusal("tank/ROOT/be"), None);
        assert_eq!(
            crate::mounting::automount_in_boot_environments(&state),
            vec!["tank/ROOT/be/var"]
        );
        // No countdown, even for A, the default.
        let reason = countdown_refusal(&state, None).expect("no countdown");
        assert!(reason.contains("tank/ROOT/be/var"), "{reason}");
        assert_eq!(
            countdown_refusal(&state, Some("hibernation".into())).as_deref(),
            Some("hibernation")
        );
        // Booting B is refused before any action; A boots.
        let mut backend = Fake::new();
        backend.state = state.clone();
        let error = handoff_with(
            &HandoffRequest {
                selection: PairSelection::Explicit,
                expected_assets: None,
                dataset: "tank/ROOT/b".into(),
                ..request()
            },
            &mut backend,
        )
        .unwrap_err();
        assert!(error.to_string().contains("tank/ROOT/be/var"), "{error}");
        assert!(backend.actions.is_empty(), "{:?}", backend.actions);
        let mut backend = Fake::new();
        backend.state = state;
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(error.to_string().contains("kexec returned"), "{error}");
        assert!(matches!(backend.actions.last(), Some(Action::Execute)));
        // Once A's child is `noauto`, B boots and the countdown runs.
        let fixed = two_bes(false);
        assert_eq!(countdown_refusal(&fixed, None), None);
        assert!(candidates(&fixed).iter().all(|c| c.refusal.is_none()));
    }
    pub(crate) fn boot(state: &NativeState, dataset: &str) -> (RecoveryError, Vec<Action>) {
        let mut backend = Fake::new();
        backend.state = state.clone();
        let request = HandoffRequest {
            selection: PairSelection::Explicit,
            expected_assets: None,
            dataset: dataset.into(),
            ..request()
        };
        let error = handoff_with(&request, &mut backend).unwrap_err();
        (error, backend.actions)
    }
    fn refusal_of(state: &NativeState, name: &str) -> Option<String> {
        candidates(state)
            .into_iter()
            .find(|c| c.dataset == name)
            .unwrap()
            .refusal
    }
    #[test]
    fn a_boot_environment_root_that_is_canmount_on_blocks_every_other_one() {
        // An inactive root at `/` with canmount=on would mount over the
        // running root, so it counts like a child.
        let state = two_bes_on(&["tank/ROOT/be"]);
        assert_eq!(
            crate::mounting::automount_in_boot_environments(&state),
            vec!["tank/ROOT/be"]
        );
        let b = refusal_of(&state, "tank/ROOT/b").expect("B is refused");
        assert!(b.contains("`zfs set canmount=noauto tank/ROOT/be`"), "{b}");
        let (error, actions) = boot(&state, "tank/ROOT/b");
        assert!(error.to_string().contains("tank/ROOT/be"), "{error}");
        assert!(actions.is_empty(), "{actions:?}");
        assert!(countdown_refusal(&state, None).is_some());
        // The host-wide check does not block the owner itself.
        assert_eq!(crate::mounting::refusal(&state, Some("tank/ROOT/be")), None);
    }
    #[test]
    fn two_bes_with_canmount_on_children_block_each_other_and_the_refusal_says_the_fix() {
        let state = two_bes_on(&["tank/ROOT/be/var", "tank/ROOT/b/var"]);
        for (selected, other) in [
            ("tank/ROOT/be", "tank/ROOT/b/var"),
            ("tank/ROOT/b", "tank/ROOT/be/var"),
        ] {
            let fix = format!("`zfs set canmount=noauto {other}`");
            let listed = refusal_of(&state, selected).expect("refused");
            assert!(listed.contains(&fix), "{listed}");
            // Its own child is not what blocks it.
            assert!(!listed.contains(&format!("{selected}/var")), "{listed}");
            let (error, actions) = boot(&state, selected);
            assert!(error.to_string().contains(&fix), "{error}");
            assert!(actions.is_empty(), "{actions:?}");
        }
        // The countdown reason names both commands.
        let reason = countdown_refusal(&state, None).unwrap();
        for name in ["tank/ROOT/be/var", "tank/ROOT/b/var"] {
            assert!(
                reason.contains(&format!("`zfs set canmount=noauto {name}`")),
                "{reason}"
            );
        }
        // Fixing one from the Menu shell lets its sibling's owner boot.
        let state = two_bes_on(&["tank/ROOT/b/var"]);
        assert_eq!(refusal_of(&state, "tank/ROOT/b"), None);
        let (error, _) = boot(&state, "tank/ROOT/b");
        assert!(error.to_string().contains("kexec returned"), "{error}");
    }
    #[test]
    fn handoff_reports_workspace_failure_without_losing_os_error() {
        let mut backend = Fake::new();
        backend.fail_workspace = true;
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(
            error.to_string().starts_with("prepare RAM workspace: "),
            "{error}"
        );
        assert!(error.to_string().contains("os error 30"), "{error}");
        assert!(backend.actions.is_empty());
        assert!(error_sources_include_erofs(&error));
    }
    #[test]
    fn handoff_identifies_final_export_and_reobservation_failures() {
        let mut backend = Fake::new();
        backend.fail_export_at = Some(1);
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("export read-only pool before kexec execute: busy"),
            "{error}"
        );
        assert!(!backend.actions.contains(&Action::Execute));

        let mut backend = Fake::new();
        backend.fail_observe_at = Some(5);
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("reobserve pool after final export: "),
            "{error}"
        );
        assert!(error_sources_include_erofs(&error));
        assert!(!backend.actions.contains(&Action::Execute));

        let mut backend = Fake::new();
        backend.fail_execute = true;
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("execute loaded kexec kernel: "),
            "{error}"
        );
        assert!(error_sources_include_erofs(&error));
        assert!(matches!(backend.actions.last(), Some(Action::Execute)));
    }
    #[test]
    fn handoff_preserves_primary_error_when_workspace_or_unmount_cleanup_fails() {
        let mut backend = Fake::new();
        backend.fail_observe_at = Some(5);
        backend.fail_cleanup = true;
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("handoff failed (reobserve pool after final export: "),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("remove RAM workspace failed: workspace cleanup denied"),
            "{error}"
        );
        assert!(error_sources_include_erofs(&error));

        let mut backend = Fake::new();
        backend.fail_unmount = true;
        let error = handoff_with(&request(), &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("handoff failed (busy mount)"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("release selected BE mount during handoff cleanup failed: busy mount"),
            "{error}"
        );
        assert!(!backend.actions.contains(&Action::Execute));
    }
    pub(crate) fn error_sources_include_erofs(error: &RecoveryError) -> bool {
        let mut source: &(dyn std::error::Error + 'static) = error;
        loop {
            if source
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(libc::EROFS))
            {
                return true;
            }
            let Some(next) = source.source() else {
                return false;
            };
            source = next;
        }
    }
    #[test]
    fn ram_readonly_and_pending_fail_before_effects_export_failure_blocks_execute() {
        for case in 0..3 {
            let mut backend = Fake::new();
            match case {
                0 => backend.ram = false,
                1 => backend.state = fixture(false),
                _ => {
                    backend
                        .state
                        .dataset_properties
                        .get_mut("tank/ROOT/be")
                        .unwrap()
                        .insert("zboot:pending".into(), prop("operation"));
                }
            }
            assert!(handoff_with(&request(), &mut backend).is_err());
            assert!(backend.actions.is_empty());
        }
        let mut backend = Fake::new();
        backend.fail_export = true;
        assert!(handoff_with(&request(), &mut backend).is_err());
        assert!(!backend.actions.contains(&Action::Execute));
        let mut backend = Fake::new();
        backend.drift = true;
        assert!(handoff_with(&request(), &mut backend).is_err());
        assert!(matches!(
            backend.actions.as_slice(),
            [Action::MountReadonly { .. }, Action::Unmount { .. }]
        ));
    }
    #[test]
    fn assets_reject_escape_and_ambiguous_pairs_and_hash_the_copied_bytes() {
        let scratch = Scratch::new();
        let root = scratch.0.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("boot")).unwrap();
        for version in ["1", "2"] {
            std::fs::write(root.join(format!("boot/vmlinuz-{version}")), b"kernel").unwrap();
            std::fs::write(root.join(format!("boot/initrd.img-{version}")), b"initrd").unwrap();
        }
        assert!(default_assets(&root).is_err());
        std::os::unix::fs::symlink("boot/vmlinuz-1", root.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink("boot/initrd.img-1", root.join("initrd.img")).unwrap();
        let staged = stage_kernel(
            &root,
            &scratch.0,
            &request(),
            "boot=zfs root=ZFS=tank/ROOT/be ro",
        )
        .unwrap();
        assert_eq!(
            staged.kernel_sha256,
            digest_file(&root.join("boot/vmlinuz-1")).unwrap()
        );
        std::fs::write(scratch.0.join("outside"), b"outside").unwrap();
        std::os::unix::fs::symlink("../outside", root.join("escape")).unwrap();
        assert!(bound_file(&root, Path::new("escape")).is_err());
        assert!(bound_file(&root, Path::new("../outside")).is_err());
    }
}
