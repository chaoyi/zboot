//! `zboot deploy DISK`: erase the disk with the `wipe` chain, then provision
//! the bare disk with the [`request`](mod@super::request) engine, under one
//! confirmation.
//!
//! The plan is a whole-disk erase review plus a deploy preflight made against
//! the disk as it is now; the token binds both (the erase scope and method,
//! the selection, the image, root tar and overlay digests, an external ESP's exact write
//! set and the layout sizes). After the erase the engine plans again on the
//! bare disk, and that review must bind the same selection before anything is
//! written. Nothing is recorded across the two steps: there is no surviving
//! pool, so an interrupted deploy is rerun, which plans and confirms afresh.
use super::{
    CoreOutcome, CoreReview, refuse,
    request::{self, Boot, DeployRequest, Purpose, Swap},
};
use crate::{
    device::{self, DiskIdentity, DiskReview, WipeOutcome},
    esp::EspReview,
};
use serde::Serialize;
use std::{io, path::PathBuf};

/// The command line, before any observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Disk { disk: String },
    Image { file: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Args {
    pub target: Target,
    /// The standalone zboot UKI selected by `--efi FILE`.
    pub efi: PathBuf,
    /// `--tar TAR`; `None` is `--empty`.
    pub factory: Option<PathBuf>,
    /// `--overlay DIR|TAR`, the host overlay; needs `--tar`.
    pub overlay: Vec<PathBuf>,
    pub portable: bool,
    pub be: Option<String>,
    pub pool: Option<String>,
    pub hostid: Option<String>,
    pub hostname: Option<String>,
    pub esp: Option<u64>,
    pub esp_partition: Option<String>,
    pub swap: Option<u64>,
}

pub const DEFAULT_POOL: &str = "rpool";
pub const DEFAULT_BE: &str = "default";
pub const DEFAULT_ESP_BYTES: u64 = 1 << 30;

/// What `deploy` shows and the token binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    /// The erase of the whole disk, with its current layout and method.
    pub wipe: DiskReview,
    /// Pools exported after confirmation, retained even in post-export previews.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<device::DiskScope>,
    /// The engine's preflight on the current disk; the review it applies is
    /// made again after the erase and must bind the same selection.
    pub deploy: CoreReview,
    /// The boot defaults (`bootfs`) other imported pools already name, which
    /// deploy leaves alone. Shown only; the token does not bind them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub other_defaults: Vec<String>,
}

/// What a completed deploy returns: the erase, the review the engine applied
/// and its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub wipe: WipeOutcome,
    pub review: CoreReview,
    pub outcome: CoreOutcome,
}

/// The native effects and observations, faked in tests.
pub trait Backend {
    fn wipe_plan(&mut self, disk: &str) -> io::Result<DiskReview>;
    /// The running host's hostid: the effective SPL hostid (0: none).
    fn running_hostid(&mut self) -> io::Result<u32>;
    /// A fresh private directory for one engine attempt and its hook logs.
    fn attempt(&mut self) -> io::Result<PathBuf>;
    /// Remove an attempt directory that recorded nothing.
    fn release(&mut self, attempt: &std::path::Path);
    fn deploy_plan(&mut self, request: &DeployRequest) -> io::Result<CoreReview>;
    /// Reopen the reviewed loader immediately before dispatching erase.
    fn verify_loader(&mut self, loader: &crate::loader::EfiFile) -> io::Result<()>;
    fn wipe(&mut self, review: &DiskReview) -> io::Result<WipeOutcome>;
    fn deploy_apply(&mut self, review: &CoreReview) -> io::Result<CoreOutcome>;
    /// The `bootfs` every imported pool names now.
    fn boot_defaults(&mut self) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// The selection `args` makes, with the attempt directory `attempt`.
/// Without `--hostid` the BE takes the running host's (effective) hostid, so
/// the disks of one host share it; a host without one gets a new random hostid.
pub fn request(args: &Args, running_hostid: u32, attempt: PathBuf) -> io::Result<DeployRequest> {
    if args.portable
        && (args.hostid.is_some()
            || args.swap.is_some()
            || args.esp_partition.is_some()
            || args.factory.is_none())
    {
        return Err(refuse(
            "--portable refuses --hostid, --swap, --esp-partition and --empty",
        ));
    }
    if matches!(args.target, Target::Image { .. }) && args.esp_partition.is_some() {
        return Err(refuse("--image refuses --esp-partition"));
    }
    let pool = args.pool.clone().unwrap_or_else(|| {
        if args.portable {
            "stick".into()
        } else {
            DEFAULT_POOL.into()
        }
    });
    if pool.is_empty() || pool.contains('/') || pool.contains('@') {
        return Err(refuse("--pool takes a pool name"));
    }
    let purpose = match &args.factory {
        Some(factory) => {
            let be = args.be.as_deref().unwrap_or(DEFAULT_BE);
            if be.is_empty() || be.contains('/') || be.contains('@') {
                return Err(refuse("--be takes one dataset name component"));
            }
            Purpose::Os {
                factory: factory.clone(),
                dataset: format!("{pool}/ROOT/{be}"),
            }
        }
        None if args.be.is_some() => return Err(refuse("--be needs --tar")),
        None if !args.overlay.is_empty() => return Err(refuse("--overlay needs --tar")),
        None => Purpose::EmptyRoot {
            container: format!("{pool}/ROOT"),
        },
    };
    let boot = match (&args.esp_partition, args.esp) {
        (Some(_), Some(_)) => return Err(refuse("--esp and --esp-partition exclude each other")),
        // An ESP elsewhere is shared: only zboot's own loader path is written.
        (Some(partition), None) => Boot::External {
            partition: partition.clone(),
            replace_fallback: false,
        },
        (None, esp) => Boot::OnTarget {
            esp_bytes: esp.unwrap_or(DEFAULT_ESP_BYTES),
        },
    };
    Ok(DeployRequest {
        schema_version: 3,
        disk: match &args.target {
            Target::Disk { disk } => disk.clone(),
            Target::Image { .. } => String::new(),
        },
        overlays: args.overlay.clone(),
        portable: args.portable,
        fresh_image: matches!(args.target, Target::Image { .. }),
        pool,
        hostid: if args.portable {
            None
        } else {
            args.hostid
                .clone()
                .or_else(|| (running_hostid != 0).then(|| crate::hostid::format(running_hostid)))
        },
        hostname: args.hostname.clone(),
        purpose,
        boot,
        swap: match args.swap {
            None | Some(0) => Swap::None,
            Some(bytes) => Swap::Create { bytes },
        },
        boot_artifact_directory: args.efi.clone(),
        journal_directory: attempt,
    })
}

/// The parts of an engine review the operator consents to: everything but
/// the operation id, its derived UUIDs and hostid, and the attempt directory.
/// The erase review binds what is on the disk now.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct Bound<'a> {
    selection: DeployRequest,
    disk: &'a DiskIdentity,
    factory: Option<&'a str>,
    overlays: Vec<&'a str>,
    artifacts: &'a str,
    efi_bytes: u64,
    external_esp: Option<&'a EspReview>,
    layout: [u64; 6],
}

fn bound(review: &CoreReview) -> Bound<'_> {
    let mut selection = review.selection.clone();
    selection.journal_directory = PathBuf::new();
    let layout = &review.layout;
    let swap = layout
        .swap
        .as_ref()
        .map_or((0, 0), |s| (s.start, s.sectors));
    Bound {
        selection,
        disk: &review.disk,
        factory: review.factory.as_ref().map(|f| f.sha256.as_str()),
        overlays: super::ordered_overlays(review)
            .into_iter()
            .map(|o| o.sha256.as_str())
            .collect(),
        artifacts: &review.artifacts.sha256,
        efi_bytes: review.artifacts.bytes,
        external_esp: review.external_esp.as_ref(),
        layout: [
            layout.esp_start,
            layout.esp_sectors,
            layout.zfs_start,
            layout.zfs_sectors,
            swap.0,
            swap.1,
        ],
    }
}

pub fn consent(plan: &Plan) -> io::Result<String> {
    let ordinary = (
        "zboot-deploy-1",
        device::wipe_consent(&plan.wipe)?,
        bound(&plan.deploy),
    );
    match &plan.scope {
        None => crate::consent::token(&ordinary),
        Some(scope) => crate::consent::token(&(ordinary, scope)),
    }
}

pub fn typed(plan: &Plan) -> crate::consent::Typed {
    crate::consent::disk_target(
        plan.wipe.identity.serial.as_deref(),
        plan.wipe.identity.wwn.as_deref(),
    )
}

/// Observe and preflight; changes nothing.
pub fn plan_with(args: &Args, backend: &mut impl Backend) -> io::Result<Plan> {
    let Target::Disk { disk } = &args.target else {
        return Err(refuse("an image uses its new-file planner"));
    };
    let wipe = backend.wipe_plan(disk)?;
    let other_defaults = backend.boot_defaults()?;
    let running_hostid = backend.running_hostid()?;
    let attempt = backend.attempt()?;
    let deploy = request(args, running_hostid, attempt.clone())
        .and_then(|request| backend.deploy_plan(&request));
    backend.release(&attempt);
    let deploy = deploy?;
    if deploy.disk != wipe.identity {
        return Err(refuse(
            "the disk changed while it was being planned; run again",
        ));
    }
    Ok(Plan {
        schema_version: 1,
        scope: None,
        wipe,
        deploy,
        other_defaults,
    })
}

/// Plan with the same immutable export scope before and after confirmation.
pub fn plan_scoped(args: &Args, scope: &device::DiskScope) -> io::Result<Plan> {
    let mut plan = plan_with(args, &mut ScopedNative { scope })?;
    plan.scope = Some(scope.clone());
    Ok(plan)
}

/// Erase, plan again on the bare disk, check that review binds what was
/// confirmed, then provision. A failure after the erase leaves a bare disk.
pub fn apply_with(plan: &Plan, backend: &mut impl Backend) -> io::Result<Applied> {
    let shown = bound(&plan.deploy);
    let selection = plan.deploy.selection.clone();
    backend.verify_loader(&plan.deploy.artifacts)?;
    let wipe = backend.wipe(&plan.wipe)?;
    let after_erase = |error: io::Error| {
        refuse(format!(
            "the disk was erased and nothing was deployed ({error}); rerun deploy to plan it afresh"
        ))
    };
    let attempt = backend.attempt().map_err(after_erase)?;
    let mut request = selection;
    request.journal_directory = attempt.clone();
    let review = match backend.deploy_plan(&request) {
        Ok(review) => review,
        Err(error) => {
            backend.release(&attempt);
            return Err(after_erase(error));
        }
    };
    if bound(&review) != shown {
        backend.release(&attempt);
        return Err(after_erase(refuse(
            "the deploy plan on the erased disk differs from the confirmed one",
        )));
    }
    let outcome = backend.deploy_apply(&review)?;
    if !outcome.complete || !outcome.exported {
        return Err(refuse(format!(
            "deploy {} did not complete; rerun deploy to plan it afresh",
            outcome.operation_id
        )));
    }
    Ok(Applied {
        wipe,
        review,
        outcome,
    })
}

pub fn describe(plan: &Plan, token: &str) -> String {
    let review = &plan.deploy;
    let size = device::size;
    let mut text = format!(
        "Deploy onto disk\n{}{}  Then:   partitions the disk\n",
        device::describe_disk(&plan.wipe),
        plan.wipe.method.describe()
    );
    if let Some(scope) = &plan.scope {
        text.push_str(&scope.describe());
    }
    let sector = review.disk.logical_sector;
    match &review.external_esp {
        None => text.push_str(&format!(
            "  ESP:    {} on this disk, with the recovery UKI and fallback loader\n",
            size(review.layout.esp_sectors * sector)
        )),
        Some(esp) => {
            text.push_str(&format!(
                "  ESP:    existing {} PARTUUID {} on another disk; overwrites:\n",
                zfs_tools::engine::escape_display(&esp.target.partition.path),
                zfs_tools::engine::escape_display(
                    esp.target
                        .partition
                        .partition_uuid
                        .as_deref()
                        .unwrap_or("-")
                )
            ));
            for (path, previous) in &esp.previous {
                text.push_str(&format!(
                    "            {} ({})\n",
                    zfs_tools::engine::escape_display(path),
                    previous
                        .as_ref()
                        .map_or("absent".into(), |file| size(file.bytes))
                ));
            }
        }
    }
    if let Some(swap) = &review.layout.swap {
        text.push_str(&format!("  Swap:   {}\n", size(swap.sectors * sector)));
    }
    let selection = &review.selection;
    match &selection.purpose {
        Purpose::Os { dataset, .. } => text.push_str(&format!(
            "  Pool:   {}, BE {}{}\n",
            zfs_tools::engine::escape_display(&selection.pool),
            zfs_tools::engine::escape_display(dataset),
            if selection.portable {
                "; portable, no boot default"
            } else {
                " as the new pool's boot default (bootfs)"
            }
        )),
        Purpose::EmptyRoot { .. } => text.push_str(&format!(
            "  Pool:   {} with an empty {}/ROOT; no boot default\n",
            zfs_tools::engine::escape_display(&selection.pool),
            zfs_tools::engine::escape_display(&selection.pool)
        )),
    }
    if matches!(selection.purpose, Purpose::Os { .. })
        && !selection.portable
        && !plan.other_defaults.is_empty()
    {
        text.push_str(&format!(
            "  Note:   imported pools already name a boot default ({}); deploy leaves them, so\n\
             \x20         this host then has more than one and zboot default picks one\n",
            plan.other_defaults
                .iter()
                .map(|dataset| zfs_tools::engine::escape_display(dataset))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if selection.portable {
        text.push_str("  Hostid: none (portable)\n");
    } else {
        match selection.hostid.as_deref() {
            Some(hostid) => text.push_str(&format!("  Hostid: {hostid}\n")),
            None => text.push_str("  Hostid: a new random one\n"),
        }
    }
    if let Some(name) = selection.hostname.as_deref() {
        text.push_str(&format!(
            "  Hostname: {}\n",
            zfs_tools::engine::escape_display(name)
        ));
    }
    text.push_str(&format!(
        "  EFI:    {} ({}) {}\n",
        zfs_tools::engine::escape_display(&review.artifacts.efi.display().to_string()),
        device::size(review.artifacts.bytes),
        review.artifacts.sha256
    ));
    if let Some(factory) = &review.factory {
        text.push_str(&format!(
            "  Root:   {} ({} entries, kernel {}) {}\n",
            zfs_tools::engine::escape_display(&factory.path.display().to_string()),
            factory.entries,
            zfs_tools::engine::escape_display(&factory.kernels.join(" ")),
            factory.sha256
        ));
    }
    for overlay in super::ordered_overlays(review) {
        text.push_str(&format!(
            "  Overlay: {} ({} entries{}) {}\n",
            zfs_tools::engine::escape_display(&overlay.source.display().to_string()),
            overlay.entries.len(),
            if overlay.post_install.is_some() {
                ", post-install"
            } else {
                ""
            },
            overlay.sha256
        ));
        for entry in &overlay.entries {
            text.push_str(&format!(
                "    {}  {}\n",
                zfs_tools::engine::escape_display(&entry.path),
                entry.kind
            ));
        }
    }
    text.push_str(&format!("  Token:  {token}\n"));
    text
}

/// CLI file admission runs before an image preview or exclusive file creation.
pub(super) fn validate_cli_request(request: &DeployRequest) -> io::Result<()> {
    request::validate_request(request)?;
    let efi = &request.boot_artifact_directory;
    if !std::fs::metadata(efi)
        .map_err(crate::output::naming("UKI", efi))?
        .is_file()
    {
        return Err(refuse(
            "--efi takes a regular UKI file, not a directory or special file",
        ));
    }
    Ok(())
}

/// The installed system.
pub struct Native;

impl Backend for Native {
    fn wipe_plan(&mut self, disk: &str) -> io::Result<DiskReview> {
        device::plan(disk).map_err(refuse)
    }
    fn boot_defaults(&mut self) -> io::Result<Vec<String>> {
        let state = zfs_tools::engine::state::observe().map_err(refuse)?;
        Ok(state
            .pool_properties
            .values()
            .filter_map(|properties| properties.get("bootfs"))
            .filter(|property| !property.value.is_empty() && property.value != "-")
            .map(|property| property.value.clone())
            .collect())
    }
    fn running_hostid(&mut self) -> io::Result<u32> {
        crate::hostid::effective()
    }
    fn attempt(&mut self) -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        let parent = std::path::Path::new("/run/zboot/deploy");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)?;
        let attempt = parent.join(format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&attempt)?;
        Ok(attempt)
    }
    fn release(&mut self, attempt: &std::path::Path) {
        // Only an empty directory goes; hook logs stay.
        let _ = std::fs::remove_dir(attempt);
    }
    fn deploy_plan(&mut self, request: &DeployRequest) -> io::Result<CoreReview> {
        validate_cli_request(request)?;
        request::plan(request)
    }
    fn verify_loader(&mut self, loader: &crate::loader::EfiFile) -> io::Result<()> {
        loader.revalidate()
    }
    fn wipe(&mut self, review: &DiskReview) -> io::Result<WipeOutcome> {
        device::wipe(review, &review.loss_token).map_err(refuse)
    }
    fn deploy_apply(&mut self, review: &CoreReview) -> io::Result<CoreOutcome> {
        request::apply(review, &review.loss_token)
    }
}

struct ScopedNative<'a> {
    scope: &'a device::DiskScope,
}
impl Backend for ScopedNative<'_> {
    fn wipe_plan(&mut self, disk: &str) -> io::Result<DiskReview> {
        if device::observe_identity(disk).map_err(refuse)? != *self.scope.identity() {
            return Err(refuse("deploy path differs from reviewed export disk"));
        }
        self.scope.review().map_err(refuse)
    }
    /// A pool on the reviewed disk is exported and erased, so its default
    /// goes with it.
    fn boot_defaults(&mut self) -> io::Result<Vec<String>> {
        let mut defaults = Native.boot_defaults()?;
        defaults.retain(|dataset| {
            let pool = dataset.split('/').next().unwrap_or(dataset);
            !self.scope.pools().iter().any(|scoped| scoped.name == pool)
        });
        Ok(defaults)
    }
    fn running_hostid(&mut self) -> io::Result<u32> {
        Native.running_hostid()
    }
    fn attempt(&mut self) -> io::Result<PathBuf> {
        Native.attempt()
    }
    fn release(&mut self, path: &std::path::Path) {
        Native.release(path);
    }
    fn deploy_plan(&mut self, request: &DeployRequest) -> io::Result<CoreReview> {
        validate_cli_request(request)?;
        request::plan_reviewed(request, &self.scope.review().map_err(refuse)?, self.scope)
    }
    fn verify_loader(&mut self, loader: &crate::loader::EfiFile) -> io::Result<()> {
        Native.verify_loader(loader)
    }
    fn wipe(&mut self, review: &DiskReview) -> io::Result<WipeOutcome> {
        Native.wipe(review)
    }
    fn deploy_apply(&mut self, review: &CoreReview) -> io::Result<CoreOutcome> {
        Native.deploy_apply(review)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Records every call; `fail` names the call that errors.
    struct Fake {
        calls: Vec<String>,
        fail: Option<&'static str>,
        disk: DiskReview,
        review: CoreReview,
        /// Applied to the review planned after the erase.
        drift: Option<fn(&mut CoreReview)>,
        erased: bool,
        attempts: u32,
        defaults: Vec<String>,
    }

    fn fixture() -> CoreReview {
        super::super::tests::review(Path::new("/nonexistent/zboot-pure-deploy-fixture"))
    }

    fn disk() -> DiskReview {
        let review = fixture();
        DiskReview {
            schema_version: 2,
            identity: review.disk.clone(),
            partitions: vec![device::Partition {
                path: format!("{}1", review.disk.path),
                device_number: "259:1".into(),
                bytes: 1 << 30,
                partition_uuid: Some("old-part".into()),
                filesystem: Some("ext4".into()),
                filesystem_uuid: Some("old-fs".into()),
                filesystem_label: None,
            }],
            filesystem: None,
            partition_table_uuid: Some("old-table".into()),
            method: device::Method::Clear {
                reason: device::ClearReason::NotNvme,
                extents: Vec::new(),
            },
            loss_token: "wipe-token".into(),
        }
    }

    fn engine_review(request: &DeployRequest) -> CoreReview {
        let mut review = fixture();
        let mut selection = request.clone();
        selection.disk = review.disk.path.clone();
        review.selection = selection;
        // The operation id and everything derived from it differ per attempt.
        review.operation_id = request.journal_directory.display().to_string();
        review.layout.disk_uuid = review.operation_id.clone();
        review
    }

    impl Fake {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                fail: None,
                disk: disk(),
                review: fixture(),
                drift: None,
                erased: false,
                attempts: 0,
                defaults: Vec::new(),
            }
        }
        fn call(&mut self, name: &'static str) -> io::Result<()> {
            self.calls.push(name.into());
            if self.fail == Some(name) {
                return Err(io::Error::other(format!("{name} failed")));
            }
            Ok(())
        }
        fn effects(&self) -> Vec<&str> {
            self.calls
                .iter()
                .map(String::as_str)
                .filter(|c| ["wipe", "deploy_apply"].contains(c))
                .collect()
        }
    }

    impl Backend for Fake {
        fn wipe_plan(&mut self, _: &str) -> io::Result<DiskReview> {
            self.call("wipe_plan")?;
            let mut disk = self.disk.clone();
            if self.erased {
                disk.partitions.clear();
                disk.partition_table_uuid = None;
            }
            Ok(disk)
        }
        fn running_hostid(&mut self) -> io::Result<u32> {
            self.call("running_hostid")?;
            Ok(0)
        }
        fn boot_defaults(&mut self) -> io::Result<Vec<String>> {
            Ok(self.defaults.clone())
        }
        fn attempt(&mut self) -> io::Result<PathBuf> {
            self.call("attempt")?;
            self.attempts += 1;
            Ok(format!("/run/zboot/deploy/{}", self.attempts).into())
        }
        fn release(&mut self, _: &Path) {
            self.calls.push("release".into());
        }
        fn deploy_plan(&mut self, request: &DeployRequest) -> io::Result<CoreReview> {
            self.call(if self.erased { "replan" } else { "deploy_plan" })?;
            let mut review = engine_review(request);
            review.disk = self.review.disk.clone();
            if self.erased
                && let Some(drift) = self.drift
            {
                drift(&mut review);
            }
            Ok(review)
        }
        fn verify_loader(&mut self, _: &crate::loader::EfiFile) -> io::Result<()> {
            self.call("verify_loader")
        }
        fn wipe(&mut self, review: &DiskReview) -> io::Result<WipeOutcome> {
            self.call("wipe")?;
            assert_eq!(review, &self.disk);
            self.erased = true;
            Ok(WipeOutcome {
                identity: review.identity.clone(),
                method: review.method.clone(),
                report: "cleared".into(),
                complete: true,
            })
        }
        fn deploy_apply(&mut self, review: &CoreReview) -> io::Result<CoreOutcome> {
            self.call("deploy_apply")?;
            Ok(CoreOutcome {
                operation_id: review.operation_id.clone(),
                journal_directory: review.selection.journal_directory.clone(),
                disk: review.disk.clone(),
                pool: test_endpoint("rpool"),
                dataset: Some(test_endpoint("rpool/ROOT/default")),
                root: test_endpoint("rpool/ROOT"),
                swap: None,
                external_boot_dependency: false,
                firmware_selection: "fallback".into(),
                esp: device::PartitionIdentity {
                    disk: review.disk.clone(),
                    partition: device::Partition {
                        path: "/dev/x1".into(),
                        device_number: "259:1".into(),
                        bytes: 1 << 30,
                        partition_uuid: None,
                        filesystem: Some("vfat".into()),
                        filesystem_uuid: None,
                        filesystem_label: None,
                    },
                    number: 1,
                    partition_type: None,
                    readonly: false,
                },
                complete: true,
                exported: true,
            })
        }
    }

    fn test_endpoint(name: &str) -> zfs_tools::engine::management::Endpoint {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "identity": {"pool_guid": "1", "guid": "2", "createtxg": "1", "objsetid": "3"}
        }))
        .unwrap()
    }

    fn args() -> Args {
        Args {
            target: Target::Disk {
                disk: "/dev/disk/by-id/nvme-x".into(),
            },
            efi: "/var/lib/zboot/build/artifacts".into(),
            factory: Some("/var/lib/zboot/build/factory.tar.zst".into()),
            overlay: vec!["/etc/zboot/overlay".into()],
            portable: false,
            be: None,
            pool: None,
            hostid: None,
            hostname: None,
            esp: None,
            esp_partition: None,
            swap: None,
        }
    }

    #[test]
    fn ordinary_deploy_scope_and_confirmation_encoding_stay_unchanged() {
        let plan = plan_with(&args(), &mut Fake::new()).unwrap();
        assert!(serde_json::to_value(&plan).unwrap().get("scope").is_none());
        assert_eq!(
            consent(&plan).unwrap(),
            crate::consent::token(&(
                "zboot-deploy-1",
                device::wipe_consent(&plan.wipe).unwrap(),
                bound(&plan.deploy),
            ))
            .unwrap()
        );
    }

    #[test]
    fn defaults_and_selection_follow_the_command_line() {
        let built = super::request(&args(), 0, "/run/a".into()).unwrap();
        assert_eq!(built.pool, "rpool");
        assert_eq!(
            built.purpose,
            Purpose::Os {
                factory: "/var/lib/zboot/build/factory.tar.zst".into(),
                dataset: "rpool/ROOT/default".into()
            }
        );
        assert_eq!(built.overlays, vec![PathBuf::from("/etc/zboot/overlay")]);
        assert_eq!(built.boot, Boot::OnTarget { esp_bytes: 1 << 30 });
        assert_eq!(built.swap, Swap::None);
        assert_eq!(built.hostid, None);

        let mut empty = args();
        empty.factory = None;
        empty.overlay.clear();
        empty.pool = Some("tank".into());
        empty.swap = Some(8 << 30);
        empty.esp_partition = Some("/dev/sda1".into());
        let built = super::request(&empty, 0x0a0b0c0d, "/run/a".into()).unwrap();
        assert_eq!(
            built.purpose,
            Purpose::EmptyRoot {
                container: "tank/ROOT".into()
            }
        );
        assert_eq!(
            built.boot,
            Boot::External {
                partition: "/dev/sda1".into(),
                replace_fallback: false
            }
        );
        assert_eq!(built.swap, Swap::Create { bytes: 8 << 30 });
        assert_eq!(built.hostid.as_deref(), Some("0a0b0c0d"));

        let mut explicit = args();
        explicit.hostid = Some("01020304".into());
        explicit.hostname = Some("desk".into());
        let built = super::request(&explicit, 0x0a0b0c0d, "/run/a".into()).unwrap();
        assert_eq!(built.hostid.as_deref(), Some("01020304"));
        assert_eq!(built.hostname.as_deref(), Some("desk"));

        for broken in [
            Args {
                be: Some("a/b".into()),
                ..args()
            },
            Args {
                pool: Some("a/b".into()),
                ..args()
            },
            Args {
                factory: None,
                overlay: Vec::new(),
                be: Some("x".into()),
                ..args()
            },
            Args {
                factory: None,
                ..args()
            },
            Args {
                esp: Some(1),
                esp_partition: Some("/dev/sda1".into()),
                ..args()
            },
        ] {
            assert!(super::request(&broken, 0, "/run/a".into()).is_err());
        }
    }

    #[test]
    fn the_token_is_stable_across_attempts_and_binds_the_erase_and_selection() {
        let mut fake = Fake::new();
        let first = plan_with(&args(), &mut fake).unwrap();
        let second = plan_with(&args(), &mut fake).unwrap();
        assert_ne!(first.deploy.operation_id, second.deploy.operation_id);
        let token = consent(&first).unwrap();
        assert_eq!(token.len(), 32);
        assert_eq!(token, consent(&second).unwrap());
        assert!(fake.effects().is_empty());
        // Each preflight's attempt directory is released.
        assert_eq!(fake.calls.iter().filter(|c| *c == "release").count(), 2);

        let mut other_disk = first.clone();
        other_disk.wipe.partitions.clear();
        assert_ne!(consent(&other_disk).unwrap(), token);
        let mut other_pool = first.clone();
        other_pool.deploy.selection.pool = "tank".into();
        assert_ne!(consent(&other_pool).unwrap(), token);
        let mut other_image = first.clone();
        other_image.deploy.artifacts.sha256 = "other".into();
        assert_ne!(consent(&other_image).unwrap(), token);
        let mut other_layout = first;
        other_layout.deploy.layout.zfs_sectors -= 1;
        assert_ne!(consent(&other_layout).unwrap(), token);
    }

    #[test]
    fn refusals_in_planning_change_nothing() {
        for step in ["wipe_plan", "running_hostid", "attempt", "deploy_plan"] {
            let mut fake = Fake::new();
            fake.fail = Some(step);
            assert!(plan_with(&args(), &mut fake).is_err(), "{step}");
            assert!(fake.effects().is_empty(), "{step}");
        }
        // The preflight saw another disk than the erase review.
        let mut fake = Fake::new();
        fake.review.disk.serial = Some("OTHER".into());
        let error = plan_with(&args(), &mut fake).unwrap_err();
        assert!(error.to_string().contains("disk changed"));
        assert!(fake.effects().is_empty());
    }

    #[test]
    fn consent_binds_standalone_efi_source_digest_and_size() {
        let mut fake = Fake::new();
        let mut plan = plan_with(&args(), &mut fake).unwrap();
        let file = crate::loader::EfiFile {
            efi: "/bound/loader.efi".into(),
            sha256: "ab".repeat(32),
            bytes: 4096,
        };
        plan.deploy.artifacts = file.clone();
        plan.deploy.selection.boot_artifact_directory = file.efi.clone();
        let shown = consent(&plan).unwrap();
        let mut changed = plan.clone();
        changed.deploy.artifacts.bytes += 1;
        assert_ne!(consent(&changed).unwrap(), shown);
        changed.deploy.artifacts.sha256 = "cd".repeat(32);
        assert_ne!(consent(&changed).unwrap(), shown);
        changed = plan.clone();
        changed.deploy.selection.boot_artifact_directory = "/other/loader.efi".into();
        assert_ne!(consent(&changed).unwrap(), shown);
    }

    #[test]
    fn loader_revalidation_failure_precedes_the_first_erase() {
        let mut fake = Fake::new();
        let plan = plan_with(&args(), &mut fake).unwrap();
        fake.calls.clear();
        fake.fail = Some("verify_loader");
        assert!(
            apply_with(&plan, &mut fake)
                .unwrap_err()
                .to_string()
                .contains("verify_loader")
        );
        assert_eq!(fake.calls, ["verify_loader"]);
        assert!(fake.effects().is_empty());
    }

    #[test]
    fn apply_erases_then_deploys_the_replanned_review() {
        let mut fake = Fake::new();
        let plan = plan_with(&args(), &mut fake).unwrap();
        fake.calls.clear();
        let applied = apply_with(&plan, &mut fake).unwrap();
        assert_eq!(
            fake.calls,
            ["verify_loader", "wipe", "attempt", "replan", "deploy_apply"]
        );
        // The engine applied the review made on the erased disk.
        assert_ne!(applied.review.operation_id, plan.deploy.operation_id);
        assert_eq!(applied.outcome.operation_id, applied.review.operation_id);
        assert!(applied.outcome.complete && applied.wipe.complete);
    }

    #[test]
    fn a_cut_at_each_step_stops_before_the_next_effect() {
        for (step, effects) in [
            ("wipe", vec!["wipe"]),
            ("attempt", vec!["wipe"]),
            ("replan", vec!["wipe"]),
            ("deploy_apply", vec!["wipe", "deploy_apply"]),
        ] {
            let mut fake = Fake::new();
            let plan = plan_with(&args(), &mut fake).unwrap();
            fake.calls.clear();
            fake.fail = Some(step);
            let error = apply_with(&plan, &mut fake).unwrap_err().to_string();
            assert_eq!(fake.effects(), effects, "{step}");
            if ["attempt", "replan"].contains(&step) {
                assert!(error.contains("rerun deploy"), "{step}: {error}");
            }
            // A rerun plans the now-different disk afresh: a new token.
            fake.fail = None;
            let again = plan_with(&args(), &mut fake).unwrap();
            if step != "wipe" {
                assert_ne!(consent(&again).unwrap(), consent(&plan).unwrap(), "{step}");
            }
        }
    }

    #[test]
    fn a_replan_that_differs_from_the_confirmed_plan_is_refused_before_deploying() {
        let drifts: [fn(&mut CoreReview); 5] = [
            |r| r.artifacts.sha256 = "changed".into(),
            |r| r.layout.esp_sectors += 8,
            |r| r.selection.hostid = Some("01020304".into()),
            |r| r.selection.hostname = Some("other".into()),
            |r| r.disk.serial = Some("OTHER".into()),
        ];
        for drift in drifts {
            let mut fake = Fake::new();
            let plan = plan_with(&args(), &mut fake).unwrap();
            fake.calls.clear();
            fake.drift = Some(drift);
            let error = apply_with(&plan, &mut fake).unwrap_err().to_string();
            assert!(error.contains("differs from the confirmed"), "{error}");
            assert_eq!(fake.effects(), ["wipe"]);
            assert_eq!(fake.calls.last().map(String::as_str), Some("release"));
        }
    }

    #[test]
    fn a_lost_apply_reply_is_not_success() {
        struct Incomplete(Fake);
        impl Backend for Incomplete {
            fn wipe_plan(&mut self, disk: &str) -> io::Result<DiskReview> {
                self.0.wipe_plan(disk)
            }
            fn running_hostid(&mut self) -> io::Result<u32> {
                self.0.running_hostid()
            }
            fn attempt(&mut self) -> io::Result<PathBuf> {
                self.0.attempt()
            }
            fn release(&mut self, attempt: &Path) {
                self.0.release(attempt)
            }
            fn deploy_plan(&mut self, request: &DeployRequest) -> io::Result<CoreReview> {
                self.0.deploy_plan(request)
            }
            fn verify_loader(&mut self, loader: &crate::loader::EfiFile) -> io::Result<()> {
                self.0.verify_loader(loader)
            }
            fn wipe(&mut self, review: &DiskReview) -> io::Result<WipeOutcome> {
                self.0.wipe(review)
            }
            fn deploy_apply(&mut self, review: &CoreReview) -> io::Result<CoreOutcome> {
                let mut outcome = self.0.deploy_apply(review)?;
                outcome.exported = false;
                Ok(outcome)
            }
        }
        let mut fake = Incomplete(Fake::new());
        let plan = plan_with(&args(), &mut fake).unwrap();
        let error = apply_with(&plan, &mut fake).unwrap_err().to_string();
        assert!(error.contains("did not complete"), "{error}");
    }

    #[test]
    fn another_pools_default_is_noted_but_not_bound() {
        let mut fake = Fake::new();
        let alone = plan_with(&args(), &mut fake).unwrap();
        fake.defaults = vec!["rpool/ROOT/default".into()];
        let plan = plan_with(&args(), &mut fake).unwrap();
        let text = describe(&plan, "tok");
        assert!(
            text.contains("BE rpool/ROOT/default as the new pool's boot default (bootfs)\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "  Note:   imported pools already name a boot default (rpool/ROOT/default); \
                 deploy leaves them, so\n          this host then has more than one and \
                 zboot default picks one\n"
            ),
            "{text}"
        );
        assert_eq!(consent(&plan).unwrap(), consent(&alone).unwrap());
    }

    #[test]
    fn the_plan_names_the_erase_the_pool_and_the_image() {
        let mut fake = Fake::new();
        let plan = plan_with(&args(), &mut fake).unwrap();
        let text = describe(&plan, "tok");
        assert!(
            text.contains("Effect: ZFS labels, signatures and partition tables are cleared"),
            "{text}"
        );
        assert!(text.contains("Now:"), "{text}");
        assert!(text.contains("Token:  tok"), "{text}");
        assert!(text.contains("Hostid: a new random one"), "{text}");
        assert!(!text.contains("Note:"), "{text}");
        assert_eq!(
            typed(&plan).text.is_empty(),
            plan.wipe.identity.serial.is_none() && plan.wipe.identity.wwn.is_none()
        );
    }
}
