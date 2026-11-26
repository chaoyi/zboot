//! Provisioning choices composed through the shared disk/owned-image executor.
use super::*;
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeployRequest {
    pub schema_version: u32,
    pub disk: String,
    pub pool: String,
    /// The host identity the pool records and the BE's `/etc/hostid` carries;
    /// the disks of one host share it. Omission derives a new random one from
    /// the operation id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostid: Option<String>,
    /// The BE's `/etc/hostname`; an OS deploy only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub purpose: Purpose,
    pub boot: Boot,
    pub swap: Swap,
    /// The standalone zboot UKI written to the ESP.
    pub boot_artifact_directory: PathBuf,
    /// This attempt's private directory; it receives the post-install logs.
    pub journal_directory: PathBuf,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub overlays: Vec<PathBuf>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub portable: bool,
    /// Only the image wrapper sets this, after creating and binding a new
    /// file: the target is that file's loop device, bare from the start.
    /// Otherwise the target is a disk the caller erases after planning.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fresh_image: bool,
}
fn valid_hostid(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value != "00000000"
        && value != "ffffffff"
}
/// A hostname of dot-separated labels: letters, digits and inner hyphens,
/// at most 63 bytes each and 253 in all.
pub fn valid_hostname(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub(super) fn requested_hostid(request: &DeployRequest, operation_id: &str) -> io::Result<String> {
    if request.portable {
        if request.hostid.is_some() {
            return Err(refuse("--portable refuses --hostid"));
        }
        return Ok("00000000".into());
    }
    match &request.hostid {
        Some(value) if valid_hostid(value) => Ok(value.clone()),
        Some(_) => Err(refuse(
            "deploy hostid must be eight lowercase hex digits, excluding 00000000 and ffffffff",
        )),
        None => Ok(hostid(operation_id)),
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Purpose {
    Os {
        /// Any admitted root tar, normally produced by `zboot factory`.
        factory: PathBuf,
        dataset: String,
    },
    EmptyRoot {
        container: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Boot {
    OnTarget {
        esp_bytes: u64,
    },
    External {
        partition: String,
        replace_fallback: bool,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Swap {
    None,
    Create { bytes: u64 },
}
pub type DeployReview = CoreReview;
pub type DeployOutcome = CoreOutcome;
impl DeployRequest {
    /// The BE of an OS deploy; the `ROOT` container of an empty root.
    pub(super) fn dataset(&self) -> &str {
        match &self.purpose {
            Purpose::Os { dataset, .. } => dataset,
            Purpose::EmptyRoot { container } => container,
        }
    }
    fn esp_bytes(&self) -> Option<u64> {
        match self.boot {
            Boot::OnTarget { esp_bytes } => Some(esp_bytes),
            Boot::External { .. } => None,
        }
    }
    fn swap_bytes(&self) -> Option<u64> {
        match self.swap {
            Swap::None => None,
            Swap::Create { bytes } => Some(bytes),
        }
    }
}
pub(super) fn validate_selection(review: &CoreReview) -> io::Result<()> {
    let request = &review.selection;
    if review.hostid != requested_hostid(request, &review.operation_id)?
        || Layout::selected(
            &review.disk,
            request.esp_bytes(),
            request.swap_bytes(),
            &review.operation_id,
        )? != review.layout
    {
        return Err(refuse("deploy selection and exact layout disagree"));
    }
    review.artifacts.validate()?;
    if request.portable
        && (request.hostid.is_some()
            || !matches!(request.swap, Swap::None)
            || !matches!(request.boot, Boot::OnTarget { .. })
            || !matches!(request.purpose, Purpose::Os { .. }))
    {
        return Err(refuse(
            "portable deploy refuses hostid, swap, external ESP and empty content",
        ));
    }
    if request.fresh_image && !matches!(request.boot, Boot::OnTarget { .. }) {
        return Err(refuse("new image deploy needs an on-image ESP"));
    }
    let user_count = request.overlays.len();
    if review.overlays.len() != user_count + usize::from(request.portable)
        || review
            .overlays
            .iter()
            .take(user_count)
            .map(|o| &o.source)
            .ne(request.overlays.iter())
        || request.portable && review.overlays.last() != Some(&overlay::portable())
    {
        return Err(refuse(
            "ordered deploy overlays differ from the selected sources or portable policy",
        ));
    }
    if request
        .hostname
        .as_deref()
        .is_some_and(|name| !valid_hostname(name) || review.factory.is_none())
    {
        return Err(refuse(
            "deploy hostname needs an OS deploy and a valid name",
        ));
    }
    match (&request.purpose, &review.factory) {
        (Purpose::Os { factory, .. }, Some(admitted)) if factory == &admitted.path => {}
        (Purpose::EmptyRoot { container }, None)
            if container == &format!("{}/ROOT", request.pool) => {}
        _ => return Err(refuse("deploy purpose and factory/container disagree")),
    }
    if let Some(external) = &review.external_esp {
        esp::validate_review(external)?;
    }
    match (&request.boot, &review.external_esp) {
        (Boot::OnTarget { .. }, None) => {}
        (
            Boot::External {
                partition,
                replace_fallback,
            },
            Some(esp),
        ) if &esp.target.partition.path == partition
            && esp.target.disk.device_number != review.disk.device_number
            && esp.target.disk.sysfs_path != review.disk.sysfs_path
            && esp.artifacts == review.artifacts
            && (*replace_fallback
                || esp
                    .previous
                    .keys()
                    .all(|path| !path.eq_ignore_ascii_case("EFI/BOOT/BOOTX64.EFI"))) => {}
        _ => {
            return Err(refuse(
                "external ESP must bind a different physical disk and exact write set",
            ));
        }
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Inputs {
    pub factory: Option<RootTar>,
    pub overlays: Vec<overlay::Overlay>,
    pub artifacts: EfiFile,
}
pub(crate) fn inputs(request: &DeployRequest) -> io::Result<Inputs> {
    let factory = match &request.purpose {
        Purpose::Os { factory, .. } => Some(factory::root_tar::inspect(factory)?),
        Purpose::EmptyRoot { .. } => None,
    };
    if factory.is_none() && (!request.overlays.is_empty() || request.portable) {
        return Err(refuse("overlays and portable mode require a root tar"));
    }
    let mut overlays = request
        .overlays
        .iter()
        .map(|path| overlay::review(path))
        .collect::<io::Result<Vec<_>>>()?;
    if request.portable {
        overlays.push(overlay::portable());
    }
    let artifacts = EfiFile::inspect(&request.boot_artifact_directory)?;
    Ok(Inputs {
        factory,
        overlays,
        artifacts,
    })
}
pub(crate) fn bound_inputs(review: &CoreReview) -> Inputs {
    Inputs {
        factory: review.factory.clone(),
        overlays: review.overlays.clone(),
        artifacts: review.artifacts.clone(),
    }
}

/// Target-independent admission, before a new image or native disk is opened.
pub(super) fn validate_request(request: &DeployRequest) -> io::Result<()> {
    // Explicit identity refusals precede schema admission. Portable zero is
    // derived internally, never an explicit hostid value.
    if request
        .hostid
        .as_deref()
        .is_some_and(|value| !valid_hostid(value))
    {
        return Err(refuse(
            "deploy hostid must be eight lowercase hex digits, excluding 00000000 and ffffffff",
        ));
    }
    if let Some(name) = &request.hostname
        && (!valid_hostname(name) || matches!(request.purpose, Purpose::EmptyRoot { .. }))
    {
        return Err(refuse(
            "deploy hostname must be dot-separated letters, digits and inner hyphens, for an OS deploy",
        ));
    }
    let (dataset, os) = match &request.purpose {
        Purpose::Os { dataset, .. } => (dataset, true),
        Purpose::EmptyRoot { container } => (container, false),
    };
    super::validate_names(&request.pool, dataset, os)?;
    Ok(())
}

fn plan_selected(
    request: &DeployRequest,
    admitted: Option<(device::DiskReview, &device::DiskScope)>,
) -> io::Result<DeployReview> {
    validate_request(request)?;
    require_native_tools()?;
    let (disk, scope) = match admitted {
        Some((review, scope)) => (review.identity, Some(scope)),
        None => (device::plan(&request.disk).map_err(refuse)?.identity, None),
    };
    if request.fresh_image && !image::registered_disk(&disk)? {
        return Err(refuse(
            "new image deploy lacks its exclusive created-file loop authority",
        ));
    }
    // A disk deploy is planned before its erase; a new image is bare.
    if request.fresh_image {
        bare(&disk)?;
    } else {
        require_erase_tools()?;
    }
    let attempt = attempt_directory(&request.journal_directory)?;
    let inputs = inputs(request)?;
    let factory = inputs.factory;
    let overlays = inputs.overlays;
    let artifacts = inputs.artifacts;
    let external_esp = match &request.boot {
        Boot::External {
            partition,
            replace_fallback,
        } => Some(esp::plan_loader(partition, &artifacts, *replace_fallback)?),
        _ => None,
    };
    let mut request = request.clone();
    request.disk = disk.path.clone();
    request.journal_directory = attempt;
    request.boot_artifact_directory = artifacts.efi.clone();
    if let (Purpose::Os { factory: path, .. }, Some(factory)) = (&mut request.purpose, &factory) {
        path.clone_from(&factory.path);
    }
    request.overlays = overlays
        .iter()
        .take(request.overlays.len())
        .map(|o| o.source.clone())
        .collect();
    if let (Boot::External { partition, .. }, Some(esp)) = (&mut request.boot, &external_esp) {
        *partition = esp.target.partition.path.clone();
    }
    let seed = serde_json::to_vec(&(
        &request,
        &disk,
        &factory,
        &overlays,
        &artifacts,
        &external_esp,
    ))
    .map_err(refuse)?;
    let operation_id = layout::derived_uuid(&seed, "operation");
    let mut review = CoreReview {
        schema_version: request.schema_version,
        hostid: requested_hostid(&request, &operation_id)?,
        layout: Layout::selected(
            &disk,
            request.esp_bytes(),
            request.swap_bytes(),
            &operation_id,
        )?,
        operation_id,
        disk,
        factory,
        overlays,
        artifacts,
        selection: request,
        external_esp,
        loss_token: String::new(),
    };
    review.loss_token = token(&review)?;
    validate(&review)?;
    if state::observe()
        .map_err(refuse)?
        .inspection
        .pools
        .iter()
        .any(|p| {
            p.name == review.selection.pool
                && !scope.is_some_and(|scope| {
                    scope
                        .pools()
                        .iter()
                        .any(|bound| bound.name == p.name && bound.guid == p.guid)
                })
        })
    {
        return Err(refuse("deploy pool name is already imported"));
    }
    Ok(review)
}
pub fn plan(request: &DeployRequest) -> io::Result<DeployReview> {
    plan_selected(request, None)
}
/// Preflight using an explicitly reviewed read-only disk admission. Execution
/// still uses the ordinary imported-none guards after the scope is exported.
pub fn plan_reviewed(
    request: &DeployRequest,
    disk: &device::DiskReview,
    scope: &device::DiskScope,
) -> io::Result<DeployReview> {
    if device::observe_identity(&request.disk).map_err(refuse)? != *scope.identity()
        || scope.review().map_err(refuse)? != *disk
    {
        return Err(refuse(
            "deploy disk scope differs from its reviewed inventory",
        ));
    }
    plan_selected(request, Some((disk.clone(), scope)))
}
pub fn apply(review: &DeployReview, consent: &str) -> io::Result<DeployOutcome> {
    no_hibernation_image()?;
    apply_core(review, consent)
}
fn no_hibernation_image() -> io::Result<()> {
    crate::handoff::require_no_hibernation_image()
        .map_err(|error| io::Error::other(error.to_string()))
}
