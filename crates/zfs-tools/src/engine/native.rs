use crate::engine::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
};

static VERBOSE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static WRITER_CUSTODY: std::cell::RefCell<Vec<crate::engine::lock::WriterLock>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run synchronous native effects under duplicate custody of this exact writer
/// session. The duplicate shares the existing open-file description; no second
/// flock acquisition occurs. Nested contexts restore the previous session.
pub(crate) fn with_writer_lock<T>(
    held: &crate::engine::lock::WriterLock,
    run: impl FnOnce() -> T,
) -> Result<T, Error> {
    let duplicate = held
        .duplicate()
        .map_err(|error| Error::Inconsistent(error.to_string()))?;
    WRITER_CUSTODY.with(|stack| stack.borrow_mut().push(duplicate));
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            WRITER_CUSTODY.with(|stack| {
                stack.borrow_mut().pop();
            });
        }
    }
    let _restore = Restore;
    Ok(run())
}

fn inherit_writer(command: &mut Command) -> Result<(), Error> {
    WRITER_CUSTODY.with(|stack| match stack.borrow().last() {
        Some(held) => held
            .inherit_for(command)
            .map_err(|error| Error::Inconsistent(error.to_string())),
        None => Ok(()),
    })
}

/// Set this invocation's explicit verbosity, returning the previous value so
/// a caller that temporarily enables diagnostics can restore it afterwards.
#[cfg(feature = "internal")]
pub fn set_verbose(value: bool) -> bool {
    VERBOSE.swap(value, Ordering::SeqCst)
}

/// Nested commands also recognize the explicit environment opt-in. Reading
/// it here requires no mutation of the multithreaded parent's environment.
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::SeqCst)
        || std::env::var_os("ZBOOT_VERBOSE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Announce the actual configured program and arguments on one diagnostic
/// line. Diagnostic output never replaces a native result or reaches stdout.
pub fn announce(command: &Command) {
    if !verbose() {
        return;
    }
    let words = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|word| crate::engine::escape_display(&word.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");
    let _ = writeln!(std::io::stderr().lock(), "+ {words}");
}

/// Finish configuring a child after any environment whitelist, then announce
/// it immediately before execution. This helper does not launch the child.
pub fn announced(command: &mut Command) -> Announced<'_> {
    if verbose() {
        command.env("ZBOOT_VERBOSE", "1");
    }
    announce(command);
    Announced(command)
}

/// An announced child that can only be launched. Configuring it after the
/// announcement does not compile, so `-v` always shows what actually runs.
/// `clippy.toml` forbids launching a [`Command`] any other way.
#[must_use = "an announced command does nothing until it is launched"]
pub struct Announced<'a>(&'a mut Command);

impl<'a> Announced<'a> {
    /// Announce a child whose argv may carry credentials: one fixed line
    /// naming `what`, with no arguments and no change to its environment.
    #[cfg(feature = "internal")]
    pub fn withheld(command: &'a mut Command, what: &str) -> Self {
        if verbose() {
            let _ = writeln!(std::io::stderr().lock(), "+ {what} (arguments withheld)");
        }
        Announced(command)
    }

    #[allow(clippy::disallowed_methods, reason = "the announced launch")]
    pub fn spawn(self) -> std::io::Result<std::process::Child> {
        self.0
            .spawn()
            .map_err(|error| launch_failure(self.0, "could not start", error))
    }

    #[cfg(feature = "internal")]
    #[allow(clippy::disallowed_methods, reason = "the announced launch")]
    pub fn status(self) -> std::io::Result<std::process::ExitStatus> {
        // Spawn and wait separately so only a failed start is named one.
        let mut child = self
            .0
            .spawn()
            .map_err(|error| launch_failure(self.0, "could not start", error))?;
        child.wait()
    }

    #[cfg(any(test, feature = "internal"))]
    #[allow(clippy::disallowed_methods, reason = "the announced launch")]
    pub fn output(self) -> std::io::Result<std::process::Output> {
        // Std's `output` pipes unset streams, so it is not rebuilt from `spawn`;
        // its rare post-start read failure is reported as "could not run".
        self.0
            .output()
            .map_err(|error| launch_failure(self.0, "could not run", error))
    }

    /// Replace this process with the child; returns only on failure.
    #[cfg(feature = "internal")]
    #[allow(clippy::disallowed_methods, reason = "the announced launch")]
    pub fn exec(self) -> std::io::Error {
        let error = std::os::unix::process::CommandExt::exec(self.0);
        launch_failure(self.0, "could not start", error)
    }
}

/// Name the program a launch could not start, keeping the error's kind. A bare
/// program name was searched on PATH, so a missing one shows the PATH searched.
fn launch_failure(command: &Command, what: &str, error: std::io::Error) -> std::io::Error {
    let program = command.get_program().to_string_lossy();
    let hint = if error.kind() == std::io::ErrorKind::NotFound && !program.contains('/') {
        // The child's own PATH when the command sets one, else the inherited one.
        let path = match command.get_envs().find(|(name, _)| *name == "PATH") {
            Some((_, value)) => value.map(std::ffi::OsStr::to_os_string),
            None => std::env::var_os("PATH"),
        };
        match path {
            Some(path) => format!("; not found on PATH={}", path.to_string_lossy()),
            None => "; not found, and PATH is unset".to_owned(),
        }
    } else {
        String::new()
    };
    std::io::Error::new(error.kind(), format!("{program}: {what}: {error}{hint}"))
}

const POOL_COLUMNS: &str = "name,guid,size,allocated,free,health,bootfs";
const DATASET_COLUMNS: &str = "name,type,guid,used,available,referenced,mountpoint,volsize,createtxg,objsetid,mounted,readonly,canmount,origin,encryption,keystatus,encryptionroot,zboot:staging,zboot:pending";
/// `DATASET_COLUMNS` without its user properties: a user property value may
/// hold tabs and newlines, which would let it forge rows in a tab table.
const INVENTORY_COLUMNS: &str = "name,type,guid,used,available,referenced,mountpoint,volsize,createtxg,objsetid,mounted,readonly,canmount,origin,encryption,keystatus,encryptionroot";
const SNAPSHOT_COLUMNS: &str =
    "name,guid,creation,used,referenced,createtxg,objsetid,userrefs,defer_destroy,clones";

/// Execute an observation without changing this invocation's effect flag.
pub fn run(program: &'static str, args: &[String]) -> Result<String, Error> {
    run_with_effect(program, args, false)
}

/// Execute a validated writer. A launched child may mutate before returning an
/// error, so record the effect immediately after spawn and before waiting.
pub fn run_mutating(program: &'static str, args: &[String]) -> Result<String, Error> {
    run_with_effect(program, args, true)
}

fn run_with_effect(
    program: &'static str,
    args: &[String],
    mutating: bool,
) -> Result<String, Error> {
    let failure = |detail| Error::Command {
        program,
        args: args.to_vec(),
        detail,
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if mutating {
        inherit_writer(&mut command)?;
    }
    let child = announced(&mut command)
        .spawn()
        .map_err(|e| failure(e.to_string()))?;
    if mutating {
        crate::engine::effect::mark();
    }
    let output = child
        .wait_with_output()
        .map_err(|e| failure(e.to_string()))?;
    if !output.status.success() {
        return Err(failure(format!(
            "{}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout).map_err(|e| failure(format!("stdout is not UTF-8: {e}")))
}

/// A native property with its reported source, including empty and literal `-` values.
/// Unknown user properties are retained so callers cannot mistake them for absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeProperty {
    pub value: String,
    pub source: String,
}

pub type PropertyInventory = BTreeMap<String, BTreeMap<String, NativeProperty>>;

/// Query every property for exact dataset names. Completeness is checked against
/// requested names and a required native GUID. Callers must compare that GUID to
/// their prior identity and apply their own supported-property admission policy.
/// Native observations are sequential and this function does not lock writers.
pub fn dataset_properties_with(
    names: &[String],
    mut run: impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<PropertyInventory, Error> {
    if names.is_empty() {
        return Err(Error::InvalidScope(
            "property query requires exact dataset names".into(),
        ));
    }
    let mut expected = BTreeSet::new();
    for name in names {
        validate_dataset_name(name)?;
        if !expected.insert(name.as_str()) {
            return Err(Error::InvalidScope("duplicate property query scope".into()));
        }
    }
    let mut args = argv(&["get", "-H", "-p", "-o", "name,property,value,source", "all"]);
    args.extend(names.iter().cloned());
    parse_properties(&run("zfs", &args)?, &expected, "dataset properties")
}

/// Query all native properties of exact imported pools, preserving unknown user
/// properties and sources. Every pool must report a nonzero GUID; the caller
/// compares it with prior inventory before relying on management-property absence.
pub fn pool_properties_with(
    names: &[String],
    mut run: impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<PropertyInventory, Error> {
    if names.is_empty() {
        return Err(Error::InvalidScope(
            "property query requires exact pool names".into(),
        ));
    }
    let mut expected = BTreeSet::new();
    for name in names {
        validate_dataset_name(name)?;
        if name.contains('/') || !expected.insert(name.as_str()) {
            return Err(Error::InvalidScope(
                "invalid or duplicate pool property scope".into(),
            ));
        }
    }
    // One query per pool: OpenZFS 2.4 `zpool get all A B` expands user
    // properties from the first pool only, so B's management properties
    // would silently read as absent.
    let mut result = PropertyInventory::new();
    for name in expected {
        let mut args = argv(&["get", "-H", "-p", "-o", "name,property,value,source", "all"]);
        args.push(name.into());
        let one = BTreeSet::from([name]);
        result.extend(parse_properties(
            &run("zpool", &args)?,
            &one,
            "pool properties",
        )?);
    }
    Ok(result)
}

fn parse_properties(
    output: &str,
    expected: &BTreeSet<&str>,
    subject: &'static str,
) -> Result<PropertyInventory, Error> {
    let mut result: PropertyInventory = BTreeMap::new();
    // User-property values may be empty (for example an explicitly cleared
    // zboot:cmdline). Keep the other columns mandatory and do not relax the
    // shared table parser used for native identity/inventory observations.
    for line in output.strip_suffix('\n').unwrap_or(output).split('\n') {
        let row: Vec<_> = line.split('\t').collect();
        if row.len() != 4 || [0, 1, 3].iter().any(|&i| row[i].is_empty()) {
            return Err(parse_error(
                subject,
                "expected 4 tab-separated columns with nonempty name, property and source",
            ));
        }
        if !expected.contains(row[0]) {
            return Err(Error::Inconsistent(
                "properties outside requested native objects".into(),
            ));
        }
        if row[1].chars().any(char::is_control) || row[3].chars().any(char::is_control) {
            return Err(parse_error(subject, "invalid property/source"));
        }
        if result
            .entry(row[0].into())
            .or_default()
            .insert(
                row[1].into(),
                NativeProperty {
                    value: row[2].into(),
                    source: row[3].into(),
                },
            )
            .is_some()
        {
            return Err(parse_error(subject, "duplicate object/property"));
        }
    }
    for name in expected {
        let guid = result
            .get(*name)
            .and_then(|p| p.get("guid"))
            .ok_or_else(|| parse_error(subject, "missing native GUID"))?;
        if number(&guid.value, "native property GUID")? == 0 {
            return Err(parse_error(subject, "zero native GUID"));
        }
    }
    Ok(result)
}

fn parse_error(subject: &'static str, detail: impl Into<String>) -> Error {
    Error::Parse {
        subject,
        detail: detail.into(),
    }
}
fn number(value: &str, subject: &'static str) -> Result<u64, Error> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(parse_error(
            subject,
            format!("expected unsigned integer, got {value:?}"),
        ));
    }
    value
        .parse()
        .map_err(|_| parse_error(subject, "integer overflow"))
}
fn table<'a>(
    output: &'a str,
    columns: usize,
    subject: &'static str,
) -> Result<Vec<Vec<&'a str>>, Error> {
    if output.is_empty() {
        return Ok(vec![]);
    }
    output
        .strip_suffix('\n')
        .unwrap_or(output)
        .split('\n')
        .map(|line| {
            let row: Vec<_> = line.split('\t').collect();
            if row.len() != columns || row.iter().any(|v| v.is_empty()) {
                return Err(parse_error(
                    subject,
                    format!("expected {columns} nonempty tab-separated columns"),
                ));
            }
            Ok(row)
        })
        .collect()
}
fn rows<'a>(
    output: &'a str,
    columns: usize,
    subject: &'static str,
) -> Result<Vec<Vec<&'a str>>, Error> {
    let rows = table(output, columns, subject)?;
    let mut seen = HashSet::new();
    for row in &rows {
        if !seen.insert(row[0]) {
            return Err(parse_error(subject, format!("duplicate name {}", row[0])));
        }
    }
    Ok(rows)
}
fn in_scope(name: &str, scopes: &[String]) -> bool {
    scopes.is_empty() || scopes.iter().any(|s| contains_dataset(s, name))
}
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).into()).collect()
}
fn pool_args() -> Vec<String> {
    argv(&["list", "-H", "-p", "-o", POOL_COLUMNS])
}
pub(crate) fn imported_pools_with(
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Vec<Pool>, Error> {
    parse_pools(&run("zpool", &pool_args())?)
}
fn dataset_args(request: &InspectRequest, snapshots: bool) -> Vec<String> {
    let mut args = argv(&[
        "list",
        "-H",
        "-p",
        "-t",
        if snapshots {
            "snapshot"
        } else {
            "filesystem,volume"
        },
        "-o",
        if snapshots {
            SNAPSHOT_COLUMNS
        } else {
            DATASET_COLUMNS
        },
    ]);
    if !request.datasets.is_empty() {
        args.push("-r".into());
        args.extend(
            request
                .datasets
                .iter()
                .filter(|scope| {
                    !request
                        .datasets
                        .iter()
                        .any(|parent| *scope != parent && contains_dataset(parent, scope))
                })
                .cloned(),
        );
    }
    args
}
fn parse_pools(output: &str) -> Result<Vec<Pool>, Error> {
    let mut pools = Vec::new();
    let mut guids = HashSet::new();
    for row in rows(output, 7, "pool")? {
        validate_pool_name(row[0]).map_err(|_| {
            parse_error(
                "pool",
                if row[0].contains('/') && validate_dataset_name(row[0]).is_ok() {
                    "pool name contains slash"
                } else {
                    "invalid name"
                },
            )
        })?;
        if !matches!(
            row[5],
            "ONLINE" | "DEGRADED" | "FAULTED" | "OFFLINE" | "REMOVED" | "UNAVAIL" | "SUSPENDED"
        ) {
            return Err(parse_error("pool", format!("unknown health {}", row[5])));
        }
        let guid = Guid::new(number(row[1], "pool GUID")?);
        if guid.get() == 0 {
            return Err(parse_error("pool", "zero pool GUID"));
        }
        if !guids.insert(guid) {
            return Err(parse_error("pool", "duplicate pool GUID"));
        }
        let bootfs = if row[6] == "-" {
            None
        } else {
            validate_dataset_name(row[6])
                .map_err(|_| parse_error("pool bootfs", "invalid dataset"))?;
            if !contains_dataset(row[0], row[6]) {
                return Err(parse_error("pool bootfs", "dataset outside pool"));
            }
            Some(row[6].to_string())
        };
        pools.push(Pool {
            name: row[0].into(),
            guid,
            size_bytes: number(row[2], "pool size")?,
            allocated_bytes: number(row[3], "pool allocated")?,
            free_bytes: number(row[4], "pool free")?,
            health: row[5].into(),
            bootfs,
        });
    }
    Ok(pools)
}
fn optional(value: &str) -> Option<String> {
    (value != "-").then(|| value.to_owned())
}

fn parse_datasets(
    output: &str,
    request: &InspectRequest,
    pools: &[Pool],
) -> Result<Vec<Dataset>, Error> {
    parse_dataset_rows(output, request, pools, true)
}
/// Parse `DATASET_COLUMNS` rows, or `INVENTORY_COLUMNS` rows (without the
/// free-text management user properties) when `management` is false.
fn parse_dataset_rows(
    output: &str,
    request: &InspectRequest,
    pools: &[Pool],
    management: bool,
) -> Result<Vec<Dataset>, Error> {
    // The first pool of a name wins, as a linear scan of `pools` would find it.
    let mut pool_guids = BTreeMap::new();
    for pool in pools {
        pool_guids.entry(pool.name.as_str()).or_insert(pool.guid);
    }
    let mut datasets = Vec::new();
    for row in rows(output, if management { 19 } else { 17 }, "dataset")? {
        validate_dataset_name(row[0]).map_err(|_| parse_error("dataset", "invalid name"))?;
        let pool_name = pool_of(row[0]);
        let Some(&pool_guid) = pool_guids.get(pool_name) else {
            return Err(Error::Inconsistent(format!(
                "dataset outside observed pools/request: {}",
                row[0]
            )));
        };
        if !in_scope(row[0], &request.datasets) {
            return Err(Error::Inconsistent(format!(
                "dataset outside observed pools/request: {}",
                row[0]
            )));
        }
        let (kind, mountpoint, volume_size_bytes) = match row[1] {
            "volume" if row[7] == "-" => {
                return Err(parse_error(
                    "dataset",
                    format!(
                        "volume reports no size, as an incomplete or abandoned receive does: {}",
                        row[0]
                    ),
                ));
            }
            "filesystem" if row[6] != "-" && row[7] == "-" => {
                (DatasetKind::Filesystem, Some(row[6].into()), None)
            }
            "volume" if row[6] == "-" => (
                DatasetKind::Volume,
                None,
                Some(number(row[7], "volume size")?),
            ),
            _ => {
                return Err(parse_error(
                    "dataset",
                    format!("invalid type or type-specific properties: {}", row[0]),
                ));
            }
        };
        let guid = Guid::new(number(row[2], "dataset GUID")?);
        let identity = DatasetIdentity {
            pool_guid,
            guid,
            createtxg: Txg::new(number(row[8], "dataset createtxg")?),
            objsetid: ObjsetId::new(number(row[9], "dataset objsetid")?),
        };
        if !identity.is_complete() {
            return Err(parse_error("dataset identity", "zero native identity"));
        }
        let (mounted, canmount) = match kind {
            DatasetKind::Filesystem => (
                Some(match row[10] {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(parse_error("mounted", "expected yes or no")),
                }),
                Some(match row[12] {
                    "on" => CanMount::On,
                    "off" => CanMount::Off,
                    "noauto" => CanMount::NoAuto,
                    _ => return Err(parse_error("canmount", "unknown value")),
                }),
            ),
            DatasetKind::Volume if row[10] == "-" && row[12] == "-" => (None, None),
            DatasetKind::Volume => {
                return Err(parse_error("dataset", "volume has mount properties"));
            }
        };
        let readonly = match row[11] {
            "on" => true,
            "off" => false,
            _ => return Err(parse_error("readonly", "expected on or off")),
        };
        let origin = optional(row[13]);
        if let Some(origin) = &origin {
            validate_snapshot_name(origin)?;
            if pool_of(origin.split('@').next().unwrap_or(origin)) != pool_name {
                return Err(parse_error("origin", "origin outside pool"));
            }
        }
        let encryption = match row[14] {
            "off" => Encryption::Off,
            "aes-128-ccm" => Encryption::Aes128Ccm,
            "aes-192-ccm" => Encryption::Aes192Ccm,
            "aes-256-ccm" => Encryption::Aes256Ccm,
            "aes-128-gcm" => Encryption::Aes128Gcm,
            "aes-192-gcm" => Encryption::Aes192Gcm,
            "aes-256-gcm" => Encryption::Aes256Gcm,
            _ => return Err(parse_error("encryption", "unknown value")),
        };
        let keystatus = match row[15] {
            "-" if encryption == Encryption::Off => KeyStatus::Unencrypted,
            "available" if encryption != Encryption::Off => KeyStatus::Available,
            "unavailable" if encryption != Encryption::Off => KeyStatus::Unavailable,
            _ => return Err(parse_error("keystatus", "unknown or inconsistent value")),
        };
        let encryptionroot = optional(row[16]);
        match (&encryptionroot, encryption) {
            (None, Encryption::Off) => {}
            (Some(root), encryption) if encryption != Encryption::Off => {
                validate_dataset_name(root)?;
                if !contains_dataset(root, row[0]) {
                    return Err(parse_error("encryptionroot", "root is not an ancestor"));
                }
            }
            _ => {
                return Err(parse_error(
                    "encryptionroot",
                    "inconsistent encryption root",
                ));
            }
        }
        datasets.push(Dataset {
            name: row[0].into(),
            kind,
            guid,
            identity,
            mounted,
            readonly,
            canmount,
            origin,
            encryption,
            keystatus,
            encryptionroot,
            staging: if management { optional(row[17]) } else { None },
            pending: if management { optional(row[18]) } else { None },
            used_bytes: number(row[3], "dataset used")?,
            available_bytes: number(row[4], "dataset available")?,
            referenced_bytes: number(row[5], "dataset referenced")?,
            mountpoint,
            volume_size_bytes,
        });
    }
    let names: HashSet<_> = datasets.iter().map(|d| d.name.as_str()).collect();
    for scope in &request.datasets {
        if !names.contains(scope.as_str()) {
            return Err(Error::MissingScope(scope.clone()));
        }
    }
    if request.datasets.is_empty() {
        for pool in pools {
            if !names.contains(pool.name.as_str()) {
                return Err(Error::Inconsistent(format!(
                    "pool root dataset missing: {}",
                    pool.name
                )));
            }
        }
    }
    Ok(datasets)
}
fn parse_snapshots(
    output: &str,
    pools: &[Pool],
    datasets: &[Dataset],
    exact_parent: Option<&str>,
) -> Result<Vec<Snapshot>, Error> {
    let parents: BTreeMap<_, _> = datasets.iter().map(|d| (d.name.as_str(), d.guid)).collect();
    // The first pool of a name wins, as a linear scan of `pools` would find it.
    let mut pool_guids = BTreeMap::new();
    for pool in pools {
        pool_guids.entry(pool.name.as_str()).or_insert(pool.guid);
    }
    let mut snapshots = Vec::new();
    let mut identities = HashSet::new();
    for row in rows(output, 10, "snapshot")? {
        validate_snapshot_name(row[0]).map_err(|_| parse_error("snapshot", "invalid name"))?;
        let (dataset, _) = row[0].split_once('@').unwrap();
        let Some(dataset_guid) = parents.get(dataset) else {
            return Err(Error::Inconsistent(format!(
                "snapshot parent not observed: {dataset}"
            )));
        };
        if exact_parent.is_some_and(|parent| dataset != parent) {
            return Err(Error::Inconsistent(format!(
                "snapshot outside exact parent: {}",
                row[0]
            )));
        }
        let pool_name = pool_of(dataset);
        let pool_guid = *pool_guids.get(pool_name).ok_or_else(|| {
            Error::Inconsistent(format!("snapshot pool not observed: {pool_name}"))
        })?;
        let guid = Guid::new(number(row[1], "snapshot GUID")?);
        let createtxg = Txg::new(number(row[5], "snapshot createtxg")?);
        let objsetid = ObjsetId::new(number(row[6], "snapshot objsetid")?);
        if guid.get() == 0 || createtxg.get() == 0 || objsetid.get() == 0 {
            return Err(parse_error("snapshot identity", "zero native identity"));
        }
        if !identities.insert((pool_guid, guid, createtxg, objsetid)) {
            return Err(parse_error("snapshot", "duplicate native identity"));
        }
        let creation = number(row[2], "snapshot creation")?;
        if creation > 253402300799 {
            return Err(parse_error(
                "snapshot creation",
                "epoch outside supported UTC years 1970–9999",
            ));
        }
        let defer_destroy = match row[8] {
            "on" => true,
            "off" => false,
            _ => return Err(parse_error("snapshot defer_destroy", "expected on or off")),
        };
        let mut clones = Vec::new();
        if row[9] != "-" {
            let mut seen = HashSet::new();
            for clone in row[9].split(',') {
                validate_dataset_name(clone)
                    .map_err(|_| parse_error("snapshot clones", "invalid dataset"))?;
                if !contains_dataset(pool_name, clone) || !seen.insert(clone) {
                    return Err(parse_error(
                        "snapshot clones",
                        "duplicate or foreign-pool clone",
                    ));
                }
                clones.push(clone.to_owned());
            }
            clones.sort();
        }
        snapshots.push(Snapshot {
            name: row[0].into(),
            guid,
            dataset_guid: *dataset_guid,
            identity: SnapshotIdentity {
                pool_guid,
                guid,
                createtxg,
                objsetid,
            },
            userrefs: number(row[7], "snapshot userrefs")?,
            defer_destroy,
            clones,
            holds: vec![],
            creation_epoch_seconds: creation as i64,
            used_bytes: number(row[3], "snapshot used")?,
            referenced_bytes: number(row[4], "snapshot referenced")?,
        });
    }
    Ok(snapshots)
}
fn populate_holds(
    snapshots: &mut [Snapshot],
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<(), Error> {
    let selected: BTreeSet<_> = snapshots
        .iter()
        .filter(|s| s.userrefs > 0)
        .map(|s| s.name.as_str())
        .collect();
    if selected.is_empty() {
        return Ok(());
    }
    let mut args = argv(&["holds", "-H"]);
    args.extend(selected.iter().map(|name| (*name).to_string()));
    let output = run("zfs", &args)?;
    let mut by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in table(&output, 3, "snapshot holds")? {
        if !selected.contains(row[0]) || row[1].chars().any(char::is_control) {
            return Err(Error::Inconsistent(format!(
                "hold outside observed snapshots or invalid tag: {}",
                row[0]
            )));
        }
        if !by_name
            .entry(row[0].into())
            .or_default()
            .insert(row[1].into())
        {
            return Err(parse_error("snapshot holds", "duplicate snapshot/tag"));
        }
    }
    for snapshot in snapshots.iter_mut().filter(|s| s.userrefs > 0) {
        let holds = by_name.remove(&snapshot.name).unwrap_or_default();
        if holds.len() as u64 != snapshot.userrefs {
            return Err(Error::Inconsistent(format!(
                "snapshot hold count changed or incomplete: {}",
                snapshot.name
            )));
        }
        snapshot.holds = holds.into_iter().collect();
    }
    Ok(())
}

pub fn inspect_with(
    request: &InspectRequest,
    mut run: impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Inspection, Error> {
    for scope in &request.datasets {
        validate_dataset_name(scope)?;
    }
    let pools = imported_pools_with(&mut run)?;
    let mut result = Inspection {
        schema_version: 3,
        imported_only: true,
        non_atomic: true,
        recursive: true,
        requested_datasets: request.datasets.clone(),
        pools: vec![],
        datasets: vec![],
        snapshots: request.snapshots.then(Vec::new),
    };
    if pools.is_empty() {
        if let Some(name) = request.datasets.first() {
            return Err(Error::MissingScope(name.clone()));
        }
        return Ok(result);
    }
    for scope in &request.datasets {
        if !pools.iter().any(|pool| contains_dataset(&pool.name, scope)) {
            return Err(Error::MissingScope(scope.clone()));
        }
    }
    result.datasets = parse_datasets(&run("zfs", &dataset_args(request, false))?, request, &pools)?;
    if let Some(snapshots) = &mut result.snapshots {
        *snapshots = parse_snapshots(
            &run("zfs", &dataset_args(request, true))?,
            &pools,
            &result.datasets,
            None,
        )?;
        populate_holds(snapshots, &mut run)?;
        snapshots.sort_by(|a, b| a.name.cmp(&b.name));
    }
    let selected_pools: BTreeSet<_> = result
        .datasets
        .iter()
        .map(|d| d.name.split('/').next().unwrap())
        .collect();
    result.pools = pools
        .into_iter()
        .filter(|p| selected_pools.contains(p.name.as_str()))
        .collect();
    result.pools.sort_by(|a, b| a.name.cmp(&b.name));
    result.datasets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

/// One root's subtree from successful native queries. `pool` is the root's
/// imported pool, or `None` when no pool of that name is imported. An empty
/// dataset list is proven absence. Snapshots and properties are `None` when
/// not requested; when requested they cover the whole present subtree.
#[derive(Debug, Clone)]
pub(crate) struct RootInventory {
    pub(crate) pool: Option<Guid>,
    pub(crate) datasets: Vec<Dataset>,
    pub(crate) snapshots: Option<Vec<Snapshot>>,
    pub(crate) properties: Option<PropertyInventory>,
}

/// Inventory ROOT and its descendants without a writer lock.
///
/// Presence is decided from a successful name-only listing of the root's pool
/// down to the root's depth, never from a failed exact-name command. Only a
/// dataset at the root's depth can be the root, so the depth limit drops
/// nothing that decides absence, and the name-only columns keep an unrelated
/// broken dataset elsewhere in the pool from failing the inventory. The root's
/// subtree is then listed in full. Snapshot and property queries are
/// root-scoped and must match that listing; when either ran, the subtree and
/// the pool are listed again and must be unchanged, so a member created,
/// destroyed or replaced at its name between queries is an error.
pub(crate) fn inventory_with(
    root: &str,
    snapshots: bool,
    properties: bool,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<RootInventory, Error> {
    validate_dataset_name(root)?;
    let pool_name = root.split('/').next().unwrap();
    let mut absent = RootInventory {
        pool: None,
        datasets: vec![],
        snapshots: snapshots.then(Vec::new),
        properties: properties.then(PropertyInventory::new),
    };
    let pools = root_pool(pool_name, run)?;
    let Some(pool) = pools.first() else {
        return Ok(absent);
    };
    absent.pool = Some(pool.guid);
    let depth = root.matches('/').count().to_string();
    let names = run(
        "zfs",
        &argv(&[
            "list",
            "-H",
            "-t",
            "filesystem,volume",
            "-o",
            "name",
            "-d",
            &depth,
            pool_name,
        ]),
    )?;
    let mut seen = BTreeSet::new();
    for row in table(&names, 1, "dataset names")? {
        validate_dataset_name(row[0]).map_err(|_| parse_error("dataset names", "invalid name"))?;
        if !contains_dataset(pool_name, row[0])
            || row[0].matches('/').count() > root.matches('/').count()
            || !seen.insert(row[0])
        {
            return Err(Error::Inconsistent(format!(
                "dataset outside the depth-limited pool listing or duplicated: {}",
                row[0]
            )));
        }
    }
    if !seen.contains(pool_name) {
        return Err(Error::Inconsistent(format!(
            "pool root dataset missing: {pool_name}"
        )));
    }
    if !seen.contains(root) {
        return Ok(absent);
    }
    let datasets = subtree(root, &pools, run)?;
    let snapshots = if snapshots {
        let scope = InspectRequest::new(vec![root.into()], false)?;
        let mut observed = parse_snapshots(
            &run("zfs", &dataset_args(&scope, true))?,
            &pools,
            &datasets,
            None,
        )?;
        populate_holds(&mut observed, run)?;
        observed.sort_by(|a, b| a.name.cmp(&b.name));
        Some(observed)
    } else {
        None
    };
    let properties = if properties {
        let args = argv(&[
            "get",
            "-H",
            "-p",
            "-r",
            "-t",
            "filesystem,volume",
            "-o",
            "name,property,value,source",
            "all",
            root,
        ]);
        let expected: BTreeSet<_> = datasets.iter().map(|d| d.name.as_str()).collect();
        let observed = parse_properties(&run("zfs", &args)?, &expected, "dataset properties")?;
        for dataset in &datasets {
            let guid = &observed[&dataset.name]["guid"].value;
            if number(guid, "property GUID")? != dataset.guid.get() {
                return Err(Error::Inconsistent(format!(
                    "dataset incarnation changed during property observation: {}",
                    dataset.name
                )));
            }
        }
        Some(observed)
    } else {
        None
    };
    if snapshots.is_some() || properties.is_some() {
        // Snapshot rows are bound to their parents by name only, so confirm
        // every parent incarnation outlived the queries that followed it.
        let again = subtree(root, &pools, run)?;
        if again.len() != datasets.len()
            || again
                .iter()
                .zip(&datasets)
                .any(|(a, b)| a.name != b.name || a.identity != b.identity || a.kind != b.kind)
        {
            return Err(Error::Inconsistent(format!(
                "dataset tree changed during inventory: {}",
                root
            )));
        }
    }
    if root_pool(pool_name, run)?.first().map(|p| p.guid) != Some(pool.guid) {
        return Err(Error::Inconsistent(format!(
            "pool changed during inventory: {pool_name}"
        )));
    }
    Ok(RootInventory {
        pool: Some(pool.guid),
        datasets,
        snapshots,
        properties,
    })
}

fn root_pool(
    pool_name: &str,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Vec<Pool>, Error> {
    Ok(imported_pools_with(run)?
        .into_iter()
        .filter(|pool| pool.name == pool_name)
        .collect())
}

/// The full rows of ROOT and its descendants, sorted by name.
fn subtree(
    root: &str,
    pools: &[Pool],
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Vec<Dataset>, Error> {
    let scope = InspectRequest::new(vec![root.into()], false)?;
    let mut args = argv(&[
        "list",
        "-H",
        "-p",
        "-t",
        "filesystem,volume",
        "-o",
        INVENTORY_COLUMNS,
        "-r",
    ]);
    args.push(root.into());
    let mut datasets = parse_dataset_rows(&run("zfs", &args)?, &scope, pools, false)?;
    datasets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(datasets)
}

/// Read explicit recursive roots and exact authority ancestors without a
/// global pool/dataset/snapshot sweep. Dependencies are present in the result,
/// while requested_datasets remains the selected read-only scope's roots.
#[cfg(feature = "internal")]
pub(crate) fn inspect_readonly_scope_with(
    selected_roots: &[String],
    recursive_roots: &[String],
    exact_names: &[String],
    pool_names: &[String],
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Inspection, Error> {
    if selected_roots.is_empty() || recursive_roots.is_empty() || pool_names.is_empty() {
        return Err(Error::InvalidScope(
            "empty read-only inventory scope".into(),
        ));
    }
    for name in pool_names {
        validate_dataset_name(name)?;
        if name.contains('/') {
            return Err(Error::InvalidScope(
                "read-only inventory requires exact pool names".into(),
            ));
        }
    }
    let mut args = pool_args();
    args.extend(pool_names.iter().cloned());
    let pools = parse_pools(&run("zpool", &args)?)?;
    if pools
        .iter()
        .map(|pool| pool.name.clone())
        .collect::<BTreeSet<_>>()
        != pool_names.iter().cloned().collect()
    {
        return Err(Error::Inconsistent(
            "read-only inventory pool scope changed".into(),
        ));
    }
    let recursive = InspectRequest::new(recursive_roots.to_vec(), false)?;
    let mut datasets = parse_datasets(
        &run("zfs", &dataset_args(&recursive, false))?,
        &recursive,
        &pools,
    )?;
    if !exact_names.is_empty() {
        let exact = InspectRequest::new(exact_names.to_vec(), false)?;
        let mut args = argv(&[
            "list",
            "-H",
            "-p",
            "-t",
            "filesystem,volume",
            "-o",
            DATASET_COLUMNS,
        ]);
        args.extend(exact_names.iter().cloned());
        let ancestors = parse_datasets(&run("zfs", &args)?, &exact, &pools)?;
        if ancestors
            .iter()
            .any(|dataset| !exact_names.contains(&dataset.name))
        {
            return Err(Error::Inconsistent(
                "recursive rows returned for exact inventory ancestors".into(),
            ));
        }
        datasets.extend(ancestors);
    }
    datasets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Inspection {
        schema_version: 3,
        imported_only: true,
        non_atomic: true,
        recursive: true,
        requested_datasets: selected_roots.to_vec(),
        pools,
        datasets,
        snapshots: None,
    })
}

/// Absence comes only from successful inventory, never from interpreting a
/// failed exact-name command. Snapshot history stays scoped to one parent.
pub fn observe_with(
    name: &str,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Snapshot, Error> {
    validate_snapshot_name(name)?;
    let parent = name.split_once('@').unwrap().0;
    let inventory = inspect_with(&InspectRequest::new(vec![], false)?, &mut *run)?;
    if !inventory.datasets.iter().any(|d| d.name == parent) {
        return Err(Error::NotFound(name.into()));
    }
    let args = argv(&[
        "list",
        "-H",
        "-p",
        "-d",
        "1",
        "-t",
        "snapshot",
        "-o",
        SNAPSHOT_COLUMNS,
        parent,
    ]);
    let mut snapshots = parse_snapshots(
        &run("zfs", &args)?,
        &inventory.pools,
        &inventory.datasets,
        Some(parent),
    )?;
    let Some(mut snapshot) = snapshots.drain(..).find(|s| s.name == name) else {
        return Err(Error::NotFound(name.into()));
    };
    populate_holds(std::slice::from_mut(&mut snapshot), run)?;
    Ok(snapshot)
}

pub fn resolve_with(
    point: &SnapshotRef,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Snapshot, Error> {
    validate_snapshot_name(&point.name)?;
    match observe_with(&point.name, run) {
        Ok(snapshot) => {
            if snapshot.identity != point.identity || snapshot.dataset_guid != point.dataset_guid {
                return Err(Error::Inconsistent(format!(
                    "snapshot name now identifies a different point: {}",
                    point.name
                )));
            }
            return Ok(snapshot);
        }
        Err(Error::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    // The dataset or pool may have been renamed. Find the original imported
    // pool by GUID, then scan only that pool for the exact native identity.
    let pools = parse_pools(&run("zpool", &pool_args())?)?;
    let Some(pool) = pools.iter().find(|p| p.guid == point.identity.pool_guid) else {
        return Err(Error::Inconsistent(
            "expected snapshot pool is not imported; absence is unproven".into(),
        ));
    };
    let inventory = inspect_with(
        &InspectRequest::new(vec![pool.name.clone()], true)?,
        &mut *run,
    )?;
    let mut matches = inventory
        .snapshots
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.identity == point.identity);
    let Some(snapshot) = matches.next() else {
        return Err(Error::NotFound(point.name.clone()));
    };
    if matches.next().is_some() || snapshot.dataset_guid != point.dataset_guid {
        return Err(Error::Inconsistent(format!(
            "snapshot identity moved to another parent or is ambiguous: {}",
            point.name
        )));
    }
    Ok(snapshot)
}

/// Observe the hidden IV-set GUID for an exact local snapshot incarnation.
/// All native queries are sequential; exclusive execution and fresh drift checks
/// remain the caller's responsibility. The property is opt-in because backend
/// support must be earned with native acceptance, not inferred from CLI parsing.
#[cfg(feature = "internal")]
pub fn observe_ivset_with(
    point: &SnapshotRef,
    mut run: impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<SnapshotIvset, Error> {
    let before = resolve_with(point, &mut run)?;
    let props = exact_properties_with(
        &before.name,
        &["guid", "createtxg", "objsetid", "ivsetguid"],
        &mut run,
    )?;
    check_property_identity(
        &props,
        before.identity.guid,
        before.identity.createtxg,
        before.identity.objsetid,
    )?;
    let value = number(&props["ivsetguid"], "snapshot IV-set GUID")?;
    if value == 0 {
        return Err(parse_error(
            "snapshot IV-set GUID",
            "zero IV-set identity is not encryption evidence",
        ));
    }
    let after = resolve_with(&before.point(), &mut run)?;
    if after.name != before.name {
        return Err(Error::Inconsistent(
            "snapshot renamed during IV-set observation".into(),
        ));
    }
    Ok(SnapshotIvset {
        point: after.point(),
        ivset_guid: Guid::new(value),
    })
}

/// Query `written@<exact base>` for an observed local head. `latest` is not a
/// special snapshot name; callers select a real base from snapshot inventory.
/// Positive bytes are evidence of newly referenced writes; zero is only an
/// accounting observation, never permission to overwrite or proof of no change.
/// Identity checks detect replacement, but do not fence concurrent head writes.
#[cfg(feature = "internal")]
pub fn observe_written_since_with(
    dataset: &Dataset,
    base: &SnapshotRef,
    mut run: impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<WrittenSince, Error> {
    validate_snapshot_name(&base.name)?;
    if base.name.split_once('@').unwrap().0 != dataset.name
        || base.dataset_guid != dataset.guid
        || base.identity.pool_guid != dataset.identity.pool_guid
    {
        return Err(Error::Inconsistent(
            "written base does not belong to the observed head".into(),
        ));
    }
    revalidate_head(dataset, &mut run)?;
    let before = resolve_with(base, &mut run)?;
    if before.name != base.name {
        return Err(Error::Inconsistent(
            "written base moved from its selected name".into(),
        ));
    }
    let property = format!("written@{}", before.name.split_once('@').unwrap().1);
    let props = exact_properties_with(
        &dataset.name,
        &["guid", "createtxg", "objsetid", &property],
        &mut run,
    )?;
    check_property_identity(
        &props,
        dataset.identity.guid,
        dataset.identity.createtxg,
        dataset.identity.objsetid,
    )?;
    let referenced_new_bytes = number(&props[&property], "written bytes")?;
    let after = resolve_with(&before.point(), &mut run)?;
    if after.name != before.name {
        return Err(Error::Inconsistent(
            "written base renamed during observation".into(),
        ));
    }
    revalidate_head(dataset, &mut run)?;
    Ok(WrittenSince {
        dataset_name: dataset.name.clone(),
        dataset_identity: dataset.identity.clone(),
        base: after.point(),
        referenced_new_bytes,
    })
}

#[cfg(feature = "internal")]
fn revalidate_head(
    dataset: &Dataset,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<(), Error> {
    let observed = inspect_with(
        &InspectRequest::new(vec![dataset.name.clone()], false)?,
        run,
    )?;
    let head = observed
        .datasets
        .iter()
        .find(|head| head.name == dataset.name)
        .ok_or_else(|| Error::MissingScope(dataset.name.clone()))?;
    if head.identity != dataset.identity {
        return Err(Error::Inconsistent(
            "dataset head identity changed during written observation".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "internal")]
fn exact_properties_with(
    name: &str,
    properties: &[&str],
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<BTreeMap<String, String>, Error> {
    let args = argv(&[
        "get",
        "-H",
        "-p",
        "-o",
        "name,property,value",
        &properties.join(","),
        name,
    ]);
    let output = run("zfs", &args)?;
    let mut result = BTreeMap::new();
    for row in table(&output, 3, "exact properties")? {
        if row[0] != name || !properties.contains(&row[1]) {
            return Err(Error::Inconsistent(
                "property outside exact requested object/property set".into(),
            ));
        }
        if result.insert(row[1].into(), row[2].into()).is_some() {
            return Err(parse_error("exact properties", "duplicate property"));
        }
    }
    if result.len() != properties.len() {
        return Err(parse_error(
            "exact properties",
            "incomplete property observation",
        ));
    }
    Ok(result)
}

#[cfg(feature = "internal")]
fn check_property_identity(
    props: &BTreeMap<String, String>,
    guid: Guid,
    createtxg: Txg,
    objsetid: ObjsetId,
) -> Result<(), Error> {
    if number(&props["guid"], "property GUID")? != guid.get()
        || number(&props["createtxg"], "property createtxg")? != createtxg.get()
        || number(&props["objsetid"], "property objsetid")? != objsetid.get()
    {
        return Err(Error::Inconsistent(
            "native identity changed during property observation".into(),
        ));
    }
    Ok(())
}

/// Admission is deliberately independent of names and inferred pair roles.
/// Ordinary read-only datasets and clones can be protected. Boot-owned or other
/// managed topologies need their owning adapter, not a generic hold shortcut.
pub(crate) fn admit_with(
    snapshot: &Snapshot,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<(), Error> {
    let current = observe_with(&snapshot.name, run)?;
    if current.identity != snapshot.identity || current.dataset_guid != snapshot.dataset_guid {
        return Err(Error::Inconsistent(format!(
            "snapshot changed before admission: {}",
            snapshot.name
        )));
    }
    if current.defer_destroy {
        return Err(Error::Inconsistent(format!(
            "snapshot is marked for deferred destruction: {}",
            snapshot.name
        )));
    }
    let parent = snapshot.name.split_once('@').unwrap().0;
    let pool_name = parent.split('/').next().unwrap();
    let pools = parse_pools(&run("zpool", &pool_args())?)?;
    let pool = pools
        .iter()
        .find(|p| p.name == pool_name && p.guid == snapshot.identity.pool_guid)
        .ok_or_else(|| Error::Inconsistent("snapshot pool changed before admission".into()))?;
    if pool.bootfs.as_deref().is_some_and(|bootfs| {
        let region = bootfs.rsplit_once('/').map_or(bootfs, |(base, _)| base);
        contains_dataset(region, parent)
    }) {
        return Err(Error::Inconsistent(format!(
            "snapshot belongs to bootfs: {}",
            snapshot.name
        )));
    }
    // Pool roles are native pool properties, not dataset properties. Bind this
    // complete property observation to the expected imported pool before
    // treating absence of management metadata as admission evidence.
    let observed = pool_properties_with(&[pool_name.into()], &mut *run)?;
    let pool_properties = &observed[pool_name];
    for property in pool_properties.keys() {
        if property != crate::engine::management::RETIRED_MARKER
            && crate::engine::management::managed_key(property)
        {
            return Err(Error::Inconsistent(format!(
                "managed pool property requires its owning adapter: {pool_name} {property}"
            )));
        }
    }
    let observed_guid = Guid::new(number(
        &pool_properties["guid"].value,
        "pool admission GUID",
    )?);
    if observed_guid != snapshot.identity.pool_guid {
        return Err(Error::Inconsistent(
            "pool changed during admission property observation".into(),
        ));
    }
    let mut ancestors = Vec::new();
    let mut cursor = parent;
    loop {
        ancestors.push(cursor.to_string());
        let Some((next, _)) = cursor.rsplit_once('/') else {
            break;
        };
        cursor = next;
    }
    ancestors.reverse();
    let properties = dataset_properties_with(&ancestors, &mut *run)?;
    for (name, props) in &properties {
        for property in props.keys() {
            if property != crate::engine::management::RETIRED_MARKER
                && crate::engine::management::managed_key(property)
            {
                return Err(Error::Inconsistent(format!(
                    "managed property requires its owning adapter: {name} {property}"
                )));
            }
        }
    }
    // A successful but incomplete/mismatched property observation is not
    // permission to assume that a missing management property was unset.
    for ancestor in &ancestors {
        let props = properties.get(ancestor.as_str()).ok_or_else(|| {
            Error::Inconsistent(format!("missing ancestor property observation: {ancestor}"))
        })?;
        let guid = Guid::new(number(
            &props
                .get("guid")
                .ok_or_else(|| parse_error("dataset admission properties", "missing guid"))?
                .value,
            "ancestor GUID",
        )?);
        if ancestor == parent && guid != snapshot.dataset_guid {
            return Err(Error::Inconsistent(
                "snapshot parent changed before admission".into(),
            ));
        }
        if !matches!(
            props.get("type").map(|property| property.value.as_str()),
            Some("filesystem") | Some("volume")
        ) {
            return Err(parse_error(
                "dataset admission properties",
                "missing/invalid type",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const POOL: &str = "tank\t123\t1000\t100\t900\tONLINE\t-\n";
    const DATA: &str =
        "tank\tfilesystem\t456\t100\t900\t80\t/tank\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\n";
    const SNAP: &str = "tank@s\t789\t1700000000\t0\t20\t30\t40\t0\toff\t-\n";
    fn point() -> SnapshotRef {
        SnapshotRef {
            name: "tank@s".into(),
            dataset_guid: Guid::new(456),
            identity: SnapshotIdentity {
                pool_guid: Guid::new(123),
                guid: Guid::new(789),
                createtxg: Txg::new(30),
                objsetid: ObjsetId::new(40),
            },
        }
    }
    #[test]
    fn a_program_that_cannot_start_is_named_and_keeps_its_error_kind() {
        let mut command = Command::new("zboot-no-such-program");
        command.env("PATH", "/nonexistent-zboot-path");
        let error = announced(&mut command).spawn().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .starts_with("zboot-no-such-program: could not start: ")
                && error
                    .to_string()
                    .ends_with("; not found on PATH=/nonexistent-zboot-path"),
            "{error}"
        );
        let error = announced(&mut Command::new("/nonexistent-zboot-path/zdb"))
            .output()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .starts_with("/nonexistent-zboot-path/zdb: could not run: ")
                && !error.to_string().contains("PATH"),
            "{error}"
        );
        let failure = run("zboot-no-such-program", &[]).unwrap_err().to_string();
        assert!(
            failure.contains("zboot-no-such-program: could not start"),
            "{failure}"
        );
    }

    fn responses<'a>(
        outputs: &'a [&'a str],
    ) -> impl FnMut(&'static str, &[String]) -> Result<String, Error> + 'a {
        let mut outputs = outputs.iter();
        move |program, args| {
            assert!(matches!(program, "zpool" | "zfs"));
            assert!(matches!(args[0].as_str(), "list" | "get" | "holds"));
            Ok(outputs.next().expect("unexpected native call").to_string())
        }
    }
    #[test]
    fn schema_three_identity_is_exact_and_unknown_history_stays_unknown() {
        let output = [POOL, DATA, SNAP];
        let got = inspect_with(
            &InspectRequest::new(vec![], true).unwrap(),
            responses(&output),
        )
        .unwrap();
        assert_eq!(got.schema_version, 3);
        assert_eq!(got.snapshots.unwrap()[0].point(), point());
        let output = [POOL, DATA];
        assert!(
            inspect_with(
                &InspectRequest::new(vec![], false).unwrap(),
                responses(&output)
            )
            .unwrap()
            .snapshots
            .is_none()
        );
    }
    #[test]
    fn holds_are_batched_exact_and_count_checked() {
        let held = SNAP.replace("\t0\toff\t-", "\t2\toff\t-");
        let output = [
            POOL,
            DATA,
            held.as_str(),
            "tank@s\towner-a\t1\ntank@s\towner-b\t2\n",
        ];
        let got = observe_with("tank@s", &mut responses(&output)).unwrap();
        assert_eq!(got.holds, ["owner-a", "owner-b"]);
        let output = [POOL, DATA, held.as_str(), "tank@s\towner-a\t1\n"];
        assert!(matches!(
            observe_with("tank@s", &mut responses(&output)),
            Err(Error::Inconsistent(_))
        ));
    }
    #[test]
    fn resolver_refuses_name_reuse_and_unavailable_pool_but_follows_rename() {
        let reused = SNAP.replace("\t789\t", "\t790\t");
        let output = [POOL, DATA, reused.as_str()];
        assert!(matches!(
            resolve_with(&point(), &mut responses(&output)),
            Err(Error::Inconsistent(_))
        ));
        let output = ["", ""];
        assert!(matches!(
            resolve_with(&point(), &mut responses(&output)),
            Err(Error::Inconsistent(_))
        ));
        let renamed = SNAP.replace("tank@s", "tank@renamed");
        let output = [POOL, DATA, "", POOL, POOL, DATA, renamed.as_str()];
        assert_eq!(
            resolve_with(&point(), &mut responses(&output))
                .unwrap()
                .name,
            "tank@renamed"
        );
    }
    #[test]
    fn metadata_and_deferred_state_block_generic_admission() {
        let snapshot = parse_snapshots(
            SNAP,
            &parse_pools(POOL).unwrap(),
            &parse_datasets(
                DATA,
                &InspectRequest::new(vec![], false).unwrap(),
                &parse_pools(POOL).unwrap(),
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .remove(0);
        let ordinary = "tank\tguid\t456\t-\ntank\ttype\tfilesystem\t-\ntank\treadonly\ton\tlocal\n";
        let pool_properties = "tank\tguid\t123\t-\n";
        let output = [POOL, DATA, SNAP, POOL, pool_properties, ordinary];
        admit_with(&snapshot, &mut responses(&output)).unwrap();
        let managed = format!("{ordinary}tank\tzboot:unknown\t-\tlocal\n");
        let output = [POOL, DATA, SNAP, POOL, pool_properties, managed.as_str()];
        assert!(admit_with(&snapshot, &mut responses(&output)).is_err());
        let deferred = SNAP.replace("\toff\t", "\ton\t");
        let output = [POOL, DATA, deferred.as_str()];
        assert!(admit_with(&snapshot, &mut responses(&output)).is_err());
    }
    #[test]
    fn pool_admission_properties_are_guid_bound_and_fail_closed() {
        let snapshot = observe_with("tank@s", &mut responses(&[POOL, DATA, SNAP])).unwrap();
        for properties in [
            "",
            "tank\tguid\t999\t-\n",
            "tank\tguid\t123\t-\ntank\tguid\t123\t-\n",
            "other\tguid\t123\t-\n",
            "tank\tguid\t123\n",
            "tank\tguid\t123\t-\ntank\tzboot:role\troot\tlocal\n",
            "tank\tguid\t123\t-\ntank\tzboot:future\t-\tlocal\n",
        ] {
            let output = [POOL, DATA, SNAP, POOL, properties];
            assert!(
                admit_with(&snapshot, &mut responses(&output)).is_err(),
                "{properties:?}"
            );
        }
        let output = [POOL, DATA, SNAP, POOL];
        let mut fixture = responses(&output);
        let result = admit_with(&snapshot, &mut |program, args| {
            if program == "zpool" && args[0] == "get" {
                return Err(Error::Command {
                    program,
                    args: args.to_vec(),
                    detail: "denied".into(),
                });
            }
            fixture(program, args)
        });
        assert!(matches!(result, Err(Error::Command { .. })));
    }
    #[test]
    fn invalid_scope_and_native_failure_never_become_absence() {
        assert!(
            observe_with("tank@bad/name", &mut |_, _| panic!(
                "invalid name reached backend"
            ))
            .is_err()
        );
        let mut failed = |program, args: &[String]| {
            Err(Error::Command {
                program,
                args: args.to_vec(),
                detail: "denied".into(),
            })
        };
        assert!(matches!(
            resolve_with(&point(), &mut failed),
            Err(Error::Command { .. })
        ));
    }
    #[test]
    fn dataset_head_identity_and_native_properties_are_observed() {
        let inventory = inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            responses(&[POOL, DATA]),
        )
        .unwrap();
        let dataset = &inventory.datasets[0];
        assert_eq!(
            &dataset.identity,
            &DatasetIdentity {
                pool_guid: Guid::new(123),
                guid: Guid::new(456),
                createtxg: Txg::new(5),
                objsetid: ObjsetId::new(6),
            }
        );
        assert_eq!(&dataset.mounted, &Some(false));
        assert_eq!(&dataset.canmount, &Some(CanMount::On));
        assert_eq!(&dataset.encryption, &Encryption::Off);
        assert_eq!(&dataset.keystatus, &KeyStatus::Unencrypted);
        assert_eq!(&dataset.pending, &None);
        assert_eq!(
            serde_json::to_value(dataset).unwrap()["identity"]["guid"],
            "456"
        );
    }

    fn changed_dataset_column(column: usize, value: &str) -> String {
        let mut row: Vec<_> = DATA.trim_end().split('\t').collect();
        row[column] = value;
        format!("{}\n", row.join("\t"))
    }

    #[test]
    fn unknown_or_inconsistent_native_properties_never_become_safe_defaults() {
        let pools = parse_pools(POOL).unwrap();
        let request = InspectRequest::new(vec![], false).unwrap();
        for (column, value) in [
            (8, "0"),
            (9, "?"),
            (10, "-"),
            (11, "unknown"),
            (12, "future"),
            (13, "elsewhere@s"),
            (14, "future-cipher"),
            (15, "available"),
            (16, "tank"),
        ] {
            assert!(
                parse_datasets(&changed_dataset_column(column, value), &request, &pools).is_err(),
                "{column}: {value}"
            );
        }
        let legacy = DATA.split('\t').take(8).collect::<Vec<_>>().join("\t");
        assert!(parse_datasets(&legacy, &request, &pools).is_err());
    }

    #[test]
    fn encrypted_and_management_observations_preserve_values() {
        let mut fields: Vec<_> = DATA.trim_end().split('\t').collect();
        fields[14] = "aes-256-gcm";
        fields[15] = "unavailable";
        fields[16] = "tank";
        fields[17] = "archive";
        fields[18] = "operation-id";
        let datasets = parse_datasets(
            &fields.join("\t"),
            &InspectRequest::new(vec![], false).unwrap(),
            &parse_pools(POOL).unwrap(),
        )
        .unwrap();
        let dataset = &datasets[0];
        assert_eq!(&dataset.keystatus, &KeyStatus::Unavailable);
        assert_eq!(dataset.staging.as_deref(), Some("archive"));
        assert_eq!(dataset.pending.as_deref(), Some("operation-id"));
    }

    #[test]
    fn property_query_retains_unknown_management_and_native_sources() {
        let names = vec!["tank".into()];
        let output = "tank\tguid\t456\t-\ntank\tzboot:future\t-\tlocal\n";
        let props = dataset_properties_with(&names, |program, args| {
            assert_eq!(program, "zfs");
            assert_eq!(args.last().unwrap(), "tank");
            assert!(args.iter().any(|arg| arg == "all"));
            Ok(output.into())
        })
        .unwrap();
        assert_eq!(props["tank"]["zboot:future"].value, "-");
        assert_eq!(props["tank"]["zboot:future"].source, "local");
        for invalid in [
            "",
            "tank\tguid\t0\t-\n",
            "elsewhere\tguid\t456\t-\n",
            "tank\tguid\t456\t-\ntank\tguid\t456\t-\n",
        ] {
            assert!(dataset_properties_with(&names, |_, _| Ok(invalid.into())).is_err());
        }
    }
    #[test]
    fn property_query_preserves_empty_value_as_present_local_evidence() {
        let names = vec!["tank/ROOT/os".into()];
        let output = "tank/ROOT/os\tguid\t456\t-\ntank/ROOT/os\tzboot:cmdline\t\tlocal\ntank/ROOT/os\tuser:dash\t-\tlocal\n";
        let props = dataset_properties_with(&names, |program, args| {
            assert_eq!(program, "zfs");
            assert_eq!(
                args,
                &argv(&[
                    "get",
                    "-H",
                    "-p",
                    "-o",
                    "name,property,value,source",
                    "all",
                    "tank/ROOT/os"
                ])
            );
            Ok(output.into())
        })
        .unwrap();
        let props = &props["tank/ROOT/os"];
        assert_eq!(props["zboot:cmdline"].value, "");
        assert_eq!(props["zboot:cmdline"].source, "local");
        assert_eq!(props["user:dash"].value, "-");
        assert!(!props.contains_key("user:missing"));
    }

    #[test]
    fn property_query_only_allows_empty_value_and_keeps_native_inventory_strict() {
        let names = vec!["tank".into()];
        for row in [
            "\tzboot:cmdline\t\tlocal\n",
            "tank\t\t\tlocal\n",
            "tank\tzboot:cmdline\t\t\n",
            "tank\tzboot:cmdline\tlocal\n",
            "tank\tzboot:cmdline\t\tlocal\textra\n",
            "tank\tzboot:cmdline\t\tlo\rcal\n",
            "tank\tzboot:cmdline\t\tlocal\n\n",
        ] {
            let output = format!("tank\tguid\t456\t-\n{row}");
            assert!(
                dataset_properties_with(&names, |_, _| Ok(output.clone())).is_err(),
                "{row:?}"
            );
        }
        for guid in ["", "-", "0", "not-a-guid", "18446744073709551616"] {
            let output = format!("tank\tguid\t{guid}\t-\ntank\tzboot:cmdline\t\tlocal\n");
            assert!(
                dataset_properties_with(&names, |_, _| Ok(output.clone())).is_err(),
                "{guid:?}"
            );
        }
        assert!(table("tank\tzboot:cmdline\t\tlocal\n", 4, "inventory").is_err());
        assert!(
            parse_datasets(
                &changed_dataset_column(17, ""),
                &InspectRequest::new(vec![], false).unwrap(),
                &parse_pools(POOL).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn volume_mount_absence_is_typed_and_head_recreation_changes_identity() {
        let request = InspectRequest::new(vec![], false).unwrap();
        let pools = parse_pools(POOL).unwrap();
        let original = parse_datasets(DATA, &request, &pools).unwrap();
        let changed = parse_datasets(&changed_dataset_column(9, "7"), &request, &pools).unwrap();
        assert_ne!(&original[0].identity, &changed[0].identity);
        assert_eq!(&original[0].guid, &changed[0].guid);
        let mut fields: Vec<_> = DATA.trim_end().split('\t').collect();
        fields[1] = "volume";
        fields[6] = "-";
        fields[7] = "1024";
        fields[10] = "-";
        fields[12] = "-";
        let volume = parse_datasets(&fields.join("\t"), &request, &pools).unwrap();
        assert_eq!(&volume[0].mounted, &None);
        assert_eq!(&volume[0].canmount, &None);
        assert_eq!(&volume[0].volume_size_bytes, &Some(1024));
    }
    #[cfg(feature = "internal")]
    fn exact_property_fixture<'a>(
        property_output: &'a str,
    ) -> impl FnMut(&'static str, &[String]) -> Result<String, Error> + 'a {
        move |program, args| match (program, args[0].as_str()) {
            ("zpool", "list") => Ok(POOL.into()),
            ("zfs", "list") if args.iter().any(|arg| arg == "filesystem,volume") => Ok(DATA.into()),
            ("zfs", "list") => Ok(SNAP.into()),
            ("zfs", "get") => {
                assert!(args.iter().any(|arg| arg == "name,property,value"));
                assert!(
                    args.iter()
                        .any(|arg| arg == "guid,createtxg,objsetid,ivsetguid"
                            || arg == "guid,createtxg,objsetid,written@s")
                );
                Ok(property_output.into())
            }
            _ => panic!("unexpected command: {program} {args:?}"),
        }
    }

    #[cfg(feature = "internal")]
    const IVSET: &str = "tank@s\tguid\t789\ntank@s\tcreatetxg\t30\ntank@s\tobjsetid\t40\ntank@s\tivsetguid\t18446744073709551615\n";
    #[cfg(feature = "internal")]
    const WRITTEN: &str =
        "tank\tguid\t456\ntank\tcreatetxg\t5\ntank\tobjsetid\t6\ntank\twritten@s\t0\n";

    #[cfg(feature = "internal")]
    #[test]
    fn explicit_ivset_observation_preserves_exact_identity_and_full_u64() {
        let observed = observe_ivset_with(&point(), exact_property_fixture(IVSET)).unwrap();
        assert_eq!(observed.point, point());
        assert_eq!(observed.ivset_guid, Guid::new(u64::MAX));
        assert_eq!(
            serde_json::to_value(observed).unwrap()["ivset_guid"],
            "18446744073709551615"
        );
    }

    #[cfg(feature = "internal")]
    #[test]
    fn ivset_unknown_zero_incomplete_and_substituted_properties_refuse() {
        for output in [
            String::new(),
            IVSET.replace("18446744073709551615", "-"),
            IVSET.replace("18446744073709551615", "0"),
            IVSET.replace("18446744073709551615", "18446744073709551616"),
            IVSET.replace("\t789\n", "\t790\n"),
            IVSET.replace("\t30\n", "\t31\n"),
            IVSET.replace("\t40\n", "\t41\n"),
            IVSET.replace("tank@s", "tank@replacement"),
            format!("{IVSET}tank@s\tivsetguid\t1\n"),
            format!("{IVSET}tank@s\tfuture\t1\n"),
        ] {
            assert!(
                observe_ivset_with(&point(), exact_property_fixture(&output)).is_err(),
                "{output:?}"
            );
        }
    }

    #[cfg(feature = "internal")]
    #[test]
    fn unsupported_ivset_query_and_postquery_identity_drift_never_succeed() {
        let mut fixture = exact_property_fixture(IVSET);
        let failed = observe_ivset_with(&point(), |program, args| {
            if args[0] == "get" {
                return Err(Error::Command {
                    program,
                    args: args.to_vec(),
                    detail: "unsupported hidden property".into(),
                });
            }
            fixture(program, args)
        });
        assert!(matches!(failed, Err(Error::Command { .. })));
        let mut queried = false;
        let mut fixture = exact_property_fixture(IVSET);
        let changed = observe_ivset_with(&point(), |program, args| {
            if queried && args[0] == "list" && args.iter().any(|arg| arg == "snapshot") {
                return Ok(SNAP.replace("\t40\t", "\t41\t"));
            }
            if args[0] == "get" {
                queried = true;
            }
            fixture(program, args)
        });
        assert!(matches!(changed, Err(Error::Inconsistent(_))));
    }

    #[cfg(feature = "internal")]
    #[test]
    fn written_since_observation_binds_base_and_head_without_inventing_clean_state() {
        let dataset = parse_datasets(
            DATA,
            &InspectRequest::new(vec![], false).unwrap(),
            &parse_pools(POOL).unwrap(),
        )
        .unwrap()
        .remove(0);
        for bytes in [0, 8192, u64::MAX] {
            let output = WRITTEN.replace("written@s\t0", &format!("written@s\t{bytes}"));
            let observed =
                observe_written_since_with(&dataset, &point(), exact_property_fixture(&output))
                    .unwrap();
            assert_eq!(observed.referenced_new_bytes, bytes);
            assert_eq!(observed.dataset_identity, dataset.identity);
            assert_eq!(observed.base, point());
        }
        let mut foreign = point();
        foreign.dataset_guid = Guid::new(999);
        assert!(
            observe_written_since_with(&dataset, &foreign, |_, _| panic!(
                "invalid base reached native backend"
            ))
            .is_err()
        );
        for output in [
            WRITTEN.replace("written@s\t0", "written@s\t-"),
            WRITTEN.replace("\t6\n", "\t7\n"),
        ] {
            assert!(
                observe_written_since_with(&dataset, &point(), exact_property_fixture(&output))
                    .is_err()
            );
        }
    }

    #[cfg(feature = "internal")]
    #[test]
    fn written_observation_rechecks_head_after_query() {
        let dataset = parse_datasets(
            DATA,
            &InspectRequest::new(vec![], false).unwrap(),
            &parse_pools(POOL).unwrap(),
        )
        .unwrap()
        .remove(0);
        let mut queried = false;
        let mut fixture = exact_property_fixture(WRITTEN);
        let changed = observe_written_since_with(&dataset, &point(), |program, args| {
            if queried && args[0] == "list" && args.iter().any(|arg| arg == "filesystem,volume") {
                return Ok(changed_dataset_column(9, "7"));
            }
            if args[0] == "get" {
                queried = true;
            }
            fixture(program, args)
        });
        assert!(matches!(changed, Err(Error::Inconsistent(_))));
    }
    #[test]
    fn full_pool_properties_preserve_unknown_metadata_and_refuse_incompleteness() {
        let names = vec!["tank".into()];
        let output = "tank\tguid\t123\t-\ntank\tzctl:future\t-\tlocal\n";
        let properties = pool_properties_with(&names, |program, args| {
            assert_eq!(program, "zpool");
            assert_eq!(args.last().unwrap(), "tank");
            assert!(args.iter().any(|arg| arg == "all"));
            Ok(output.into())
        })
        .unwrap();
        assert_eq!(properties["tank"]["zctl:future"].source, "local");
        for invalid in [
            "",
            "tank\tguid\t0\t-\n",
            "other\tguid\t123\t-\n",
            "tank\tguid\t123\t-\ntank\tguid\t123\t-\n",
        ] {
            assert!(pool_properties_with(&names, |_, _| Ok(invalid.into())).is_err());
        }
        // Each pool is queried alone; a user property of the second pool
        // must not depend on the first pool's set.
        let names = vec!["apool".into(), "rpool".into()];
        let mut queried = Vec::new();
        let properties = pool_properties_with(&names, |_, args| {
            let pool = args.last().unwrap().clone();
            queried.push(pool.clone());
            Ok(match pool.as_str() {
                "apool" => "apool\tguid\t7\t-\n".into(),
                _ => "rpool\tguid\t9\t-\nrpool\tzboot:role\troot\tlocal\n".into(),
            })
        })
        .unwrap();
        assert_eq!(queried, ["apool", "rpool"]);
        assert_eq!(properties["rpool"]["zboot:role"].value, "root");
        assert!(
            pool_properties_with(&names, |_, _| Ok(
                "apool\tguid\t7\t-\nrpool\tguid\t9\t-\n".into()
            ))
            .is_err()
        );
        for names in [
            vec![],
            vec!["tank/data".into()],
            vec!["tank".into(), "tank".into()],
        ] {
            assert!(
                pool_properties_with(&names, |_, _| panic!("invalid scope reached backend"))
                    .is_err()
            );
        }
    }
}

#[cfg(test)]
#[cfg(feature = "internal")]
#[path = "native_verbose_tests.rs"]
mod verbose_tests;

#[cfg(test)]
#[path = "native_custody_tests.rs"]
mod custody_tests;
