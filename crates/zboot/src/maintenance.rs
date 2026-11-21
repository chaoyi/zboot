//! Writable maintenance in a private mount namespace. Admission never promotes
//! a secondary, relaxes readonly, or imports a missing pool. The writer guard is
//! retained for the foreground maintenance session and all owned mount cleanup.
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
};
use zfs_tools::engine::{
    Error,
    management::{Endpoint, Ownership},
    native,
    operation::SnapshotScope,
    pool_of,
    state::{self, NativeState},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaintenancePlan {
    pub endpoint: Endpoint,
    pub scope: SnapshotScope,
    pub ownership: Ownership,
}
pub fn plan_with(state: &NativeState, dataset: &str) -> Result<MaintenancePlan, Error> {
    let (scope, ownership, _) =
        crate::handoff::eligible(state, dataset).map_err(|e| refuse(e.to_string()))?;
    for member in scope.datasets() {
        let dataset = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == member.name)
            .ok_or_else(|| refuse("maintenance member missing"))?;
        let pool = pool_of(&member.name);
        if dataset.readonly
            || state
                .pool_properties
                .get(pool)
                .and_then(|p| p.get("readonly"))
                .map(|p| p.value.as_str())
                != Some("off")
        {
            return Err(refuse(
                "writable maintenance requires writable datasets and an already writable imported pool; activate the intended primary explicitly first",
            ));
        }
    }
    let root = scope
        .datasets()
        .iter()
        .find(|d| d.name == dataset)
        .ok_or_else(|| refuse("maintenance root missing"))?;
    Ok(MaintenancePlan {
        endpoint: Endpoint {
            name: root.name.clone(),
            identity: root.identity.clone(),
        },
        scope,
        ownership,
    })
}
fn owned_mounts_remain(root: &Path) -> Result<bool, Error> {
    Ok(zfs_tools::engine::mountinfo::current()
        .map_err(io_error)?
        .iter()
        .any(|mount| mount.mount_point.starts_with(root)))
}
fn workspace(prefix: &str) -> Result<PathBuf, Error> {
    crate::mount_view::check_runtime_dir().map_err(io_error)?;
    let work = Path::new("/run").join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .map_err(io_error)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(work.join("root"))
        .map_err(io_error)?;
    Ok(work)
}
fn mount_be(mounts: &mut Mounts, dataset: &str, root: &Path, writable: bool) -> Result<(), Error> {
    mounts.mount(
        vec![
            "-t".into(),
            "zfs".into(),
            "-o".into(),
            if writable {
                "rw,zfsutil"
            } else {
                "ro,zfsutil,nosuid,nodev,noexec"
            }
            .into(),
            dataset.into(),
            root.to_string_lossy().into_owned(),
        ],
        root.into(),
    )
}
fn bind_runtime(root: &Path, mounts: &mut Mounts) -> Result<(), Error> {
    for relative in ["dev", "dev/pts", "proc", "sys"] {
        let target = directory(root, Path::new(relative))?;
        mounts.mount(
            vec![
                "--bind".into(),
                format!("/{relative}"),
                target.to_string_lossy().into_owned(),
            ],
            target,
        )?;
    }
    let run = directory(root, Path::new("run"))?;
    mounts.mount(
        vec![
            "-t".into(),
            "tmpfs".into(),
            "-o".into(),
            "mode=0755,nosuid,nodev".into(),
            "tmpfs".into(),
            run.to_string_lossy().into_owned(),
        ],
        run.clone(),
    )?;
    // Before anything else is placed there: the tmpfs is still empty and
    // wholly this session's.
    provide_resolver(root, &run, Path::new("/etc/resolv.conf"));
    // Writers inside the BE join the host's writer lock, not a private one.
    let host = Path::new(zfs_tools::engine::lock::PATH)
        .parent()
        .expect("fixed writer lock parent");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(host)
        .map_err(io_error)?;
    let shared = run.join(host.strip_prefix("/run").expect("writer lock under /run"));
    fs::DirBuilder::new()
        .mode(0o755)
        .create(&shared)
        .map_err(io_error)?;
    mounts.mount(
        vec![
            "--bind".into(),
            host.to_string_lossy().into_owned(),
            shared.to_string_lossy().into_owned(),
        ],
        shared,
    )
}
/// Give the BE the host's resolver when its `/etc/resolv.conf` is a symlink
/// into `/run`, as systemd-resolved installs it: the BE's `/run` in this
/// session is new and empty, so the link would dangle and nothing run there
/// (apt, say) could resolve a name. HOST's content is copied to where the
/// link points inside RUN. A regular file, a link elsewhere or none is left
/// as it is, and so is a host with no resolver file (the UKI). This is a
/// convenience: whatever stops it leaves the session without a resolver, as
/// it was, and never stops the session.
fn provide_resolver(root: &Path, run: &Path, host: &Path) {
    use std::io::{Read, Write};
    const LIMIT: u64 = 64 * 1024;
    let Ok(etc) = directory(root, Path::new("etc")) else {
        return;
    };
    let Ok(target) = fs::read_link(etc.join("resolv.conf")) else {
        return;
    };
    // `/run/...`, or `../run/...` as seen from the BE's `/etc`.
    let Ok(relative) = target
        .strip_prefix("/run")
        .or_else(|_| target.strip_prefix("../run"))
    else {
        return;
    };
    // The writer lock's directory is bound into this `/run` next.
    let reserved = Path::new(zfs_tools::engine::lock::PATH)
        .parent()
        .and_then(|lock| lock.strip_prefix("/run").ok());
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || reserved.is_some_and(|r| relative.starts_with(r) || r.starts_with(relative))
    {
        return;
    }
    let _ = (|| -> io::Result<()> {
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(host)?;
        let mut resolver = Vec::new();
        if !source.metadata()?.is_file()
            || source.take(LIMIT + 1).read_to_end(&mut resolver)? as u64 > LIMIT
        {
            return Ok(());
        }
        let file = run.join(relative);
        if let Some(parent) = file.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent)?;
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&file)?
            .write_all(&resolver)
    })();
}
fn verify(plan: &MaintenancePlan) -> Result<(), Error> {
    if plan_with(&state::observe()?, &plan.endpoint.name)? != *plan {
        return Err(refuse(
            "maintenance scope, incarnation or ownership changed",
        ));
    }
    Ok(())
}
fn run(program: &'static str, args: &[String]) -> Result<(), Error> {
    native::run(program, args).map(|_| ())
}
/// Ensure an existing path is made only of real directories inside the selected
/// root. This is evaluated before any mount, never using a BE symlink as a host
/// mount destination. Missing directories must be repaired explicitly first.
fn directory(root: &Path, relative: &Path) -> Result<PathBuf, Error> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(refuse(
            "maintenance path must be a contained relative directory",
        ));
    }
    let mut path = root.to_path_buf();
    for part in relative.components() {
        path.push(part);
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(refuse(
                "maintenance mount destination is not a real contained directory",
            ));
        }
    }
    Ok(path)
}
fn command(root: &Path, requested: &[String]) -> Result<Vec<String>, Error> {
    let mut args = requested.to_vec();
    if args.is_empty() {
        args.push(
            if resolve_inside(root, Path::new("bin/bash")).is_ok() {
                "/bin/bash"
            } else {
                "/bin/sh"
            }
            .into(),
        );
    }
    let path = Path::new(&args[0]);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(refuse(
            "maintenance executable must be an absolute contained path",
        ));
    }
    // Resolve executable symlinks as they will be seen from inside the chroot,
    // so an absolute /bin -> /usr/bin link remains inside the selected BE.
    let relative = path.strip_prefix("/").map_err(|e| refuse(e.to_string()))?;
    resolve_inside(root, relative)?;
    Ok(args)
}
fn resolve_inside(root: &Path, relative: &Path) -> Result<PathBuf, Error> {
    let mut components: std::collections::VecDeque<_> = relative
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let mut resolved = root.to_path_buf();
    let mut links = 0;
    while let Some(part) = components.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            if resolved == root {
                return Err(refuse("maintenance executable escapes selected root"));
            }
            resolved.pop();
            continue;
        }
        resolved.push(&part);
        let metadata = fs::symlink_metadata(&resolved).map_err(io_error)?;
        if metadata.file_type().is_symlink() {
            links += 1;
            if links > 40 {
                return Err(refuse("maintenance executable symlink loop"));
            }
            let target = fs::read_link(&resolved).map_err(io_error)?;
            resolved.pop();
            if target.is_absolute() {
                resolved = root.to_path_buf();
            }
            for component in target.components().rev() {
                if component != Component::RootDir {
                    components.push_front(component.as_os_str().to_os_string());
                }
            }
        }
    }
    if !fs::metadata(&resolved).map_err(io_error)?.is_file() {
        return Err(refuse("maintenance executable is not a regular file"));
    }
    Ok(resolved)
}
struct Mounts {
    paths: Vec<PathBuf>,
}
impl Mounts {
    fn mount(&mut self, args: Vec<String>, target: PathBuf) -> Result<(), Error> {
        // Arm cleanup before spawning: a lost successful mount reply must not
        // leave the owned path outside cleanup's scope.
        self.paths.push(target);
        run("mount", &args)
    }
    fn unmount_last(&mut self) -> Result<(), Error> {
        if let Some(path) = self.paths.last() {
            if owned_mounts_remain(path)? {
                run("umount", &[path.to_string_lossy().into_owned()])?;
                if owned_mounts_remain(path)? {
                    return Err(refuse("maintenance mount remains after successful unmount"));
                }
            }
            self.paths.pop();
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        while !self.paths.is_empty() {
            self.unmount_last()?;
        }
        Ok(())
    }
}
impl Drop for Mounts {
    fn drop(&mut self) {
        for path in self.paths.iter().rev() {
            let _ = native::run("umount", &[path.to_string_lossy().into_owned()]);
        }
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[allow(unsafe_code)]
fn spawn_chroot(root: &Path, args: &[String]) -> Result<OwnedChild, Error> {
    use std::os::unix::process::CommandExt;
    let parent = nix::unistd::getpid();
    let mut command = Command::new("chroot");
    command
        .arg(root)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: this pre-exec hook uses only prctl/getppid syscalls and constructs
    // raw-OS-error values. It allocates no memory and takes no process locks.
    unsafe {
        command.pre_exec(move || {
            nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            if nix::unistd::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    let child = zfs_tools::engine::native::announced(&mut command)
        .spawn()
        .map_err(io_error)?;
    zfs_tools::engine::effect::mark();
    Ok(OwnedChild(child))
}
fn private_namespace() -> Result<(), Error> {
    crate::mount_view::enter_private_namespace().map_err(|e| refuse(e.to_string()))
}
struct CacheShadow {
    target: PathBuf,
    created: Option<(u64, u64)>,
}
impl CacheShadow {
    fn install(root: &Path, work: &Path, mounts: &mut Mounts) -> Result<Self, Error> {
        let cache = Self::prepare(root, work)?;
        cache.bind(work, mounts)?;
        Ok(cache)
    }
    fn prepare(root: &Path, work: &Path) -> Result<Self, Error> {
        let parent = directory(root, Path::new("etc/zfs"))?;
        let target = parent.join("zpool.cache");
        let created = match fs::symlink_metadata(&target) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= 64 * 1024 * 1024 =>
            {
                None
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&target)
                    .map_err(io_error)?;
                let metadata = file.metadata().map_err(io_error)?;
                Some((metadata.dev(), metadata.ino()))
            }
            _ => {
                return Err(refuse(
                    "maintenance pool-cache boundary is not a bounded regular file",
                ));
            }
        };
        let cache = Self { target, created };
        let shadow = work.join("zpool.cache.shadow");
        if let Err(error) = fs::copy(&cache.target, &shadow) {
            if let Err(cleanup) = cache.cleanup() {
                return Err(refuse(format!(
                    "cache shadow failed: {error}; created boundary cleanup failed: {cleanup}"
                )));
            }
            return Err(io_error(error));
        }
        Ok(cache)
    }
    fn bind(&self, work: &Path, mounts: &mut Mounts) -> Result<(), Error> {
        mounts.mount(
            vec![
                "--bind".into(),
                work.join("zpool.cache.shadow")
                    .to_string_lossy()
                    .into_owned(),
                self.target.to_string_lossy().into_owned(),
            ],
            self.target.clone(),
        )
    }
    fn cleanup(&self) -> Result<(), Error> {
        if let Some((dev, ino)) = self.created {
            let metadata = fs::symlink_metadata(&self.target).map_err(io_error)?;
            if metadata.dev() != dev
                || metadata.ino() != ino
                || metadata.len() != 0
                || !metadata.is_file()
                || metadata.file_type().is_symlink()
            {
                return Err(refuse(
                    "created empty cache boundary changed; retained for inspection",
                ));
            }
            fs::remove_file(&self.target).map_err(io_error)?;
        }
        Ok(())
    }
}
pub fn chroot(dataset: &str, requested: &[String]) -> Result<i32, Error> {
    let plan = plan_with(&state::observe()?, dataset)?;
    if crate::status::running_root().map_err(io_error)?.as_deref() == Some(dataset) {
        return Err(refuse(
            "select a maintenance BE other than the running root",
        ));
    }
    // The menu runs commands in its own process. A worker thread holds the
    // private mount namespace, so it ends with this command (as esp.rs does).
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                private_namespace()?;
                chroot_in_namespace(&plan, dataset, requested)
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}
fn chroot_in_namespace(
    plan: &MaintenancePlan,
    dataset: &str,
    requested: &[String],
) -> Result<i32, Error> {
    let work = workspace("zboot-chroot")?;
    let root = work.join("root");
    let mut mounts = Mounts { paths: vec![] };
    let result = (|| {
        verify(plan)?;
        mount_be(&mut mounts, dataset, &root, true)?;
        verify(plan)?;
        let args = command(&root, requested)?;
        bind_runtime(&root, &mut mounts)?;
        let cache = CacheShadow::install(&root, &work, &mut mounts)?;
        verify(plan)?;
        let mut child = spawn_chroot(&root, &args)?;
        let status = child.0.wait().map_err(io_error)?;
        verify(plan)?;
        // Release just the cache boundary before inspecting its original inode.
        let cache_path = mounts
            .paths
            .last()
            .ok_or_else(|| refuse("cache mount boundary missing"))?
            .clone();
        run("umount", &[cache_path.to_string_lossy().into_owned()])?;
        mounts.paths.pop();
        cache.cleanup()?;
        Ok(exit_code(status))
    })();
    let cleanup = mounts.finish();
    drop(mounts);
    if cleanup.is_ok() {
        let shadow = work.join("zpool.cache.shadow");
        if shadow.exists() {
            fs::remove_file(shadow).map_err(io_error)?;
        }
        fs::remove_dir(&root).map_err(io_error)?;
        fs::remove_dir(&work).map_err(io_error)?;
    }
    match (result, cleanup) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) => Err(error),
        (result, Err(cleanup)) => Err(refuse(format!(
            "maintenance result {result:?}; owned mount cleanup at {} needs inspection: {cleanup}",
            work.display()
        ))),
    }
}
fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}
fn refuse(detail: impl Into<String>) -> Error {
    Error::Refused(detail.into())
}
fn io_error(error: io::Error) -> Error {
    refuse(error.to_string())
}

#[derive(Debug)]
pub struct CommandExit(pub i32);
impl std::fmt::Display for CommandExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "maintenance command exited {}", self.0)
    }
}
impl std::error::Error for CommandExit {}
#[cfg(test)]
mod tests {
    use super::*;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("zboot-maintenance-test-{}", uuid::Uuid::new_v4()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn contained_directory_paths_refuse_symlinks_missing_and_parent_traversal() {
        use std::os::unix::fs::symlink;
        let scratch = Scratch::new();
        fs::create_dir(scratch.0.join("dev")).unwrap();
        assert_eq!(
            directory(&scratch.0, Path::new("dev")).unwrap(),
            scratch.0.join("dev")
        );
        symlink("/dev", scratch.0.join("escape")).unwrap();
        for path in ["escape", "../dev", "/dev", "missing"] {
            assert!(directory(&scratch.0, Path::new(path)).is_err(), "{path}");
        }
    }
    #[test]
    fn a_resolver_link_into_run_gets_the_hosts_resolver_and_nothing_else_does() {
        use std::os::unix::fs::symlink;
        let scratch = Scratch::new();
        let host = scratch.0.join("host-resolv.conf");
        fs::write(&host, b"nameserver 192.0.2.53\n").unwrap();
        // (the BE's /etc/resolv.conf, the file expected under its /run)
        for (link, expected) in [
            (
                Some("/run/systemd/resolve/stub-resolv.conf"),
                Some("systemd/resolve/stub-resolv.conf"),
            ),
            (
                Some("../run/resolvconf/resolv.conf"),
                Some("resolvconf/resolv.conf"),
            ),
            (Some("/run"), None),
            (Some("/run/../etc/shadow"), None),
            (Some("/etc/resolv.conf.real"), None),
            (Some("/runaway/resolv.conf"), None),
            // Where the writer lock's directory is bound next.
            (Some("/run/zfs-tools"), None),
            (Some("/run/zfs-tools/resolv.conf"), None),
            (None, None),
        ] {
            let be = Scratch::new();
            let (root, run) = (be.0.join("root"), be.0.join("root/run"));
            fs::create_dir_all(root.join("etc")).unwrap();
            fs::create_dir(&run).unwrap();
            match link {
                Some(link) => symlink(link, root.join("etc/resolv.conf")).unwrap(),
                None => {
                    fs::write(root.join("etc/resolv.conf"), b"nameserver 198.51.100.1\n").unwrap()
                }
            }
            provide_resolver(&root, &run, &host);
            match expected {
                Some(path) => assert_eq!(
                    fs::read(run.join(path)).unwrap(),
                    b"nameserver 192.0.2.53\n",
                    "{link:?}"
                ),
                None => assert_eq!(fs::read_dir(&run).unwrap().count(), 0, "{link:?}"),
            }
        }
        // A host without a resolver file, or with something that is not a
        // small regular file, and a BE whose /etc is a link.
        let be = Scratch::new();
        let (root, run) = (be.0.join("root"), be.0.join("root/run"));
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir(&run).unwrap();
        symlink("/run/resolv.conf", root.join("etc/resolv.conf")).unwrap();
        let huge = scratch.0.join("huge");
        fs::write(&huge, vec![b'#'; 64 * 1024 + 1]).unwrap();
        for unusable in [scratch.0.join("absent"), scratch.0.clone(), huge] {
            provide_resolver(&root, &run, &unusable);
            assert_eq!(fs::read_dir(&run).unwrap().count(), 0, "{unusable:?}");
        }
        fs::remove_dir_all(root.join("etc")).unwrap();
        symlink("/etc", root.join("etc")).unwrap();
        provide_resolver(&root, &run, &host);
        assert_eq!(fs::read_dir(&run).unwrap().count(), 0);
    }
    #[test]
    fn executable_resolution_uses_chroot_absolute_symlink_semantics_and_bounds_loops() {
        use std::os::unix::fs::symlink;
        let scratch = Scratch::new();
        fs::create_dir_all(scratch.0.join("usr/bin")).unwrap();
        fs::write(scratch.0.join("usr/bin/sh"), b"fixture executable").unwrap();
        symlink("/usr/bin", scratch.0.join("bin")).unwrap();
        assert_eq!(command(&scratch.0, &[]).unwrap(), vec!["/bin/sh"]);
        assert_eq!(
            resolve_inside(&scratch.0, Path::new("bin/sh")).unwrap(),
            scratch.0.join("usr/bin/sh")
        );
        symlink("/loop", scratch.0.join("loop")).unwrap();
        assert!(command(&scratch.0, &["/loop".into()]).is_err());
        assert!(command(&scratch.0, &["sh".into()]).is_err());
        assert!(command(&scratch.0, &["/bin/../sh".into()]).is_err());
        symlink("../../outside", scratch.0.join("escape")).unwrap();
        assert!(command(&scratch.0, &["/escape".into()]).is_err());
    }
    #[test]
    fn nonzero_and_signal_status_are_preserved() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(exit_code(ExitStatus::from_raw(libc::SIGTERM)), 143);
    }
    fn fixture(readonly: bool, pool_readonly: bool) -> NativeState {
        fixture_options(readonly, pool_readonly, false, false)
    }
    fn fixture_options(
        readonly: bool,
        pool_readonly: bool,
        mounted: bool,
        child: bool,
    ) -> NativeState {
        use std::collections::BTreeMap;
        let rows = [
            "tank\t1\t1000\t100\t900\tONLINE\t-\n".to_string(),
            format!(
                "tank\tfilesystem\t1\t100\t900\t80\t/tank\t-\t11\t21\tno\toff\ton\t-\toff\t-\t-\t-\t-\ntank/be\tfilesystem\t2\t100\t900\t80\t/\t-\t12\t22\tno\t{}\tnoauto\t-\toff\t-\t-\t-\t-\n",
                if readonly { "on" } else { "off" }
            ),
            String::new(),
        ];
        let mut rows = rows;
        if mounted {
            rows[1] = rows[1].replace("22\tno\t", "22\tyes\t");
        }
        if child {
            rows[1].push_str("tank/be/child\tfilesystem\t3\t100\t900\t80\t/var\t-\t13\t23\tno\toff\tnoauto\t-\toff\t-\t-\t-\t-\n");
        }
        let mut rows = rows.into_iter();
        let inspection = native::inspect_with(
            &zfs_tools::engine::InspectRequest::new(vec![], true).unwrap(),
            |_, _| Ok(rows.next().unwrap()),
        )
        .unwrap();
        let property = |value: String| zfs_tools::engine::native::NativeProperty {
            value,
            source: "-".into(),
        };
        let dataset_properties: zfs_tools::engine::native::PropertyInventory = inspection
            .datasets
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), property(d.identity.guid.to_string())),
                        (
                            "createtxg".into(),
                            property(d.identity.createtxg.to_string()),
                        ),
                        ("objsetid".into(), property(d.identity.objsetid.to_string())),
                    ]),
                )
            })
            .collect();
        NativeState {
            inspection,
            dataset_properties,
            pool_properties: BTreeMap::from([(
                "tank".into(),
                BTreeMap::from([
                    ("guid".into(), property("1".into())),
                    (
                        "readonly".into(),
                        property(if pool_readonly { "on" } else { "off" }.into()),
                    ),
                ]),
            )]),
        }
    }
    #[test]
    fn writable_maintenance_rechecks_dataset_and_pool_modes_beyond_boot_read_admission() {
        plan_with(&fixture(false, false), "tank/be").unwrap();
        assert!(plan_with(&fixture(true, false), "tank/be").is_err());
        assert!(plan_with(&fixture(false, true), "tank/be").is_err());
        let mut future = fixture(false, false);
        future
            .dataset_properties
            .get_mut("tank/be")
            .unwrap()
            .insert(
                "zboot:future".into(),
                zfs_tools::engine::native::NativeProperty {
                    value: "-".into(),
                    source: "local".into(),
                },
            );
        assert!(plan_with(&future, "tank/be").is_err());
    }
}
