//! `zboot factory`: a host-agnostic Debian root as one zstd tar, made by
//! `mmdebstrap --mode=unshare` as the calling user (no root, no VM).
//!
//! Before any work, factory packages the zboot installation it runs from
//! (the three tools beside it and `../lib`) as the Debian package `zboot`.
//! mmdebstrap installs the floor packages and that package's Depends; its
//! customize hook runs this same zboot executable (`factory-finish`,
//! [`finish_stage`]) as root of its user namespace to install the package
//! with `dpkg -i`, clear host identity, build and check the ZFS module for
//! every installed kernel and generate and check each initrd. The root keeps
//! Debian's stock mounting (no zboot setting). The tar is then admitted
//! exactly as `deploy` admits any root tar ([`root_tar`]) before it is
//! published with its package list.
mod failure;
mod finish;
pub mod root_tar;

pub use finish::finish_stage;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

pub const DEFAULT_SUITE: &str = "forky";
pub const DEFAULT_MIRROR: &str = "https://deb.debian.org/debian";
const SECURITY_MIRROR: &str = "https://security.debian.org/debian-security";
const SNAPSHOT: &str = "https://snapshot.debian.org/archive";
const COMPONENTS: &str = "main contrib non-free-firmware";

/// The floor every factory root gets, plus the `zboot` package and its
/// Depends, plus `--packages` (a host typically adds `openssh-server`).
pub const FLOOR: &[&str] = &[
    "linux-image-amd64",
    "linux-headers-amd64",
    "zfs-dkms",
    "zfs-initramfs",
    "systemd-sysv",
];

/// zboot's package definition. `dist/dist.sh` builds the same package;
/// both append the `Version` field.
const CONTROL: &str = include_str!("../../../dist/deb/control");

/// The `Depends` of zboot's Debian package: the tools zboot runs on an
/// installed host. `dpkg -i` does not resolve them, so mmdebstrap installs
/// them first.
pub fn deb_depends() -> Vec<&'static str> {
    CONTROL
        .lines()
        .find_map(|line| line.strip_prefix("Depends:"))
        .map(|list| {
            list.split(',')
                // `libc6 (>= 2.34)`: mmdebstrap takes the name alone.
                .map(|entry| entry.split('(').next().unwrap_or(entry).trim())
                .collect()
        })
        .unwrap_or_default()
}

/// The installed tools, beside the running zboot.
pub(crate) const TOOLS: [&str; 2] = ["zboot", "zsnap"];

/// The rest of the installation, under `../lib` from the tools: the UKI and
/// the writer lock's tmpfiles entry.
const LIBRARY: [&str; 2] = ["zboot/zboot.efi", "tmpfiles.d/zfs-tools.conf"];

/// The helpers under `../sbin` from the tools: the probe that verifies an
/// erase, which `wipe`, `deploy DISK` and `restore` run
/// (`device::wipe::PROBE`), and the key relink helper `restore` runs
/// (`restore::native::CHANGE_KEY`).
const HELPERS: [&str; 2] = ["zboot-probe-signatures", "zboot-change-key"];

/// Where the finish hook finds the package inside the root.
const PACKAGE: &str = "zboot.deb";

pub(crate) fn refuse(value: impl ToString) -> io::Error {
    io::Error::other(value.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageFile {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub output: PathBuf,
    pub suite: String,
    pub mirror: String,
    /// snapshot.debian.org timestamp applied to every archive.
    pub snapshot: Option<String>,
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub tar: PathBuf,
    pub packages_file: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub kernels: Vec<String>,
    pub packages: usize,
    pub suite: String,
    pub snapshot: Option<String>,
    pub seconds: u64,
}

/// What the customize hook needs, written beside the staged inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stage {
    /// Sources the deployed root updates from (never a snapshot).
    pub sources: String,
}

pub(crate) fn atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+:-_~".contains(&b))
}

fn mirror_url(mirror: &str) -> io::Result<String> {
    let mirror = mirror.trim_end_matches('/');
    if !(mirror.starts_with("http://") || mirror.starts_with("https://"))
        || mirror
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "\"'\\@[]".contains(c))
    {
        return Err(refuse(
            "--mirror must be a plain http(s) Debian archive URL",
        ));
    }
    Ok(mirror.into())
}

/// Suites with security and updates archives beside them.
fn released(suite: &str) -> bool {
    !matches!(suite, "sid" | "unstable" | "experimental" | "rc-buggy")
}

/// The apt source lines mmdebstrap builds from: one timestamp for every
/// archive with `--snapshot` (snapshot.debian.org serves expired Release
/// files, so only those lines skip the Valid-Until check), else the mirror.
/// Signatures are always checked.
pub(crate) fn build_sources(suite: &str, mirror: &str, snapshot: Option<&str>) -> Vec<String> {
    let (debian, security, options) = match snapshot {
        Some(time) => (
            format!("{SNAPSHOT}/debian/{time}"),
            format!("{SNAPSHOT}/debian-security/{time}"),
            "[check-valid-until=no] ",
        ),
        None => (mirror.to_string(), SECURITY_MIRROR.to_string(), ""),
    };
    let mut lines = vec![format!("deb {options}{debian} {suite} {COMPONENTS}")];
    if released(suite) {
        lines.push(format!(
            "deb {options}{debian} {suite}-updates {COMPONENTS}"
        ));
        lines.push(format!(
            "deb {options}{security} {suite}-security {COMPONENTS}"
        ));
    }
    lines
}

/// The deb822 sources a deployed root updates from: the live mirror, never
/// a snapshot.
pub(crate) fn deployed_sources(suite: &str, mirror: &str) -> String {
    let stanza = |uri: &str, suites: &str| {
        format!(
            "Types: deb\nURIs: {uri}\nSuites: {suites}\nComponents: {COMPONENTS}\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
        )
    };
    if released(suite) {
        stanza(mirror, &format!("{suite} {suite}-updates"))
            + "\n"
            + &stanza(SECURITY_MIRROR, &format!("{suite}-security"))
    } else {
        stanza(mirror, suite)
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(crate) fn hash(file: &mut File) -> io::Result<ImageFile> {
    let (sha256, bytes) = crate::loader::hash(file)?;
    Ok(ImageFile { sha256, bytes })
}

fn copy_input(source: &Path, destination: &Path, mode: u32) -> io::Result<()> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|e| refuse(format!("{}: {e}", source.display())))?;
    if !input.metadata()?.is_file() {
        return Err(refuse(format!(
            "{} is not a regular file",
            source.display()
        )));
    }
    let before = hash(&mut input)?;
    input.seek(SeekFrom::Start(0))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))?;
    if hash(&mut File::open(destination)?)? != before {
        return Err(refuse(format!("{} changed while staged", source.display())));
    }
    Ok(())
}

/// A world-readable copy of a plain tree (directories, files, symlinks).
/// mmdebstrap's unshare mode runs as the first subordinate uid, which must
/// be able to reach the work directory.
fn traversable(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        if fs::metadata(ancestor)?.mode() & 0o001 == 0 {
            return Err(refuse(format!(
                "{} is not searchable by other users, so mmdebstrap's user namespace cannot reach the work directory; set TMPDIR to a disk-backed directory every user can traverse",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

/// mmdebstrap's work tree: `$TMPDIR` (absolute), else `/var/tmp`.
fn work_parent() -> PathBuf {
    std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/var/tmp"))
}

struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        // mmdebstrap removes its own tree; what remains is ours.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o755).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

/// The installation `executable` runs from, as (path, path in the package)
/// pairs: the tools beside it, `../sbin`'s helpers and `../lib`. A missing
/// piece is refused by path.
pub(crate) fn installation(executable: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let bin = executable
        .parent()
        .ok_or_else(|| refuse("the running zboot has no directory"))?;
    let prefix = bin.parent().unwrap_or(bin);
    let lib = prefix.join("lib");
    let pieces = TOOLS
        .iter()
        .map(|name| (bin.join(name), format!("usr/bin/{name}")))
        .chain(
            HELPERS
                .iter()
                .map(|name| (prefix.join("sbin").join(name), format!("usr/sbin/{name}"))),
        )
        .chain(
            LIBRARY
                .iter()
                .map(|path| (lib.join(path), format!("usr/lib/{path}"))),
        )
        .chain([(prefix.join("share/doc/zboot"), "usr/share/doc/zboot".into())]);
    let mut found = Vec::new();
    for (path, packaged) in pieces {
        if fs::symlink_metadata(&path).is_err() {
            return Err(refuse(format!(
                "{} is missing: factory installs the zboot it runs from, the tools beside it, ../sbin/{} and ../lib/zboot (run OUT/usr/bin/zboot that dist/dist.sh wrote, or an installed /usr/bin/zboot)",
                path.display(),
                HELPERS.join(" and ../sbin/")
            )));
        }
        found.push((path, packaged));
    }
    Ok(found)
}

/// A copy of a tree of directories and regular files; executables keep
/// 0755, everything else is 0644.
fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        private_directory(destination)?;
        let mut names = fs::read_dir(source)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        names.sort();
        for name in names {
            copy_tree(&source.join(&name), &destination.join(&name))?;
        }
        Ok(())
    } else if metadata.is_file() {
        let mode = if metadata.mode() & 0o111 != 0 {
            0o755
        } else {
            0o644
        };
        copy_input(source, destination, mode)
    } else {
        Err(refuse(format!(
            "{} is neither a directory nor a regular file",
            source.display()
        )))
    }
}

/// The `zboot` package of `pieces`, staged in `tree` and built as `deb`.
fn package(pieces: &[(PathBuf, String)], tree: &Path, deb: &Path) -> io::Result<()> {
    private_directory(tree)?;
    for directory in [
        "DEBIAN",
        "usr",
        "usr/bin",
        "usr/sbin",
        "usr/lib",
        "usr/lib/zboot",
        "usr/lib/tmpfiles.d",
        "usr/share",
        "usr/share/doc",
    ] {
        private_directory(&tree.join(directory))?;
    }
    for (path, packaged) in pieces {
        copy_tree(path, &tree.join(packaged))?;
    }
    let control = tree.join("DEBIAN/control");
    fs::write(
        &control,
        format!(
            "{CONTROL}Version: {}\n",
            crate::build_identity::PACKAGE_VERSION
        ),
    )?;
    fs::set_permissions(&control, fs::Permissions::from_mode(0o644))?;
    let status = zfs_tools::engine::native::announced(
        Command::new("dpkg-deb")
            .args(["--root-owner-group", "--build"])
            .arg(tree)
            .arg(deb)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(Stdio::from(io::stderr().as_fd().try_clone_to_owned()?)),
    )
    .status()
    .map_err(|e| refuse(format!("dpkg-deb: {e}")))?;
    if !status.success() {
        return Err(refuse(format!("dpkg-deb failed ({status})")));
    }
    fs::set_permissions(deb, fs::Permissions::from_mode(0o644))
}

/// Seconds since the epoch for a snapshot.debian.org timestamp.
pub(crate) fn snapshot_epoch(snapshot: &str) -> io::Result<u64> {
    let digits = |range: std::ops::Range<usize>| -> io::Result<u64> {
        snapshot
            .get(range)
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| refuse("snapshot must be YYYYMMDDTHHMMSSZ"))
    };
    if snapshot.len() != 16 || &snapshot[8..9] != "T" || !snapshot.ends_with('Z') {
        return Err(refuse("snapshot must be YYYYMMDDTHHMMSSZ"));
    }
    let (y, m, d) = (
        digits(0..4)? as i64,
        digits(4..6)? as i64,
        digits(6..8)? as i64,
    );
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe - 719_468) as u64;
    Ok(days * 86_400 + digits(9..11)? * 3600 + digits(11..13)? * 60 + digits(13..15)?)
}

/// Match dist/dist.sh: an unset or empty value keeps the eight-job default.
/// Parse before staging anything and interpolate only the resulting number.
fn factory_jobs(value: Option<&OsStr>) -> io::Result<u8> {
    let invalid = || refuse("ZBOOT_JOBS must be 1 to 99");
    let value = match value {
        None => return Ok(8),
        Some(value) if value.is_empty() => return Ok(8),
        Some(value) => value.to_str().ok_or_else(invalid)?,
    };
    if !matches!(value.as_bytes(), [b'1'..=b'9'] | [b'1'..=b'9', b'0'..=b'9']) {
        return Err(invalid());
    }
    value.parse().map_err(refuse)
}

pub fn build(request: &Request) -> io::Result<Outcome> {
    let jobs = factory_jobs(std::env::var_os("ZBOOT_JOBS").as_deref())?;
    let started = Instant::now();
    let suite = &request.suite;
    if !atom(suite) {
        return Err(refuse("--suite takes a Debian suite name"));
    }
    let epoch = match &request.snapshot {
        Some(time) => Some(snapshot_epoch(time)?),
        None => None,
    };
    if request.packages.iter().any(|p| !atom(p)) {
        return Err(refuse("--packages takes Debian package names"));
    }
    let mirror = mirror_url(&request.mirror)?;
    let output = if request.output.is_absolute() {
        request.output.clone()
    } else {
        std::env::current_dir()?.join(&request.output)
    };
    let packages_file = PathBuf::from(format!("{}.packages", output.display()));
    for path in [&output, &packages_file] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(refuse(format!("{} already exists", path.display())));
        }
    }
    let parent = output
        .parent()
        .ok_or_else(|| refuse("TAR has no parent directory"))?
        .to_path_buf();
    let executable = std::env::current_exe()?;
    let pieces = installation(&executable)?;
    let work_root = work_parent();
    traversable(&work_root)?;
    let work = Work(work_root.join(format!("zboot-factory-{}", uuid::Uuid::new_v4())));
    private_directory(&work.0)?;
    let stage = work.0.join("stage");
    private_directory(&stage)?;
    // The hook runs this executable and installs the package; both are
    // staged readable to the namespace's root.
    copy_input(&executable, &stage.join("zboot-factory"), 0o755)?;
    package(&pieces, &work.0.join("package"), &stage.join(PACKAGE))?;
    let plan = Stage {
        sources: deployed_sources(suite, &mirror),
    };
    fs::write(
        stage.join("stage.json"),
        serde_json::to_vec_pretty(&plan).map_err(refuse)?,
    )?;
    let mut include: Vec<String> = FLOOR
        .iter()
        .copied()
        .chain(deb_depends())
        .map(|p| p.to_string())
        .collect();
    include.extend(request.packages.iter().cloned());
    let tar = work.0.join("rootfs.tar.zst");
    let listed = work.0.join("packages.tsv");
    let quoted = shell_quote(&stage.display().to_string());
    let mut command = Command::new("mmdebstrap");
    command
        .args([
            "--mode=unshare",
            "--variant=minbase",
            "--format=tar",
            "--aptopt=Acquire::Languages \"none\"",
            "--aptopt=APT::Install-Recommends \"false\"",
            "--dpkgopt=force-unsafe-io",
        ])
        .arg(format!("--include={}", include.join(",")))
        // DKMS honors the validated job bound and leaves modules unsigned: a signing key
        // made here would be shared by every deployment, so it is scrubbed.
        .arg(format!(
            "--essential-hook=mkdir -p \"$1/etc/dkms/framework.conf.d\" && printf 'parallel_jobs={jobs}\\nsign_file=/nonexistent/zboot-factory-unsigned\\n' > \"$1/etc/dkms/framework.conf.d/zboot-factory.conf\"",
        ));
    command
        .arg(format!(
            "--customize-hook={quoted}/zboot-factory factory-finish \"$1\" {quoted}"
        ))
        .arg(format!(
            "--customize-hook=download /tmp/zboot-factory.packages {}",
            listed.display()
        ))
        .arg("--customize-hook=rm -f \"$1/tmp/zboot-factory.packages\" \"$1/etc/dkms/framework.conf.d/zboot-factory.conf\"")
        .arg(suite)
        .arg(&tar)
        .args(build_sources(suite, &mirror, request.snapshot.as_deref()))
        // No caller environment reaches the build or its log.
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C.UTF-8")
        .env("TMPDIR", &work.0)
        .env("HOME", &work.0)
        .stdin(Stdio::null());
    if let Some(epoch) = epoch {
        command.env("SOURCE_DATE_EPOCH", epoch.to_string());
    }
    eprintln!("zboot factory: mmdebstrap {suite} in {}", work.0.display());
    run_mmdebstrap(command)?;
    // The same admission deploy applies to any root tar.
    let admitted = root_tar::inspect(&tar)?;
    let packages = finish::parse_inventory(&fs::read(&listed)?)?;
    fs::create_dir_all(&parent)?;
    publish_outputs(&tar, &output, &listed, &packages_file)?;
    Ok(Outcome {
        tar: output,
        packages_file,
        sha256: admitted.sha256,
        bytes: admitted.bytes,
        kernels: admitted.kernels,
        packages: packages.len(),
        suite: suite.clone(),
        snapshot: request.snapshot.clone(),
        seconds: started.elapsed().as_secs(),
    })
}

/// Run mmdebstrap with its stdout and stderr streamed to ours. A failure's
/// refusal names the cause its output gave, which may be far above the end.
fn run_mmdebstrap(mut command: Command) -> io::Result<()> {
    let (mut output, writer) = io::pipe()?;
    command.stdout(writer.try_clone()?).stderr(writer);
    let mut child = zfs_tools::engine::native::announced(&mut command)
        .spawn()
        .map_err(|e| refuse(e.to_string()))?;
    // Only the child may hold the pipe's write end, or it never ends.
    drop(command);
    let mut failure = failure::Failure::default();
    let mut stderr = io::stderr();
    let mut buffer = [0; 8192];
    loop {
        let read = match output.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = child.wait();
                return Err(refuse(format!("mmdebstrap output: {e}")));
            }
        };
        // Our stderr going away must not stop the build mid-way.
        let _ = stderr.write_all(&buffer[..read]);
        failure.feed(&buffer[..read]);
    }
    let status = child
        .wait()
        .map_err(|e| refuse(format!("mmdebstrap: {e}")))?;
    if status.success() {
        return Ok(());
    }
    let status = status
        .code()
        .map_or(status.to_string(), |code| format!("exit status {code}"));
    Err(refuse(match failure.summary() {
        Some(cause) => {
            format!("mmdebstrap failed ({status}): {cause}; its output above has the details")
        }
        None => format!("mmdebstrap failed ({status}); its output above has the details"),
    }))
}

/// Publish the admitted root and its inventory with output-specific errors.
fn publish_outputs(
    tar: &Path,
    output: &Path,
    listed: &Path,
    packages_file: &Path,
) -> io::Result<()> {
    publish(tar, output)?;
    publish(listed, packages_file).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "factory root {} was published. Package inventory publication {} failed with {error}. \
             Preserve the root and rerun factory with a new TAR path",
                output.display(),
                packages_file.display()
            ),
        )
    })
}

/// No-clobber publication, also across filesystems.
fn publish(from: &Path, to: &Path) -> io::Result<()> {
    let result = (|| -> io::Result<()> {
        match rustix::fs::renameat_with(
            rustix::fs::CWD,
            from,
            rustix::fs::CWD,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                zfs_tools::engine::effect::mark();
                Ok(())
            }
            Err(rustix::io::Errno::XDEV) => {
                let mut input = File::open(from)?;
                let expected = hash(&mut input)?;
                input.seek(SeekFrom::Start(0))?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(to)?;
                // Creation publishes an output even if a later copy writes only a
                // prefix, or its final hash/readback fails.
                zfs_tools::engine::effect::mark();
                io::copy(&mut input, &mut output)?;
                output.sync_all()?;
                if hash(&mut File::open(to)?)? != expected {
                    return Err(refuse(format!("{} changed while published", to.display())));
                }
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    })();
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot publish {} as {}: {error}",
                from.display(),
                to.display()
            ),
        )
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Scratch(pub PathBuf);
    impl Scratch {
        pub(crate) fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("zboot-factory-test-{}", uuid::Uuid::new_v4()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Run effect classification in a fresh process so unrelated engine/fake
    /// tests cannot set this invocation's process-wide effect flag.
    pub(crate) fn classified_child(
        case: &str,
        retry: &str,
        expected_exit: i32,
        action: impl FnOnce(&Path) -> io::Result<()>,
    ) -> String {
        const CHILD: &str = "ZBOOT_ARTIFACT_EFFECT_CASE";
        if std::env::var(CHILD).ok().as_deref() == Some(case) {
            zfs_tools::engine::effect::reset();
            let result = {
                let scratch = Scratch::new();
                action(&scratch.0).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
            };
            std::process::exit(crate::cli::finish(result, None, false, retry));
        }
        let test = std::thread::current().name().unwrap().to_owned();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env(CHILD, case)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "child stdout: {}\nchild stderr: {stderr}",
            String::from_utf8_lossy(&output.stdout)
        );
        stderr
    }

    #[test]
    fn factory_jobs_accepts_only_the_distribution_job_grammar() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        assert_eq!(factory_jobs(None).unwrap(), 8);
        assert_eq!(factory_jobs(Some(OsStr::new(""))).unwrap(), 8);
        for (value, expected) in [
            ("1", 1),
            ("2", 2),
            ("8", 8),
            ("9", 9),
            ("10", 10),
            ("99", 99),
        ] {
            assert_eq!(factory_jobs(Some(OsStr::new(value))).unwrap(), expected);
        }
        for value in [
            "0", "00", "01", "100", "-1", "+1", " 2", "2 ", "2\n", "2;id", "２",
        ] {
            assert_eq!(
                factory_jobs(Some(OsStr::new(value)))
                    .unwrap_err()
                    .to_string(),
                "ZBOOT_JOBS must be 1 to 99",
                "{value:?}"
            );
        }
        let non_unicode = OsString::from_vec(vec![0xff]);
        assert_eq!(
            factory_jobs(Some(&non_unicode)).unwrap_err().to_string(),
            "ZBOOT_JOBS must be 1 to 99"
        );
    }

    #[test]
    fn factory_floor_omits_network_manager_and_firmware_linux_free() {
        assert!(!FLOOR.contains(&"network-manager"));
        assert!(!FLOOR.contains(&"firmware-linux-free"));
    }

    #[test]
    fn factory_floor_has_no_listening_daemon() {
        assert_eq!(
            FLOOR,
            [
                "linux-image-amd64",
                "linux-headers-amd64",
                "zfs-dkms",
                "zfs-initramfs",
                "systemd-sysv"
            ]
        );
        for daemon in [
            "openssh-server",
            "network-manager",
            "systemd-resolved",
            "avahi-daemon",
        ] {
            assert!(!FLOOR.contains(&daemon));
            assert!(!deb_depends().contains(&daemon));
        }
    }

    #[test]
    fn the_package_definition_names_zboot_and_plain_depends() {
        assert!(CONTROL.starts_with("Package: zboot\n"));
        assert!(CONTROL.ends_with('\n') && !CONTROL.contains("Version:"));
        let depends = deb_depends();
        assert!(depends.contains(&"zfsutils-linux"));
        // The probe's libc dependency is versioned; mmdebstrap gets the name.
        assert!(CONTROL.contains("libc6 (>= 2.34)") && depends.contains(&"libc6"));
        assert!(depends.iter().all(|name| atom(name)), "{depends:?}");
    }

    #[test]
    fn a_failed_mmdebstrap_is_refused_with_the_cause_its_output_named() {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/factory/fixtures/mmdebstrap-dkms-failure.log"
        );
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "cat -- \"$0\"; echo 'I: stdout ends' >&2; exit 25",
            fixture,
        ]);
        assert_eq!(
            run_mmdebstrap(command).unwrap_err().to_string(),
            "mmdebstrap failed (exit status 25): dpkg could not configure \
             linux-image-7.3.4+deb14-amd64, zfs-dkms, linux-image-amd64, zfs-initramfs; \
             its output above has the details"
        );
        let mut command = Command::new("sh");
        command.args(["-c", "echo 'E: setup failed: E: hook failed' >&2; exit 1"]);
        assert_eq!(
            run_mmdebstrap(command).unwrap_err().to_string(),
            "mmdebstrap failed (exit status 1); its output above has the details"
        );
        run_mmdebstrap(Command::new("true")).unwrap();
    }

    #[test]
    fn snapshot_epoch_is_the_utc_instant() {
        assert_eq!(snapshot_epoch("19700101T000000Z").unwrap(), 0);
        assert_eq!(snapshot_epoch("20261108T022935Z").unwrap(), 1_794_104_975);
        assert!(snapshot_epoch("20261108022935Z").is_err());
        assert!(snapshot_epoch("2026110xT022935Z").is_err());
    }

    #[test]
    fn the_installation_is_the_tools_beside_zboot_and_lib_zboot() {
        let scratch = Scratch::new();
        let usr = scratch.0.join("usr");
        let executable = usr.join("bin/zboot");
        for directory in ["bin", "sbin", "lib/zboot", "lib/tmpfiles.d"] {
            fs::create_dir_all(usr.join(directory)).unwrap();
        }
        // Each missing piece is named, in order.
        for path in [
            "bin/zboot",
            "bin/zsnap",
            "sbin/zboot-probe-signatures",
            "sbin/zboot-change-key",
            "lib/zboot/zboot.efi",
            "lib/tmpfiles.d/zfs-tools.conf",
            "share/doc/zboot",
        ] {
            let error = installation(&executable).unwrap_err().to_string();
            let missing = format!("{} is missing", usr.join(path).display());
            assert!(error.starts_with(&missing), "{error}");
            fs::create_dir_all(usr.join(path).parent().unwrap()).unwrap();
            fs::write(usr.join(path), b"x").unwrap();
        }
        let pieces = installation(&executable).unwrap();
        assert_eq!(
            pieces
                .iter()
                .map(|(_, packaged)| packaged.as_str())
                .collect::<Vec<_>>(),
            [
                "usr/bin/zboot",
                "usr/bin/zsnap",
                "usr/sbin/zboot-probe-signatures",
                "usr/sbin/zboot-change-key",
                "usr/lib/zboot/zboot.efi",
                "usr/lib/tmpfiles.d/zfs-tools.conf",
                "usr/share/doc/zboot",
            ]
        );
        fs::remove_file(usr.join("lib/zboot/zboot.efi")).unwrap();
        let error = installation(&executable).unwrap_err().to_string();
        assert!(error.contains("lib/zboot/zboot.efi is missing"), "{error}");
    }

    #[test]
    fn repackaging_preserves_the_complete_notice_tree() {
        let scratch = Scratch::new();
        let docs = scratch.0.join("docs");
        fs::create_dir_all(docs.join("LICENCES/debian")).unwrap();
        fs::write(docs.join("copyright"), b"project licence").unwrap();
        fs::write(
            docs.join("LICENCES/debian/components.json"),
            b"component provenance",
        )
        .unwrap();
        let deb = scratch.0.join("zboot.deb");
        package(
            &[(docs, "usr/share/doc/zboot".into())],
            &scratch.0.join("package"),
            &deb,
        )
        .unwrap();
        let extracted = scratch.0.join("extracted");
        assert!(
            Command::new("dpkg-deb")
                .arg("-x")
                .arg(&deb)
                .arg(&extracted)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            fs::read(extracted.join("usr/share/doc/zboot/copyright")).unwrap(),
            b"project licence"
        );
        assert_eq!(
            fs::read(extracted.join("usr/share/doc/zboot/LICENCES/debian/components.json"))
                .unwrap(),
            b"component provenance"
        );
    }

    #[test]
    fn factory_tar_published_before_inventory_failure_exits_4() {
        let stderr = classified_child("factory-inventory", "factory", 4, |root| {
            let tar = root.join("constructed-root.tar");
            let output = root.join("published-root.tar");
            let listed = root.join("constructed-packages.tsv");
            let packages = root.join("published-root.tar.packages");
            fs::write(&tar, b"admitted root payload")?;
            fs::write(&listed, b"package inventory")?;
            fs::create_dir(&packages)?;
            let result = publish_outputs(&tar, &output, &listed, &packages);
            assert!(result.is_err());
            assert_eq!(fs::read(&output)?, b"admitted root payload");
            assert!(listed.is_file());
            assert!(packages.is_dir());
            result
        });
        assert!(
            stderr.contains("published-root.tar was published"),
            "{stderr}"
        );
        assert!(stderr.contains("constructed-packages.tsv"), "{stderr}");
        assert!(stderr.contains("new TAR path"), "{stderr}");
    }

    #[test]
    fn factory_cross_device_partial_copy_exits_4() {
        let stderr = classified_child("factory-cross-device", "factory", 4, |root| {
            use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
            use std::{io::Write, os::fd::AsRawFd};
            // The anonymous RAM input and disk-backed destination force the
            // actual EXDEV branch without using a second persistent mount.
            let mut input = File::from(rustix::fs::memfd_create(
                "zboot-factory-publish",
                rustix::fs::MemfdFlags::CLOEXEC,
            )?);
            input.write_all(&[7; 8192])?;
            let from = PathBuf::from(format!("/proc/self/fd/{}", input.as_raw_fd()));
            let to = root.join("partial-root.tar");
            assert_ne!(input.metadata()?.dev(), fs::metadata(root)?.dev());
            // Bound this child's partial output rather than filling a disk.
            // SIGXFSZ stays blocked until this isolated process exits.
            let mut signals = SigSet::empty();
            signals.add(Signal::SIGXFSZ);
            pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
                .map_err(io::Error::other)?;
            rustix::process::setrlimit(
                rustix::process::Resource::Fsize,
                rustix::process::Rlimit {
                    current: Some(1024),
                    maximum: Some(1024),
                },
            )?;
            let result = publish(&from, &to);
            assert!(result.is_err());
            let length = fs::metadata(&to)?.len();
            assert!((1..=1024).contains(&length), "partial bytes: {length}");
            assert_eq!(input.metadata()?.len(), 8192);
            result
        });
        assert!(stderr.contains("/proc/self/fd/"), "{stderr}");
        assert!(stderr.contains("partial-root.tar"), "{stderr}");
    }

    #[test]
    fn prepublication_failure_remains_ordinary() {
        classified_child("factory-prepublication", "factory", 1, |root| {
            let result = publish(
                &root.join("missing-input.tar"),
                &root.join("absent-root.tar"),
            );
            assert!(result.is_err());
            assert!(!root.join("absent-root.tar").exists());
            assert!(!zfs_tools::engine::effect::any());
            result
        });
    }

    #[test]
    fn one_snapshot_timestamp_covers_every_archive_and_only_it_skips_expiry() {
        let lines = build_sources("forky", DEFAULT_MIRROR, Some("20261108T022935Z"));
        let snapshot = "https://snapshot.debian.org/archive";
        assert_eq!(
            lines,
            [
                format!(
                    "deb [check-valid-until=no] {snapshot}/debian/20261108T022935Z forky {COMPONENTS}"
                ),
                format!(
                    "deb [check-valid-until=no] {snapshot}/debian/20261108T022935Z forky-updates {COMPONENTS}"
                ),
                format!(
                    "deb [check-valid-until=no] {snapshot}/debian-security/20261108T022935Z forky-security {COMPONENTS}"
                ),
            ]
        );
        let live = build_sources("sid", "https://mirror.example/debian", None);
        assert_eq!(
            live,
            [format!(
                "deb https://mirror.example/debian sid {COMPONENTS}"
            )]
        );
        // The deployed root updates from the live mirror, never the snapshot.
        let deployed = deployed_sources("forky", DEFAULT_MIRROR);
        assert!(!deployed.contains("snapshot") && !deployed.contains("trusted"));
        assert!(deployed.contains("Suites: forky forky-updates\n"));
        assert!(deployed.contains("Suites: forky-security\n"));
        assert!(!deployed.contains("Suites: sid\n"));
    }

    #[test]
    fn requests_refuse_bad_names_mirrors_and_timestamps_before_any_work() {
        let scratch = Scratch::new();
        let base = Request {
            output: scratch.0.join("root.tar.zst"),
            suite: "forky".into(),
            mirror: DEFAULT_MIRROR.into(),
            snapshot: None,
            packages: vec![],
        };
        for broken in [
            Request {
                suite: "forky;rm".into(),
                ..base.clone()
            },
            Request {
                snapshot: Some("2026-11-08".into()),
                ..base.clone()
            },
            Request {
                packages: vec!["vim,curl".into()],
                ..base.clone()
            },
            Request {
                mirror: "ftp://x".into(),
                ..base.clone()
            },
        ] {
            assert!(build(&broken).is_err());
        }
        fs::write(&base.output, b"").unwrap();
        let error = build(&base).unwrap_err().to_string();
        assert!(error.contains("already exists"), "{error}");
        assert!(!scratch.0.join("root.tar.zst.packages").exists());
    }
}
