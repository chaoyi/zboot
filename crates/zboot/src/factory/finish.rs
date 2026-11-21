//! The factory's customize hook: runs as root of mmdebstrap's user namespace
//! with the finished package set in `root` (its `/dev`, `/proc` and `/sys`
//! mounted by mmdebstrap). In order:
//!
//! 1. zboot itself: the `zboot` package with `dpkg -i`, then each of
//!    `/usr/bin/{zboot,zsnap}` run once inside the root;
//! 2. no mount setting: the root keeps Debian's stock mounting;
//! 3. the OpenZFS cohort is one version (from the donor suite, if any);
//! 4. host identity and generated secrets are removed, and the deployed apt
//!    sources written, before any initrd is generated (the ZFS hook copies
//!    `/etc/hostid` and the pool cache);
//! 5. for every installed kernel (each `/usr/lib/modules` release with an
//!    image), never the builder's `uname -r`: matching chroot headers,
//!    `dkms install -k RELEASE`, `depmod`, and a ZFS module whose vermagic
//!    and dependencies resolve for it. Package scripts are not relied on;
//!    zfs-dkms's own trigger targets the builder's kernel;
//! 6. every initrd regenerated with initramfs-tools and checked for the ZFS
//!    module, script and tools and for no host identity or cache;
//! 7. the package inventory, for `TAR.packages`.
use super::{PACKAGE, Stage, TOOLS, atom, refuse};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

/// Files that identify a machine or hold a secret generated during
/// construction; every deployment would share them.
const IDENTITY: &[&str] = &[
    "etc/hostid",
    "etc/hostname",
    "etc/zfs/zpool.cache",
    "etc/nvme/hostid",
    "etc/nvme/hostnqn",
    "var/lib/dbus/machine-id",
    "var/lib/systemd/random-seed",
    "var/lib/dkms/mok.key",
    "var/lib/dkms/mok.pub",
    "etc/ssl/private/ssl-cert-snakeoil.key",
    "etc/ssl/certs/ssl-cert-snakeoil.pem",
    "var/cache/ldconfig/aux-cache",
    // mmdebstrap's build-time apt and dpkg options (no recommends, unsafe io).
    "etc/apt/apt.conf.d/99mmdebstrap",
    "etc/dpkg/dpkg.cfg.d/99mmdebstrap",
    "etc/apt/sources.list",
];

/// What an initrd must not carry: identity, the pool cache, mount caches.
/// (`etc/hostname` is always there: OpenZFS's hook copies the root's, else
/// the builder's `hostname`, so the factory gives it [`INITRD_HOSTNAME`].)
const INITRD_FORBIDDEN: &[&str] = &["etc/hostid", "etc/machine-id", "etc/zfs/zpool.cache"];

/// The hostname every factory initrd carries.
const INITRD_HOSTNAME: &[u8] = b"localhost\n";

/// A command inside the root; its stdout is returned, stderr passes through.
pub(crate) trait Run {
    fn run(&mut self, program: &str, args: &[&str]) -> io::Result<Vec<u8>>;
}

struct Chroot<'a>(&'a Path);
impl Run for Chroot<'_> {
    fn run(&mut self, program: &str, args: &[&str]) -> io::Result<Vec<u8>> {
        let output = zfs_tools::engine::native::announced(
            Command::new("chroot")
                .arg(self.0)
                .arg(program)
                .args(args)
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .env("LC_ALL", "C")
                .env("DEBIAN_FRONTEND", "noninteractive")
                .env("TMPDIR", "/tmp")
                .stdin(Stdio::null())
                .stderr(Stdio::inherit()),
        )
        .output()?;
        if !output.status.success() {
            return Err(refuse(format!(
                "factory: {program} {} failed with {}",
                args.join(" "),
                output.status
            )));
        }
        Ok(output.stdout)
    }
}

/// The hidden `zboot factory-finish ROOT STAGE` entry point.
pub fn finish_stage(root: &Path, stage: &Path) -> io::Result<()> {
    let plan: Stage =
        serde_json::from_slice(&fs::read(stage.join("stage.json"))?).map_err(refuse)?;
    finish(root, stage, &plan, &mut Chroot(root))
}

pub(crate) fn finish(
    root: &Path,
    stage: &Path,
    plan: &Stage,
    run: &mut impl Run,
) -> io::Result<()> {
    let step = |what: &'static str| move |e: io::Error| refuse(format!("factory {what}: {e}"));
    install_package(root, stage, run).map_err(step("zboot package"))?;
    let installed = parse_inventory(&query_inventory(run)?)?;
    let version = check_cohort(&installed).map_err(step("OpenZFS cohort"))?;
    if let Some(donor) = &plan.zfs_from_suite {
        check_donor(
            &run.run("apt-cache", &["madison", "zfsutils-linux"])?,
            &version,
            donor,
        )
        .map_err(step("OpenZFS donor"))?;
    }
    neutralize(root).map_err(step("host identity"))?;
    lock_root_password(root).map_err(step("root password"))?;
    install_missing_host_keys(root, installed.contains_key("openssh-server"))
        .map_err(step("SSH host-key generation"))?;
    write_new(
        &root.join("etc/apt/sources.list.d/debian.sources"),
        plan.sources.as_bytes(),
        0o644,
    )?;
    let kernels = kernels(root).map_err(step("kernels"))?;
    for release in &kernels {
        build_module(root, release, run).map_err(step("DKMS"))?;
    }
    for release in &kernels {
        let image = format!("/boot/initrd.img-{release}");
        remove(&root.join(image.trim_start_matches('/')))?;
        fs::write(root.join("etc/hostname"), INITRD_HOSTNAME)?;
        run.run("update-initramfs", &["-c", "-k", release])?;
        check_initrd(&run.run("lsinitramfs", &[&image])?, release).map_err(step("initrd"))?;
        verify_bzimage_release(
            &mut File::open(root.join(format!("boot/vmlinuz-{release}")))?,
            release,
        )
        .map_err(step("kernel"))?;
    }
    let (kernel, _) = crate::handoff::default_assets(root).map_err(refuse)?;
    if !kernels
        .iter()
        .any(|release| kernel == root.join(format!("boot/vmlinuz-{release}")))
    {
        return Err(refuse(format!(
            "factory default kernel {} is not an installed kernel",
            kernel.display()
        )));
    }
    // Nothing above may have recreated an identity file.
    neutralize(root).map_err(step("host identity"))?;
    lock_root_password(root).map_err(step("root password"))?;
    let listing = query_inventory(run)?;
    write_new(
        &root.join("tmp/zboot-factory.packages"),
        &render_inventory(&parse_inventory(&listing)?),
        0o644,
    )
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    remove(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// `dpkg -i` the staged package (mmdebstrap installed its Depends), then run
/// each tool once in the root: that catches an ABI mismatch with its libc.
fn install_package(root: &Path, stage: &Path, run: &mut impl Run) -> io::Result<()> {
    let inside = format!("/tmp/{PACKAGE}");
    let target = root.join(inside.trim_start_matches('/'));
    remove(&target)?;
    let mut copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&target)?;
    io::copy(&mut File::open(stage.join(PACKAGE))?, &mut copy)?;
    copy.sync_all()?;
    drop(copy);
    run.run("dpkg", &["-i", &inside])?;
    remove(&target)?;
    for name in TOOLS {
        run.run(&format!("/usr/bin/{name}"), &["--version"])?;
    }
    Ok(())
}

fn lock_root_password(root: &Path) -> io::Result<()> {
    let mut shadow = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("etc/shadow"))?;
    if !shadow.metadata()?.is_file() {
        return Err(refuse("shadow is not a regular file"));
    }
    let mut bytes = Vec::new();
    (&mut shadow).take(1_048_577).read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err(refuse("shadow exceeds its bound"));
    }
    let text = std::str::from_utf8(&bytes).map_err(refuse)?;
    let mut result = String::new();
    let mut roots = 0;
    for line in text.lines() {
        let mut fields: Vec<_> = line.split(':').collect();
        if fields.len() != 9 {
            return Err(refuse("shadow has malformed account fields"));
        }
        if fields[0] == "root" {
            roots += 1;
            fields[1] = "*";
        }
        result.push_str(&fields.join(":"));
        result.push('\n');
    }
    if roots != 1 {
        return Err(refuse("shadow must have exactly one root account"));
    }
    // Edit the held regular file so Debian's root:shadow owner/mode survive.
    shadow.seek(SeekFrom::Start(0))?;
    shadow.write_all(result.as_bytes())?;
    shadow.set_len(result.len() as u64)?;
    shadow.sync_all()
}

fn install_missing_host_keys(root: &Path, installed: bool) -> io::Result<()> {
    if !installed {
        return Ok(());
    }
    if !root.join("usr/sbin/sshd").is_file() {
        return Err(refuse("openssh-server is installed without /usr/sbin/sshd"));
    }
    write_new(
        &root.join("etc/systemd/system/zboot-ssh-keygen.service"),
        include_bytes!("zboot-ssh-keygen.service"),
        0o644,
    )?;
    let directory = root.join("etc/systemd/system/ssh.service.wants");
    fs::create_dir_all(&directory)?;
    let link = directory.join("zboot-ssh-keygen.service");
    remove(&link)?;
    std::os::unix::fs::symlink("/etc/systemd/system/zboot-ssh-keygen.service", link)
}

fn neutral_resolver(root: &Path) -> io::Result<()> {
    let path = root.join("etc/resolv.conf");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::read_link(&path)?;
            // Preserve the runtime resolver link without dereferencing it or
            // retaining a build-machine resolver file behind some other link.
            if target == Path::new("/run")
                || target.starts_with("/run/")
                || target == Path::new("../run")
                || target.starts_with("../run/")
            {
                if target
                    .components()
                    .skip(1)
                    .any(|part| part == std::path::Component::ParentDir)
                {
                    return remove(&path);
                }
                Ok(())
            } else {
                remove(&path)
            }
        }
        Ok(metadata) if metadata.is_file() => remove(&path),
        Ok(_) => Err(refuse(
            "resolv.conf is neither a regular file nor a runtime symlink",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn neutralize(root: &Path) -> io::Result<()> {
    neutral_resolver(root)?;
    for relative in IDENTITY {
        remove(&root.join(relative))?;
    }
    for directory in ["etc/ssh", "etc/zfs/zfs-list.cache"] {
        let Ok(entries) = fs::read_dir(root.join(directory)) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if directory == "etc/zfs/zfs-list.cache"
                || name.as_encoded_bytes().starts_with(b"ssh_host_")
            {
                remove(&entry.path())?;
            }
        }
    }
    // An empty machine-id: systemd generates one at first boot.
    write_new(&root.join("etc/machine-id"), b"", 0o444)
}

/// The installed kernels: every `/usr/lib/modules` release with an image in
/// `/boot`. A module tree with kernel modules but no image, or an image
/// without a module tree, is refused; a headers-only tree is skipped.
fn kernels(root: &Path) -> io::Result<Vec<String>> {
    let mut releases = Vec::new();
    for entry in fs::read_dir(root.join("usr/lib/modules"))? {
        let entry = entry?;
        let name = entry.file_name();
        let release = name
            .to_str()
            .filter(|r| atom(r))
            .ok_or_else(|| refuse(format!("unexpected module tree {name:?}")))?;
        let image = root.join(format!("boot/vmlinuz-{release}"));
        if fs::symlink_metadata(&image).is_ok_and(|m| m.is_file()) {
            releases.push(release.to_string());
        } else if entry.path().join("kernel").exists() {
            return Err(refuse(format!(
                "kernel modules {release} have no /boot image"
            )));
        }
    }
    for entry in fs::read_dir(root.join("boot"))? {
        let name = entry?.file_name();
        if let Some(release) = name.to_str().and_then(|n| n.strip_prefix("vmlinuz-"))
            && !releases.iter().any(|r| r == release)
        {
            return Err(refuse(format!("kernel image {release} has no module tree")));
        }
    }
    if releases.is_empty() {
        return Err(refuse("no kernel is installed"));
    }
    releases.sort();
    Ok(releases)
}

fn build_module(root: &Path, release: &str, run: &mut impl Run) -> io::Result<()> {
    if !root
        .join("usr/src")
        .join(format!("linux-headers-{release}"))
        .is_dir()
    {
        return Err(refuse(format!(
            "kernel {release} has no matching headers (linux-headers-{release}); DKMS cannot build ZFS for it"
        )));
    }
    let version = dkms_version(&run.run("dkms", &["status", "-m", "zfs"])?)?;
    let module = format!("zfs/{version}");
    if !dkms_installed(
        &run.run("dkms", &["status", "-m", "zfs"])?,
        &version,
        release,
    ) {
        run.run("dkms", &["install", &module, "-k", release])?;
    }
    if !dkms_installed(
        &run.run("dkms", &["status", "-m", "zfs"])?,
        &version,
        release,
    ) {
        return Err(refuse(format!(
            "DKMS did not install {module} for {release}"
        )));
    }
    run.run("depmod", &["-a", release])?;
    check_vermagic(
        &run.run("modinfo", &["-k", release, "-F", "vermagic", "zfs"])?,
        release,
    )?;
    check_depends(
        &run.run("modprobe", &["-S", release, "--show-depends", "zfs"])?,
        release,
    )
}

/// The one zfs module version DKMS knows, from `dkms status -m zfs` rows like
/// `zfs/2.4.4, 7.2.15+deb14-amd64, x86_64: installed` or `zfs/2.4.4: added`.
pub(crate) fn dkms_version(status: &[u8]) -> io::Result<String> {
    let text = String::from_utf8_lossy(status);
    let mut versions: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("zfs/"))
        .filter_map(|rest| rest.split([',', ':']).next())
        .map(str::trim)
        .collect();
    versions.sort();
    versions.dedup();
    match versions.as_slice() {
        [one] if atom(one) => Ok(one.to_string()),
        _ => Err(refuse(format!(
            "DKMS must know exactly one zfs module version, found {versions:?}"
        ))),
    }
}

pub(crate) fn dkms_installed(status: &[u8], version: &str, release: &str) -> bool {
    String::from_utf8_lossy(status).lines().any(|line| {
        let Some((key, state)) = line.rsplit_once(':') else {
            return false;
        };
        let fields: Vec<_> = key.split(',').map(str::trim).collect();
        state.trim().starts_with("installed")
            && fields.first() == Some(&format!("zfs/{version}").as_str())
            && fields.get(1) == Some(&release)
    })
}

pub(crate) fn check_vermagic(output: &[u8], release: &str) -> io::Result<()> {
    let text = String::from_utf8_lossy(output);
    let lines: Vec<_> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() != 1 || lines[0].split_whitespace().next() != Some(release) {
        return Err(refuse(format!(
            "the zfs module's vermagic {text:?} is not for {release}"
        )));
    }
    Ok(())
}

/// `modprobe --show-depends zfs` resolves every dependency to a module file
/// of `release`, ending with zfs itself; spl must be among them.
pub(crate) fn check_depends(output: &[u8], release: &str) -> io::Result<()> {
    let text = String::from_utf8_lossy(output);
    let mut modules = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let (Some("insmod"), Some(path)) = (fields.next(), fields.next()) else {
            return Err(refuse(format!("zfs depends on a non-module: {line:?}")));
        };
        let inside = path
            .strip_prefix("/usr")
            .unwrap_or(path)
            .strip_prefix(&format!("/lib/modules/{release}/"));
        let name = path.rsplit('/').next().unwrap_or("");
        if inside.is_none() {
            return Err(refuse(format!("{path} is not a module of {release}")));
        }
        modules.push(name.split('.').next().unwrap_or("").to_string());
    }
    if modules.last().map(String::as_str) != Some("zfs") || !modules.iter().any(|m| m == "spl") {
        return Err(refuse(format!(
            "zfs for {release} does not resolve with spl: {modules:?}"
        )));
    }
    Ok(())
}

/// An `lsinitramfs` listing: the ZFS and SPL modules of `release` (exactly
/// one each), the ZFS boot script, `zpool` and `zfs`; no identity or cache.
pub(crate) fn check_initrd(listing: &[u8], release: &str) -> io::Result<()> {
    let text = String::from_utf8_lossy(listing);
    let paths: Vec<&str> = text
        .lines()
        .map(|line| line.trim().trim_start_matches("./").trim_start_matches('/'))
        .filter(|p| !p.is_empty())
        .collect();
    let module = |name: &str| {
        paths
            .iter()
            .filter(|path| {
                let path = path.strip_prefix("usr/").unwrap_or(path);
                path.strip_prefix(&format!("lib/modules/{release}/"))
                    .and_then(|rest| rest.rsplit('/').next())
                    .is_some_and(|file| {
                        file.split_once('.')
                            .is_some_and(|(stem, ext)| stem == name && ext.starts_with("ko"))
                    })
            })
            .count()
    };
    let tool = |name: &str| {
        paths
            .iter()
            .any(|p| p.strip_prefix("usr/").unwrap_or(p) == format!("sbin/{name}"))
    };
    let mut missing = Vec::new();
    for name in ["zfs", "spl"] {
        if module(name) != 1 {
            missing.push(format!("one {name} module for {release}"));
        }
    }
    if !paths.contains(&"scripts/zfs") {
        missing.push("scripts/zfs".into());
    }
    for name in ["zpool", "zfs"] {
        if !tool(name) {
            missing.push(format!("sbin/{name}"));
        }
    }
    if !missing.is_empty() {
        return Err(refuse(format!(
            "initrd for {release} lacks {}",
            missing.join(", ")
        )));
    }
    let carried: Vec<_> = paths
        .iter()
        .filter(|p| {
            INITRD_FORBIDDEN.contains(p)
                || p.starts_with("etc/zfs/zfs-list.cache/")
                || p.starts_with("etc/ssh/ssh_host_")
        })
        .collect();
    if !carried.is_empty() {
        return Err(refuse(format!(
            "initrd for {release} carries host identity or caches: {carried:?}"
        )));
    }
    Ok(())
}

fn query_inventory(run: &mut impl Run) -> io::Result<Vec<u8>> {
    run.run(
        "dpkg-query",
        &[
            "-W",
            "-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\n",
        ],
    )
}

/// Installed packages (`ii`) as name -> (version, architecture). Accepts the
/// raw `dpkg-query` rows and the published `TAR.packages` rows alike.
pub(crate) fn parse_inventory(bytes: &[u8]) -> io::Result<BTreeMap<String, (String, String)>> {
    let text = std::str::from_utf8(bytes).map_err(refuse)?;
    let mut packages = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        let fields = match fields.as_slice() {
            [status, rest @ ..] if rest.len() == 3 => {
                if status.trim() != "ii" {
                    continue;
                }
                rest.to_vec()
            }
            rest if rest.len() == 3 => rest.to_vec(),
            _ => {
                return Err(refuse(format!(
                    "unsupported package inventory row {line:?}"
                )));
            }
        };
        let name = fields[0].split(':').next().unwrap_or("");
        if !atom(name) || !atom(fields[1]) || !atom(fields[2]) {
            return Err(refuse(format!(
                "unsupported package inventory row {line:?}"
            )));
        }
        packages.insert(
            name.to_string(),
            (fields[1].to_string(), fields[2].to_string()),
        );
    }
    if packages.is_empty() {
        return Err(refuse("the package inventory is empty"));
    }
    Ok(packages)
}

fn render_inventory(packages: &BTreeMap<String, (String, String)>) -> Vec<u8> {
    packages
        .iter()
        .map(|(name, (version, arch))| format!("{name}\t{version}\t{arch}\n"))
        .collect::<String>()
        .into_bytes()
}

fn in_cohort(name: &str) -> bool {
    matches!(
        name,
        "zfs-dkms" | "zfsutils-linux" | "zfs-zed" | "zfs-initramfs" | "zfs-dracut" | "libpam-zfs"
    ) || ["libzfs", "libzpool", "libnvpair", "libuutil"]
        .iter()
        .any(|prefix| name.starts_with(prefix) && name.ends_with("linux"))
}

/// The OpenZFS cohort is installed at one version; returns it.
pub(crate) fn check_cohort(packages: &BTreeMap<String, (String, String)>) -> io::Result<String> {
    for required in ["zfs-dkms", "zfsutils-linux", "zfs-initramfs"] {
        if !packages.contains_key(required) {
            return Err(refuse(format!("{required} is not installed")));
        }
    }
    let versions: BTreeMap<_, _> = packages
        .iter()
        .filter(|(name, _)| in_cohort(name))
        .map(|(name, (version, _))| (name.as_str(), version.as_str()))
        .collect();
    let mut distinct: Vec<_> = versions.values().collect();
    distinct.sort();
    distinct.dedup();
    if distinct.len() != 1 {
        return Err(refuse(format!(
            "the OpenZFS packages are not one version: {versions:?}"
        )));
    }
    Ok(distinct[0].to_string())
}

/// `apt-cache madison` shows the installed cohort version offered by the
/// donor suite.
pub(crate) fn check_donor(madison: &[u8], version: &str, donor: &str) -> io::Result<()> {
    let text = String::from_utf8_lossy(madison);
    if !text.lines().any(|line| {
        let fields: Vec<_> = line.split('|').map(str::trim).collect();
        fields.len() >= 3
            && fields[1] == version
            && fields[2]
                .split_whitespace()
                .any(|f| f.starts_with(&format!("{donor}/")))
    }) {
        return Err(refuse(format!(
            "the installed OpenZFS {version} is not the {donor} suite's"
        )));
    }
    Ok(())
}

pub(crate) fn verify_bzimage_release(file: &mut File, release: &str) -> io::Result<()> {
    let mut header = [0_u8; 0x210];
    file.read_exact(&mut header)?;
    if header[0x1fe..0x200] != [0x55, 0xaa] || &header[0x202..0x206] != b"HdrS" {
        return Err(refuse("kernel image is not an x86 bzImage"));
    }
    // Linux boot protocol's kernel_version is relative to the setup segment.
    let offset = 0x200 + u16::from_le_bytes([header[0x20e], header[0x20f]]) as u64;
    file.seek(SeekFrom::Start(offset))?;
    let mut version = Vec::new();
    (&mut *file).take(256).read_to_end(&mut version)?;
    let text = version
        .split(|byte| *byte == 0)
        .next()
        .filter(|_| version.contains(&0))
        .ok_or_else(|| refuse("bzImage has no bounded version string"))?;
    if !text.starts_with(release.as_bytes()) || text.get(release.len()) != Some(&b' ') {
        return Err(refuse(format!("bzImage is not release {release}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory::tests::Scratch;
    use std::path::PathBuf;
    const R: &str = "7.2.15+deb14-amd64";

    fn listing(extra: &[&str], skip: &str) -> Vec<u8> {
        [
            "usr/lib/modules/7.2.15+deb14-amd64/updates/dkms/zfs.ko.xz",
            "usr/lib/modules/7.2.15+deb14-amd64/updates/dkms/spl.ko.xz",
            "scripts/zfs",
            "usr/sbin/zpool",
            "usr/sbin/zfs",
            "etc/zfs/zfs/vdev_id.conf",
        ]
        .iter()
        .chain(extra)
        .filter(|p| **p != skip)
        .map(|p| format!("{p}\n"))
        .collect::<String>()
        .into_bytes()
    }

    #[test]
    fn factory_installs_missing_key_generation_only_with_sshd() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        let absent = parse_inventory(
            b"ii \tzfs-initramfs\t2.4.4-1\tall\nrc \topenssh-server\t10.2p1-2\tamd64\n",
        )
        .unwrap();
        install_missing_host_keys(root, absent.contains_key("openssh-server")).unwrap();
        assert!(
            !root
                .join("etc/systemd/system/zboot-ssh-keygen.service")
                .exists()
        );
        fs::create_dir_all(root.join("usr/sbin")).unwrap();
        fs::write(root.join("usr/sbin/sshd"), b"sshd").unwrap();
        let present = parse_inventory(b"ii \topenssh-server\t10.2p1-2\tamd64\n").unwrap();
        install_missing_host_keys(root, present.contains_key("openssh-server")).unwrap();
        let unit =
            fs::read_to_string(root.join("etc/systemd/system/zboot-ssh-keygen.service")).unwrap();
        assert!(unit.contains("Before=ssh.service\n"));
        assert!(!unit.contains("ssh.socket\n"));
        assert!(!unit.contains("ConditionFirstBoot="));
        assert!(unit.contains("ExecStart=/usr/bin/ssh-keygen -A\n"));
        for kind in ["rsa", "ecdsa", "ed25519"] {
            assert!(unit.contains(&format!(
                "ConditionPathExists=|!/etc/ssh/ssh_host_{kind}_key\n"
            )));
        }
        assert_eq!(
            fs::read_link(
                root.join("etc/systemd/system/ssh.service.wants/zboot-ssh-keygen.service")
            )
            .unwrap(),
            Path::new("/etc/systemd/system/zboot-ssh-keygen.service")
        );
        assert!(!root.join("etc/systemd/system/ssh.socket.wants").exists());
    }

    fn host_keys(root: &Path) -> BTreeMap<String, Vec<u8>> {
        ["rsa", "ecdsa", "ed25519"]
            .into_iter()
            .map(|kind| {
                let name = format!("ssh_host_{kind}_key");
                let bytes = fs::read(root.join("etc/ssh").join(&name)).unwrap();
                (name, bytes)
            })
            .collect()
    }

    fn generate_missing(root: &Path) {
        fs::create_dir_all(root.join("etc/ssh")).unwrap();
        assert!(
            Command::new("ssh-keygen")
                .args(["-A", "-f"])
                .arg(root)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn factory_host_keys_are_stable_on_disk_and_ephemeral_on_a_stick() {
        let scratch = Scratch::new();
        let persistent = scratch.0.join("persistent");
        generate_missing(&persistent);
        let first = host_keys(&persistent);
        generate_missing(&persistent);
        assert_eq!(host_keys(&persistent), first);
        // Separate empty roots model successive disposable RAM upper layers;
        // no initramfs or real mount is claimed by this key-generator test.
        let boot_one = scratch.0.join("upper-one");
        let boot_two = scratch.0.join("upper-two");
        generate_missing(&boot_one);
        generate_missing(&boot_two);
        assert_ne!(host_keys(&boot_one), host_keys(&boot_two));
    }

    #[test]
    fn overlay_supplied_host_keys_are_preserved() {
        let scratch = Scratch::new();
        generate_missing(&scratch.0);
        let supplied = fs::read(scratch.0.join("etc/ssh/ssh_host_ed25519_key")).unwrap();
        for kind in ["rsa", "ecdsa"] {
            fs::remove_file(scratch.0.join(format!("etc/ssh/ssh_host_{kind}_key"))).unwrap();
        }
        generate_missing(&scratch.0);
        assert_eq!(
            fs::read(scratch.0.join("etc/ssh/ssh_host_ed25519_key")).unwrap(),
            supplied
        );
    }

    #[test]
    fn a_resolv_conf_run_symlink_survives_the_finish_and_a_file_does_not() {
        let scratch = Scratch::new();
        fs::create_dir_all(scratch.0.join("etc")).unwrap();
        let path = scratch.0.join("etc/resolv.conf");
        for target in [
            "/run/systemd/resolve/stub-resolv.conf",
            "../run/systemd/resolve/stub-resolv.conf",
        ] {
            std::os::unix::fs::symlink(target, &path).unwrap();
            neutralize(&scratch.0).unwrap();
            assert_eq!(fs::read_link(&path).unwrap(), Path::new(target));
            fs::remove_file(&path).unwrap();
        }
        fs::write(&path, b"nameserver 192.0.2.1\n").unwrap();
        neutralize(&scratch.0).unwrap();
        assert!(!path.exists());
        for target in [
            "/etc/build-host-resolver",
            "/run/../etc/build-host-resolver",
        ] {
            std::os::unix::fs::symlink(target, &path).unwrap();
            neutralize(&scratch.0).unwrap();
            assert!(fs::symlink_metadata(&path).is_err());
        }
        fs::write(
            scratch.0.join("etc/shadow"),
            b"root:builder:1:0:99999:7:::\nuser:*:1:0:99999:7:::\n",
        )
        .unwrap();
        lock_root_password(&scratch.0).unwrap();
        assert_eq!(
            fs::read(scratch.0.join("etc/shadow")).unwrap(),
            b"root:*:1:0:99999:7:::\nuser:*:1:0:99999:7:::\n"
        );
    }

    #[test]
    fn initrds_need_zfs_for_their_kernel_and_carry_no_identity() {
        check_initrd(&listing(&[], ""), R).unwrap();
        for skip in [
            "usr/lib/modules/7.2.15+deb14-amd64/updates/dkms/zfs.ko.xz",
            "usr/lib/modules/7.2.15+deb14-amd64/updates/dkms/spl.ko.xz",
            "scripts/zfs",
            "usr/sbin/zpool",
        ] {
            assert!(check_initrd(&listing(&[], skip), R).is_err(), "{skip}");
        }
        // Another kernel's module does not count; two of one is ambiguous.
        assert!(check_initrd(&listing(&[], ""), "7.2.16+deb14-amd64").is_err());
        assert!(
            check_initrd(
                &listing(&["usr/lib/modules/7.2.15+deb14-amd64/extra/zfs.ko"], ""),
                R
            )
            .is_err()
        );
        for identity in [
            "etc/hostid",
            "etc/zfs/zpool.cache",
            "etc/zfs/zfs-list.cache/rpool",
        ] {
            let error = check_initrd(&listing(&[identity], ""), R).unwrap_err();
            assert!(error.to_string().contains("identity"), "{error}");
        }
    }

    #[test]
    fn dkms_status_must_name_one_version_installed_for_the_kernel() {
        let built = format!("zfs/2.4.4, {R}, x86_64: installed\n");
        assert_eq!(dkms_version(built.as_bytes()).unwrap(), "2.4.4");
        assert_eq!(dkms_version(b"zfs/2.4.4: added\n").unwrap(), "2.4.4");
        assert!(dkms_version(b"").is_err());
        assert!(dkms_version(b"zfs/2.4.4: added\nzfs/2.4.5: added\n").is_err());
        assert!(dkms_installed(built.as_bytes(), "2.4.4", R));
        assert!(!dkms_installed(
            built.as_bytes(),
            "2.4.4",
            "7.2.16+deb14-amd64"
        ));
        let broken = format!("zfs/2.4.4, {R}, x86_64: built\n");
        assert!(!dkms_installed(broken.as_bytes(), "2.4.4", R));
    }

    #[test]
    fn the_module_matches_its_kernel_and_resolves_with_spl() {
        check_vermagic(
            format!("{R} SMP preempt mod_unload modversions\n").as_bytes(),
            R,
        )
        .unwrap();
        assert!(check_vermagic(b"7.2.14+deb14-amd64 SMP\n", R).is_err());
        assert!(check_vermagic(b"", R).is_err());
        let deps = format!(
            "insmod /lib/modules/{R}/updates/dkms/spl.ko.xz\ninsmod /lib/modules/{R}/updates/dkms/zfs.ko.xz\n"
        );
        check_depends(deps.as_bytes(), R).unwrap();
        assert!(
            check_depends(
                format!("insmod /lib/modules/{R}/updates/dkms/zfs.ko.xz\n").as_bytes(),
                R
            )
            .is_err()
        );
        assert!(
            check_depends(
                b"insmod /lib/modules/other/spl.ko\ninsmod /lib/modules/other/zfs.ko\n",
                R
            )
            .is_err()
        );
        assert!(
            check_depends(
                format!("builtin spl\ninsmod /lib/modules/{R}/zfs.ko\n").as_bytes(),
                R
            )
            .is_err()
        );
    }

    #[test]
    fn the_openzfs_cohort_is_one_version_from_the_donor() {
        let rows = |zfs: &str, lib: &str| {
            format!(
                "ii \tzfs-dkms\t{zfs}\tall\nii \tzfsutils-linux\t{zfs}\tamd64\nii \tzfs-zed\t{zfs}\tamd64\nii \tzfs-initramfs\t{zfs}\tall\nii \tlibzfs7linux:amd64\t{lib}\tamd64\nrc \tlibzfs6linux:amd64\t2.3.1-1\tamd64\nii \tbash\t5.3-1\tamd64\n"
            )
        };
        let same = parse_inventory(rows("2.4.4-1", "2.4.4-1").as_bytes()).unwrap();
        assert!(!same.contains_key("libzfs6linux"));
        assert_eq!(check_cohort(&same).unwrap(), "2.4.4-1");
        let mixed = parse_inventory(rows("2.4.4-1", "2.4.3-2").as_bytes()).unwrap();
        assert!(check_cohort(&mixed).is_err());
        let madison = b"zfsutils-linux |    2.4.4-1 | https://deb.debian.org/debian sid/contrib amd64 Packages\nzfsutils-linux |    2.4.3-2 | https://deb.debian.org/debian forky/contrib amd64 Packages\n";
        check_donor(madison, "2.4.4-1", "sid").unwrap();
        assert!(check_donor(madison, "2.4.3-2", "sid").is_err());
        // The published rows read back the same.
        let published = render_inventory(&same);
        assert_eq!(parse_inventory(&published).unwrap(), same);
    }

    /// Records commands and answers like a finished Debian root would.
    struct Fake {
        root: PathBuf,
        calls: Vec<String>,
    }
    impl Run for Fake {
        fn run(&mut self, program: &str, args: &[&str]) -> io::Result<Vec<u8>> {
            let call = format!("{program} {}", args.join(" "));
            self.calls.push(call.clone());
            Ok(match program {
                "dpkg-query" => b"ii \tzfs-dkms\t2.4.4-1\tall\nii \tzfsutils-linux\t2.4.4-1\tamd64\nii \tzfs-zed\t2.4.4-1\tamd64\nii \tzfs-initramfs\t2.4.4-1\tall\n".to_vec(),
                "dkms" if self.calls.iter().any(|c| c.starts_with("dkms install")) => {
                    format!("zfs/2.4.4, {R}, x86_64: installed\n").into_bytes()
                }
                "dkms" => b"zfs/2.4.4: added\n".to_vec(),
                "modinfo" => format!("{R} SMP\n").into_bytes(),
                "modprobe" => format!("insmod /lib/modules/{R}/updates/dkms/spl.ko.xz\ninsmod /lib/modules/{R}/updates/dkms/zfs.ko.xz\n").into_bytes(),
                "update-initramfs" => {
                    // The hook would copy these into the initrd if present.
                    assert!(!self.root.join("etc/hostid").exists());
                    assert_eq!(fs::read(self.root.join("etc/hostname")).unwrap(), b"localhost\n");
                    fs::write(self.root.join(format!("boot/initrd.img-{R}")), b"new").unwrap();
                    Vec::new()
                }
                "lsinitramfs" => listing(&[], ""),
                "dpkg" => {
                    assert_eq!(args, ["-i", "/tmp/zboot.deb"]);
                    assert_eq!(fs::read(self.root.join("tmp/zboot.deb")).unwrap(), b"package");
                    Vec::new()
                }
                _ => Vec::new(),
            })
        }
    }

    fn bzimage(release: &str) -> Vec<u8> {
        let mut image = vec![0_u8; 0x400];
        image[0x1fe] = 0x55;
        image[0x1ff] = 0xaa;
        image[0x202..0x206].copy_from_slice(b"HdrS");
        image[0x20e..0x210].copy_from_slice(&0x100_u16.to_le_bytes());
        let text = format!("{release} (debian-kernel@lists.debian.org)\0");
        image[0x300..0x300 + text.len()].copy_from_slice(text.as_bytes());
        image
    }

    #[test]
    fn finishing_builds_the_module_before_initrds_and_clears_identity_first() {
        let scratch = Scratch::new();
        let (root, stage) = (scratch.0.join("root"), scratch.0.join("stage"));
        for dir in [
            "boot",
            "usr/bin",
            &format!("usr/lib/modules/{R}"),
            &format!("usr/src/linux-headers-{R}"),
            "etc/ssh",
            "tmp",
        ] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join(format!("boot/vmlinuz-{R}")), bzimage(R)).unwrap();
        fs::write(root.join(format!("boot/initrd.img-{R}")), b"old").unwrap();
        std::os::unix::fs::symlink(format!("boot/vmlinuz-{R}"), root.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink(format!("boot/initrd.img-{R}"), root.join("initrd.img"))
            .unwrap();
        for identity in [
            "etc/hostid",
            "etc/hostname",
            "etc/resolv.conf",
            "etc/ssh/ssh_host_ed25519_key",
        ] {
            fs::write(root.join(identity), b"builder").unwrap();
        }
        fs::write(root.join("etc/shadow"), b"root:!:1:0:99999:7:::\n").unwrap();
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join(PACKAGE), b"package").unwrap();
        let plan = Stage {
            sources: "Types: deb\n".into(),
            zfs_from_suite: None,
        };
        let mut fake = Fake {
            root: root.clone(),
            calls: Vec::new(),
        };
        finish(&root, &stage, &plan, &mut fake).unwrap();
        let position = |prefix: &str| {
            fake.calls
                .iter()
                .position(|c| c.starts_with(prefix))
                .unwrap()
        };
        assert_eq!(position("dpkg -i"), 0);
        assert!(position("/usr/bin/zsnap --version") < position("dpkg-query"));
        assert!(!root.join("tmp/zboot.deb").exists());
        assert!(position("dkms install") < position("depmod -a"));
        assert!(position("depmod -a") < position("update-initramfs"));
        assert!(position("modprobe") < position("update-initramfs"));
        assert_eq!(fs::read(root.join("etc/machine-id")).unwrap(), b"");
        assert!(!root.join("etc/ssh/ssh_host_ed25519_key").exists());
        assert!(root.join("tmp/zboot-factory.packages").is_file());
        assert!(
            fake.calls
                .contains(&format!("dkms install zfs/2.4.4 -k {R}"))
        );
    }

    #[test]
    fn finishing_refuses_a_kernel_without_headers_before_any_initrd() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        fs::create_dir_all(root.join(format!("usr/lib/modules/{R}"))).unwrap();
        let mut fake = Fake {
            root: root.clone(),
            calls: Vec::new(),
        };
        let error = build_module(root, R, &mut fake).unwrap_err();
        assert!(error.to_string().contains("headers"), "{error}");
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn bzimage_release_is_read_from_the_boot_header() {
        let scratch = Scratch::new();
        let path = scratch.0.join("vmlinuz");
        fs::write(&path, bzimage(R)).unwrap();
        verify_bzimage_release(&mut File::open(&path).unwrap(), R).unwrap();
        assert!(verify_bzimage_release(&mut File::open(&path).unwrap(), "7.2.15").is_err());
        fs::write(&path, vec![0; 0x400]).unwrap();
        assert!(verify_bzimage_release(&mut File::open(&path).unwrap(), R).is_err());
    }
}
