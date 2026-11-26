//! Host identity. A host is one hostid: the SPL module's effective value (what
//! the kernel and libzfs use, and what "running hostid" means everywhere), the
//! `/etc/hostid` a BE carries, and the value OpenZFS records in the labels of
//! every pool the host imports. Zboot never invents an identity for an
//! existing installation: a missing, zero, malformed, unreadable or conflicting
//! one is reported. Only `deploy` chooses a hostid, for the BE it creates.
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

use rustix::fs::{Mode, OFlags, ResolveFlags};

/// The effective hostid both the kernel and libzfs use.
pub const EFFECTIVE: &str = "/proc/sys/kernel/spl/hostid";
const MAX_LABEL_OUTPUT: usize = 1024 * 1024;

fn refuse(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

/// Eight hex digits, as zboot prints and records a hostid.
pub fn format(hostid: u32) -> String {
    format!("{hostid:08x}")
}

/// A hostid given as eight hex digits; 00000000 and ffffffff are reserved.
pub fn parse(value: &str) -> io::Result<u32> {
    (value.len() == 8 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(value, 16).ok())
        .flatten()
        .filter(|hostid| *hostid != 0 && *hostid != u32::MAX)
        .ok_or_else(|| refuse("hostid must be eight hex digits, excluding 00000000 and ffffffff"))
}

/// `/proc/sys/kernel/spl/hostid` as the kernel prints it.
pub fn parse_effective(text: &str) -> io::Result<u32> {
    let value = text.trim();
    let value = value.strip_prefix("0x").unwrap_or(value);
    u32::from_str_radix(value, 16).map_err(|_| refuse("the effective SPL hostid is not hex"))
}

/// The running hostid: the SPL module's effective value.
pub fn effective() -> io::Result<u32> {
    parse_effective(
        &fs::read_to_string(EFFECTIVE)
            .map_err(|error| refuse(format!("read the effective SPL hostid: {error}")))?,
    )
}

/// What a root's `/etc/hostid` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installed {
    Hostid(u32),
    Missing,
    Zero,
    /// Not four bytes, or the reserved ffffffff.
    Malformed,
    Unreadable(String),
}

impl Installed {
    /// The hostid, or why `whose` has none that zboot may use.
    pub fn require(&self, whose: &str) -> io::Result<u32> {
        match self {
            Self::Hostid(hostid) => Ok(*hostid),
            Self::Missing => Err(refuse(format!("{whose} has no /etc/hostid"))),
            Self::Zero => Err(refuse(format!("{whose} has a zero /etc/hostid"))),
            Self::Malformed => Err(refuse(format!(
                "{whose} has a malformed /etc/hostid (not four bytes, or ffffffff)"
            ))),
            Self::Unreadable(why) => Err(refuse(format!(
                "{whose}'s /etc/hostid is unreadable: {why}"
            ))),
        }
    }
}

/// Decode the bytes of an `/etc/hostid` (Linux's little-endian binary form).
pub fn decode(bytes: &[u8]) -> Installed {
    match <[u8; 4]>::try_from(bytes).map(u32::from_le_bytes) {
        Ok(0) => Installed::Zero,
        Ok(u32::MAX) | Err(_) => Installed::Malformed,
        Ok(hostid) => Installed::Hostid(hostid),
    }
}

/// `etc/hostid` beneath `root`, never following a symlink out of it.
pub fn installed(root: &File) -> Installed {
    let fd = match crate::openat2_scoped(
        root,
        "etc/hostid",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Installed::Missing,
        Err(error) => return Installed::Unreadable(error.to_string()),
    };
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    match file.metadata() {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Installed::Malformed,
        Err(error) => return Installed::Unreadable(error.to_string()),
    }
    match (&mut file).take(5).read_to_end(&mut bytes) {
        Ok(_) => decode(&bytes),
        Err(error) => Installed::Unreadable(error.to_string()),
    }
}

/// The `/etc/hostid` of a dataset or snapshot, read from a private read-only
/// mount of exactly it in a mount namespace of its own. Its pool may be
/// imported read-only; nothing else is mounted or changed.
pub fn installed_in(source: &str) -> Installed {
    match read_in(source) {
        Ok(found) => found,
        Err(error) => Installed::Unreadable(error.to_string()),
    }
}

fn read_in(source: &str) -> io::Result<Installed> {
    readonly_view(source, |root| Ok(installed(&File::open(root)?)))
}

/// Inspect exactly one dataset or snapshot through a private read-only mount.
/// An already mounted filesystem gets a read-only bind view, preserving the
/// original superblock and mount mode. This is an observation, including when
/// its pool is imported writable.
pub(crate) fn readonly_view<T: Send>(
    source: &str,
    read: impl FnOnce(&Path) -> io::Result<T> + Send,
) -> io::Result<T> {
    if source.contains('@') {
        zfs_tools::engine::validate_snapshot_name(source).map_err(refuse)?;
    } else {
        zfs_tools::engine::validate_dataset_name(source).map_err(refuse)?;
    }
    crate::mount_view::readonly(crate::mount_view::Source::Zfs(source), || Ok(()), read)
}

/// One ZFS label's top-level identity, as `zdb -l` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub path: String,
    pub name: String,
    pub pool_guid: u64,
    /// Leaf vdev identity, absent only in older label observations.
    pub vdev_guid: Option<u64>,
    /// OpenZFS pool state: 0 active (in use), 1 exported, ...
    pub state: u64,
    /// 0 when the label records none.
    pub hostid: u32,
}

/// OpenZFS pool label state for a pool that is in use (not exported).
pub const POOL_STATE_ACTIVE: u64 = 0;

/// Every distinct label `zdb -l` prints for one device. zdb prints identical
/// labels once (`labels = 0 1 2 3`) and each differing label separately, so a
/// device whose labels disagree contributes each version. Pure for tests.
pub fn parse_labels(path: &str, text: &str) -> io::Result<Vec<Label>> {
    let mut labels: Vec<Label> = Vec::new();
    let mut section = String::new();
    let mut in_label = false;
    for line in text.lines().chain(std::iter::once("LABEL end")) {
        if line.starts_with("LABEL ") {
            if in_label
                && let Some(label) = parse_label(path, &section)?
                && !labels.contains(&label)
            {
                labels.push(label);
            }
            in_label = true;
            section.clear();
        } else if in_label {
            section.push_str(line);
            section.push('\n');
        }
    }
    Ok(labels)
}

fn parse_label(path: &str, text: &str) -> io::Result<Option<Label>> {
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        // Top-level label pairs are indented by exactly four spaces; the
        // vdev tree and feature lists follow at deeper indentation.
        let Some(pair) = line.strip_prefix("    ") else {
            continue;
        };
        if pair.starts_with(' ') {
            continue;
        }
        if pair == "vdev_tree:" {
            if values.contains_key("pool_guid") {
                break;
            }
            continue;
        }
        if let Some((key, value)) = pair.split_once(": ")
            && matches!(key, "name" | "state" | "pool_guid" | "hostid" | "guid")
            && values.insert(key, value).is_some()
        {
            return Err(refuse(format!(
                "pool label on {} repeats {key}",
                zfs_tools::engine::escape_display(path)
            )));
        }
    }
    // Spare and cache devices carry no pool name or GUID; they are imported
    // with their pool and never decide its owner.
    let (Some(name), Some(state), Some(pool_guid)) = (
        values.get("name"),
        values.get("state"),
        values.get("pool_guid"),
    ) else {
        return Ok(None);
    };
    let bad = |what: &str| {
        refuse(format!(
            "pool label on {} has an invalid {what}",
            zfs_tools::engine::escape_display(path)
        ))
    };
    let name = name
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| bad("name"))?;
    let hostid = match values.get("hostid") {
        Some(value) => u32::try_from(value.parse::<u64>().map_err(|_| bad("hostid"))?)
            .map_err(|_| bad("hostid"))?,
        None => 0,
    };
    let vdev_guid = values
        .get("guid")
        .map(|value| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(bad("vdev GUID"));
            }
            value
                .parse::<u64>()
                .ok()
                .filter(|guid| *guid != 0)
                .ok_or_else(|| bad("vdev GUID"))
        })
        .transpose()?;
    Ok(Some(Label {
        path: path.to_owned(),
        name: name.to_owned(),
        pool_guid: pool_guid.parse().map_err(|_| bad("pool GUID"))?,
        vdev_guid,
        state: state.parse().map_err(|_| bad("state"))?,
        hostid,
    }))
}

/// The labels of one device. zdb exits nonzero when any of the four labels is
/// unreadable; the remaining labels still describe the pool.
pub fn read_labels(path: &str) -> io::Result<Vec<Label>> {
    let output =
        crate::native_run::run_status("zdb", &["-l".into(), path.into()], MAX_LABEL_OUTPUT, 30)
            .map_err(refuse)?;
    parse_labels(path, &String::from_utf8_lossy(&output.stdout))
}

/// The one hostid the labels of pool `guid` record (0: none). Labels that
/// disagree, or no label of the pool at all, refuse. Pure for tests.
pub fn recorded_in(labels: &[Label], pool: &str, guid: u64) -> io::Result<u32> {
    let mut hostids = labels
        .iter()
        .filter(|label| label.pool_guid == guid)
        .map(|label| label.hostid)
        .collect::<Vec<_>>();
    hostids.sort_unstable();
    hostids.dedup();
    match hostids[..] {
        [hostid] => Ok(hostid),
        [] => Err(refuse(format!(
            "no label of pool {} was readable",
            zfs_tools::engine::escape_display(pool)
        ))),
        _ => Err(refuse(format!(
            "the labels of pool {} record different hostids",
            zfs_tools::engine::escape_display(pool)
        ))),
    }
}

/// The hostid recorded in the labels of the imported pool `pool`. A pool
/// imported read-only keeps the labels its last writer left.
pub fn recorded(pool: &str, guid: zfs_tools::engine::Guid) -> io::Result<u32> {
    let mut labels = Vec::new();
    for leaf in crate::device::pool_leaves(pool, &guid).map_err(refuse)? {
        labels.extend(read_labels(&leaf)?);
    }
    recorded_in(&labels, pool, guid.get())
}

pub(crate) fn native_recorded(
    pool: &str,
    guid: zfs_tools::engine::Guid,
) -> Result<u32, zfs_tools::engine::Error> {
    recorded(pool, guid).map_err(|error| zfs_tools::engine::Error::Inconsistent(error.to_string()))
}

/// Two pools belong to one host only when their labels record one hostid.
pub fn require_one_host(left: (&str, u32), right: (&str, u32)) -> io::Result<()> {
    if left.1 != right.1 {
        let shown = |hostid: u32| match hostid {
            0 => "none".to_owned(),
            hostid => format(hostid),
        };
        return Err(refuse(format!(
            "pools {} (hostid {}) and {} (hostid {}) record different hosts; pair only the pools of one host",
            zfs_tools::engine::escape_display(left.0),
            shown(left.1),
            zfs_tools::engine::escape_display(right.0),
            shown(right.1)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESKTOP: &str = "------------------------------------\nLABEL 0 \n------------------------------------\n    version: 5000\n    name: 'rpool'\n    state: 0\n    txg: 912\n    pool_guid: 12345678901234567890\n    errata: 0\n    hostid: 24404602\n    hostname: '(none)'\n    top_guid: 1\n    guid: 1\n    vdev_children: 1\n    vdev_tree:\n        type: 'disk'\n        id: 0\n        guid: 1\n        name: 'nested'\n        state: 7\n    features_for_read:\n        com.delphix:hole_birth\n    labels = 0 1 2 3 \n";

    #[test]
    fn zdb_label_reads_top_level_identity_only() {
        let parsed = parse_labels("/dev/nvme3n1p1", DESKTOP).unwrap().remove(0);
        assert_eq!(
            parsed,
            Label {
                path: "/dev/nvme3n1p1".into(),
                name: "rpool".into(),
                pool_guid: 12345678901234567890,
                vdev_guid: Some(1),
                state: 0,
                hostid: 0x0174627a,
            }
        );
        let exported = DESKTOP.replace("    state: 0\n", "    state: 1\n");
        assert_eq!(parse_labels("p", &exported).unwrap()[0].state, 1);
        let anonymous = DESKTOP.replace("    hostid: 24404602\n", "");
        assert_eq!(parse_labels("p", &anonymous).unwrap()[0].hostid, 0);
        // A device whose labels disagree contributes every version.
        let split = format!(
            "{DESKTOP}{}",
            DESKTOP.replace("hostid: 24404602", "hostid: 5")
        );
        let both = parse_labels("p", &split).unwrap();
        assert_eq!(
            both.iter().map(|l| l.hostid).collect::<Vec<_>>(),
            [0x0174627a, 5]
        );
        let same = format!("{DESKTOP}{DESKTOP}");
        assert_eq!(parse_labels("p", &same).unwrap().len(), 1);
    }

    #[test]
    fn zdb_label_without_pool_identity_or_with_bad_values_is_not_guessed() {
        let cache = "LABEL 0\n    version: 5000\n    state: 4\n    guid: 9\n";
        assert!(parse_labels("p", cache).unwrap().is_empty());
        assert!(
            parse_labels("p", "failed to unpack label 0\n")
                .unwrap()
                .is_empty()
        );
        let wide = DESKTOP.replace("hostid: 24404602", "hostid: 4294967296");
        assert!(parse_labels("p", &wide).is_err());
        let repeated = DESKTOP.replace("    errata: 0\n", "    state: 1\n");
        assert!(parse_labels("p", &repeated).is_err());
    }

    #[test]
    fn top_level_vdev_guid_is_optional_but_present_values_are_exact_and_nonzero() {
        let old = DESKTOP.replace("    guid: 1\n", "");
        assert_eq!(parse_labels("p", &old).unwrap()[0].vdev_guid, None);
        for value in ["0", "+1", "-1", "18446744073709551616", "1junk", ""] {
            let invalid = DESKTOP.replace("    guid: 1\n", &format!("    guid: {value}\n"));
            assert!(parse_labels("p", &invalid).is_err(), "{value:?}");
        }
        let repeated = DESKTOP.replace("    top_guid: 1\n", "    guid: 2\n");
        assert!(parse_labels("p", &repeated).is_err());
        let nested = DESKTOP.replace("        guid: 1\n", "        guid: 999\n");
        assert_eq!(parse_labels("p", &nested).unwrap()[0].vdev_guid, Some(1));
    }

    #[test]
    fn a_pool_records_one_hostid_or_refuses() {
        let label = |guid, hostid| Label {
            path: "p".into(),
            name: "rpool".into(),
            pool_guid: guid,
            vdev_guid: None,
            state: 1,
            hostid,
        };
        let labels = [label(1, 7), label(1, 7), label(2, 9)];
        assert_eq!(recorded_in(&labels, "rpool", 1).unwrap(), 7);
        assert_eq!(recorded_in(&[label(1, 0)], "rpool", 1).unwrap(), 0);
        assert!(recorded_in(&labels, "rpool", 3).is_err(), "no label");
        assert!(recorded_in(&[label(1, 7), label(1, 8)], "rpool", 1).is_err());
    }

    #[test]
    fn two_pools_are_one_host_only_with_one_recorded_hostid() {
        require_one_host(("a", 7), ("b", 7)).unwrap();
        require_one_host(("a", 0), ("b", 0)).unwrap();
        let error = require_one_host(("a", 7), ("b", 8))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("a (hostid 00000007) and b (hostid 00000008)"),
            "{error}"
        );
        assert!(require_one_host(("a", 7), ("b", 0)).is_err(), "none vs one");
    }

    #[test]
    fn an_installed_hostid_is_four_nonzero_unreserved_bytes() {
        assert_eq!(decode(b"zbt\x01"), Installed::Hostid(0x0174627a));
        assert_eq!(decode(&[0; 4]), Installed::Zero);
        assert_eq!(decode(&[0xff; 4]), Installed::Malformed);
        assert_eq!(decode(b"zbt"), Installed::Malformed);
        assert_eq!(decode(b"zbt\x01\n"), Installed::Malformed);
        assert_eq!(decode(b""), Installed::Malformed);
        for (found, text) in [
            (Installed::Missing, "has no /etc/hostid"),
            (Installed::Zero, "zero /etc/hostid"),
            (Installed::Malformed, "malformed"),
            (Installed::Unreadable("EIO".into()), "unreadable: EIO"),
        ] {
            let error = found.require("BE x").unwrap_err().to_string();
            assert!(error.starts_with("BE x") && error.contains(text), "{error}");
        }
        assert_eq!(Installed::Hostid(7).require("x").unwrap(), 7);
    }

    #[test]
    fn installed_reads_the_file_beneath_the_root_and_never_follows_a_link() {
        let root = std::env::temp_dir().join(format!("zboot-hostid-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("etc")).unwrap();
        let open = || File::open(&root).unwrap();
        assert_eq!(installed(&open()), Installed::Missing);
        fs::write(root.join("etc/hostid"), b"zbt\x01").unwrap();
        assert_eq!(installed(&open()), Installed::Hostid(0x0174627a));
        fs::remove_file(root.join("etc/hostid")).unwrap();
        std::os::unix::fs::symlink("/etc/hostid", root.join("etc/hostid")).unwrap();
        assert!(matches!(installed(&open()), Installed::Unreadable(_)));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn hostids_parse_as_eight_hex_digits_and_the_kernel_form() {
        assert_eq!(parse("0174627a").unwrap(), 0x0174627a);
        assert_eq!(parse("0174627A").unwrap(), 0x0174627a);
        for bad in [
            "",
            "174627a",
            "0x174627a",
            "00000000",
            "ffffffff",
            "0174627g",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_effective("174627a\n").unwrap(), 0x0174627a);
        assert_eq!(parse_effective("0x0\n").unwrap(), 0);
        assert!(parse_effective("zz").is_err());
        assert_eq!(format(7), "00000007");
    }
}
