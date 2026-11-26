//! The kernel's per-namespace mount table, `/proc/<pid>/mountinfo`
//! (proc_pid_mountinfo(5)). Root, mount point and source are decoded to bytes
//! with no UTF-8 requirement, so a non-UTF-8 mount anywhere in the table does
//! not stop a caller observing the mounts it cares about.
use std::{collections::BTreeSet, ffi::OsString, io, os::unix::ffi::OsStringExt, path::PathBuf};

/// One mountinfo row. The filesystem type and both option lists are text that
/// callers match against known ASCII names, so any non-UTF-8 byte in them is
/// kept as U+FFFD; that can never make a known name or option match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub id: u64,
    pub parent: u64,
    /// `major:minor` of the filesystem's device.
    pub device: String,
    /// The directory of the filesystem that forms this mount's root.
    pub root: PathBuf,
    pub mount_point: PathBuf,
    /// Per-mount options, such as `ro,nosuid`.
    pub options: String,
    pub filesystem: String,
    pub source: OsString,
    /// Per-superblock options.
    pub super_options: String,
}

impl Mount {
    pub fn has_option(&self, option: &str) -> bool {
        self.options.split(',').any(|present| present == option)
    }

    pub fn has_super_option(&self, option: &str) -> bool {
        self.super_options
            .split(',')
            .any(|present| present == option)
    }
}

fn malformed(row: usize, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("mountinfo row {row}: {detail}"),
    )
}

/// The kernel escapes space, tab, newline and backslash as `\ooo`; decode
/// every such octal escape of one byte and refuse any other backslash.
fn decode(field: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte != b'\\' {
            decoded.push(byte);
            rest = tail;
            continue;
        }
        let digits = tail.get(..3)?;
        if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) || digits[0] > b'3' {
            return None;
        }
        decoded.push(
            digits
                .iter()
                .fold(0, |value, digit| value * 8 + (digit - b'0')),
        );
        rest = &tail[3..];
    }
    Some(decoded)
}

fn row(number: usize, line: &[u8]) -> io::Result<Mount> {
    let bad = |detail| malformed(number, detail);
    // Single spaces: an empty field (such as an empty source) stays a field.
    let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
    let separator = fields
        .iter()
        .skip(6)
        .position(|field| *field == b"-")
        .map(|index| index + 6)
        .ok_or_else(|| bad("no `-` separator after six fields"))?;
    // Super options come last and some filesystems print user values in them
    // unescaped (NFS `fsc=`, Ceph `mon_addr=`), so a space there is kept.
    if fields.len() < separator + 4 {
        return Err(bad("fewer than three fields after the separator"));
    }
    let identity = |field: &[u8]| {
        std::str::from_utf8(field)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| bad("invalid mount identity"))
    };
    let bytes = |field| decode(field).ok_or_else(|| bad("invalid escape"));
    let text = |field: &[u8]| String::from_utf8_lossy(field).into_owned();
    Ok(Mount {
        id: identity(fields[0])?,
        parent: identity(fields[1])?,
        device: text(fields[2]),
        root: OsString::from_vec(bytes(fields[3])?).into(),
        mount_point: OsString::from_vec(bytes(fields[4])?).into(),
        options: text(fields[5]),
        filesystem: text(&bytes(fields[separator + 1])?),
        source: OsString::from_vec(bytes(fields[separator + 2])?),
        super_options: text(&fields[separator + 3..].join(&b' ')),
    })
}

/// Each row of `text`, or why it is malformed. A caller that tolerates bad
/// rows may skip them; [`table`] refuses the whole text instead.
pub fn parse<T: AsRef<[u8]> + ?Sized>(text: &T) -> impl Iterator<Item = io::Result<Mount>> + '_ {
    let text = text.as_ref();
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    (!text.is_empty())
        .then(|| text.split(|byte| *byte == b'\n'))
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, line)| row(index + 1, line))
}

/// Every row of `text`, refusing any malformed row or repeated mount id.
pub fn table<T: AsRef<[u8]> + ?Sized>(text: &T) -> io::Result<Vec<Mount>> {
    let mounts = parse(text).collect::<io::Result<Vec<_>>>()?;
    let mut ids = BTreeSet::new();
    if let Some(repeated) = mounts.iter().find(|mount| !ids.insert(mount.id)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mountinfo repeats mount id {}", repeated.id),
        ));
    }
    Ok(mounts)
}

/// The mount table of the calling thread's mount namespace. A read that
/// spans several `read()` calls can see a mount id reused by concurrent
/// mount churn, so an invalid table is read once more before it is refused.
pub fn current() -> io::Result<Vec<Mount>> {
    let read = || table(&std::fs::read("/proc/thread-self/mountinfo")?);
    match read() {
        Err(error) if error.kind() == io::ErrorKind::InvalidData => read(),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

    const ROW: &str =
        "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n";

    #[test]
    fn rows_name_every_field_and_skip_optional_ones() {
        let mounts = table(ROW).unwrap();
        assert_eq!(
            mounts,
            [Mount {
                id: 36,
                parent: 35,
                device: "98:0".into(),
                root: "/mnt1".into(),
                mount_point: "/mnt2".into(),
                options: "rw,noatime".into(),
                filesystem: "ext3".into(),
                source: "/dev/root".into(),
                super_options: "rw,errors=continue".into(),
            }]
        );
        assert!(mounts[0].has_option("noatime") && !mounts[0].has_option("ro"));
        assert!(mounts[0].has_super_option("errors=continue"));
        assert!(!mounts[0].has_super_option("errors"));
        let plain = ROW.replace(" master:1", "");
        let shared = ROW.replace(" master:1", " shared:2 master:1 unbindable");
        for text in [plain, shared] {
            assert_eq!(table(&text).unwrap()[0].filesystem, "ext3");
        }
        assert!(table("").unwrap().is_empty());
        let two = format!("{ROW}{}", ROW.replacen("36 35", "37 36", 1));
        assert_eq!(table(two.trim_end()).unwrap().len(), 2);
    }

    #[test]
    fn escapes_decode_to_bytes() {
        let row = "1 0 0:1 /a\\040b /x\\011y\\012z\\134 rw - tmpfs s\\303\\251 rw\n";
        let mount = &table(row).unwrap()[0];
        assert_eq!(mount.root, Path::new("/a b"));
        assert_eq!(mount.mount_point, Path::new("/x\ty\nz\\"));
        assert_eq!(mount.source, "sé");
        let any = &table("1 0 0:1 / /\\000\\177\\377 rw - tmpfs x rw").unwrap()[0];
        assert_eq!(any.mount_point.as_os_str().as_bytes(), b"/\0\x7f\xff");
    }

    #[test]
    fn unescaped_spaces_in_super_options_stay_in_them() {
        let text = "41 22 0:52 / /mnt/nfs rw,relatime - nfs4 srv:/x rw,vers=4.2,fsc=a b\n";
        let mount = &table(text).unwrap()[0];
        assert_eq!(mount.source, "srv:/x");
        assert_eq!(mount.super_options, "rw,vers=4.2,fsc=a b");
        assert!(mount.has_super_option("rw"));
    }

    #[test]
    fn empty_fields_survive() {
        let mount = &table("1 0 0:1 / /run rw - tmpfs  rw\n").unwrap()[0];
        assert_eq!(mount.source, "");
        assert_eq!(mount.super_options, "rw");
        let mount = &table("1 0 0:1 / /run rw - tmpfs tmpfs \n").unwrap()[0];
        assert_eq!(mount.super_options, "");
    }

    #[test]
    fn non_utf8_paths_are_kept_and_do_not_spoil_other_rows() {
        let mut text = b"1 0 0:1 / / rw - zfs tank/ROOT/be rw\n".to_vec();
        text.extend_from_slice(b"2 1 0:2 /\xff /srv/\xfe rw - tmpfs \xfd rw,x\xfc\n");
        let mounts = table(&text).unwrap();
        assert_eq!(mounts[0].source, "tank/ROOT/be");
        assert_eq!(mounts[1].root.as_os_str().as_bytes(), b"/\xff");
        assert_eq!(mounts[1].mount_point.as_os_str().as_bytes(), b"/srv/\xfe");
        assert_eq!(mounts[1].source, OsStr::from_bytes(b"\xfd"));
        assert!(mounts[1].has_super_option("rw") && !mounts[1].has_super_option("x"));
    }

    #[test]
    fn malformed_rows_are_refused() {
        for wrong in [
            "garbage".to_owned(),
            ROW.replace(" - ", " "),
            ROW.replace(" rw,errors=continue", ""),
            ROW.replace("36 35", "x 35"),
            ROW.replace("36 35", "36 -1"),
            ROW.replace(" master:1", "").replace("/mnt1 ", ""),
            ROW.replace("/mnt2", "/mnt\\04"),
            ROW.replace("/mnt2", "/mnt\\400"),
            ROW.replace("/mnt2", "/mnt\\8xx"),
            ROW.replace("/dev/root", "/dev/\\"),
            ROW.replace("ext3", "ext\\9"),
            ROW.replace(" ", "  "),
            format!("{ROW}\n{ROW}"),
            ROW.replace(" ", "\t"),
        ] {
            assert!(table(&wrong).is_err(), "{wrong:?}");
        }
        let error = table(&format!("{ROW}{}", ROW.replace(" - ", " "))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().starts_with("mountinfo row 2:"), "{error}");
        assert!(table(&ROW.repeat(2)).is_err());
        let rows: Vec<_> = parse(&format!("garbage\n{ROW}")).collect();
        assert!(rows[0].is_err() && rows[1].is_ok());
    }
}
