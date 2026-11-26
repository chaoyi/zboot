//! Admission of a root tar (zstd or plain), however it was made: `zboot
//! factory`'s output or any other. Contained members only (no absolute or
//! `..` path, no member under an earlier non-directory, no duplicate, every
//! hardlink to an earlier regular member), and the boot checks: each
//! `boot/vmlinuz-R` has `boot/initrd.img-R` and a ZFS module under
//! `lib/modules/R` (merged or not), and every initrd has its kernel. Deploy
//! repeats the scan while extracting from the same bytes.
//!
//! A GNU sparse 1.0 member, which `tar --format=pax --sparse` writes for a
//! file with holes (mmdebstrap 1.7 always passes `--sparse`, and on
//! compressed ZFS every all-zero record is a hole), is checked as its real
//! name and size from the `GNU.sparse.*` keys, as GNU tar extracts it, and its
//! map must account for exactly its stored bytes. Every other sparse format
//! is refused. Each member's extension headers are parsed again as GNU tar
//! parses them, and a member GNU tar would read differently from the tar
//! crate is refused, so the scan and GNU tar's extraction see the same
//! members.
use super::{ImageFile, atom, hash, refuse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::ffi::OsStrExt,
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
};

const MAX_ENTRIES: u64 = 2_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTar {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub zstd: bool,
    /// Kernel releases with an initrd and a ZFS module.
    pub kernels: Vec<String>,
    pub entries: u64,
    /// Sum of member sizes.
    pub logical_bytes: u64,
}

fn member_path(path: &Path) -> io::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| refuse("root tar member path is not UTF-8"))?,
            ),
            _ => {
                return Err(refuse(
                    "root tar contains an absolute or parent-traversing member",
                ));
            }
        }
    }
    let path = parts.join("/");
    if path.len() > 64 * 1024 {
        return Err(refuse("root tar member path exceeds its bound"));
    }
    Ok(path)
}

/// The GNU sparse 1.0 keys, all required; any other `GNU.sparse.` key is
/// an older format.
const SPARSE_KEYS: [&str; 4] = ["major", "minor", "name", "realsize"];

/// A decimal as GNU tar reads sparse keys and map entries: digits only,
/// within `off_t`.
fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 19 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()?
        .parse()
        .ok()
        .filter(|value| i64::try_from(*value).is_ok())
}

/// Whether `header` is the name GNU tar gives a sparse 1.0 member whose
/// real name is `name`: `DIR/GNUSparseFile.N/BASE` of the raw name, with
/// `.` for no directory, cut to a ustar name field's 100 bytes when longer.
fn sparse_placeholder(header: &[u8], name: &[u8]) -> bool {
    const FIELD: usize = 100;
    let (directory, base) = name
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or((&b"."[..], name), |at| (&name[..at], &name[at + 1..]));
    let lead = [directory, b"/GNUSparseFile."].concat();
    let cut = header.len() == FIELD;
    let Some(rest) = header.strip_prefix(lead.as_slice()) else {
        return cut && lead.starts_with(header);
    };
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    match rest[digits..].split_first() {
        None => cut,
        Some((b'/', tail)) => digits > 0 && (tail == base || (cut && base.starts_with(tail))),
        Some(_) => false,
    }
}

/// What the tar crate has read of an archive from `keep` on: the extension
/// headers and header of the member it yields next, which [`member`] reads
/// again as GNU tar does. Member data, before `keep`, is not kept.
#[derive(Default)]
struct Tapped {
    /// The archive offset of the next byte read.
    read: u64,
    /// Where the kept bytes start: the end of the last member's data.
    keep: u64,
    bytes: Vec<u8>,
}

/// The reader under the tar crate that keeps what [`Tapped`] describes.
struct Tap<R> {
    inner: R,
    tapped: Rc<RefCell<Tapped>>,
}
impl<R: Read> Read for Tap<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buffer)?;
        let mut tapped = self.tapped.borrow_mut();
        let skip = usize::try_from(tapped.keep.saturating_sub(tapped.read)).unwrap_or(usize::MAX);
        tapped.bytes.extend_from_slice(&buffer[skip.min(n)..n]);
        tapped.read += n as u64;
        Ok(n)
    }
}

/// A tar archive whose members [`member`] reads.
type Tapping<'a> = tar::Archive<Tap<Box<dyn Read + 'a>>>;

/// A tar archive of `reader` whose members [`member`] reads.
fn archive<'a>(reader: Box<dyn Read + 'a>) -> (Tapping<'a>, Rc<RefCell<Tapped>>) {
    let tapped = Rc::new(RefCell::new(Tapped::default()));
    let tap = Tap {
        inner: reader,
        tapped: Rc::clone(&tapped),
    };
    (tar::Archive::new(tap), tapped)
}

/// What GNU tar takes from the extension headers before a member. PAX
/// records are parsed by their length, as GNU tar parses them; the tar crate
/// splits them at newlines, stops at an empty line and takes a repeated key's
/// first value, where GNU tar takes the last. A malformed record, and a
/// repeated key that names, sizes or makes a member sparse, are refused.
#[derive(Default)]
struct Extensions {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
    /// [`SPARSE_KEYS`] in order.
    sparse: [Option<Vec<u8>>; 4],
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
}

impl Extensions {
    /// The extension headers in `bytes`, which end at the member's header.
    fn read(mut bytes: &[u8]) -> io::Result<Self> {
        let short = || refuse("its extension headers are cut short");
        let mut found = Self::default();
        while !bytes.is_empty() {
            let (block, rest) = bytes.split_at_checked(512).ok_or_else(short)?;
            let header = tar::Header::from_byte_slice(block);
            let size = usize::try_from(header.entry_size()?).map_err(|_| short())?;
            let data = rest.get(..size).ok_or_else(short)?;
            bytes = rest.get(size.next_multiple_of(512)..).ok_or_else(short)?;
            let kind = header.entry_type();
            // GNU tar ends a long name at its first NUL, reading on into the
            // block's padding when its size holds none, so one is required.
            let name = || match data.iter().position(|byte| *byte == 0) {
                Some(end) => Ok(data[..end].to_vec()),
                None => Err(refuse(
                    "its GNU long name or link has no NUL within its size",
                )),
            };
            if kind.is_pax_local_extensions() {
                found.records(data)?;
            } else if kind.is_gnu_longname() {
                found.long_name = Some(name()?);
            } else if kind.is_gnu_longlink() {
                found.long_link = Some(name()?);
            } else {
                return Err(refuse("an unexpected extension header precedes it"));
            }
        }
        Ok(found)
    }

    /// PAX records, `LENGTH KEY=VALUE\n` each. As in GNU tar's
    /// `decode_record`, at least one blank follows the length and every
    /// space and tab before the key is skipped.
    fn records(&mut self, mut data: &[u8]) -> io::Result<()> {
        let malformed = || refuse("its PAX header has a malformed record");
        while !data.is_empty() {
            let digits = data.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let blanks = data[digits..]
                .iter()
                .take_while(|byte| matches!(byte, b' ' | b'\t'))
                .count();
            let key = digits + blanks;
            let length = decimal(&data[..digits])
                .and_then(|length| usize::try_from(length).ok())
                .filter(|length| blanks > 0 && *length > key + 1 && *length <= data.len())
                .ok_or_else(malformed)?;
            let (record, rest) = data.split_at(length);
            data = rest;
            let body = record[key..].strip_suffix(b"\n").ok_or_else(malformed)?;
            let equals = body
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or_else(malformed)?;
            let (key, value) = (&body[..equals], &body[equals + 1..]);
            let shown = String::from_utf8_lossy(key);
            let slot = match key {
                b"path" => &mut self.path,
                b"linkpath" => &mut self.linkpath,
                b"size" => {
                    let size = decimal(value).ok_or_else(malformed)?;
                    if self.size.replace(size).is_some() {
                        return Err(refuse("its PAX header repeats size"));
                    }
                    continue;
                }
                _ => match key.strip_prefix(b"GNU.sparse.") {
                    Some(field) => {
                        let index = SPARSE_KEYS
                            .iter()
                            .position(|key| key.as_bytes() == field)
                            .ok_or_else(|| {
                                refuse(format!(
                                    "it uses {shown}, an older GNU sparse format; only 1.0 is admitted"
                                ))
                            })?;
                        &mut self.sparse[index]
                    }
                    None => continue,
                },
            };
            if slot.replace(value.to_vec()).is_some() {
                return Err(refuse(format!("its PAX header repeats {shown}")));
            }
        }
        Ok(())
    }
}

/// A member as GNU tar reads it.
struct Member {
    /// The real path, checked by [`member_path`].
    path: String,
    /// A link's raw target.
    link: Option<Vec<u8>>,
    /// The real size of a GNU sparse 1.0 file.
    sparse: Option<u64>,
}

/// The member as GNU tar reads it.
///
/// The member's extension headers are read again from `tapped` as GNU tar
/// reads them ([`Extensions`]), and its name and link come from that reading.
/// The tar crate frames the stream by the member's size, which must be GNU
/// tar's, so both read the same members from the same bytes. A
/// name with a NUL, where GNU tar's name ends, or a non-directory named with a
/// trailing `/`, which GNU tar extracts as a directory, is refused, as is
/// data, from the header or a PAX size, on a member that is not a regular
/// file, which GNU tar does not read as its data.
///
/// GNU tar extracts a sparse member as `GNU.sparse.name`, so that name takes
/// every path check. GNU tar reads the sparse keys only under a POSIX
/// header, so the header must have ustar magic and an empty prefix, and name
/// the placeholder GNU tar writes ([`sparse_placeholder`]) in its name field
/// alone; under any other header GNU tar reads a plain file of the real size.
fn member<R: Read>(entry: &mut tar::Entry<'_, R>, tapped: &RefCell<Tapped>) -> io::Result<Member> {
    // A placeholder cut at 100 bytes need not be UTF-8.
    let header = String::from_utf8_lossy(&entry.header().path_bytes()).into_owned();
    let at = |error: io::Error| refuse(format!("root tar member {header}: {error}"));
    let found = {
        let mut tapped = tapped.borrow_mut();
        let found = entry
            .raw_header_position()
            .checked_sub(tapped.keep)
            .and_then(|length| usize::try_from(length).ok())
            .and_then(|length| tapped.bytes.get(..length))
            .ok_or_else(|| refuse("the archive was read out of step"))
            .and_then(Extensions::read);
        tapped.keep = entry
            .raw_file_position()
            .saturating_add(entry.size().next_multiple_of(512));
        tapped.bytes.clear();
        found
    }
    .map_err(at)?;
    let kind = entry.header().entry_type();
    let nul = |value: &Option<Vec<u8>>| value.as_ref().is_some_and(|value| value.contains(&0));
    let both = (found.long_name.is_some() && found.path.is_some())
        || (found.long_link.is_some() && found.linkpath.is_some());
    let size = match found.size {
        Some(size) => size,
        None => entry.header().entry_size()?,
    };
    let renamed = found.path.is_some() || found.long_name.is_some();
    let raw = match found.path.as_ref().or(found.long_name.as_ref()) {
        Some(path) => path.clone(),
        None => entry.header().path_bytes().into_owned(),
    };
    let link = match found.linkpath.as_ref().or(found.long_link.as_ref()) {
        Some(link) => Some(link.clone()),
        None => entry
            .header()
            .link_name_bytes()
            .map(|link| link.into_owned()),
    };
    let problem = if kind.is_gnu_sparse() {
        // Named before the size check, since the crate expands its size.
        Some("it is an old GNU sparse member; only GNU sparse 1.0 is admitted")
    } else if nul(&found.path) || nul(&found.linkpath) || nul(&found.sparse[2]) {
        Some("a PAX name holds a NUL, where GNU tar ends the name")
    } else if both {
        Some("it has both a GNU long name and a PAX name")
    } else if size != entry.size() {
        Some("GNU tar reads its size differently, and so the members after it")
    } else if found.sparse.iter().all(Option::is_none) && !kind.is_dir() && raw.ends_with(b"/") {
        // A sparse member's name is its real name, checked below; its
        // placeholder may be cut just after a `/`.
        Some("a non-directory name ends in /, which GNU tar extracts as a directory")
    } else if size != 0
        && (kind.is_dir()
            || kind.is_symlink()
            || kind.is_hard_link()
            || kind.is_character_special()
            || kind.is_block_special()
            || kind.is_fifo())
    {
        // GNU tar reads data only for a regular file, and gives a hardlink
        // no size, so it would read what follows as the next header.
        Some("it is not a regular file but has data, which GNU tar does not read as its data")
    } else {
        None
    };
    if let Some(problem) = problem {
        return Err(at(refuse(problem)));
    }
    let [major, minor, name, realsize] = found.sparse;
    if [&major, &minor, &name, &realsize]
        .iter()
        .all(|key| key.is_none())
    {
        let path = member_path(Path::new(OsStr::from_bytes(&raw)))?;
        return Ok(Member {
            path,
            link,
            sparse: None,
        });
    }
    let version = |key: &Option<Vec<u8>>| key.as_deref().and_then(decimal);
    if (version(&major), version(&minor)) != (Some(1), Some(0)) {
        let shown = |key: &Option<Vec<u8>>| {
            key.as_deref().map_or("?".into(), |value| {
                String::from_utf8_lossy(value).into_owned()
            })
        };
        return Err(refuse(format!(
            "root tar member {header} is GNU sparse {}.{}; only 1.0 is admitted",
            shown(&major),
            shown(&minor)
        )));
    }
    let (Some(name), Some(realsize)) = (name, realsize) else {
        return Err(refuse(format!(
            "GNU sparse member {header} lacks GNU.sparse.name or GNU.sparse.realsize"
        )));
    };
    let realsize = decimal(&realsize).ok_or_else(|| {
        refuse(format!(
            "GNU sparse member {header} has an invalid GNU.sparse.realsize"
        ))
    })?;
    let posix = entry
        .header()
        .as_ustar()
        .is_some_and(|ustar| ustar.prefix.iter().all(|byte| *byte == 0));
    if !posix || renamed {
        return Err(refuse(format!(
            "GNU sparse member {header} is not under a POSIX header with only a name, as GNU tar writes one; GNU tar would read it as a plain file"
        )));
    }
    if name.ends_with(b"/") {
        return Err(refuse(format!(
            "GNU sparse member {header} has a real name ending in /, which GNU tar extracts as a directory"
        )));
    }
    let real =
        std::str::from_utf8(&name).map_err(|_| refuse("root tar member path is not UTF-8"))?;
    let path = member_path(Path::new(real))?;
    if path.is_empty() || !sparse_placeholder(&raw, &name) {
        return Err(refuse(format!(
            "GNU sparse member {header} is not GNU tar's placeholder for its real name {path}"
        )));
    }
    Ok(Member {
        path,
        link,
        sparse: Some(realsize),
    })
}

/// One decimal line of a GNU sparse map; `read` counts the bytes.
fn map_number(data: &mut impl BufRead, read: &mut u64) -> io::Result<u64> {
    let mut line = Vec::new();
    // At most 19 digits and the newline, as GNU tar bounds them.
    data.by_ref().take(20).read_until(b'\n', &mut line)?;
    *read += line.len() as u64;
    match line.split_last() {
        Some((b'\n', digits)) => decimal(digits),
        _ => None,
    }
    .ok_or_else(|| refuse("its GNU sparse map is malformed"))
}

/// Read and check the map that opens a GNU sparse 1.0 member's `stored`
/// bytes: decimal lines, the chunk count then each chunk's offset and size,
/// padded to a 512-byte block, then the chunks' bytes. `chunk` sees each
/// chunk; `data` is left at the first chunk's bytes.
///
/// GNU tar's writer keeps invariants its reader relies on, and admission
/// requires them so GNU tar and this scan see the same members and content:
/// chunks are in order and do not overlap; every chunk but the last non-empty
/// one is whole 512-byte blocks, because GNU tar reads each chunk in whole
/// blocks; the last chunk ends at `realsize` (an empty one when the file ends
/// in a hole), because GNU tar sizes the file by it, and only the last may be
/// empty, which bounds the map by the stored bytes; and the map and chunks
/// are exactly the stored bytes.
fn sparse_map(
    data: &mut impl BufRead,
    stored: u64,
    realsize: u64,
    mut chunk: impl FnMut(u64, u64),
) -> io::Result<()> {
    let mut read = 0;
    let count = map_number(data, &mut read)?;
    // With an empty chunk only last, every chunk but the last two holds a
    // block, and the map takes one.
    if count > stored / 512 + 1 {
        return Err(refuse(
            "its GNU sparse map lists more chunks than its stored bytes hold",
        ));
    }
    let (mut end, mut bytes, mut partial) = (0_u64, 0_u64, false);
    for index in 0..count {
        let offset = map_number(data, &mut read)?;
        let size = map_number(data, &mut read)?;
        if size == 0 && index + 1 != count {
            return Err(refuse(
                "its GNU sparse map has an empty chunk before the last",
            ));
        }
        end = offset
            .checked_add(size)
            .filter(|next| offset >= end && *next <= realsize)
            .ok_or_else(|| {
                refuse("its GNU sparse map has chunks out of order or past the real size")
            })?;
        if size > 0 {
            if partial {
                return Err(refuse(
                    "its GNU sparse map has a chunk of part of a block before another chunk",
                ));
            }
            partial = size % 512 != 0;
        }
        // Chunks in order within realsize cannot sum past it.
        bytes += size;
        chunk(offset, size);
    }
    if end != realsize {
        return Err(refuse("its GNU sparse map does not reach its real size"));
    }
    let padding = read.next_multiple_of(512) - read;
    if io::copy(&mut data.by_ref().take(padding), &mut io::sink())? != padding
        || read + padding + bytes != stored
    {
        return Err(refuse(
            "its GNU sparse map does not account for exactly its stored bytes",
        ));
    }
    Ok(())
}

struct Hashing<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}
impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

fn open(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| refuse(format!("root tar {}: {e}", path.display())))?;
    if !file.metadata()?.is_file() {
        return Err(refuse("a root tar must be a regular file"));
    }
    Ok(file)
}

fn is_zstd(file: &mut File) -> io::Result<bool> {
    let mut magic = [0_u8; 4];
    let read = file.read(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(read == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd])
}

/// Each member's path and kind.
pub type Members = BTreeMap<String, tar::EntryType>;

/// One pass over the archive bytes of `path`: containment and boot checks,
/// and the digest of exactly the bytes scanned. A failure to read or decode
/// the archive itself names `path`; a refusal of its contents says why.
fn scan(file: &mut File, path: &Path) -> io::Result<(RootTar, Members)> {
    let unreadable = |error: io::Error| {
        io::Error::new(
            error.kind(),
            format!(
                "root tar {}: not a readable tar archive: {error}",
                path.display()
            ),
        )
    };
    let zstd = is_zstd(file).map_err(unreadable)?;
    let mut hashing = Hashing {
        inner: &mut *file,
        hasher: Sha256::new(),
        bytes: 0,
    };
    let mut names = Members::new();
    let mut parents = BTreeSet::new();
    let mut logical = 0_u64;
    {
        let reader: Box<dyn Read + '_> = if zstd {
            Box::new(zstd::stream::read::Decoder::new(&mut hashing).map_err(unreadable)?)
        } else {
            Box::new(&mut hashing)
        };
        let (mut archive, tapped) = archive(reader);
        for entry in archive.entries().map_err(unreadable)? {
            let mut entry = entry.map_err(unreadable)?;
            let Member { path, link, sparse } = member(&mut entry, &tapped)?;
            let kind = entry.header().entry_type();
            if sparse.is_some() && !kind.is_file() {
                return Err(refuse(format!(
                    "root tar member {path} has GNU sparse keys but is not a regular file"
                )));
            }
            if !(kind.is_file()
                || kind.is_dir()
                || kind.is_symlink()
                || kind.is_hard_link()
                || kind.is_character_special()
                || kind.is_block_special()
                || kind.is_fifo())
            {
                return Err(refuse(format!(
                    "root tar member {path} has an unsupported kind"
                )));
            }
            if path.is_empty() && !kind.is_dir() {
                return Err(refuse("the root tar's root must be a directory"));
            }
            if names.len() as u64 >= MAX_ENTRIES || names.contains_key(&path) {
                return Err(refuse(format!(
                    "root tar duplicates {path} or exceeds {MAX_ENTRIES} members"
                )));
            }
            let mut ancestor = path.as_str();
            while let Some((up, _)) = ancestor.rsplit_once('/') {
                if names.get(up).is_some_and(|k| !k.is_dir()) {
                    return Err(refuse(format!(
                        "root tar member {path} lies under an earlier non-directory"
                    )));
                }
                ancestor = up;
            }
            if !kind.is_dir() && parents.contains(&path) {
                return Err(refuse(format!(
                    "root tar replaces the populated directory {path}"
                )));
            }
            if kind.is_hard_link() {
                let target = link.ok_or_else(|| refuse("root tar hardlink has no target"))?;
                let target = member_path(Path::new(OsStr::from_bytes(&target)))?;
                if names
                    .get(&target)
                    .is_none_or(|k| !k.is_file() && !k.is_hard_link())
                {
                    return Err(refuse(format!(
                        "root tar hardlink {path} must name an earlier regular member"
                    )));
                }
            }
            let mut ancestor = path.as_str();
            while let Some((up, _)) = ancestor.rsplit_once('/') {
                parents.insert(up.to_string());
                ancestor = up;
            }
            if !path.is_empty() {
                parents.insert(String::new());
            }
            let size = match sparse {
                Some(realsize) => {
                    let stored = entry.size();
                    sparse_map(&mut BufReader::new(&mut entry), stored, realsize, |_, _| {})
                        .map_err(|error| refuse(format!("root tar member {path}: {error}")))?;
                    realsize
                }
                None => entry.size(),
            };
            logical = logical.saturating_add(size);
            names.insert(path, kind);
        }
    }
    io::copy(&mut hashing, &mut io::sink()).map_err(unreadable)?;
    let sha256 = format!("{:x}", hashing.hasher.finalize());
    let bytes = hashing.bytes;
    let kernels = boot_checks(&names)?;
    let admitted = RootTar {
        path: PathBuf::new(),
        sha256,
        bytes,
        zstd,
        kernels,
        entries: names.len() as u64,
        logical_bytes: logical,
    };
    Ok((admitted, names))
}

/// Kernels with an initrd and a ZFS module, from the member index.
pub(crate) fn boot_checks(names: &Members) -> io::Result<Vec<String>> {
    let regular = |path: &str| {
        names
            .get(path)
            .is_some_and(|k| k.is_file() || k.is_hard_link())
    };
    if !names.contains_key("") {
        return Err(refuse("the root tar has no root directory member"));
    }
    let mut kernels = Vec::new();
    for path in names.keys() {
        if let Some(release) = path.strip_prefix("boot/vmlinuz-") {
            if !atom(release) || !regular(path) {
                return Err(refuse(format!(
                    "root tar kernel {path} is not a regular file"
                )));
            }
            kernels.push(release.to_string());
        } else if let Some(release) = path.strip_prefix("boot/initrd.img-")
            && !names.contains_key(&format!("boot/vmlinuz-{release}"))
        {
            return Err(refuse(format!("root tar initrd {path} has no kernel")));
        }
    }
    if kernels.is_empty() {
        return Err(refuse("the root tar has no kernel under /boot"));
    }
    for release in &kernels {
        if !regular(&format!("boot/initrd.img-{release}")) {
            return Err(refuse(format!("root tar kernel {release} has no initrd")));
        }
        let module = names.keys().any(|path| {
            let path = path.strip_prefix("usr/").unwrap_or(path);
            path.strip_prefix(&format!("lib/modules/{release}/"))
                .and_then(|rest| rest.rsplit('/').next())
                .is_some_and(|file| {
                    file.split_once('.')
                        .is_some_and(|(stem, ext)| stem == "zfs" && ext.starts_with("ko"))
                })
        });
        if !module {
            return Err(refuse(format!(
                "root tar kernel {release} has no ZFS module"
            )));
        }
    }
    Ok(kernels)
}

/// Admit `path` as a root tar.
pub fn inspect(path: &Path) -> io::Result<RootTar> {
    Ok(inspect_members(path)?.0)
}

fn inspect_members(path: &Path) -> io::Result<(RootTar, Members)> {
    let path = std::fs::canonicalize(path).map_err(crate::output::naming("root tar", path))?;
    let mut file = open(&path)?;
    let before = file.metadata()?;
    let (mut admitted, members) = scan(&mut file, &path)?;
    let after = file.metadata()?;
    if before.len() != after.len()
        || before.modified()? != after.modified()?
        || admitted.bytes != after.len()
    {
        return Err(refuse("root tar changed while it was read"));
    }
    admitted.path = path;
    Ok((admitted, members))
}

/// Admit `path` for a boot in RAM: [`inspect`], plus exactly one kernel, its
/// `modules.dep` and an init (`sbin/init` or `usr/sbin/init`, a file or a
/// link). Returns the member index too.
pub fn inspect_for_ram(path: &Path) -> io::Result<(RootTar, Members)> {
    let (admitted, members) = inspect_members(path)?;
    let [release] = admitted.kernels.as_slice() else {
        return Err(refuse(format!(
            "a RAM boot needs a root tar with exactly one kernel; this one has {}",
            admitted.kernels.join(", ")
        )));
    };
    let present = |path: &str| {
        members
            .get(path)
            .is_some_and(|kind| kind.is_file() || kind.is_hard_link() || kind.is_symlink())
    };
    if !["lib", "usr/lib"]
        .iter()
        .any(|lib| present(&format!("{lib}/modules/{release}/modules.dep")))
    {
        return Err(refuse(format!(
            "root tar kernel {release} has no lib/modules/{release}/modules.dep"
        )));
    }
    if !present("sbin/init") && !present("usr/sbin/init") {
        return Err(refuse("root tar has no sbin/init or usr/sbin/init"));
    }
    Ok((admitted, members))
}

/// A GNU sparse 1.0 member's content as GNU tar extracts it: zeros up to
/// each chunk, then its bytes, ending at the real size. The map was checked
/// ([`sparse_map`]), so the chunks are in order and the last ends there.
struct Expanded<R> {
    /// The member's data after its map.
    data: R,
    chunks: std::vec::IntoIter<(u64, u64)>,
    /// The chunk being read, as its offset and end.
    chunk: Option<(u64, u64)>,
    at: u64,
}
impl<R: Read> Read for Expanded<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some((offset, end)) = self
                .chunk
                .or_else(|| self.chunks.next().map(|(at, size)| (at, at + size)))
            else {
                return Ok(0);
            };
            self.chunk = Some((offset, end));
            let length = buffer.len();
            let room = |left: u64| usize::try_from(left).unwrap_or(usize::MAX).min(length);
            let n = if self.at < offset {
                let n = room(offset - self.at);
                buffer[..n].fill(0);
                n
            } else if self.at < end {
                let n = self.data.read(&mut buffer[..room(end - self.at)])?;
                if n == 0 {
                    return Err(refuse("a GNU sparse member is cut short"));
                }
                n
            } else {
                self.chunk = None;
                continue;
            };
            self.at += n as u64;
            return Ok(n);
        }
    }
}

/// The content of the regular `entry`, as GNU tar extracts it: a GNU sparse
/// 1.0 member expanded from its map, any other as stored.
fn content<'e, 'a: 'e, R: Read + 'e>(
    entry: &'e mut tar::Entry<'a, R>,
    member: &Member,
) -> io::Result<Box<dyn Read + 'e>> {
    let Some(realsize) = member.sparse else {
        return Ok(Box::new(entry));
    };
    let stored = entry.size();
    let mut data = BufReader::new(entry);
    let mut chunks = Vec::new();
    sparse_map(&mut data, stored, realsize, |offset, size| {
        chunks.push((offset, size));
    })
    .map_err(|error| refuse(format!("root tar member {}: {error}", member.path)))?;
    Ok(Box::new(Expanded {
        data,
        chunks: chunks.into_iter(),
        chunk: None,
        at: 0,
    }))
}

/// Write the regular member at the real path `path` from the tar bytes
/// `read` opens (the caller binds them to the admitted digest), as GNU tar
/// would extract it, and return its size. A hardlink names an earlier
/// member, so it takes another read; any other kind is refused.
///
/// This is how zboot reads a member's content from the tar itself; deploy
/// and the RAM bootstrap extract with GNU tar. A GNU sparse 1.0 member is
/// expanded from its map rather than refused: whether a file is stored
/// sparse depends on the filesystem it was archived from, not on the tar's
/// meaning, and admission already parses and checks the same map, so
/// expansion adds only the zero fill between chunks.
pub fn copy_member(
    admitted: &RootTar,
    path: &str,
    mut read: impl FnMut() -> io::Result<Box<dyn Read>>,
    output: &mut impl io::Write,
) -> io::Result<u64> {
    let mut wanted = path.to_string();
    for _ in 0..4 {
        let raw = read()?;
        let reader: Box<dyn Read> = if admitted.zstd {
            Box::new(zstd::stream::read::Decoder::new(raw)?)
        } else {
            raw
        };
        let (mut archive, tapped) = archive(reader);
        let mut link = None;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let member = member(&mut entry, &tapped)?;
            if member.path != wanted {
                continue;
            }
            let kind = entry.header().entry_type();
            if kind.is_hard_link() {
                let target = member
                    .link
                    .ok_or_else(|| refuse("root tar hardlink has no target"))?;
                link = Some(member_path(Path::new(OsStr::from_bytes(&target)))?);
                break;
            }
            if !kind.is_file() {
                return Err(refuse(format!(
                    "root tar member {wanted} is not a regular file"
                )));
            }
            return io::copy(&mut content(&mut entry, &member)?, output);
        }
        wanted = link.ok_or_else(|| refuse(format!("root tar has no {wanted}")))?;
    }
    Err(refuse(format!(
        "root tar member {path} is a chain of hardlinks"
    )))
}

/// Write the kernel `boot/vmlinuz-RELEASE` ([`copy_member`]).
pub fn copy_kernel(
    admitted: &RootTar,
    release: &str,
    read: impl FnMut() -> io::Result<Box<dyn Read>>,
    output: &mut impl io::Write,
) -> io::Result<u64> {
    copy_member(admitted, &format!("boot/vmlinuz-{release}"), read, output)
}

/// Extract the admitted tar into the empty `root`. The same file is scanned
/// and hashed again first and after `tar` read it, so the bytes extracted
/// are the bytes reviewed.
pub fn extract(admitted: &RootTar, root: &Path) -> io::Result<()> {
    if std::fs::read_dir(root)?.next().is_some() {
        return Err(refuse("extraction needs an empty BE root"));
    }
    let mut file = open(&admitted.path)?;
    let (mut again, _) = scan(&mut file, &admitted.path)?;
    again.path = admitted.path.clone();
    if again != *admitted {
        return Err(refuse("root tar changed since it was reviewed"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut command = Command::new("tar");
    command.args(["--extract", "--file=-"]);
    if admitted.zstd {
        command.arg("--zstd");
    }
    let status = zfs_tools::engine::native::announced(
        command
            .args([
                "--xattrs",
                "--xattrs-include=*",
                "--acls",
                "--numeric-owner",
                "--same-owner",
                "--same-permissions",
                "--delay-directory-restore",
            ])
            .arg("--directory")
            .arg(root)
            .stdin(Stdio::from(file.try_clone()?))
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .stdout(io::stderr().as_fd().try_clone_to_owned()?),
    )
    .status()?;
    file.seek(SeekFrom::Start(0))?;
    if hash(&mut file)?
        != (ImageFile {
            sha256: admitted.sha256.clone(),
            bytes: admitted.bytes,
        })
    {
        return Err(refuse("root tar changed during extraction"));
    }
    if !status.success() {
        return Err(refuse(format!("root tar extraction failed ({status})")));
    }
    Ok(())
}

/// The extracted root's boot files: every reviewed kernel and initrd is a
/// regular file; returns their digests.
pub fn boot_files(admitted: &RootTar, root: &Path) -> io::Result<BTreeMap<String, ImageFile>> {
    let directory = File::open(root)?;
    let mut files = BTreeMap::new();
    for release in &admitted.kernels {
        for name in [
            format!("boot/vmlinuz-{release}"),
            format!("boot/initrd.img-{release}"),
        ] {
            let fd = crate::openat2_scoped(
                &directory,
                name.as_str(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(|e| refuse(format!("deployed {name}: {e}")))?;
            let mut file = File::from(fd);
            if !file.metadata()?.is_file() {
                return Err(refuse(format!("deployed {name} is not a regular file")));
            }
            files.insert(name, hash(&mut file)?);
        }
    }
    Ok(files)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::factory::tests::Scratch;

    pub(crate) const R: &str = "7.2.15+deb14-amd64";

    #[test]
    fn a_missing_root_tar_is_named() {
        let error = inspect(Path::new("/nonexistent/zboot-test.tar.zst")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .starts_with("root tar /nonexistent/zboot-test.tar.zst: "),
            "{error}"
        );
    }

    #[test]
    fn a_root_tar_that_is_not_a_tar_is_named() {
        let scratch = Scratch::new();
        for (name, bytes) in [
            ("short.tar", b"not a tar".to_vec()),
            ("header.tar", vec![b'x'; 1024]),
            ("bad.tar.zst", vec![0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3]),
        ] {
            let path = scratch.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            let error = inspect(&path).unwrap_err().to_string();
            let prefix = format!(
                "root tar {}: not a readable tar archive: ",
                std::fs::canonicalize(&path).unwrap().display()
            );
            assert!(error.starts_with(&prefix), "{error}");
        }
    }

    /// A tar of `entries` (path, kind, link target), plain or zstd.
    pub(crate) fn tar_of(
        path: &Path,
        entries: &[(&str, tar::EntryType, Option<&str>)],
        zstd: bool,
    ) {
        let file = File::create(path).unwrap();
        let writer: Box<dyn io::Write> = if zstd {
            Box::new(
                zstd::stream::write::Encoder::new(file, 1)
                    .unwrap()
                    .auto_finish(),
            )
        } else {
            Box::new(file)
        };
        let mut builder = tar::Builder::new(writer);
        append(&mut builder, entries);
        builder.into_inner().unwrap();
    }

    fn append<W: io::Write>(
        builder: &mut tar::Builder<W>,
        entries: &[(&str, tar::EntryType, Option<&str>)],
    ) {
        for (name, kind, link) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
            header.set_size(if kind.is_file() { 1 } else { 0 });
            if let Some(link) = link {
                header.set_link_name(link).unwrap();
            }
            header.set_path(name).unwrap_or_else(|_| {
                // set_path refuses `..`; write the raw name.
                let bytes = name.as_bytes();
                header.as_old_mut().name[..bytes.len()].copy_from_slice(bytes);
            });
            header.set_cksum();
            let data: &[u8] = if kind.is_file() { b"x" } else { b"" };
            builder.append(&header, data).unwrap();
        }
    }

    pub(crate) fn bootable() -> Vec<(&'static str, tar::EntryType, Option<&'static str>)> {
        use tar::EntryType::{Directory, Regular};
        vec![
            ("./", Directory, None),
            ("boot/", Directory, None),
            ("boot/vmlinuz-7.2.15+deb14-amd64", Regular, None),
            ("boot/initrd.img-7.2.15+deb14-amd64", Regular, None),
            ("usr/", Directory, None),
            ("usr/lib/", Directory, None),
            ("usr/lib/modules/", Directory, None),
            ("usr/lib/modules/7.2.15+deb14-amd64/", Directory, None),
            (
                "usr/lib/modules/7.2.15+deb14-amd64/updates/",
                Directory,
                None,
            ),
            (
                "usr/lib/modules/7.2.15+deb14-amd64/updates/zfs.ko.xz",
                Regular,
                None,
            ),
        ]
    }

    /// [`bootable`] with what a RAM boot needs too: `modules.dep` and an init.
    pub(crate) fn ram_bootable() -> Vec<(&'static str, tar::EntryType, Option<&'static str>)> {
        use tar::EntryType::{Directory, Regular, Symlink};
        let mut entries = bootable();
        entries.extend([
            (
                "usr/lib/modules/7.2.15+deb14-amd64/modules.dep",
                Regular,
                None,
            ),
            ("usr/sbin/", Directory, None),
            ("usr/sbin/init", Symlink, Some("../lib/systemd/systemd")),
        ]);
        entries
    }

    #[test]
    fn a_tar_needs_one_kernel_its_modules_and_an_init() {
        use tar::EntryType::{Directory, Link, Regular};
        let scratch = Scratch::new();
        let path = scratch.0.join("root.tar.zst");
        tar_of(&path, &ram_bootable(), true);
        let (admitted, members) = inspect_for_ram(&path).unwrap();
        assert_eq!(admitted, inspect(&path).unwrap());
        assert_eq!(admitted.kernels, [R]);
        assert!(members.contains_key("usr/sbin/init"));
        let mut kernel = Vec::new();
        copy_kernel(
            &admitted,
            R,
            || Ok(Box::new(File::open(&path)?) as Box<dyn Read>),
            &mut kernel,
        )
        .unwrap();
        assert_eq!(kernel, b"x");
        std::fs::remove_file(&path).unwrap();
        // A plain init at sbin/init, and modules.dep outside usr/, also do.
        let mut entries: Vec<_> = bootable();
        entries.extend([
            ("lib/", Directory, None),
            ("lib/modules/", Directory, None),
            ("lib/modules/7.2.15+deb14-amd64/", Directory, None),
            ("lib/modules/7.2.15+deb14-amd64/modules.dep", Regular, None),
            ("sbin/", Directory, None),
            ("sbin/init", Regular, None),
        ]);
        tar_of(&path, &entries, true);
        inspect_for_ram(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        for missing in [
            "usr/lib/modules/7.2.15+deb14-amd64/modules.dep",
            "usr/sbin/init",
        ] {
            let entries: Vec<_> = ram_bootable()
                .into_iter()
                .filter(|e| e.0 != missing)
                .collect();
            tar_of(&path, &entries, true);
            assert!(inspect(&path).is_ok(), "{missing}: a deployable tar");
            let error = inspect_for_ram(&path).unwrap_err().to_string();
            assert!(
                error.contains(missing.rsplit('/').next().unwrap()),
                "{error}"
            );
            std::fs::remove_file(&path).unwrap();
        }
        // Two kernels deploy, but a RAM boot needs exactly one.
        let mut entries = ram_bootable();
        entries.extend([
            ("boot/vmlinuz-7.2.16+deb14-amd64", Regular, None),
            ("boot/initrd.img-7.2.16+deb14-amd64", Regular, None),
            ("usr/lib/modules/7.2.16+deb14-amd64/", Directory, None),
            ("usr/lib/modules/7.2.16+deb14-amd64/zfs.ko", Regular, None),
            (
                "usr/lib/modules/7.2.16+deb14-amd64/modules.dep",
                Regular,
                None,
            ),
        ]);
        tar_of(&path, &entries, true);
        assert_eq!(inspect(&path).unwrap().kernels.len(), 2);
        let error = inspect_for_ram(&path).unwrap_err().to_string();
        assert!(error.contains("exactly one kernel"), "{error}");
        std::fs::remove_file(&path).unwrap();
        // A hardlinked kernel is read from the member it names.
        let mut entries = ram_bootable();
        entries.retain(|e| e.0 != "boot/vmlinuz-7.2.15+deb14-amd64");
        entries.push(("usr/lib/modules/7.2.15+deb14-amd64/vmlinuz", Regular, None));
        entries.push((
            "boot/vmlinuz-7.2.15+deb14-amd64",
            Link,
            Some("usr/lib/modules/7.2.15+deb14-amd64/vmlinuz"),
        ));
        tar_of(&path, &entries, false);
        let (admitted, _) = inspect_for_ram(&path).unwrap();
        let mut kernel = Vec::new();
        copy_kernel(
            &admitted,
            R,
            || Ok(Box::new(File::open(&path)?) as Box<dyn Read>),
            &mut kernel,
        )
        .unwrap();
        assert_eq!(kernel, b"x");
    }

    #[test]
    fn any_bootable_root_tar_is_admitted_plain_or_zstd() {
        let scratch = Scratch::new();
        for zstd in [false, true] {
            let path = scratch.0.join(format!("root-{zstd}.tar"));
            tar_of(&path, &bootable(), zstd);
            let admitted = inspect(&path).unwrap();
            assert_eq!(admitted.kernels, [R]);
            assert_eq!(admitted.zstd, zstd);
            assert_eq!(admitted.bytes, std::fs::metadata(&path).unwrap().len());
            let mut file = File::open(&path).unwrap();
            assert_eq!(hash(&mut file).unwrap().sha256, admitted.sha256);
        }
    }

    #[test]
    fn boot_checks_need_an_initrd_and_zfs_module_for_every_kernel() {
        let scratch = Scratch::new();
        let path = scratch.0.join("root.tar");
        for missing in [
            "boot/initrd.img-7.2.15+deb14-amd64",
            "usr/lib/modules/7.2.15+deb14-amd64/updates/zfs.ko.xz",
            "boot/vmlinuz-7.2.15+deb14-amd64",
        ] {
            let entries: Vec<_> = bootable().into_iter().filter(|e| e.0 != missing).collect();
            tar_of(&path, &entries, false);
            assert!(inspect(&path).is_err(), "{missing}");
            std::fs::remove_file(&path).unwrap();
        }
        // Another kernel's module does not count.
        let mut entries = bootable();
        entries.push((
            "boot/vmlinuz-7.2.16+deb14-amd64",
            tar::EntryType::Regular,
            None,
        ));
        entries.push((
            "boot/initrd.img-7.2.16+deb14-amd64",
            tar::EntryType::Regular,
            None,
        ));
        tar_of(&path, &entries, false);
        let error = inspect(&path).unwrap_err().to_string();
        assert!(error.contains("7.2.16") && error.contains("ZFS"), "{error}");
    }

    #[test]
    fn containment_refuses_traversal_crossing_duplicates_and_dangling_hardlinks() {
        use tar::EntryType::{Link, Regular, Symlink};
        let scratch = Scratch::new();
        let path = scratch.0.join("root.tar");
        for extra in [
            vec![("../escape", Regular, None)],
            vec![("etc", Symlink, Some("/")), ("etc/passwd", Regular, None)],
            vec![("boot/vmlinuz-7.2.15+deb14-amd64", Regular, None)],
            vec![("etc/shadow", Link, Some("missing"))],
            vec![("usr", Regular, None)],
        ] {
            let mut entries = bootable();
            entries.extend(extra.clone());
            tar_of(&path, &entries, false);
            assert!(inspect(&path).is_err(), "{extra:?}");
            std::fs::remove_file(&path).unwrap();
        }
        // A boot file hardlinked to an earlier regular member is fine.
        let mut entries = bootable();
        entries.retain(|e| e.0 != "boot/vmlinuz-7.2.15+deb14-amd64");
        entries.push(("usr/lib/modules/7.2.15+deb14-amd64/vmlinuz", Regular, None));
        entries.push((
            "boot/vmlinuz-7.2.15+deb14-amd64",
            Link,
            Some("usr/lib/modules/7.2.15+deb14-amd64/vmlinuz"),
        ));
        tar_of(&path, &entries, false);
        inspect(&path).unwrap();
    }

    #[test]
    fn extraction_refuses_a_tar_changed_since_review_before_writing() {
        let scratch = Scratch::new();
        let path = scratch.0.join("root.tar");
        tar_of(&path, &bootable(), false);
        let admitted = inspect(&path).unwrap();
        let mut entries = bootable();
        entries.push(("etc/", tar::EntryType::Directory, None));
        std::fs::remove_file(&path).unwrap();
        tar_of(&path, &entries, false);
        let root = scratch.0.join("root");
        std::fs::create_dir(&root).unwrap();
        assert!(extract(&admitted, &root).is_err());
        assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    }

    /// The format options mmdebstrap 1.7 gives GNU tar for a root tar,
    /// besides `--sparse`.
    const MMDEBSTRAP: [&str; 2] = [
        "--format=pax",
        "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
    ];

    /// Whether `path`, a member's real name, is a file in DIR whose name
    /// starts with BASE.
    fn real_name(path: &str, dir: &str, base: &str) -> bool {
        path.rsplit_once('/').is_some_and(|(parent, name)| {
            (parent == dir || parent.ends_with(&format!("/{dir}"))) && name.starts_with(base)
        })
    }

    /// Whether `bytes`, a plain GNU tar archive, holds that file as a sparse
    /// member: a pax extended header with `GNU.sparse.name` naming it. The
    /// placeholder name GNU tar gives the member itself varies (its process
    /// id upstream, 0 in Debian's tar) and, for a deep path, fits no header
    /// field, so only this record identifies the member everywhere.
    fn stored_sparse(bytes: &[u8], dir: &str, base: &str) -> bool {
        let field = |block: &[u8], from: usize, to: usize| {
            let raw = &block[from..to];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..end]).into_owned()
        };
        let mut at = 0;
        while at + 512 <= bytes.len() {
            let block = &bytes[at..at + 512];
            if block.iter().all(|&b| b == 0) {
                break;
            }
            let size = usize::from_str_radix(field(block, 124, 136).trim(), 8).unwrap();
            if block[156] == b'x' {
                let records = String::from_utf8_lossy(&bytes[at + 512..at + 512 + size]);
                // Records are `LEN KEY=VALUE\n`; a value holds no newline here.
                if records.lines().any(|record| {
                    record
                        .split_once(' ')
                        .and_then(|(_, kv)| kv.strip_prefix("GNU.sparse.name="))
                        .is_some_and(|name| real_name(name, dir, base))
                }) {
                    return true;
                }
            }
            at += 512 + size.div_ceil(512) * 512;
        }
        false
    }

    /// `tar --create --sparse` of `root` with the format `options`.
    fn gnu_tar(root: &Path, output: &Path, options: &[&str]) {
        let status = Command::new("tar")
            .args(["--sort=name", "--numeric-owner", "--sparse"])
            .args(options)
            .arg("--create")
            .arg("--file")
            .arg(output)
            .arg("--directory")
            .arg(root)
            .arg(".")
            .env("LC_ALL", "C")
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Write `path` with `len` bytes: each `(offset, bytes)` and holes
    /// between. Returns the content.
    fn holey(path: &Path, len: u64, data: &[(u64, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = File::create(path).unwrap();
        let mut content = vec![0; len as usize];
        for (offset, bytes) in data {
            file.seek(SeekFrom::Start(*offset)).unwrap();
            file.write_all(bytes).unwrap();
            content[*offset as usize..][..bytes.len()].copy_from_slice(bytes);
        }
        file.set_len(len).unwrap();
        content
    }

    /// A sparse file in Debian's firmware-sof-signed whose GNU tar
    /// placeholder exceeds a ustar name field.
    const LONG: &str =
        "usr/lib/firmware/intel/sof-ipc4-lib/mtl/community/google_rtc_audio_processing.llext";
    /// A sparse file in the zboot package whose placeholder GNU tar cuts to
    /// `.../GNUSparseFile.0/`.
    const SLASH: &str = "usr/share/doc/zboot/LICENCES/rust/crates/is_terminal_polyfill-1.70.2-50146a7801ff/LICENSE-MIT";

    /// A bootable root under `root` whose kernel, initrd, `usr/bin/zboot`,
    /// `usr/bin/perl`, [`LONG`] and [`SLASH`] have holes, with
    /// `usr/bin/perl5.44.0` a hardlink to perl, as Debian ships it, and
    /// `usr/bin/zsnap` a symlink to zboot. Returns each regular file's
    /// content.
    fn sparse_root(root: &Path) -> BTreeMap<&'static str, Vec<u8>> {
        const MIB: u64 = 1 << 20;
        let mut files = BTreeMap::new();
        for (name, len, data) in [
            (
                "boot/vmlinuz-7.2.15+deb14-amd64",
                2 * MIB + 5,
                &[(0, &b"MZ kernel"[..]), (MIB, b"middle")][..],
            ),
            (
                "usr/bin/perl",
                3 * MIB,
                &[(0, &b"\x7fELF perl"[..]), (2 * MIB + 7, b"tail")][..],
            ),
            // Its placeholder is longer than a ustar name, so GNU tar cuts
            // it to 100 bytes (`...google_rtc_audio_processing.llex`).
            (LONG, MIB + 4, &[(0, &b"llext"[..]), (MIB, b"tail")][..]),
            // GNU tar cuts this one's placeholder just after its `/`.
            (SLASH, MIB + 4, &[(0, &b"MIT"[..]), (MIB, b"tail")][..]),
            // The other members the engine reads from a factory tar.
            (
                "boot/initrd.img-7.2.15+deb14-amd64",
                2 * MIB + 1,
                &[(0, &b"\x28\xb5\x2f\xfd initrd"[..]), (2 * MIB, b"!")][..],
            ),
            (
                "usr/bin/zboot",
                MIB + 9,
                &[(0, &b"\x7fELF zboot"[..]), (MIB, b"zboot end")][..],
            ),
        ] {
            files.insert(name, holey(&root.join(name), len, data));
        }
        let module = "usr/lib/modules/7.2.15+deb14-amd64/updates/zfs.ko.xz";
        files.insert(module, holey(&root.join(module), 3, &[(0, b"abc")]));
        std::fs::hard_link(root.join("usr/bin/perl"), root.join("usr/bin/perl5.44.0")).unwrap();
        std::os::unix::fs::symlink("zboot", root.join("usr/bin/zsnap")).unwrap();
        files
    }

    #[test]
    fn gnu_sparse_members_are_admitted_by_their_real_names_and_sizes() {
        use tar::EntryType::{Link, Regular};
        let scratch = Scratch::new();
        let source = scratch.0.join("source");
        let files = sparse_root(&source);
        let plain = scratch.0.join("root.tar");
        gnu_tar(&source, &plain, &MMDEBSTRAP);
        let bytes = std::fs::read(&plain).unwrap();
        for (dir, base) in [
            ("boot", "vmlinuz-"),
            ("usr/bin", "perl"),
            ("community", "google_rtc_audio_processing.llex"),
        ] {
            assert!(
                stored_sparse(&bytes, dir, base),
                "GNU tar stored {dir}/{base} as sparse"
            );
        }
        let zstd = scratch.0.join("root.tar.zst");
        std::fs::write(
            &zstd,
            zstd::stream::encode_all(bytes.as_slice(), 1).unwrap(),
        )
        .unwrap();
        for path in [&plain, &zstd] {
            let (admitted, members) = inspect_members(path).unwrap();
            assert_eq!(admitted.kernels, [R]);
            assert_eq!(members.get("usr/bin/perl"), Some(&Regular));
            // The hardlink names the real path, an earlier regular member.
            assert_eq!(members.get("usr/bin/perl5.44.0"), Some(&Link));
            assert_eq!(members.get(LONG), Some(&Regular));
            assert_eq!(members.get(SLASH), Some(&Regular));
            assert!(members.keys().all(|name| !name.contains("GNUSparseFile")));
            let logical: usize = files.values().map(Vec::len).sum();
            assert_eq!(admitted.logical_bytes, logical as u64);
            let mut kernel = Vec::new();
            copy_kernel(
                &admitted,
                R,
                || Ok(Box::new(File::open(path)?) as Box<dyn Read>),
                &mut kernel,
            )
            .unwrap();
            assert!(kernel == files["boot/vmlinuz-7.2.15+deb14-amd64"]);
        }
        // Deploy's GNU tar extraction restores the content the boot files
        // are then hashed from.
        let admitted = inspect(&plain).unwrap();
        let root = scratch.0.join("root");
        std::fs::create_dir(&root).unwrap();
        extract(&admitted, &root).unwrap();
        let boot = boot_files(&admitted, &root).unwrap();
        for (name, digest) in &boot {
            let content = &files[name.as_str()];
            assert_eq!(digest.bytes, content.len() as u64);
            assert_eq!(digest.sha256, format!("{:x}", Sha256::digest(content)));
        }
        assert!(std::fs::read(root.join("usr/bin/perl5.44.0")).unwrap() == files["usr/bin/perl"]);
    }

    /// One member as `tar --sparse` writes a GNU sparse 1.0 file: `keys` as
    /// PAX records, the header path and kind, then `map` padded to a block
    /// and `chunks` as its data.
    #[derive(Clone)]
    struct Crafted<'a> {
        keys: Vec<(&'a str, &'a str)>,
        header: (&'a str, tar::EntryType),
        map: &'a str,
        chunks: Vec<u8>,
    }

    const KERNEL: &str = "boot/vmlinuz-7.2.15+deb14-amd64";
    const PERL: &str = "usr/bin/GNUSparseFile.0/perl";
    /// A block of data, a hole, four bytes and a trailing hole, ending in
    /// GNU tar's empty last chunk.
    const MAP: &str = "3\n0\n512\n8192\n4\n10000\n0\n";

    /// The bytes of [`MAP`]'s chunks.
    fn chunks() -> Vec<u8> {
        [vec![b'h'; 512], b"tail".to_vec()].concat()
    }

    fn sparse_keys<'a>(name: &'a str, realsize: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.minor", "0"),
            ("GNU.sparse.name", name),
            ("GNU.sparse.realsize", realsize),
        ]
    }

    /// `usr/bin/perl` as a 10000-byte sparse file.
    fn perl() -> Crafted<'static> {
        Crafted {
            keys: sparse_keys("usr/bin/perl", "10000"),
            header: (PERL, tar::EntryType::Regular),
            map: MAP,
            chunks: chunks(),
        }
    }

    /// `before`, the `crafted` member, then `after`.
    fn sparse_tar(
        path: &Path,
        before: &[(&str, tar::EntryType, Option<&str>)],
        crafted: &Crafted,
        after: &[(&str, tar::EntryType, Option<&str>)],
    ) {
        let mut builder = tar::Builder::new(File::create(path).unwrap());
        append(&mut builder, before);
        let keys = crafted.keys.iter();
        builder
            .append_pax_extensions(keys.map(|(key, value)| (*key, value.as_bytes())))
            .unwrap();
        let mut data = crafted.map.as_bytes().to_vec();
        data.resize(crafted.map.len().next_multiple_of(512), 0);
        data.extend_from_slice(&crafted.chunks);
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(crafted.header.1);
        header.set_mode(0o644);
        header.set_size(data.len() as u64);
        header.set_path(crafted.header.0).unwrap();
        header.set_cksum();
        builder.append(&header, data.as_slice()).unwrap();
        append(&mut builder, after);
        builder.into_inner().unwrap();
    }

    #[test]
    fn a_sparse_kernel_is_read_from_its_map_as_gnu_tar_extracts_it() {
        use tar::EntryType::{Link, Regular};
        const MODULE_KERNEL: &str = "usr/lib/modules/7.2.15+deb14-amd64/vmlinuz";
        let scratch = Scratch::new();
        let path = scratch.0.join("root.tar");
        // The kernel is a hardlink to a sparse member.
        let mut before = bootable();
        before.retain(|entry| entry.0 != KERNEL);
        let kernel = Crafted {
            keys: sparse_keys(MODULE_KERNEL, "10000"),
            header: (
                "usr/lib/modules/7.2.15+deb14-amd64/GNUSparseFile.0/vmlinuz",
                Regular,
            ),
            ..perl()
        };
        sparse_tar(
            &path,
            &before,
            &kernel,
            &[(KERNEL, Link, Some(MODULE_KERNEL))],
        );
        let admitted = inspect(&path).unwrap();
        // The initrd and module of `bootable` are a byte each.
        assert_eq!(admitted.logical_bytes, 10000 + 2);
        let mut copied = Vec::new();
        let bytes = copy_kernel(
            &admitted,
            R,
            || Ok(Box::new(File::open(&path)?) as Box<dyn Read>),
            &mut copied,
        )
        .unwrap();
        let mut expected = vec![0; 10000];
        expected[..512].fill(b'h');
        expected[8192..8196].copy_from_slice(b"tail");
        assert_eq!(bytes, 10000);
        assert!(copied == expected);
        // GNU tar reads the same map. These members are uid 0, which deploy's
        // --same-owner could not restore here, so it extracts plainly.
        let root = scratch.0.join("root");
        std::fs::create_dir(&root).unwrap();
        let status = Command::new("tar")
            .arg("--extract")
            .arg("--file")
            .arg(&path)
            .arg("--directory")
            .arg(&root)
            .env("LC_ALL", "C")
            .status()
            .unwrap();
        assert!(status.success());
        assert!(std::fs::read(root.join(MODULE_KERNEL)).unwrap() == expected);
        assert!(std::fs::read(root.join(KERNEL)).unwrap() == expected);
    }

    #[test]
    fn other_sparse_formats_and_inconsistent_sparse_members_are_refused() {
        use tar::EntryType::{Link, Regular, Symlink};
        let scratch = Scratch::new();
        // GNU tar's older formats, written from files with holes.
        let source = scratch.0.join("source");
        sparse_root(&source);
        for (options, refusal) in [
            (&["--format=gnu"][..], "old GNU sparse member"),
            (
                &[MMDEBSTRAP[0], MMDEBSTRAP[1], "--sparse-version=0.0"],
                "an older GNU sparse format",
            ),
            (
                &[MMDEBSTRAP[0], MMDEBSTRAP[1], "--sparse-version=0.1"],
                "an older GNU sparse format",
            ),
        ] {
            let path = scratch.0.join("old.tar");
            gnu_tar(&source, &path, options);
            let error = inspect(&path).unwrap_err().to_string();
            assert!(error.contains(refusal), "{options:?}: {error}");
            std::fs::remove_file(&path).unwrap();
        }
        let link = ("usr/bin/perl5.44.0", Link, Some("usr/bin/perl"));
        let placeholder_link = ("usr/bin/perl5.44.0", Link, Some(PERL));
        let mut repeated = perl();
        repeated.keys.push(("GNU.sparse.name", "usr/bin/other"));
        let with_keys = |keys| Crafted { keys, ..perl() };
        let with_header = |name| Crafted {
            header: (name, Regular),
            ..perl()
        };
        let with_map = |map| Crafted { map, ..perl() };
        let with_chunks = |chunks: &[u8]| Crafted {
            chunks: chunks.to_vec(),
            ..perl()
        };
        let cases = [
            ("the reference member", perl(), Some(link), ""),
            (
                "format 2.0",
                with_keys(vec![
                    ("GNU.sparse.major", "2"),
                    ("GNU.sparse.minor", "0"),
                    ("GNU.sparse.name", "usr/bin/perl"),
                    ("GNU.sparse.realsize", "10000"),
                ]),
                None,
                "GNU sparse 2.0; only 1.0",
            ),
            (
                "no real size",
                with_keys(perl().keys[..3].to_vec()),
                None,
                "lacks GNU.sparse.name or GNU.sparse.realsize",
            ),
            (
                "no version",
                with_keys(perl().keys[2..].to_vec()),
                None,
                "GNU sparse ?.?",
            ),
            ("a repeated name", repeated, None, "repeats GNU.sparse.name"),
            (
                "a real size that is not a decimal",
                with_keys(sparse_keys("usr/bin/perl", "1e4")),
                None,
                "invalid GNU.sparse.realsize",
            ),
            (
                "a header that is not the placeholder",
                with_header("usr/bin/perl.sparse"),
                None,
                "placeholder",
            ),
            (
                "a placeholder without the real name's ./",
                with_keys(sparse_keys("./usr/bin/perl", "10000")),
                None,
                "placeholder",
            ),
            (
                "a placeholder in another directory",
                with_header("etc/GNUSparseFile.0/perl"),
                None,
                "placeholder",
            ),
            (
                "a traversing real name",
                Crafted {
                    keys: sparse_keys("../perl", "10000"),
                    header: ("GNUSparseFile.0/perl", Regular),
                    ..perl()
                },
                None,
                "parent-traversing",
            ),
            (
                "an absolute real name",
                with_keys(sparse_keys("/usr/bin/perl", "10000")),
                None,
                "absolute",
            ),
            (
                "a real name that duplicates a member",
                Crafted {
                    keys: sparse_keys(KERNEL, "10000"),
                    header: ("boot/GNUSparseFile.0/vmlinuz-7.2.15+deb14-amd64", Regular),
                    ..perl()
                },
                None,
                "duplicates",
            ),
            (
                "a hardlink to the placeholder",
                perl(),
                Some(placeholder_link),
                "must name an earlier regular member",
            ),
            (
                "sparse keys on a symlink",
                Crafted {
                    header: (PERL, Symlink),
                    ..perl()
                },
                None,
                "not a regular file",
            ),
            (
                "a real size before the last chunk's end",
                Crafted {
                    keys: sparse_keys("usr/bin/perl", "8195"),
                    map: "2\n0\n512\n8192\n4\n",
                    ..perl()
                },
                None,
                "past the real size",
            ),
            (
                "chunks out of order",
                with_map("2\n8192\n4\n0\n512\n"),
                None,
                "out of order",
            ),
            (
                "a partial block before another chunk",
                Crafted {
                    map: "3\n0\n4\n8192\n600\n10000\n0\n",
                    chunks: vec![b'p'; 604],
                    ..perl()
                },
                None,
                "part of a block before another chunk",
            ),
            (
                "an empty chunk before the last",
                with_map("3\n0\n512\n8192\n0\n10000\n0\n"),
                None,
                "empty chunk before the last",
            ),
            (
                "a map short of the real size",
                with_map("2\n0\n512\n8192\n4\n"),
                None,
                "does not reach its real size",
            ),
            (
                "more stored bytes than the map's chunks",
                with_chunks(&[chunks(), b"!".to_vec()].concat()),
                None,
                "account for exactly its stored bytes",
            ),
            (
                "fewer stored bytes than the map's chunks",
                with_chunks(&chunks()[..515]),
                None,
                "account for exactly its stored bytes",
            ),
            (
                "a map entry that is not a decimal",
                with_map("3\n0\n512\n8192\n+4\n10000\n0\n"),
                None,
                "malformed",
            ),
            (
                "a map cut short",
                with_map("3\n0\n512\n8192\n4\n"),
                None,
                "malformed",
            ),
        ];
        let path = scratch.0.join("root.tar");
        for (case, crafted, after, refusal) in cases {
            let after: Vec<_> = after.into_iter().collect();
            sparse_tar(&path, &bootable(), &crafted, &after);
            match inspect_members(&path) {
                Ok((admitted, members)) if refusal.is_empty() => {
                    // `bootable` holds three one-byte files.
                    assert_eq!(admitted.logical_bytes, 3 + 10000, "{case}");
                    assert!(members.contains_key("usr/bin/perl"), "{case}");
                }
                Ok(_) => panic!("{case}: admitted"),
                Err(error) => {
                    let error = error.to_string();
                    assert!(
                        !refusal.is_empty() && error.contains(refusal),
                        "{case}: {error}"
                    );
                }
            }
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn a_sparse_placeholder_is_gnu_tars_name_cut_only_at_the_name_field() {
        let name = format!("./{LONG}");
        let full = format!(
            "./usr/lib/firmware/intel/sof-ipc4-lib/mtl/community/GNUSparseFile.0/{}",
            "google_rtc_audio_processing.llext"
        );
        let (name, full) = (name.as_bytes(), full.as_bytes());
        assert_eq!(full.len(), 101);
        assert!(sparse_placeholder(full, name));
        assert!(sparse_placeholder(&full[..100], name));
        // Only the field size cuts a placeholder.
        assert!(!sparse_placeholder(&full[..99], name));
        assert!(!sparse_placeholder(
            &full[..100],
            b"./usr/lib/firmware/other.llext"
        ));
        assert!(!sparse_placeholder(&full[2..], name));
        // Cut inside the directory, or right after the marker's digits.
        let deep = format!("{}/f", "d".repeat(95));
        let placeholder = format!("{}/GNUSparseFile.0/f", "d".repeat(95));
        assert!(sparse_placeholder(
            &placeholder.as_bytes()[..100],
            deep.as_bytes()
        ));
        let digits = format!("{}/f", "d".repeat(84));
        let placeholder = format!("{}/GNUSparseFile.0", "d".repeat(84));
        assert_eq!(placeholder.len(), 100);
        assert!(sparse_placeholder(
            placeholder.as_bytes(),
            digits.as_bytes()
        ));
        let slash = format!("./{SLASH}");
        let cut = format!("{}/GNUSparseFile.0/", slash.rsplit_once('/').unwrap().0);
        assert_eq!(cut.len(), 100);
        assert!(sparse_placeholder(cut.as_bytes(), slash.as_bytes()));
        assert!(real_name("./usr/bin/perl", "usr/bin", "perl"));
        assert!(real_name("./a/mtl/community/x.llex", "community", "x.llex"));
        assert!(real_name("./boot/vmlinuz-7.2", "boot", "vmlinuz-"));
        assert!(!real_name("./usr/bin/perl", "usr/bin", "perl5"));
        assert!(!real_name("./usr/xbin/perl", "bin", "perl"));
        // A name with no directory is under `.`.
        assert!(sparse_placeholder(b"./GNUSparseFile.0/perl", b"perl"));
        assert!(!sparse_placeholder(b"GNUSparseFile.0/perl", b"perl"));
        assert!(!sparse_placeholder(b"./GNUSparseFile./perl", b"perl"));
        assert!(!sparse_placeholder(b"./GNUSparseFile.0x/perl", b"perl"));
    }

    /// A raw tar header as the review's probe tars were written, with ustar
    /// (`posix`), GNU (`gnu`) or no (`v7`) magic.
    fn raw_header(name: &[u8], size: usize, kind: u8, magic: &str, prefix: &[u8]) -> Vec<u8> {
        let mut header = vec![0_u8; 512];
        let octal = |value: usize, width: usize| format!("{value:0w$o}\0", w = width - 1);
        header[..name.len()].copy_from_slice(name);
        let mode = if kind == b'5' { 0o755 } else { 0o644 };
        header[100..108].copy_from_slice(octal(mode, 8).as_bytes());
        header[108..116].copy_from_slice(octal(0, 8).as_bytes());
        header[116..124].copy_from_slice(octal(0, 8).as_bytes());
        header[124..136].copy_from_slice(octal(size, 12).as_bytes());
        header[136..148].copy_from_slice(octal(0, 12).as_bytes());
        header[156] = kind;
        match magic {
            "posix" => header[257..265].copy_from_slice(b"ustar\x0000"),
            "gnu" => header[257..265].copy_from_slice(b"ustar  \0"),
            _ => {}
        }
        header[345..345 + prefix.len()].copy_from_slice(prefix);
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }

    /// `header` with the link name `link`, its checksum again.
    fn linked(mut header: Vec<u8>, link: &[u8]) -> Vec<u8> {
        header[157..157 + link.len()].copy_from_slice(link);
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }

    fn blocks(data: &[u8]) -> Vec<u8> {
        let mut data = data.to_vec();
        data.resize(data.len().next_multiple_of(512), 0);
        data
    }

    /// One PAX record, its length counting itself.
    fn record(key: &str, value: &[u8]) -> Vec<u8> {
        let body = [b" ", key.as_bytes(), b"=", value, b"\n"].concat();
        let mut length = body.len() + 1;
        while length.to_string().len() + body.len() != length {
            length += 1;
        }
        [length.to_string().as_bytes(), &body].concat()
    }

    fn pax_header(records: &[Vec<u8>]) -> Vec<u8> {
        let data = records.concat();
        [
            raw_header(b"PaxHeaders/x", data.len(), b'x', "posix", b""),
            blocks(&data),
        ]
        .concat()
    }

    fn raw_file(name: &[u8], data: &[u8]) -> Vec<u8> {
        [
            raw_header(name, data.len(), b'0', "posix", b""),
            blocks(data),
        ]
        .concat()
    }

    fn raw_sparse_keys(name: &[u8], realsize: &str) -> Vec<Vec<u8>> {
        vec![
            record("GNU.sparse.major", b"1"),
            record("GNU.sparse.minor", b"0"),
            record("GNU.sparse.name", name),
            record("GNU.sparse.realsize", realsize.as_bytes()),
        ]
    }

    /// [`bootable`], then `body`, then the end of the archive.
    fn probe(path: &Path, body: &[u8]) {
        let mut builder = tar::Builder::new(Vec::new());
        append(&mut builder, &bootable());
        let bytes = [builder.get_ref().as_slice(), body, &[0; 1024]].concat();
        std::fs::write(path, bytes).unwrap();
    }

    /// The review's probes, each a member GNU tar 1.35 reads differently
    /// from the tar crate unless admission refuses it.
    #[test]
    fn members_gnu_tar_would_read_differently_are_refused() {
        let scratch = Scratch::new();
        let path = scratch.0.join("probe.tar");
        let map = blocks(b"1\n1024\n0\n");
        let placeholder = b"usr/bin/GNUSparseFile.0/perl";
        let perl = || pax_header(&raw_sparse_keys(b"usr/bin/perl", "1024"));
        let sparse_under = |magic: &str, prefix: &[u8]| {
            [
                raw_header(placeholder, map.len(), b'0', magic, prefix),
                map.clone(),
            ]
            .concat()
        };
        // GNU tar reads a sparse member under any other header as a plain
        // file of its real size, so the next member hides in its data.
        let carrier = [
            raw_header(b"usr/share/carrier", 512, b'0', "posix", b""),
            raw_header(b"etc/hidden", 0, b'0', "posix", b""),
        ]
        .concat();
        let star = [&[0; 131][..], b"00000000000 00000000000 "].concat();
        let mut zero_chunks = b"201\n".to_vec();
        zero_chunks.extend(b"0\n0\n".repeat(200));
        zero_chunks.extend(b"4096\n0\n");
        let zero_chunks = blocks(&zero_chunks);
        let long_name = b"usr/share/long-name-from-L\0";
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("control", [perl(), sparse_under("posix", b"")].concat(), ""),
            (
                "gnu_magic",
                [perl(), sparse_under("gnu", b""), carrier.clone()].concat(),
                "POSIX header",
            ),
            (
                "star_prefix",
                [perl(), sparse_under("posix", &star), carrier.clone()].concat(),
                "POSIX header",
            ),
            (
                "v7_magic",
                [perl(), sparse_under("v7", b""), carrier.clone()].concat(),
                "POSIX header",
            ),
            (
                "dup_path",
                [
                    pax_header(&[
                        record("path", b"usr/share/doc-a"),
                        record("path", b"etc/dup-path-last"),
                    ]),
                    raw_file(b"usr/share/plain", b"content"),
                ]
                .concat(),
                "repeats path",
            ),
            (
                "dup_size",
                [
                    pax_header(&[record("size", b"512"), record("size", b"0")]),
                    raw_header(b"usr/share/sized", 512, b'0', "posix", b""),
                    raw_header(b"etc/hidden-dupsize", 0, b'0', "posix", b""),
                ]
                .concat(),
                "repeats size",
            ),
            (
                "hidden_name",
                [
                    pax_header(&[
                        record("comment", b"x\n"),
                        record("GNU.sparse.name", b"etc/hidden-name"),
                    ]),
                    raw_file(b"usr/share/harmless", b"content"),
                ]
                .concat(),
                "GNU sparse ?.?",
            ),
            (
                "nul_name",
                [
                    raw_file(b"sbin/init", b"real init"),
                    pax_header(
                        &[
                            vec![record("path", b"sbin/GNUSparseFile.0/init\0x")],
                            raw_sparse_keys(b"sbin/init\0x", "1024"),
                        ]
                        .concat(),
                    ),
                    raw_header(b"sbin/GNUSparseFile.0/init", map.len(), b'0', "posix", b""),
                    map.clone(),
                ]
                .concat(),
                "NUL",
            ),
            (
                "a NUL in a plain member's PAX path",
                [
                    pax_header(&[record("path", b"usr/share/a\0b")]),
                    raw_file(b"usr/share/a", b"x"),
                ]
                .concat(),
                "NUL",
            ),
            (
                "trailing_slash",
                [
                    pax_header(&raw_sparse_keys(b"usr/bin/perl/", "1024")),
                    raw_header(
                        b"usr/bin/perl/GNUSparseFile.0/",
                        map.len(),
                        b'0',
                        "posix",
                        b"",
                    ),
                    map.clone(),
                ]
                .concat(),
                "ending in /",
            ),
            (
                "a sparse real name ending in /",
                [
                    pax_header(&raw_sparse_keys(b"usr/bin/perl/", "1024")),
                    sparse_under("posix", b""),
                ]
                .concat(),
                "ending in /",
            ),
            (
                "a plain file named with a trailing /",
                raw_file(b"usr/share/file/", b"x"),
                "ends in /",
            ),
            (
                "a directory with data",
                [
                    raw_header(b"usr/share/dir/", 512, b'5', "posix", b""),
                    raw_header(b"etc/hidden-in-dir", 0, b'0', "posix", b""),
                ]
                .concat(),
                "not a regular file but has data",
            ),
            (
                "many_zero_chunks",
                [
                    pax_header(&raw_sparse_keys(b"usr/bin/zero", "4096")),
                    raw_header(
                        b"usr/bin/GNUSparseFile.0/zero",
                        zero_chunks.len(),
                        b'0',
                        "posix",
                        b"",
                    ),
                    zero_chunks,
                ]
                .concat(),
                "more chunks than its stored bytes hold",
            ),
            (
                "global_sparse",
                {
                    let data = record("GNU.sparse.name", b"etc/global-name");
                    [
                        raw_header(b"PaxHeaders/g", data.len(), b'g', "posix", b""),
                        blocks(&data),
                        raw_file(b"usr/share/after-global", b"c"),
                    ]
                    .concat()
                },
                "unsupported kind",
            ),
            (
                "longname_sparse",
                [
                    raw_header(b"././@LongLink", long_name.len(), b'L', "gnu", b""),
                    blocks(long_name),
                    perl(),
                    sparse_under("posix", b""),
                ]
                .concat(),
                "POSIX header",
            ),
            (
                "longname_padding",
                [
                    raw_header(b"././@LongLink", 12, b'L', "gnu", b""),
                    blocks(b"usr/share/ln-padding-tail\0"),
                    raw_file(b"usr/share/short", b"c"),
                ]
                .concat(),
                "no NUL within its size",
            ),
            (
                "tab_sparse_name",
                {
                    let record = b" \tGNU.sparse.name=etc/tab-name\n";
                    let record = [format!("{}", record.len() + 2).as_bytes(), record].concat();
                    [
                        raw_header(b"PaxHeaders/x", record.len(), b'x', "posix", b""),
                        blocks(&record),
                        raw_file(b"usr/share/plain3", b"c"),
                    ]
                    .concat()
                },
                "GNU sparse ?.?",
            ),
            (
                "len_overrun",
                [
                    pax_header(&[b"9999 path=etc/x\n".to_vec()]),
                    raw_file(b"usr/share/o1", b"c"),
                ]
                .concat(),
                "malformed record",
            ),
            (
                "len_huge",
                [
                    pax_header(&[b"99999999999999999999 path=etc/x\n".to_vec()]),
                    raw_file(b"usr/share/o2", b"c"),
                ]
                .concat(),
                "malformed record",
            ),
            (
                "non_utf8_path",
                [
                    pax_header(&[record("path", b"usr/share/\xff\xfe")]),
                    raw_file(b"usr/share/o3", b"c"),
                ]
                .concat(),
                "not UTF-8",
            ),
        ];
        // GNU tar reads data only for a regular file and gives a hardlink no
        // size, so the next header hides in a non-file's data.
        let initrd = format!("boot/initrd.img-{R}");
        let mut cases = cases;
        for (case, kind, link) in [
            ("data_on_symlink", b'2', &b"plain"[..]),
            ("data_on_hardlink", b'1', initrd.as_bytes()),
            ("data_on_fifo", b'6', b""),
        ] {
            let name = format!("usr/share/{case}");
            let body = [
                linked(raw_header(name.as_bytes(), 512, kind, "posix", b""), link),
                raw_header(b"etc/hidden", 0, b'0', "posix", b""),
            ]
            .concat();
            cases.push((case, body, "not a regular file but has data"));
        }
        cases.push((
            "hardlink_pax_size",
            [
                pax_header(&[record("size", b"512")]),
                linked(
                    raw_header(b"usr/share/hard2", 0, b'1', "posix", b""),
                    initrd.as_bytes(),
                ),
                raw_header(b"etc/hidden-hard2", 0, b'0', "posix", b""),
            ]
            .concat(),
            "not a regular file but has data",
        ));
        for (case, body, refusal) in cases {
            probe(&path, &body);
            match inspect_members(&path) {
                Ok((_, members)) if refusal.is_empty() => {
                    assert!(members.contains_key("usr/bin/perl"), "{case}");
                }
                Ok(_) => panic!("{case}: admitted"),
                Err(error) => {
                    let error = error.to_string();
                    assert!(
                        !refusal.is_empty() && error.contains(refusal),
                        "{case}: {error}"
                    );
                }
            }
            std::fs::remove_file(&path).unwrap();
        }
    }

    /// Records the tar crate misreads are read as GNU tar reads them, and a
    /// value with newlines, as a binary xattr may have, is no refusal.
    #[test]
    fn pax_records_are_read_by_their_length_as_gnu_tar_reads_them() {
        let scratch = Scratch::new();
        let path = scratch.0.join("probe.tar");
        // Sparse keys inside a comment's value: GNU tar sees a plain file
        // under the placeholder's own name, and so does the scan.
        let keys = [
            record("GNU.sparse.major", b"1"),
            record("GNU.sparse.minor", b"0"),
            record("GNU.sparse.realsize", b"1024"),
        ]
        .concat();
        let inner = record("GNU.sparse.name", b"usr/bin/perl");
        let value = [b"y\n".as_slice(), &keys, &inner[..inner.len() - 1]].concat();
        let map = blocks(b"1\n1024\n0\n");
        probe(
            &path,
            &[
                pax_header(&[record("comment", &value)]),
                raw_header(
                    b"usr/bin/GNUSparseFile.0/perl",
                    map.len(),
                    b'0',
                    "posix",
                    b"",
                ),
                map,
            ]
            .concat(),
        );
        let (_, members) = inspect_members(&path).unwrap();
        assert_eq!(
            members.get("usr/bin/GNUSparseFile.0/perl"),
            Some(&tar::EntryType::Regular)
        );
        assert!(!members.contains_key("usr/bin/perl"));
        std::fs::remove_file(&path).unwrap();
        probe(
            &path,
            &[
                pax_header(&[
                    record(
                        "SCHILY.xattr.security.capability",
                        b"\x01\0\0\x02\n\x20\n\n",
                    ),
                    record("path", b"usr/share/after-xattr"),
                ]),
                raw_file(b"usr/share/x", b"x"),
            ]
            .concat(),
        );
        let (_, members) = inspect_members(&path).unwrap();
        assert!(members.contains_key("usr/share/after-xattr"));
        std::fs::remove_file(&path).unwrap();
        // Blanks after the length, all skipped as GNU tar skips them.
        let record = b"  path=etc/dbl-space\n";
        let record = [format!("{}", record.len() + 2).as_bytes(), record].concat();
        probe(
            &path,
            &[
                raw_header(b"PaxHeaders/x", record.len(), b'x', "posix", b""),
                blocks(&record),
                raw_file(b"usr/share/plain2", b"c"),
            ]
            .concat(),
        );
        let (_, members) = inspect_members(&path).unwrap();
        assert!(members.contains_key("etc/dbl-space"));
        assert!(!members.contains_key("usr/share/plain2"));
        std::fs::remove_file(&path).unwrap();
        // A record whose length overruns the header, or lacks its newline.
        for records in [b"99 path=usr/x\n".to_vec(), b"14 path=usr/x!".to_vec()] {
            probe(
                &path,
                &[
                    raw_header(b"PaxHeaders/x", records.len(), b'x', "posix", b""),
                    blocks(&records),
                    raw_file(b"usr/x", b"x"),
                ]
                .concat(),
            );
            let error = inspect(&path).unwrap_err().to_string();
            assert!(error.contains("malformed record"), "{error}");
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn any_regular_member_is_read_as_gnu_tar_extracts_it() {
        let scratch = Scratch::new();
        let source = scratch.0.join("source");
        let files = sparse_root(&source);
        let plain = scratch.0.join("root.tar");
        gnu_tar(&source, &plain, &MMDEBSTRAP);
        let bytes = std::fs::read(&plain).unwrap();
        for (dir, base) in [("boot", "initrd.img-"), ("usr/bin", "zboot")] {
            assert!(
                stored_sparse(&bytes, dir, base),
                "GNU tar stored {dir}/{base} as sparse"
            );
        }
        let zstd = scratch.0.join("root.tar.zst");
        std::fs::write(
            &zstd,
            zstd::stream::encode_all(bytes.as_slice(), 1).unwrap(),
        )
        .unwrap();
        for path in [&plain, &zstd] {
            let admitted = inspect(path).unwrap();
            let copy = |member: &str| {
                let mut output = Vec::new();
                copy_member(
                    &admitted,
                    member,
                    || Ok(Box::new(File::open(path)?) as Box<dyn Read>),
                    &mut output,
                )
                .map(|size| {
                    assert_eq!(size, output.len() as u64);
                    output
                })
            };
            for (name, content) in &files {
                assert!(copy(name).unwrap() == *content, "{name}");
            }
            // A hardlink is read from the member it names.
            assert!(copy("usr/bin/perl5.44.0").unwrap() == files["usr/bin/perl"]);
            let error = copy("usr/bin/zsnap").unwrap_err().to_string();
            assert!(error.contains("not a regular file"), "{error}");
            let error = copy("usr/bin/absent").unwrap_err().to_string();
            assert!(error.contains("has no usr/bin/absent"), "{error}");
        }
    }
}
