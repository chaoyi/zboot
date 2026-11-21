//! One-boot remote requests. ESP contents are consumed before callers may start
//! networking. Invalid input is an ordinary-start diagnostic, never authority
//! to start SSH. File keys precede command-line keys; either source invalidates
//! the whole request. An empty consumed file still requests the temporary wait.
use crate::device::{self, PartitionIdentity};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

pub const MAX_KEY_FILE_BYTES: usize = 65_536;
const LOADER_VARIABLE: &str =
    "/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

fn refuse(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeys {
    authorized_keys: Vec<u8>,
    fingerprints: Vec<String>,
}
impl PublicKeys {
    pub fn authorized_keys(&self) -> &[u8] {
        &self.authorized_keys
    }
    pub fn fingerprints(&self) -> &[String] {
        &self.fingerprints
    }
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

/// Plain modern OpenSSH public lines with complete bounded public wire fields.
/// Options, certificates, unknown algorithms and private fields are refused.
pub fn parse_public_keys(bytes: &[u8]) -> io::Result<PublicKeys> {
    if bytes.len() > MAX_KEY_FILE_BYTES {
        return Err(refuse("authorized_keys exceeds 64 KiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(refuse)?;
    let mut result = PublicKeys {
        authorized_keys: Vec::new(),
        fingerprints: Vec::new(),
    };
    for line in text.lines() {
        if line.is_empty() || line.chars().any(|c| c.is_control() && c != '\t') {
            return Err(refuse(
                "authorized_keys requires only plain printable public key lines",
            ));
        }
        let mut fields = line.split_ascii_whitespace();
        let kind = fields.next().unwrap_or_default();
        let encoded = fields
            .next()
            .ok_or_else(|| refuse("public key lacks base64 material"))?;
        let decoded =
            decode_base64(encoded).ok_or_else(|| refuse("invalid canonical public key base64"))?;
        validate_wire(kind, &decoded)?;
        let fingerprint = format!(
            "SHA256:{}",
            encode_base64(&Sha256::digest(&decoded)).trim_end_matches('=')
        );
        if !result.fingerprints.contains(&fingerprint) {
            result
                .authorized_keys
                .extend_from_slice(format!("{kind} {encoded}\n").as_bytes());
            result.fingerprints.push(fingerprint);
        }
    }
    Ok(result)
}

pub fn keys_from_cmdline(cmdline: &str) -> io::Result<Option<PublicKeys>> {
    let mut lines = String::new();
    let mut found = false;
    for value in cmdline
        .split_ascii_whitespace()
        .filter_map(|word| word.strip_prefix("zboot.ssh_key="))
    {
        found = true;
        let (kind, encoded) = value
            .split_once(':')
            .ok_or_else(|| refuse("zboot.ssh_key requires TYPE:BASE64"))?;
        if lines
            .len()
            .saturating_add(kind.len())
            .saturating_add(encoded.len())
            .saturating_add(2)
            > MAX_KEY_FILE_BYTES
        {
            return Err(refuse("command-line public keys exceed 64 KiB"));
        }
        lines.push_str(kind);
        lines.push(' ');
        lines.push_str(encoded);
        lines.push('\n');
    }
    found
        .then(|| parse_public_keys(lines.as_bytes()))
        .transpose()
}

fn validate_wire(kind: &str, wire: &[u8]) -> io::Result<()> {
    let mut rest = wire;
    if ssh_string(&mut rest) != Some(kind.as_bytes()) {
        return Err(refuse("public key wire algorithm differs from its type"));
    }
    match kind {
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => {
            if ssh_string(&mut rest).is_none_or(|key| key.len() != 32) {
                return Err(refuse("public key has an invalid Ed25519 length"));
            }
        }
        "ssh-rsa" => {
            for _ in 0..2 {
                let integer =
                    ssh_string(&mut rest).ok_or_else(|| refuse("RSA key lacks public integers"))?;
                // Positive, minimally encoded SSH mpint; no private fields.
                if integer.is_empty()
                    || integer[0] & 0x80 != 0
                    || (integer[0] == 0 && (integer.len() == 1 || integer[1] & 0x80 == 0))
                {
                    return Err(refuse(
                        "RSA public integer is not canonical positive material",
                    ));
                }
            }
        }
        "ecdsa-sha2-nistp256"
        | "ecdsa-sha2-nistp384"
        | "ecdsa-sha2-nistp521"
        | "sk-ecdsa-sha2-nistp256@openssh.com" => {
            let (curve, bytes) = match kind {
                "ecdsa-sha2-nistp384" => ("nistp384", 97),
                "ecdsa-sha2-nistp521" => ("nistp521", 133),
                _ => ("nistp256", 65),
            };
            if ssh_string(&mut rest) != Some(curve.as_bytes())
                || ssh_string(&mut rest).is_none_or(|point| point.len() != bytes || point[0] != 4)
            {
                return Err(refuse("ECDSA curve or public point shape differs"));
            }
        }
        _ => {
            return Err(refuse(
                "unsupported plain OpenSSH public key type or key options",
            ));
        }
    }
    if kind.starts_with("sk-") {
        let application =
            ssh_string(&mut rest).ok_or_else(|| refuse("security key lacks application"))?;
        if !(4..=255).contains(&application.len())
            || !application.starts_with(b"ssh:")
            || application.iter().any(|byte| !(33..=126).contains(byte))
        {
            return Err(refuse("invalid security-key application"));
        }
    }
    if !rest.is_empty() {
        return Err(refuse("public key contains trailing wire fields"));
    }
    Ok(())
}

fn ssh_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let size = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let data = input.get(4..4usize.checked_add(size)?)?;
    *input = input.get(4 + size..)?;
    Some(data)
}

// The same canonical decoder used by the retired profile's strict validator.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let digit = |b| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut result = Vec::new();
    for (i, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let last = i + 1 == bytes.len() / 4;
        let padding = usize::from(chunk[3] == b'=') + usize::from(chunk[2] == b'=');
        if (padding != 0 && !last) || (chunk[2] == b'=' && chunk[3] != b'=') {
            return None;
        }
        let a = digit(chunk[0])?;
        let b = digit(chunk[1])?;
        let c = if padding == 2 { 0 } else { digit(chunk[2])? };
        let d = if padding != 0 { 0 } else { digit(chunk[3])? };
        if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
            return None;
        }
        result.push((a << 2) | (b >> 4));
        if padding < 2 {
            result.push((b << 4) | (c >> 2));
        }
        if padding == 0 {
            result.push((c << 6) | d);
        }
    }
    Some(result)
}
fn encode_base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(DIGITS[(a >> 2) as usize] as char);
        out.push(DIGITS[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            DIGITS[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            DIGITS[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn loader_uuid(bytes: &[u8]) -> io::Result<String> {
    // efivarfs prefixes the UTF16LE value with four attribute bytes.
    if bytes.len() != 4 + 2 * 37 {
        return Err(refuse("LoaderDevicePartUUID is not a bounded UTF16 UUID"));
    }
    let mut units = Vec::new();
    for pair in bytes[4..].as_chunks::<2>().0 {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    if units.pop() != Some(0) {
        return Err(refuse("LoaderDevicePartUUID lacks its terminator"));
    }
    let text = String::from_utf16(&units).map_err(refuse)?;
    let uuid = uuid::Uuid::parse_str(&text).map_err(refuse)?;
    if text.len() != 36 || !text.eq_ignore_ascii_case(&uuid.to_string()) {
        return Err(refuse("invalid loader partition UUID"));
    }
    Ok(uuid.to_string())
}

/// A non-volatile copy survives reboots, so it need not name this boot.
const EFI_VARIABLE_NON_VOLATILE: u32 = 1;
fn names_this_boot(bytes: &[u8]) -> bool {
    bytes
        .first_chunk::<4>()
        .is_some_and(|attributes| u32::from_le_bytes(*attributes) & EFI_VARIABLE_NON_VOLATILE == 0)
}

/// The raw LoaderDevicePartUUID variable, attribute bytes included.
fn loader_variable() -> io::Result<Option<Vec<u8>>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(LOADER_VARIABLE)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(refuse(
            "LoaderDevicePartUUID is not an efivarfs regular file",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(4 + 2 * 37 + 1).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

/// The PARTUUID of the ESP systemd-stub loaded this boot from. A non-volatile
/// variable may be left from an earlier boot and is not used.
pub(crate) fn loader_partuuid() -> io::Result<Option<String>> {
    match loader_variable()? {
        Some(bytes) if names_this_boot(&bytes) => loader_uuid(&bytes).map(Some),
        Some(bytes) => loader_uuid(&bytes).map(|_| None),
        None => Ok(None),
    }
}

/// Resolve only the systemd-stub-selected ESP, never a guessed boot partition.
pub fn loader_esp() -> io::Result<Option<PartitionIdentity>> {
    let Some(bytes) = loader_variable()? else {
        return Ok(None);
    };
    let uuid = loader_uuid(&bytes)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    resolve_loader_esp(
        Some(&uuid),
        || device::observe_landscape().map_err(refuse),
        |path| device::observe_partition(path).map_err(refuse),
        || {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            std::thread::sleep(remaining.min(Duration::from_millis(100)));
            true
        },
    )
}

fn resolve_loader_esp(
    uuid: Option<&str>,
    mut observe: impl FnMut() -> io::Result<device::Landscape>,
    mut inspect: impl FnMut(&str) -> io::Result<PartitionIdentity>,
    mut retry_missing: impl FnMut() -> bool,
) -> io::Result<Option<PartitionIdentity>> {
    let Some(uuid) = uuid else { return Ok(None) };
    // Resolve native PARTUUID facts, not aliases. A valid firmware UUID can
    // precede USB block enumeration; only absence permits the bounded wait.
    let path = loop {
        let landscape = observe()?;
        let mut pending: Vec<_> = landscape.blockdevices.iter().collect();
        let mut matches = std::collections::BTreeMap::new();
        while let Some(block) = pending.pop() {
            pending.extend(block.children.iter());
            if block.kind == "part"
                && block
                    .partuuid
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case(uuid))
            {
                matches.insert(block.device_number.clone(), block.path.clone());
            }
        }
        match matches.len() {
            0 if retry_missing() => continue,
            0 => {
                return Err(refuse(format!(
                    "the ESP this system booted from (PARTUUID {uuid}, from LoaderDevicePartUUID) \
                     is no longer present, for example after wipe or deploy rewrote that disk; \
                     reboot once, so the firmware loads zboot from a current ESP, and retry"
                )));
            }
            1 => break matches.into_values().next().unwrap(),
            _ => return Err(refuse("loader ESP PARTUUID is ambiguous")),
        }
    };
    let target = inspect(&path)?;
    if target
        .partition
        .partition_uuid
        .as_deref()
        .is_none_or(|actual| !actual.eq_ignore_ascii_case(uuid))
    {
        return Err(refuse("loader ESP PARTUUID changed during resolution"));
    }
    crate::esp::validate_target(&target)?;
    Ok(Some(target))
}

pub(crate) fn open_directory(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
}
pub(crate) fn key_directory(root: &File) -> io::Result<File> {
    Ok(crate::openat2_scoped(
        root,
        "zboot",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?
    .into())
}
fn open_key(directory: &File) -> io::Result<File> {
    Ok(crate::openat2_scoped(
        directory,
        "authorized_keys",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?
    .into())
}
fn request_present_at(root: &Path) -> io::Result<bool> {
    let root = open_directory(root)?;
    let result = key_directory(&root).and_then(|directory| open_key(&directory));
    match result {
        Ok(file) if file.metadata()?.is_file() => Ok(true),
        Ok(_) => Err(refuse("authorized_keys is not a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
fn consume_at(
    root: &Path,
    delete: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<Option<PublicKeys>> {
    let root = open_directory(root)?;
    let directory = match key_directory(&root) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut file = match open_key(&directory) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(refuse("authorized_keys is not a regular file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_KEY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let held = open_key(&directory)?.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || held.dev() != before.dev()
        || held.ino() != before.ino()
    {
        return Err(refuse("authorized_keys changed while being consumed"));
    }
    // Consume even malformed/oversized contents. No keys escape this function
    // until deletion and durable filesystem sync both succeed.
    delete(&directory)?;
    if file.metadata()?.nlink() != 0 {
        return Err(refuse(
            "authorized_keys inode was not unlinked; no SSH request consumed",
        ));
    }
    directory.sync_all()?;
    rustix::fs::syncfs(&directory).map_err(refuse)?;
    parse_public_keys(&bytes).map(Some)
}

/// Consume the loader ESP before interpreting command-line keys. The mounting
/// helper verifies the partition before/after and unmounts before this returns.
pub fn consume_startup() -> io::Result<Option<PublicKeys>> {
    let from_file = match loader_esp()? {
        Some(target) => {
            let present = crate::esp::mounted(&target, false, request_present_at)?;
            if present {
                crate::esp::mounted(&target, true, |root| {
                    consume_at(root, |directory| {
                        zfs_tools::engine::effect::mark();
                        rustix::fs::unlinkat(
                            directory,
                            "authorized_keys",
                            rustix::fs::AtFlags::empty(),
                        )
                        .map_err(io::Error::from)
                    })
                })?
            } else {
                None
            }
        }
        None => None,
    };
    if from_file.is_some() {
        println!("One-boot ESP remote request deleted and synced before networking.");
    }
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    let from_cmdline = keys_from_cmdline(&cmdline)?;
    match (from_file, from_cmdline) {
        (None, None) => Ok(None),
        (Some(keys), None) | (None, Some(keys)) => Ok(Some(keys)),
        (Some(mut file), Some(command)) => {
            file.authorized_keys.extend(command.authorized_keys);
            // Bound the combined authority, preserving file-before-cmdline order.
            parse_public_keys(&file.authorized_keys).map(Some)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> String {
        let mut wire = Vec::new();
        wire.extend(11u32.to_be_bytes());
        wire.extend(b"ssh-ed25519");
        wire.extend(32u32.to_be_bytes());
        wire.extend([7; 32]);
        format!("ssh-ed25519 {}", encode_base64(&wire))
    }
    fn scratch() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("zboot-remote-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(p.join("zboot")).unwrap();
        p
    }
    #[test]
    fn only_plain_public_key_lines_are_accepted_and_the_read_is_bounded() {
        let key = key();
        let keys = parse_public_keys(format!("{key} comment\n{key}\n").as_bytes()).unwrap();
        assert_eq!(keys.authorized_keys(), format!("{key}\n").as_bytes());
        assert_eq!(keys.fingerprints().len(), 1);
        assert_eq!(
            parse_public_keys(format!("{key} opérateur\n").as_bytes()).unwrap(),
            keys
        );
        for bad in [
            format!("command=sh {key}\n"),
            format!("no-touch-required {key}\n"),
            "ssh-ed25519 AAAA\n".into(),
            format!("{key}\ninvalid\n"),
            format!("{key}\0\n"),
        ] {
            assert!(parse_public_keys(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let exact = format!("{key} {}\n", "x".repeat(MAX_KEY_FILE_BYTES - key.len() - 2));
        assert_eq!(exact.len(), MAX_KEY_FILE_BYTES);
        parse_public_keys(exact.as_bytes()).unwrap();
        assert!(parse_public_keys(format!("{exact}x").as_bytes()).is_err());
        assert!(keys_from_cmdline("zboot.ssh_key=ssh-ed25519:AAAA").is_err());
        let command = key.replace(' ', ":");
        assert_eq!(
            keys_from_cmdline(&format!(
                "quiet zboot.ssh_key={command} zboot.ssh_key={command}"
            ))
            .unwrap()
            .unwrap(),
            keys
        );
    }
    fn wire_line(kind: &str, fields: &[&[u8]]) -> String {
        let mut wire = Vec::new();
        for field in std::iter::once(kind.as_bytes()).chain(fields.iter().copied()) {
            wire.extend((field.len() as u32).to_be_bytes());
            wire.extend(field);
        }
        format!("{kind} {}\n", encode_base64(&wire))
    }
    #[test]
    fn modern_public_key_types_require_complete_matching_wire_fields() {
        let exponent = [1, 0, 1];
        let modulus = [0, 0x80, 1];
        let rsa = wire_line("ssh-rsa", &[&exponent, &modulus]);
        parse_public_keys(rsa.as_bytes()).unwrap();
        for (kind, curve, size) in [
            ("ecdsa-sha2-nistp256", "nistp256", 65),
            ("ecdsa-sha2-nistp384", "nistp384", 97),
            ("ecdsa-sha2-nistp521", "nistp521", 133),
            ("sk-ecdsa-sha2-nistp256@openssh.com", "nistp256", 65),
        ] {
            let mut point = vec![1; size];
            point[0] = 4;
            let mut fields = vec![curve.as_bytes(), point.as_slice()];
            if kind.starts_with("sk-") {
                fields.push(b"ssh:test");
            }
            // These are wire-shape fixtures, not claims of cryptographic keys.
            let line = wire_line(kind, &fields);
            parse_public_keys(line.as_bytes()).unwrap();
            assert!(parse_public_keys(line.replacen(kind, "ssh-ed25519", 1).as_bytes()).is_err());
            fields.push(b"private");
            assert!(parse_public_keys(wire_line(kind, &fields).as_bytes()).is_err());
        }
        let key = [7; 32];
        parse_public_keys(wire_line("sk-ssh-ed25519@openssh.com", &[&key, b"ssh:test"]).as_bytes())
            .unwrap();
        assert!(parse_public_keys(wire_line("ssh-rsa", &[&[0, 1], &modulus]).as_bytes()).is_err());
        assert!(parse_public_keys(wire_line("ssh-dss", &[&key]).as_bytes()).is_err());
        assert!(
            parse_public_keys(wire_line("ssh-ed25519-cert-v01@openssh.com", &[&key]).as_bytes())
                .is_err()
        );
    }
    #[test]
    fn the_key_file_is_deleted_and_synced_before_network_or_ssh_start() {
        let root = scratch();
        std::fs::write(root.join("zboot/authorized_keys"), key()).unwrap();
        let keys = consume_at(&root, |dir| {
            rustix::fs::unlinkat(dir, "authorized_keys", rustix::fs::AtFlags::empty())
                .map_err(io::Error::from)
        })
        .unwrap()
        .unwrap();
        assert!(!keys.is_empty());
        assert!(!root.join("zboot/authorized_keys").exists());
        // The network caller receives keys only after the real sync calls return.
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_key_file_that_cannot_be_deleted_starts_no_ssh() {
        let root = scratch();
        std::fs::write(root.join("zboot/authorized_keys"), key()).unwrap();
        assert!(
            consume_at(&root, |_| Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "delete refused"
            )))
            .is_err()
        );
        assert!(root.join("zboot/authorized_keys").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn an_empty_key_file_gives_the_wait_without_ssh() {
        let root = scratch();
        std::fs::write(root.join("zboot/authorized_keys"), b"").unwrap();
        assert!(
            consume_at(&root, |dir| rustix::fs::unlinkat(
                dir,
                "authorized_keys",
                rustix::fs::AtFlags::empty()
            )
            .map_err(io::Error::from))
            .unwrap()
            .unwrap()
            .is_empty()
        );
        std::fs::write(root.join("zboot/authorized_keys"), b"invalid").unwrap();
        assert!(
            consume_at(&root, |dir| rustix::fs::unlinkat(
                dir,
                "authorized_keys",
                rustix::fs::AtFlags::empty()
            )
            .map_err(io::Error::from))
            .is_err()
        );
        assert!(!root.join("zboot/authorized_keys").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn absent_requests_are_ordinary_and_oversized_requests_are_consumed() {
        let root = scratch();
        assert!(!request_present_at(&root).unwrap());
        assert!(
            consume_at(&root, |_| panic!("absent request must not delete"))
                .unwrap()
                .is_none()
        );
        std::fs::write(
            root.join("zboot/authorized_keys"),
            vec![b'x'; MAX_KEY_FILE_BYTES + 100],
        )
        .unwrap();
        assert!(request_present_at(&root).unwrap());
        assert!(
            consume_at(&root, |dir| rustix::fs::unlinkat(
                dir,
                "authorized_keys",
                rustix::fs::AtFlags::empty()
            )
            .map_err(io::Error::from))
            .is_err()
        );
        assert!(!root.join("zboot/authorized_keys").exists());
        std::fs::remove_dir(root.join("zboot")).unwrap();
        assert!(!request_present_at(&root).unwrap());
        assert!(
            consume_at(&root, |_| panic!("absent ancestor must not delete"))
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn key_consumption_refuses_symlink_files_and_ancestors() {
        let root = scratch();
        std::os::unix::fs::symlink("/etc/passwd", root.join("zboot/authorized_keys")).unwrap();
        assert!(request_present_at(&root).is_err());
        assert!(consume_at(&root, |_| panic!("must not delete")).is_err());
        std::fs::remove_dir_all(root.join("zboot")).unwrap();
        std::os::unix::fs::symlink("/temp", root.join("zboot")).unwrap();
        assert!(consume_at(&root, |_| panic!("must not delete")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    fn loader_landscape(parts: &[(&str, &str)]) -> device::Landscape {
        device::parse_landscape(&serde_json::json!({"blockdevices": parts.iter().map(|(path, number)| serde_json::json!({
            "path": path, "maj:min": number, "type": "part", "size": 512 << 20,
            "log-sec": 512, "phy-sec": 512, "ro": false,
            "partuuid": "12345678-1234-1234-1234-123456789abc", "mountpoints": [],
        })).collect::<Vec<_>>()}).to_string()).unwrap()
    }
    fn loader_target() -> PartitionIdentity {
        PartitionIdentity {
            disk: device::DiskIdentity {
                path: "/dev/sda".into(),
                device_number: "8:0".into(),
                sysfs_path: "/sys/devices/test/usb/block/sda".into(),
                bytes: 8 << 30,
                logical_sector: 512,
                physical_sector: 512,
                serial: Some("test-usb".into()),
                wwn: None,
                model: None,
            },
            partition: device::Partition {
                path: "/dev/sda1".into(),
                device_number: "8:1".into(),
                bytes: 512 << 20,
                partition_uuid: Some("12345678-1234-1234-1234-123456789abc".into()),
                filesystem: Some("vfat".into()),
                filesystem_uuid: Some("1234-5678".into()),
                filesystem_label: None,
            },
            number: 1,
            partition_type: Some("c12a7328-f81f-11d2-ba4b-00a0c93ec93b".into()),
            readonly: false,
        }
    }
    #[test]
    fn loader_esp_waits_only_for_missing_native_hardware() {
        let mut observations = 0;
        let mut waits = 0;
        let expected = loader_target();
        let result = resolve_loader_esp(
            Some("12345678-1234-1234-1234-123456789abc"),
            || {
                observations += 1;
                Ok(if observations == 1 {
                    loader_landscape(&[])
                } else {
                    loader_landscape(&[("/dev/sda1", "8:1")])
                })
            },
            |path| {
                assert_eq!(path, "/dev/sda1");
                Ok(expected.clone())
            },
            || {
                waits += 1;
                true
            },
        )
        .unwrap();
        assert_eq!(result, Some(expected));
        assert_eq!((observations, waits), (2, 1));
    }
    #[test]
    fn loader_esp_ambiguity_refuses_without_retry_or_target_admission() {
        let result = resolve_loader_esp(
            Some("12345678-1234-1234-1234-123456789abc"),
            || {
                Ok(loader_landscape(&[
                    ("/dev/sda1", "8:1"),
                    ("/dev/sdb1", "8:17"),
                ]))
            },
            |_| panic!("ambiguous target must not be inspected"),
            || panic!("ambiguous UUID must not wait"),
        );
        assert!(result.unwrap_err().to_string().contains("ambiguous"));
    }
    #[test]
    fn loader_esp_missing_hardware_exhausts_its_retry_bound() {
        let mut observations = 0;
        let mut waits = 0;
        let result = resolve_loader_esp(
            Some("12345678-1234-1234-1234-123456789abc"),
            || {
                observations += 1;
                Ok(loader_landscape(&[]))
            },
            |_| panic!("absent target must not be inspected"),
            || {
                waits += 1;
                waits < 3
            },
        );
        let message = result.unwrap_err().to_string();
        assert!(
            message.starts_with(
                "the ESP this system booted from \
                 (PARTUUID 12345678-1234-1234-1234-123456789abc, from LoaderDevicePartUUID) \
                 is no longer present"
            ) && message.ends_with(
                "reboot once, so the firmware loads zboot from a current ESP, and retry"
            ),
            "{message}"
        );
        assert_eq!((observations, waits), (3, 3));
    }
    #[test]
    fn absent_loader_variable_is_ordinary_without_inventory_or_wait() {
        assert_eq!(
            resolve_loader_esp(
                None,
                || panic!("absent firmware variable must not probe storage"),
                |_| panic!("absent firmware variable must not inspect a target"),
                || panic!("absent firmware variable must not wait")
            )
            .unwrap(),
            None
        );
    }
    #[test]
    fn loader_variable_requires_exact_bounded_utf16_partition_uuid() {
        let uuid = "12345678-1234-1234-1234-123456789abc";
        let mut bytes = vec![7, 0, 0, 0];
        for unit in uuid.encode_utf16().chain([0]) {
            bytes.extend(unit.to_le_bytes());
        }
        assert_eq!(loader_uuid(&bytes).unwrap(), uuid);
        // systemd-stub sets it volatile (06); a non-volatile copy (07) can be stale.
        assert!(!names_this_boot(&bytes));
        bytes[0] = 6;
        assert!(names_this_boot(&bytes));
        bytes.push(0);
        assert!(loader_uuid(&bytes).is_err());
        assert!(loader_uuid(&bytes[..bytes.len() - 3]).is_err());
    }
}
