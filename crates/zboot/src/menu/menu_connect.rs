//! Wired, ephemeral SSH in the RAM Menu. The supervisor owns the listener,
//! authentication evidence and lease independently of a blocked console.

use super::{RecoveryError, Result, refuse};
use crate::handoff::{prove_ram, readonly_pools};
use crate::remote_access::PublicKeys;
use nix::mount::{MsFlags, mount};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::fd::OwnedFd,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        net::UnixDatagram,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};
use zfs_tools::engine::state;

mod custody;

const WORK: &str = "/run/zboot-connect";
const PASSWORD_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const MAX_LOG_LINE: usize = 4096;
const MAX_LOG_BATCH: usize = 65_536;
const MAX_LOG_HISTORY_INPUT: usize = 256 * 1024;
const MAX_LOG_HISTORY_ENCODED: usize = 2 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
// LogVerbose adds OpenSSH's own source/function/bin/PID prefix. Plain -e
// messages contain no PID. These selected sites are from openssh-portable
// log.c:sshlogv, auth.c:auth_log, session.c:do_exec/session_close and packet.c.
// Never substring-match remote-controlled diagnostic text as authentication.
const LOG_VERBOSE: &str = "auth.c:auth_log():*,session.c:do_exec():*,session.c:session_close():*,packet.c:sshpkt_vfatal():*,serverloop.c:process_input():*,serverloop.c:client_alive_check():*,serverloop.c:wait_until_can_do_something():*,sshd-session.c:privsep_postauth():*,sshd-session.c:main():*";
static SSHD: OnceLock<Mutex<Manager>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Event {
    Authenticated,
    SessionEnded,
    Stopped,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum PollError {
    #[error("{0}")]
    Service(RecoveryError),
    #[error("{0}")]
    Cleanup(RecoveryError),
}

#[derive(Default)]
struct Manager {
    session: Option<SshSession>,
    events: VecDeque<Event>,
    failure: Option<PollError>,
    cleanup_failed: bool,
    recovered: bool,
    /// The live session's console lines: address, host key words and
    /// fingerprint, and the admitted keys. The menu repeats them last.
    banner: Vec<String>,
}
impl Manager {
    fn queue(&mut self, event: Event) -> Result<()> {
        // Coalesce levels, retaining authentication-since-poll. An end is
        // global (the tracked set is empty), never an individual peer's end.
        // A later authentication cancels a pending end while retaining the
        // sticky authentication event. At most three events can accumulate
        // while the canonical console or a foreground command is blocked.
        if event == Event::Authenticated {
            self.events.retain(|e| *e != Event::SessionEnded);
        }
        if !self.events.contains(&event) {
            self.events.push_back(event);
        }
        Ok(())
    }

    fn cleaned(&mut self, result: Result<()>) -> Result<()> {
        if let Err(error) = &result {
            self.cleanup_failed = true;
            self.failure = Some(PollError::Cleanup(refuse(error.to_string())));
        }
        result
    }

    fn stopped(&mut self, cleanup: Result<()>) -> Result<()> {
        self.cleaned(cleanup)?;
        self.queue(Event::Stopped)
    }

    fn require_cleaned(&self) -> Result<()> {
        if self.cleanup_failed {
            Err(refuse(
                "Menu SSH cleanup previously failed; custody is not proven closed",
            ))
        } else {
            Ok(())
        }
    }

    fn poll(&mut self) -> std::result::Result<Vec<Event>, PollError> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.require_cleaned().map_err(PollError::Cleanup)?;
        Ok(self.events.drain(..).collect())
    }
}

struct SshSession {
    custody: custody::Owned,
    stderr: UnixDatagram,
    evidence: File,
    evidence_state: EvidenceState,
    log: LogState,
    iface: String,
    deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lease {
    address: Ipv4Addr,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    session_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Peer {
    address: IpAddr,
    port: u16,
}
#[derive(Default)]
struct Connection {
    // Authentication runs in the privileged monitor; the session may run in
    // another process. A trusted start record binds that PID to this peer.
    pids: BTreeSet<u32>,
    sessions: BTreeSet<(u32, u32)>,
}
#[derive(Default)]
struct LoginLog {
    connections: BTreeMap<Peer, Connection>,
    // Lost inventory precision can extend a hold only until the bounded lease.
    overflow: bool,
}

#[derive(Default)]
struct LogState {
    log: LoginLog,
    password_live: bool,
}
impl LogState {
    fn record(
        &mut self,
        bytes: &[u8],
        mut retire: impl FnMut() -> Result<()>,
    ) -> Result<Option<Event>> {
        if bytes.len() > MAX_LOG_LINE {
            return Ok(None);
        }
        let Some(line) = bytes.strip_suffix(b"\r\n") else {
            return Ok(None);
        };
        // OpenSSH preserves embedded newlines in stderr diagnostics. Its one
        // write per record is received as one datagram, so remote text cannot
        // create a second trusted record by injecting CR/LF or a fake prefix.
        let event = self.log.line(line)?;
        if event == Some(Event::Authenticated) && self.password_live {
            retire()?;
            self.password_live = false;
        }
        Ok(event)
    }
}

fn canonical_number<T: std::str::FromStr + ToString>(s: &str) -> Option<T> {
    let value = s.parse::<T>().ok()?;
    (value.to_string() == s).then_some(value)
}

fn peer(s: &str) -> Option<(Peer, &str)> {
    let (address, rest) = s.split_once(" port ")?;
    let address = canonical_number::<IpAddr>(address)?;
    let (port, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let port = canonical_number::<u16>(port)?;
    (port != 0).then_some((Peer { address, port }, rest))
}

// The complete trusted prefix must start the line, including the known source
// function. The datagram reader removes the terminal CRLF; embedded controls
// invalidate the entire record.
fn log_record(line: &[u8]) -> Option<(&str, u32, &str)> {
    let line = std::str::from_utf8(line).ok()?;
    if !line.bytes().all(|c| (32..=126).contains(&c)) {
        return None;
    }
    let (site, rest) = line.split_once("():")?;
    if !matches!(
        site,
        "auth.c:auth_log"
            | "session.c:do_exec"
            | "session.c:session_close"
            | "packet.c:sshpkt_vfatal"
            | "serverloop.c:process_input"
            | "serverloop.c:client_alive_check"
            | "serverloop.c:wait_until_can_do_something"
            | "sshd-session.c:privsep_postauth"
            | "sshd-session.c:main"
    ) {
        return None;
    }
    let (number, rest) = rest.split_once(" (bin=")?;
    canonical_number::<u32>(number)?;
    let (binary, rest) = rest.split_once(", pid=")?;
    if !matches!(binary, "sshd" | "sshd-auth" | "sshd-session") {
        return None;
    }
    let (pid, message) = rest.split_once("): ")?;
    let pid = canonical_number::<u32>(pid)?;
    (pid != 0).then_some((site, pid, message))
}

impl LoginLog {
    fn line(&mut self, line: &[u8]) -> Result<Option<Event>> {
        let Some((site, pid, message)) = log_record(line) else {
            return Ok(None);
        };
        if site == "auth.c:auth_log" {
            let rest = message
                .strip_prefix("Accepted publickey for root from ")
                .or_else(|| message.strip_prefix("Accepted password for root from "));
            let Some((peer, suffix)) = rest.and_then(peer) else {
                return Ok(None);
            };
            if suffix != "ssh2" && !suffix.starts_with("ssh2: ") {
                return Ok(None);
            }
            if self.connections.contains_key(&peer) || self.connections.len() >= MAX_CONNECTIONS {
                self.overflow = true;
                return Ok(Some(Event::Authenticated));
            }
            let mut connection = Connection::default();
            connection.pids.insert(pid);
            self.connections.insert(peer, connection);
            return Ok(Some(Event::Authenticated));
        }
        if site == "sshd-session.c:privsep_postauth" {
            let Some(child) = message
                .strip_prefix("User child is on pid ")
                .and_then(canonical_number::<u32>)
            else {
                return Ok(None);
            };
            if child == 0 {
                return Ok(None);
            }
            // OpenSSH's privileged monitor (the Accepted PID) explicitly
            // names its post-auth child, even for `ssh -N` with no shell.
            for connection in self.connections.values_mut() {
                if connection.pids.contains(&pid) {
                    if connection.pids.len() >= 16 {
                        self.overflow = true;
                        break;
                    }
                    connection.pids.insert(child);
                    break;
                }
            }
            return Ok(None);
        }
        if site == "session.c:do_exec" {
            let Some(rest) = message.strip_prefix("Starting session: ") else {
                return Ok(None);
            };
            // The command text is not logged here; even so parse the peer only
            // after the final exact root delimiter, never a contained Accepted.
            let Some((_, rest)) = rest.rsplit_once(" for root from ") else {
                return Ok(None);
            };
            let Some((peer, suffix)) = peer(rest) else {
                return Ok(None);
            };
            let Some(id) = suffix.strip_prefix("id ").and_then(canonical_number::<u32>) else {
                return Ok(None);
            };
            if let Some(connection) = self.connections.get_mut(&peer) {
                if connection.sessions.len() >= 16 || connection.pids.len() >= 16 {
                    self.overflow = true;
                    return Ok(None);
                }
                connection.pids.insert(pid);
                connection.sessions.insert((pid, id));
            }
            return Ok(None);
        }
        if site == "session.c:session_close" {
            let Some((peer, suffix)) = message
                .strip_prefix("Close session: user root from ")
                .and_then(peer)
            else {
                return Ok(None);
            };
            let Some(id) = suffix.strip_prefix("id ").and_then(canonical_number::<u32>) else {
                return Ok(None);
            };
            if let Some(connection) = self.connections.get_mut(&peer)
                && connection.sessions.remove(&(pid, id))
                && connection.sessions.is_empty()
            {
                self.connections.remove(&peer);
                return Ok(
                    (self.connections.is_empty() && !self.overflow).then_some(Event::SessionEnded)
                );
            }
            return Ok(None);
        }
        // A failed or unauthenticated connection cannot retire another peer.
        // Disconnect reasons contain client text, so none of that suffix is
        // interpreted. Only source-tagged server-generated endpoint records.
        // These exact sites/messages are from pinned OpenSSH V10.2
        // serverloop.c and packet.c. remote_id's root preamble is server-owned;
        // read-error text after the endpoint is ignored, never re-parsed.
        let endpoint = match site {
            "serverloop.c:client_alive_check" => message
                .strip_prefix("Timeout, client not responding from user root ")
                .and_then(peer)
                .filter(|(_, suffix)| suffix.is_empty()),
            "serverloop.c:wait_until_can_do_something" => message
                .strip_prefix("terminating inactive connection from user root ")
                .and_then(peer)
                .filter(|(_, suffix)| suffix.is_empty()),
            "serverloop.c:process_input" => message
                .strip_prefix("Read error from remote host ")
                .and_then(|rest| rest.split_once(": "))
                .and_then(|(endpoint, _)| peer(endpoint))
                .filter(|(_, suffix)| suffix.is_empty())
                .or_else(|| {
                    message
                        .strip_prefix("Connection closed by ")
                        .and_then(peer)
                        .filter(|(_, suffix)| suffix.is_empty())
                }),
            "packet.c:sshpkt_vfatal" => message
                .strip_prefix("Connection from user root ")
                .and_then(|rest| rest.strip_suffix(" timed out"))
                .and_then(peer)
                .filter(|(_, suffix)| suffix.is_empty())
                .or_else(|| {
                    [
                        "Disconnected from user root ",
                        "Connection closed by user root ",
                        "Connection reset by user root ",
                    ]
                    .iter()
                    .find_map(|prefix| message.strip_prefix(prefix))
                    .and_then(peer)
                    .filter(|(_, suffix)| suffix.is_empty())
                }),
            "sshd-session.c:main" => message
                .strip_prefix("Closing connection to ")
                .and_then(peer)
                .filter(|(_, suffix)| suffix.is_empty()),
            _ => None,
        };
        let Some((peer, _)) = endpoint else {
            return Ok(None);
        };
        if self
            .connections
            .get(&peer)
            .is_some_and(|c| c.pids.contains(&pid))
        {
            self.connections.remove(&peer);
            return Ok(
                (self.connections.is_empty() && !self.overflow).then_some(Event::SessionEnded)
            );
        }
        Ok(None)
    }
}

pub(super) fn available() -> bool {
    custody::available()
        && [
            "/usr/sbin/sshd",
            "/usr/bin/ssh-keygen",
            "/bin/ip",
            "/bin/busybox",
            "/usr/bin/udevadm",
            "/usr/lib/zboot/menu-dhcp.sh",
        ]
        .iter()
        .all(|p| Path::new(p).try_exists().unwrap_or(false))
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output =
        zfs_tools::engine::native::announced(Command::new(program).args(args).env("LC_ALL", "C"))
            .output()?;
    if !output.status.success() {
        return Err(refuse(format!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if output.stdout.len() > 4096 || output.stderr.len() > 4096 {
        return Err(refuse("Menu connect command output exceeds bound"));
    }
    String::from_utf8(output.stdout).map_err(|_| refuse("Menu connect output is not UTF-8"))
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// How long a freshly raised link may take to report carrier. A USB
/// gigabit adapter (r8152, say) negotiates for a few seconds after its first
/// `ip link set up`, which is when keyed Menu SSH starts at boot.
const CARRIER_WAIT: Duration = Duration::from_secs(10);
/// Once one link has carrier, how much longer others get, so that two
/// connected links still refuse as ambiguous.
const CARRIER_SETTLE: Duration = Duration::from_secs(1);

fn sole_carrier_wired(root: &Path, bring_up: impl FnMut(&str) -> Result<()>) -> Result<String> {
    sole_carrier_wired_within(root, bring_up, CARRIER_WAIT, CARRIER_SETTLE)
}

fn sole_carrier_wired_within(
    root: &Path,
    mut bring_up: impl FnMut(&str) -> Result<()>,
    wait: Duration,
    settle: Duration,
) -> Result<String> {
    let mut candidates = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(root)? {
        count += 1;
        if count > 128 {
            return Err(refuse("network interface inventory exceeds bound"));
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| refuse("invalid interface name"))?;
        if !valid_interface(&name) {
            return Err(refuse("invalid interface name"));
        }
        let path = entry.path();
        if !path.join("device").exists()
            || path.join("wireless").exists()
            || fs::read_to_string(path.join("type"))?.trim() != "1"
        {
            continue;
        }
        if candidates.len() >= 8 {
            return Err(refuse("too many physical wired interfaces"));
        }
        bring_up(&name)?;
        candidates.push((name, path));
    }
    // Every candidate negotiates at once; poll until one has carrier and
    // the others have had `settle` more, or until `wait` runs out.
    let start = Instant::now();
    let mut first = None;
    loop {
        let mut up = Vec::new();
        for (name, path) in &candidates {
            if fs::read_to_string(path.join("carrier"))?.trim() == "1" {
                up.push(name.clone());
            }
        }
        if up.len() > 1 {
            return Err(refuse(
                "multiple carrier-present wired interfaces; connect refuses ambiguity",
            ));
        }
        let now = Instant::now();
        if !up.is_empty() {
            let seen = *first.get_or_insert(now);
            if now.duration_since(seen) >= settle || up.len() == candidates.len() {
                return Ok(up.remove(0));
            }
        }
        if now.duration_since(start) >= wait {
            return up
                .pop()
                .ok_or_else(|| refuse("no carrier-present wired interface"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn disable_ipv6(iface: &str) -> Result<()> {
    // The Menu uses only the validated IPv4 lease. Prevent router
    // advertisements from adding an unrelated route when the link comes up.
    let path = Path::new("/proc/sys/net/ipv6/conf")
        .join(iface)
        .join("disable_ipv6");
    if path.exists() {
        fs::write(path, b"1\n")?;
    }
    Ok(())
}

fn dhcp_lease(work: &Path, iface: &str, custody: &custody::Owned) -> Result<Lease> {
    let lease = work.join("dhcp-lease");
    match fs::remove_file(&lease) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // The fixed callback records only interface, address, netmask, router and
    // lease lifetime in RAM. DNS, other routes, domains and hooks are ignored.
    let mut command = Command::new("/bin/busybox");
    command
        .args([
            "udhcpc",
            "-f",
            "-n",
            "-q",
            "-o",
            "-O",
            "subnet",
            "-O",
            "router",
            "-O",
            "lease",
            "-t",
            "3",
            "-T",
            "3",
            "-i",
            iface,
            "-s",
            "/usr/lib/zboot/menu-dhcp.sh",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Foreground -q exits after obtaining the lease; no renewal daemon is
    // retained. Its callback and any forked children share SSH's owned leaf.
    custody.admit(&mut command)?;
    let mut child = zfs_tools::engine::native::announced(&mut command).spawn()?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(20) {
            child.kill()?;
            child.wait()?;
            return Err(refuse("wired DHCP lease timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !status.success() {
        return Err(refuse("wired DHCP lease was not obtained"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lease)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.len() > 128 {
        return Err(refuse("wired DHCP lease record is not private RAM data"));
    }
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes)?;
    parse_lease(&bytes, iface)
}

fn parse_lease(bytes: &[u8], iface: &str) -> Result<Lease> {
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("wired DHCP lease is not UTF-8"))?;
    let lines: Vec<_> = text
        .strip_suffix('\n')
        .ok_or_else(|| refuse("wired DHCP lease is incomplete"))?
        .split('\n')
        .collect();
    if lines.len() != 5 || lines[0] != iface {
        return Err(refuse("wired DHCP lease interface changed"));
    }
    let address = lines[1]
        .parse::<Ipv4Addr>()
        .map_err(|_| refuse("invalid DHCP IPv4 address"))?;
    let mask = lines[2]
        .parse::<Ipv4Addr>()
        .map_err(|_| refuse("invalid DHCP IPv4 netmask"))?;
    if address.to_string() != lines[1]
        || mask.to_string() != lines[2]
        || address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_link_local()
    {
        return Err(refuse("DHCP lease address is not usable"));
    }
    let bits = u32::from(mask);
    let prefix = bits.leading_ones() as u8;
    if !(1..=32).contains(&prefix) || bits != u32::MAX << (32 - prefix) {
        return Err(refuse("DHCP lease netmask is not contiguous"));
    }
    let network = u32::from(address) & bits;
    if prefix < 31 && (u32::from(address) == network || u32::from(address) == network | !bits) {
        return Err(refuse("DHCP lease selected network or broadcast address"));
    }
    // A controller on another provision subnet needs this one default route.
    // A list of gateways, an off-link gateway or a second route is refused.
    // A lease with no router serves its own subnet only.
    let gateway = if lines[3].is_empty() {
        None
    } else {
        let gateway = lines[3]
            .parse::<Ipv4Addr>()
            .map_err(|_| refuse("DHCP lease offers more than one IPv4 router"))?;
        let gateway_bits = u32::from(gateway);
        if gateway.to_string() != lines[3]
            || gateway.is_unspecified()
            || gateway.is_loopback()
            || gateway.is_multicast()
            || gateway.is_broadcast()
            || gateway.is_link_local()
            || gateway == address
            || gateway_bits & bits != network
            || (prefix < 31 && (gateway_bits == network || gateway_bits == network | !bits))
        {
            return Err(refuse("DHCP router is not one usable on-link gateway"));
        }
        Some(gateway)
    };
    let lifetime = lines[4]
        .parse::<u32>()
        .map_err(|_| refuse("DHCP lease lifetime is invalid"))?;
    if lifetime.to_string() != lines[4] || lifetime < 120 {
        return Err(refuse("DHCP lease lifetime is too short or noncanonical"));
    }
    // No renewal daemon runs in the small Menu. End SSH well before expiry,
    // with an absolute bound even if a server grants a very long lease.
    Ok(Lease {
        address,
        prefix,
        gateway,
        session_seconds: (lifetime / 2).min(6 * 60 * 60),
    })
}

fn recorded_interface() -> Result<Option<String>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(WORK).join("network-interface"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 15
    {
        return Err(refuse(
            "Menu SSH lease interface is not a private bounded RAM file",
        ));
    }
    let mut interface = String::new();
    file.take(16).read_to_string(&mut interface)?;
    if !valid_interface(&interface) {
        return Err(refuse("Menu SSH lease interface is invalid"));
    }
    Ok(Some(interface))
}

fn parse_ifindex(value: &str) -> Result<u32> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    canonical_number::<u32>(value)
        .filter(|index| *index != 0)
        .ok_or_else(|| refuse("Menu SSH interface index is invalid"))
}

fn interface_index(iface: &str) -> Result<Option<u32>> {
    let path = Path::new("/sys/class/net").join(iface).join("ifindex");
    match fs::read_to_string(path) {
        Ok(value) => parse_ifindex(&value).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn recorded_ifindex(iface: &str) -> Result<Option<u32>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(WORK).join("network-ifindex"))
    {
        Ok(file) => file,
        // Existing name-only RAM records remain readable. New activations
        // record the chosen device index before any DHCP/address effect.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 32
    {
        return Err(refuse(
            "Menu SSH interface index is not a private bounded RAM file",
        ));
    }
    let mut value = String::new();
    file.take(33).read_to_string(&mut value)?;
    let (name, index) = value
        .split_once('\n')
        .ok_or_else(|| refuse("Menu SSH interface index record is invalid"))?;
    if name != iface || !valid_interface(name) {
        return Err(refuse("Menu SSH interface index names another device"));
    }
    parse_ifindex(index).map(Some)
}

fn private_work() -> Result<PathBuf> {
    let path = PathBuf::from(WORK);
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let metadata = fs::symlink_metadata(&path)?;
    let ram = rustix::fs::statfs(&path).map_err(io::Error::from)?;
    if ram.f_type != 0x0102_1994 {
        return Err(refuse("Menu SSH workspace is not on tmpfs"));
    }
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(refuse("Menu SSH workspace is not private RAM"));
    }
    Ok(path)
}

fn devpts() -> Result<()> {
    if zfs_tools::engine::mountinfo::current()?
        .iter()
        .any(|mount| mount.mount_point == Path::new("/dev/pts"))
    {
        return Ok(());
    }
    fs::create_dir_all("/dev/pts")?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0620,ptmxmode=0666"),
    )
    .map_err(std::io::Error::other)?;
    Ok(())
}

fn host_identity(work: &Path) -> Result<String> {
    let key = work.join("ssh_host_ed25519_key");
    if !key.exists() {
        let text = key
            .to_str()
            .ok_or_else(|| refuse("invalid Menu host-key path"))?;
        run(
            "/usr/bin/ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "zboot-menu",
                "-f",
                text,
            ],
        )?;
    }
    let metadata = fs::symlink_metadata(&key)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(refuse("Menu host key is not private RAM material"));
    }
    let public = run(
        "/usr/bin/ssh-keygen",
        &["-y", "-P", "", "-f", key.to_str().unwrap()],
    )?;
    if !public.starts_with("ssh-ed25519 ") {
        return Err(refuse("Menu host key is not Ed25519"));
    }
    let pub_path = work.join("ssh_host_ed25519_key.pub");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&pub_path)?;
    file.write_all(public.as_bytes())?;
    file.sync_all()?;
    let output = run(
        "/usr/bin/ssh-keygen",
        &["-l", "-E", "sha256", "-f", pub_path.to_str().unwrap()],
    )?;
    let fingerprint = output
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| refuse("Menu SSH fingerprint unavailable"))?;
    if !fingerprint.starts_with("SHA256:")
        || fingerprint.len() != 50
        || super::host_words::words(fingerprint).is_none()
    {
        return Err(refuse("Menu SSH fingerprint is invalid"));
    }
    Ok(fingerprint.into())
}

fn flush_routes(iface: &str, mut ip: impl FnMut(&[&str]) -> Result<String>) -> Result<()> {
    // iproute2 reports an error when a fresh Menu has no IPv4 FIB at all.
    // Observe first so an empty table is a successful no-op.
    if !ip(&["-4", "route", "show", "dev", iface])?
        .trim()
        .is_empty()
    {
        ip(&["-4", "route", "flush", "dev", iface])?;
    }
    Ok(())
}

fn deconfigure(iface: &str, ip: impl FnMut(&[&str]) -> Result<String>) -> Result<()> {
    if !valid_interface(iface) {
        return Err(refuse("Menu SSH lease interface is invalid"));
    }
    let expected = recorded_ifindex(iface)?;
    deconfigure_with(iface, expected, || interface_index(iface), ip)
}

fn deconfigure_with(
    iface: &str,
    expected_index: Option<u32>,
    mut current_index: impl FnMut() -> Result<Option<u32>>,
    mut ip: impl FnMut(&[&str]) -> Result<String>,
) -> Result<()> {
    if !valid_interface(iface) {
        return Err(refuse("Menu SSH lease interface is invalid"));
    }
    let mut gone = false;
    let mut guarded_ip = |args: &[&str]| {
        if gone {
            return Ok(String::new());
        }
        let current = current_index()?;
        if current.is_none() || expected_index.is_some_and(|index| current != Some(index)) {
            // Netdevice removal also removes its addresses/routes. A reused
            // name with a different index belongs to a different device.
            // Once gone, never act on a replacement appearing later here.
            gone = true;
            return Ok(String::new());
        }
        ip(args)
    };
    // Try all remaining steps while the same device exists, retaining real
    // command/probe failures. Device removal during cleanup settles old IP
    // errors too; the kernel has already removed that lease's network state.
    let mut first_error = None;
    for args in [
        ["link", "set", "dev", iface, "down"].as_slice(),
        ["-4", "address", "flush", "dev", iface].as_slice(),
    ] {
        if let Err(error) = guarded_ip(args)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Err(error) = flush_routes(iface, guarded_ip)
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    if gone {
        return Ok(());
    }
    let current = current_index()?;
    if current.is_none() || expected_index.is_some_and(|index| current != Some(index)) {
        return Ok(());
    }
    first_error.map_or(Ok(()), Err)
}

fn atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| refuse("private RAM path has no parent"))?;
    let temporary = parent.join(format!(".zboot-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn shadow_with_password(bytes: &[u8], password_hash: &str) -> Result<Vec<u8>> {
    if bytes.len() > 65_536
        || !bytes.ends_with(b"\n")
        || bytes.contains(&0)
        || password_hash.contains([':', '\n', '\r'])
    {
        return Err(refuse(
            "Menu shadow file is not bounded complete account data",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("Menu shadow file is not UTF-8"))?;
    let mut roots = 0;
    let mut result = String::new();
    for line in text.lines() {
        let mut fields: Vec<_> = line.split(':').collect();
        if fields.len() != 9 {
            return Err(refuse("Menu shadow account has invalid fields"));
        }
        if fields[0] == "root" {
            roots += 1;
            fields[1] = password_hash;
            // A last change of 0 means "must change at the next login", and
            // sshd then refuses the password without a terminal. An empty
            // field turns password ageing off.
            fields[2] = "";
        }
        result.push_str(&fields.join(":"));
        result.push('\n');
    }
    if roots != 1 {
        return Err(refuse(
            "Menu shadow file must contain exactly one root account",
        ));
    }
    Ok(result.into_bytes())
}

fn set_password_hash(hash: &str) -> Result<()> {
    let path = Path::new("/etc/shadow");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 65_536
    {
        return Err(refuse("Menu shadow file is not private RAM account data"));
    }
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    atomic_private(path, &shadow_with_password(&bytes, hash)?)
}

// NP cannot match crypt(3); unlike a locked account prefix it still permits
// public-key login with UsePAM=no, as in the assembled Menu account floor.
fn retire_password() -> Result<()> {
    set_password_hash("NP")
}

fn password_from_random(bytes: [u8; 12]) -> String {
    bytes
        .iter()
        .map(|b| char::from(PASSWORD_ALPHABET[usize::from(b & 31)]))
        .collect()
}

fn one_time_password() -> Result<String> {
    let mut bytes = [0_u8; 12];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(password_from_random(bytes))
}

fn hash_password(password: &str) -> Result<String> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let salt: String = random
        .iter()
        .map(|b| char::from(PASSWORD_ALPHABET[usize::from(b & 31)]))
        .collect();
    // No password in argv, the command trace, an environment variable or a
    // temporary file. Busybox reads its sole input over this private pipe.
    let mut child = zfs_tools::engine::native::announced(
        Command::new("/bin/busybox")
            .args(["mkpasswd", "-m", "sha512", "-S", &salt, "-s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
    )
    .spawn()?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| refuse("password hash input unavailable"))
        .and_then(|mut input| {
            input.write_all(password.as_bytes())?;
            input.write_all(b"\n")?;
            Ok(())
        });
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = child.wait_with_output()?;
    let hash = std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|v| v.strip_suffix('\n'))
        .filter(|v| {
            v.strip_prefix(&format!("$6${salt}$"))
                .is_some_and(|digest| {
                    digest.len() == 86
                        && digest
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"./".contains(&c))
                })
        });
    if !output.status.success() || hash.is_none() {
        return Err(refuse("Menu SHA512 password hashing is unavailable"));
    }
    Ok(hash.unwrap_or_default().to_owned())
}

fn ssh_configuration(address: Ipv4Addr, keys: bool) -> String {
    let (methods, publickey, password, root, authorized) = if keys {
        (
            "publickey",
            "yes",
            "no",
            "prohibit-password",
            "/run/zboot-connect/authorized_keys",
        )
    } else {
        ("password", "no", "yes", "yes", "none")
    };
    format!(
        "ListenAddress {address}\nHostKey {WORK}/ssh_host_ed25519_key\nHostKeyAlgorithms ssh-ed25519\nAuthenticationMethods {methods}\nPubkeyAuthentication {publickey}\nPasswordAuthentication {password}\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nPermitRootLogin {root}\nAllowUsers root\nAuthorizedKeysFile {authorized}\nAuthorizedKeysCommand none\nHostbasedAuthentication no\nGSSAPIAuthentication no\nDisableForwarding yes\nPermitTunnel no\nPermitUserEnvironment no\nPermitUserRC no\nUsePAM no\nUseDNS no\nStrictModes yes\nMaxAuthTries 3\nPerSourcePenalties yes\nPerSourceMaxStartups 1\nMaxStartups 3:30:3\nMaxSessions 1\nLoginGraceTime 30\nClientAliveInterval 30\nClientAliveCountMax 3\nLogLevel VERBOSE\nLogVerbose {LOG_VERBOSE}\nPidFile {WORK}/sshd.pid\nSubsystem sftp internal-sftp\n"
    )
}

fn remove_session_files() -> Result<()> {
    let mut first_error = None;
    for name in [
        "authorized_keys",
        "sshd_config",
        "sshd.pid",
        "ssh_host_ed25519_key",
        "ssh_host_ed25519_key.pub",
        "dhcp-lease",
        "network-interface",
        "network-ifindex",
    ] {
        if let Err(error) = fs::remove_file(Path::new(WORK).join(name))
            && error.kind() != io::ErrorKind::NotFound
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), |error| Err(error.into()))
}

fn stop_session(session: &mut SshSession) -> Result<()> {
    // Password and link cleanup are attempted even if an uninterruptible
    // cgroup member delays the barrier. Keep the owned Child and directory
    // handles on every failure; restart also discovers the reserved leaf.
    let password = retire_password();
    let group = session.custody.stop();
    let network = deconfigure(&session.iface, |args| run("/bin/ip", args));
    group.and(password).and(network)?;
    remove_session_files()
}

#[derive(Default)]
struct EvidenceState {
    input: usize,
    encoded: usize,
    truncated: bool,
}
impl EvidenceState {
    fn record(&mut self, writer: &mut impl Write, listener: u32, group: u32, bytes: &[u8]) {
        if self.truncated {
            return;
        }
        let input = self.input.saturating_add(bytes.len());
        let mut encoded = serde_json::to_vec(&serde_json::json!({
            "listener_pid":listener, "process_group":group, "record":bytes,
        }))
        .unwrap_or_default();
        encoded.push(b'\n');
        let total = self.encoded.saturating_add(encoded.len());
        // Diagnostics never consume the authentication/lifetime budget. The
        // marker has reserved space; an unwritable evidence sink is nonfatal.
        if bytes.len() > MAX_LOG_LINE
            || input > MAX_LOG_HISTORY_INPUT
            || total > MAX_LOG_HISTORY_ENCODED.saturating_sub(128)
            || writer.write_all(&encoded).is_err()
        {
            self.truncated = true;
            let _ = writer.write_all(
                b"{\"truncated\":true,\"reason\":\"raw diagnostic bound or write failure\"}\n",
            );
            return;
        }
        self.input = input;
        self.encoded = total;
    }
}

fn drain_log(session: &mut SshSession) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    let mut total = 0;
    let mut buffer = [0_u8; MAX_LOG_LINE + 1];
    while total < MAX_LOG_BATCH {
        let count = match session.stderr.recv(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        total += count.max(1);
        session.evidence_state.record(
            &mut session.evidence,
            session.custody.listener_pid(),
            session.custody.listener_pid(),
            &buffer[..count],
        );
        // The supervisor retires the password before any Menu event, including
        // while the menu is blocked. Oversized/malformed diagnostics are not
        // trusted records and cannot stop an already-authenticated session.
        if let Some(event) = session.log.record(&buffer[..count], retire_password)? {
            events.push(event);
        }
    }
    Ok(events)
}

fn finish(manager: &mut Manager) -> Result<()> {
    manager.banner.clear();
    if let Some(session) = manager.session.as_mut() {
        let cleaned = stop_session(session);
        manager.stopped(cleaned)?;
        manager.session.take();
        Ok(())
    } else {
        manager.require_cleaned()
    }
}

fn failed_after_cleanup(
    manager: &mut Manager,
    primary: RecoveryError,
    cleanup: Result<()>,
) -> RecoveryError {
    let error = match cleanup {
        Ok(()) => primary,
        Err(cleanup) => {
            manager.cleanup_failed = true;
            RecoveryError::Cleanup {
                activity: "Menu SSH service",
                primary: Box::new(primary),
                operation: "close owned SSH resources",
                cleanup: Box::new(cleanup),
            }
        }
    };
    // The closed variant carries the classification; neither the caller nor
    // the Menu has to inspect error text. Retain the fact after poll consumes
    // this report, and after an empty finish/new activation is attempted.
    let report = refuse(error.to_string());
    manager.failure = Some(if manager.cleanup_failed {
        PollError::Cleanup(report)
    } else {
        PollError::Service(report)
    });
    error
}

fn supervise(manager: &mut Manager, now: Instant) -> Result<bool> {
    let Some(session) = manager.session.as_mut() else {
        return Ok(false);
    };
    let events = drain_log(session)?;
    let last_session_ended = events.contains(&Event::SessionEnded)
        && session.log.log.connections.is_empty()
        && !session.log.log.overflow;
    let ended = now >= session.deadline || session.custody.exited()? || last_session_ended;
    for event in events {
        manager.queue(event)?;
    }
    if ended {
        finish(manager)?;
        if last_session_ended {
            println!("Menu SSH: last authenticated session ended; owned cgroup closed.");
        }
        return Ok(false);
    }
    Ok(true)
}

fn launch_supervisor(
    mut session: SshSessionStart,
    config: String,
    sender: Stdio,
) -> Result<SshSession> {
    let (ready, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("zboot-ssh-supervisor".into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Spawn here, not on the caller thread: PDEATHSIG must follow the
                // supervisor that owns retirement and the absolute lease.
                let started = (|| -> Result<SshSession> {
                    session.custody.spawn(&config, sender)?;
                    Ok(SshSession {
                        custody: session.custody,
                        stderr: session.stderr,
                        evidence: session.evidence,
                        evidence_state: EvidenceState::default(),
                        log: LogState {
                            password_live: session.password_live,
                            ..LogState::default()
                        },
                        iface: std::mem::take(&mut session.iface),
                        deadline: session.deadline,
                    })
                })();
                let succeeded = started.is_ok();
                if ready.send(started).is_err() || !succeeded {
                    return;
                }
                loop {
                    thread::sleep(Duration::from_millis(50));
                    let Some(lock) = SSHD.get() else {
                        return;
                    };
                    let mut manager = lock.lock().unwrap_or_else(|poison| poison.into_inner());
                    if !manager
                        .session
                        .as_ref()
                        .is_some_and(|s| s.deadline == session.deadline)
                    {
                        return;
                    }
                    match supervise(&mut manager, Instant::now()) {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(error) => {
                            let cleanup = finish(&mut manager);
                            failed_after_cleanup(&mut manager, error, cleanup);
                            return;
                        }
                    }
                }
            }));
            drop(ready); // unblock startup receiver before taking its Manager lock
            if outcome.is_err()
                && let Some(lock) = SSHD.get()
            {
                let mut manager = lock.lock().unwrap_or_else(|poison| poison.into_inner());
                let cleanup = finish(&mut manager);
                failed_after_cleanup(
                    &mut manager,
                    refuse("SSH supervisor panicked; owned custody must close"),
                    cleanup,
                );
                // Thread exit also SIGKILLs the direct listener. Its leaf is
                // still the authority for every detached descendant's barrier.
            }
        })?;
    // A stalled pre-exec migration cannot indefinitely block the console.
    // Caller cleanup removes the leaf; a late write through its held admission
    // FD then fails rather than launching an untracked listener.
    receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| refuse("SSH supervisor did not complete startup; owned custody must close"))?
}

struct SshSessionStart {
    custody: custody::Owned,
    stderr: UnixDatagram,
    evidence: File,
    iface: String,
    deadline: Instant,
    password_live: bool,
}

/// Before consuming a startup key request or arming any countdown, close only
/// every generation under the reserved cgroup parent and retire credentials.
/// Root's menu entry calls this even when no new SSH was requested.
pub(super) fn recover() -> Result<()> {
    prove_ram()?;
    private_work()?;
    let mut manager = SSHD
        .get_or_init(|| Mutex::new(Manager::default()))
        .lock()
        .map_err(|_| refuse("Menu SSH state poisoned; custody is unknown"))?;
    manager.require_cleaned()?;
    if manager.recovered {
        return Ok(());
    }
    let result = (|| {
        // Always retire credentials and attempt known link cleanup even if a
        // stuck member makes the cgroup barrier fail. Never erase the lease
        // identity until every cleanup effect has succeeded.
        let password = retire_password();
        let interface = recorded_interface();
        let group = custody::recover();
        let had_interface = interface.as_ref().is_ok_and(|value| value.is_some());
        let network = interface.and_then(|iface| {
            iface.map_or(Ok(()), |iface| {
                deconfigure(&iface, |args| run("/bin/ip", args))
            })
        });
        password.and(group).and(network)?;
        remove_session_files()?;
        if had_interface {
            println!("Menu SSH: previous owned cgroups closed before startup.");
        }
        Ok(())
    })();
    manager.cleaned(result)?;
    manager.recovered = true;
    Ok(())
}

/// Drain observations, never infer an authenticated session from a live
/// listener. Cleanup and first-login password retirement run without polling.
pub(super) fn poll() -> std::result::Result<Vec<Event>, PollError> {
    recover().map_err(PollError::Cleanup)?;
    let mut manager = SSHD
        .get_or_init(|| Mutex::new(Manager::default()))
        .lock()
        .map_err(|_| PollError::Cleanup(refuse("Menu SSH state poisoned; custody is unknown")))?;
    manager.poll()
}

pub(super) fn stop() -> Result<()> {
    let mut manager = SSHD
        .get_or_init(|| Mutex::new(Manager::default()))
        .lock()
        .map_err(|_| refuse("Menu SSH state poisoned"))?;
    finish(&mut manager)
}

/// The address line keeps its 0.4.0 shape (`Host key fingerprint: SHA256:...`)
/// for tools; the words line follows it for people.
fn session_banner(
    address: Ipv4Addr,
    iface: &str,
    fingerprint: &str,
    keys: Option<&PublicKeys>,
) -> Vec<String> {
    let mut lines = vec![format!(
        "Menu SSH enabled on {address} ({iface}). Host key fingerprint: {fingerprint}"
    )];
    lines.extend(super::host_words::line(fingerprint));
    if let Some(keys) = keys {
        lines.push(format!("Key-only SSH: {}", keys.fingerprints().join(", ")));
    }
    lines
}

/// The live SSH session's console lines, empty when none runs. The menu
/// prints them after its listing and after each discovery line, so they stay
/// the bottom lines of a console without scrollback.
pub(super) fn banner() -> Vec<String> {
    let Some(lock) = SSHD.get() else {
        return Vec::new();
    };
    let manager = lock.lock().unwrap_or_else(|poison| poison.into_inner());
    if manager.session.is_some() {
        manager.banner.clone()
    } else {
        Vec::new()
    }
}

pub(super) fn start_keys(keys: &PublicKeys) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    start(Some(keys))
}

pub(super) fn connect() -> Result<()> {
    start(None)
}

fn start(keys: Option<&PublicKeys>) -> Result<()> {
    recover()?;
    prove_ram()?;
    readonly_pools(&state::observe()?)?;
    if !available() {
        return Err(refuse(
            "Menu connect requires the Menu runtime role, SSH/network tools and cgroup2 custody",
        ));
    }
    let mut manager = SSHD
        .get_or_init(|| Mutex::new(Manager::default()))
        .lock()
        .map_err(|_| refuse("Menu SSH state poisoned"))?;
    // Explicit activation starts a fresh credential window; never quietly
    // turn an already-running key-only listener into a password listener.
    finish(&mut manager)?;
    manager.failure = None;
    manager.events.clear();
    let work = private_work()?;
    let cleared = remove_session_files();
    manager.cleaned(cleared)?;
    match fs::remove_file(work.join("sshd.log")) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let password = retire_password();
    manager.cleaned(password)?;
    for driver in ["r8152", "virtio_net", "e1000e", "igc", "r8169"] {
        let _ = run("/sbin/modprobe", &[driver]);
    }
    run("/usr/bin/udevadm", &["settle"])?;
    // Carrier discovery may raise candidate links. Record only the selected
    // device below, before DHCP and address/route lease effects begin.
    let iface = sole_carrier_wired(Path::new("/sys/class/net"), |name| {
        disable_ipv6(name)?;
        run("/bin/ip", &["link", "set", "dev", name, "up"])?;
        Ok(())
    })?;
    let mut custody = None;
    let started = (|| -> Result<(SshSession, String, Option<String>, Ipv4Addr)> {
        custody = Some(custody::Owned::new()?);
        let ifindex = interface_index(&iface)?
            .ok_or_else(|| refuse("chosen wired interface disappeared before DHCP"))?;
        atomic_private(
            &work.join("network-ifindex"),
            format!("{iface}\n{ifindex}\n").as_bytes(),
        )?;
        atomic_private(&work.join("network-interface"), iface.as_bytes())?;
        if interface_index(&iface)? != Some(ifindex) {
            return Err(refuse("chosen wired interface changed before DHCP"));
        }
        let fingerprint = host_identity(&work)?;
        devpts()?;
        fs::create_dir_all("/run/sshd")?;
        disable_ipv6(&iface)?;
        run("/bin/ip", &["-4", "address", "flush", "dev", &iface])?;
        flush_routes(&iface, |args| run("/bin/ip", args))?;
        run("/bin/ip", &["link", "set", "dev", &iface, "up"])?;
        let lease = dhcp_lease(&work, &iface, custody.as_ref().expect("unspawned custody"))?;
        let deadline = Instant::now() + Duration::from_secs(u64::from(lease.session_seconds));
        let cidr = format!("{}/{}", lease.address, lease.prefix);
        run("/bin/ip", &["address", "replace", &cidr, "dev", &iface])?;
        if let Some(gateway) = lease.gateway {
            run(
                "/bin/ip",
                &[
                    "route",
                    "replace",
                    "default",
                    "via",
                    &gateway.to_string(),
                    "dev",
                    &iface,
                ],
            )?;
        }
        let password = if let Some(keys) = keys {
            atomic_private(&work.join("authorized_keys"), keys.authorized_keys())?;
            None
        } else {
            let password = one_time_password()?;
            let hash = hash_password(&password)?;
            set_password_hash(&hash)?;
            Some(password)
        };
        let config = work.join("sshd_config");
        atomic_private(
            &config,
            ssh_configuration(lease.address, keys.is_some()).as_bytes(),
        )?;
        let config = config
            .to_str()
            .ok_or_else(|| refuse("invalid Menu SSH config path"))?;
        run("/usr/sbin/sshd", &["-t", "-f", config])?;
        let evidence = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(work.join("sshd.log"))?;
        // stderr is a private datagram socket, not a byte stream: a single
        // sshd log write remains indivisible even with hostile embedded LF.
        let (stderr, sender) = UnixDatagram::pair()?;
        stderr.set_nonblocking(true)?;
        let session = launch_supervisor(
            SshSessionStart {
                custody: custody.take().expect("one owned generation"),
                stderr,
                evidence,
                iface: iface.clone(),
                deadline,
                password_live: password.is_some(),
            },
            config.to_owned(),
            Stdio::from(OwnedFd::from(sender)),
        )?;
        Ok((session, fingerprint, password, lease.address))
    })();
    let (session, fingerprint, password, address) = match started {
        Ok(started) => started,
        Err(error) => {
            let password = retire_password();
            let network = deconfigure(&iface, |args| run("/bin/ip", args));
            let group = custody::recover();
            // A group moved to the supervisor is still discoverable under the
            // reserved parent if startup unwinds before returning its handle.
            let cleanup = group.and(password).and(network);
            let cleanup = cleanup.and_then(|()| remove_session_files());
            return Err(failed_after_cleanup(&mut manager, error, cleanup));
        }
    };
    let deadline = session.deadline;
    manager.session = Some(session);
    manager.banner = session_banner(address, &iface, &fingerprint, keys);
    for line in &manager.banner {
        println!("{line}");
    }
    if let Some(password) = password {
        println!("One-time root password: {password}");
    }
    println!(
        "SSH lease window ends in at most {} seconds.",
        deadline.saturating_duration_since(Instant::now()).as_secs()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Modelled lines use the upstream LogVerbose format; these are parser
    // fixtures, not claimed captures of the packaged runtime. EFI-CONNECT
    // checks the packaged daemon's actual stderr and authentication lifecycle.
    fn record(site: &str, pid: u32, message: &str) -> Vec<u8> {
        format!("{site}():279 (bin=sshd-session, pid={pid}): {message}\r\n").into_bytes()
    }
    fn accepted(pid: u32, port: u16) -> Vec<u8> {
        record(
            "auth.c:auth_log",
            pid,
            &format!(
                "Accepted publickey for root from 192.0.2.2 port {port} ssh2: ED25519 SHA256:example"
            ),
        )
    }
    fn observe(log: &mut LogState, bytes: &[u8]) -> Option<Event> {
        log.record(bytes, || Ok(())).unwrap()
    }

    #[test]
    fn the_ssh_lines_keep_the_fingerprint_line_and_add_the_words() {
        let fingerprint = "SHA256:7R47Vfjv11EU/pHF5UnS60ljM38uX1q9DzZX0HLvBCg";
        let lines = session_banner(Ipv4Addr::new(192, 168, 25, 11), "enp0s2", fingerprint, None);
        assert_eq!(
            lines,
            [
                format!(
                    "Menu SSH enabled on 192.168.25.11 (enp0s2). Host key fingerprint: {fingerprint}"
                ),
                "Host key words: 1 unfair 2 vault 3 step 4 vault 5 word 6 possible".to_owned(),
            ]
        );
    }

    #[test]
    fn a_service_error_with_successful_cleanup_does_not_hold_the_menu() {
        let mut manager = Manager::default();
        manager.stopped(Ok(())).unwrap();
        failed_after_cleanup(&mut manager, refuse("injected SSH service failure"), Ok(()));
        assert!(matches!(manager.poll(), Err(PollError::Service(_))));
        assert!(!manager.cleanup_failed);
        assert!(finish(&mut manager).is_ok());
        assert_eq!(manager.poll().unwrap(), [Event::Stopped]);
        assert!(manager.require_cleaned().is_ok());
    }

    #[test]
    fn a_cleanup_failure_is_sticky_after_the_session_and_error_are_consumed() {
        let mut manager = Manager::default();
        assert!(
            manager
                .stopped(Err(refuse("injected link cleanup failure")))
                .is_err()
        );
        assert!(
            manager.events.is_empty(),
            "Stopped requires successful cleanup"
        );
        assert!(matches!(manager.poll(), Err(PollError::Cleanup(_))));
        assert!(matches!(manager.poll(), Err(PollError::Cleanup(_))));
        assert!(manager.session.is_none());
        assert!(finish(&mut manager).is_err());
        // start() calls the same finish gate before clearing the old report or
        // constructing any new credential/network/listener resources.
        assert!(finish(&mut manager).is_err());
        assert!(manager.require_cleaned().is_err());
        assert!(manager.events.is_empty());
    }

    #[test]
    fn partial_start_cleanup_failure_is_reported_as_cleanup_not_service() {
        let mut manager = Manager::default();
        let error = failed_after_cleanup(
            &mut manager,
            refuse("sshd start failed"),
            Err(refuse("password retirement failed")),
        );
        assert!(matches!(error, RecoveryError::Cleanup { .. }));
        assert!(matches!(manager.poll(), Err(PollError::Cleanup(_))));
        assert!(finish(&mut manager).is_err());
        assert!(!manager.events.contains(&Event::Stopped));
    }

    #[test]
    fn ssh_started_by_a_key_never_offers_the_password() {
        let config = ssh_configuration(Ipv4Addr::new(192, 0, 2, 10), true);
        for required in [
            "AuthenticationMethods publickey",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PermitEmptyPasswords no",
            "PermitRootLogin prohibit-password",
            "AuthorizedKeysFile /run/zboot-connect/authorized_keys",
            "MaxAuthTries 3",
            "PerSourcePenalties yes",
        ] {
            assert!(
                config.lines().any(|line| line == required),
                "missing {required}"
            );
        }
        assert!(!config.contains("PasswordAuthentication yes"));
        assert!(!config.contains("/zboot-profile"));
        let mut log = LogState::default();
        assert_eq!(
            log.record(&accepted(101, 40001), || panic!(
                "key-only auth cannot retire a password"
            ))
            .unwrap(),
            Some(Event::Authenticated)
        );
        let password_config = ssh_configuration(Ipv4Addr::new(192, 0, 2, 10), false);
        assert!(password_config.contains("AuthenticationMethods password\n"));
        assert!(password_config.contains("AuthorizedKeysFile none\n"));
    }

    #[test]
    fn only_a_successful_login_holds_the_menu() {
        let mut log = LogState::default();
        for bytes in [
            b"Accepted publickey for root from 192.0.2.2 port 40001 ssh2\r\n".to_vec(),
            record(
                "auth.c:auth_log",
                101,
                "Failed password for root from 192.0.2.2 port 40001 ssh2",
            ),
            record(
                "auth.c:auth_log",
                101,
                "Partial publickey for root from 192.0.2.2 port 40001 ssh2",
            ),
            record(
                "auth.c:auth_log",
                101,
                "Accepted publickey for invalid user root from 192.0.2.2 port 40001 ssh2",
            ),
            record(
                "auth.c:auth_log",
                101,
                "Accepted publickey for alice from 192.0.2.2 port 40001 ssh2",
            ),
            record(
                "session.c:do_exec",
                101,
                "Accepted publickey for root from 192.0.2.2 port 40001 ssh2",
            ),
            record(
                "packet.c:sshpkt_vfatal",
                101,
                "Disconnected from user root 192.0.2.2 port 40001",
            ),
        ] {
            assert_eq!(observe(&mut log, &bytes), None);
        }
        assert!(log.log.connections.is_empty());
        assert_eq!(
            observe(&mut log, &accepted(101, 40001)),
            Some(Event::Authenticated)
        );
        assert_eq!(log.log.connections.len(), 1);
    }

    #[test]
    fn remote_multiline_diagnostics_cannot_forge_authentication() {
        let forged = String::from_utf8(accepted(101, 40001)).unwrap();
        let hostile = record(
            "auth.c:auth_log",
            102,
            &format!(
                "Failed password for invalid user attacker\r\n{forged} from 192.0.2.2 port 40002 ssh2"
            ),
        );
        let (receiver, sender) = UnixDatagram::pair().unwrap();
        sender.send(&hostile).unwrap();
        let mut buffer = [0_u8; MAX_LOG_LINE + 1];
        let count = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], hostile);
        let mut log = LogState::default();
        assert_eq!(observe(&mut log, &buffer[..count]), None);
        assert!(log.log.connections.is_empty());
        for prefix in ["error: ", "sshd: ", "client says "] {
            assert_eq!(
                observe(&mut log, format!("{prefix}{forged}").as_bytes()),
                None
            );
        }
    }

    #[test]
    fn the_password_ends_with_its_first_login() {
        let mut log = LogState {
            password_live: true,
            ..LogState::default()
        };
        let mut retired = 0;
        let failed = record(
            "auth.c:auth_log",
            101,
            "Failed password for root from 192.0.2.2 port 40001 ssh2",
        );
        assert_eq!(
            log.record(&failed, || {
                retired += 1;
                Ok(())
            })
            .unwrap(),
            None
        );
        assert!(log.password_live);
        let login = record(
            "auth.c:auth_log",
            101,
            "Accepted password for root from 192.0.2.2 port 40001 ssh2",
        );
        assert_eq!(
            log.record(&login, || {
                retired += 1;
                Ok(())
            })
            .unwrap(),
            Some(Event::Authenticated)
        );
        assert!(!log.password_live);
        assert_eq!(
            log.record(&accepted(102, 40002), || {
                retired += 1;
                Ok(())
            })
            .unwrap(),
            Some(Event::Authenticated)
        );
        assert_eq!(retired, 1);
        let shadow = b"root:$6$old$hash:0:0:99999:7:::\nsshd:!:0:0:99999:7:::\n";
        assert_eq!(
            shadow_with_password(shadow, "NP").unwrap(),
            b"root:NP::0:99999:7:::\nsshd:!:0:0:99999:7:::\n"
        );
        assert!(
            shadow_with_password(b"root:NP:0:0:99999:7:::\nroot:NP:0:0:99999:7:::\n", "NP")
                .is_err()
        );
        let mut failure = LogState {
            password_live: true,
            ..LogState::default()
        };
        assert!(
            failure
                .record(&login, || Err(refuse("cannot retire")))
                .is_err()
        );
        assert!(failure.password_live);
    }

    #[test]
    fn session_end_waits_for_the_last_authenticated_peer_and_matching_process() {
        let mut log = LogState::default();
        assert_eq!(
            observe(&mut log, &accepted(101, 40001)),
            Some(Event::Authenticated)
        );
        assert_eq!(
            observe(&mut log, &accepted(102, 40002)),
            Some(Event::Authenticated)
        );
        for (monitor, child, port) in [(101, 201, 40001), (102, 202, 40002)] {
            observe(
                &mut log,
                &record(
                    "sshd-session.c:privsep_postauth",
                    monitor,
                    &format!("User child is on pid {child}"),
                ),
            );
            observe(
                &mut log,
                &record(
                    "session.c:do_exec",
                    child,
                    &format!(
                        "Starting session: shell on pts/0 for root from 192.0.2.2 port {port} id 0"
                    ),
                ),
            );
        }
        assert_eq!(
            observe(
                &mut log,
                &record(
                    "session.c:session_close",
                    999,
                    "Close session: user root from 192.0.2.2 port 40001 id 0"
                )
            ),
            None
        );
        assert_eq!(
            observe(
                &mut log,
                &record(
                    "packet.c:sshpkt_vfatal",
                    999,
                    "Disconnected from user root 192.0.2.2 port 40001"
                )
            ),
            None
        );
        assert_eq!(
            observe(
                &mut log,
                &record(
                    "packet.c:sshpkt_vfatal",
                    201,
                    "Disconnected from user root 192.0.2.2 port 49999"
                )
            ),
            None
        );
        assert_eq!(log.log.connections.len(), 2);
        assert_eq!(
            observe(
                &mut log,
                &record(
                    "session.c:session_close",
                    201,
                    "Close session: user root from 192.0.2.2 port 40001 id 0"
                )
            ),
            None
        );
        assert_eq!(
            observe(
                &mut log,
                &record(
                    "session.c:session_close",
                    202,
                    "Close session: user root from 192.0.2.2 port 40002 id 0"
                )
            ),
            Some(Event::SessionEnded)
        );
        assert!(log.log.connections.is_empty());
    }

    #[test]
    fn authenticated_connection_without_a_shell_has_a_real_end() {
        let mut log = LogState::default();
        observe(&mut log, &accepted(101, 40001));
        observe(
            &mut log,
            &record(
                "sshd-session.c:privsep_postauth",
                101,
                "User child is on pid 201",
            ),
        );
        assert_eq!(
            observe(
                &mut log,
                &record(
                    "packet.c:sshpkt_vfatal",
                    201,
                    "Disconnected from user root 192.0.2.2 port 40001"
                )
            ),
            Some(Event::SessionEnded)
        );
        assert!(log.log.connections.is_empty());
    }

    #[test]
    fn diagnostic_and_connection_bounds_do_not_release_an_authenticated_hold() {
        let mut log = LogState::default();
        assert_eq!(observe(&mut log, &vec![b'x'; MAX_LOG_LINE + 1]), None);
        assert_eq!(observe(&mut log, b"unterminated"), None);
        for index in 0..MAX_CONNECTIONS {
            assert_eq!(
                observe(&mut log, &accepted(index as u32 + 1, index as u16 + 40000)),
                Some(Event::Authenticated)
            );
        }
        assert_eq!(
            observe(&mut log, &accepted(999, 50000)),
            Some(Event::Authenticated)
        );
        assert!(log.log.overflow);
        assert_eq!(log.log.connections.len(), MAX_CONNECTIONS);
        for index in 0..MAX_CONNECTIONS {
            assert_eq!(
                observe(
                    &mut log,
                    &record(
                        "packet.c:sshpkt_vfatal",
                        index as u32 + 1,
                        &format!(
                            "Disconnected from user root 192.0.2.2 port {}",
                            index + 40000
                        )
                    )
                ),
                None
            );
        }
        assert!(log.log.connections.is_empty());
        assert!(
            log.log.overflow,
            "unknown sessions stay held until lease/barrier stop"
        );
    }

    #[test]
    fn raw_log_truncation_and_write_failure_do_not_consume_authentication() {
        let mut capture = EvidenceState::default();
        let mut bytes = Vec::new();
        let failed = record(
            "auth.c:auth_log",
            1,
            "Failed publickey for root from 192.0.2.2 port 1 ssh2",
        );
        for _ in 0..MAX_LOG_HISTORY_INPUT {
            capture.record(&mut bytes, 12, 11, &failed);
        }
        assert!(capture.truncated);
        assert!(bytes.len() <= MAX_LOG_HISTORY_ENCODED);
        assert_eq!(
            bytes
                .windows(b"\"truncated\":true".len())
                .filter(|part| *part == b"\"truncated\":true")
                .count(),
            1
        );
        let len = bytes.len();
        capture.record(&mut bytes, 12, 11, &accepted(2, 40001));
        assert_eq!(bytes.len(), len);
        let mut log = LogState {
            password_live: true,
            ..LogState::default()
        };
        let mut retired = 0;
        assert_eq!(
            log.record(&accepted(2, 40001), || {
                retired += 1;
                Ok(())
            })
            .unwrap(),
            Some(Event::Authenticated)
        );
        assert_eq!(retired, 1);
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("injected evidence error"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut failed_capture = EvidenceState::default();
        failed_capture.record(&mut Broken, 12, 11, &failed);
        assert!(failed_capture.truncated);
        assert_eq!(
            observe(&mut log, &accepted(3, 40002)),
            Some(Event::Authenticated)
        );
    }

    #[test]
    fn events_coalesce_global_state_without_losing_first_authentication() {
        let mut manager = Manager::default();
        for _ in 0..1000 {
            manager.queue(Event::Authenticated).unwrap();
        }
        manager.queue(Event::SessionEnded).unwrap();
        manager.queue(Event::Authenticated).unwrap();
        assert_eq!(manager.poll().unwrap(), [Event::Authenticated]);
        manager.queue(Event::Authenticated).unwrap();
        manager.queue(Event::SessionEnded).unwrap();
        manager.queue(Event::Stopped).unwrap();
        assert_eq!(
            manager.poll().unwrap(),
            [Event::Authenticated, Event::SessionEnded, Event::Stopped]
        );
        assert!(manager.poll().unwrap().is_empty());
    }

    #[test]
    fn trusted_timeout_and_read_errors_require_the_authenticated_pid_and_peer() {
        for (site, message) in [
            (
                "serverloop.c:client_alive_check",
                "Timeout, client not responding from user root 192.0.2.2 port 40001",
            ),
            (
                "serverloop.c:wait_until_can_do_something",
                "terminating inactive connection from user root 192.0.2.2 port 40001",
            ),
            (
                "serverloop.c:process_input",
                "Read error from remote host 192.0.2.2 port 40001: Connection reset by peer",
            ),
            (
                "serverloop.c:process_input",
                "Connection closed by 192.0.2.2 port 40001",
            ),
            (
                "packet.c:sshpkt_vfatal",
                "Connection from user root 192.0.2.2 port 40001 timed out",
            ),
        ] {
            let mut log = LogState::default();
            observe(&mut log, &accepted(101, 40001));
            observe(
                &mut log,
                &record(
                    "sshd-session.c:privsep_postauth",
                    101,
                    "User child is on pid 201",
                ),
            );
            assert_eq!(observe(&mut log, &record(site, 999, message)), None);
            assert_eq!(
                observe(
                    &mut log,
                    &record(site, 201, &message.replace("40001", "40002"))
                ),
                None
            );
            assert_eq!(
                observe(&mut log, &record("auth.c:auth_log", 201, message)),
                None
            );
            assert_eq!(
                observe(&mut log, &record(site, 201, message)),
                Some(Event::SessionEnded)
            );
        }
    }

    #[test]
    fn the_console_password_has_twelve_uniform_base32_characters() {
        assert_eq!(PASSWORD_ALPHABET.iter().collect::<BTreeSet<_>>().len(), 32);
        let mut counts = BTreeMap::new();
        for value in 0..=255 {
            let password = password_from_random([value; 12]);
            assert_eq!(password.len(), 12);
            assert!(
                password
                    .as_bytes()
                    .iter()
                    .all(|b| PASSWORD_ALPHABET.contains(b))
            );
            *counts.entry(password.as_bytes()[0]).or_insert(0) += 1;
        }
        assert_eq!(counts.len(), 32);
        assert!(counts.values().all(|n| *n == 8));
    }

    #[test]
    fn dhcp_lease_refuses_extra_or_ambiguous_values() {
        assert_eq!(
            parse_lease(b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.2\n120\n", "eth0").unwrap(),
            Lease {
                address: Ipv4Addr::new(192, 0, 2, 10),
                prefix: 24,
                gateway: Some(Ipv4Addr::new(192, 0, 2, 2)),
                session_seconds: 60,
            }
        );
        // No router offered: the address serves its own subnet.
        assert_eq!(
            parse_lease(b"eth0\n192.0.2.10\n255.255.255.0\n\n120\n", "eth0")
                .unwrap()
                .gateway,
            None
        );
        for invalid in [
            b"eth1\n192.0.2.10\n255.255.255.0\n192.0.2.2\n120\n".as_slice(),
            b"eth0\n192.0.2.10\n255.0.255.0\n192.0.2.2\n120\n",
            b"eth0\n192.0.2.255\n255.255.255.0\n192.0.2.2\n120\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.2 192.0.2.3\n120\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n198.51.100.2\n120\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.255\n120\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.10\n120\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.2\n119\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.2\n0120\n",
            b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.2\n120\nextra\n",
        ] {
            assert!(parse_lease(invalid, "eth0").is_err());
        }
    }

    #[test]
    fn lease_cleanup_disables_link_and_removes_stale_address_and_route_even_on_error() {
        let mut calls = Vec::new();
        let failure = deconfigure_with(
            "eth0",
            Some(7),
            || Ok(Some(7)),
            |args| {
                calls.push(args.join(" "));
                if calls.len() == 1 {
                    Err(refuse("injected link error"))
                } else if args.get(2) == Some(&"show") {
                    Ok("default via 192.0.2.2 dev eth0\n".into())
                } else {
                    Ok(String::new())
                }
            },
        );
        assert!(failure.is_err());
        assert_eq!(
            calls,
            [
                "link set dev eth0 down",
                "-4 address flush dev eth0",
                "-4 route show dev eth0",
                "-4 route flush dev eth0"
            ]
        );
        let mut clean_calls = Vec::new();
        deconfigure_with(
            "eth0",
            Some(7),
            || Ok(Some(7)),
            |args| {
                clean_calls.push(args.join(" "));
                Ok(String::new())
            },
        )
        .unwrap();
        assert_eq!(clean_calls.len(), 3);
        assert_eq!(
            parse_lease(
                b"eth0\n192.0.2.10\n255.255.255.0\n192.0.2.2\n86400\n",
                "eth0"
            )
            .unwrap()
            .session_seconds,
            6 * 60 * 60
        );
    }

    #[test]
    fn a_vanished_lease_interface_is_already_deconfigured() {
        deconfigure_with(
            "eth0",
            Some(7),
            || Ok(None),
            |_| panic!("no ip effect on absent interface"),
        )
        .unwrap();
        let mut observations = [Some(7), None].into_iter();
        let mut calls = 0;
        deconfigure_with(
            "eth0",
            Some(7),
            || Ok(observations.next().expect("bounded probes")),
            |_| {
                calls += 1;
                Err(refuse("device disappeared during link-down"))
            },
        )
        .unwrap();
        assert_eq!(calls, 1);
    }

    #[test]
    fn lease_cleanup_does_not_flush_a_same_name_replacement() {
        deconfigure_with(
            "eth0",
            Some(7),
            || Ok(Some(8)),
            |_| panic!("replacement is unrelated"),
        )
        .unwrap();
        let mut calls = 0;
        // Old name-only records retain their original readable semantics.
        deconfigure_with(
            "eth0",
            None,
            || Ok(Some(7)),
            |_| {
                calls += 1;
                Ok(String::new())
            },
        )
        .unwrap();
        assert_eq!(calls, 3);
    }

    #[test]
    fn interface_inventory_errors_and_invalid_names_do_not_claim_cleanup() {
        assert!(
            deconfigure_with(
                "eth0",
                Some(7),
                || Err(refuse("injected sysfs read error")),
                |_| panic!("unknown identity permits no ip effect")
            )
            .is_err()
        );
        assert!(
            deconfigure_with(
                "../eth0",
                Some(7),
                || panic!("invalid name permits no probe"),
                |_| panic!("invalid name permits no ip effect")
            )
            .is_err()
        );
        assert_eq!(parse_ifindex("7\n").unwrap(), 7);
        for invalid in ["0", "07", "-1", "7\n\n", "4294967296"] {
            assert!(parse_ifindex(invalid).is_err());
        }
    }

    #[test]
    fn dhcp_selects_only_one_carrier_present_physical_wired_interface() {
        let root = std::env::temp_dir().join(format!("zboot-wired-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        for (name, carrier) in [("eth0", "1"), ("eth1", "0"), ("wlan0", "1")] {
            let path = root.join(name);
            fs::create_dir(&path).unwrap();
            fs::create_dir(path.join("device")).unwrap();
            fs::write(path.join("type"), "1\n").unwrap();
            fs::write(path.join("carrier"), format!("{carrier}\n")).unwrap();
        }
        fs::create_dir(root.join("wlan0/wireless")).unwrap();
        let short = Duration::from_millis(300);
        let mut raised = Vec::new();
        assert_eq!(
            sole_carrier_wired_within(
                &root,
                |name| {
                    raised.push(name.to_owned());
                    Ok(())
                },
                short,
                Duration::from_millis(100),
            )
            .unwrap(),
            "eth0"
        );
        assert_eq!(raised.len(), 2);
        // A link that comes up a while after it was raised is still found.
        fs::write(root.join("eth0/carrier"), "0\n").unwrap();
        let late = root.join("eth0/carrier");
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            fs::write(late, "1\n").unwrap();
        });
        assert_eq!(
            sole_carrier_wired_within(
                &root,
                |_| Ok(()),
                Duration::from_secs(5),
                Duration::from_millis(100)
            )
            .unwrap(),
            "eth0"
        );
        writer.join().unwrap();
        // Nothing up within the wait refuses.
        fs::write(root.join("eth0/carrier"), "0\n").unwrap();
        assert!(sole_carrier_wired_within(&root, |_| Ok(()), short, short).is_err());
        fs::write(root.join("eth0/carrier"), "1\n").unwrap();
        fs::write(root.join("eth1/carrier"), "1\n").unwrap();
        assert!(sole_carrier_wired_within(&root, |_| Ok(()), short, short).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
