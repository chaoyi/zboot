//! What a failed mmdebstrap's output says went wrong. Factory streams the
//! whole output through unchanged; this keeps only the few lines that name
//! the cause, in bounded memory, so the final refusal can name it too.

/// Bytes kept of any one line; the rest of a longer line is dropped.
const LINE: usize = 512;
/// Package names the summary lists before counting the rest.
const NAMES: usize = 6;
/// Characters of a quoted error line.
const QUOTE: usize = 200;

#[derive(Debug, Default)]
pub(crate) struct Failure {
    line: Vec<u8>,
    /// dpkg's action on the first package it failed, e.g. `configure`.
    action: Option<String>,
    packages: Vec<String>,
    more: usize,
    /// Within dpkg's `Errors were encountered while processing:` list.
    listing: bool,
    /// The last error the factory-finish hook (this zboot) printed.
    hook: Option<String>,
    /// The first `E:` line that is not a wrapper around an earlier error.
    error: Option<String>,
}

impl Failure {
    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.line);
                self.read_line(&line);
            } else if self.line.len() < LINE {
                self.line.push(byte);
            }
        }
    }

    /// The cause, if the output named one, for `mmdebstrap failed (...): CAUSE`.
    pub(crate) fn summary(mut self) -> Option<String> {
        if !self.line.is_empty() {
            let line = std::mem::take(&mut self.line);
            self.read_line(&line);
        }
        if !self.packages.is_empty() {
            let mut names = self.packages.join(", ");
            if self.more > 0 {
                names.push_str(&format!(" and {} more", self.more));
            }
            let action = self.action.as_deref().unwrap_or("process");
            return Some(format!("dpkg could not {action} {names}"));
        }
        self.hook.or(self.error)
    }

    fn read_line(&mut self, raw: &[u8]) {
        let text = String::from_utf8_lossy(raw);
        let text = text.trim_end_matches('\r');
        if self.listing {
            match text.strip_prefix(' ').map(str::trim) {
                Some(name) if package_name(name) => return self.add(name),
                _ => self.listing = false,
            }
        }
        if text == "Errors were encountered while processing:" {
            self.listing = true;
        } else if let Some(rest) = text.strip_prefix("dpkg: error processing ") {
            // `package NAME (--configure):` or `archive PATH (--unpack):`
            let mut words = rest.split_whitespace();
            let (kind, name, action) = (words.next(), words.next(), words.next());
            let name = match (kind, name) {
                (Some("package"), Some(name)) => name,
                // /var/cache/apt/archives/NAME_VERSION_ARCH.deb
                (Some("archive"), Some(path)) => {
                    let file = path.rsplit('/').next().unwrap_or(path);
                    file.split('_').next().unwrap_or(file)
                }
                _ => return,
            };
            if package_name(name) {
                self.add(name);
            }
            if self.action.is_none() {
                self.action = action
                    .and_then(|a| a.strip_prefix("(--"))
                    .and_then(|a| a.strip_suffix("):"))
                    .filter(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_lowercase()))
                    .map(str::to_string);
            }
        } else if let Some(message) = text.strip_prefix("zboot: ") {
            self.hook = Some(quote(message));
        } else if let Some(message) = text.strip_prefix("E: ")
            && self.error.is_none()
            && !wrapper(message)
        {
            self.error = Some(quote(message));
        }
    }

    fn add(&mut self, name: &str) {
        if self.packages.iter().any(|known| known == name) {
            return;
        }
        if self.packages.len() < NAMES {
            self.packages.push(name.to_string());
        } else {
            self.more += 1;
        }
    }
}

/// A Debian package name, optionally with `:ARCH`.
fn package_name(name: &str) -> bool {
    name.split_once(':').map_or(name, |(name, _)| name).len() >= 2
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || (i > 0 && matches!(b, b'+' | b'-' | b'.' | b':'))
        })
}

/// mmdebstrap's and apt's lines that only report that something earlier
/// failed: a subprocess, the apt-get run, a hook or the setup as a whole.
fn wrapper(message: &str) -> bool {
    [
        "setup failed",
        "child had a non-zero exit status",
        "hookhelper failed",
        "run_progress() received signal",
        "progress parsing failed",
        "listening on child socket failed",
        "command failed:",
        "chrooted hook failed",
        "Sub-process ",
    ]
    .iter()
    .any(|prefix| message.starts_with(prefix))
        || [
            " failed: process exited with",
            " failed: process was killed",
            " failed: process failed",
            " failed: error in console output",
        ]
        .iter()
        .any(|part| message.contains(part))
}

/// One line as plain text: control characters replaced, length bounded.
fn quote(message: &str) -> String {
    let mut quoted: String = message
        .trim()
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(QUOTE)
        .collect();
    if message.trim().chars().count() > QUOTE {
        quoted.push_str("...");
    }
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summarize(output: &[u8]) -> Option<String> {
        let mut failure = Failure::default();
        // Arbitrary chunk boundaries, as a pipe delivers them.
        for chunk in output.chunks(7) {
            failure.feed(chunk);
        }
        failure.summary()
    }

    #[test]
    fn a_dkms_failure_names_the_packages_dpkg_could_not_configure() {
        assert_eq!(
            summarize(include_bytes!("fixtures/mmdebstrap-dkms-failure.log")).as_deref(),
            Some(
                "dpkg could not configure linux-image-7.3.4+deb14-amd64, zfs-dkms, \
                 linux-image-amd64, zfs-initramfs"
            )
        );
    }

    #[test]
    fn without_dpkg_failures_the_first_specific_error_line_is_the_cause() {
        let output = b"I: running apt-get update...\n\
            E: Unable to locate package no-such-package\n\
            E: apt-get --yes install no-such-package failed: process exited with 100\n\
            E: setup failed: E: apt-get --yes install failed\n\
            I: main() received signal PIPE: waiting for setup...\n";
        assert_eq!(
            summarize(output).as_deref(),
            Some("Unable to locate package no-such-package")
        );
        // Wrapper lines alone name no cause.
        let output = b"E: Sub-process /usr/bin/dpkg returned an error code (1)\n\
            E: setup failed: E: apt-get --yes install failed";
        assert_eq!(summarize(output), None);
        assert_eq!(summarize(b""), None);
    }

    #[test]
    fn the_hook_error_outranks_mmdebstraps_report_of_it() {
        let output = b"zboot: no ZFS module for 7.3.4+deb14-amd64\n\
            E: command failed: /stage/zboot-factory factory-finish\n\
            E: customize hook failed\n";
        assert_eq!(
            summarize(output).as_deref(),
            Some("no ZFS module for 7.3.4+deb14-amd64")
        );
    }

    #[test]
    fn names_and_lines_stay_bounded_and_plain() {
        let mut output = b"Errors were encountered while processing:\n".to_vec();
        for n in 0..1000 {
            output.extend_from_slice(format!(" package-{n}\n").as_bytes());
        }
        // A repeated name counts once; a non-name ends the list.
        output.extend_from_slice(b" package-0\n Not A Package\n other\n");
        let summary = summarize(&output).unwrap();
        assert_eq!(
            summary,
            "dpkg could not process package-0, package-1, package-2, package-3, \
             package-4, package-5 and 994 more"
        );
        let mut failure = Failure::default();
        failure.feed(b"dpkg: error processing archive /var/cache/apt/archives/zfs-dkms_2.4.4-1_all.deb (--unpack):\n");
        assert_eq!(
            failure.summary().as_deref(),
            Some("dpkg could not unpack zfs-dkms")
        );
        let mut failure = Failure::default();
        failure.feed(b"E: \x1b[31m");
        failure.feed(&vec![b'x'; 1 << 20]);
        assert!(failure.line.len() <= LINE);
        let summary = failure.summary().unwrap();
        assert!(summary.starts_with("?[31mxxx") && summary.ends_with("..."));
        assert_eq!(summary.chars().count(), QUOTE + 3);
    }
}
