//! Read-only signature admission helper; absence is the sole success protocol.
#![cfg_attr(not(test), no_main)]
// The Rust test harness replaces the C entry; subprocess ABI tests exercise it.
#![cfg_attr(test, allow(dead_code))]

use std::ffi::CStr;
use std::io::{self, Write};

fn valid_path(path: &[u8]) -> bool {
    let Some(relative) = path.strip_prefix(b"/dev/") else {
        return false;
    };
    !path.iter().any(|&byte| byte < 32 || byte == 127)
        && relative
            .split(|&byte| byte == b'/')
            .all(|segment| !segment.is_empty() && segment != b"." && segment != b"..")
}

enum Outcome {
    None,
    CannotOpen,
    SetupFailed,
    Locked,
    Signature,
    Ambiguous,
    ProbeError {
        result: libc::c_int,
        errno: libc::c_int,
    },
}

impl Outcome {
    fn exit_code(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Signature => 2,
            Self::Ambiguous => 3,
            _ => 1,
        }
    }

    fn report(&self) {
        let mut stderr = io::stderr().lock();
        // As with the original fputs/fprintf diagnostics, stderr errors do not
        // turn a refusal into a success or replace its exit status.
        let _ = match self {
            Self::None => return,
            Self::CannotOpen => writeln!(stderr, "zboot signature probe: cannot open block device"),
            Self::SetupFailed => writeln!(stderr, "zboot signature probe: setup failed"),
            Self::Locked => writeln!(
                stderr,
                "zboot signature probe: locked device or unavailable lock status"
            ),
            Self::Signature => writeln!(stderr, "zboot signature probe: signature found"),
            Self::Ambiguous => writeln!(stderr, "zboot signature probe: ambiguous signatures"),
            Self::ProbeError { result, errno } => writeln!(
                stderr,
                "zboot signature probe: probe error result={result} errno={errno}"
            ),
        };
    }
}

// This private boundary owns all foreign pointers and file descriptors. The
// remainder of the helper cannot issue ioctls or call libblkid directly.
#[allow(unsafe_code, reason = "Linux/libblkid FFI is confined to this module")]
mod native {
    use super::{CStr, Outcome};
    use libc::{c_char, c_int, c_ulong};
    use std::mem::MaybeUninit;
    use std::ptr::NonNull;

    #[repr(C)]
    struct BlkidProbe {
        _opaque: [u8; 0],
    }

    // linux/sed-opal.h: struct opal_status contains two __u32 members.
    #[derive(Default)]
    #[repr(C)]
    struct OpalStatus {
        flags: u32,
        reserved: u32,
    }

    const OPAL_FL_SUPPORTED: u32 = 0x0000_0001;
    const OPAL_FL_LOCKED: u32 = 0x0000_0008;
    // IOC_OPAL_GET_STATUS = _IOR('p', 236, struct opal_status).
    const IOC_OPAL_GET_STATUS: c_ulong = libc::_IOR::<OpalStatus>(b'p' as u32, 236) as c_ulong;
    // blkid/blkid.h superblock flags.
    const BLKID_SUBLKS_LABEL: c_int = 1 << 1;
    const BLKID_SUBLKS_UUID: c_int = 1 << 3;
    const BLKID_SUBLKS_TYPE: c_int = 1 << 5;
    const BLKID_SUBLKS_USAGE: c_int = 1 << 7;
    const BLKID_SUBLKS_MAGIC: c_int = 1 << 9;
    const BLKID_SUBLKS_BADCSUM: c_int = 1 << 10;
    const SUPERBLOCK_FLAGS: c_int = BLKID_SUBLKS_MAGIC
        | BLKID_SUBLKS_TYPE
        | BLKID_SUBLKS_USAGE
        | BLKID_SUBLKS_LABEL
        | BLKID_SUBLKS_UUID
        | BLKID_SUBLKS_BADCSUM;

    // Keep the C symbol names used by the existing linker-wrapper ABI tests.
    // On the supported GNU Linux targets libc::stat is the native stat layout.
    unsafe extern "C" {
        fn open(path: *const c_char, flags: c_int, ...) -> c_int;
        fn fstat(fd: c_int, stat: *mut libc::stat) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        static stdout: *mut libc::FILE;
    }

    #[link(name = "blkid")]
    unsafe extern "C" {
        fn blkid_new_probe() -> *mut BlkidProbe;
        fn blkid_free_probe(probe: *mut BlkidProbe);
        // blkid_loff_t is int64_t, independent of libc's off_t.
        fn blkid_probe_set_device(probe: *mut BlkidProbe, fd: c_int, off: i64, size: i64) -> c_int;
        fn blkid_probe_enable_superblocks(probe: *mut BlkidProbe, enable: c_int) -> c_int;
        fn blkid_probe_set_superblocks_flags(probe: *mut BlkidProbe, flags: c_int) -> c_int;
        fn blkid_probe_enable_partitions(probe: *mut BlkidProbe, enable: c_int) -> c_int;
        fn blkid_probe_set_partitions_flags(probe: *mut BlkidProbe, flags: c_int) -> c_int;
        fn blkid_probe_enable_topology(probe: *mut BlkidProbe, enable: c_int) -> c_int;
        fn blkid_do_safeprobe(probe: *mut BlkidProbe) -> c_int;
    }

    struct Probe(NonNull<BlkidProbe>);

    impl Drop for Probe {
        fn drop(&mut self) {
            // SAFETY: this non-null probe was allocated by blkid_new_probe and
            // is owned only by this value; freeing it does not close our fd.
            unsafe { blkid_free_probe(self.0.as_ptr()) };
        }
    }

    fn unlocked(fd: c_int) -> bool {
        let mut status = OpalStatus::default();
        clear_errno();
        // SAFETY: fd is live and status has the exact writable kernel ABI
        // layout required by IOC_OPAL_GET_STATUS, including its reserved word.
        let result = unsafe { ioctl(fd, IOC_OPAL_GET_STATUS, &mut status as *mut OpalStatus) };
        // Capture errno before any other operation can change the thread-local
        // value. Only a -1 result makes ENOTTY/EOPNOTSUPP an unsupported ioctl.
        let errno = io_errno();
        if result == 0 {
            status.flags & OPAL_FL_SUPPORTED != 0 && status.flags & OPAL_FL_LOCKED == 0
        } else {
            result == -1 && (errno == libc::ENOTTY || errno == libc::EOPNOTSUPP)
        }
    }

    fn clear_errno() {
        // SAFETY: GNU libc supplies a valid writable pointer to this thread's errno.
        unsafe { *libc::__errno_location() = 0 };
    }

    fn io_errno() -> c_int {
        // SAFETY: GNU libc supplies a valid pointer to this thread's errno.
        unsafe { *libc::__errno_location() }
    }

    fn inspect(fd: c_int) -> Outcome {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is live and fstat receives writable, correctly sized and
        // aligned storage; its contents are used only after a successful call.
        if unsafe { fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Outcome::CannotOpen;
        }
        // SAFETY: the successful fstat initialized every field we read.
        let mode = unsafe { (*stat.as_ptr()).st_mode };
        if mode & libc::S_IFMT != libc::S_IFBLK {
            return Outcome::CannotOpen;
        }
        // SAFETY: allocation requires no arguments; null is checked below.
        let Some(pointer) = NonNull::new(unsafe { blkid_new_probe() }) else {
            return Outcome::SetupFailed;
        };
        let probe = Probe(pointer);
        let pointer = probe.0.as_ptr();
        // SAFETY: pointer is an owned, live probe; fd stays open until probe
        // destruction. Short-circuiting preserves the original setup order.
        let configured = unsafe {
            blkid_probe_set_device(pointer, fd, 0, 0) == 0
                && blkid_probe_enable_superblocks(pointer, 1) == 0
                && blkid_probe_set_superblocks_flags(pointer, SUPERBLOCK_FLAGS) == 0
                && blkid_probe_enable_partitions(pointer, 1) == 0
                // Parent GPT entry metadata is not a signature on this leaf.
                && blkid_probe_set_partitions_flags(pointer, 0) == 0
                && blkid_probe_enable_topology(pointer, 0) == 0
        };
        if !configured {
            return Outcome::SetupFailed;
        }
        // For caller-admitted NVMe/virtio leaves: a successful status lacking
        // SUPPORTED can mask failed discovery, so it must also refuse.
        if !unlocked(fd) {
            return Outcome::Locked;
        }
        clear_errno();
        // SAFETY: pointer is still a live configured probe. Read errno immediately.
        let result = unsafe { blkid_do_safeprobe(pointer) };
        let errno = io_errno();
        match result {
            1 => Outcome::None,
            0 => Outcome::Signature,
            -2 => Outcome::Ambiguous,
            result => Outcome::ProbeError { result, errno },
        }
    }

    pub(super) fn run(path: &CStr) -> u8 {
        // SAFETY: path is NUL terminated and flags require no variadic mode;
        // every successful open below has exactly one matching close.
        let fd = unsafe {
            open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            Outcome::CannotOpen.report();
            return Outcome::CannotOpen.exit_code();
        }
        let outcome = inspect(fd);
        // SAFETY: fd is ours and any libblkid probe has already been freed.
        // Close before writing stderr so an initially closed fd 2 cannot alias
        // the device descriptor. Do not retry close after EINTR.
        let close_failed = unsafe { close(fd) } != 0;
        outcome.report();
        let mut result = outcome.exit_code();
        if close_failed && result == 0 {
            result = 1;
        }
        result
    }

    pub(super) fn write_success() -> bool {
        // SAFETY: the C runtime initializes stdout before calling main. C stdio
        // preserves write/flush errors, including EBADF, unlike Rust's stdout
        // adapter which treats an initially closed descriptor as a silent sink.
        unsafe {
            libc::fputs(c"zboot-signatures-v1:none\n".as_ptr(), stdout) != libc::EOF
                && libc::fflush(stdout) == 0
        }
    }

    // Enter through the C runtime, preserving initially closed descriptors and
    // the inherited SIGPIPE disposition. Rust's usual std::rt startup would
    // reopen closed stdout as /dev/null, which could falsely report success.
    #[cfg(not(test))]
    #[unsafe(no_mangle)]
    unsafe extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
        if argc != 3 {
            return super::usage();
        }
        // SAFETY: the C runtime passes argc non-null NUL-terminated argv strings.
        // argc == 3 above establishes both indexed entries. CStr retains the raw
        // Unix bytes without Unicode conversion or allocating a replacement argv.
        let (separator, path) =
            unsafe { (CStr::from_ptr(*argv.add(1)), CStr::from_ptr(*argv.add(2))) };
        super::run(separator.to_bytes(), path)
    }
}

fn usage() -> libc::c_int {
    let _ = io::stderr().write_all(b"zboot signature probe: expected -- /dev/DEVICE\n");
    2
}

fn run(separator: &[u8], path: &CStr) -> libc::c_int {
    if separator != b"--" || !valid_path(path.to_bytes()) {
        return usage();
    }
    let mut result = native::run(path);
    if result == 0 && !native::write_success() {
        result = 1;
    }
    libc::c_int::from(result)
}

#[cfg(test)]
mod tests {
    use super::valid_path;

    #[test]
    fn device_path_validation_preserves_raw_unix_bytes() {
        for path in [
            b"/dev/nvme0n1p1".as_slice(),
            b"/dev/disk/by-id/a b",
            b"/dev/\xff",
        ] {
            assert!(valid_path(path), "{path:?}");
        }
        for path in [
            b"/dev/".as_slice(),
            b"/dev",
            b"/tmp/leaf",
            b"/dev/../leaf",
            b"/dev/./leaf",
            b"/dev//leaf",
            b"/dev/leaf/",
            b"/dev/leaf\0",
            b"/dev/leaf\n",
            b"/dev/leaf\x7f",
        ] {
            assert!(!valid_path(path), "{path:?}");
        }
    }
}
