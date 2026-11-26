//! Restore's forced encryption-root relink, without checking or rewrapping keys.
//! The caller proves the wrapping before using this dynamic libzfs_core helper.

#![cfg_attr(not(test), no_main)]
// The Rust test harness replaces the C entry; subprocess ABI tests exercise it.
#![cfg_attr(test, allow(dead_code))]

use std::ffi::CStr;
use std::io::{self, Write};

const DCP_CMD_FORCE_NEW_KEY: u64 = 4;
const DCP_CMD_FORCE_INHERIT: u64 = 5;
const USAGE: &[u8] = b"zboot-change-key: expected --check, or inherit|new-key POOL/DATASET\n";

// Only this module crosses the C ABI. OpenZFS has exported these signatures
// since 0.8; no development headers or unversioned linker symlink are needed.
#[allow(
    unsafe_code,
    reason = "libzfs_core FFI and C runtime entry point are confined to this module"
)]
mod native {
    use std::ffi::CStr;
    use std::ptr;

    use libc::{c_char, c_int, c_uint};

    #[repr(C)]
    struct NvList {
        _private: [u8; 0],
    }

    unsafe extern "C" {
        static stdout: *mut libc::FILE;
    }

    #[link(name = "libzfs_core.so.3", kind = "dylib", modifiers = "+verbatim")]
    unsafe extern "C" {
        fn libzfs_core_init() -> c_int;
        fn libzfs_core_fini();
        fn lzc_change_key(
            name: *const c_char,
            command: u64,
            props: *mut NvList,
            key: *mut u8,
            key_length: c_uint,
        ) -> c_int;
    }

    pub fn init() -> c_int {
        // SAFETY: Initialization takes no pointers or caller-owned state.
        unsafe { libzfs_core_init() }
    }

    pub fn fini() {
        // SAFETY: Called once after successful initialization, after all uses.
        unsafe { libzfs_core_fini() }
    }

    pub fn change_key(name: &CStr, command: u64) -> c_int {
        // SAFETY: name is NUL-terminated and lives through the call. The only
        // commands passed are FORCE_INHERIT/NEW_KEY, which require no props or
        // key material. Initialization has succeeded before this call.
        unsafe { lzc_change_key(name.as_ptr(), command, ptr::null_mut(), ptr::null_mut(), 0) }
    }

    pub fn error_message(error: c_int) -> Vec<u8> {
        // SAFETY: strerror returns either NULL or a NUL-terminated message for
        // an error number. Copy it immediately; this helper is single-threaded.
        unsafe {
            let ptr = libc::strerror(error);
            if ptr.is_null() {
                b"unknown error".to_vec()
            } else {
                CStr::from_ptr(ptr).to_bytes().to_vec()
            }
        }
    }

    pub fn write_success() -> bool {
        // SAFETY: the C runtime initializes stdout before calling main. C stdio
        // preserves write/flush errors, including EBADF, unlike Rust's stdout
        // adapter which treats an initially closed descriptor as a silent sink.
        unsafe {
            libc::fputs(c"zboot-change-key-v1:ok\n".as_ptr(), stdout) != libc::EOF
                && libc::fflush(stdout) == 0
        }
    }

    // Use the C runtime entry directly: Rust's normal startup repairs closed
    // standard descriptors and changes SIGPIPE, both observable in this helper's
    // success protocol. The C ABI also aborts rather than unwinding into libc if
    // an unexpected Rust panic occurs.
    #[cfg(not(test))]
    #[unsafe(no_mangle)]
    unsafe extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: The C runtime supplies argc non-null, NUL-terminated argument
        // pointers; each branch checks argc before indexing argv.
        match argc {
            2 => super::run(&[unsafe { CStr::from_ptr(*argv.add(1)) }]),
            3 => super::run(&[unsafe { CStr::from_ptr(*argv.add(1)) }, unsafe {
                CStr::from_ptr(*argv.add(2))
            }]),
            _ => super::run(&[]),
        }
    }
}

enum Invocation<'a> {
    Check,
    Change { name: &'a CStr, command: u64 },
}

/// POOL/DATASET[/...], with the same byte grammar as the original helper.
fn valid_dataset(name: &[u8]) -> bool {
    if name.is_empty() || name.len() >= 256 || name[0] == b'-' {
        return false;
    }
    let mut parts = 0;
    for part in name.split(|byte| *byte == b'/') {
        if part.is_empty() || part == b"." || part == b".." {
            return false;
        }
        if !part.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b' ')
        }) {
            return false;
        }
        parts += 1;
    }
    parts > 1
}

fn invocation<'a>(args: &[&'a CStr]) -> Option<Invocation<'a>> {
    match args {
        [verb] if verb.to_bytes() == b"--check" => Some(Invocation::Check),
        [verb, name] if valid_dataset(name.to_bytes()) => {
            let command = match verb.to_bytes() {
                b"inherit" => DCP_CMD_FORCE_INHERIT,
                b"new-key" => DCP_CMD_FORCE_NEW_KEY,
                _ => return None,
            };
            Some(Invocation::Change { name, command })
        }
        _ => None,
    }
}

fn report_error(operation: &[u8], name: Option<&CStr>, error: libc::c_int) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(b"zboot-change-key: ");
    let _ = stderr.write_all(operation);
    if let Some(name) = name {
        let _ = stderr.write_all(b" ");
        let _ = stderr.write_all(name.to_bytes());
    }
    let _ = stderr.write_all(b": ");
    let _ = stderr.write_all(&native::error_message(error));
    let _ = stderr.write_all(b"\n");
}

fn run(args: &[&CStr]) -> libc::c_int {
    let Some(invocation) = invocation(args) else {
        let _ = io::stderr().lock().write_all(USAGE);
        return 2;
    };
    let error = native::init();
    if error != 0 {
        report_error(b"libzfs_core_init", None, error);
        return 1;
    }
    if let Invocation::Change { name, command } = invocation {
        let error = native::change_key(name, command);
        if error != 0 {
            // Release /dev/zfs before writing stderr so an initially closed
            // fd 2 cannot alias the descriptor libzfs_core_init opened.
            native::fini();
            report_error(b"lzc_change_key", Some(name), error);
            return 1;
        }
    }
    native::fini();
    if !native::write_success() {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::valid_dataset;

    #[test]
    fn accepts_ascii_space_colon_and_the_maximum_length() {
        assert!(valid_dataset(b"rpool/secret/inner deep:1"));
        assert!(valid_dataset(b"rpool/-child/..."));
        assert!(valid_dataset(
            &[b"rpool/".as_slice(), &[b'a'; 249]].concat()
        ));
    }

    #[test]
    fn refuses_non_dataset_names_and_non_ascii_bytes() {
        for name in [
            b"".as_slice(),
            b"rpool",
            b"/rpool/a",
            b"rpool/a/",
            b"rpool//a",
            b"rpool/./a",
            b"rpool/../a",
            b"-rpool/a",
            b"rpool/a@snapshot",
            b"rpool/a#bookmark",
            b"rpool/a\n",
            b"rpool/a\x7f",
            b"rpool/a\xff",
            b"rpool/a\0",
        ] {
            assert!(!valid_dataset(name), "accepted {name:?}");
        }
        assert!(!valid_dataset(
            &[b"rpool/".as_slice(), &[b'a'; 250]].concat()
        ));
    }
}
