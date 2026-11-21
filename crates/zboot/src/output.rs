//! Standard output and error that outlive their reader. zboot keeps SIGPIPE
//! ignored so a closed pipe can never kill it while a native `zfs send` or
//! `receive` runs; a write to a closed pipe answers EPIPE instead. Std's
//! `print!` family panics on that error. These replacements, shadowing them
//! crate-wide from `main.rs`, stop writing that stream after its first EPIPE
//! and never panic, so the verb carries on and exits with its own status.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);
static STDERR_CLOSED: AtomicBool = AtomicBool::new(false);

/// A writer that discards what it is given once its stream's reader has gone.
/// Other write errors still reach the caller.
pub(crate) struct Tolerant<W> {
    inner: W,
    closed: &'static AtomicBool,
}

/// Standard output that stops writing after the first EPIPE.
pub(crate) fn stdout() -> Tolerant<io::Stdout> {
    Tolerant {
        inner: io::stdout(),
        closed: &STDOUT_CLOSED,
    }
}

/// Standard error that stops writing after the first EPIPE.
pub(crate) fn stderr() -> Tolerant<io::Stderr> {
    Tolerant {
        inner: io::stderr(),
        closed: &STDERR_CLOSED,
    }
}

impl<W: Write> Tolerant<W> {
    fn absorb(&self, result: io::Result<()>) -> io::Result<()> {
        match result {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed.store(true, Ordering::Relaxed);
                Ok(())
            }
            result => result,
        }
    }
}

impl<W: Write> Write for Tolerant<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Ok(buf.len());
        }
        match self.inner.write(buf) {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed.store(true, Ordering::Relaxed);
                Ok(buf.len())
            }
            result => result,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let result = self.inner.flush();
        self.absorb(result)
    }
}

fn emit(mut stream: impl Write, args: std::fmt::Arguments, newline: bool) {
    // One write per call keeps a line whole between threads, as std's does.
    let mut text = args.to_string();
    if newline {
        text.push('\n');
    }
    // Std panics here; a failed diagnostic is not worth stopping a verb for.
    let _ = stream.write_all(text.as_bytes());
}

/// `print!` and `println!`. Test builds keep std's, which the harness captures.
pub(crate) fn print(args: std::fmt::Arguments, newline: bool) {
    if cfg!(test) {
        if newline {
            std::println!("{args}");
        } else {
            std::print!("{args}");
        }
    } else {
        emit(stdout(), args, newline);
    }
}

/// `eprint!` and `eprintln!`.
pub(crate) fn eprint(args: std::fmt::Arguments, newline: bool) {
    if cfg!(test) {
        if newline {
            std::eprintln!("{args}");
        } else {
            std::eprint!("{args}");
        }
    } else {
        emit(stderr(), args, newline);
    }
}

/// Name the user-supplied `path` in an error about it, keeping its kind, so a
/// missing file reads `--key /x.pub: No such file or directory (os error 2)`.
pub(crate) fn naming(what: &str, path: &std::path::Path) -> impl FnOnce(io::Error) -> io::Error {
    let named = if what.is_empty() {
        path.display().to_string()
    } else {
        format!("{what} {}", path.display())
    };
    move |error| io::Error::new(error.kind(), format!("{named}: {error}"))
}

macro_rules! print {
    ($($arg:tt)*) => { $crate::output::print(format_args!($($arg)*), false) };
}

macro_rules! println {
    () => { $crate::output::print(format_args!(""), true) };
    ($($arg:tt)*) => { $crate::output::print(format_args!($($arg)*), true) };
}

macro_rules! eprint {
    ($($arg:tt)*) => { $crate::output::eprint(format_args!($($arg)*), false) };
}

macro_rules! eprintln {
    () => { $crate::output::eprint(format_args!(""), true) };
    ($($arg:tt)*) => { $crate::output::eprint(format_args!($($arg)*), true) };
}

#[cfg(test)]
mod tests {
    use super::{Tolerant, emit};
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A pipe whose reader has closed answers EPIPE (SIGPIPE is ignored in
    /// Rust programs); the writer must absorb it, remember it and stop.
    #[test]
    fn closed_pipe_is_absorbed_and_remembered() {
        static CLOSED: AtomicBool = AtomicBool::new(false);
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut stream = Tolerant {
            inner: writer,
            closed: &CLOSED,
        };
        emit(&mut stream, format_args!("first line"), true);
        assert!(CLOSED.load(Ordering::Relaxed));
        assert_eq!(stream.write(b"more").unwrap(), 4);
        stream.flush().unwrap();
        writeln!(stream, "still nothing to panic about").unwrap();
    }

    /// Other errors still reach a caller that asks, such as `dialogue`.
    #[test]
    fn other_errors_still_surface() {
        static CLOSED: AtomicBool = AtomicBool::new(false);
        let mut stream = Tolerant {
            inner: std::fs::File::open("/dev/null").unwrap(),
            closed: &CLOSED,
        };
        assert!(stream.write(b"x").is_err());
        assert!(!CLOSED.load(Ordering::Relaxed));
    }
}
