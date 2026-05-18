//! `zboot-boot` — runs as PID 1 inside the initrd of the EFI bundle.
//!
//! Renders the BE forest as an interactive TUI; selection calls
//! `kexec::handoff` (a no-op on dev hosts unless the gate is open —
//! see `kexec.rs`).

#![doc(html_no_source)]

use anyhow::Result;
use clap::Parser;

use zboot_boot::{menu, preinit};

#[derive(Debug, Parser)]
#[command(
    name = "zboot-boot",
    version,
    about = "zboot bootloader (initrd PID 1)"
)]
struct Cli {}

fn main() -> Result<()> {
    let _ = Cli::parse();
    let mut stdout = std::io::stdout();

    // PID 1 starts with a bare userspace — no /proc, no /sys, no PATH,
    // no kernel modules loaded. Run the bootstrap before any code that
    // shells out (`Command::new(...)` ENOENTs without /proc; `zpool`
    // can't talk to a kernel that hasn't loaded `zfs.ko`). Skipped on
    // dev-host where the surrounding system already has all of this.
    if std::process::id() == 1
        && let Err(e) = preinit::run()
    {
        eprintln!("zboot-boot/preinit: {e:#}");
    }

    let result = menu::run(&mut stdout);
    // PID 1 must never exit — the kernel panics if it does. After menu
    // selection the path is `kexec(2)`, which never returns. If we reach
    // here, either the menu errored or finished without handing off
    // (dev-host or no-tty fallback). Print errors, then sleep silently
    // so the serial log doesn't get a scary banner.
    if let Err(ref e) = result {
        eprintln!("zboot-boot: error: {e:#}");
    }
    loop {
        std::thread::park();
    }
}
