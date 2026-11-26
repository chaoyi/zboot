//! Process-level proof that a native mutator keeps the exact writer flock after
//! its frontend dies. The only native program is a private test shell reader.
use super::*;
use crate::engine::lock::{LockError, WriterLock};
use std::{
    fs,
    path::Path,
    process::Child,
    time::{Duration, Instant},
};

const CASE: &str = "ZFS_TOOLS_CUSTODY_CASE";
const ROOT: &str = "ZFS_TOOLS_CUSTODY_ROOT";
const WORKER: &str = "engine::native::custody_tests::native_custody_worker";

#[test]
fn native_custody_worker() {
    let Some(mode) = std::env::var_os(CASE) else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
    let held = WriterLock::acquire_at(
        &root.join("writer.lock"),
        "custody test",
        Duration::ZERO,
        |_| {},
    )
    .unwrap();
    let args = [
        "-c".into(),
        "printf '%s\\n' \"$$\" > \"$1\"; while [ ! -e \"$2\" ]; do sleep 0.05; done; : > \"$3\""
            .into(),
        "native-custody-test".into(),
        root.join("native.pid").to_str().unwrap().into(),
        root.join("finish").to_str().unwrap().into(),
        root.join("native.done").to_str().unwrap().into(),
    ];
    if mode == "restored" {
        with_writer_lock(&held, || ()).unwrap();
        run_mutating("/bin/sh", &args).unwrap();
    } else {
        with_writer_lock(&held, || {
            if mode == "mutator" {
                run_mutating("/bin/sh", &args)
            } else {
                run("/bin/sh", &args)
            }
        })
        .unwrap()
        .unwrap();
    }
}

struct Fixture {
    root: std::path::PathBuf,
    worker: Child,
}
impl Fixture {
    fn start(mode: &str) -> Self {
        let root = std::env::temp_dir().join(format!("zfs-custody-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let worker = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", WORKER, "--nocapture"])
            .env(CASE, mode)
            .env(ROOT, &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut fixture = Self { root, worker };
        let limit = Instant::now() + Duration::from_secs(10);
        while !fixture.root.join("native.pid").is_file() {
            assert!(Instant::now() < limit, "native child did not start");
            assert!(
                fixture.worker.try_wait().unwrap().is_none(),
                "worker exited before native dispatch"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        fixture
    }
    fn kill_frontend(&mut self) {
        self.worker.kill().unwrap();
        self.worker.wait().unwrap();
    }
    fn finish(&self) {
        fs::write(self.root.join("finish"), b"done").unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::write(self.root.join("finish"), b"done");
        let _ = self.worker.kill();
        let _ = self.worker.wait();
        // Reader/restored children do not hold this writer lock, so flock
        // availability alone cannot establish that they consumed the finish
        // signal. Wait for their final no-more-reads acknowledgement too.
        let limit = Instant::now() + Duration::from_secs(5);
        while !self.root.join("native.done").is_file() && Instant::now() < limit {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.root.join("native.done").is_file()
            && wait_for_lock(&self.root, Duration::from_secs(5))
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
fn wait_for_lock(root: &Path, bound: Duration) -> bool {
    let limit = Instant::now() + bound;
    loop {
        match WriterLock::acquire_at(
            &root.join("writer.lock"),
            "custody readback",
            Duration::ZERO,
            |_| {},
        ) {
            Ok(held) => {
                drop(held);
                return true;
            }
            Err(LockError::Busy { .. }) if Instant::now() < limit => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => return false,
        }
    }
}

#[test]
fn mutator_keeps_writer_custody_after_frontend_death() {
    let mut fixture = Fixture::start("mutator");
    fixture.kill_frontend();
    assert!(
        !wait_for_lock(&fixture.root, Duration::from_millis(100)),
        "a live mutator lost writer custody with its frontend"
    );
    fixture.finish();
    assert!(
        wait_for_lock(&fixture.root, Duration::from_secs(5)),
        "writer custody was not released after native completion"
    );
}

#[test]
fn readers_and_completed_dispatch_contexts_do_not_leak_writer_custody() {
    for mode in ["reader", "restored"] {
        let mut fixture = Fixture::start(mode);
        fixture.kill_frontend();
        assert!(
            wait_for_lock(&fixture.root, Duration::from_secs(2)),
            "read-only or restored context unexpectedly retained writer custody: {mode}"
        );
        fixture.finish();
    }
}
