//! A caller-set observation deadline through the supported API, against fake
//! `zpool` and `zfs` programs on PATH. One test in its own binary, so the
//! process's descriptor, thread and child counts are its own.
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zfs_tools::{
    InventoryRequest, ObservationStop, QueryCleanup, observe_inventory, observe_management_within,
};

fn entries(dir: &str) -> usize {
    fs::read_dir(dir).unwrap().count()
}
/// Every child of every thread of this process, by PID.
fn children() -> Vec<String> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .flat_map(|task| {
            let path = task.unwrap().path().join("children");
            fs::read_to_string(path)
                .unwrap()
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}
fn pid_in(file: &Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(pid) = fs::read_to_string(file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "no pid in {}", file.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}
/// Gone, or a zombie its new parent has not yet reaped.
fn ended(pid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => return true,
            Ok(stat)
                if stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, s)| s.starts_with('Z')) =>
            {
                return true;
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    false
}
fn fake(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

const EXPIRED: &str = "observation exceeded its 300ms deadline: zpool was still running at the \
                       observation's 300ms deadline; SIGKILL was sent to its process group and its leader reaped";

#[test]
fn an_expired_observation_kills_reaps_and_leaks_nothing() {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "zfs-tools-observation-deadline-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let d = dir.display();
    fake(
        &dir,
        "zpool",
        &format!(
            "case $(/bin/cat {d}/mode) in\n\
             empty) exit 0 ;;\n\
             descendant) /bin/sleep 30 & echo $! > {d}/descendant; echo partial; exit 0 ;;\n\
             hang) echo $$ > {d}/leader; exec /bin/sleep 30 ;;\n\
             esac\nexit 2"
        ),
    );
    fake(&dir, "zfs", "echo 'fake zfs is not queried' >&2; exit 1");
    // SAFETY: this binary's only test sets it before any query runs.
    #[allow(unsafe_code, reason = "the fake programs are found on PATH")]
    unsafe {
        std::env::set_var("PATH", &dir)
    };
    let mode = |m: &str| fs::write(dir.join("mode"), m).unwrap();
    let within = Duration::from_millis(300);

    // A finished observation is the same with and without a deadline: no
    // pool named tank is imported, so the root is absent.
    mode("empty");
    let unbounded = observe_inventory(&InventoryRequest::new("tank").unwrap()).unwrap();
    let bounded =
        observe_inventory(&InventoryRequest::new("tank").unwrap().within(within)).unwrap();
    assert_eq!(bounded, unbounded);
    assert_eq!(bounded.pool_guid(), None);
    assert!(bounded.datasets().is_empty());

    let (fds, threads) = (entries("/proc/self/fd"), entries("/proc/self/task"));
    assert_eq!(children(), Vec::<String>::new());

    // The leader prints a partial row and exits; its child keeps stdout open.
    mode("descendant");
    let started = Instant::now();
    let error =
        observe_inventory(&InventoryRequest::new("tank").unwrap().within(within)).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        error.observation_stop(),
        Some(ObservationStop::Deadline(QueryCleanup::LeaderReaped))
    );
    assert_eq!(error.to_string(), EXPIRED);
    assert!(ended(pid_in(&dir.join("descendant"))), "descendant killed");

    // A leader that never exits.
    mode("hang");
    let error =
        observe_inventory(&InventoryRequest::new("tank").unwrap().within(within)).unwrap_err();
    assert_eq!(
        error.observation_stop(),
        Some(ObservationStop::Deadline(QueryCleanup::LeaderReaped))
    );
    assert_eq!(error.to_string(), EXPIRED);
    let leader = pid_in(&dir.join("leader"));
    assert!(
        !Path::new(&format!("/proc/{leader}")).exists(),
        "leader reaped"
    );

    fs::remove_file(dir.join("leader")).unwrap();
    let error = observe_management_within("tank/vm", within).unwrap_err();
    assert_eq!(
        error.observation_stop(),
        Some(ObservationStop::Deadline(QueryCleanup::LeaderReaped))
    );
    assert_eq!(error.to_string(), EXPIRED);
    let leader = pid_in(&dir.join("leader"));
    assert!(
        !Path::new(&format!("/proc/{leader}")).exists(),
        "leader reaped"
    );

    let error = observe_inventory(
        &InventoryRequest::new("tank")
            .unwrap()
            .within(Duration::ZERO),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "an observation deadline must be nonzero");
    assert_eq!(error.observation_stop(), None);

    assert_eq!(entries("/proc/self/fd"), fds, "no descriptor leaked");
    assert_eq!(entries("/proc/self/task"), threads, "no thread leaked");
    assert_eq!(children(), Vec::<String>::new(), "no child left unreaped");

    // With SIGCHLD ignored the kernel reaps children itself, so a PID could be
    // reused before the group kill: refused before any query starts.
    mode("hang");
    let _ = fs::remove_file(dir.join("leader"));
    // SAFETY: this binary's only test; nothing else changes signal state.
    #[allow(unsafe_code, reason = "setting SIGCHLD for the refusal case")]
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN)
    };
    let error =
        observe_inventory(&InventoryRequest::new("tank").unwrap().within(within)).unwrap_err();
    #[allow(unsafe_code, reason = "restoring SIGCHLD")]
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL)
    };
    assert_eq!(
        error.observation_stop(),
        Some(ObservationStop::ChildrenNotWaitable)
    );
    assert_eq!(
        error.to_string(),
        "bounded observation refused: SIGCHLD is ignored or SA_NOCLDWAIT is set, so this \
         process's children are reaped without it and their PIDs cannot be kept from reuse"
    );
    assert!(!dir.join("leader").exists(), "no query started");
    fs::remove_dir_all(&dir).unwrap();
}
