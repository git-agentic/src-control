//! Helpers for tests that run worker threads: a failure must end the test
//! with a diagnostic, never leave the scope or the harness waiting forever.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Stops a concurrency test from hanging: a worker that panics raises the flag
/// (and a guard built with `true` always does, on exit), so one failure
/// releases every loop instead of leaving the scope waiting on workers that
/// never see `done`.
pub(crate) struct Stop<'a>(pub &'a AtomicBool, pub bool);
impl Drop for Stop<'_> {
    fn drop(&mut self) {
        if self.1 || std::thread::panicking() {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

/// Last-known step per worker, shown by [`watchdog`] when it fires.
pub(crate) type Status = Mutex<BTreeMap<String, String>>;

/// Record `what` as `who`'s current step.
pub(crate) fn note(status: &Status, who: String, what: String) {
    status.lock().unwrap().insert(who, what);
}

/// Aborts the process with each worker's last-known step if the test is still
/// running at `limit`: a worker stuck inside a call (a lock, a bucket op, a
/// barrier whose peer panicked) can not be unwound, so the hang becomes a
/// diagnosed failure. Written straight to stderr because the harness captures
/// `eprintln!` until the test ends. Raise `finished` (see [`Stop`]) to stand
/// the watchdog down.
pub(crate) fn watchdog<'a>(
    s: &'a std::thread::Scope<'a, '_>,
    finished: &'a AtomicBool,
    status: &'a Status,
    limit: Duration,
) {
    s.spawn(move || {
        let start = std::time::Instant::now();
        while !finished.load(Ordering::SeqCst) {
            if start.elapsed() > limit {
                use std::io::Write;
                let _ = writeln!(
                    std::io::stderr(),
                    "WATCHDOG: test still running after {limit:?}; last steps: {:#?}",
                    status.lock().map(|m| m.clone()).unwrap_or_default()
                );
                std::process::abort();
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    });
}

/// Windows: assert `path` carries exactly one explicit, non-inherited
/// full-control ACE for the current user, read back with `icacls`.
#[cfg(windows)]
pub(crate) fn assert_owner_only_dacl(path: &std::path::Path) {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success(), "icacls failed: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let acl = text.replace(path.to_str().unwrap(), "");
    let aces: Vec<&str> = acl.lines().filter(|l| l.contains(":(")).collect();
    let user = std::env::var("USERNAME").unwrap().to_lowercase();
    assert_eq!(aces.len(), 1, "exactly one ACE expected:\n{text}");
    let ace = aces[0].trim().to_lowercase();
    assert!(
        ace.contains(&format!("\\{user}:(")) && ace.contains("(f)") && !ace.contains("(i)"),
        "ACE must be an explicit full-control grant to {user}:\n{text}"
    );
}
