//! Single-writer repo lock via an exclusive lock file.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// RAII guard; removes the lock file on drop.
///
/// The lock file records the holder's PID. `acquire` breaks a lock whose
/// recorded process is provably dead (a SIGKILLed `sc` never runs its `Drop`),
/// so a crash cannot brick the repo until manual cleanup. A lock with no
/// parseable PID (legacy format, or written by something else) is
/// conservatively respected — the `Locked` error names the file to remove.
pub struct RepoLock {
    path: PathBuf,
}

impl RepoLock {
    /// Acquire the lock, or `Error::Locked` if held by a live process.
    pub fn acquire(layout: &Layout) -> Result<RepoLock> {
        let path = layout.lock_path();
        // Two attempts: the second runs only after breaking a stale lock. If
        // another process wins the re-create race, we report Locked normally.
        for attempt in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    // Best-effort: the lock works even if the PID write fails;
                    // it only degrades staleness detection for the next holder.
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(RepoLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt == 0 && holder_is_dead(&path) {
                        // Stale: the recorded process is gone. Remove and retry
                        // once (NotFound = someone else broke it first — fine).
                        match std::fs::remove_file(&path) {
                            Ok(()) => continue,
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(e) => return Err(e.into()),
                        }
                    }
                    return Err(Error::Locked(path.display().to_string()));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Locked(path.display().to_string()))
    }
}

thread_local! {
    /// Index locks this thread holds (by path), so a nested critical section
    /// on the same thread reuses the held lock instead of deadlocking on it.
    static HELD_INDEX_LOCKS: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// How long [`with_index_lock`] waits for another holder before giving up.
/// Tests get a long wait: their threads queue behind durable (fsynced) writes
/// on a loaded machine; the timeout path is tested with `with_index_lock_for`.
const INDEX_LOCK_WAIT: std::time::Duration =
    std::time::Duration::from_secs(if cfg!(test) { 300 } else { 10 });

/// Run `f` holding the short-lived index lock (`.sc/index.lock`, ADR-0038
/// "Index lock", #260). It serializes the read-modify-write of the derived
/// index files (`signatures.v2`, `transcripts`, `transcript-pending`...)
/// between concurrent serve-path ingests and local commands, WITHOUT being
/// [`RepoLock`]: it is held only around a single index update, never for a
/// command's lifetime, so it never turns a busy repo into `Locked` for a
/// local `sc` command.
///
/// An advisory `flock` on a file that is never removed: the OS drops it when
/// the holder dies, so there is no stale-lock breaking (and none of its
/// races). Polls up to [`INDEX_LOCK_WAIT`], then `Error::Locked`. Reentrant per
/// thread. Lock order: this lock is a leaf. Never acquire [`RepoLock`] (or
/// wait on anything else) while holding it; taking it under `RepoLock` is fine.
pub(crate) fn with_index_lock<T>(layout: &Layout, f: impl FnOnce() -> Result<T>) -> Result<T> {
    with_index_lock_for(layout, INDEX_LOCK_WAIT, f)
}

fn with_index_lock_for<T>(
    layout: &Layout,
    wait: std::time::Duration,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let path = layout.dot_sc.join("index.lock");
    if HELD_INDEX_LOCKS.with(|h| h.borrow().contains(&path)) {
        return f();
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(Error::Locked(path.display().to_string()))
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
    }
    HELD_INDEX_LOCKS.with(|h| h.borrow_mut().push(path.clone()));
    // Pops the entry (and unlocks via `file`'s drop) even if `f` panics.
    struct Release(PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            HELD_INDEX_LOCKS.with(|h| h.borrow_mut().retain(|p| p != &self.0));
        }
    }
    let _release = Release(path);
    let out = f();
    drop(file);
    out
}

/// True only when the lock file names a PID we can *prove* is not running.
/// Unreadable file, no parseable PID, or an inconclusive probe all return
/// false (respect the lock).
pub(crate) fn holder_is_dead(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return false;
    };
    pid_is_dead(pid)
}

/// True only when `pid` is provably not running (see [`holder_is_dead`]).
pub(crate) fn pid_is_dead(pid: u32) -> bool {
    if pid == std::process::id() {
        return false; // our own pid: definitely alive
    }
    #[cfg(unix)]
    {
        // kill(pid, 0) probes existence without signalling. ESRCH = no such
        // process = provably dead. EPERM = exists but not ours = alive.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        false // no cheap probe: stay conservative
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-lock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn stale_lock_from_a_dead_process_is_broken_automatically() {
        // A SIGKILLed `sc` leaves .sc/lock behind; the next invocation must
        // recover instead of bricking the repo until manual cleanup.
        let layout = tmp_layout("stale");
        // A PID above every platform's max is guaranteed dead.
        std::fs::write(layout.lock_path(), "999999999\n").unwrap();
        let lock = RepoLock::acquire(&layout).expect("stale lock must be broken");
        drop(lock);
        assert!(!layout.lock_path().exists());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn lock_held_by_a_live_process_stays_locked() {
        let layout = tmp_layout("live");
        // Our own PID is definitely alive.
        std::fs::write(layout.lock_path(), format!("{}\n", std::process::id())).unwrap();
        assert!(matches!(RepoLock::acquire(&layout), Err(Error::Locked(_))));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn legacy_empty_lock_file_is_conservatively_respected() {
        // Pre-upgrade lock files carry no PID; we can't prove the holder is
        // dead, so refuse (the error names the file for manual removal).
        let layout = tmp_layout("legacy");
        std::fs::write(layout.lock_path(), "").unwrap();
        assert!(matches!(RepoLock::acquire(&layout), Err(Error::Locked(_))));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn acquire_writes_our_pid() {
        let layout = tmp_layout("pid");
        let _lock = RepoLock::acquire(&layout).unwrap();
        let content = std::fs::read_to_string(layout.lock_path()).unwrap();
        assert_eq!(content.trim(), std::process::id().to_string());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn index_lock_is_not_the_repo_lock() {
        // Holding either never makes the other fail: a local command keeps
        // `RepoLock` for its lifetime while a serve-path ingest takes the short
        // index lock, and vice versa (#260).
        let layout = tmp_layout("idx-indep");
        let repo_lock = RepoLock::acquire(&layout).unwrap();
        with_index_lock(&layout, || Ok(())).unwrap();
        assert!(matches!(RepoLock::acquire(&layout), Err(Error::Locked(_))));
        drop(repo_lock);
        with_index_lock(&layout, || {
            // Reentrant on the same thread, and RepoLock is still free.
            with_index_lock(&layout, || Ok(()))?;
            drop(RepoLock::acquire(&layout)?);
            Ok(())
        })
        .unwrap();
        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }

    #[test]
    fn index_lock_serializes_threads_and_times_out_with_locked() {
        let layout = tmp_layout("idx-wait");
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let l2 = layout.clone();
        let holder = std::thread::spawn(move || {
            with_index_lock(&l2, || {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
        });
        held_rx.recv().unwrap();
        // Another thread of the same process waits, then gives up.
        assert!(matches!(
            with_index_lock_for(&layout, std::time::Duration::from_millis(100), || Ok(())),
            Err(Error::Locked(_))
        ));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        // Released: free again, and the failed waiter left no held entry.
        with_index_lock(&layout, || Ok(())).unwrap();
        std::fs::remove_dir_all(&layout.root).unwrap();
        assert!(!layout.root.exists());
    }
}
