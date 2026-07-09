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

/// True only when the lock file names a PID we can *prove* is not running.
/// Unreadable file, no parseable PID, or an inconclusive probe all return
/// false (respect the lock).
fn holder_is_dead(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return false;
    };
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
}
