//! Durable atomic file writes, shared by every ref/object write path.
//!
//! `.sc/` is user-owned durable state (like `.git/`), so a write that survives
//! a crash must (1) land the bytes on the platter before the rename makes them
//! visible, and (2) land the rename itself. Plain write-then-rename gives
//! readers a consistent view but can lose either on power loss; this helper
//! adds the two fsyncs Git performs: `fsync` the temp file before renaming,
//! then `fsync` the parent directory after.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-global monotonic counter appended to each temp sibling name, so
/// two threads in the same process racing to write the same target (e.g. two
/// `sc serve --http` connections landing an overlapping object) never pick
/// the identical temp path. Mirrors `TempPackGuard`'s pid + counter
/// discipline (`crates/repo/src/transport.rs`).
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically and durably write `bytes` to `path`.
///
/// Writes to a temp sibling in the same directory, named with both the
/// process id and a process-global counter (so the rename never crosses a
/// filesystem, concurrent writers in different processes never clobber each
/// other's staging file, and concurrent writers — threads or processes —
/// targeting the same final path never collide on the same temp name
/// either), fsyncs it, renames it over `path`, then fsyncs the parent
/// directory so the rename itself is durable. The parent directory must
/// exist.
pub fn atomic_write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}.{n}.tmp", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    fsync_dir(parent)
}

/// Fsync a directory so a rename/create/unlink inside it is durable. On
/// platforms where directories cannot be opened for sync (e.g. Windows), this
/// is a no-op — the write is still atomic, just not crash-durable.
pub fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_atomically_and_leaves_no_temp_sibling() {
        let dir = std::env::temp_dir().join(format!("scl-fsutil-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ref");

        atomic_write_durable(&path, b"one").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");

        // Overwrite is atomic too.
        atomic_write_durable(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");

        // No staging file lingers.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_parent_directory_is_an_error_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("scl-fsutil-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(atomic_write_durable(&dir.join("x"), b"v").is_err());
    }

    /// Two threads in the same process writing the SAME final path with the
    /// SAME bytes concurrently (the P26 `sc serve --http` thread-per-
    /// connection scenario: two connections racing to land an overlapping
    /// object) must both succeed — no ENOENT from a temp-name collision —
    /// and the final file must end up with correct bytes. This failed with
    /// the pre-fix pid-only temp name (`<obj>.<pid>.tmp`): both threads
    /// share one pid, so they raced on the identical temp sibling and the
    /// losing rename got `ENOENT`.
    #[test]
    fn concurrent_writers_same_target_dont_collide() {
        let dir = std::env::temp_dir()
            .join(format!("scl-fsutil-concurrent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("obj");

        for _ in 0..20 {
            let bytes = b"same-content".to_vec();
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let path = path.clone();
                    let bytes = bytes.clone();
                    std::thread::spawn(move || atomic_write_durable(&path, &bytes))
                })
                .collect();

            for h in handles {
                h.join().unwrap().expect("concurrent write must not fail");
            }
            assert_eq!(std::fs::read(&path).unwrap(), b"same-content");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
