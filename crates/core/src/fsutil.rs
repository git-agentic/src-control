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

/// Atomically and durably write `bytes` to `path`.
///
/// Writes to a per-process temp sibling in the same directory (so the rename
/// never crosses a filesystem and concurrent writers in different processes
/// never clobber each other's staging file), fsyncs it, renames it over
/// `path`, then fsyncs the parent directory so the rename itself is durable.
/// The parent directory must exist.
pub fn atomic_write_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
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
}
