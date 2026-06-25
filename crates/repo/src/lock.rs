//! Single-writer repo lock via an exclusive lock file.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// RAII guard; removes the lock file on drop.
pub struct RepoLock {
    path: PathBuf,
}

impl RepoLock {
    /// Acquire the lock, or `Error::Locked` if already held.
    pub fn acquire(layout: &Layout) -> Result<RepoLock> {
        let path = layout.lock_path();
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => Ok(RepoLock { path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(Error::Locked(path.display().to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
