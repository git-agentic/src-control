//! On-disk `.sc/` directory layout.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Resolved paths for a repo rooted at the directory containing `.sc/`.
#[derive(Clone, Debug)]
pub struct Layout {
    pub root: PathBuf,
    pub dot_sc: PathBuf,
}

impl Layout {
    /// The directory containing `.sc` for `root`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let dot_sc = root.join(".sc");
        Layout { root, dot_sc }
    }

    /// Search `start` and its ancestors for a `.sc/` directory.
    pub fn discover(start: impl AsRef<Path>) -> Result<Layout> {
        let mut cur = Some(start.as_ref().to_path_buf());
        while let Some(dir) = cur {
            if dir.join(".sc").is_dir() {
                return Ok(Layout::at(dir));
            }
            cur = dir.parent().map(|p| p.to_path_buf());
        }
        Err(Error::NotARepo)
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.dot_sc.join("objects")
    }
    pub fn refs_heads_dir(&self) -> PathBuf {
        self.dot_sc.join("refs").join("heads")
    }
    pub fn head_path(&self) -> PathBuf {
        self.dot_sc.join("HEAD")
    }
    pub fn lock_path(&self) -> PathBuf {
        self.dot_sc.join("lock")
    }
    pub fn ref_path(&self, branch: &str) -> PathBuf {
        self.refs_heads_dir().join(branch)
    }
}
