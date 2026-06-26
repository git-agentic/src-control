//! HEAD and branch ref reading/writing. HEAD is symbolic (names a branch).

use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

const HEAD_PREFIX: &str = "ref: refs/heads/";

/// Write `HEAD` as a symbolic ref to `branch`.
pub fn write_head(layout: &Layout, branch: &str) -> Result<()> {
    atomic_write(&layout.head_path(), format!("{HEAD_PREFIX}{branch}\n").as_bytes())
}

/// The branch currently named by `HEAD`.
pub fn current_branch(layout: &Layout) -> Result<String> {
    let text = std::fs::read_to_string(layout.head_path())?;
    let line = text.trim();
    line.strip_prefix(HEAD_PREFIX)
        .map(|b| b.to_string())
        .ok_or_else(|| Error::BadRef(format!("HEAD is not symbolic: {line}")))
}

/// The tip snapshot of `branch`, or `None` if the branch is unborn.
pub fn read_branch_tip(layout: &Layout, branch: &str) -> Result<Option<ObjectId>> {
    let path = layout.ref_path(branch);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let hex = text.trim();
            ObjectId::from_str(hex)
                .map(Some)
                .map_err(|_| Error::BadRef(format!("ref {branch} has bad id: {hex}")))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Point `branch` at `id` (atomic).
pub fn write_branch_tip(layout: &Layout, branch: &str, id: &ObjectId) -> Result<()> {
    std::fs::create_dir_all(layout.refs_heads_dir())?;
    atomic_write(&layout.ref_path(branch), format!("{}\n", id.to_hex()).as_bytes())
}

/// The tip recorded for `refs/remotes/<remote>/<branch>`, or None if absent.
pub fn read_remote_tip(layout: &Layout, remote: &str, branch: &str) -> Result<Option<ObjectId>> {
    let path = layout.remote_ref_path(remote, branch);
    match std::fs::read_to_string(&path) {
        Ok(text) => ObjectId::from_str(text.trim())
            .map(Some)
            .map_err(|_| Error::BadRef(format!("remote ref {remote}/{branch} has bad id"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Set `refs/remotes/<remote>/<branch>` to `id` (atomic).
pub fn write_remote_tip(layout: &Layout, remote: &str, branch: &str, id: &ObjectId) -> Result<()> {
    let dir = layout.refs_remotes_dir().join(remote);
    std::fs::create_dir_all(&dir)?;
    atomic_write(&dir.join(branch), format!("{}\n", id.to_hex()).as_bytes())
}

/// The tip of the branch HEAD names (or None if unborn).
pub fn head_tip(layout: &Layout) -> Result<Option<ObjectId>> {
    read_branch_tip(layout, &current_branch(layout)?)
}

/// Write `bytes` to `path` via a temp file + rename so a reader never observes
/// a half-written ref. The temp sibling is per-process (`<name>.<pid>.tmp`) so
/// writers in different processes never clobber each other's temp file; the
/// rename itself is atomic. The single-writer repo lock
/// ([`crate::lock::RepoLock`]) still serializes the final ref content.
fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::RepoLock;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-repo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(layout.refs_heads_dir()).unwrap();
        layout
    }

    #[test]
    fn head_and_branch_roundtrip() {
        let layout = tmp_layout("refs");
        write_head(&layout, "main").unwrap();
        assert_eq!(current_branch(&layout).unwrap(), "main");
        assert_eq!(head_tip(&layout).unwrap(), None); // unborn
        let id = ObjectId::of(b"snap");
        write_branch_tip(&layout, "main", &id).unwrap();
        assert_eq!(head_tip(&layout).unwrap(), Some(id));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn lock_is_exclusive() {
        let layout = tmp_layout("lock");
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        let l1 = RepoLock::acquire(&layout).unwrap();
        assert!(matches!(RepoLock::acquire(&layout), Err(Error::Locked(_))));
        drop(l1);
        let _l2 = RepoLock::acquire(&layout).unwrap(); // freed
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
