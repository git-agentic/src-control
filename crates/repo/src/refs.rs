//! HEAD and branch ref reading/writing. HEAD is symbolic (names a branch).

use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;
// Smaller diff than moving the function: repo.rs's strict, single-component
// `validate_branch_name` (rejects `/`, unlike this module's own
// `is_unsafe_ref_component`) is the right guard for local branch writes —
// `Repo::branch`'s existing calls to it become redundant belt-and-suspenders.
pub(crate) use crate::repo::validate_branch_name;

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
    validate_branch_name(branch)?;
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
    validate_branch_name(branch)?;
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

/// Set `refs/remotes/<remote>/<branch>` to `id` (atomic). Defense-in-depth:
/// both components are traversal-guarded here too, so even a hand-edited
/// `.sc/config` remote (which bypasses `remote_add`'s validation) can't escape
/// `.sc/refs/remotes/` on the write side.
pub fn write_remote_tip(layout: &Layout, remote: &str, branch: &str, id: &ObjectId) -> Result<()> {
    if is_unsafe_ref_component(remote) || is_unsafe_ref_component(branch) {
        return Err(Error::BadRef(format!("invalid remote-tracking ref: {remote}/{branch}")));
    }
    let dir = layout.refs_remotes_dir().join(remote);
    std::fs::create_dir_all(&dir)?;
    atomic_write(&dir.join(branch), format!("{}\n", id.to_hex()).as_bytes())
}

/// Resolve a merge source name to a tip. A name containing `/` is treated as a
/// remote-tracking ref `<remote>/<branch>`; otherwise a local branch. The split
/// is left-greedy: `"origin/feature/x"` means remote `origin`, branch
/// `feature/x` (a nested branch is legitimate). Both the remote and branch
/// components are guarded against path traversal before they reach
/// `remote_ref_path`, so neither can escape `.sc/refs/remotes/`.
pub fn resolve_tip(layout: &Layout, name: &str) -> Result<Option<ObjectId>> {
    match name.split_once('/') {
        Some((remote, branch)) => {
            if is_unsafe_ref_component(remote) || is_unsafe_ref_component(branch) {
                return Err(Error::BadRef(format!("invalid remote-tracking ref: {name:?}")));
            }
            read_remote_tip(layout, remote, branch)
        }
        None => read_branch_tip(layout, name),
    }
}

/// Whether a `<remote>/<branch>` path component could escape or corrupt
/// `refs/remotes/`: empty, dot-prefixed, backslash-bearing, whitespace/control
/// bearing, or containing an empty or `..` sub-component. The empty
/// sub-component check rejects an absolute component (leading `/`, e.g.
/// `"/etc/passwd"`), a trailing `/`, and `//` — all of which would otherwise
/// let `Path::join` discard the `.sc/refs/remotes/` prefix. (A
/// single-component `remote` splits to just itself; a legit nested branch
/// like `feature/x` still passes — `/` itself is deliberately allowed here,
/// unlike `validate_branch_name`.) Whitespace/control is rejected too: a
/// hostile git remote's branch name lands here via `sc fetch`, and the oplog
/// is space-delimited, so a name like `"has space"` would corrupt it.
fn is_unsafe_ref_component(s: &str) -> bool {
    s.is_empty()
        || s.starts_with('.')
        || s.contains('\\')
        || s.split('/').any(|c| c.is_empty() || c == "..")
        || s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Remove a branch ref file (P20, `sc ws harvest`'s candidate-branch cleanup
/// after a clean landing). Refuses to delete the branch `HEAD` currently
/// names — that would leave `HEAD` dangling — and errors `NoSuchBranch` if
/// the ref is already absent.
pub fn delete_branch(layout: &Layout, name: &str) -> Result<()> {
    if current_branch(layout)? == name {
        return Err(Error::InvalidArgument(format!(
            "refusing to delete the current branch: {name}"
        )));
    }
    match std::fs::remove_file(layout.ref_path(name)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(Error::NoSuchBranch(name.to_string()))
        }
        Err(e) => Err(e.into()),
    }
}

/// `(branch, tip)` for every `refs/heads/*`. Skips temp files and unreadable
/// names; a malformed ref body is an error.
pub fn list_heads(layout: &Layout) -> Result<Vec<(String, ObjectId)>> {
    let mut out = Vec::new();
    let dir = layout.refs_heads_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for e in entries {
        let e = e?;
        if !e.file_type()?.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.contains(".tmp") {
            continue;
        }
        let text = std::fs::read_to_string(e.path())?;
        let id = ObjectId::from_str(text.trim())
            .map_err(|_| Error::BadRef(format!("head {name} has bad id")))?;
        out.push((name, id));
    }
    Ok(out)
}

/// `(remote, branch, tip)` for every `refs/remotes/<remote>/<branch>`.
pub fn list_remote_tips(layout: &Layout) -> Result<Vec<(String, String, ObjectId)>> {
    let mut out = Vec::new();
    let root = layout.refs_remotes_dir();
    let remotes = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for r in remotes {
        let r = r?;
        if !r.file_type()?.is_dir() {
            continue;
        }
        let remote = r.file_name().to_string_lossy().into_owned();
        for b in std::fs::read_dir(r.path())? {
            let b = b?;
            if !b.file_type()?.is_file() {
                continue;
            }
            let branch = b.file_name().to_string_lossy().into_owned();
            if branch.contains(".tmp") {
                continue;
            }
            let text = std::fs::read_to_string(b.path())?;
            let id = ObjectId::from_str(text.trim())
                .map_err(|_| Error::BadRef(format!("remote ref {remote}/{branch} has bad id")))?;
            out.push((remote.clone(), branch, id));
        }
    }
    Ok(out)
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
    Ok(scl_core::fsutil::atomic_write_durable(path, bytes)?)
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
    fn resolve_tip_rejects_traversal_in_either_component() {
        let layout = tmp_layout("resolve");
        write_head(&layout, "main").unwrap();
        let id = ObjectId::of(b"snap");
        write_branch_tip(&layout, "main", &id).unwrap();

        // Traversal in the remote component or the branch component is rejected.
        assert!(matches!(
            resolve_tip(&layout, "../evil/main"),
            Err(Error::BadRef(_))
        ));
        assert!(matches!(resolve_tip(&layout, "origin/../x"), Err(Error::BadRef(_))));
        // Absolute branch component (leading `/`) and an empty `//` sub-component
        // — these slip past a `..`-only check but `Path::join` would discard the
        // prefix, so they must be rejected.
        assert!(matches!(
            resolve_tip(&layout, "origin//etc/passwd"),
            Err(Error::BadRef(_))
        ));
        assert!(matches!(resolve_tip(&layout, "origin/a//b"), Err(Error::BadRef(_))));
        // A legitimate nested branch under a remote resolves (None = absent ref).
        assert_eq!(resolve_tip(&layout, "origin/feature/x").unwrap(), None);
        // A plain local branch still resolves to its tip.
        assert_eq!(resolve_tip(&layout, "main").unwrap(), Some(id));

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn write_remote_tip_rejects_traversal_in_either_component() {
        let layout = tmp_layout("write-remote");
        let id = ObjectId::of(b"snap");
        // A hostile remote name (bypassing remote_add) is rejected on write.
        assert!(matches!(
            write_remote_tip(&layout, "../../x", "main", &id),
            Err(Error::BadRef(_))
        ));
        // A normal write still succeeds and round-trips.
        write_remote_tip(&layout, "origin", "main", &id).unwrap();
        assert_eq!(read_remote_tip(&layout, "origin", "main").unwrap(), Some(id));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn lists_all_heads_and_remote_tips() {
        let layout = tmp_layout("listall");
        write_head(&layout, "main").unwrap();
        let a = ObjectId::of(b"a");
        let b = ObjectId::of(b"b");
        let c = ObjectId::of(b"c");
        write_branch_tip(&layout, "main", &a).unwrap();
        write_branch_tip(&layout, "feature", &b).unwrap();
        write_remote_tip(&layout, "origin", "main", &c).unwrap();

        let mut heads = list_heads(&layout).unwrap();
        heads.sort();
        assert_eq!(heads, vec![("feature".to_string(), b), ("main".to_string(), a)]);

        let remotes = list_remote_tips(&layout).unwrap();
        assert_eq!(remotes, vec![("origin".to_string(), "main".to_string(), c)]);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn delete_branch_removes_ref_refuses_current_and_errors_on_absent() {
        let layout = tmp_layout("delete-branch");
        write_head(&layout, "main").unwrap();
        let id = ObjectId::of(b"snap");
        write_branch_tip(&layout, "main", &id).unwrap();
        write_branch_tip(&layout, "work-1", &id).unwrap();

        // Non-current branch: deletes cleanly.
        delete_branch(&layout, "work-1").unwrap();
        assert_eq!(read_branch_tip(&layout, "work-1").unwrap(), None);

        // Already-absent branch: NoSuchBranch.
        assert!(matches!(delete_branch(&layout, "work-1"), Err(Error::NoSuchBranch(_))));

        // Current branch: refused.
        assert!(matches!(delete_branch(&layout, "main"), Err(Error::InvalidArgument(_))));
        assert_eq!(read_branch_tip(&layout, "main").unwrap(), Some(id));

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn write_branch_tip_rejects_unsafe_names() {
        let layout = tmp_layout("write-branch-unsafe");
        let id = ObjectId::of(b"snap");
        for bad in ["../evil", "a/b", "has space", "ctrl\u{7}", ".hidden", ""] {
            assert!(
                matches!(write_branch_tip(&layout, bad, &id), Err(Error::BadRef(_))),
                "expected BadRef for {bad:?}"
            );
        }
        // No file was written under refs/heads/ for any of the rejected names.
        assert_eq!(list_heads(&layout).unwrap(), Vec::new());

        // A legit name still succeeds.
        write_branch_tip(&layout, "feature", &id).unwrap();
        assert_eq!(read_branch_tip(&layout, "feature").unwrap(), Some(id));

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn read_branch_tip_rejects_unsafe_names() {
        let layout = tmp_layout("read-branch-unsafe");
        assert!(matches!(
            read_branch_tip(&layout, "../etc/passwd"),
            Err(Error::BadRef(_))
        ));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn is_unsafe_ref_component_rejects_whitespace_and_control() {
        assert!(is_unsafe_ref_component("has space"));
        assert!(is_unsafe_ref_component("...\u{9}..."));
        assert!(is_unsafe_ref_component("ctrl\u{7}"));
        // Nested `/` is still allowed for remote-tracking branches.
        assert!(!is_unsafe_ref_component("origin"));
        assert!(!is_unsafe_ref_component("feature/x"));
    }

    #[test]
    fn remote_tracking_write_rejects_whitespace_branch() {
        let layout = tmp_layout("remote-tracking-whitespace");
        let id = ObjectId::of(b"snap");
        assert!(matches!(
            write_remote_tip(&layout, "origin", "bad name", &id),
            Err(Error::BadRef(_))
        ));
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
