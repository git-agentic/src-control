//! Merge-in-progress state under `.sc/`: `MERGE_HEAD` (the other parent),
//! `MERGE_CONFLICTS` (newline-separated conflicted paths), and
//! `MERGE_DECIDED_ROOT` (the tree id of the merge's decided carried entries,
//! P15 Task 6 — completion carries absent protected files from it instead of
//! re-arbitrating by parent order). Written atomically; correctness relies on
//! the single-writer repo lock.

use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

fn merge_head_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("MERGE_HEAD")
}
fn merge_conflicts_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("MERGE_CONFLICTS")
}
fn decided_root_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("MERGE_DECIDED_ROOT")
}

/// True if a merge is in progress.
pub fn in_progress(layout: &Layout) -> bool {
    merge_head_path(layout).exists()
}

/// The other parent (theirs) of an in-progress merge, if any.
pub fn read_merge_head(layout: &Layout) -> Result<Option<ObjectId>> {
    match std::fs::read_to_string(merge_head_path(layout)) {
        Ok(text) => ObjectId::from_str(text.trim())
            .map(Some)
            .map_err(|_| Error::BadRef(format!("MERGE_HEAD has bad id: {}", text.trim()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The conflicted paths recorded for an in-progress merge.
pub fn read_conflicts(layout: &Layout) -> Result<Vec<String>> {
    match std::fs::read_to_string(merge_conflicts_path(layout)) {
        Ok(text) => Ok(text.lines().map(|l| l.to_string()).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// The decided-carried tree of an in-progress merge, if recorded. Absent for
/// merge state written by older code paths (or by tests that don't need it) —
/// callers must fall back gracefully.
pub fn read_decided_root(layout: &Layout) -> Result<Option<ObjectId>> {
    match std::fs::read_to_string(decided_root_path(layout)) {
        Ok(text) => ObjectId::from_str(text.trim())
            .map(Some)
            .map_err(|_| Error::BadRef(format!("MERGE_DECIDED_ROOT has bad id: {}", text.trim()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Record an in-progress merge: theirs id + conflicted paths + (optionally)
/// the tree id holding the merge's decided carried entries, which completion
/// uses to carry absent protected files without re-arbitrating by parent
/// order. `MERGE_HEAD` is written LAST — it is the `in_progress` signal, so a
/// crash mid-write leaves no half-announced merge.
pub fn write(
    layout: &Layout,
    theirs: &ObjectId,
    conflicts: &[String],
    decided_root: Option<&ObjectId>,
) -> Result<()> {
    atomic_write(&merge_conflicts_path(layout), (conflicts.join("\n") + "\n").as_bytes())?;
    match decided_root {
        Some(root) => {
            atomic_write(&decided_root_path(layout), format!("{}\n", root.to_hex()).as_bytes())?
        }
        None => remove_if_exists(&decided_root_path(layout))?,
    }
    atomic_write(&merge_head_path(layout), format!("{}\n", theirs.to_hex()).as_bytes())?;
    Ok(())
}

/// Clear all merge state (after a successful merge commit or `--abort`).
pub fn clear(layout: &Layout) -> Result<()> {
    remove_if_exists(&merge_head_path(layout))?;
    remove_if_exists(&merge_conflicts_path(layout))?;
    remove_if_exists(&decided_root_path(layout))?;
    Ok(())
}

/// Remove a file, treating "already absent" as success but propagating any
/// other IO error rather than swallowing it.
fn remove_if_exists(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    // Build the tmp path as "<file_name>.tmp" so we don't clobber a sibling
    // that differs only by extension (e.g. MERGE_HEAD vs MERGE_HEAD.tmp, not
    // turning "foo.bar" into "foo.tmp").
    let name = path
        .file_name()
        .ok_or_else(|| Error::InvalidArgument(format!("path has no file name: {}", path.display())))?
        .to_string_lossy()
        .into_owned();
    let tmp = path.with_file_name(format!("{name}.tmp"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-mergestate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn write_read_clear_roundtrip() {
        let layout = tmp_layout("rt");
        assert!(!in_progress(&layout));
        let theirs = ObjectId::of(b"theirs");
        // Without a decided root (older code paths / plain merges): reads None.
        write(&layout, &theirs, &["a.txt".into(), "b.txt".into()], None).unwrap();
        assert!(in_progress(&layout));
        assert_eq!(read_merge_head(&layout).unwrap(), Some(theirs));
        assert_eq!(read_conflicts(&layout).unwrap(), vec!["a.txt", "b.txt"]);
        assert_eq!(read_decided_root(&layout).unwrap(), None, "absent record reads None");
        // With a decided root: round-trips; a later record without one drops it.
        let decided = ObjectId::of(b"decided-tree");
        write(&layout, &theirs, &["a.txt".into()], Some(&decided)).unwrap();
        assert_eq!(read_decided_root(&layout).unwrap(), Some(decided));
        write(&layout, &theirs, &["a.txt".into()], None).unwrap();
        assert_eq!(read_decided_root(&layout).unwrap(), None);
        write(&layout, &theirs, &["a.txt".into()], Some(&decided)).unwrap();
        clear(&layout).unwrap();
        assert!(!in_progress(&layout));
        assert_eq!(read_merge_head(&layout).unwrap(), None);
        assert_eq!(read_decided_root(&layout).unwrap(), None, "clear drops the decided root");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
