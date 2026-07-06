//! Cherry-pick-in-progress state under `.sc/`: `PICK_HEAD` (the commit being
//! picked), `PICK_CONFLICTS` (newline-separated conflicted paths), and
//! `PICK_DECIDED_ROOT` (the tree id of the pick's decided carried entries,
//! P15 Task 7 — completion carries absent protected files from it instead of
//! re-reading the stale tip). Written atomically; correctness relies on the
//! single-writer repo lock. Mirrors `merge_state.rs`, but `PICK_HEAD` is
//! provenance + a guard only — unlike `MERGE_HEAD`, completing a pick never
//! adds it as a second commit parent.

use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::layout::Layout;

fn pick_head_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("PICK_HEAD")
}
fn pick_conflicts_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("PICK_CONFLICTS")
}
fn decided_root_path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("PICK_DECIDED_ROOT")
}

/// True if a cherry-pick is in progress.
pub fn in_progress(layout: &Layout) -> bool {
    pick_head_path(layout).exists()
}

/// The commit being cherry-picked, if any.
pub fn read_pick_head(layout: &Layout) -> Result<Option<ObjectId>> {
    match std::fs::read_to_string(pick_head_path(layout)) {
        Ok(text) => ObjectId::from_str(text.trim())
            .map(Some)
            .map_err(|_| Error::BadRef(format!("PICK_HEAD has bad id: {}", text.trim()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The conflicted paths recorded for an in-progress cherry-pick.
pub fn read_conflicts(layout: &Layout) -> Result<Vec<String>> {
    match std::fs::read_to_string(pick_conflicts_path(layout)) {
        Ok(text) => Ok(text.lines().map(|l| l.to_string()).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// The decided-carried tree of an in-progress cherry-pick, if recorded.
/// Absent for pick state written by older code paths (or tests that don't
/// need it) — callers must fall back gracefully.
pub fn read_decided_root(layout: &Layout) -> Result<Option<ObjectId>> {
    match std::fs::read_to_string(decided_root_path(layout)) {
        Ok(text) => ObjectId::from_str(text.trim())
            .map(Some)
            .map_err(|_| Error::BadRef(format!("PICK_DECIDED_ROOT has bad id: {}", text.trim()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Record an in-progress cherry-pick: the picked commit + conflicted paths +
/// (optionally) the tree id holding the pick's decided carried entries, which
/// completion uses to carry absent protected files without re-reading the
/// stale tip. `PICK_HEAD` is written LAST — it is the `in_progress` signal,
/// so a crash mid-write leaves no half-announced pick (same discipline as
/// `merge_state::write`).
pub fn write(
    layout: &Layout,
    picked: &ObjectId,
    conflicts: &[String],
    decided_root: Option<&ObjectId>,
) -> Result<()> {
    atomic_write(&pick_conflicts_path(layout), (conflicts.join("\n") + "\n").as_bytes())?;
    match decided_root {
        Some(root) => {
            atomic_write(&decided_root_path(layout), format!("{}\n", root.to_hex()).as_bytes())?
        }
        None => remove_if_exists(&decided_root_path(layout))?,
    }
    atomic_write(&pick_head_path(layout), format!("{}\n", picked.to_hex()).as_bytes())?;
    Ok(())
}

/// Clear all pick state (after a successful completion commit or `--abort`).
pub fn clear(layout: &Layout) -> Result<()> {
    remove_if_exists(&pick_head_path(layout))?;
    remove_if_exists(&pick_conflicts_path(layout))?;
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
    // that differs only by extension (e.g. PICK_HEAD vs PICK_HEAD.tmp, not
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
        let root = std::env::temp_dir().join(format!("scl-pickstate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn write_read_clear_roundtrip() {
        let layout = tmp_layout("rt");
        assert!(!in_progress(&layout));
        let picked = ObjectId::of(b"picked");
        // Without a decided root (older code paths / plain picks): reads None.
        write(&layout, &picked, &["a.txt".into(), "b.txt".into()], None).unwrap();
        assert!(in_progress(&layout));
        assert_eq!(read_pick_head(&layout).unwrap(), Some(picked));
        assert_eq!(read_conflicts(&layout).unwrap(), vec!["a.txt", "b.txt"]);
        assert_eq!(read_decided_root(&layout).unwrap(), None, "absent record reads None");
        // With a decided root: round-trips; a later record without one drops it.
        let decided = ObjectId::of(b"decided-tree");
        write(&layout, &picked, &["a.txt".into()], Some(&decided)).unwrap();
        assert_eq!(read_decided_root(&layout).unwrap(), Some(decided));
        write(&layout, &picked, &["a.txt".into()], None).unwrap();
        assert_eq!(read_decided_root(&layout).unwrap(), None);
        write(&layout, &picked, &["a.txt".into()], Some(&decided)).unwrap();
        clear(&layout).unwrap();
        assert!(!in_progress(&layout));
        assert_eq!(read_pick_head(&layout).unwrap(), None);
        assert_eq!(read_decided_root(&layout).unwrap(), None, "clear drops the decided root");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
