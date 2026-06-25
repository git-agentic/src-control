//! Merge-in-progress state under `.sc/`: `MERGE_HEAD` (the other parent) and
//! `MERGE_CONFLICTS` (newline-separated conflicted paths). Written atomically;
//! correctness relies on the single-writer repo lock.

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

/// Record an in-progress merge: theirs id + conflicted paths.
pub fn write(layout: &Layout, theirs: &ObjectId, conflicts: &[String]) -> Result<()> {
    atomic_write(&merge_head_path(layout), format!("{}\n", theirs.to_hex()).as_bytes())?;
    atomic_write(&merge_conflicts_path(layout), (conflicts.join("\n") + "\n").as_bytes())?;
    Ok(())
}

/// Clear all merge state (after a successful merge commit or `--abort`).
pub fn clear(layout: &Layout) -> Result<()> {
    let _ = std::fs::remove_file(merge_head_path(layout));
    let _ = std::fs::remove_file(merge_conflicts_path(layout));
    Ok(())
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
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
        write(&layout, &theirs, &["a.txt".into(), "b.txt".into()]).unwrap();
        assert!(in_progress(&layout));
        assert_eq!(read_merge_head(&layout).unwrap(), Some(theirs));
        assert_eq!(read_conflicts(&layout).unwrap(), vec!["a.txt", "b.txt"]);
        clear(&layout).unwrap();
        assert!(!in_progress(&layout));
        assert_eq!(read_merge_head(&layout).unwrap(), None);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
