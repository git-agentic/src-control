//! The paths a stopped merge, cherry-pick or rebase wrote to the working tree
//! as plaintext (`.sc/CONFLICT_PLAINTEXT`, one path per line).
//!
//! A protected path's conflict text, or a clean content merge of one, is never
//! put in the CAS (ADR-0025), so no tree records that the file was written.
//! Two things need to know: completion, which would otherwise read a path the
//! user deleted from disk as "absent because the committer cannot read it" and
//! carry the parent's ciphertext back, and abort, whose removal walk only sees
//! the trees and would leave the decrypted text behind (ADR-0049 q16, q18).
//!
//! One file serves all three operations because only one can be in progress.
//! It is replaced at every stop and cleared with the operation's own state.
//! Read it only while an operation is in progress: residue from a crash is
//! otherwise inert.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::layout::Layout;

fn path(layout: &Layout) -> std::path::PathBuf {
    layout.dot_sc.join("CONFLICT_PLAINTEXT")
}

/// Record `paths` as written to the working tree in plaintext. An empty list
/// removes the record.
pub(crate) fn write(layout: &Layout, paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return clear(layout);
    }
    let tmp = layout.dot_sc.join("CONFLICT_PLAINTEXT.tmp");
    std::fs::write(&tmp, paths.join("\n") + "\n")?;
    std::fs::rename(&tmp, path(layout))?;
    Ok(())
}

/// The recorded paths, empty when there is no record.
pub(crate) fn read(layout: &Layout) -> Result<BTreeSet<String>> {
    match std::fs::read_to_string(path(layout)) {
        Ok(text) => Ok(text.lines().map(str::to_string).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(e.into()),
    }
}

/// Drop the record.
pub(crate) fn clear(layout: &Layout) -> Result<()> {
    match std::fs::remove_file(path(layout)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_read_clear_roundtrip() {
        let root =
            std::env::temp_dir().join(format!("scl-conflict-plaintext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        assert!(read(&layout).unwrap().is_empty());
        write(&layout, &["a/b.txt".into(), "c.txt".into()]).unwrap();
        assert_eq!(
            read(&layout).unwrap().into_iter().collect::<Vec<_>>(),
            vec!["a/b.txt", "c.txt"]
        );
        write(&layout, &[]).unwrap();
        assert!(read(&layout).unwrap().is_empty(), "an empty list clears");
        write(&layout, &["x".into()]).unwrap();
        clear(&layout).unwrap();
        assert!(read(&layout).unwrap().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
