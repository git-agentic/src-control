//! Per-remote opaque marks: append-only `<key> <value>` lines under
//! `.sc/git-remotes/<remote>/marks`. This module is Git-agnostic — it never
//! interprets a key or value (the git-oid ↔ sc-id meaning lives in `cli`).

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::layout::Layout;

/// A per-remote opaque marks file.
pub struct MarksStore {
    path: PathBuf,
}

impl MarksStore {
    /// Open (do not create) the marks file for `remote`. The remote name becomes
    /// a directory component under `.sc/git-remotes/`, so it is traversal-guarded
    /// exactly like a remote-tracking ref component.
    pub fn open(layout: &Layout, remote: &str) -> Result<MarksStore> {
        if remote.is_empty()
            || remote.starts_with('.')
            || remote.contains('/')
            || remote.contains('\\')
        {
            return Err(Error::BadRef(format!("invalid remote name for marks: {remote:?}")));
        }
        let path = layout.dot_sc.join("git-remotes").join(remote).join("marks");
        Ok(MarksStore { path })
    }

    /// Load all `(key, value)` pairs in file order. A missing file is an empty map.
    pub fn load(&self) -> Result<Vec<(String, String)>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.split_once(' ') {
                Some((k, v)) => out.push((k.to_string(), v.to_string())),
                None => return Err(Error::BadRef(format!("malformed marks line: {line:?}"))),
            }
        }
        Ok(out)
    }

    /// Append `pairs` as `<key> <value>` lines. Creates the parent dir on first
    /// write. No-op when `pairs` is empty (so callers need not special-case it).
    pub fn append(&self, pairs: &[(String, String)]) -> Result<()> {
        use std::io::Write;
        if pairs.is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        let mut buf = String::new();
        for (k, v) in pairs {
            buf.push_str(k);
            buf.push(' ');
            buf.push_str(v);
            buf.push('\n');
        }
        f.write_all(buf.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-marks-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn append_then_load_roundtrips_and_accumulates() {
        let layout = tmp_layout("rt");
        let m = MarksStore::open(&layout, "hub").unwrap();
        assert_eq!(m.load().unwrap(), Vec::<(String, String)>::new()); // missing => empty

        m.append(&[("git1".into(), "sc1".into())]).unwrap();
        m.append(&[("git2".into(), "sc2".into()), ("git3".into(), "sc3".into())]).unwrap();

        let loaded = m.load().unwrap();
        assert_eq!(
            loaded,
            vec![
                ("git1".to_string(), "sc1".to_string()),
                ("git2".to_string(), "sc2".to_string()),
                ("git3".to_string(), "sc3".to_string()),
            ]
        );
        // Empty append is a no-op.
        m.append(&[]).unwrap();
        assert_eq!(m.load().unwrap().len(), 3);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn hostile_remote_name_is_rejected() {
        let layout = tmp_layout("hostile");
        assert!(matches!(MarksStore::open(&layout, "../evil"), Err(Error::BadRef(_))));
        assert!(matches!(MarksStore::open(&layout, ""), Err(Error::BadRef(_))));
        assert!(matches!(MarksStore::open(&layout, ".hidden"), Err(Error::BadRef(_))));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
