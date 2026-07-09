//! `.sc/promisor` — a partial clone's durable fetch-filter marker (P27 Task 1).
//!
//! A `Promisor` records that this clone did not fetch every object: only
//! paths matching its `prefixes` were transferred, and the remainder is a
//! set of "promised" gaps the promisor `origin` remote can fill in later.
//! Absent file = a full clone (no gaps, nothing promised). Matching reuses
//! the same path-boundary discipline as [`crate::sparse::Sparse`] and
//! `protect.rs::matching_prefix` (P7/P24): a prefix without a trailing
//! slash matches its own bare path or any child under a `/` boundary, never
//! a sibling that merely shares a textual prefix.
//!
//! Beyond `Sparse::matches`, a partial-clone tree walk needs a second
//! predicate: whether to *descend* into a tree at all. A tree can be an
//! ancestor of an in-filter prefix without itself being in-filter (e.g.
//! filter `["src/app/"]`: `src` must be descended into to reach `src/app/`,
//! but `src` itself is not "in the filter"). [`Promisor::should_descend`]
//! is that ancestor-aware predicate; [`Promisor::matches`] stays the
//! narrower "is this path itself in-filter" check Task 2's object-emission
//! logic needs.
//!
//! Persistence: line 1 is `origin <url>`, then one prefix per line, written
//! atomically. This module only defines the marker + persistence +
//! matching; the filtered walk (Task 2), fetch-side filtering (Task 3),
//! backfill (Task 4), and gap-tolerant gc (Task 5) build on top of it.

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::repo::Repo;

/// A partial clone's durable marker: the fetch-filter prefixes + the
/// promisor remote (origin URL) that can fill in objects outside the
/// filter on demand. Absent file = a full clone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Promisor {
    prefixes: Vec<String>,
    pub origin: String,
}

impl Promisor {
    /// Build a marker from an explicit origin + prefix list.
    pub fn new(origin: impl Into<String>, prefixes: Vec<String>) -> Self {
        Promisor {
            prefixes,
            origin: origin.into(),
        }
    }

    /// Whether `path` falls under any recorded prefix, at a `/` boundary —
    /// mirrors [`crate::sparse::Sparse::matches`] / `protect::matching_prefix`.
    /// Unlike `Sparse`, an empty prefix list matches nothing (a promisor
    /// marker with no prefixes would be a degenerate/empty partial clone,
    /// not "everything" — callers gate on `Repo::promisor()` returning
    /// `None` for "no filter at all").
    pub fn matches(&self, path: &str) -> bool {
        self.prefixes.iter().any(|p| {
            let bare = p.trim_end_matches('/');
            path == bare || path.starts_with(&format!("{bare}/"))
        })
    }

    /// Should a tree walk descend into `path`? True if `path` is itself
    /// in-filter, or some filter prefix lies strictly *under* `path` (i.e.
    /// `path` is an ancestor the walk must pass through to reach in-filter
    /// content deeper in the tree). The empty path (the root) always
    /// descends, since every prefix lies under it.
    pub fn should_descend(&self, path: &str) -> bool {
        path.is_empty()
            || self.matches(path)
            || self
                .prefixes
                .iter()
                .any(|p| p.trim_end_matches('/').starts_with(&format!("{path}/")))
    }

    /// The recorded prefixes, in the order they were set.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// Widen the filter to also include `prefixes` (backfill, Task 4).
    /// Dedups against the existing set; order is existing-then-new.
    pub fn widen(&mut self, prefixes: &[String]) {
        for p in prefixes {
            if !self.prefixes.iter().any(|existing| existing == p) {
                self.prefixes.push(p.clone());
            }
        }
    }
}

/// Build the "outside this partial clone's fetch filter" error for `path`
/// (P27 Task 5) — one shared error so the sparse-widen preflight
/// (`set_sparse`/`disable_sparse`) and the merge/pick out-of-filter guard
/// speak with one voice, both pointing at `sc backfill`.
pub fn partial_gap_hint(path: &str) -> Error {
    Error::GapOutsideFilter(path.to_string())
}

/// Load the repo's promisor marker. An absent `.sc/promisor` file reads as
/// `None` — a full clone, not an empty filter.
pub fn load(layout: &Layout) -> Result<Option<Promisor>> {
    match std::fs::read_to_string(layout.promisor_path()) {
        Ok(text) => {
            let mut lines = text.lines();
            let origin = match lines.next() {
                Some(line) => line
                    .strip_prefix("origin ")
                    .ok_or_else(|| {
                        Error::InvalidArgument(
                            "malformed .sc/promisor: first line must be 'origin <url>'".into(),
                        )
                    })?
                    .to_string(),
                None => {
                    return Err(Error::InvalidArgument(
                        "malformed .sc/promisor: missing 'origin <url>' line".into(),
                    ))
                }
            };
            let prefixes = lines.map(|l| l.to_string()).collect();
            Ok(Some(Promisor { prefixes, origin }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Persist the repo's promisor marker, atomically.
pub fn store(layout: &Layout, p: &Promisor) -> Result<()> {
    let mut text = format!("origin {}\n", p.origin);
    for prefix in &p.prefixes {
        text.push_str(prefix);
        text.push('\n');
    }
    scl_core::fsutil::atomic_write_durable(&layout.promisor_path(), text.as_bytes())?;
    Ok(())
}

impl Repo {
    /// The repo's current promisor marker, if any (thin wrapper over
    /// `load`). `None` means this is a full clone.
    pub fn promisor(&self) -> Result<Option<Promisor>> {
        load(self.layout())
    }

    /// The out-of-filter gap count for `sc verify`'s partial-clone report
    /// (P27 Task 5): walks the filtered reachability from `tips` and returns
    /// the number of gaps recorded (ids referenced by an in-filter parent
    /// tree but never fetched) — `None` if this is a full clone (no
    /// `.sc/promisor`), so a partial clone's expected gaps are never mistaken
    /// for missing/corrupt objects. An in-filter object that's genuinely
    /// absent still surfaces as an `Err` from the underlying walk (real
    /// corruption), not folded into this count.
    pub fn partial_gap_count(&self, tips: &[scl_core::ObjectId]) -> Result<Option<usize>> {
        let Some(p) = self.promisor()? else {
            return Ok(None);
        };
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let r = crate::reachable::reachable_objects_filtered(&mut *store, tips, Some(&p))?;
        Ok(Some(r.gaps.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root =
            std::env::temp_dir().join(format!("scl-promisor-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn matches_boundary() {
        let p = Promisor::new("origin-url", vec!["src/".into()]);
        assert!(p.matches("src/a"));
        assert!(p.matches("src"));
        assert!(!p.matches("srcfoo"));
        assert!(!p.matches("docs/x"));
    }

    #[test]
    fn should_descend_includes_ancestors() {
        let p = Promisor::new("origin-url", vec!["src/app/".into()]);
        // "src" is an ancestor of the in-filter "src/app/" — must descend
        // through it to reach the filtered content, but "src" itself is not
        // in-filter.
        assert!(p.should_descend("src"));
        assert!(!p.matches("src"));
        // "src/app" is itself in-filter.
        assert!(p.should_descend("src/app"));
        assert!(p.matches("src/app"));
        // Unrelated subtree: neither in-filter nor an ancestor.
        assert!(!p.should_descend("docs"));
        assert!(!p.matches("docs"));
        // The root always descends.
        assert!(p.should_descend(""));
    }

    #[test]
    fn store_load_round_trip() {
        let layout = tmp_layout("rt");
        // Absent file reads as None (a full clone).
        assert_eq!(load(&layout).unwrap(), None);

        let p = Promisor::new("ssh://host/repo", vec!["src/".into(), "docs/".into()]);
        store(&layout, &p).unwrap();
        assert_eq!(load(&layout).unwrap(), Some(p));

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn widen_dedups() {
        let mut p = Promisor::new("origin-url", vec!["src/".into()]);
        p.widen(&["docs/".into(), "src/".into(), "tests/".into()]);
        assert_eq!(
            p.prefixes(),
            &["src/".to_string(), "docs/".to_string(), "tests/".to_string()]
        );

        // Widening with an already-present set is a no-op.
        p.widen(&["src/".into(), "docs/".into(), "tests/".into()]);
        assert_eq!(p.prefixes().len(), 3);
    }
}
