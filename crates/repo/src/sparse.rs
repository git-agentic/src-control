//! `.sc/sparse` — the repo's sparse-checkout prefix spec (P24 Task 1).
//!
//! A `Sparse` spec is the set of path prefixes that materialize to disk; an
//! empty spec means full materialization (no sparseness at all — every repo
//! is "sparse: disabled" by default). Matching reuses the same path-boundary
//! discipline `protect.rs::matching_prefix` established for P7: a prefix
//! without a trailing slash matches its own bare path or any child under a
//! `/` boundary, never a sibling that merely shares a textual prefix (e.g.
//! `src` must not match `srcfoo.rs`).
//!
//! Persistence: one prefix per line in `.sc/sparse`, written atomically.
//! Storing an empty spec removes the file entirely rather than writing an
//! empty one, so "no file" and "empty spec" are the same observable state —
//! `load` treats an absent file as an empty `Sparse`.
//!
//! This module only defines the spec + persistence + matching. `sc sparse
//! set`/`disable` (Task 3) and checkout/commit integration (Task 2) build on
//! top of this.

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::repo::Repo;

/// A repo's sparse-checkout spec: the prefixes that materialize to disk.
/// Empty = full materialization (no sparseness).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sparse {
    prefixes: Vec<String>,
}

impl Sparse {
    /// Build a spec from an explicit prefix list.
    pub fn new(prefixes: Vec<String>) -> Self {
        Sparse { prefixes }
    }

    /// No prefixes recorded → materialize everything.
    pub fn is_full(&self) -> bool {
        self.prefixes.is_empty()
    }

    /// Whether `path` falls under any recorded prefix, at a `/` boundary —
    /// mirrors `protect::matching_prefix`'s bare-form + boundary check. A
    /// full (empty) spec matches everything.
    pub fn matches(&self, path: &str) -> bool {
        self.is_full()
            || self.prefixes.iter().any(|p| {
                let bare = p.trim_end_matches('/');
                path == bare || path.starts_with(&format!("{bare}/"))
            })
    }

    /// The recorded prefixes, in the order they were set.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// Should a tree walk descend into `path`? True if `path` is itself
    /// in-spec, or some spec prefix lies strictly *under* `path` (an
    /// ancestor the walk must pass through to reach in-spec content deeper
    /// in the tree). A full (empty) spec always descends. Mirrors
    /// [`crate::promisor::Promisor::should_descend`] exactly — added for
    /// P27 Task 4 so a gap-tolerant tree walk (`materialize` on a partial
    /// clone) can prune out-of-sparse subtrees without ever calling
    /// `store.get` on an object a promisor filter never fetched.
    pub fn should_descend(&self, path: &str) -> bool {
        self.is_full()
            || path.is_empty()
            || self.matches(path)
            || self
                .prefixes
                .iter()
                .any(|p| p.trim_end_matches('/').starts_with(&format!("{path}/")))
    }
}

/// Remove a file, treating "already absent" as success but propagating any
/// other IO error rather than swallowing it. Mirrors `pick_state.rs`.
fn remove_if_exists(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Load the repo's sparse spec. An absent `.sc/sparse` file reads as an
/// empty (full-materialization) spec.
pub fn load(layout: &Layout) -> Result<Sparse> {
    match std::fs::read_to_string(layout.sparse_path()) {
        Ok(text) => {
            let prefixes = text.lines().map(|l| l.to_string()).collect();
            Ok(Sparse { prefixes })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Sparse::default()),
        Err(e) => Err(e.into()),
    }
}

/// Persist the repo's sparse spec, atomically. An empty spec removes the
/// file entirely rather than writing an empty one, so `load` sees the same
/// "no sparseness" state whether the file was never written or was cleared.
pub fn store(layout: &Layout, s: &Sparse) -> Result<()> {
    if s.prefixes.is_empty() {
        return remove_if_exists(&layout.sparse_path());
    }
    let text = format!("{}\n", s.prefixes.join("\n"));
    scl_core::fsutil::atomic_write_durable(&layout.sparse_path(), text.as_bytes())?;
    Ok(())
}

/// Clear the sparse spec (equivalent to `store`-ing an empty one).
pub fn clear(layout: &Layout) -> Result<()> {
    remove_if_exists(&layout.sparse_path())
}

impl Repo {
    /// The repo's current sparse-checkout spec (thin wrapper over `load`).
    pub fn sparse_spec(&self) -> Result<Sparse> {
        load(self.layout())
    }

    /// Set the sparse-checkout spec to `prefixes` and re-lay the working tree
    /// to match: persists the new spec, then materializes HEAD's tree against
    /// it with `old_root = Some(head_root)` — target and old root are the same
    /// commit, so the write loop only re-touches files already on disk, and
    /// the removal loop's narrowing check (`materialize`'s `!sparse.matches`
    /// arm) prunes any file that's on disk today but falls outside the new
    /// spec. An unborn HEAD has no working tree to re-lay; the spec is still
    /// persisted so it takes effect on the first commit/checkout.
    ///
    /// Refuses (same as [`Repo::switch_with_identity`]) when the working tree
    /// has uncommitted modifications or deletions: `materialize`'s write loop
    /// rewrites every in-sparse target entry from HEAD's blob unconditionally,
    /// and narrowing additionally removes newly-excluded files from disk —
    /// either would silently clobber uncommitted edits.
    ///
    /// Returns the protected paths skipped (no matching key) for the same
    /// reason [`Repo::switch_with_identity`] does — sparse narrowing can
    /// newly bring a protected path into view that `identity` can't decrypt.
    pub fn set_sparse(
        &self,
        prefixes: &[String],
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<Vec<String>> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(crate::error::Error::InvalidArgument(
                "working tree has uncommitted changes; commit before changing the sparse spec"
                    .into(),
            ));
        }
        let spec = Sparse::new(prefixes.to_vec());
        store(self.layout(), &spec)?;
        let Some(tip) = self.head_tip()? else {
            return Ok(Vec::new());
        };
        let snap = self.snapshot(&tip)?;
        let store_arc = self.vfs().store();
        let mut s = store_arc.lock().unwrap();
        crate::worktree::materialize(
            self.layout(),
            &mut s,
            snap.root,
            Some(snap.root),
            &snap.protection,
            identity,
            &spec,
        )
    }

    /// Disable sparse checkout: clear the persisted spec and re-materialize
    /// HEAD's tree in full, restoring every previously-excluded file to disk.
    /// An unborn HEAD has no working tree to re-lay; the spec is still
    /// cleared.
    ///
    /// Refuses on a dirty working tree, same as [`Repo::set_sparse`] and for
    /// the same reason (the write loop rewrites every in-sparse target entry
    /// unconditionally).
    pub fn disable_sparse(
        &self,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<Vec<String>> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(crate::error::Error::InvalidArgument(
                "working tree has uncommitted changes; commit before changing the sparse spec"
                    .into(),
            ));
        }
        clear(self.layout())?;
        let Some(tip) = self.head_tip()? else {
            return Ok(Vec::new());
        };
        let snap = self.snapshot(&tip)?;
        let store_arc = self.vfs().store();
        let mut s = store_arc.lock().unwrap();
        crate::worktree::materialize(
            self.layout(),
            &mut s,
            snap.root,
            Some(snap.root),
            &snap.protection,
            identity,
            &Sparse::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-sparse-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn matches_full_when_empty() {
        let s = Sparse::default();
        assert!(s.is_full());
        assert!(s.matches("anything"));
        assert!(s.matches("src/main.rs"));
    }

    #[test]
    fn matches_at_path_boundary() {
        let s = Sparse::new(vec!["src/".into()]);
        assert!(!s.is_full());
        assert!(s.matches("src/main.rs"));
        assert!(s.matches("src"));
        assert!(!s.matches("srcfoo.rs"));
        assert!(!s.matches("docs/x"));
    }

    #[test]
    fn store_load_round_trip() {
        let layout = tmp_layout("rt");
        let s = Sparse::new(vec!["src/".into(), "docs/".into()]);
        store(&layout, &s).unwrap();
        assert_eq!(load(&layout).unwrap(), s);

        // Storing an empty spec removes the file; load reads back empty.
        store(&layout, &Sparse::default()).unwrap();
        assert_eq!(load(&layout).unwrap(), Sparse::default());

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn store_empty_removes_file() {
        let layout = tmp_layout("empty-removes");
        let s = Sparse::new(vec!["src/".into()]);
        store(&layout, &s).unwrap();
        assert!(layout.sparse_path().exists());

        store(&layout, &Sparse::default()).unwrap();
        assert!(!layout.sparse_path().exists(), "empty spec must remove the file");

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn clear_removes_file_and_is_idempotent() {
        let layout = tmp_layout("clear");
        let s = Sparse::new(vec!["src/".into()]);
        store(&layout, &s).unwrap();
        clear(&layout).unwrap();
        assert!(!layout.sparse_path().exists());
        // Clearing again (already absent) must not error.
        clear(&layout).unwrap();

        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn sparse_set_refused_during_in_progress() {
        use crate::repo::Repo;
        use scl_core::ObjectId;

        // Test that set_sparse refuses during merge, pick, and rebase.
        let root = std::env::temp_dir().join(format!("scl-sparse-in-progress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repo = Repo::init(&root).unwrap();

        // Create an initial commit so HEAD exists.
        std::fs::write(root.join("a.txt"), b"content").unwrap();
        repo.commit("test_author", "initial commit").unwrap();

        // Record original sparse spec (should be empty/full).
        let orig_spec = repo.sparse_spec().unwrap();
        assert!(orig_spec.is_full(), "initial spec should be full");

        // Helper to test refusal for a given state.
        macro_rules! test_refused_during_state {
            ($name:ident, $write_fn:expr, $clear_fn:expr, $err_type:path) => {
                // Write state.
                $write_fn(&repo.layout);

                // set_sparse should be refused with the expected error.
                let result = repo.set_sparse(&["src/".into()], None);
                assert!(
                    matches!(result, Err($err_type)),
                    "set_sparse during {} should be refused with {:?}, got {:?}",
                    stringify!($name),
                    stringify!($err_type),
                    result
                );

                // Sparse spec should be unchanged.
                assert_eq!(
                    repo.sparse_spec().unwrap(),
                    orig_spec,
                    "sparse spec should not change during refused {}",
                    stringify!($name)
                );

                // Also test disable_sparse is refused.
                let result = repo.disable_sparse(None);
                assert!(
                    matches!(result, Err($err_type)),
                    "disable_sparse during {} should be refused with {:?}, got {:?}",
                    stringify!($name),
                    stringify!($err_type),
                    result
                );

                // Clear state.
                $clear_fn(&repo.layout);
            };
        }

        // Test merge in progress.
        test_refused_during_state!(
            merge,
            |layout: &Layout| {
                crate::merge_state::write(layout, &ObjectId::of(b"theirs"), &[], None).unwrap();
            },
            |layout: &Layout| {
                crate::merge_state::clear(layout).unwrap();
            },
            Error::MergeInProgress
        );

        // Test pick in progress.
        test_refused_during_state!(
            pick,
            |layout: &Layout| {
                crate::pick_state::write(layout, &ObjectId::of(b"picked"), &[], None, None).unwrap();
            },
            |layout: &Layout| {
                crate::pick_state::clear(layout).unwrap();
            },
            Error::PickInProgress
        );

        // Test rebase in progress.
        test_refused_during_state!(
            rebase,
            |layout: &Layout| {
                let state = crate::rebase_state::RebaseState {
                    branch: "main".into(),
                    original_tip: ObjectId::of(b"orig"),
                    target: "feature".into(),
                    acc_tip: ObjectId::of(b"acc"),
                    conflicted: ObjectId::of(b"conflicted"),
                    remaining: vec![],
                    total: 1,
                    author: "test_author".into(),
                    resolved: false,
                    replayed: 0,
                    skipped: 0,
                };
                crate::rebase_state::write(layout, &state).unwrap();
            },
            |layout: &Layout| {
                crate::rebase_state::clear(layout).unwrap();
            },
            Error::RebaseInProgress
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
