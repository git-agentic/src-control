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

    /// Whether every path `other` matches is also matched here: the widen-only
    /// test for a spec change while an op is stopped. A prefix names its bare
    /// path and everything under it, so `other`'s prefix is covered exactly
    /// when this spec matches that bare path.
    pub fn covers(&self, other: &Sparse) -> bool {
        self.is_full()
            || (!other.is_full()
                && other
                    .prefixes
                    .iter()
                    .all(|p| self.matches(p.trim_end_matches('/'))))
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
            // Blank lines (a hand edit, a trailing newline doubled) name no
            // prefix; keep them out of the spec.
            // `trim` only decides what is blank: a prefix keeps its bytes.
            let prefixes = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(String::from)
                .collect();
            Ok(Sparse { prefixes })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Sparse::default()),
        Err(e) => Err(e.into()),
    }
}

/// Refuse a blank prefix (empty or whitespace-only). It would be persisted as a
/// blank line, which `load` reads back as no prefix at all: a laid-out empty
/// view would turn into a full checkout on the next process, and every absent
/// file would then read as a deletion. No prefix at all (an empty list) is the
/// one spelling of a full view and is accepted.
pub(crate) fn validate_prefixes(prefixes: &[String]) -> Result<()> {
    match prefixes.iter().find(|p| p.trim().is_empty()) {
        Some(p) => Err(crate::error::Error::InvalidArgument(format!(
            "empty sparse prefix {p:?}; name a path, or use `sc sparse disable` for a full checkout"
        ))),
        None => Ok(()),
    }
}

/// Persist the repo's sparse spec, atomically. An empty spec removes the
/// file entirely rather than writing an empty one, so `load` sees the same
/// "no sparseness" state whether the file was never written or was cleared.
pub fn store(layout: &Layout, s: &Sparse) -> Result<()> {
    // The shared persistence boundary: a blank prefix would become a blank
    // line that `load` reads back as no prefix.
    validate_prefixes(&s.prefixes)?;
    if s.prefixes.is_empty() {
        return remove_if_exists(&layout.sparse_path());
    }
    let text = format!("{}\n", s.prefixes.join("\n"));
    scl_core::fsutil::atomic_write_durable(&layout.sparse_path(), text.as_bytes())?;
    Ok(())
}

/// Record `s` as the spec in effect before an in-flight `sparse set`.
pub(crate) fn store_prev(layout: &Layout, s: &Sparse) -> Result<()> {
    let text = format!("{}\n", s.prefixes.join("\n"));
    scl_core::fsutil::atomic_write_durable(&layout.sparse_prev_path(), text.as_bytes())?;
    Ok(())
}

/// The spec recorded by an interrupted `sparse set`, if one is pending.
pub(crate) fn load_prev(layout: &Layout) -> Result<Option<Sparse>> {
    match std::fs::read_to_string(layout.sparse_prev_path()) {
        Ok(text) => Ok(Some(Sparse {
            prefixes: text
                .lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect(),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Drop the pending-`sparse set` marker.
pub(crate) fn clear_prev(layout: &Layout) -> Result<()> {
    remove_if_exists(&layout.sparse_prev_path())
}

/// The paths an in-flight stopped-op widen recorded writing, if the record
/// belongs to the stop whose decided root is `decided` (its first line); a
/// record from another stop is stale and reads as empty.
pub(crate) fn load_widen(
    layout: &Layout,
    decided: scl_core::ObjectId,
) -> Result<std::collections::BTreeSet<String>> {
    match std::fs::read_to_string(layout.sparse_widen_path()) {
        Ok(text) => {
            let mut lines = text.lines();
            if lines.next() != Some(decided.to_hex().as_str()) {
                return Ok(Default::default());
            }
            Ok(lines.filter(|l| !l.is_empty()).map(String::from).collect())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(e.into()),
    }
}

/// Record `paths` as the files a widen over the stop with decided root
/// `decided` is about to write.
pub(crate) fn store_widen(
    layout: &Layout,
    decided: scl_core::ObjectId,
    paths: &std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut text = format!("{}\n", decided.to_hex());
    text.extend(paths.iter().map(|p| format!("{p}\n")));
    scl_core::fsutil::atomic_write_durable(&layout.sparse_widen_path(), text.as_bytes())?;
    Ok(())
}

impl Sparse {
    /// A spec that matches whatever either input matches. A full (empty) spec
    /// is full in the union.
    pub(crate) fn union(&self, other: &Sparse) -> Sparse {
        if self.is_full() || other.is_full() {
            return Sparse::default();
        }
        let mut prefixes = self.prefixes.clone();
        for p in &other.prefixes {
            if !prefixes.contains(p) {
                prefixes.push(p.clone());
            }
        }
        Sparse { prefixes }
    }
}

/// Clear the sparse spec (equivalent to `store`-ing an empty one).
pub fn clear(layout: &Layout) -> Result<()> {
    remove_if_exists(&layout.sparse_path())
}

/// Whether the path `bare` (no trailing slash) exists in the tree at `root`,
/// as a file or a directory: `Some(true)`/`Some(false)`, or `None` when a tree
/// on the way is not held (a partial clone's gap), which is not an answer.
fn prefix_present(
    store: &mut scl_core::Store,
    root: scl_core::ObjectId,
    bare: &str,
) -> Option<bool> {
    // Literal components, as `Sparse::matches` reads the prefix: a leading
    // slash or a doubled one names nothing, it is not skipped.
    let comps: Vec<&str> = bare.split('/').collect();
    let mut cur = root;
    for (i, comp) in comps.iter().enumerate() {
        if !store.contains(&cur) {
            return None;
        }
        let tree = store.get_tree(&cur).ok()?;
        let Some(e) = tree.get(comp) else {
            return Some(false);
        };
        let last = i + 1 == comps.len();
        match e.kind {
            scl_core::EntryKind::Tree if !last => cur = e.id,
            _ => return Some(last),
        }
    }
    Some(true)
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
    /// While a merge, pick or rebase is stopped it refuses with that op's
    /// `*InProgress` error unless `prefixes` cover the current spec (a strict
    /// widen) and the stop recorded its decided root; a widen then lays out
    /// only the files that come into view (see `widen_while_stopped`).
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
        self.refuse_on_private("sc sparse set")?;
        // Before any side effect (the shared `store` checks again).
        validate_prefixes(prefixes)?;
        let spec = Sparse::new(prefixes.to_vec());
        // The view in effect now, read before it is replaced: it bounds the
        // removal walk in the re-lay below.
        let old_spec = self.sparse_spec()?;
        // A stopped merge, pick or rebase refuses a narrowing or sideways
        // change (the re-lay would clobber its markers). A strict widen is
        // allowed when the stop recorded its decided root: see
        // `widen_while_stopped`.
        let stopped = match self.stopped_op()? {
            None => None,
            // A full spec is `disable`, which stays refused.
            Some((_, Some(decided))) if !spec.is_full() && spec.covers(&old_spec) => Some(decided),
            Some((refusal, _)) => return Err(refusal),
        };
        // Gap error on sparse-widen (P27 Task 5): a partial clone never
        // fetched anything outside its promisor filter, so narrowing the
        // sparse view to a prefix that isn't itself covered by the filter
        // would materialize a path this clone has no object closure for.
        // Preflight — before any disk write (the spec file or the working
        // tree) — so a refused widen leaves nothing partially written.
        if let Some(promisor) = self.promisor()? {
            // No prefixes means a full checkout, which is what `sparse
            // disable` is, and that is refused on a partial clone.
            if prefixes.is_empty() {
                return Err(Error::InvalidArgument(format!(
                    "cannot set an empty sparse spec (a full checkout) on a partial clone: \
                     only [{}] was fetched; run `sc backfill --all` to convert to a full \
                     clone first, or name a prefix within it",
                    promisor.prefixes().join(", ")
                )));
            }
            // A lazy clone may widen the view past its fetch filter: the
            // closure is filled by id below. Any other partial clone never
            // fetched outside the filter, so it refuses.
            if !crate::promisor::is_lazy(&self.layout) {
                for p in prefixes {
                    let bare = p.trim_end_matches('/');
                    if !promisor.matches(bare) {
                        return Err(crate::promisor::partial_gap_hint(p));
                    }
                }
            }
        }
        if let Some(decided) = stopped {
            return self.widen_while_stopped(decided, &old_spec, &spec);
        }
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(crate::error::Error::InvalidArgument(
                "working tree has uncommitted changes; commit before changing the sparse spec"
                    .into(),
            ));
        }
        let tip = self.head_tip()?;
        let snap = match tip {
            Some(tip) => Some(self.snapshot(&tip)?),
            None => None,
        };
        // Check the PROPOSED view's closure against HEAD before the spec is
        // stored: once it is stored the previous view cannot be recovered and
        // a failure below would leave the new spec over a tree that cannot be
        // laid out (ADR-0048).
        if let Some(snap) = &snap {
            self.ensure_view(snap.root, &spec)?;
            {
                let store_arc = self.vfs().store();
                let mut s = store_arc.lock().unwrap();
                crate::worktree::preflight_view(self.layout(), &mut s, snap.root, &spec)?;
            }
            // Widening lays tracked files onto disk: refuse before anything is
            // stored if one would replace a file the user owns.
            self.refuse_untracked_for_view_change(
                "sparse set",
                snap.root,
                &old_spec,
                &spec,
                &Default::default(),
            )?;
        }
        // Crash safety: record the spec being replaced before the new one is
        // stored. If the process dies before the re-lay finishes, the marker
        // keeps the old view in the removal walk's bound until a later
        // materialize completes the job (ADR-0048, open question 9).
        let partial = self.promisor()?.is_some();
        if partial {
            // An earlier interrupted `sparse set` may have left a marker: keep
            // its view in the bound too.
            let pending = match load_prev(self.layout())? {
                Some(prev) => prev.union(&old_spec),
                None => old_spec.clone(),
            };
            store_prev(self.layout(), &pending)?;
        }
        store(self.layout(), &spec)?;
        let Some(snap) = snap else {
            if partial {
                clear_prev(self.layout())?;
            }
            return Ok(Vec::new());
        };
        let store_arc = self.vfs().store();
        let mut s = store_arc.lock().unwrap();
        let mut cache = self.open_protected_cache()?;
        let skipped = crate::worktree::materialize_with_old_view(
            self.layout(),
            &mut s,
            snap.root,
            Some(snap.root),
            &snap.protection,
            identity,
            &spec,
            Some(&old_spec),
            Some(&mut cache),
        )?;
        // The sparse spec (the operation's durable commit point) is already
        // persisted above; this re-lay moves no branch ref, so the cache save
        // is best-effort — never abort a sparse change on cache trouble
        // (P33 Task 7).
        cache.save_best_effort();
        if partial {
            clear_prev(self.layout())?;
        }
        Ok(skipped)
    }

    /// The in-progress merge, pick or rebase, if any, as the refusal a
    /// spec change gets and the decided root the stop recorded (the tree its
    /// working tree was laid out from).
    fn stopped_op(&self) -> Result<Option<(Error, Option<scl_core::ObjectId>)>> {
        Ok(if crate::merge_state::in_progress(&self.layout) {
            Some((
                Error::MergeInProgress,
                crate::merge_state::read_decided_root(&self.layout)?,
            ))
        } else if crate::pick_state::in_progress(&self.layout) {
            Some((
                Error::PickInProgress,
                crate::pick_state::read_decided_root(&self.layout)?,
            ))
        } else if crate::rebase_state::in_progress(&self.layout) {
            Some((
                Error::RebaseInProgress,
                crate::rebase_state::read_decided_root(&self.layout)?,
            ))
        } else {
            None
        })
    }

    /// Widen the view (`new` covers `old`) while a merge, pick or rebase is
    /// stopped, laying out only the files that come into view, from the
    /// stop's decided root. A normal `set_sparse` re-lays HEAD, which would
    /// overwrite the conflict markers and the user's resolution, and its
    /// dirty-tree check reads those as uncommitted edits.
    ///
    /// The decided root is right for every path the stop did not write: it is
    /// what completion carries an out-of-view path from, so laying a path out
    /// from it changes nothing the completion would compute, while leaving
    /// it off disk would read as a deletion. Marker, plaintext and sidecar
    /// paths are all in the old view (the stop gates them), so none is
    /// touched. Protected entries are not decrypted here: they stay absent,
    /// and completion carries them from the decided root as it does for any
    /// absent protected file. Files are written before the spec, so a crash
    /// leaves only extra out-of-view files, never a view with files missing.
    fn widen_while_stopped(
        &self,
        decided: scl_core::ObjectId,
        old: &Sparse,
        new: &Sparse,
    ) -> Result<Vec<String>> {
        // Same view: nothing comes into view, so there is nothing to write.
        if new.covers(old) && old.covers(new) {
            return Ok(Vec::new());
        }
        let (skipped, prev) = self.lay_out_widened_view(decided, old, new)?;
        self.finish_widen(new, prev)?;
        Ok(skipped)
    }

    /// The first half of [`Repo::widen_while_stopped`]: every guard, the
    /// `.sc/sparse-widen` record, and the writes, but not the spec. Returns
    /// the protected paths left absent and the `sparse-prev` marker to
    /// restore. A crash or error after this leaves exactly the state the
    /// abort and completion cleanup (`remove_widen_residue`) handles.
    pub(crate) fn lay_out_widened_view(
        &self,
        decided: scl_core::ObjectId,
        old: &Sparse,
        new: &Sparse,
    ) -> Result<(Vec<String>, Option<Sparse>)> {
        // Before any write, for every tree the stopped op still reads over
        // the new view (the decided root; the tip, which `--abort` and the
        // completion's `tracked_paths_at` read; a rebase's accumulator):
        // fill the closure (lazy partial clones), check it is present, and
        // refuse to lay a file over one the user owns.
        let mut roots = vec![decided];
        if let Some(tip) = self.head_tip()? {
            roots.push(self.snapshot(&tip)?.root);
        }
        if let Some(st) = crate::rebase_state::read(&self.layout)? {
            roots.push(self.snapshot(&st.acc_tip)?.root);
        }
        let store_arc = self.vfs().store();
        for &root in &roots {
            self.ensure_view(root, new)?;
            let mut s = store_arc.lock().unwrap();
            crate::worktree::preflight_view(self.layout(), &mut s, root, new)?;
        }
        // Files an interrupted run of this same widen already wrote (recorded
        // in `.sc/sparse-widen`, bytes equal to the decided root's): a retry
        // may rewrite them. Anything else at those paths is the user's.
        let recorded = load_widen(self.layout(), decided)?;
        let already_laid = {
            let mut s = store_arc.lock().unwrap();
            crate::worktree::added_view_already_laid(
                self.layout(),
                &mut s,
                decided,
                old,
                new,
                &recorded,
            )?
        };
        for root in roots {
            self.refuse_untracked_for_view_change("sparse set", root, old, new, &already_laid)?;
        }
        // Every guard passed, so each path below is the widen's to write:
        // record them (keeping an earlier interrupted run's) before the first.
        let mut written = recorded;
        {
            let mut s = store_arc.lock().unwrap();
            let (plain, _) = crate::worktree::added_view_files(&mut s, decided, old, new)?;
            written.extend(plain.into_iter().map(|(p, _)| p));
        }
        store_widen(self.layout(), decided, &written)?;
        // A partial clone's abort removes only what its removal walk can see,
        // which is the spec's view plus this marker. The files are laid before
        // the spec is stored, so record the new view first; a crash then
        // leaves a bound that covers them. An earlier interrupted `sparse set`
        // may have left its own marker: keep it.
        let partial = self.promisor()?.is_some();
        let prev = load_prev(self.layout())?;
        if partial {
            let bound = prev.as_ref().map_or_else(|| new.clone(), |p| p.union(new));
            store_prev(self.layout(), &bound)?;
        }
        let skipped = {
            let mut s = store_arc.lock().unwrap();
            crate::worktree::lay_out_added_view(self.layout(), &mut s, decided, old, new)?
        };
        Ok((skipped, prev))
    }

    /// The second half: store the spec, drop the record, and put back any
    /// `sparse-prev` marker an earlier interrupted `sparse set` left.
    fn finish_widen(&self, new: &Sparse, prev: Option<Sparse>) -> Result<()> {
        store(self.layout(), new)?;
        remove_if_exists(&self.layout().sparse_widen_path())?;
        if self.promisor()?.is_some() {
            match prev {
                Some(p) => store_prev(self.layout(), &p)?,
                None => clear_prev(self.layout())?,
            }
        }
        Ok(())
    }

    /// Delete the files an interrupted stopped-op widen wrote, when the stop
    /// ends (abort or completion) with the old view still in force. Abort's
    /// removal walk follows the other side's tree and the restored view, so it
    /// cannot see an ours-only file or a subtree it never fetched; this uses
    /// the `.sc/sparse-widen` record instead. A path is removed only if the
    /// record names `decided` (a stale record from another stop is ignored),
    /// the path is outside the current view, and its bytes still equal the
    /// decided tree's: a file the user edited since is theirs. Call it before
    /// the stopped op's state, which removes the record, is cleared.
    pub(crate) fn remove_widen_residue(&self, decided: Option<scl_core::ObjectId>) -> Result<()> {
        let Some(decided) = decided else {
            return Ok(());
        };
        let recorded = load_widen(self.layout(), decided)?;
        if recorded.is_empty() {
            return Ok(());
        }
        let view = self.sparse_spec()?;
        let outside: std::collections::BTreeSet<String> =
            recorded.into_iter().filter(|p| !view.matches(p)).collect();
        let laid = {
            let store_arc = self.vfs().store();
            let mut s = store_arc.lock().unwrap();
            crate::worktree::recorded_paths_laid(self.layout(), &mut s, decided, &outside)?
        };
        for path in laid {
            match std::fs::remove_file(crate::worktree::safe_join(&self.layout.root, &path)?) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// The prefixes in `prefixes` that match no tracked path at HEAD, so a
    /// typo or a path that does not exist is not silently taken for a narrow
    /// view that happens to be empty. Each prefix is one path-directed lookup
    /// (depth, not tree size). A prefix whose answer needs an object this
    /// partial clone does not hold is left out: the report is advice, never a
    /// refusal, and never a guess. An unborn HEAD has no paths and reports
    /// nothing; a private branch refuses, as `sparse set` does.
    pub fn sparse_prefixes_matching_nothing(&self, prefixes: &[String]) -> Result<Vec<String>> {
        self.refuse_on_private("sc sparse set")?;
        let Some(tip) = self.head_tip()? else {
            return Ok(Vec::new());
        };
        let root = self.snapshot(&tip)?.root;
        let store_arc = self.vfs().store();
        let mut store = store_arc.lock().unwrap();
        Ok(prefixes
            .iter()
            .filter(|p| prefix_present(&mut store, root, p.trim_end_matches('/')) == Some(false))
            .cloned()
            .collect())
    }

    /// Disable sparse checkout: clear the persisted spec and re-materialize
    /// HEAD's tree in full, restoring every previously-excluded file to disk.
    /// An unborn HEAD has no working tree to re-lay; the spec is still
    /// cleared.
    ///
    /// Refuses on a dirty working tree, same as [`Repo::set_sparse`] and for
    /// the same reason (the write loop rewrites every in-sparse target entry
    /// unconditionally).
    pub fn disable_sparse(&self, identity: Option<&scl_crypto::SecretKey>) -> Result<Vec<String>> {
        self.refuse_on_private("sc sparse disable")?;
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
        }
        // Gap error on sparse-widen (P27 Task 5): disabling sparse means full
        // materialization, which by definition reaches beyond a partial
        // clone's fetch filter (unless the filter happens to cover the
        // entire tree, which this clone has no way to know without asking
        // the origin). Refuse up front, before any disk write, pointing at
        // backfill — same preflight discipline as `set_sparse` above.
        if let Some(promisor) = self.promisor()? {
            return Err(Error::InvalidArgument(format!(
                "cannot disable sparse checkout (full materialization) on a partial clone: \
                 only [{}] was fetched; run `sc backfill --all` to convert to a full clone \
                 first, or `sc sparse set` to a prefix within it",
                promisor.prefixes().join(", ")
            )));
        }
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(crate::error::Error::InvalidArgument(
                "working tree has uncommitted changes; commit before changing the sparse spec"
                    .into(),
            ));
        }
        if let Some(tip) = self.head_tip()? {
            let root = self.snapshot(&tip)?.root;
            self.refuse_untracked_for_view_change(
                "sparse disable",
                root,
                &self.sparse_spec()?,
                &Sparse::default(),
                &Default::default(),
            )?;
        }
        clear(self.layout())?;
        let Some(tip) = self.head_tip()? else {
            return Ok(Vec::new());
        };
        let snap = self.snapshot(&tip)?;
        let store_arc = self.vfs().store();
        let mut s = store_arc.lock().unwrap();
        let mut cache = self.open_protected_cache()?;
        // ensure-view-exempt: sparse disable is refused on partial clones
        let skipped = crate::worktree::materialize(
            self.layout(),
            &mut s,
            snap.root,
            Some(snap.root),
            &snap.protection,
            identity,
            &Sparse::default(),
            Some(&mut cache),
        )?;
        // Best-effort: the cleared sparse spec is already persisted above and
        // this re-lay moves no branch ref (P33 Task 7).
        cache.save_best_effort();
        Ok(skipped)
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
        assert!(
            !layout.sparse_path().exists(),
            "empty spec must remove the file"
        );

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
    fn covers_is_a_strict_superset_test_on_path_boundaries() {
        let sp = |v: &[&str]| Sparse::new(v.iter().map(|s| s.to_string()).collect());
        assert!(sp(&["src/", "docs/"]).covers(&sp(&["src"])));
        assert!(sp(&["src"]).covers(&sp(&["src/a/", "src/b.txt"])));
        assert!(sp(&["src"]).covers(&sp(&["src"])));
        assert!(sp(&[]).covers(&sp(&["src"])), "full covers everything");
        assert!(sp(&[]).covers(&sp(&[])));
        assert!(!sp(&["src"]).covers(&sp(&[])), "full is wider than any set");
        assert!(!sp(&["src/a.txt"]).covers(&sp(&["src"])), "narrower");
        assert!(!sp(&["docs"]).covers(&sp(&["src"])), "sideways");
        assert!(!sp(&["src"]).covers(&sp(&["srcfoo"])), "boundary, not text");
    }

    #[test]
    fn sparse_set_refused_during_in_progress() {
        use crate::repo::Repo;
        use scl_core::ObjectId;

        // Test that set_sparse refuses during merge, pick, and rebase.
        let root =
            std::env::temp_dir().join(format!("scl-sparse-in-progress-{}", std::process::id()));
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
                crate::pick_state::write(layout, &ObjectId::of(b"picked"), &[], None, None)
                    .unwrap();
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

    /// P27 Task 5: widening a partial clone's sparse spec beyond its
    /// promisor filter must be refused, before touching disk, naming the
    /// offending prefix and pointing at `sc backfill`.
    #[test]
    fn set_sparse_widen_beyond_partial_errors_with_backfill_hint() {
        let src_root =
            std::env::temp_dir().join(format!("scl-sparse-widen-src-{}", std::process::id()));
        let dst_root =
            std::env::temp_dir().join(format!("scl-sparse-widen-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(src_root.join("src")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(src_root.join("docs/b.txt"), b"b").unwrap();
        src.commit("t", "c1").unwrap();

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        let before = dst.sparse_spec().unwrap();
        assert_eq!(before.prefixes(), &["src/".to_string()]);

        let err = dst.set_sparse(&["docs/".to_string()], None).unwrap_err();
        assert!(
            matches!(err, Error::GapOutsideFilter(ref p) if p.contains("docs/")),
            "expected a gap error naming docs/, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("backfill"),
            "error must hint at `sc backfill`: {msg}"
        );

        // No partial write: the spec is unchanged.
        assert_eq!(dst.sparse_spec().unwrap(), before);

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// `sc sparse disable` (full materialization) is always refused on a
    /// partial clone: nothing short of a full backfill can cover the whole
    /// tree. Preflight — before any disk write.
    #[test]
    fn disable_sparse_on_partial_clone_errors_with_backfill_hint() {
        let src_root =
            std::env::temp_dir().join(format!("scl-sparse-disable-src-{}", std::process::id()));
        let dst_root =
            std::env::temp_dir().join(format!("scl-sparse-disable-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(src_root.join("src")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("src/a.txt"), b"a").unwrap();
        std::fs::write(src_root.join("docs/b.txt"), b"b").unwrap();
        src.commit("t", "c1").unwrap();

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        let before = dst.sparse_spec().unwrap();

        let err = dst.disable_sparse(None).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "expected a clear refusal, got {err:?}"
        );
        assert!(
            err.to_string().contains("backfill"),
            "error must hint at `sc backfill`: {err}"
        );

        // No partial write: the spec is unchanged, and nothing outside the
        // filter got materialized to disk.
        assert_eq!(dst.sparse_spec().unwrap(), before);
        assert!(!dst_root.join("docs/b.txt").exists());

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// A narrower-but-still-in-filter widen (e.g. into a subdirectory of the
    /// promisor's own prefix) must NOT be refused.
    #[test]
    fn set_sparse_within_filter_is_allowed_on_partial_clone() {
        let src_root =
            std::env::temp_dir().join(format!("scl-sparse-within-src-{}", std::process::id()));
        let dst_root =
            std::env::temp_dir().join(format!("scl-sparse-within-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(src_root.join("src/app")).unwrap();
        std::fs::create_dir_all(src_root.join("docs")).unwrap();
        let src = Repo::init(&src_root).unwrap();
        std::fs::write(src_root.join("src/app/a.txt"), b"a").unwrap();
        std::fs::write(src_root.join("docs/b.txt"), b"b").unwrap();
        src.commit("t", "c1").unwrap();

        let dst = Repo::clone_url_filtered(
            src_root.to_str().unwrap(),
            &dst_root,
            Some(&["src/".to_string()]),
        )
        .unwrap();

        // A real out-of-filter gap (docs/) exists elsewhere in the tree —
        // narrowing further within the filter must not touch it (P27 Task 5
        // fix to `materialize`'s old-root walk).
        dst.set_sparse(&["src/app/".to_string()], None).unwrap();
        assert_eq!(
            dst.sparse_spec().unwrap().prefixes(),
            &["src/app/".to_string()]
        );
        assert!(!dst_root.join("docs/b.txt").exists());
        assert!(dst_root.join("src/app/a.txt").exists());

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    #[test]
    fn load_ignores_blank_lines_in_a_hand_edited_spec() {
        let layout = tmp_layout("blank-lines");
        std::fs::write(layout.sparse_path(), "src/\n\n  \ndocs/\n\n").unwrap();
        let spec = load(&layout).unwrap();
        assert_eq!(spec.prefixes(), ["src/", "docs/"]);
        assert!(
            !spec.matches("lib/x.txt"),
            "a blank line must not widen the view"
        );

        // A nonblank prefix is kept byte for byte, significant whitespace
        // included, across a store/load round trip.
        let odd = Sparse::new(vec![" lead/".to_string(), "trail /".to_string()]);
        store(&layout, &odd).unwrap();
        assert_eq!(load(&layout).unwrap().prefixes(), odd.prefixes());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn set_sparse_refuses_a_blank_prefix_and_leaves_the_tree_alone() {
        let root =
            std::env::temp_dir().join(format!("scl-sparse-blank-prefix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("src/a.txt"), b"a\n").unwrap();
        repo.commit("t", "c1").unwrap();
        for bad in ["", "   "] {
            let err = repo.set_sparse(&[bad.to_string()], None).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidArgument(m) if m.contains("empty sparse prefix")),
                "got {err:?}"
            );
        }
        assert!(root.join("src/a.txt").exists(), "nothing was removed");
        assert!(
            repo.sparse_spec().unwrap().is_full(),
            "the spec is untouched"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn prefixes_matching_nothing_is_a_path_lookup() {
        let root = std::env::temp_dir().join(format!("scl-sparse-nomatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src/deep")).unwrap();
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("src/deep/a.txt"), b"a\n").unwrap();
        std::fs::write(root.join("top.txt"), b"t\n").unwrap();
        repo.commit("t", "c1").unwrap();
        let ask = |ps: &[&str]| {
            let ps: Vec<String> = ps.iter().map(|p| p.to_string()).collect();
            repo.sparse_prefixes_matching_nothing(&ps).unwrap()
        };
        assert!(ask(&["src/", "src/deep", "top.txt", "src/deep/a.txt"]).is_empty());
        assert_eq!(
            ask(&["sorc/", "src/nope", "top.txt/x", "src/deep/a.txt/y"]).len(),
            4
        );
        // Literal, like `Sparse::matches`: a leading or doubled slash names
        // nothing, so these are reported rather than read as `src/`.
        let odd = ask(&["/src/", "src//deep", "/"]);
        assert_eq!(odd.len(), 3, "got {odd:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_blank_clone_filter_is_refused_before_anything_is_created() {
        let src = std::env::temp_dir().join(format!("scl-blank-filter-src-{}", std::process::id()));
        let dst = std::env::temp_dir().join(format!("scl-blank-filter-dst-{}", std::process::id()));
        for r in [&src, &dst] {
            let _ = std::fs::remove_dir_all(r);
        }
        std::fs::create_dir_all(&src).unwrap();
        let origin = Repo::init(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"a\n").unwrap();
        origin.commit("t", "c1").unwrap();
        for bad in ["", "  "] {
            let Err(err) =
                Repo::clone_url_filtered(src.to_str().unwrap(), &dst, Some(&[bad.to_string()]))
            else {
                panic!("a blank clone filter must be refused");
            };
            assert!(
                matches!(&err, Error::InvalidArgument(m) if m.contains("empty sparse prefix")),
                "got {err:?}"
            );
            assert!(!dst.exists(), "no clone directory may be left behind");
        }
        drop(origin);
        std::fs::remove_dir_all(&src).unwrap();
        assert!(!src.exists());
    }

    #[test]
    fn store_refuses_a_blank_prefix() {
        let layout = tmp_layout("store-blank");
        let err = store(&layout, &Sparse::new(vec!["src/".into(), " ".into()])).unwrap_err();
        assert!(matches!(&err, Error::InvalidArgument(_)), "got {err:?}");
        assert!(!layout.sparse_path().exists(), "nothing was written");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
