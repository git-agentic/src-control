//! The `conflicts` module (P23 Task 1): re-derives a conflicted path's
//! base/ours/theirs content straight from the DAG for whichever operation
//! (merge/pick/rebase) is currently in progress, rather than requiring a
//! caller to hand-parse marker text out of the working tree. This is the
//! foundation Tasks 2–3 (`sc conflicts` / `sc resolve`) build on.

use scl_core::{Object, ObjectId, Store, PROTECTED};

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::worktree::{safe_join, tree_file_entries_with_perms};

/// Which in-progress operation owns the current conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveOp {
    Merge,
    Pick,
    Rebase,
}

/// One side's content for a path, or that the path is absent there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Present(Vec<u8>),
    Absent,
}

/// base/ours/theirs content for one conflicted path, re-derived from the DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictVersions {
    pub base: Side,
    pub ours: Side,
    pub theirs: Side,
}

/// Classification for display and to decide whether `--identity` is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    Text,
    Binary,
    Protected,
}

/// Which side of a conflict `Repo::resolve_path` should write to the working
/// tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveSide {
    Ours,
    Theirs,
}

/// The three snapshot ids that frame a conflicted path under the active op:
/// `ours`/`theirs` are the two sides being reconciled; `base` is their common
/// ancestor (`None` for a root-commit pick/rebase, which has no parent).
struct OpTriple {
    ours: ObjectId,
    theirs: ObjectId,
    base: Option<ObjectId>,
}

impl Repo {
    /// The active in-progress op, by the status precedence (merge → pick →
    /// rebase), or `None` if none is in progress.
    pub fn active_conflict_op(&self) -> Result<Option<ActiveOp>> {
        if crate::merge_state::in_progress(&self.layout) {
            Ok(Some(ActiveOp::Merge))
        } else if crate::pick_state::in_progress(&self.layout) {
            Ok(Some(ActiveOp::Pick))
        } else if crate::rebase_state::in_progress(&self.layout) {
            Ok(Some(ActiveOp::Rebase))
        } else {
            Ok(None)
        }
    }

    /// The conflicted paths recorded for the active op (its `<STATE>_CONFLICTS`).
    pub fn active_conflicts(&self) -> Result<Vec<String>> {
        match self.active_conflict_op()? {
            Some(ActiveOp::Merge) => crate::merge_state::read_conflicts(&self.layout),
            Some(ActiveOp::Pick) => crate::pick_state::read_conflicts(&self.layout),
            Some(ActiveOp::Rebase) => crate::rebase_state::read_conflicts(&self.layout),
            None => Ok(Vec::new()),
        }
    }

    /// Resolve `(ours, theirs, base)` for whichever op is active. Errors if
    /// none is in progress, or if the on-disk state is missing a field its
    /// own `in_progress` signal promised (a corrupt/foreign-written `.sc/`).
    fn op_triple(&self) -> Result<OpTriple> {
        match self.active_conflict_op()? {
            Some(ActiveOp::Merge) => {
                let ours = self.head_tip()?.ok_or_else(|| {
                    Error::BadRef("HEAD unborn while a merge is in progress".into())
                })?;
                let theirs =
                    crate::merge_state::read_merge_head(&self.layout)?.ok_or_else(|| {
                        Error::BadRef("MERGE_HEAD missing while a merge is in progress".into())
                    })?;
                let store_arc = self.vfs.store();
                let mut store = store_arc.lock().unwrap();
                let base = crate::merge::merge_base(&mut store, ours, theirs)?;
                Ok(OpTriple { ours, theirs, base })
            }
            Some(ActiveOp::Pick) => {
                let theirs = crate::pick_state::read_pick_head(&self.layout)?.ok_or_else(|| {
                    Error::BadRef("PICK_HEAD missing while a cherry-pick is in progress".into())
                })?;
                let ours = self.head_tip()?.ok_or_else(|| {
                    Error::BadRef("HEAD unborn while a cherry-pick is in progress".into())
                })?;
                // A `--mainline`-resolved base (persisted in PICK_MAINLINE_BASE,
                // P19 I2) takes priority: a conflicted mainline pick's replay
                // used that parent as its base, so conflict_versions must
                // agree — falling back to parents[0] here would silently
                // re-derive the WRONG base for a mainline != 1 pick.
                let base = match crate::pick_state::read_mainline_base(&self.layout)? {
                    Some(mainline_base) => Some(mainline_base),
                    None => self.snapshot(&theirs)?.parents.first().copied(),
                };
                Ok(OpTriple { ours, theirs, base })
            }
            Some(ActiveOp::Rebase) => {
                let st = crate::rebase_state::read(&self.layout)?.ok_or_else(|| {
                    Error::BadRef("REBASE_STATE missing while a rebase is in progress".into())
                })?;
                let base = self.snapshot(&st.conflicted)?.parents.first().copied();
                Ok(OpTriple {
                    ours: st.acc_tip,
                    theirs: st.conflicted,
                    base,
                })
            }
            None => Err(Error::InvalidArgument(
                "no merge/pick/rebase is in progress".into(),
            )),
        }
    }

    /// Classify a conflicted path (`PROTECTED` perms on either tip → Protected;
    /// else non-UTF8 ours/theirs content → Binary; else Text).
    pub fn conflict_kind(&self, path: &str) -> Result<ConflictKind> {
        let triple = self.op_triple()?;
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        for id in [triple.ours, triple.theirs] {
            let root = store.get_snapshot(&id)?.root;
            let entries = tree_file_entries_with_perms(&mut store, root)?;
            if let Some((_, _, perms)) = entries.get(path) {
                if perms & PROTECTED != 0 {
                    return Ok(ConflictKind::Protected);
                }
            }
        }
        // Neither tip is protected: a None identity is fine to inspect content.
        let ours = side_for(&mut store, triple.ours, None, path)?;
        let theirs = side_for(&mut store, triple.theirs, None, path)?;
        let is_binary = |s: &Side| matches!(s, Side::Present(b) if std::str::from_utf8(b).is_err());
        if is_binary(&ours) || is_binary(&theirs) {
            Ok(ConflictKind::Binary)
        } else {
            Ok(ConflictKind::Text)
        }
    }

    /// base/ours/theirs for `path` under the active op. Protected paths
    /// require `identity` (else `Error::ProtectedMergeNeedsIdentity(path)`).
    pub fn conflict_versions(
        &self,
        path: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<ConflictVersions> {
        let triple = self.op_triple()?;
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let base = match triple.base {
            Some(id) => side_for(&mut store, id, identity, path)?,
            None => Side::Absent,
        };
        let ours = side_for(&mut store, triple.ours, identity, path)?;
        let theirs = side_for(&mut store, triple.theirs, identity, path)?;
        Ok(ConflictVersions { base, ours, theirs })
    }

    /// Resolve one conflicted path to `side`: write that side's content to
    /// the working file (or delete the file if the side is `Absent`),
    /// remove the `.theirs` sidecar this system may have written for a
    /// binary conflict (only if `{path}.theirs` isn't itself a tracked file
    /// — see below), and drop `path` from the active op's conflict record.
    /// Protected paths need `identity`
    /// (decrypt only — this never re-encrypts; completion's commit path does
    /// that). Errors if `path` is not currently conflicted or no op is in
    /// progress.
    pub fn resolve_path(
        &self,
        path: &str,
        side: ResolveSide,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<()> {
        let op = self
            .active_conflict_op()?
            .ok_or_else(|| Error::InvalidArgument("no merge/pick/rebase is in progress".into()))?;
        let conflicts = self.active_conflicts()?;
        if !conflicts.iter().any(|p| p == path) {
            return Err(Error::InvalidArgument(format!(
                "{path} is not currently conflicted"
            )));
        }
        // Gate on sparse (P24 Task 4) before writing anything: resolving a
        // path outside the sparse view would materialize a file the user
        // asked to exclude from disk. Inspection (`conflict_versions`) is
        // DAG-derived and untouched by this — it still works for an
        // out-of-sparse conflict, only the write-to-disk path is refused.
        if !self.sparse_spec()?.matches(path) {
            return Err(Error::InvalidArgument(format!(
                "conflict in {path} is outside your sparse checkout; run `sc sparse set` to include it, then retry"
            )));
        }

        let versions = self.conflict_versions(path, identity)?;
        let chosen = match side {
            ResolveSide::Ours => versions.ours,
            ResolveSide::Theirs => versions.theirs,
        };

        let full = safe_join(&self.layout.root, path)?;
        match chosen {
            Side::Present(bytes) => {
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&full, &bytes)?;
            }
            Side::Absent => match std::fs::remove_file(&full) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            },
        }

        // Drop the `.theirs` sidecar this system may have written — the only
        // sidecar extension ever written (`.base` and `.ours` are never
        // produced, so removing them was both dead code and a footgun: a
        // repo can legitimately track a real file named
        // `foo.txt.base`/`foo.txt.ours`, and blind-unlinking it would
        // silently destroy user data). `.theirs` is written only for
        // BINARY/PROTECTED-with-binary-content conflicts (merge.rs writes
        // `{path}.theirs` in the binary-conflict arm) — a TEXT conflict
        // never writes one, so a `.theirs`-named file sitting untracked next
        // to a text conflict is not this system's scratch, it's the user's;
        // removing it there would silently and unrecoverably delete
        // untracked data. So only consider removal when the conflict kind is
        // NOT Text (`!= Text`, not `== Binary`: a protected binary conflict
        // still writes a plaintext `.theirs` sidecar and classifies as
        // Protected, so it must still be cleaned up). And even then, only
        // remove it when it is NOT a tracked path — a genuine sidecar is
        // untracked scratch by construction, so a tracked `{path}.theirs`
        // must be a user's real file and is left alone.
        if self.conflict_kind(path)? != ConflictKind::Text {
            let theirs_sidecar_path = format!("{path}.theirs");
            if !self.tracked_paths()?.contains(&theirs_sidecar_path) {
                let sidecar = safe_join(&self.layout.root, &theirs_sidecar_path)?;
                match std::fs::remove_file(&sidecar) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }

        let remaining: Vec<String> = conflicts.into_iter().filter(|p| p != path).collect();
        match op {
            ActiveOp::Merge => crate::merge_state::set_conflicts(&self.layout, &remaining)?,
            ActiveOp::Pick => crate::pick_state::set_conflicts(&self.layout, &remaining)?,
            ActiveOp::Rebase => crate::rebase_state::write_conflicts(&self.layout, &remaining)?,
        }
        Ok(())
    }
}

/// One side's content for `path` at `snapshot_id`: absent if the path isn't
/// in that snapshot's tree; else the plaintext bytes, decrypting through the
/// snapshot's own protection registry (the wraps that sealed it) if the
/// entry is `PROTECTED`.
fn side_for(
    store: &mut Store,
    snapshot_id: ObjectId,
    identity: Option<&scl_crypto::SecretKey>,
    path: &str,
) -> Result<Side> {
    let snap = store.get_snapshot(&snapshot_id)?;
    let entries = tree_file_entries_with_perms(store, snap.root)?;
    let Some((blob_id, _mode, perms)) = entries.get(path).copied() else {
        return Ok(Side::Absent);
    };
    let bytes = match store.get(&blob_id)? {
        Object::Blob(b) => b,
        _ => return Err(Error::BadRef(format!("{path}: tree entry is not a blob"))),
    };
    if perms & PROTECTED != 0 {
        let sk = identity.ok_or_else(|| Error::ProtectedMergeNeedsIdentity(path.to_string()))?;
        let pt = crate::protect::decrypt_with(&bytes, &blob_id, &[&snap.protection], sk, path)?;
        Ok(Side::Present(pt.to_vec()))
    } else {
        Ok(Side::Present(bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-conflicts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn active_op_precedence_and_none() {
        let root = tmp_root("precedence");
        let repo = Repo::init(&root).unwrap();
        assert_eq!(repo.active_conflict_op().unwrap(), None);
        assert_eq!(repo.active_conflicts().unwrap(), Vec::<String>::new());

        // Write raw merge state: reports Merge.
        let dummy = ObjectId::of(b"dummy-theirs");
        crate::merge_state::write(repo.layout(), &dummy, &["a.txt".into()], None).unwrap();
        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Merge));
        assert_eq!(repo.active_conflicts().unwrap(), vec!["a.txt".to_string()]);

        // Merge takes precedence even when pick/rebase state also exist.
        crate::pick_state::write(repo.layout(), &dummy, &["b.txt".into()], None, None).unwrap();
        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Merge));
        crate::merge_state::clear(repo.layout()).unwrap();

        // Pick takes precedence over rebase.
        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Pick));
        assert_eq!(repo.active_conflicts().unwrap(), vec!["b.txt".to_string()]);
        let rebase_st = crate::rebase_state::RebaseState {
            branch: "feature".into(),
            original_tip: dummy,
            target: "main".into(),
            acc_tip: dummy,
            conflicted: dummy,
            remaining: vec![],
            total: 1,
            author: "me".into(),
            resolved: false,
            replayed: 0,
            skipped: 0,
        };
        crate::rebase_state::write(repo.layout(), &rebase_st).unwrap();
        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Pick));
        crate::pick_state::clear(repo.layout()).unwrap();

        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Rebase));
        crate::rebase_state::clear(repo.layout()).unwrap();
        assert_eq!(repo.active_conflict_op().unwrap(), None);

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn versions_from_merge() {
        let root = tmp_root("merge");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Merge));
        assert_eq!(repo.active_conflicts().unwrap(), vec!["a.txt".to_string()]);

        let versions = repo.conflict_versions("a.txt", None).unwrap();
        assert_eq!(versions.base, Side::Present(b"base\n".to_vec()));
        assert_eq!(versions.ours, Side::Present(b"ours\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"theirs\n".to_vec()));

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn versions_from_pick() {
        let root = tmp_root("pick");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        std::fs::write(root.join("x.txt"), b"main-edit\n").unwrap();
        let main_tip = repo.commit("me", "main edits x").unwrap();

        repo.switch("work").unwrap();
        std::fs::write(root.join("x.txt"), b"work-edit\n").unwrap();
        let picked = repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip));

        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");

        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Pick));
        assert_eq!(repo.active_conflicts().unwrap(), vec!["x.txt".to_string()]);
        assert_eq!(repo.pick_head().unwrap(), Some(picked));

        let versions = repo.conflict_versions("x.txt", None).unwrap();
        // theirs/base track PICK_HEAD (`picked`) and its parent (the shared
        // base commit); ours tracks the branch tip (`main_tip`).
        assert_eq!(versions.base, Side::Present(b"base\n".to_vec()));
        assert_eq!(versions.ours, Side::Present(b"main-edit\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"work-edit\n".to_vec()));

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn versions_from_rebase_stop() {
        let root = tmp_root("rebase");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"main-edit\n").unwrap();
        repo.commit("me", "main edits x").unwrap();
        let main_tip = repo.head_tip().unwrap().unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"feature-edit\n").unwrap();
        let feature_tip = repo.commit("me", "feature edits x").unwrap();
        // Stay on feature: rebase feature onto main.

        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(
            matches!(outcome, crate::replay::RebaseResult::Stopped { .. }),
            "got {outcome:?}"
        );
        assert!(repo.rebase_in_progress());

        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Rebase));
        assert_eq!(repo.active_conflicts().unwrap(), vec!["x.txt".to_string()]);

        let st = crate::rebase_state::read(repo.layout()).unwrap().unwrap();
        assert_eq!(
            st.conflicted, feature_tip,
            "the replayed (stopped) commit is theirs"
        );
        assert_eq!(
            st.acc_tip, main_tip,
            "acc_tip is ours: nothing landed yet before the stop"
        );

        let versions = repo.conflict_versions("x.txt", None).unwrap();
        assert_eq!(versions.base, Side::Present(b"base\n".to_vec()));
        assert_eq!(versions.ours, Side::Present(b"main-edit\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"feature-edit\n".to_vec()));

        repo.rebase_abort().unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_out_of_sparse_path_errors_widen() {
        // P24 Task 4: `resolve_path` gates on sparse before writing anything
        // to disk. Reachable in practice via a narrower spec being persisted
        // out-of-band while a conflict from a wider view is still active
        // (`Repo::set_sparse` itself refuses mid-conflict, so this exercises
        // `resolve_path`'s own defensive gate directly, bypassing that
        // guard the way an operator editing `.sc/sparse` by hand could).
        // Inspection (`conflict_versions`) is DAG-derived and must still work.
        let root = tmp_root("resolve-sparse-gate");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert_eq!(repo.active_conflicts().unwrap(), vec!["a.txt".to_string()]);

        // Narrow the spec out-of-band so a.txt now falls outside it.
        crate::sparse::store(
            repo.layout(),
            &crate::sparse::Sparse::new(vec!["src/".into()]),
        )
        .unwrap();

        // Inspection still works.
        let versions = repo.conflict_versions("a.txt", None).unwrap();
        assert_eq!(versions.ours, Side::Present(b"ours\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"theirs\n".to_vec()));

        // Resolving is refused with the widen hint.
        let err = repo
            .resolve_path("a.txt", ResolveSide::Ours, None)
            .unwrap_err();
        match err {
            Error::InvalidArgument(msg) => {
                assert!(msg.contains("a.txt"), "message must name the path: {msg}");
                assert!(
                    msg.contains("sc sparse set"),
                    "message must suggest widening the sparse set: {msg}"
                );
            }
            other => panic!("expected InvalidArgument widen hint, got {other:?}"),
        }
        // Still conflicted: resolution was refused, not silently applied.
        assert_eq!(repo.active_conflicts().unwrap(), vec!["a.txt".to_string()]);

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn absent_side_is_absent() {
        // Add/delete conflict: theirs deletes a.txt while ours edits it
        // (a real P4 conflict, per merge.rs's add/delete-vs-modify handling) —
        // theirs is missing the path entirely.
        let root = tmp_root("absent");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours-edit\n").unwrap();
        repo.commit("me", "ours edits").unwrap();
        repo.switch("feature").unwrap();
        std::fs::remove_file(root.join("a.txt")).unwrap();
        repo.commit("me", "theirs deletes").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        let versions = repo.conflict_versions("a.txt", None).unwrap();
        assert_eq!(versions.base, Side::Present(b"base\n".to_vec()));
        assert_eq!(versions.ours, Side::Present(b"ours-edit\n".to_vec()));
        assert_eq!(versions.theirs, Side::Absent);

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn protected_needs_identity_then_decrypts() {
        let root = tmp_root("protected");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk, bob_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours edits secret").unwrap();
        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("secret/a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs edits secret").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo
            .merge_with_identity("feature", "me", Some(&alice_sk))
            .unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert_eq!(
            repo.active_conflicts().unwrap(),
            vec!["secret/a.txt".to_string()]
        );

        // Without identity: refuses.
        let err = repo.conflict_versions("secret/a.txt", None).unwrap_err();
        assert!(
            matches!(err, Error::ProtectedMergeNeedsIdentity(ref p) if p == "secret/a.txt"),
            "got {err:?}"
        );

        // With alice's identity: decrypts all three sides.
        let versions = repo
            .conflict_versions("secret/a.txt", Some(&alice_sk))
            .unwrap();
        assert_eq!(versions.base, Side::Present(b"base\n".to_vec()));
        assert_eq!(versions.ours, Side::Present(b"ours\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"theirs\n".to_vec()));

        // Bob is also a recipient of every side; his identity decrypts too.
        let versions = repo
            .conflict_versions("secret/a.txt", Some(&bob_sk))
            .unwrap();
        assert_eq!(versions.ours, Side::Present(b"ours\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"theirs\n".to_vec()));

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn kind_classification() {
        let root = tmp_root("kind");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let _ = &alice_sk;
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/p.txt"), b"base\n").unwrap();
        std::fs::write(root.join("text.txt"), b"base\n").unwrap();
        std::fs::write(root.join("bin.dat"), [0u8, 159, 146, 150]).unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/p.txt"), b"ours\n").unwrap();
        std::fs::write(root.join("text.txt"), b"ours\n").unwrap();
        std::fs::write(root.join("bin.dat"), [1u8, 159, 146, 150]).unwrap();
        repo.commit("me", "ours edits all").unwrap();

        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("secret/p.txt"), b"theirs\n").unwrap();
        std::fs::write(root.join("text.txt"), b"theirs\n").unwrap();
        std::fs::write(root.join("bin.dat"), [2u8, 159, 146, 150]).unwrap();
        repo.commit("me", "theirs edits all").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo
            .merge_with_identity("feature", "me", Some(&alice_sk))
            .unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(3)), "got {err:?}");

        assert_eq!(
            repo.conflict_kind("secret/p.txt").unwrap(),
            ConflictKind::Protected
        );
        assert_eq!(repo.conflict_kind("text.txt").unwrap(), ConflictKind::Text);
        assert_eq!(repo.conflict_kind("bin.dat").unwrap(), ConflictKind::Binary);

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_ours_writes_clean_and_drops_record() {
        let root = tmp_root("resolve-ours");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        repo.resolve_path("a.txt", ResolveSide::Ours, None).unwrap();

        let on_disk = std::fs::read(root.join("a.txt")).unwrap();
        assert_eq!(on_disk, b"ours\n");
        assert!(
            !String::from_utf8_lossy(&on_disk).contains("<<<<<<<"),
            "resolved file must be clean of markers"
        );
        assert!(
            repo.active_conflicts().unwrap().is_empty(),
            "resolved path must be dropped from the record"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_theirs_across_pick_and_rebase() {
        // Pick side.
        let root = tmp_root("resolve-theirs-pick");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        std::fs::write(root.join("x.txt"), b"main-edit\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch("work").unwrap();
        std::fs::write(root.join("x.txt"), b"work-edit\n").unwrap();
        repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();

        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");

        repo.resolve_path("x.txt", ResolveSide::Theirs, None)
            .unwrap();
        let on_disk = std::fs::read(root.join("x.txt")).unwrap();
        assert_eq!(on_disk, b"work-edit\n");
        assert!(repo.active_conflicts().unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();

        // Rebase side.
        let root = tmp_root("resolve-theirs-rebase");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"main-edit\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"feature-edit\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();

        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(
            matches!(outcome, crate::replay::RebaseResult::Stopped { .. }),
            "got {outcome:?}"
        );
        assert!(repo.rebase_in_progress());

        repo.resolve_path("x.txt", ResolveSide::Theirs, None)
            .unwrap();
        let on_disk = std::fs::read(root.join("x.txt")).unwrap();
        assert_eq!(on_disk, b"feature-edit\n");
        assert!(repo.active_conflicts().unwrap().is_empty());

        repo.rebase_abort().unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_absent_side_deletes_file() {
        let root = tmp_root("resolve-absent");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours-edit\n").unwrap();
        repo.commit("me", "ours edits").unwrap();
        repo.switch("feature").unwrap();
        std::fs::remove_file(root.join("a.txt")).unwrap();
        repo.commit("me", "theirs deletes").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        // theirs is Absent: resolving to Theirs must delete the file.
        repo.resolve_path("a.txt", ResolveSide::Theirs, None)
            .unwrap();
        assert!(!root.join("a.txt").exists());
        assert!(repo.active_conflicts().unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_removes_theirs_sidecar() {
        let root = tmp_root("resolve-sidecar");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("bin.dat"), [0u8, 159, 146, 150]).unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("bin.dat"), [1u8, 159, 146, 150]).unwrap();
        repo.commit("me", "ours edits bin").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("bin.dat"), [2u8, 159, 146, 150]).unwrap();
        repo.commit("me", "theirs edits bin").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert!(
            root.join("bin.dat.theirs").exists(),
            "test setup: sidecar must be on disk"
        );

        repo.resolve_path("bin.dat", ResolveSide::Ours, None)
            .unwrap();
        assert!(
            !root.join("bin.dat.theirs").exists(),
            "sidecar must be removed on resolve"
        );
        assert_eq!(
            std::fs::read(root.join("bin.dat")).unwrap(),
            vec![1u8, 159, 146, 150]
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// P23 review fix: `resolve_path` used to unconditionally `remove_file`
    /// `{path}.theirs`/`.base`/`.ours` sidecars. `.base`/`.ours` are never
    /// written by this system, and even `.theirs` is only a genuine sidecar
    /// when untracked — a repo can track a real file named `a.txt.theirs`,
    /// and resolving a conflict on `a.txt` must never delete it.
    #[test]
    fn resolve_does_not_delete_a_real_tracked_sidecar_named_file() {
        let root = tmp_root("resolve-real-sidecar");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        std::fs::write(root.join("a.txt.theirs"), b"real tracked content\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        repo.resolve_path("a.txt", ResolveSide::Ours, None).unwrap();

        assert!(
            root.join("a.txt.theirs").exists(),
            "a real tracked file named a.txt.theirs must survive resolving a.txt's conflict"
        );
        assert_eq!(
            std::fs::read(root.join("a.txt.theirs")).unwrap(),
            b"real tracked content\n",
            "tracked sidecar-named file content must be untouched"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// P23 final-review fix: for a TEXT conflict this system never writes a
    /// `.theirs` sidecar (only BINARY/PROTECTED-binary conflicts do), so an
    /// untracked file that merely happens to be named `file.txt.theirs`
    /// (e.g. a user's scratch file) is not this system's residue. Resolving
    /// a TEXT conflict on `file.txt` must leave it alone.
    #[test]
    fn resolve_text_conflict_preserves_untracked_theirs_named_file() {
        let root = tmp_root("resolve-text-preserves-untracked-theirs");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("file.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("file.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("file.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert_eq!(
            repo.conflict_kind("file.txt").unwrap(),
            ConflictKind::Text,
            "test setup: this must be a text conflict"
        );

        // An untracked scratch file that happens to share the sidecar name.
        std::fs::write(root.join("file.txt.theirs"), b"user scratch content\n").unwrap();

        repo.resolve_path("file.txt", ResolveSide::Ours, None)
            .unwrap();

        assert!(
            root.join("file.txt.theirs").exists(),
            "untracked file.txt.theirs must survive resolving a TEXT conflict on file.txt"
        );
        assert_eq!(
            std::fs::read(root.join("file.txt.theirs")).unwrap(),
            b"user scratch content\n",
            "untracked sidecar-named file content must be untouched"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_one_of_several_conflicts_leaves_the_rest() {
        // Every other resolve test conflicts on exactly one path, so
        // `retain != path` always degenerates to the empty-list case. This
        // test conflicts on three paths and resolves only one, exercising
        // the "drop one, keep the rest" branch the task is named for.
        let root = tmp_root("resolve-partial");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        std::fs::write(root.join("b.txt"), b"base\n").unwrap();
        std::fs::write(root.join("c.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours-a\n").unwrap();
        std::fs::write(root.join("b.txt"), b"ours-b\n").unwrap();
        std::fs::write(root.join("c.txt"), b"ours-c\n").unwrap();
        repo.commit("me", "ours edits all").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs-a\n").unwrap();
        std::fs::write(root.join("b.txt"), b"theirs-b\n").unwrap();
        std::fs::write(root.join("c.txt"), b"theirs-c\n").unwrap();
        repo.commit("me", "theirs edits all").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(3)), "got {err:?}");
        let mut before = repo.active_conflicts().unwrap();
        before.sort();
        assert_eq!(
            before,
            vec![
                "a.txt".to_string(),
                "b.txt".to_string(),
                "c.txt".to_string()
            ]
        );

        repo.resolve_path("b.txt", ResolveSide::Ours, None).unwrap();

        let mut after = repo.active_conflicts().unwrap();
        after.sort();
        assert_eq!(
            after,
            vec!["a.txt".to_string(), "c.txt".to_string()],
            "only b.txt is dropped; a.txt and c.txt remain conflicted"
        );
        assert_eq!(std::fs::read(root.join("b.txt")).unwrap(), b"ours-b\n");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_protected_needs_identity() {
        let root = tmp_root("resolve-protected");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours edits secret").unwrap();
        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("secret/a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs edits secret").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo
            .merge_with_identity("feature", "me", Some(&alice_sk))
            .unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        let err = repo
            .resolve_path("secret/a.txt", ResolveSide::Ours, None)
            .unwrap_err();
        assert!(
            matches!(err, Error::ProtectedMergeNeedsIdentity(ref p) if p == "secret/a.txt"),
            "got {err:?}"
        );

        repo.resolve_path("secret/a.txt", ResolveSide::Ours, Some(&alice_sk))
            .unwrap();
        assert_eq!(std::fs::read(root.join("secret/a.txt")).unwrap(), b"ours\n");
        assert!(repo.active_conflicts().unwrap().is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolved_merge_completes_via_commit() {
        let root = tmp_root("resolve-completes");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();

        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        repo.resolve_path("a.txt", ResolveSide::Ours, None).unwrap();
        let tip = repo.commit("me", "resolve via ours").unwrap();
        assert!(
            repo.active_conflict_op().unwrap().is_none(),
            "merge state cleared by commit"
        );

        let snap = repo.snapshot(&tip).unwrap();
        let store_arc = repo.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let entries = tree_file_entries_with_perms(&mut store, snap.root).unwrap();
        let (blob_id, _, _) = entries.get("a.txt").copied().unwrap();
        let bytes = match store.get(&blob_id).unwrap() {
            Object::Blob(b) => b,
            _ => panic!("expected blob"),
        };
        assert_eq!(&bytes[..], b"ours\n");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_nonconflicted_or_no_op_errors() {
        let root = tmp_root("resolve-errors");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();

        // No op in progress at all.
        let err = repo
            .resolve_path("a.txt", ResolveSide::Ours, None)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

        // An op is in progress, but the path named isn't one of its conflicts.
        repo.branch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"ours\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        let err = repo.merge("feature", "me").unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");

        let err = repo
            .resolve_path("does-not-exist.txt", ResolveSide::Ours, None)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Task 2 mandatory carry-in from Task 1 review: `op_triple`'s Pick arm
    /// must base a conflicted MAINLINE pick's `conflict_versions` on
    /// `PICK_MAINLINE_BASE` (the parent `--mainline` resolved to and the file
    /// replay actually used), not silently fall back to the picked commit's
    /// `parents[0]` — that would re-derive the WRONG base whenever
    /// `--mainline` selected any parent other than 1. Mirrors the shape of
    /// `replay.rs`'s `conflicted_mainline_pick_completion_bases_registry_off_chosen_parent`:
    /// a-side and b-side both branch off a common base, target-m2 branches
    /// off a-side and independently edits x.txt so mainline-2's delta
    /// (b_tip -> merge) conflicts, forcing `PickConflicts`.
    #[test]
    fn versions_from_mainline_pick_uses_chosen_parent_base() {
        let root = tmp_root("mainline-pick-base");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"x\n").unwrap();
        repo.commit("me", "base").unwrap();

        repo.branch("a-side").unwrap();
        repo.branch("b-side").unwrap();

        repo.switch("a-side").unwrap();
        std::fs::write(root.join("x.txt"), b"a-edit\n").unwrap();
        repo.commit("me", "a-side edits x.txt").unwrap();
        let a_tip = repo.head_tip().unwrap().unwrap();
        repo.branch("target-m2").unwrap();

        // target-m2 independently edits x.txt so the mainline-2 delta
        // (b_tip -> merge, "x\n" -> "a-edit\n") conflicts with it.
        repo.switch("target-m2").unwrap();
        std::fs::write(root.join("x.txt"), b"target-edit\n").unwrap();
        repo.commit("me", "target independently edits x.txt")
            .unwrap();

        repo.switch("b-side").unwrap();
        // b-side does not touch x.txt: b_tip's x.txt stays "x\n".
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "b-side adds b.txt").unwrap();
        let b_tip = repo.head_tip().unwrap().unwrap();

        repo.switch("a-side").unwrap();
        let m = repo.merge("b-side", "me").unwrap();
        let m_snap = repo.snapshot(&m).unwrap();
        assert_eq!(m_snap.parents, vec![a_tip, b_tip]);

        // --mainline 2 onto target-m2: base = b_tip (unchanged x.txt = "x\n"),
        // NOT parents[0] = a_tip (x.txt = "a-edit\n").
        repo.switch("target-m2").unwrap();
        let err = repo.cherry_pick("a-side", "me", None, Some(2)).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");

        let versions = repo.conflict_versions("x.txt", None).unwrap();
        assert_eq!(
            versions.base,
            Side::Present(b"x\n".to_vec()),
            "base must track the --mainline 2-chosen parent (b_tip), not parents[0] (a_tip)"
        );

        repo.resolve_path("x.txt", ResolveSide::Theirs, None)
            .unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }
}
