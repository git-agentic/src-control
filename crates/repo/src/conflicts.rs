//! The `conflicts` module (P23 Task 1): re-derives a conflicted path's
//! base/ours/theirs content straight from the DAG for whichever operation
//! (merge/pick/rebase) is currently in progress, rather than requiring a
//! caller to hand-parse marker text out of the working tree. This is the
//! foundation Tasks 2–3 (`sc conflicts` / `sc resolve`) build on.

use scl_core::{Object, ObjectId, Store, PROTECTED};

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::worktree::tree_file_entries_with_perms;

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
                let ours = self
                    .head_tip()?
                    .ok_or_else(|| Error::BadRef("HEAD unborn while a merge is in progress".into()))?;
                let theirs = crate::merge_state::read_merge_head(&self.layout)?.ok_or_else(|| {
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
                let ours = self
                    .head_tip()?
                    .ok_or_else(|| Error::BadRef("HEAD unborn while a cherry-pick is in progress".into()))?;
                let base = self.snapshot(&theirs)?.parents.first().copied();
                Ok(OpTriple { ours, theirs, base })
            }
            Some(ActiveOp::Rebase) => {
                let st = crate::rebase_state::read(&self.layout)?
                    .ok_or_else(|| Error::BadRef("REBASE_STATE missing while a rebase is in progress".into()))?;
                let base = self.snapshot(&st.conflicted)?.parents.first().copied();
                Ok(OpTriple { ours: st.acc_tip, theirs: st.conflicted, base })
            }
            None => Err(Error::InvalidArgument("no merge/pick/rebase is in progress".into())),
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
        assert!(matches!(outcome, crate::replay::RebaseResult::Stopped { .. }), "got {outcome:?}");
        assert!(repo.rebase_in_progress());

        assert_eq!(repo.active_conflict_op().unwrap(), Some(ActiveOp::Rebase));
        assert_eq!(repo.active_conflicts().unwrap(), vec!["x.txt".to_string()]);

        let st = crate::rebase_state::read(repo.layout()).unwrap().unwrap();
        assert_eq!(st.conflicted, feature_tip, "the replayed (stopped) commit is theirs");
        assert_eq!(st.acc_tip, main_tip, "acc_tip is ours: nothing landed yet before the stop");

        let versions = repo.conflict_versions("x.txt", None).unwrap();
        assert_eq!(versions.base, Side::Present(b"base\n".to_vec()));
        assert_eq!(versions.ours, Side::Present(b"main-edit\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"feature-edit\n".to_vec()));

        repo.rebase_abort().unwrap();
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
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"theirs\n").unwrap();
        repo.commit("me", "theirs edits secret").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo.merge_with_identity("feature", "me", Some(&alice_sk)).unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(1)), "got {err:?}");
        assert_eq!(repo.active_conflicts().unwrap(), vec!["secret/a.txt".to_string()]);

        // Without identity: refuses.
        let err = repo.conflict_versions("secret/a.txt", None).unwrap_err();
        assert!(matches!(err, Error::ProtectedMergeNeedsIdentity(ref p) if p == "secret/a.txt"), "got {err:?}");

        // With alice's identity: decrypts all three sides.
        let versions = repo.conflict_versions("secret/a.txt", Some(&alice_sk)).unwrap();
        assert_eq!(versions.base, Side::Present(b"base\n".to_vec()));
        assert_eq!(versions.ours, Side::Present(b"ours\n".to_vec()));
        assert_eq!(versions.theirs, Side::Present(b"theirs\n".to_vec()));

        // Bob is also a recipient of every side; his identity decrypts too.
        let versions = repo.conflict_versions("secret/a.txt", Some(&bob_sk)).unwrap();
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

        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/p.txt"), b"theirs\n").unwrap();
        std::fs::write(root.join("text.txt"), b"theirs\n").unwrap();
        std::fs::write(root.join("bin.dat"), [2u8, 159, 146, 150]).unwrap();
        repo.commit("me", "theirs edits all").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo.merge_with_identity("feature", "me", Some(&alice_sk)).unwrap_err();
        assert!(matches!(err, Error::MergeConflicts(3)), "got {err:?}");

        assert_eq!(repo.conflict_kind("secret/p.txt").unwrap(), ConflictKind::Protected);
        assert_eq!(repo.conflict_kind("text.txt").unwrap(), ConflictKind::Text);
        assert_eq!(repo.conflict_kind("bin.dat").unwrap(), ConflictKind::Binary);

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }
}
