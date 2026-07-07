//! `sc rewrap` (P17): one-commit bulk cutover of every secret and protected
//! blob at the tip to the current recipient/escrow sets. Composes the P11
//! rotate machinery (secrets) and the P7 grant-style wrap lookup (paths);
//! skip-and-report semantics — see ADR-0027 for why not all-or-nothing.

use scl_core::{Object, ObjectId, WrappedKey};
use scl_crypto::{PublicKey, SecretKey};

use crate::error::{Error, Result};
use crate::repo::Repo;

/// What a `rewrap` run did (or would do, on dry-run).
#[derive(Debug)]
pub struct RewrapReport {
    pub secrets_rewrapped: Vec<String>,
    pub blobs_rewrapped: usize,
    /// (entry label e.g. "secret db-pass" / "path secret/db.txt", reason)
    pub skipped: Vec<(String, String)>,
    /// The commit id; None on --dry-run or when nothing needed rewrapping.
    pub commit: Option<ObjectId>,
}

impl Repo {
    /// Re-seal every secret (fresh DEK, current recipients + escrow) and
    /// replace every protected blob's wrap list (rule's granted set + escrow)
    /// at the tip, as ONE commit and ONE oplog record. Entries `identity`
    /// cannot open are skipped and reported. Policy/registry-only: the root
    /// tree id is untouched. Cuts the LIVE TIP only — history keeps old wraps
    /// and old secret objects (content addressing; same boundary as rotation,
    /// ADR-0019).
    pub fn rewrap(
        &self,
        identity: &SecretKey,
        escrows: &[PublicKey],
        known_keys: &[PublicKey],
        dry_run: bool,
    ) -> Result<RewrapReport> {
        // Refuse mid-merge/mid-pick: completion unions the OLD wraps back in
        // over rewrap's cutover, silently resurrecting a stripped recipient
        // at the tip (final-review I1). Checked even on --dry-run — a
        // dry-run report computed against a state that's about to be
        // unioned away would be just as misleading as a real commit.
        if crate::merge_state::in_progress(self.layout()) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(self.layout()) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(self.layout()) {
            return Err(Error::RebaseInProgress);
        }
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let snap = self.snapshot(&tip)?;
        let mut skipped: Vec<(String, String)> = Vec::new();

        // ---- Secrets half: fresh-DEK reseal to current set + escrow. ----
        let mut registry = snap.secrets.clone();
        let mut secrets_rewrapped = Vec::new();
        let mut new_secret_objs: Vec<(String, Object)> = Vec::new();
        for (name, sid) in registry.clone() {
            let secret = {
                let arc = self.store_arc();
                let obj = arc.lock().unwrap().get(&sid)?;
                match obj {
                    Object::Secret(s) => s,
                    _ => {
                        skipped.push((format!("secret {name}"), "registry entry is not a secret".into()));
                        continue;
                    }
                }
            };
            // Resolve current recipient ids to pubkeys from the known pool.
            let mut targets: Vec<PublicKey> = Vec::new();
            let mut unresolvable = None;
            for w in &secret.wrapped_keys {
                match known_keys.iter().find(|k| k.recipient_id().as_str() == w.recipient_id) {
                    Some(pk) => {
                        if !targets.iter().any(|t| t.recipient_id() == pk.recipient_id()) {
                            targets.push(pk.clone());
                        }
                    }
                    None => {
                        unresolvable = Some(w.recipient_id.clone());
                        break;
                    }
                }
            }
            if let Some(rid) = unresolvable {
                skipped.push((
                    format!("secret {name}"),
                    format!("recipient id {rid} not resolvable to a public key (add to recipients.toml)"),
                ));
                continue;
            }
            let targets = crate::secrets::append_dedup(targets, escrows);
            let value = match scl_crypto::open(&secret, identity) {
                Ok(v) => v,
                Err(_) => {
                    skipped.push((format!("secret {name}"), "identity cannot open this secret".into()));
                    continue;
                }
            };
            crate::secrets::require_recipients(&targets)?;
            if dry_run {
                secrets_rewrapped.push(name);
                continue;
            }
            let sealed = scl_crypto::seal(&secret.name, &value, &targets);
            new_secret_objs.push((name, Object::Secret(sealed)));
        }

        // ---- Paths half: replace wrap lists with granted + escrow. ----
        let mut protection = snap.protection.clone();
        let mut blobs_rewrapped = 0usize;
        let entries = {
            let arc = self.store_arc();
            let mut store = arc.lock().unwrap();
            crate::worktree::tree_file_entries_with_perms(&mut store, snap.root)?
        };
        for (path, (blob_id, _mode, perms)) in entries {
            if perms & scl_core::PROTECTED == 0 {
                continue;
            }
            let Some(rule) = crate::protect::matching_prefix(&protection, &path) else {
                skipped.push((format!("path {path}"), "no governing rule (bit/rule mismatch)".into()));
                continue;
            };
            let granted = rule.granted_keys();
            if granted.is_empty() {
                skipped.push((
                    format!("path {path}"),
                    "rule has no granted recipients (crossed revokes?); run `sc grant` first".into(),
                ));
                continue;
            }
            let Some(wks) = protection.wrapped.get(&blob_id) else {
                skipped.push((format!("path {path}"), "no wrapped DEKs recorded for blob".into()));
                continue;
            };
            let my_id = identity.public().recipient_id().to_string();
            let Some(wk) = wks.iter().find(|w| w.recipient_id == my_id) else {
                skipped.push((format!("path {path}"), "identity is not a recipient of this blob".into()));
                continue;
            };
            let dek = match scl_crypto::unwrap_dek_with(wk, identity) {
                Ok(d) => d,
                Err(e) => {
                    skipped.push((format!("path {path}"), format!("wrap failed to open: {e}")));
                    continue;
                }
            };
            if dry_run {
                blobs_rewrapped += 1;
                continue;
            }
            // Rebuild the wrap list: exactly granted + escrow, reusing prior
            // wrap bytes for recipients already present (id-stability), fresh
            // wraps for the rest. Tombstoned/stale wraps are dropped.
            let prior = wks.clone();
            let mut new_wks: Vec<WrappedKey> = Vec::new();
            let mut target_pks: Vec<PublicKey> =
                granted.iter().map(|b| PublicKey::from_bytes(*b)).collect();
            for e in escrows {
                if !target_pks.iter().any(|t| t.recipient_id() == e.recipient_id()) {
                    target_pks.push(e.clone());
                }
            }
            for pk in &target_pks {
                let rid = pk.recipient_id().to_string();
                match prior.iter().find(|w| w.recipient_id == rid) {
                    Some(existing) => new_wks.push(existing.clone()),
                    None => new_wks.push(scl_crypto::wrap_dek_for(&dek, pk)),
                }
            }
            new_wks.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
            protection.wrapped.insert(blob_id, new_wks);
            blobs_rewrapped += 1;
        }

        // ---- Nothing to do / dry-run: report only. ----
        if dry_run || (secrets_rewrapped.is_empty() && new_secret_objs.is_empty() && blobs_rewrapped == 0) {
            return Ok(RewrapReport { secrets_rewrapped, blobs_rewrapped, skipped, commit: None });
        }

        // ---- One commit + one oplog record. ----
        for (name, obj) in new_secret_objs {
            let id = {
                let arc = self.store_arc();
                let i = arc.lock().unwrap().put(obj)?;
                i
            };
            registry.insert(name.clone(), id);
            secrets_rewrapped.push(name);
        }
        let head = crate::refs::current_branch(self.layout())?;
        let before = crate::refs::read_branch_tip(self.layout(), &head)?;
        let msg = format!(
            "rewrap: {} secret(s), {} blob(s)",
            secrets_rewrapped.len(),
            blobs_rewrapped
        );
        let id = self.commit_snapshot(snap.root, vec![tip], registry, protection, "system", &msg)?;
        crate::oplog::record(self.layout(), "rewrap", &head, &head, &[(head.clone(), before, Some(id))])?;
        Ok(RewrapReport { secrets_rewrapped, blobs_rewrapped, skipped, commit: Some(id) })
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::repo::Repo;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-rewrap-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn rewrap_adds_escrow_to_pre_escrow_secret_in_one_commit() {
        let root = tmp_root("secret-escrow");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_esc_sk, esc_pk) = scl_crypto::generate_keypair();
        repo.secret_add("db-pass", b"hunter2", std::slice::from_ref(&alice_pk)).unwrap();
        repo.secret_add("api-key", b"tok", std::slice::from_ref(&alice_pk)).unwrap();
        let tip_before = repo.head_tip().unwrap().unwrap();

        let report = repo
            .rewrap(&alice_sk, std::slice::from_ref(&esc_pk), std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert_eq!(report.secrets_rewrapped.len(), 2);
        assert!(report.skipped.is_empty());
        let commit = report.commit.expect("must commit");

        // ONE commit: new tip's sole parent is the old tip.
        assert_eq!(repo.snapshot(&commit).unwrap().parents, vec![tip_before]);
        // Both secrets now sealed to alice + escrow.
        for name in ["db-pass", "api-key"] {
            let rids = repo.secret_recipients(name).unwrap();
            assert_eq!(rids.len(), 2, "{name} must gain the escrow key");
            assert!(rids.contains(&esc_pk.recipient_id()));
        }
        // Root unchanged (policy/registry-only).
        assert_eq!(
            repo.snapshot(&commit).unwrap().root,
            repo.snapshot(&tip_before).unwrap().root
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_strips_reattached_wraps_after_pre_revoke_merge() {
        // The ADR-0026 R1 scenario, closed: merge re-attaches a revoked
        // recipient's wrap; rewrap strips it from the tip.
        let root = tmp_root("r1-strip");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        repo.branch("pre-revoke").unwrap();
        repo.switch("pre-revoke").unwrap();
        std::fs::write(root.join("readme.txt"), b"work").unwrap();
        repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();
        repo.revoke("secret/", &bob_pk.recipient_id()).unwrap();
        repo.merge("pre-revoke", "me").unwrap();

        // Precondition (per ADR-0026 Consequences): bob's wrap is BACK at tip.
        let tip = repo.head_tip().unwrap().unwrap();
        let prot = repo.snapshot(&tip).unwrap().protection;
        let bob_id = bob_pk.recipient_id();
        assert!(
            prot.wrapped.values().any(|wks| wks.iter().any(|w| w.recipient_id == bob_id.as_str())),
            "test setup must reproduce the R1 re-attachment"
        );

        let report = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert!(report.blobs_rewrapped >= 1);
        assert!(report.skipped.is_empty());

        // Tip wraps no longer include bob anywhere; root unchanged.
        let commit = report.commit.unwrap();
        let snap = repo.snapshot(&commit).unwrap();
        assert!(
            !snap.protection.wrapped.values().any(|wks| wks.iter().any(|w| w.recipient_id == bob_id.as_str())),
            "rewrap must strip the revoked recipient's re-attached wrap"
        );
        assert_eq!(snap.root, repo.snapshot(&tip).unwrap().root);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_skips_unopenable_entries_and_reports() {
        let root = tmp_root("skip");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        // One secret alice can open, one she cannot (bob-only).
        repo.secret_add("mine", b"a", std::slice::from_ref(&alice_pk)).unwrap();
        repo.secret_add("theirs", b"b", std::slice::from_ref(&bob_pk)).unwrap();

        let known = [alice_pk.clone(), bob_pk.clone()];
        let report = repo.rewrap(&alice_sk, &[], &known, false).unwrap();
        assert_eq!(report.secrets_rewrapped, vec!["mine".to_string()]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].0.contains("theirs"));
        assert!(report.commit.is_some(), "partial success still commits");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_skips_secret_with_unresolvable_recipient_id() {
        // A wrap whose recipient_id has no pubkey in the known pool cannot be
        // re-sealed to that recipient — must be reported, not silently dropped.
        let root = tmp_root("unresolvable");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_ghost_sk, ghost_pk) = scl_crypto::generate_keypair();
        repo.secret_add("shared", b"v", &[alice_pk.clone(), ghost_pk]).unwrap();
        // ghost's pubkey is NOT in the known pool.
        let report = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert!(report.secrets_rewrapped.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].1.contains("not resolvable"));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_dry_run_commits_nothing() {
        let root = tmp_root("dry");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_e, esc_pk) = scl_crypto::generate_keypair();
        repo.secret_add("s", b"v", std::slice::from_ref(&alice_pk)).unwrap();
        let tip_before = repo.head_tip().unwrap();
        let report = repo
            .rewrap(&alice_sk, std::slice::from_ref(&esc_pk), std::slice::from_ref(&alice_pk), true)
            .unwrap();
        assert_eq!(report.secrets_rewrapped.len(), 1, "dry-run still REPORTS the work");
        assert!(report.commit.is_none());
        assert_eq!(repo.head_tip().unwrap(), tip_before, "tip must not move");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_is_undoable_as_one_operation() {
        let root = tmp_root("undo");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_e, esc_pk) = scl_crypto::generate_keypair();
        repo.secret_add("s", b"v", std::slice::from_ref(&alice_pk)).unwrap();
        let tip_before = repo.head_tip().unwrap().unwrap();
        repo.rewrap(&alice_sk, std::slice::from_ref(&esc_pk), std::slice::from_ref(&alice_pk), false)
            .unwrap();
        repo.undo().unwrap();
        assert_eq!(repo.head_tip().unwrap().unwrap(), tip_before, "one undo reverts the whole rewrap");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_reports_empty_granted_rule_not_silently() {
        // Crossed revokes can empty a rule (see Task 2 of P16). Simulate the
        // merged state directly, then rewrap: the blob must land in skipped
        // with a reason pointing at `sc grant`.
        let root = tmp_root("empty-rule");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"x").unwrap();
        repo.commit("me", "add").unwrap();
        // Tombstone alice directly in a synthetic snapshot (bypasses the CLI
        // guard, which is exactly what a crossed-revoke merge does).
        let tip = repo.head_tip().unwrap().unwrap();
        let mut snap = repo.snapshot(&tip).unwrap();
        for rule in snap.protection.prefixes.iter_mut() {
            for e in rule.recipients.iter_mut() {
                e.epoch += 1;
                e.state = scl_core::RecipientState::Revoked;
            }
        }
        repo.commit_snapshot(snap.root, vec![tip], snap.secrets, snap.protection, "test", "empty rule")
            .unwrap();

        let report = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert_eq!(report.blobs_rewrapped, 0);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].1.contains("sc grant"), "reason must point at sc grant");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_refuses_during_in_progress_merge() {
        // final-review I1: rewrap must not cut over while a conflicted
        // merge is live — completion would union the OLD wraps back in on
        // top of rewrap's cutover, silently resurrecting a stripped wrap.
        let root = tmp_root("in-progress-merge");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("f.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nX\nc\n").unwrap();
        repo.commit("me", "ours").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"a\nY\nc\n").unwrap();
        repo.commit("me", "theirs").unwrap();
        repo.switch("main").unwrap();
        let _ = repo.merge("feature", "me").unwrap_err();
        assert!(repo.merge_in_progress());

        let err = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");

        // Same guard must fire on --dry-run: a report against a state
        // that's about to be unioned away would be equally misleading.
        let err = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), true)
            .unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
