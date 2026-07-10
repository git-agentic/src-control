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
    /// Convergent (pre-P33) protected blobs eagerly re-sealed randomized
    /// (fresh DEK + nonce, new ciphertext id) during this run (P33 Task 10).
    pub blobs_resealed: usize,
    /// (entry label e.g. "secret db-pass" / "path secret/db.txt", reason)
    pub skipped: Vec<(String, String)>,
    /// The commit id; None on --dry-run or when nothing needed rewrapping.
    pub commit: Option<ObjectId>,
}

impl Repo {
    /// Re-seal every secret (fresh DEK, current recipients + escrow) and
    /// replace every protected blob's wrap list (rule's granted set + escrow)
    /// at the tip, as ONE commit and ONE oplog record. Entries `identity`
    /// cannot open are skipped and reported. Still-convergent (pre-P33)
    /// protected blobs are eagerly upgraded while we're here: decrypted with
    /// the unwrapped DEK, re-sealed randomized (`encrypt_path_randomized`),
    /// and the tree entry retargeted to the new ciphertext id with the
    /// `RANDOMIZED` perms bit — so the root tree changes exactly when an
    /// upgrade happened. Once every entry is randomized the run is
    /// policy/registry-only again and the root tree id is untouched (the P17
    /// property). Cuts the LIVE TIP only — history keeps old wraps, old
    /// convergent ciphertext, and old secret objects (content addressing;
    /// same boundary as rotation, ADR-0019).
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
                        skipped.push((
                            format!("secret {name}"),
                            "registry entry is not a secret".into(),
                        ));
                        continue;
                    }
                }
            };
            // Resolve current recipient ids to pubkeys from the known pool.
            let mut targets: Vec<PublicKey> = Vec::new();
            let mut unresolvable = None;
            for w in &secret.wrapped_keys {
                match known_keys
                    .iter()
                    .find(|k| k.recipient_id().as_str() == w.recipient_id)
                {
                    Some(pk) => {
                        if !targets
                            .iter()
                            .any(|t| t.recipient_id() == pk.recipient_id())
                        {
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
                    skipped.push((
                        format!("secret {name}"),
                        "identity cannot open this secret".into(),
                    ));
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

        // ---- Paths half: replace wrap lists with granted + escrow; eagerly
        // upgrade still-convergent (pre-P33) blobs to randomized. ----
        let mut protection = snap.protection.clone();
        let mut blobs_rewrapped = 0usize;
        let mut blobs_resealed = 0usize;
        // path -> (new blob id, new perms) for eagerly-upgraded entries; the
        // commit tail rebuilds the root iff this is non-empty.
        let mut retargets: std::collections::BTreeMap<String, (ObjectId, u8)> =
            std::collections::BTreeMap::new();
        // Main-tree protected cache: recording (path, plaintext, new id) for
        // each upgraded path is what keeps the next `sc status`/`commit`
        // quiet — rewrap never rematerializes the working tree, so the
        // on-disk plaintext (and its stat) is untouched while its sealed id
        // changes. Never opened on dry-run (no mutation, nothing to record).
        let mut main_cache = if dry_run {
            None
        } else {
            Some(self.open_protected_cache()?)
        };
        let entries = {
            let arc = self.store_arc();
            let mut store = arc.lock().unwrap();
            crate::worktree::tree_file_entries_with_perms(&mut store, snap.root)?
        };
        for (path, (blob_id, _mode, perms)) in &entries {
            if perms & scl_core::PROTECTED == 0 {
                continue;
            }
            let Some(rule) = crate::protect::matching_prefix(&protection, path) else {
                skipped.push((
                    format!("path {path}"),
                    "no governing rule (bit/rule mismatch)".into(),
                ));
                continue;
            };
            let granted = rule.granted_keys();
            if granted.is_empty() {
                skipped.push((
                    format!("path {path}"),
                    "rule has no granted recipients (crossed revokes?); run `sc grant` first"
                        .into(),
                ));
                continue;
            }
            let Some(wks) = protection.wrapped.get(blob_id) else {
                skipped.push((
                    format!("path {path}"),
                    "no wrapped DEKs recorded for blob".into(),
                ));
                continue;
            };
            let my_id = identity.public().recipient_id().to_string();
            let Some(wk) = wks.iter().find(|w| w.recipient_id == my_id) else {
                skipped.push((
                    format!("path {path}"),
                    "identity is not a recipient of this blob".into(),
                ));
                continue;
            };
            let dek = match scl_crypto::unwrap_dek_with(wk, identity) {
                Ok(d) => d,
                Err(e) => {
                    skipped.push((format!("path {path}"), format!("wrap failed to open: {e}")));
                    continue;
                }
            };
            // The target recipient set — exactly granted + escrow — shared
            // by both arms below.
            let mut target_pks: Vec<PublicKey> =
                granted.iter().map(|b| PublicKey::from_bytes(*b)).collect();
            for e in escrows {
                if !target_pks
                    .iter()
                    .any(|t| t.recipient_id() == e.recipient_id())
                {
                    target_pks.push(e.clone());
                }
            }
            if perms & scl_core::RANDOMIZED == 0 {
                // Convergent (pre-P33): eager upgrade. Decrypt with the DEK
                // we just unwrapped, re-seal randomized, retarget the tree
                // entry + wraps to the fresh ciphertext id.
                let cipher = {
                    let arc = self.store_arc();
                    let obj = arc.lock().unwrap().get(blob_id)?;
                    match obj {
                        Object::Blob(b) => b.to_vec(),
                        _ => {
                            skipped
                                .push((format!("path {path}"), "tree entry is not a blob".into()));
                            continue;
                        }
                    }
                };
                let pt = match scl_crypto::decrypt_path(&cipher, &dek) {
                    Ok(p) => p,
                    Err(e) => {
                        // Corruption-shaped, not an authorization failure
                        // (the wrap itself opened): named, not fatal.
                        skipped.push((
                            format!("path {path}"),
                            format!("ciphertext failed to open: {e}"),
                        ));
                        continue;
                    }
                };
                if dry_run {
                    blobs_resealed += 1;
                    continue;
                }
                let (new_cipher, new_dek) = scl_crypto::encrypt_path_randomized(&pt);
                let new_id = {
                    let arc = self.store_arc();
                    let i = arc.lock().unwrap().put(Object::blob(new_cipher))?;
                    i
                };
                let mut new_wks: Vec<WrappedKey> = target_pks
                    .iter()
                    .map(|pk| scl_crypto::wrap_dek_for(&new_dek, pk))
                    .collect();
                new_wks.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
                protection.wrapped.remove(blob_id);
                protection.wrapped.insert(new_id, new_wks);
                retargets.insert(
                    path.clone(),
                    (new_id, scl_core::PROTECTED | scl_core::RANDOMIZED),
                );
                if let Some(c) = main_cache.as_mut() {
                    // Recorded unconditionally for upgraded paths: if the
                    // working file diverged locally, the keyed tag simply
                    // won't match its plaintext — a benign spurious reseal
                    // at the next commit, never incorrectness.
                    c.record(path, &pt, new_id);
                }
                blobs_resealed += 1;
                continue;
            }
            if dry_run {
                blobs_rewrapped += 1;
                continue;
            }
            // Randomized: rebuild the wrap list only — exactly granted +
            // escrow, reusing prior wrap bytes for recipients already
            // present (id-stability), fresh wraps for the rest.
            // Tombstoned/stale wraps are dropped. Ciphertext id unchanged.
            let prior = wks.clone();
            let mut new_wks: Vec<WrappedKey> = Vec::new();
            for pk in &target_pks {
                let rid = pk.recipient_id().to_string();
                match prior.iter().find(|w| w.recipient_id == rid) {
                    Some(existing) => new_wks.push(existing.clone()),
                    None => new_wks.push(scl_crypto::wrap_dek_for(&dek, pk)),
                }
            }
            new_wks.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
            protection.wrapped.insert(*blob_id, new_wks);
            blobs_rewrapped += 1;
        }

        // ---- Nothing to do / dry-run: report only. ----
        if dry_run
            || (secrets_rewrapped.is_empty()
                && new_secret_objs.is_empty()
                && blobs_rewrapped == 0
                && blobs_resealed == 0)
        {
            return Ok(RewrapReport {
                secrets_rewrapped,
                blobs_rewrapped,
                blobs_resealed,
                skipped,
                commit: None,
            });
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
        // Rebuild the root tree iff any convergent blob was re-sealed: walk
        // the tip's entries again, swapping in each retargeted path's new
        // ciphertext id + `RANDOMIZED` perms and keeping every other entry's
        // bytes/mode/perms verbatim. With no retargets the root is untouched
        // byte-for-byte (policy-only, the P17 property — a second rewrap
        // converges back to tree-identical).
        let new_root = if retargets.is_empty() {
            snap.root
        } else {
            let mut all: Vec<(String, Vec<u8>, scl_core::FileMode, u8)> =
                Vec::with_capacity(entries.len());
            {
                let arc = self.store_arc();
                let mut store = arc.lock().unwrap();
                for (path, (blob_id, mode, perms)) in &entries {
                    let (id, p) = match retargets.get(path) {
                        Some((new_id, new_perms)) => (*new_id, *new_perms),
                        None => (*blob_id, *perms),
                    };
                    let bytes = match store.get(&id)? {
                        Object::Blob(b) => b.to_vec(),
                        _ => return Err(Error::CorruptObject(id)),
                    };
                    all.push((path.clone(), bytes, *mode, p));
                }
                // Store lock dropped here: write_tree_with_perms locks it.
            }
            self.vfs.write_tree_with_perms(&all)?
        };
        let head = crate::refs::current_branch(self.layout())?;
        let before = crate::refs::read_branch_tip(self.layout(), &head)?;
        let msg = if blobs_resealed > 0 {
            format!(
                "rewrap: {} secret(s), {} blob(s), {} re-sealed randomized",
                secrets_rewrapped.len(),
                blobs_rewrapped,
                blobs_resealed
            )
        } else {
            format!(
                "rewrap: {} secret(s), {} blob(s)",
                secrets_rewrapped.len(),
                blobs_rewrapped
            )
        };
        let id = self.commit_snapshot(new_root, vec![tip], registry, protection, "system", &msg)?;
        crate::oplog::record(
            self.layout(),
            "rewrap",
            &head,
            &head,
            &[(head.clone(), before, Some(id))],
        )?;
        // Persist the cache only after the commit has landed (never `?` a
        // save — cache trouble must not fail a rewrap that already
        // succeeded; worst case is a spurious reseal next commit).
        if !retargets.is_empty() {
            if let Some(c) = &main_cache {
                c.save_best_effort();
            }
        }
        Ok(RewrapReport {
            secrets_rewrapped,
            blobs_rewrapped,
            blobs_resealed,
            skipped,
            commit: Some(id),
        })
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
        repo.secret_add("db-pass", b"hunter2", std::slice::from_ref(&alice_pk))
            .unwrap();
        repo.secret_add("api-key", b"tok", std::slice::from_ref(&alice_pk))
            .unwrap();
        let tip_before = repo.head_tip().unwrap().unwrap();

        let report = repo
            .rewrap(
                &alice_sk,
                std::slice::from_ref(&esc_pk),
                std::slice::from_ref(&alice_pk),
                false,
            )
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
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None)
            .unwrap();
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
            prot.wrapped
                .values()
                .any(|wks| wks.iter().any(|w| w.recipient_id == bob_id.as_str())),
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
            !snap
                .protection
                .wrapped
                .values()
                .any(|wks| wks.iter().any(|w| w.recipient_id == bob_id.as_str())),
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
        repo.secret_add("mine", b"a", std::slice::from_ref(&alice_pk))
            .unwrap();
        repo.secret_add("theirs", b"b", std::slice::from_ref(&bob_pk))
            .unwrap();

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
        repo.secret_add("shared", b"v", &[alice_pk.clone(), ghost_pk])
            .unwrap();
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
        repo.secret_add("s", b"v", std::slice::from_ref(&alice_pk))
            .unwrap();
        let tip_before = repo.head_tip().unwrap();
        let report = repo
            .rewrap(
                &alice_sk,
                std::slice::from_ref(&esc_pk),
                std::slice::from_ref(&alice_pk),
                true,
            )
            .unwrap();
        assert_eq!(
            report.secrets_rewrapped.len(),
            1,
            "dry-run still REPORTS the work"
        );
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
        repo.secret_add("s", b"v", std::slice::from_ref(&alice_pk))
            .unwrap();
        let tip_before = repo.head_tip().unwrap().unwrap();
        repo.rewrap(
            &alice_sk,
            std::slice::from_ref(&esc_pk),
            std::slice::from_ref(&alice_pk),
            false,
        )
        .unwrap();
        repo.undo().unwrap();
        assert_eq!(
            repo.head_tip().unwrap().unwrap(),
            tip_before,
            "one undo reverts the whole rewrap"
        );
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
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None)
            .unwrap();
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
        repo.commit_snapshot(
            snap.root,
            vec![tip],
            snap.secrets,
            snap.protection,
            "test",
            "empty rule",
        )
        .unwrap();

        let report = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert_eq!(report.blobs_rewrapped, 0);
        assert_eq!(report.skipped.len(), 1);
        assert!(
            report.skipped[0].1.contains("sc grant"),
            "reason must point at sc grant"
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ---- P33 Task 10: eager convergent → randomized upgrade ----

    use scl_core::{
        FileMode, Object, ObjectId, ProtectPrefix, Protection, RecipientEntry, RecipientState,
        PROTECTED, RANDOMIZED,
    };

    /// Seed the tip with pre-P33 CONVERGENT protected entries under
    /// `secret/`. The CLI can no longer mint convergent ciphertext (commit
    /// seals randomized since Task 6), so this seals via the low-level
    /// `encrypt_path` and writes the tree + protection registry directly.
    /// Each entry: (path, plaintext, recipient the DEK is wrapped for,
    /// wrap_wrong_dek — when true, the wrap holds a DEK that does NOT open
    /// the ciphertext, simulating corruption the unwrap can't detect).
    fn seed_convergent_tip(
        repo: &Repo,
        rule_pk: &scl_crypto::PublicKey,
        entries: &[(&str, &[u8], &scl_crypto::PublicKey, bool)],
    ) {
        let mut prot = Protection::default();
        prot.prefixes.push(ProtectPrefix {
            prefix: "secret/".into(),
            recipients: vec![RecipientEntry {
                key: rule_pk.to_bytes(),
                epoch: 1,
                state: RecipientState::Granted,
            }],
        });
        let mut files = Vec::new();
        for (path, pt, pk, wrap_wrong) in entries {
            let (cipher, dek) = scl_crypto::encrypt_path(pt);
            let id = Object::blob(cipher.clone()).id();
            let wrapped_dek = if *wrap_wrong {
                let (_c, other) = scl_crypto::encrypt_path(b"a different plaintext entirely");
                other
            } else {
                dek
            };
            prot.wrapped
                .entry(id)
                .or_default()
                .push(scl_crypto::wrap_dek_for(&wrapped_dek, pk));
            files.push((path.to_string(), cipher, FileMode::FILE, PROTECTED));
        }
        let root = repo.vfs.write_tree_with_perms(&files).unwrap();
        let parents = repo.head_tip().unwrap().into_iter().collect();
        repo.commit_snapshot(
            root,
            parents,
            Default::default(),
            prot,
            "test",
            "seed convergent",
        )
        .unwrap();
    }

    /// The tip tree's (blob id, perms) at `path`.
    fn entry_at(repo: &Repo, tip: ObjectId, path: &str) -> (ObjectId, u8) {
        let snap = repo.snapshot(&tip).unwrap();
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        let entries = crate::worktree::tree_file_entries_with_perms(&mut store, snap.root).unwrap();
        let (id, _mode, perms) = *entries.get(path).expect("entry present");
        (id, perms)
    }

    /// Decrypt `path`'s ciphertext at `tip` via wrap presence (as `sc run`/
    /// `decrypt_with` do): unwrap the DEK with `sk`, open the blob.
    fn decrypt_at(repo: &Repo, tip: ObjectId, path: &str, sk: &scl_crypto::SecretKey) -> Vec<u8> {
        let snap = repo.snapshot(&tip).unwrap();
        let (id, _perms) = entry_at(repo, tip, path);
        let wks = snap.protection.wrapped.get(&id).expect("wraps recorded");
        let me = sk.public().recipient_id().to_string();
        let wk = wks
            .iter()
            .find(|w| w.recipient_id == me)
            .expect("identity has a wrap");
        let dek = scl_crypto::unwrap_dek_with(wk, sk).unwrap();
        let cipher = {
            let arc = repo.store_arc();
            let obj = arc.lock().unwrap().get(&id).unwrap();
            match obj {
                Object::Blob(b) => b.to_vec(),
                _ => panic!("tree entry is not a blob"),
            }
        };
        scl_crypto::decrypt_path(&cipher, &dek).unwrap().to_vec()
    }

    #[test]
    fn rewrap_upgrades_convergent_blobs_and_second_run_is_policy_only() {
        let root = tmp_root("upgrade");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        seed_convergent_tip(
            &repo,
            &alice_pk,
            &[("secret/x", b"top secret", &alice_pk, false)],
        );
        let tip0 = repo.head_tip().unwrap().unwrap();
        let (old_id, old_perms) = entry_at(&repo, tip0, "secret/x");
        assert_eq!(old_perms, PROTECTED, "fixture must be convergent");
        let known = [alice_pk.clone()];

        // Dry-run counts the upgrade without mutating anything.
        let dry = repo.rewrap(&alice_sk, &[], &known, true).unwrap();
        assert_eq!(dry.blobs_resealed, 1, "dry-run still REPORTS the upgrade");
        assert!(dry.commit.is_none());
        assert_eq!(repo.head_tip().unwrap().unwrap(), tip0, "tip must not move");

        let r1 = repo.rewrap(&alice_sk, &[], &known, false).unwrap();
        assert_eq!(r1.blobs_resealed, 1);
        assert!(r1.skipped.is_empty());
        let tip1 = repo.head_tip().unwrap().unwrap();
        let (id1, perms1) = entry_at(&repo, tip1, "secret/x");
        assert!(perms1 & RANDOMIZED != 0, "entry must be flagged randomized");
        assert!(perms1 & PROTECTED != 0, "entry must stay protected");
        assert_ne!(id1, old_id, "randomized reseal mints a fresh ciphertext id");
        assert_eq!(
            decrypt_at(&repo, tip1, "secret/x", &alice_sk),
            b"top secret".to_vec()
        );
        // Old convergent id's wrap entry is dropped from the live tip; the
        // new id carries the fresh wraps.
        let snap1 = repo.snapshot(&tip1).unwrap();
        assert!(!snap1.protection.wrapped.contains_key(&old_id));
        assert!(snap1.protection.wrapped.contains_key(&id1));

        let r2 = repo.rewrap(&alice_sk, &[], &known, false).unwrap();
        assert_eq!(r2.blobs_resealed, 0, "second rewrap is policy-only again");
        if r2.commit.is_some() {
            let tip2 = repo.head_tip().unwrap().unwrap();
            assert_eq!(
                entry_at(&repo, tip2, "secret/x").0,
                id1,
                "ciphertext id stable"
            );
            assert_eq!(
                repo.snapshot(&tip2).unwrap().root,
                snap1.root,
                "root untouched byte-for-byte (P17 policy-only property)"
            );
        }
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_skips_unopenable_convergent_blob_and_upgrades_the_rest() {
        // Skip-and-report for the new decrypt step: a convergent blob whose
        // wrap opens but whose ciphertext does NOT (corruption-shaped) lands
        // in `skipped`, named; the openable one still upgrades; the run
        // still commits (existing partial-success semantics).
        let root = tmp_root("convergent-skip");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        seed_convergent_tip(
            &repo,
            &alice_pk,
            &[
                ("secret/good", b"ok", &alice_pk, false),
                ("secret/bad", b"nope", &alice_pk, true),
            ],
        );
        let known = [alice_pk.clone()];
        let report = repo.rewrap(&alice_sk, &[], &known, false).unwrap();
        assert_eq!(report.blobs_resealed, 1, "the openable blob still upgrades");
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].0.contains("secret/bad"));
        assert!(
            report.skipped[0].1.contains("ciphertext failed to open"),
            "got {:?}",
            report.skipped[0]
        );
        assert!(report.commit.is_some(), "partial success still commits");
        let tip = repo.head_tip().unwrap().unwrap();
        let (_gid, gperms) = entry_at(&repo, tip, "secret/good");
        assert!(gperms & RANDOMIZED != 0);
        // The unopenable entry is left exactly as it was: convergent, same
        // id, wraps intact — nothing silently dropped.
        let (bid, bperms) = entry_at(&repo, tip, "secret/bad");
        assert_eq!(bperms & RANDOMIZED, 0);
        assert!(repo
            .snapshot(&tip)
            .unwrap()
            .protection
            .wrapped
            .contains_key(&bid));
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
