//! Per-file permission (protected-path) operations on [`Repo`]: `protect`,
//! `grant`, `revoke`, and the prefix listing. Split from `repo.rs` for
//! cohesion — same `impl Repo` extension pattern as `secrets.rs`.

use scl_core::{ObjectId, Protection};

use crate::error::{Error, Result};
use crate::repo::Repo;
use crate::worktree;
use std::collections::BTreeMap;

/// One recipient's standing on a listed prefix, for display.
pub struct PrefixRecipient {
    pub id: scl_crypto::RecipientId,
    pub epoch: u32,
    pub granted: bool,
}

impl Repo {
    /// Record (or extend) a protected-path rule for `prefix`, encrypting any
    /// matching working-tree files for `recipients`.
    ///
    /// The rule is persisted as a policy-only snapshot first (so the subsequent
    /// commit reads it from the tip), then a normal `commit` runs: matching
    /// working-tree files are convergently encrypted and wrapped for each
    /// recipient. If nothing matches yet, the rule is still recorded for future
    /// commits. The `identity` arg is reserved for future re-encrypt symmetry
    /// (e.g. re-protecting already-committed plaintext) and is unused today.
    /// Returns the id of the resulting commit.
    pub fn protect(
        &self,
        prefix: &str,
        recipients: &[scl_crypto::PublicKey],
        _identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<ObjectId> {
        self.refuse_on_private("sc protect")?;
        use scl_core::ProtectPrefix;
        // `protect`'s first write is a policy-only commit_snapshot, which
        // (unlike `commit`) has no in-progress guard of its own — the P19-I1
        // hazard: an unguarded policy op moving the branch tip out from under
        // a stopped merge/pick/rebase (P21).
        if crate::merge_state::in_progress(self.layout()) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(self.layout()) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(self.layout()) {
            return Err(Error::RebaseInProgress);
        }
        crate::secrets::require_recipients(recipients)?;
        // Load the tip's protection, add/replace the rule, and persist it as a
        // policy-only commit (same root) so `commit` below sees the new prefix.
        let (root, parents, secrets, mut protection) = match self.head_tip()? {
            Some(t) => {
                let snap = self.snapshot(&t)?;
                (snap.root, vec![t], snap.secrets, snap.protection)
            }
            None => {
                let root = self.vfs.write_tree(&[])?;
                (root, vec![], BTreeMap::new(), Protection::default())
            }
        };
        match protection.prefixes.iter_mut().find(|p| p.prefix == prefix) {
            Some(rule) => {
                // Existing rule: (re-)grant the named recipients at the next epoch.
                // Never rebuild the rule wholesale — that would drop tombstones.
                let epoch = rule.next_epoch();
                for pk in recipients {
                    rule.set_standing(pk.to_bytes(), epoch, scl_core::RecipientState::Granted);
                }
            }
            None => protection.prefixes.push(ProtectPrefix {
                prefix: prefix.to_string(),
                recipients: recipients
                    .iter()
                    .map(|p| scl_core::RecipientEntry {
                        key: p.to_bytes(),
                        epoch: 1,
                        state: scl_core::RecipientState::Granted,
                    })
                    .collect(),
            }),
        }
        let head = crate::refs::current_branch(self.layout())?;
        let before = crate::refs::read_branch_tip(self.layout(), &head)?;
        let id = self.commit_snapshot(
            root,
            parents,
            secrets,
            protection,
            "system",
            &format!("protect {prefix}"),
        )?;
        crate::oplog::record(
            self.layout(),
            &format!("protect {prefix}"),
            &head,
            &head,
            &[(head.clone(), before, Some(id))],
        )?;
        // Now encrypt matching working-tree files under the freshly-recorded rule.
        // `commit` (repo.rs) logs its own oplog record ("commit: encrypt under
        // <prefix>") — a second, distinct ref move, so no double-logging here.
        self.commit("system", &format!("encrypt under {prefix}"))
    }

    /// Collect the PROTECTED blob ids in the tip tree whose path is governed by
    /// the rule `prefix` (longest-prefix wins, mirroring `matching_prefix`).
    fn protected_blob_ids_under(
        &self,
        root: ObjectId,
        protection: &Protection,
        prefix: &str,
    ) -> Result<Vec<ObjectId>> {
        let store_arc = self.vfs.store();
        let mut store = store_arc.lock().unwrap();
        let entries = worktree::tree_file_entries_with_perms(&mut store, root)?;
        Ok(entries
            .into_iter()
            .filter(|(path, (_id, _mode, perms))| {
                perms & scl_core::PROTECTED != 0
                    && crate::protect::matching_prefix(protection, path)
                        .is_some_and(|r| r.prefix == prefix)
            })
            .map(|(_path, (id, _, _))| id)
            .collect())
    }

    /// Grant `new` read access to the files protected under `prefix` — a
    /// policy-only operation that does NOT touch any blob or tree id.
    ///
    /// For each protected blob under `prefix`, the DEK is recovered with the
    /// `authorized` identity (which must currently be a recipient, else
    /// `NotAuthorized`) and re-wrapped for `new` (deduped by recipient id). The
    /// `new` recipient is also added to the prefix rule. The resulting snapshot
    /// reuses the tip's exact root tree. Errors `NotProtected` if no such prefix.
    pub fn grant(
        &self,
        prefix: &str,
        authorized: &scl_crypto::SecretKey,
        new: &scl_crypto::PublicKey,
    ) -> Result<ObjectId> {
        self.refuse_on_private("sc grant")?;
        // P21: same in-progress guard as `protect` — see its comment.
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
        let (root, secrets, mut protection) = (snap.root, snap.secrets, snap.protection);

        let rule_idx = protection
            .prefixes
            .iter()
            .position(|p| p.prefix == prefix)
            .ok_or_else(|| Error::NotProtected(prefix.to_string()))?;

        let protected_ids = self.protected_blob_ids_under(root, &protection, prefix)?;
        let authorized_id = authorized.public().recipient_id().to_string();
        let new_id = new.recipient_id().to_string();
        for blob_id in protected_ids {
            let Some(wks) = protection.wrapped.get(&blob_id) else {
                continue;
            };
            if wks.iter().any(|w| w.recipient_id == new_id) {
                continue; // `new` already a recipient for this blob
            }
            // Locate the wrap addressed to `authorized` by recipient id (mirrors
            // the Phase-2 `secrets.rs`/`open` lookup). A missing wrap means the
            // caller isn't a recipient → NotAuthorized; a present-but-corrupt
            // wrap must surface as a hard crypto error via `?`, not be misread as
            // an authorization failure. The DEK stays `Zeroizing`.
            let wk = wks
                .iter()
                .find(|w| w.recipient_id == authorized_id)
                .ok_or_else(|| Error::NotAuthorized(prefix.to_string()))?;
            let dek = scl_crypto::unwrap_dek_with(wk, authorized)?;
            let new_wk = scl_crypto::wrap_dek_for(&dek, new);
            protection
                .wrapped
                .get_mut(&blob_id)
                .expect("present above")
                .push(new_wk);
        }

        let rule = &mut protection.prefixes[rule_idx];
        let epoch = rule.next_epoch();
        rule.set_standing(new.to_bytes(), epoch, scl_core::RecipientState::Granted);
        let head = crate::refs::current_branch(self.layout())?;
        let before = crate::refs::read_branch_tip(self.layout(), &head)?;
        let id = self.commit_snapshot(
            root,
            vec![tip],
            secrets,
            protection,
            "system",
            &format!("grant {prefix}"),
        )?;
        crate::oplog::record(
            self.layout(),
            &format!("grant {prefix}"),
            &head,
            &head,
            &[(head.clone(), before, Some(id))],
        )?;
        Ok(id)
    }

    /// Revoke `recipient_id` from `prefix`: drop its wrapped DEK from every
    /// protected blob under the prefix and record a durable `Revoked` tombstone
    /// on the rule's recipient register (ADR-0026) — a fresh epoch that wins the
    /// LWW merge against any pre-revoke branch, instead of just deleting the
    /// entry. Policy-only (root tree unchanged). Errors `NotProtected` if no
    /// such prefix. Does not rotate content (a prior holder kept any plaintext
    /// already checked out — see the secrets-revoke rationale in ADR-0008).
    pub fn revoke(&self, prefix: &str, recipient_id: &scl_crypto::RecipientId) -> Result<ObjectId> {
        self.refuse_on_private("sc revoke")?;
        // P21: same in-progress guard as `protect` — see its comment.
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
        let (root, secrets, mut protection) = (snap.root, snap.secrets, snap.protection);

        let rule_idx = protection
            .prefixes
            .iter()
            .position(|p| p.prefix == prefix)
            .ok_or_else(|| Error::NotProtected(prefix.to_string()))?;

        // Refuse to empty the rule's effective set: subsequent commits under the
        // prefix would seal new content for nobody (the empty-recipient footgun).
        let survives = protection.prefixes[rule_idx]
            .granted_keys()
            .iter()
            .any(|pk| {
                scl_crypto::PublicKey::from_bytes(*pk)
                    .recipient_id()
                    .as_str()
                    != recipient_id.as_str()
            });
        if !survives {
            return Err(Error::InvalidArgument(format!(
                "revoking the last recipient would leave {prefix} readable by nobody; \
                 grant another recipient first"
            )));
        }

        let protected_ids = self.protected_blob_ids_under(root, &protection, prefix)?;
        let rid = recipient_id.as_str();
        for blob_id in protected_ids {
            if let Some(wks) = protection.wrapped.get_mut(&blob_id) {
                wks.retain(|w| w.recipient_id != rid);
            }
        }
        // Tombstone, don't delete: the Revoked entry at a fresh epoch is what wins
        // the LWW register against any pre-revoke branch at merge time (ADR-0026).
        let rule = &mut protection.prefixes[rule_idx];
        let epoch = rule.next_epoch();
        if let Some(e) = rule.recipients.iter_mut().find(|e| {
            scl_crypto::PublicKey::from_bytes(e.key)
                .recipient_id()
                .as_str()
                == rid
        }) {
            e.epoch = epoch;
            e.state = scl_core::RecipientState::Revoked;
        }
        let head = crate::refs::current_branch(self.layout())?;
        let before = crate::refs::read_branch_tip(self.layout(), &head)?;
        let id = self.commit_snapshot(
            root,
            vec![tip],
            secrets,
            protection,
            "system",
            &format!("revoke from {prefix}"),
        )?;
        crate::oplog::record(
            self.layout(),
            &format!("revoke {prefix}"),
            &head,
            &head,
            &[(head.clone(), before, Some(id))],
        )?;
        Ok(id)
    }

    /// List the tip's protected prefixes with every recipient register —
    /// tombstones included, so a post-merge listing shows revocations holding.
    pub fn protected_prefixes(&self) -> Result<Vec<(String, Vec<PrefixRecipient>)>> {
        self.refuse_on_private("sc protect --list")?;
        let protection = match self.head_tip()? {
            Some(t) => self.snapshot(&t)?.protection,
            None => Protection::default(),
        };
        Ok(protection
            .prefixes
            .into_iter()
            .map(|p| {
                let rids = p
                    .recipients
                    .iter()
                    .map(|e| PrefixRecipient {
                        id: scl_crypto::PublicKey::from_bytes(e.key).recipient_id(),
                        epoch: e.epoch,
                        granted: e.state == scl_core::RecipientState::Granted,
                    })
                    .collect();
                (p.prefix, rids)
            })
            .collect())
    }
}
