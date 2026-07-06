//! Replay core (P14): cherry-pick is a three-way merge whose base is the
//! replayed commit's first parent (empty base for a root commit). Consumed by
//! the cherry-pick/rebase CLI surface (Tasks 8-9) to apply one commit onto an
//! arbitrary target tree without requiring a full branch merge.
//!
//! P15 Task 9: the secret registry is replayed too, via the same base as the
//! file three-way — `merge::merge_secrets(base, ours, theirs)` where `base`
//! is the replayed commit's own first parent's registry, `ours` is the
//! onto-side registry (the current tip for `cherry_pick`, the fold's
//! accumulator for `rebase`), and `theirs` is the commit's own registry. A
//! name that changed differently on both sides aborts the whole replay
//! (`Error::SecretMergeConflict`) before anything is written. `ReplayOutcome`
//! itself stays registry-agnostic (`replay_commit` never sees a registry) —
//! callers merge the registry alongside the tree/protection outcome and fold
//! the result into `Empty`'s redefinition (see below).

use std::collections::BTreeMap;

use scl_core::{FileMode, ObjectId, Protection, WrappedKey};

use crate::error::{Error, Result};
use crate::merge::{self, MergedFile};
use crate::protect;
use crate::refs;
use crate::repo::Repo;
use crate::worktree;

/// Three-way merge of the secret registry for one replayed commit — the
/// registry analog of `replay_commit`'s file three-way, using the same base
/// (the commit's own first parent, empty registry if it's a root commit).
/// `onto_secrets` is the onto side (current tip for `cherry_pick`, fold
/// accumulator for `rebase`); `commit_secrets`/`commit_parents` are the
/// replayed commit's own registry and parent list. Errors
/// (`Error::SecretMergeConflict`) propagate verbatim — the caller must not
/// have written anything yet when this is called, so the abort is atomic.
fn merged_registry_for_replay(
    repo: &Repo,
    commit_parents: &[ObjectId],
    commit_secrets: &BTreeMap<String, ObjectId>,
    onto_secrets: &BTreeMap<String, ObjectId>,
) -> Result<BTreeMap<String, ObjectId>> {
    let parent_secrets = match commit_parents.first() {
        Some(p) => repo.snapshot(p)?.secrets,
        None => BTreeMap::new(),
    };
    merge::merge_secrets(&parent_secrets, onto_secrets, commit_secrets)
}

/// Result of replaying one commit onto a target tree.
#[derive(Debug)]
pub(crate) enum ReplayOutcome {
    /// Merged tree written to the CAS.
    Clean {
        root: ObjectId,
        /// Assembled protection for the replayed snapshot: union rules
        /// (onto-side ∪ commit-side), wrapped = carry ∪ fresh (wrap-reused
        /// against the onto side's prior wraps, pruned to the merged tree).
        protection: Protection,
    },
    /// Replayed tree equals the onto tree AND this commit's own
    /// protection-prefix rules are unchanged from its parent's — a genuine
    /// tree+rules no-op (P15 Task 9). The secret registry is NOT considered
    /// here (`replay_commit` never sees a registry): callers additionally
    /// merge the registry and must not treat this as a true no-op if that
    /// merge changes anything — see `merged_registry_for_replay` and the
    /// `Empty` handling in `Repo::cherry_pick`/`Repo::rebase`.
    Empty,
    /// Conflicting paths, with the raw merged working set (markers included;
    /// `needs_encrypt` entries carry plaintext that must NEVER transit the
    /// CAS) and sidecars, ready for the caller's conflict-materialize path.
    Conflicts {
        files: Vec<MergedFile>,
        sidecars: Vec<(String, Vec<u8>)>,
        paths: Vec<String>,
    },
}

/// Split a replay/merge working set the way `Repo::merge_with_identity`'s
/// clean path does (Task 6): carried ciphertext (`needs_encrypt: false`,
/// PROTECTED) stays byte-for-byte as-is; `needs_encrypt` outputs
/// (content-merged protected plaintext) get routed to encryption; a carried
/// PLAIN file (perms 0) whose path still matches a union rule is ALSO routed
/// through encryption — one side unprotecting a path the other side still
/// rules must not let plaintext land in the replayed snapshot (bit<->rule
/// invariant, Task 4 review I2). Returns `(carried, to_encrypt)` write-set
/// halves ready for `write_tree_with_perms` / `protect::encrypt_protected`.
#[allow(clippy::type_complexity)]
fn split_for_encryption(
    files: &[MergedFile],
    union_prot: &Protection,
) -> Result<(
    Vec<(String, Vec<u8>, FileMode, u8)>,
    Vec<(String, Vec<u8>, FileMode, Vec<[u8; 32]>)>,
)> {
    let mut carried: Vec<(String, Vec<u8>, FileMode, u8)> = Vec::new();
    let mut to_encrypt: Vec<(String, Vec<u8>, FileMode, Vec<[u8; 32]>)> = Vec::new();
    for f in files {
        if f.needs_encrypt {
            let recipients = protect::matching_prefix(union_prot, &f.path)
                .map(|r| r.recipients.clone())
                .ok_or_else(|| Error::NotProtected(f.path.clone()))?;
            to_encrypt.push((f.path.clone(), f.bytes.clone(), f.mode, recipients));
        } else if f.perms & scl_core::PROTECTED == 0 {
            match protect::matching_prefix(union_prot, &f.path) {
                Some(rule) => to_encrypt.push((
                    f.path.clone(),
                    f.bytes.clone(),
                    f.mode,
                    rule.recipients.clone(),
                )),
                None => carried.push((f.path.clone(), f.bytes.clone(), f.mode, 0)),
            }
        } else {
            // Carried ciphertext: bytes are already the surviving blob's raw
            // ciphertext (fast path), never decrypted, perms verbatim.
            carried.push((f.path.clone(), f.bytes.clone(), f.mode, f.perms));
        }
    }
    Ok((carried, to_encrypt))
}

/// Replay (cherry-pick) `commit_id` onto the `onto` tree (root + the onto
/// side's protection policy).
///
/// This is a three-way merge: base = `commit_id`'s first parent (`None`, i.e.
/// the empty tree, if `commit_id` is a root commit), ours = `onto`, theirs =
/// `commit_id` itself — each side paired with its snapshot's protection so
/// protected paths resolve exactly like `Repo::merge_with_identity`'s
/// three-way (P15): ciphertext-id fast paths need no identity; a protected
/// path that diverged in *content* on both sides needs `identity`
/// ([`Error::ProtectedMergeNeedsIdentity`] without one). Merge commits (2+
/// parents) are refused — mainline selection is not supported.
///
/// The clean path is self-contained: `needs_encrypt` outputs are encrypted
/// against the union rules (onto-side ∪ commit-side) and the returned
/// [`ReplayOutcome::Clean`] carries the fully assembled protection (union
/// rules; wraps = carry ∪ fresh, wrap-reused against the onto side, pruned to
/// the merged tree) so callers (cherry-pick, and rebase's fold) only
/// thread it into `build_snapshot`.
pub(crate) fn replay_commit(
    repo: &Repo,
    commit_id: ObjectId,
    onto: (ObjectId, &Protection),
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<ReplayOutcome> {
    let snap = repo.snapshot(&commit_id)?;
    if snap.parents.len() >= 2 {
        return Err(Error::CannotReplayMerge(commit_id));
    }
    let (onto_root, onto_prot) = onto;
    let base_snap = match snap.parents.first() {
        Some(p) => Some(repo.snapshot(p)?),
        None => None,
    };
    let theirs_root = snap.root;
    let theirs_prot = &snap.protection;

    let fm = {
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        merge::three_way_files(
            &mut store,
            base_snap.as_ref().map(|b| (b.root, &b.protection)),
            (onto_root, onto_prot),
            (theirs_root, theirs_prot),
            identity,
        )?
    };

    if !fm.conflicts.is_empty() {
        return Ok(ReplayOutcome::Conflicts {
            files: fm.files,
            sidecars: fm.sidecars,
            paths: fm.conflicts,
        });
    }

    // Union protection rules across both sides (same discipline as the clean
    // merge path in `Repo::merge_with_identity`): governs which recipients a
    // needs_encrypt output is encrypted for, and becomes the replayed
    // snapshot's rule set. `union_prot` exists only to drive
    // `matching_prefix` lookups — its `wrapped` map is irrelevant here.
    let union_prefixes = protect::union_prefixes(&onto_prot.prefixes, &theirs_prot.prefixes);
    let union_prot = Protection { prefixes: union_prefixes.clone(), wrapped: Default::default() };

    let (mut all, to_encrypt) = split_for_encryption(&fm.files, &union_prot)?;
    let (encrypted, fresh_wrapped) = protect::encrypt_protected(to_encrypt);
    all.extend(encrypted);
    let root = repo.vfs().write_tree_with_perms(&all)?;

    // Empty (P15 Task 9 extension): a tree-equal replay is a genuine no-op
    // only when this commit's own protection-prefix rules are ALSO
    // unchanged from its parent's. A rules-only `protect` commit whose tree
    // never touched a matching file (root == onto_root) must still surface
    // as Clean so the caller counts it as replayed (not skipped) and its
    // rule reaches the assembled/accumulated protection — otherwise it is
    // silently dropped, exactly the Task 8 review finding this closes.
    let protection_changed_here = match base_snap.as_ref() {
        Some(b) => theirs_prot.prefixes != b.protection.prefixes,
        None => !theirs_prot.prefixes.is_empty(),
    };
    if root == onto_root && !protection_changed_here {
        return Ok(ReplayOutcome::Empty);
    }

    // Assembled wrap map: carried wraps (`wrapped_carry`, for ciphertext that
    // survived unchanged/one-sided) ∪ the freshly encrypted entries' wraps,
    // then reuse the onto side's prior wrap bytes for any unchanged
    // (blob, recipient), then prune to blobs actually reachable in the
    // replayed tree — verbatim the clean-merge assembly in
    // `Repo::merge_with_identity`, so replay and merge encode protection
    // identically for identical content.
    let mut wrapped: BTreeMap<ObjectId, Vec<WrappedKey>> = fm.wrapped_carry;
    for (id, wks) in fresh_wrapped {
        let entry = wrapped.entry(id).or_default();
        *entry = protect::union_wraps(entry, &wks);
    }
    protect::reuse_prior_wraps(&mut wrapped, &onto_prot.wrapped);
    {
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let reachable: std::collections::BTreeSet<ObjectId> =
            worktree::tree_file_entries_with_perms(&mut store, root)?
                .values()
                .map(|(id, _, _)| *id)
                .collect();
        wrapped.retain(|id, _| reachable.contains(id));
    }

    Ok(ReplayOutcome::Clean {
        root,
        protection: Protection { prefixes: union_prefixes, wrapped },
    })
}

/// Outcome of [`Repo::cherry_pick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickResult {
    /// The replayed commit was applied as a new single-parent snapshot.
    Picked(ObjectId),
    /// Change already present on the current branch — nothing committed.
    AlreadyApplied,
}

impl Repo {
    /// Replay `refname`'s tip commit onto the current branch (cherry-pick).
    ///
    /// Preflight mirrors `Repo::merge`'s, in the same order, so the two
    /// commands fail identically for identical reasons: merge-in-progress and
    /// pick-in-progress guards, an unborn current branch (`Error::Unborn`),
    /// resolving `refname` (`Error::NoSuchBranch`), then the dirty-working-tree
    /// check. A clean replay advances the current branch with a single-parent
    /// snapshot (`parents: [ours_tip]`) whose message is the picked commit's
    /// first message line plus a `(cherry-picked from <short>)` suffix. The
    /// clean path follows `Repo::merge`'s crash discipline: snapshot to the
    /// CAS, materialize the working tree, *then* move the branch ref (the ref
    /// update is the atomic commit point — a crash before it leaves tip and
    /// tree consistently pre-pick), with the oplog record written last, after
    /// the ref write it describes. A conflicting replay writes conflict markers
    /// + sidecars over the working tree and records pick state
    /// (`PICK_HEAD`/`PICK_CONFLICTS`/`PICK_DECIDED_ROOT`) — no ref moves, no
    /// oplog entry, so the current branch tip is unchanged until the conflicts
    /// are resolved and committed. An empty replay is `AlreadyApplied` only
    /// when the tree, the picked commit's own protection-rules delta, AND the
    /// merged secret registry are all no-ops; a secrets-only pick lands as a
    /// registry-only snapshot (same tree), and the registry is merged
    /// three-way (base = the picked commit's own parent) on every pick — a
    /// name changed differently on both sides is
    /// [`Error::SecretMergeConflict`] with refs untouched (P15 Task 9).
    ///
    /// Protected paths (P15 Task 7) resolve exactly like
    /// [`merge_with_identity`][Repo::merge_with_identity]'s three-way:
    /// ciphertext-id fast paths need no `identity`; a protected path that
    /// diverged in content on both sides needs one
    /// ([`Error::ProtectedMergeNeedsIdentity`] without it, refs untouched). A
    /// conflicted pick carrying protection writes plaintext markers to the
    /// working tree ONLY (never through the CAS) and is completed by
    /// `sc commit`, which unions the tip's rules with the picked commit's and
    /// carries absent protected files from the pick's decided tree.
    pub fn cherry_pick(
        &self,
        refname: &str,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<PickResult> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        let ours_tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let picked_tip = refs::resolve_tip(&self.layout, refname)?
            .ok_or_else(|| Error::NoSuchBranch(refname.to_string()))?;
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before cherry-picking".into(),
            ));
        }

        let head = refs::current_branch(&self.layout)?;
        let before = refs::read_branch_tip(&self.layout, &head)?;
        let ours_snap = self.snapshot(&ours_tip)?;
        let ours_root = ours_snap.root;
        let picked_snap = self.snapshot(&picked_tip)?;

        match replay_commit(self, picked_tip, (ours_root, &ours_snap.protection), identity)? {
            ReplayOutcome::Empty => {
                // Tree AND this commit's own protection-prefix delta are both
                // no-ops (see `replay_commit`'s Empty gate) — but the secret
                // registry is merged independently (P15 Task 9): a
                // secrets-only commit still needs to land as a
                // registry-only snapshot rather than being dropped.
                let merged_secrets = merged_registry_for_replay(
                    self,
                    &picked_snap.parents,
                    &picked_snap.secrets,
                    &ours_snap.secrets,
                )?;
                if merged_secrets == ours_snap.secrets {
                    Ok(PickResult::AlreadyApplied)
                } else {
                    let msg_first_line = picked_snap.message.lines().next().unwrap_or("");
                    let message =
                        format!("{msg_first_line} (cherry-picked from {})", picked_tip.short());
                    // Same crash discipline as the Clean path below: CAS
                    // write, then the ref move (atomic commit point), then
                    // the oplog record. No materialize needed — the tree is
                    // byte-identical to `ours_root`, already on disk.
                    let id = self.build_snapshot(
                        ours_root,
                        vec![ours_tip],
                        merged_secrets,
                        ours_snap.protection.clone(),
                        author,
                        &message,
                    )?;
                    refs::write_branch_tip(&self.layout, &head, &id)?;
                    crate::oplog::record(
                        &self.layout,
                        &format!("cherry-pick {refname}"),
                        &head,
                        &head,
                        &[(head.clone(), before, Some(id))],
                    )?;
                    Ok(PickResult::Picked(id))
                }
            }
            ReplayOutcome::Clean { root, protection } => {
                let merged_secrets = merged_registry_for_replay(
                    self,
                    &picked_snap.parents,
                    &picked_snap.secrets,
                    &ours_snap.secrets,
                )?;
                let msg_first_line = picked_snap.message.lines().next().unwrap_or("");
                let message = format!("{msg_first_line} (cherry-picked from {})", picked_tip.short());
                // Ordering matters for crash safety (same discipline as
                // `Repo::merge`'s ff and three-way paths): build the snapshot
                // (CAS-only, no visible state), materialize the working tree,
                // and only then move the branch ref — the ref update is the
                // atomic commit point, so a crash before it leaves both tip
                // and tree at the pre-pick state. The oplog record goes last,
                // after the ref write it describes. The replay's ASSEMBLED
                // protection (union rules, carry ∪ fresh wraps) is what the
                // new snapshot records — ours' policy alone would drop the
                // picked side's rules and the wraps of carried/re-encrypted
                // blobs. The registry is the three-way merge computed above,
                // not ours' verbatim (P15 Task 9).
                let id = self.build_snapshot(
                    root,
                    vec![ours_tip],
                    merged_secrets,
                    protection.clone(),
                    author,
                    &message,
                )?;
                {
                    let store_arc = self.vfs().store();
                    let mut store = store_arc.lock().unwrap();
                    // Protection-aware materialize: a PROTECTED entry decrypts
                    // for `identity` when possible, else is skipped (never
                    // writes ciphertext to disk) — same as merge's clean path.
                    worktree::materialize(
                        &self.layout,
                        &mut store,
                        root,
                        Some(ours_root),
                        &protection,
                        identity,
                    )?;
                }
                refs::write_branch_tip(&self.layout, &head, &id)?;
                crate::oplog::record(
                    &self.layout,
                    &format!("cherry-pick {refname}"),
                    &head,
                    &head,
                    &[(head.clone(), before, Some(id))],
                )?;
                Ok(PickResult::Picked(id))
            }
            ReplayOutcome::Conflicts { files, sidecars, paths } => {
                // Conflicted pick (P15 Task 7) — same worktree-direct-write
                // restructure as `Repo::merge_with_identity`'s conflict path
                // (Task 6). The working set holds plaintext `needs_encrypt`
                // entries (conflict markers and clean content merges of
                // protected paths; reachable only with an identity — plus
                // ours' carried-plain files under a picked-side-only rule,
                // the I2 case). Plaintext must NEVER transit the CAS: the CAS
                // tree used for materialization is built from the carried
                // entries ONLY (surviving ciphertext + plain files, all
                // already CAS-safe), and every `needs_encrypt` file —
                // conflicted or not — is written straight to the working tree
                // via `safe_join`, exactly like sidecars. Re-encryption
                // happens at completion: `sc commit` unions the tip's rules
                // with the picked commit's (`snapshot_files`).
                let union_prefixes = crate::protect::union_prefixes(
                    &ours_snap.protection.prefixes,
                    &picked_snap.protection.prefixes,
                );
                let union_prot = scl_core::Protection {
                    prefixes: union_prefixes.clone(),
                    wrapped: Default::default(),
                };
                let (carried, to_encrypt) = split_for_encryption(&files, &union_prot)?;
                let conflict_root = self.vfs().write_tree_with_perms(&carried)?;
                // Wraps for the conflict materialize: ours ∪ picked (a carried
                // blob survives from one of the two sides, so their unioned
                // maps cover every carried PROTECTED entry — the same
                // coverage `wrapped_carry` provides on the merge path).
                let mut wrapped = ours_snap.protection.wrapped.clone();
                for (id, wks) in &picked_snap.protection.wrapped {
                    let entry = wrapped.entry(*id).or_default();
                    *entry = crate::protect::union_wraps(entry, wks);
                }
                let conflict_prot =
                    scl_core::Protection { prefixes: union_prefixes, wrapped };
                {
                    let store_arc = self.vfs().store();
                    let mut store = store_arc.lock().unwrap();
                    // Carried PROTECTED entries decrypt for `identity` where
                    // its key matches; the rest are skipped (absent from
                    // disk). The completion commit's decided-tree
                    // carry-forward preserves skipped content.
                    let _skipped = worktree::materialize(
                        &self.layout,
                        &mut store,
                        conflict_root,
                        Some(ours_root),
                        &conflict_prot,
                        identity,
                    )?;
                }
                // Direct plaintext writes AFTER materialize: its deletion pass
                // (ours-tracked paths absent from the carried-only tree) would
                // otherwise remove what we just wrote.
                for (path, bytes, _mode, _recipients) in &to_encrypt {
                    let full = worktree::safe_join(&self.layout.root, path)?;
                    if let Some(parent) = full.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(full, bytes)?;
                }
                for (rel, bytes) in &sidecars {
                    let full = self.layout.root.join(rel);
                    if let Some(parent) = full.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(full, bytes)?;
                }
                // Markers are on disk; record pick state last (its PICK_HEAD
                // write is the in-progress signal). The decided carried tree
                // (`conflict_root`) is persisted alongside so completion
                // carries absent protected files from the pick's DECISION
                // rather than re-reading the stale tip.
                crate::pick_state::write(&self.layout, &picked_tip, &paths, Some(&conflict_root))?;
                Err(Error::PickConflicts(paths.len()))
            }
        }
    }

    /// Replay the current branch's commits onto `target`'s tip (rebase).
    ///
    /// Preflight mirrors `cherry_pick`'s exactly (merge/pick-in-progress
    /// guards, unborn HEAD, ref resolution, dirty-working-tree check). Then:
    /// fast paths for already-up-to-date and pure-fast-forward cases (no
    /// oplog record for the former; ref move + materialize + oplog for the
    /// latter), else a real replay over the first-parent range from the
    /// current tip back to the merge-base (exclusive), applied oldest-first
    /// onto target's tip. Any merge commit anywhere in that range refuses the
    /// whole rebase up front (`Error::CannotReplayMerge`) before a single
    /// commit is replayed. The first conflict aborts the entire rebase with
    /// refs and the working tree untouched — nothing outside the CAS is
    /// written until every replayed commit in the range is clean (unlike
    /// `cherry_pick`, which leaves conflict markers for a single commit).
    /// Same crash discipline as `cherry_pick`'s clean path: snapshots land in
    /// the CAS, then the working tree is materialized, then the branch ref is
    /// moved (the atomic commit point), with the oplog record written last.
    ///
    /// Protected paths (P15 Task 8) resolve per replayed commit exactly like
    /// [`cherry_pick`][Repo::cherry_pick]'s: ciphertext-id fast paths need no
    /// `identity`; a protected path that diverged in content on both sides
    /// needs one. The fold threads the ACCUMULATED protection — each clean
    /// replay's assembled protection (union rules, carry ∪ fresh wraps)
    /// becomes both the new snapshot's policy and the onto-side policy for
    /// the next commit in the range, so a file freshly encrypted by an
    /// earlier replay keeps its wraps through the rest of the fold. An
    /// identity/authorization failure aborts the whole rebase like a conflict
    /// does (refs and working tree byte-identical), with the typed error
    /// naming both the path and the commit being replayed. The final (and ff
    /// fast-path) materialize decrypts for `identity` where possible and
    /// skips the rest — never writes ciphertext to disk.
    ///
    /// The secret registry is replayed too (P15 Task 9): the fold's
    /// accumulator starts from target's registry and each commit's own
    /// registry change is merged in three-way (base = the commit's
    /// original-history parent). A secrets-only or rules-only commit counts
    /// as replayed — it lands as a snapshot with the accumulator's tree plus
    /// the merged registry / assembled protection — and `skipped` is reserved
    /// for commits whose tree, own-rules delta, AND registry delta are all
    /// no-ops. A name changed differently on both lines aborts the whole
    /// rebase ([`Error::SecretMergeConflict`], refs byte-identical).
    pub fn rebase(
        &self,
        target: &str,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<RebaseResult> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        let ours_tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let target_tip = refs::resolve_tip(&self.layout, target)?
            .ok_or_else(|| Error::NoSuchBranch(target.to_string()))?;
        let dirty = self.status()?;
        if !dirty.modified.is_empty() || !dirty.deleted.is_empty() {
            return Err(Error::InvalidArgument(
                "working tree has uncommitted changes; commit before rebasing".into(),
            ));
        }

        let head = refs::current_branch(&self.layout)?;
        let before = refs::read_branch_tip(&self.layout, &head)?;
        let ours_snap = self.snapshot(&ours_tip)?;
        let ours_root = ours_snap.root;

        // Fast paths.
        {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            if merge::is_ancestor(&mut store, target_tip, ours_tip)? {
                return Ok(RebaseResult::AlreadyUpToDate);
            }
            if merge::is_ancestor(&mut store, ours_tip, target_tip)? {
                let target_snap = store.get_snapshot(&target_tip)?;
                let target_root = target_snap.root;
                let target_protection = target_snap.protection;
                worktree::materialize(
                    &self.layout,
                    &mut store,
                    target_root,
                    Some(ours_root),
                    &target_protection,
                    identity,
                )?;
                drop(store);
                refs::write_branch_tip(&self.layout, &head, &target_tip)?;
                crate::oplog::record(
                    &self.layout,
                    &format!("rebase onto {target} (ff)"),
                    &head,
                    &head,
                    &[(head.clone(), before, Some(target_tip))],
                )?;
                return Ok(RebaseResult::FastForwarded(target_tip));
            }
        }

        // Real replay: collect the first-parent range from ours_tip back to
        // the merge-base (exclusive), oldest-first, then pre-scan for merge
        // commits so a rebase either replays cleanly in full or refuses
        // before touching anything.
        let base = {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            merge::merge_base(&mut store, ours_tip, target_tip)?.ok_or(Error::NoCommonAncestor)?
        };
        let mut range = Vec::new();
        {
            let mut cur = ours_tip;
            while cur != base {
                let snap = self.snapshot(&cur)?;
                if snap.parents.len() >= 2 {
                    return Err(Error::CannotReplayMerge(cur));
                }
                range.push(cur);
                cur = snap.parents.first().copied().ok_or(Error::NoCommonAncestor)?;
            }
        }
        range.reverse();

        let target_snap = self.snapshot(&target_tip)?;
        let mut acc_tip = target_tip;
        let mut acc_root = target_snap.root;
        // Accumulated protection: starts as target's policy and is replaced by
        // each clean replay's ASSEMBLED protection, so the onto side of every
        // step sees the rules and wraps produced by the steps before it (a
        // file freshly encrypted mid-range stays decryptable downstream).
        let mut acc_protection = target_snap.protection.clone();
        // Accumulated secret registry (P15 Task 9): starts as target's and
        // folds each commit's own registry change in via a per-commit
        // three-way merge (base = the commit's original-history parent,
        // ours = the accumulator, theirs = the commit) — the registry analog
        // of the file fold below. A `SecretMergeConflict` anywhere in the
        // range aborts the whole rebase before anything outside the CAS is
        // written, so refs and the working tree stay byte-identical.
        let mut acc_secrets = target_snap.secrets.clone();
        let mut replayed = 0usize;
        let mut skipped = 0usize;

        for commit in range {
            let commit_snap = self.snapshot(&commit)?;
            let merged_secrets = merged_registry_for_replay(
                self,
                &commit_snap.parents,
                &commit_snap.secrets,
                &acc_secrets,
            )?;
            let secrets_changed = merged_secrets != acc_secrets;
            // A rebase spans a range, so an identity/authorization abort must
            // name WHICH replay tripped, not just the path — same spirit as
            // `RebaseConflicts` carrying its commit. Nothing outside the CAS
            // has been written when these fire, so the abort leaves refs and
            // the working tree byte-identical.
            let outcome = replay_commit(self, commit, (acc_root, &acc_protection), identity)
                .map_err(|e| match e {
                    Error::ProtectedMergeNeedsIdentity(path) => Error::ProtectedMergeNeedsIdentity(
                        format!("{path} (replaying commit {})", commit.short()),
                    ),
                    Error::NotAuthorized(path) => {
                        Error::NotAuthorized(format!("{path} (replaying commit {})", commit.short()))
                    }
                    other => other,
                })?;
            match outcome {
                ReplayOutcome::Empty if !secrets_changed => {
                    // Empty in full — tree, this commit's own rules delta
                    // (both inside `replay_commit`'s gate), AND registry
                    // delta: a genuine no-op, skipped.
                    skipped += 1;
                }
                ReplayOutcome::Empty => {
                    // Tree/rules no-op but the registry changed: land a
                    // registry-only snapshot (same tree and protection as the
                    // accumulator) so the secret change survives the rebase —
                    // counts as replayed, not skipped.
                    let id = self.build_snapshot(
                        acc_root,
                        vec![acc_tip],
                        merged_secrets.clone(),
                        acc_protection.clone(),
                        author,
                        &commit_snap.message,
                    )?;
                    acc_tip = id;
                    acc_secrets = merged_secrets;
                    replayed += 1;
                }
                ReplayOutcome::Clean { root, protection } => {
                    // The replay's ASSEMBLED protection (union rules, carry ∪
                    // fresh wraps — same discipline as cherry-pick's clean
                    // path) is recorded on the new snapshot AND becomes the
                    // accumulator for the next step of the fold — as does the
                    // merged registry (P15 Task 9).
                    let id = self.build_snapshot(
                        root,
                        vec![acc_tip],
                        merged_secrets.clone(),
                        protection.clone(),
                        author,
                        &commit_snap.message,
                    )?;
                    acc_tip = id;
                    acc_root = root;
                    acc_protection = protection;
                    acc_secrets = merged_secrets;
                    replayed += 1;
                }
                ReplayOutcome::Conflicts { paths, .. } => {
                    // Nothing outside the CAS has been written: no working-tree
                    // markers, no ref moves — the whole rebase aborts cleanly.
                    return Err(Error::RebaseConflicts { commit, paths });
                }
            }
        }

        {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            // The LAST assembled protection covers every blob in `acc_root`
            // (each step pruned its wrap map to its own merged tree): a
            // PROTECTED entry decrypts for `identity` when possible, else is
            // skipped — never writes ciphertext to disk.
            worktree::materialize(
                &self.layout,
                &mut store,
                acc_root,
                Some(ours_root),
                &acc_protection,
                identity,
            )?;
        }
        refs::write_branch_tip(&self.layout, &head, &acc_tip)?;
        crate::oplog::record(
            &self.layout,
            &format!("rebase onto {target} ({replayed} replayed, {skipped} skipped)"),
            &head,
            &head,
            &[(head.clone(), before, Some(acc_tip))],
        )?;
        Ok(RebaseResult::Rebased { new_tip: acc_tip, replayed, skipped })
    }
}

/// Outcome of [`Repo::rebase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseResult {
    /// Target already reachable from the current tip — nothing to do.
    AlreadyUpToDate,
    /// Current tip was an ancestor of target — ref fast-forwarded.
    FastForwarded(ObjectId),
    /// Commits replayed; branch now points at the last new snapshot.
    Rebased { new_tip: ObjectId, replayed: usize, skipped: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::tree_file_ids;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-replay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// True if any loose CAS blob contains `needle` (same helper as repo.rs's
    /// Task 6 tests): plaintext markers/protected content must never transit
    /// the store.
    fn cas_blob_contains(repo: &Repo, needle: &[u8]) -> bool {
        let store_arc = repo.vfs().store();
        let mut s = store_arc.lock().unwrap();
        for id in s.list_loose().unwrap() {
            if let Ok(scl_core::Object::Blob(b)) = s.get(&id) {
                if b.windows(needle.len()).any(|w| w == needle) {
                    return true;
                }
            }
        }
        false
    }

    /// The (blob id, perms) of `path` in `commit`'s root tree.
    fn tree_entry(repo: &Repo, commit: &ObjectId, path: &str) -> (ObjectId, u8) {
        let store_arc = repo.vfs().store();
        let mut s = store_arc.lock().unwrap();
        let root = s.get_snapshot(commit).unwrap().root;
        let entries = worktree::tree_file_entries_with_perms(&mut s, root).unwrap();
        let (id, _, perms) = entries[path];
        (id, perms)
    }

    /// Raw bytes of blob `id` in the store.
    fn blob_bytes_of(repo: &Repo, id: &ObjectId) -> Vec<u8> {
        let store_arc = repo.vfs().store();
        let mut s = store_arc.lock().unwrap();
        match s.get(id).unwrap() {
            scl_core::Object::Blob(b) => b.to_vec(),
            _ => panic!("expected Blob"),
        }
    }

    #[test]
    fn clean_replay_produces_merged_root() {
        let root = tmp_root("clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"base\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        // main separately edits Y.
        std::fs::write(root.join("y.txt"), b"y\n").unwrap();
        let main_tip = repo.commit("me", "main edits y").unwrap();

        // branch b edits X.
        repo.switch("b").unwrap();
        std::fs::write(root.join("x.txt"), b"x\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip));

        let onto_snap = repo.snapshot(&main_tip).unwrap();
        let outcome =
            replay_commit(&repo, b_tip, (onto_snap.root, &onto_snap.protection), None).unwrap();
        match outcome {
            ReplayOutcome::Clean { root: merged_root, .. } => {
                let store_arc = repo.vfs().store();
                let mut store = store_arc.lock().unwrap();
                let ids = tree_file_ids(&mut store, merged_root).unwrap();
                assert!(ids.contains_key("x.txt"), "b's edit must be present");
                assert!(ids.contains_key("y.txt"), "main's edit must be present");
                assert!(ids.contains_key("shared.txt"));
            }
            _ => panic!("expected Clean, got a different outcome"),
        }
        let _ = base;
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn conflicting_replay_reports_paths_with_markers() {
        let root = tmp_root("conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        let main_tip = repo.commit("me", "main edits x").unwrap();

        repo.switch("b").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();
        repo.switch("main").unwrap();

        let onto_snap = repo.snapshot(&main_tip).unwrap();
        let outcome =
            replay_commit(&repo, b_tip, (onto_snap.root, &onto_snap.protection), None).unwrap();
        match outcome {
            ReplayOutcome::Conflicts { files, paths, .. } => {
                assert_eq!(paths, vec!["x.txt".to_string()]);
                let x = &files.iter().find(|f| f.path == "x.txt").unwrap().bytes;
                assert!(String::from_utf8_lossy(x).contains("<<<<<<<"));
            }
            _ => panic!("expected Conflicts"),
        }
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn already_applied_replay_is_empty() {
        let root = tmp_root("empty");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("b").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        let b_tip = repo.commit("me", "b edits x").unwrap();

        // main independently makes the exact same edit.
        repo.switch("main").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        let main_tip = repo.commit("me", "main makes same edit").unwrap();

        let onto_snap = repo.snapshot(&main_tip).unwrap();
        let outcome =
            replay_commit(&repo, b_tip, (onto_snap.root, &onto_snap.protection), None).unwrap();
        assert!(matches!(outcome, ReplayOutcome::Empty));
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn root_commit_replays_against_empty_base() {
        let root_a = tmp_root("root-a");
        let repo_a = Repo::init(&root_a).unwrap();
        std::fs::write(root_a.join("new.txt"), b"new\n").unwrap();
        let a_root_commit = repo_a.commit("me", "lineage a root").unwrap();
        assert!(repo_a.snapshot(&a_root_commit).unwrap().parents.is_empty());

        let root_b = tmp_root("root-b");
        let repo_b = Repo::init(&root_b).unwrap();
        std::fs::write(root_b.join("existing.txt"), b"existing\n").unwrap();
        let b_tip = repo_b.commit("me", "lineage b tip").unwrap();

        // Reconstruct lineage a's root commit inside repo_b's store so
        // `replay_commit` can read it — copy the commit's tree/blob objects.
        let a_snap = repo_a.snapshot(&a_root_commit).unwrap();
        let store_a_arc = repo_a.vfs().store();
        let store_b_arc = repo_b.vfs().store();
        {
            let mut store_a = store_a_arc.lock().unwrap();
            let ids = tree_file_ids(&mut store_a, a_snap.root).unwrap();
            let mut files = Vec::new();
            for (path, id) in ids {
                let bytes = match store_a.get(&id).unwrap() {
                    scl_core::Object::Blob(b) => b.to_vec(),
                    _ => panic!("expected blob"),
                };
                files.push((path, bytes, FileMode::FILE));
            }
            drop(store_a);
            let copied_root = repo_b.vfs().write_tree(&files).unwrap();
            let mut store_b = store_b_arc.lock().unwrap();
            let copied_commit = store_b
                .put(scl_core::Object::Snapshot(scl_core::Snapshot {
                    root: copied_root,
                    parents: vec![],
                    author: "me".into(),
                    timestamp: 0,
                    message: "lineage a root (copied)".into(),
                    secrets: Default::default(),
                    protection: Default::default(),
                }))
                .unwrap();
            drop(store_b);

            let onto_snap = repo_b.snapshot(&b_tip).unwrap();
            let outcome =
                replay_commit(&repo_b, copied_commit, (onto_snap.root, &onto_snap.protection), None)
                    .unwrap();
            match outcome {
                ReplayOutcome::Clean { root: merged_root, .. } => {
                    let mut store_b = store_b_arc.lock().unwrap();
                    let ids = tree_file_ids(&mut store_b, merged_root).unwrap();
                    assert!(ids.contains_key("new.txt"));
                    assert!(ids.contains_key("existing.txt"));
                }
                _ => panic!("expected Clean"),
            }
        }
        drop(repo_a);
        drop(repo_b);
        std::fs::remove_dir_all(&root_a).ok();
        std::fs::remove_dir_all(&root_b).ok();
    }

    #[test]
    fn merge_commit_replay_is_refused() {
        let root = tmp_root("refused");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        let base = repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        let main_tip = repo.commit("me", "main adds a").unwrap();
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"f\n").unwrap();
        repo.commit("me", "feature adds f").unwrap();
        let merged = repo.merge("main", "me").unwrap();
        assert!(repo.snapshot(&merged).unwrap().parents.len() >= 2);

        let onto_snap = repo.snapshot(&main_tip).unwrap();
        let err = replay_commit(&repo, merged, (onto_snap.root, &onto_snap.protection), None)
            .unwrap_err();
        assert!(matches!(err, Error::CannotReplayMerge(id) if id == merged), "got {err:?}");
        let _ = base;

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_clean_advances_branch_and_materializes() {
        let root = tmp_root("cp-clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();

        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"x\n").unwrap();
        let picked = repo.commit("me", "add x").unwrap();
        repo.switch("main").unwrap();
        let old_main_tip = repo.head_tip().unwrap().unwrap();

        let outcome = repo.cherry_pick("work-1", "me", None).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked, got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(id));

        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![old_main_tip]);
        assert!(
            snap.message.ends_with(&format!("(cherry-picked from {})", picked.short())),
            "got message: {}",
            snap.message
        );
        assert_eq!(std::fs::read_to_string(root.join("x.txt")).unwrap(), "x\n");

        let ops = repo.oplog().unwrap();
        assert_eq!(ops.last().unwrap().desc, "cherry-pick work-1");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_conflicting_writes_markers_and_state_moves_no_refs() {
        let root = tmp_root("cp-conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        let main_tip = repo.commit("me", "main edits x").unwrap();

        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        let picked = repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip));

        let err = repo.cherry_pick("work-1", "me", None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip), "main tip must not move");
        assert_eq!(repo.pick_head().unwrap(), Some(picked));
        let on_disk = std::fs::read_to_string(root.join("x.txt")).unwrap();
        assert!(on_disk.contains("<<<<<<<"), "got: {on_disk}");

        // Resolve + commit: single-parent commit, pick state cleared.
        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();
        let resolved = repo.commit("me", "resolve conflict").unwrap();
        let resolved_snap = repo.snapshot(&resolved).unwrap();
        assert_eq!(resolved_snap.parents, vec![main_tip]);
        assert!(!repo.pick_in_progress());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_already_applied_is_a_noop() {
        let root = tmp_root("cp-empty");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();

        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();

        let merged = repo.merge("work-1", "me").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(merged));
        let ops_before = repo.oplog().unwrap().len();

        let outcome = repo.cherry_pick("work-1", "me", None).unwrap();
        assert!(matches!(outcome, PickResult::AlreadyApplied), "got {outcome:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(merged), "tip must not move");
        assert_eq!(repo.oplog().unwrap().len(), ops_before, "no new oplog record");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_preflight_guards() {
        let root = tmp_root("cp-guards");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();
        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();

        // Dirty working tree.
        std::fs::write(root.join("x.txt"), b"dirty\n").unwrap();
        let err = repo.cherry_pick("work-1", "me", None).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();

        // Merge in progress.
        let ours_tip = repo.head_tip().unwrap().unwrap();
        crate::merge_state::write(&repo.layout, &ours_tip, &[], None).unwrap();
        let err = repo.cherry_pick("work-1", "me", None).unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        crate::merge_state::clear(&repo.layout).unwrap();

        // Pick in progress.
        crate::pick_state::write(&repo.layout, &ours_tip, &[], None).unwrap();
        let err = repo.cherry_pick("work-1", "me", None).unwrap_err();
        assert!(matches!(err, Error::PickInProgress), "got {err:?}");
        crate::pick_state::clear(&repo.layout).unwrap();

        // Unknown ref.
        let err = repo.cherry_pick("no-such-branch", "me", None).unwrap_err();
        assert!(matches!(err, Error::NoSuchBranch(_)), "got {err:?}");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// From the Task 6 review: cherry-pick must also refuse during an
    /// in-progress merge, as a standalone mutual-exclusion check distinct
    /// from `cherry_pick_preflight_guards`'s combined guard sweep.
    #[test]
    fn cherry_pick_during_merge_is_refused() {
        let root = tmp_root("cp-merge-mutex");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work-1").unwrap();
        repo.switch("work-1").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\n").unwrap();
        repo.commit("me", "work edits x").unwrap();
        repo.switch("main").unwrap();

        let ours_tip = repo.head_tip().unwrap().unwrap();
        crate::merge_state::write(&repo.layout, &ours_tip, &[], None).unwrap();
        let err = repo.cherry_pick("work-1", "me", None).unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(ours_tip), "tip must not move");

        crate::merge_state::clear(&repo.layout).unwrap();
        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_disjoint_protected_commit_needs_no_identity() {
        // The picked commit updates a protected file ours never touched: the
        // ciphertext-id fast path carries the picked blob verbatim — no
        // identity needed — the branch advances, and the new snapshot's
        // protection keeps the blob's wraps so recipients still decrypt.
        let root = tmp_root("cp-prot-disjoint");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // work updates the protected file.
        repo.switch_with_identity("work", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"v2").unwrap();
        let picked = repo.commit("me", "work updates secret").unwrap();
        let (v2_id, _) = tree_entry(&repo, &picked, "secret/db.txt");

        // main gains an unrelated plain commit (keyless hop back).
        repo.switch("main").unwrap();
        std::fs::write(root.join("main.txt"), b"m\n").unwrap();
        let main_tip = repo.commit("me", "main adds main.txt").unwrap();

        // KEYLESS pick.
        let outcome = repo.cherry_pick("work", "me", None).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked, got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(id), "branch advanced");
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);

        // The picked ciphertext blob is carried byte-for-byte, PROTECTED.
        let (got_id, perms) = tree_entry(&repo, &id, "secret/db.txt");
        assert_eq!(got_id, v2_id, "ciphertext carried verbatim");
        assert_ne!(perms & scl_core::PROTECTED, 0);
        // ...and its wraps survive into the new snapshot's protection.
        let bytes = blob_bytes_of(&repo, &got_id);
        let pt = crate::protect::decrypt_with(
            &bytes,
            &got_id,
            &[&snap.protection],
            &alice_sk,
            "secret/db.txt",
        )
        .unwrap();
        assert_eq!(&pt[..], b"v2", "recipient decrypts the picked update");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_content_divergent_requires_identity_and_reencrypts() {
        // secret/a.txt diverged in content on both sides (mergeable lines):
        // a keyless pick fails with the typed error and moves nothing; with
        // an identity the plaintexts are diff3'd and the merged content is
        // re-encrypted for ALL rule recipients.
        let root = tmp_root("cp-prot-divergent");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk, bob_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // ours edits line 1.
        std::fs::write(root.join("secret/a.txt"), b"OURS\nl2\nl3\n").unwrap();
        let main_tip = repo.commit("me", "main edits line 1").unwrap();

        // work edits line 3 (mergeable divergence).
        repo.switch_with_identity("work", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nTHEIRS\n").unwrap();
        repo.commit("me", "work edits line 3").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        // Keyless: typed error, refs untouched, no pick state.
        let err = repo.cherry_pick("work", "me", None).unwrap_err();
        assert!(
            matches!(err, Error::ProtectedMergeNeedsIdentity(ref p) if p == "secret/a.txt"),
            "got {err:?}"
        );
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip), "tip must not move");
        assert!(!repo.pick_in_progress(), "no pick state on the identity refusal");

        // With identity: clean pick, merged content re-encrypted.
        let outcome = repo.cherry_pick("work", "me", Some(&alice_sk)).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked, got {other:?}"),
        };
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);
        let (blob_id, perms) = tree_entry(&repo, &id, "secret/a.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0, "PROTECTED preserved");
        let bytes = blob_bytes_of(&repo, &blob_id);
        assert!(!bytes.windows(4).any(|w| w == b"OURS"), "plaintext leaked into the CAS blob");
        for (who, sk) in [("alice", &alice_sk), ("bob", &bob_sk)] {
            let pt = crate::protect::decrypt_with(
                &bytes,
                &blob_id,
                &[&snap.protection],
                sk,
                "secret/a.txt",
            )
            .unwrap();
            assert_eq!(&pt[..], b"OURS\nl2\nTHEIRS\n", "{who} must decrypt the merged content");
        }
        // The identity-holder gets the merged plaintext on disk.
        assert_eq!(
            std::fs::read(root.join("secret/a.txt")).unwrap(),
            b"OURS\nl2\nTHEIRS\n".to_vec()
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_protected_conflict_writes_plaintext_markers_worktree_only() {
        // Same-line edits of secret/a.txt on both sides: the pick conflicts.
        // The plaintext marker file must live on DISK ONLY — no CAS object
        // may contain the marker plaintext — and resolving + committing
        // completes the pick with a single-parent snapshot whose re-encrypted
        // blob keeps PROTECTED and decrypts for every recipient.
        let root = tmp_root("cp-prot-conflict");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk, bob_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"OURS-EDIT\nl2\nl3\n").unwrap();
        let ours = repo.commit("me", "main edits line 1").unwrap();
        repo.switch_with_identity("work", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"THEIRS-EDIT\nl2\nl3\n").unwrap();
        let picked = repo.commit("me", "work edits line 1").unwrap();
        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();

        let err = repo.cherry_pick("work", "me", Some(&alice_sk)).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(ours), "tip must not move");
        assert_eq!(repo.pick_head().unwrap(), Some(picked));
        assert!(
            crate::pick_state::read_decided_root(&repo.layout).unwrap().is_some(),
            "conflict path records the pick's decided carried tree"
        );

        // Markers are on disk as editable plaintext...
        let marked = std::fs::read(root.join("secret/a.txt")).unwrap();
        assert!(marked.windows(7).any(|w| w == b"<<<<<<<"), "markers on disk");
        assert!(marked.windows(9).any(|w| w == b"OURS-EDIT"));
        assert!(marked.windows(11).any(|w| w == b"THEIRS-EDIT"));
        // ...and NO CAS object contains the marker plaintext.
        assert!(!cas_blob_contains(&repo, b"<<<<<<<"), "marker plaintext leaked into the CAS");
        assert!(!cas_blob_contains(&repo, b"OURS-EDIT"), "protected plaintext leaked into the CAS");

        // Resolve and complete via commit: re-encryption happens there.
        std::fs::write(root.join("secret/a.txt"), b"RESOLVED\nl2\nl3\n").unwrap();
        let id = repo.commit("me", "resolve pick conflict").unwrap();
        assert!(!repo.pick_in_progress());
        assert_eq!(
            crate::pick_state::read_decided_root(&repo.layout).unwrap(),
            None,
            "completing commit clears the pick decided root"
        );
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![ours], "pick completion is single-parent");

        let (blob_id, perms) = tree_entry(&repo, &id, "secret/a.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0, "PROTECTED preserved through completion");
        let bytes = blob_bytes_of(&repo, &blob_id);
        assert!(!bytes.windows(8).any(|w| w == b"RESOLVED"), "resolved plaintext in CAS blob");
        for (who, sk) in [("alice", &alice_sk), ("bob", &bob_sk)] {
            let pt = crate::protect::decrypt_with(
                &bytes,
                &blob_id,
                &[&snap.protection],
                sk,
                "secret/a.txt",
            )
            .unwrap();
            assert_eq!(&pt[..], b"RESOLVED\nl2\nl3\n", "{who} must decrypt the resolution");
        }
        // Still no marker/plaintext residue anywhere in the CAS after completion.
        assert!(!cas_blob_contains(&repo, b"<<<<<<<"));
        assert!(!cas_blob_contains(&repo, b"RESOLVED"));

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn pick_completion_carries_picked_protected_update_not_ours_stale() {
        // The pick analog of merge scenario B (Task 6 review): a plain
        // conflict forces the conflict path while the picked commit carries a
        // protected update that resolves clean ("only theirs changed → take
        // theirs"). A keyless resolver's completing commit must carry the
        // PICKED (decided) ciphertext from PICK_DECIDED_ROOT — a tip-only
        // carry-forward would commit ours' STALE blob and silently drop the
        // picked update.
        let root = tmp_root("cp-decided-tree");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x.txt"), b"v0").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // ours: only the plain conflicting edit; secret/x.txt stays v0.
        std::fs::write(root.join("shared.txt"), b"a\nX\nc\n").unwrap();
        let ours = repo.commit("me", "ours edits shared").unwrap();

        // picked: update secret/x.txt to v1 + the conflicting plain edit.
        repo.switch_with_identity("work", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/x.txt"), b"v1").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nY\nc\n").unwrap();
        let picked = repo.commit("me", "work updates secret + edits shared").unwrap();
        let (v1_id, _) = tree_entry(&repo, &picked, "secret/x.txt");

        // KEYLESS hop back to main (secret/x.txt leaves the disk).
        repo.switch("main").unwrap();

        // KEYLESS conflicted pick: x.txt is decided clean (take picked) but
        // cannot materialize without a key; shared.txt conflicts.
        let err = repo.cherry_pick("work", "me", None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert!(!root.join("secret/x.txt").exists(), "keyless: v1 stays off disk");

        std::fs::write(root.join("shared.txt"), b"a\nRESOLVED\nc\n").unwrap();
        let id = repo.commit("me", "resolve").unwrap();
        assert!(!repo.pick_in_progress());
        assert_eq!(
            crate::pick_state::read_decided_root(&repo.layout).unwrap(),
            None,
            "completing commit clears the pick decided root"
        );
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![ours], "pick completion is single-parent");

        let (got_id, perms) = tree_entry(&repo, &id, "secret/x.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0);
        assert_eq!(
            got_id, v1_id,
            "completion must carry the PICKED decided v1 ciphertext, not ours' stale v0"
        );
        // The carried blob decrypts via the completion snapshot's protection
        // (tip ∪ picked wraps — only the picked commit knew this blob's DEK).
        let bytes = blob_bytes_of(&repo, &got_id);
        let pt = crate::protect::decrypt_with(
            &bytes,
            &got_id,
            &[&snap.protection],
            &alice_sk,
            "secret/x.txt",
        )
        .unwrap();
        assert_eq!(&pt[..], b"v1", "the carried blob decrypts to the picked update");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn stale_merge_decided_root_residue_does_not_hijack_pick_completion() {
        // Task 7 review (Important): the conflict paths write the decided
        // root BEFORE their HEAD (crash discipline), so a crashed conflicted
        // merge can leave MERGE_DECIDED_ROOT with NO MERGE_HEAD. Completion
        // must read a decided root only under its own in-progress HEAD —
        // an ungated read let this residue hijack a later pick's completion,
        // carrying ours' STALE v0 over the pick's decided v1.
        let root = tmp_root("cp-stale-merge-residue");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/x.txt"), b"v0").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // ours: only the plain conflicting edit; secret/x.txt stays v0.
        std::fs::write(root.join("shared.txt"), b"a\nX\nc\n").unwrap();
        let ours = repo.commit("me", "ours edits shared").unwrap();

        // picked: update secret/x.txt to v1 + the conflicting plain edit.
        repo.switch_with_identity("work", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/x.txt"), b"v1").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nY\nc\n").unwrap();
        let picked = repo.commit("me", "work updates secret + edits shared").unwrap();
        let (v1_id, _) = tree_entry(&repo, &picked, "secret/x.txt");

        repo.switch("main").unwrap();

        // Crash residue: MERGE_DECIDED_ROOT pointing at OURS' tree (holds the
        // stale v0 ciphertext), with NO MERGE_HEAD — exactly what a crash
        // between the decided-root write and the MERGE_HEAD write leaves.
        let ours_root = repo.snapshot(&ours).unwrap().root;
        std::fs::write(
            repo.layout.dot_sc.join("MERGE_DECIDED_ROOT"),
            format!("{}\n", ours_root.to_hex()),
        )
        .unwrap();
        assert!(!crate::merge_state::in_progress(&repo.layout), "no MERGE_HEAD");

        // Keyless conflicted pick, resolve, complete.
        let err = repo.cherry_pick("work", "me", None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        std::fs::write(root.join("shared.txt"), b"a\nRESOLVED\nc\n").unwrap();
        let id = repo.commit("me", "resolve").unwrap();

        let (got_id, perms) = tree_entry(&repo, &id, "secret/x.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0);
        assert_eq!(
            got_id, v1_id,
            "the PICK's decided v1 must win — stale merge residue hijacked the completion"
        );
        // The completing commit's merge_state::clear also swept the residue.
        assert_eq!(crate::merge_state::read_decided_root(&repo.layout).unwrap(), None);

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn clean_cherry_pick_encrypts_ours_plain_file_under_picked_side_rule() {
        // The clean-pick I2 case: ours holds a PLAIN file under a rule only
        // the picked side knows. The replayed tree must carry it as PROTECTED
        // ciphertext under the union rule — one side lacking the rule must
        // not let plaintext land in the replayed snapshot (bit<->rule
        // invariant). No identity needed: fresh encryption uses public keys.
        let root = tmp_root("cp-clean-i2");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // ours: a plain file under keys/ — no rule on this side.
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/k1.txt"), b"k1 contents\n").unwrap();
        let main_tip = repo.commit("me", "main adds plain keys/k1.txt").unwrap();

        // picked side: add the keys/ rule, then a protected file under it.
        repo.switch("work").unwrap();
        repo.protect("keys/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/k2.txt"), b"k2 contents\n").unwrap();
        let picked = repo.commit("me", "work adds protected keys/k2.txt").unwrap();
        let (k2_id, _) = tree_entry(&repo, &picked, "keys/k2.txt");

        repo.switch("main").unwrap();

        // KEYLESS clean pick.
        let outcome = repo.cherry_pick("work", "me", None).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked, got {other:?}"),
        };
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);
        assert!(
            snap.protection.prefixes.iter().any(|p| p.prefix == "keys/"),
            "union rule recorded on the picked snapshot"
        );

        // Ours' formerly-plain k1 is now PROTECTED ciphertext under the union
        // rule, freshly wrapped for the rule's recipients...
        let (k1_id, k1_perms) = tree_entry(&repo, &id, "keys/k1.txt");
        assert_ne!(k1_perms & scl_core::PROTECTED, 0, "I2: plain file under union rule encrypts");
        let k1_bytes = blob_bytes_of(&repo, &k1_id);
        assert_ne!(&k1_bytes[..], b"k1 contents\n", "no plaintext in the CAS tree");
        let pt = crate::protect::decrypt_with(
            &k1_bytes,
            &k1_id,
            &[&snap.protection],
            &alice_sk,
            "keys/k1.txt",
        )
        .unwrap();
        assert_eq!(&pt[..], b"k1 contents\n");
        // ...and the keyless materialize removed the now-protected plaintext
        // from disk (confidentiality: no key, no plaintext).
        assert!(!root.join("keys/k1.txt").exists(), "keyless: protected file leaves the disk");

        // The picked side's k2 ciphertext is carried verbatim with its wraps.
        let (got_k2, k2_perms) = tree_entry(&repo, &id, "keys/k2.txt");
        assert_eq!(got_k2, k2_id, "picked ciphertext carried verbatim");
        assert_ne!(k2_perms & scl_core::PROTECTED, 0);
        let k2_bytes = blob_bytes_of(&repo, &got_k2);
        let pt = crate::protect::decrypt_with(
            &k2_bytes,
            &got_k2,
            &[&snap.protection],
            &alice_sk,
            "keys/k2.txt",
        )
        .unwrap();
        assert_eq!(&pt[..], b"k2 contents\n");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_replays_commits_in_order_onto_target() {
        let root = tmp_root("rebase-order");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main gains a commit after the branch point.
        std::fs::write(root.join("main.txt"), b"main\n").unwrap();
        let main_tip = repo.commit("me", "main adds main.txt").unwrap();

        // feature gains two commits from the old base.
        repo.switch("feature").unwrap();
        std::fs::write(root.join("c1.txt"), b"c1\n").unwrap();
        let c1 = repo.commit("me", "feature c1").unwrap();
        std::fs::write(root.join("c2.txt"), b"c2\n").unwrap();
        let c2 = repo.commit("me", "feature c2").unwrap();
        let _ = c2;

        let outcome = repo.rebase("main", "me", None).unwrap();
        let (new_tip, replayed, skipped) = match outcome {
            RebaseResult::Rebased { new_tip, replayed, skipped } => (new_tip, replayed, skipped),
            other => panic!("expected Rebased, got {other:?}"),
        };
        assert_eq!(replayed, 2);
        assert_eq!(skipped, 0);
        assert_eq!(repo.head_tip().unwrap(), Some(new_tip));

        // Parent chain: new_tip <- c1' <- main_tip.
        let c2_snap = repo.snapshot(&new_tip).unwrap();
        assert_eq!(c2_snap.message, "feature c2");
        assert_eq!(c2_snap.parents.len(), 1);
        let c1_new_id = c2_snap.parents[0];
        let c1_snap = repo.snapshot(&c1_new_id).unwrap();
        assert_eq!(c1_snap.message, "feature c1");
        assert_eq!(c1_snap.parents, vec![main_tip]);
        assert_ne!(c1_new_id, c1);

        // Working tree matches the final root: all three files present.
        assert!(root.join("base.txt").exists());
        assert!(root.join("main.txt").exists());
        assert!(root.join("c1.txt").exists());
        assert!(root.join("c2.txt").exists());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_fast_paths() {
        let root = tmp_root("rebase-ff");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // Current (main) is already an ancestor of feature (target): FastForwarded.
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"f\n").unwrap();
        let feature_tip = repo.commit("me", "feature adds f").unwrap();
        repo.switch("main").unwrap();

        let outcome = repo.rebase("feature", "me", None).unwrap();
        assert_eq!(outcome, RebaseResult::FastForwarded(feature_tip));
        assert_eq!(repo.head_tip().unwrap(), Some(feature_tip));
        let ops = repo.oplog().unwrap();
        assert_eq!(ops.last().unwrap().desc, "rebase onto feature (ff)");

        // Target is now an ancestor of current: AlreadyUpToDate.
        let outcome = repo.rebase("feature", "me", None).unwrap();
        assert_eq!(outcome, RebaseResult::AlreadyUpToDate);
        assert_eq!(repo.head_tip().unwrap(), Some(feature_tip), "tip must not move");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn conflicting_rebase_aborts_with_refs_byte_identical() {
        let root = tmp_root("rebase-conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();
        // Stay on feature: rebase feature onto main.

        // Snapshot the entire .sc/refs dir (path -> bytes) before rebasing.
        let refs_dir = root.join(".sc/refs");
        let snapshot_refs = |dir: &std::path::Path| -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
            let mut out = std::collections::BTreeMap::new();
            for entry in walkdir(dir) {
                let bytes = std::fs::read(&entry).unwrap();
                out.insert(entry, bytes);
            }
            out
        };
        fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            let mut out = Vec::new();
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries {
                    let e = e.unwrap();
                    let p = e.path();
                    if p.is_dir() {
                        out.extend(walkdir(&p));
                    } else {
                        out.push(p);
                    }
                }
            }
            out
        }

        let before_refs = snapshot_refs(&refs_dir);
        let before_x = std::fs::read(root.join("x.txt")).unwrap();
        let ops_before = repo.oplog().unwrap().len();

        let err = repo.rebase("main", "me", None).unwrap_err();
        match err {
            Error::RebaseConflicts { paths, .. } => assert_eq!(paths, vec!["x.txt".to_string()]),
            other => panic!("expected RebaseConflicts, got {other:?}"),
        }

        let after_refs = snapshot_refs(&refs_dir);
        assert_eq!(before_refs, after_refs, "refs dir must be byte-identical after an aborted rebase");
        let after_x = std::fs::read(root.join("x.txt")).unwrap();
        assert_eq!(before_x, after_x, "working tree file must be unchanged");
        assert_eq!(repo.oplog().unwrap().len(), ops_before, "no new oplog record");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_skips_already_applied_commits() {
        let root = tmp_root("rebase-skip");
        // main independently makes the exact same edit as feature's commit A
        // (e.g. via a prior cherry-pick of an equivalent change), so replaying
        // A onto main during the rebase is `Empty` -> skipped.
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        repo.commit("me", "feature adds a").unwrap();
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "feature adds b").unwrap();

        repo.switch("main").unwrap();
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        repo.commit("me", "main makes same edit as feature's A").unwrap();

        // Rebase feature onto main.
        repo.switch("feature").unwrap();
        let outcome = repo.rebase("main", "me", None).unwrap();
        match outcome {
            RebaseResult::Rebased { replayed, skipped, .. } => {
                assert_eq!(replayed, 1, "only 'adds b' should replay");
                assert_eq!(skipped, 1, "'adds a' is already present -> skipped");
            }
            other => panic!("expected Rebased, got {other:?}"),
        }
        assert!(root.join("b.txt").exists());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// P15 Task 9: the secret registry is replayed through rebase. A
    /// secrets-only commit in the range lands as a registry-only snapshot
    /// (same tree as its parent) and counts as replayed, not skipped.
    #[test]
    fn rebase_replays_secrets_only_commit_as_registry_only_snapshot() {
        let root = tmp_root("rebase-secrets-replay");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main advances so the rebase has real work to do.
        std::fs::write(root.join("main.txt"), b"main\n").unwrap();
        repo.commit("me", "main adds main.txt").unwrap();

        // feature: a file commit + a secrets-only commit (secret_add commits
        // a registry-only snapshot itself).
        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"f\n").unwrap();
        repo.commit("me", "feature adds f").unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("API_KEY", b"v1", &[pk]).unwrap();

        let outcome = repo.rebase("main", "me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased { new_tip, replayed, skipped } => {
                assert_eq!((replayed, skipped), (2, 0), "secrets-only commit replays, not skips");
                new_tip
            }
            other => panic!("expected Rebased, got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(new_tip));

        // The new tip carries the secret through the rebase...
        let tip_snap = repo.snapshot(&new_tip).unwrap();
        assert!(
            tip_snap.secrets.contains_key("API_KEY"),
            "the rebased registry must contain the secret"
        );
        assert_eq!(repo.secret_list().unwrap().len(), 1);
        // ...as a registry-only snapshot: its tree equals its parent's (the
        // replayed file commit), which in turn holds main's + feature's files.
        let parent_snap = repo.snapshot(&tip_snap.parents[0]).unwrap();
        assert_eq!(tip_snap.root, parent_snap.root, "registry-only snapshot keeps the tree");
        assert!(!parent_snap.secrets.contains_key("API_KEY"));
        assert!(root.join("main.txt").exists());
        assert!(root.join("f.txt").exists());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// P15 Task 9: cherry-picking a secrets-only commit produces a
    /// registry-only snapshot (Picked, not AlreadyApplied), tree unchanged.
    #[test]
    fn cherry_pick_secret_add_commit_replays_registry() {
        let root = tmp_root("cp-secrets-replay");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // work: a secrets-only commit at the tip.
        repo.switch("work").unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("API_KEY", b"v1", &[pk]).unwrap();

        repo.switch("main").unwrap();
        let main_tip = repo.head_tip().unwrap().unwrap();
        let main_root = repo.snapshot(&main_tip).unwrap().root;

        let outcome = repo.cherry_pick("work", "me", None).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked (not AlreadyApplied), got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(id));

        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![main_tip], "single-parent pick completion");
        assert!(snap.secrets.contains_key("API_KEY"), "tip registry gains the secret");
        assert_eq!(snap.root, main_root, "tree unchanged by a secrets-only pick");
        assert_eq!(repo.secret_list().unwrap().len(), 1);
        let ops = repo.oplog().unwrap();
        assert_eq!(ops.last().unwrap().desc, "cherry-pick work");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// P15 Task 9: the same secret changed differently on both lines aborts
    /// the rebase atomically — typed `SecretMergeConflict`, refs
    /// byte-identical, no oplog record.
    #[test]
    fn registry_conflict_aborts_rebase_atomically() {
        let root = tmp_root("rebase-secrets-conflict");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("TOKEN", b"v0", &[pk.clone()]).unwrap();
        repo.branch("feature").unwrap();

        // main rotates TOKEN one way...
        repo.secret_rotate("TOKEN", Some(b"main-v"), &[pk.clone()], None).unwrap();
        // ...feature rotates it differently.
        repo.switch("feature").unwrap();
        repo.secret_rotate("TOKEN", Some(b"feat-v"), &[pk], None).unwrap();
        let feature_tip = repo.head_tip().unwrap();

        let before_refs = snapshot_dir(&root.join(".sc/refs"));
        let ops_before = repo.oplog().unwrap().len();

        let err = repo.rebase("main", "me", None).unwrap_err();
        assert!(
            matches!(err, Error::SecretMergeConflict(ref n) if n == "TOKEN"),
            "got {err:?}"
        );

        assert_eq!(
            before_refs,
            snapshot_dir(&root.join(".sc/refs")),
            "refs dir must be byte-identical after the aborted rebase"
        );
        assert_eq!(repo.head_tip().unwrap(), feature_tip, "feature tip must not move");
        assert_eq!(repo.oplog().unwrap().len(), ops_before, "no new oplog record");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Task 8 review (Important, folded into Task 9): a rules-only `protect`
    /// commit at the tip of the rebased range must survive — the old
    /// root-equality-only `Empty` silently dropped it. It replays as a
    /// snapshot with the same tree + assembled protection (counts as
    /// replayed), and a file later committed under the rule lands PROTECTED.
    #[test]
    fn rebase_rules_only_commit_at_range_tip_survives() {
        let root = tmp_root("rebase-rules-only");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main advances so the rebase has real work to do.
        std::fs::write(root.join("main.txt"), b"main\n").unwrap();
        repo.commit("me", "main adds main.txt").unwrap();

        // feature: a rules-only protect commit AT THE RANGE TIP. `protect`
        // lands two commits (the policy-only snapshot + a no-op encrypt
        // pass over an empty match set); point the branch at the policy-only
        // one — same tree, so the working tree stays consistent.
        repo.switch("feature").unwrap();
        let after_protect = repo.protect("keys/", &[alice_pk], None).unwrap();
        let rules_only = repo.snapshot(&after_protect).unwrap().parents[0];
        let head = refs::current_branch(&repo.layout).unwrap();
        refs::write_branch_tip(&repo.layout, &head, &rules_only).unwrap();

        let outcome = repo.rebase("main", "me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased { new_tip, replayed, skipped } => {
                assert_eq!((replayed, skipped), (1, 0), "rules-only commit replays, not skips");
                new_tip
            }
            other => panic!("expected Rebased, got {other:?}"),
        };
        let snap = repo.snapshot(&new_tip).unwrap();
        assert!(
            snap.protection.prefixes.iter().any(|p| p.prefix == "keys/"),
            "the rule survives to the new tip's protection"
        );
        // Tree-empty replay: same tree as the target tip it replayed onto.
        let main_tip_snap = repo.snapshot(&snap.parents[0]).unwrap();
        assert_eq!(snap.root, main_tip_snap.root, "rules-only replay keeps the tree");

        // A file later committed under the rule lands PROTECTED and decrypts
        // for the rule's recipient.
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/k.txt"), b"k contents\n").unwrap();
        let c = repo.commit("me", "add keys/k.txt").unwrap();
        let (k_id, perms) = tree_entry(&repo, &c, "keys/k.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0, "file under the replayed rule is PROTECTED");
        let bytes = blob_bytes_of(&repo, &k_id);
        assert_ne!(&bytes[..], b"k contents\n", "no plaintext in the CAS");
        let c_snap = repo.snapshot(&c).unwrap();
        let pt = crate::protect::decrypt_with(
            &bytes,
            &k_id,
            &[&c_snap.protection],
            &alice_sk,
            "keys/k.txt",
        )
        .unwrap();
        assert_eq!(&pt[..], b"k contents\n");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Cherry-pick analog of the rules-only regression: picking a rules-only
    /// commit is Picked (not AlreadyApplied) — same tree, union protection.
    #[test]
    fn cherry_pick_rules_only_commit_replays_rule() {
        let root = tmp_root("cp-rules-only");
        let repo = Repo::init(&root).unwrap();
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // work's tip: the policy-only protect commit (see the rebase analog
        // above for why the branch is pointed at `protect`'s first commit).
        repo.switch("work").unwrap();
        let after_protect = repo.protect("keys/", &[alice_pk], None).unwrap();
        let rules_only = repo.snapshot(&after_protect).unwrap().parents[0];
        let head = refs::current_branch(&repo.layout).unwrap();
        refs::write_branch_tip(&repo.layout, &head, &rules_only).unwrap();

        repo.switch("main").unwrap();
        let main_tip = repo.head_tip().unwrap().unwrap();
        let main_root = repo.snapshot(&main_tip).unwrap().root;

        let outcome = repo.cherry_pick("work", "me", None).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked (not AlreadyApplied), got {other:?}"),
        };
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);
        assert_eq!(snap.root, main_root, "rules-only pick keeps the tree");
        assert!(
            snap.protection.prefixes.iter().any(|p| p.prefix == "keys/"),
            "the picked rule lands on the new snapshot"
        );

        // A file later committed under the rule lands PROTECTED.
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/k.txt"), b"k contents\n").unwrap();
        let c = repo.commit("me", "add keys/k.txt").unwrap();
        let (_k_id, perms) = tree_entry(&repo, &c, "keys/k.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0, "file under the picked rule is PROTECTED");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_range_with_merge_commit_is_refused() {
        let root = tmp_root("rebase-merge-refused");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("main2").unwrap();
        repo.branch("feature").unwrap();

        // main2 is a side branch that feature will merge in.
        repo.switch("main2").unwrap();
        std::fs::write(root.join("side.txt"), b"side\n").unwrap();
        repo.commit("me", "side commit").unwrap();

        // feature merges main2 in, producing a merge commit in feature's history.
        repo.switch("feature").unwrap();
        std::fs::write(root.join("feat.txt"), b"feat\n").unwrap();
        repo.commit("me", "feature commit").unwrap();
        let merged = repo.merge("main2", "me").unwrap();
        assert!(repo.snapshot(&merged).unwrap().parents.len() >= 2);
        let feature_tip_before = repo.head_tip().unwrap();

        // main gains an unrelated commit, so rebasing feature onto main has
        // real work to do (not a fast path).
        repo.switch("main").unwrap();
        std::fs::write(root.join("main.txt"), b"main\n").unwrap();
        repo.commit("me", "main adds main.txt").unwrap();

        repo.switch("feature").unwrap();
        assert_eq!(repo.head_tip().unwrap(), feature_tip_before);

        let err = repo.rebase("main", "me", None).unwrap_err();
        assert!(matches!(err, Error::CannotReplayMerge(id) if id == merged), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), feature_tip_before, "feature tip must not move");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Snapshot every file under `dir` (path -> bytes) — the refs-dir
    /// byte-compare pattern from `conflicting_rebase_aborts_with_refs_byte_identical`.
    fn snapshot_dir(
        dir: &std::path::Path,
    ) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries {
                let p = e.unwrap().path();
                if p.is_dir() {
                    out.extend(snapshot_dir(&p));
                } else {
                    out.insert(p.clone(), std::fs::read(&p).unwrap());
                }
            }
        }
        out
    }

    #[test]
    fn rebase_protected_branch_by_non_recipient_disjoint_edits() {
        // Feature updates a protected file the target never touched: every
        // replay rides the ciphertext-id fast path, so a NON-RECIPIENT
        // rebases keyless — and the accumulated protection carries the blob's
        // wraps to the new tip, where the recipient still decrypts.
        let root = tmp_root("rebase-prot-disjoint");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"v1").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main gains an unrelated plain commit.
        std::fs::write(root.join("main.txt"), b"m\n").unwrap();
        let main_tip = repo.commit("me", "main adds main.txt").unwrap();

        // feature updates the protected file (identity only to materialize it
        // for editing — the rebase itself runs keyless).
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"v2").unwrap();
        let feature_tip = repo.commit("me", "feature updates secret").unwrap();
        let (v2_id, _) = tree_entry(&repo, &feature_tip, "secret/db.txt");

        // KEYLESS rebase of feature onto main.
        let outcome = repo.rebase("main", "me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased { new_tip, replayed, skipped } => {
                assert_eq!((replayed, skipped), (1, 0));
                new_tip
            }
            other => panic!("expected Rebased, got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(new_tip));
        let snap = repo.snapshot(&new_tip).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);

        // The feature ciphertext is carried byte-for-byte, PROTECTED, and its
        // wraps survive into the new tip's protection: alice decrypts v2.
        let (got_id, perms) = tree_entry(&repo, &new_tip, "secret/db.txt");
        assert_eq!(got_id, v2_id, "ciphertext carried verbatim");
        assert_ne!(perms & scl_core::PROTECTED, 0);
        let bytes = blob_bytes_of(&repo, &got_id);
        let pt = crate::protect::decrypt_with(
            &bytes,
            &got_id,
            &[&snap.protection],
            &alice_sk,
            "secret/db.txt",
        )
        .unwrap();
        assert_eq!(&pt[..], b"v2", "recipient decrypts at the new tip");
        // Keyless final materialize: main's file arrives, the protected file
        // leaves the disk (no key, no plaintext — never ciphertext).
        assert!(root.join("main.txt").exists());
        assert!(!root.join("secret/db.txt").exists(), "keyless: protected file leaves the disk");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_content_divergent_without_identity_aborts_byte_identical() {
        // secret/a.txt diverged in content on both sides (mergeable lines): a
        // keyless rebase aborts with the typed error naming BOTH the commit
        // being replayed and the path, refs byte-identical, working tree and
        // oplog untouched.
        let root = tmp_root("rebase-prot-divergent-keyless");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main (target) edits line 1.
        std::fs::write(root.join("secret/a.txt"), b"OURS\nl2\nl3\n").unwrap();
        repo.commit("me", "main edits line 1").unwrap();

        // feature edits line 3 (mergeable content divergence).
        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nTHEIRS\n").unwrap();
        let feature_tip = repo.commit("me", "feature edits line 3").unwrap();

        let before_refs = snapshot_dir(&root.join(".sc/refs"));
        let before_a = std::fs::read(root.join("secret/a.txt")).unwrap();
        let ops_before = repo.oplog().unwrap().len();

        let err = repo.rebase("main", "me", None).unwrap_err();
        match err {
            Error::ProtectedMergeNeedsIdentity(ref msg) => {
                assert!(msg.contains("secret/a.txt"), "error must name the path: {msg}");
                assert!(
                    msg.contains(&feature_tip.short()),
                    "error must name the replayed commit: {msg}"
                );
            }
            other => panic!("expected ProtectedMergeNeedsIdentity, got {other:?}"),
        }

        assert_eq!(
            before_refs,
            snapshot_dir(&root.join(".sc/refs")),
            "refs dir must be byte-identical after the aborted rebase"
        );
        assert_eq!(repo.head_tip().unwrap(), Some(feature_tip), "feature tip must not move");
        assert_eq!(std::fs::read(root.join("secret/a.txt")).unwrap(), before_a);
        assert_eq!(repo.oplog().unwrap().len(), ops_before, "no new oplog record");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_content_divergent_with_identity_succeeds() {
        // Same divergence as above, rebased WITH an identity: the plaintexts
        // diff3 cleanly and the merged content is re-encrypted for ALL rule
        // recipients, PROTECTED at the new tip, no plaintext in the CAS.
        let root = tmp_root("rebase-prot-divergent-key");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk, bob_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("secret/a.txt"), b"OURS\nl2\nl3\n").unwrap();
        let main_tip = repo.commit("me", "main edits line 1").unwrap();

        repo.switch_with_identity("feature", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nTHEIRS\n").unwrap();
        repo.commit("me", "feature edits line 3").unwrap();

        let outcome = repo.rebase("main", "me", Some(&alice_sk)).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased { new_tip, replayed, skipped } => {
                assert_eq!((replayed, skipped), (1, 0));
                new_tip
            }
            other => panic!("expected Rebased, got {other:?}"),
        };
        let snap = repo.snapshot(&new_tip).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);

        let (blob_id, perms) = tree_entry(&repo, &new_tip, "secret/a.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0, "PROTECTED preserved at the new tip");
        let bytes = blob_bytes_of(&repo, &blob_id);
        assert!(!bytes.windows(4).any(|w| w == b"OURS"), "plaintext leaked into the CAS blob");
        for (who, sk) in [("alice", &alice_sk), ("bob", &bob_sk)] {
            let pt = crate::protect::decrypt_with(
                &bytes,
                &blob_id,
                &[&snap.protection],
                sk,
                "secret/a.txt",
            )
            .unwrap();
            assert_eq!(&pt[..], b"OURS\nl2\nTHEIRS\n", "{who} must decrypt the merged content");
        }
        // The identity-holder gets the merged plaintext on disk.
        assert_eq!(
            std::fs::read(root.join("secret/a.txt")).unwrap(),
            b"OURS\nl2\nTHEIRS\n".to_vec()
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Task 7 review regression: the interim guard aborted MID-FOLD when an
    /// earlier replayed commit freshly encrypted a plain file under a
    /// rules-only policy (I2) — commit B's replay then saw a PROTECTED entry
    /// in the onto tree it had built itself. With the guard deleted and the
    /// accumulated protection threaded, the multi-commit rebase succeeds and
    /// the mid-range fresh wraps survive to the new tip.
    #[test]
    fn rebase_fresh_encryption_mid_fold_replays_next_commit_cleanly() {
        let root = tmp_root("rebase-midfold-i2");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main (target): a rules-only keys/ policy — no keys/ file exists.
        repo.protect("keys/", &[alice_pk], None).unwrap();
        std::fs::write(root.join("main.txt"), b"m\n").unwrap();
        repo.commit("me", "main adds main.txt").unwrap();

        // feature, no rule on this side: commit A adds a PLAIN rule-matching
        // file (gets freshly encrypted by I2 when replayed), commit B on top.
        repo.switch("feature").unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/k1.txt"), b"k1 contents\n").unwrap();
        repo.commit("me", "A: feature adds plain keys/k1.txt").unwrap();
        std::fs::write(root.join("other.txt"), b"o\n").unwrap();
        repo.commit("me", "B: feature adds other.txt").unwrap();

        // KEYLESS rebase (fresh encryption uses public keys only).
        let outcome = repo.rebase("main", "me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased { new_tip, replayed, skipped } => {
                assert_eq!((replayed, skipped), (2, 0), "both commits replay cleanly");
                new_tip
            }
            other => panic!("expected Rebased, got {other:?}"),
        };
        let snap = repo.snapshot(&new_tip).unwrap();

        // A's formerly-plain file is PROTECTED ciphertext at the new tip, and
        // the fresh wraps minted while replaying A survived B's replay via
        // the accumulated protection: alice decrypts through the TIP snapshot.
        let (k1_id, perms) = tree_entry(&repo, &new_tip, "keys/k1.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0, "I2: plain file under union rule encrypts");
        let bytes = blob_bytes_of(&repo, &k1_id);
        assert_ne!(&bytes[..], b"k1 contents\n", "no plaintext in the CAS tree");
        let pt = crate::protect::decrypt_with(
            &bytes,
            &k1_id,
            &[&snap.protection],
            &alice_sk,
            "keys/k1.txt",
        )
        .unwrap();
        assert_eq!(&pt[..], b"k1 contents\n");

        // B's plain addition landed, and the keyless materialize kept the
        // now-protected file off disk.
        assert!(root.join("other.txt").exists());
        assert!(root.join("main.txt").exists());
        assert!(!root.join("keys/k1.txt").exists(), "keyless: protected file leaves the disk");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }
}
