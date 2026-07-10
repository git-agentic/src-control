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
/// accumulator for `rebase`, the completing tip for a conflicted pick's
/// `sc commit`); `commit_secrets`/`commit_parents` are the replayed commit's
/// own registry and parent list. `base_override` mirrors `replay_commit`'s
/// parameter of the same name (P19 Task 4 `--mainline`): when the file
/// replay's base is substituted with a chosen parent of a merge commit, the
/// registry three-way's base must be that SAME parent's registry, not the
/// commit's first parent — otherwise a mainline pick can silently re-add (or
/// drop) a secret that only the non-mainline side touched, since the
/// registry base would disagree with the file base about what "already
/// there" means. `None` (all non-mainline callers, including rebase's fold,
/// which only ever replays non-merge commits) preserves the original
/// first-parent base. Errors (`Error::SecretMergeConflict`) propagate
/// verbatim — the caller must not have written anything outside the CAS when
/// this is called, so the abort is atomic.
pub(crate) fn merged_registry_for_replay(
    repo: &Repo,
    commit_parents: &[ObjectId],
    commit_secrets: &BTreeMap<String, ObjectId>,
    onto_secrets: &BTreeMap<String, ObjectId>,
    base_override: Option<ObjectId>,
) -> Result<BTreeMap<String, ObjectId>> {
    let parent_secrets = match base_override.or_else(|| commit_parents.first().copied()) {
        Some(p) => repo.snapshot(&p)?.secrets,
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
                .map(|r| r.granted_keys())
                .ok_or_else(|| Error::NotProtected(f.path.clone()))?;
            to_encrypt.push((f.path.clone(), f.bytes.clone(), f.mode, recipients));
        } else if f.perms & scl_core::PROTECTED == 0 {
            match protect::matching_prefix(union_prot, &f.path) {
                Some(rule) => {
                    to_encrypt.push((f.path.clone(), f.bytes.clone(), f.mode, rule.granted_keys()))
                }
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
/// parents) are refused unless `base_override` is supplied (P19 Task 4
/// `--mainline`): passing it substitutes the chosen parent's tree/protection
/// as the merge base in place of the derived first-parent base, so the
/// replay's delta is computed relative to that parent instead. All non-
/// mainline callers pass `None`, preserving the original "no mainline
/// selection" refusal for merge commits.
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
    base_override: Option<ObjectId>,
) -> Result<ReplayOutcome> {
    let snap = repo.snapshot(&commit_id)?;
    if snap.parents.len() >= 2 && base_override.is_none() {
        return Err(Error::CannotReplayMerge(
            commit_id,
            format!(
                "cannot replay merge commit {commit_id}; use --mainline <N> to pick relative to parent N"
            ),
        ));
    }
    // Merge/pick completion guard (P27 Task 5, T5-I4): `three_way_files`
    // below flattens the full base/onto/theirs trees; on a partial clone
    // that would touch content this clone never fetched (out-of-filter),
    // silently surfacing as a raw `NotFound` from deep inside the flatten.
    // Refuse explicitly here instead — one choke point for both cherry-pick
    // and rebase's fold, which both replay through this function — pointing
    // at `sc backfill` rather than a confusing corruption-shaped error.
    if repo.promisor()?.is_some() {
        return Err(crate::promisor::partial_clone_unsupported(
            "cherry-pick/rebase replay",
        ));
    }

    let (onto_root, onto_prot) = onto;
    let base_snap = match base_override.or_else(|| snap.parents.first().copied()) {
        Some(p) => Some(repo.snapshot(&p)?),
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
    let union_prefixes = protect::merge_prefixes(&onto_prot.prefixes, &theirs_prot.prefixes);
    let union_prot = Protection {
        prefixes: union_prefixes.clone(),
        wrapped: Default::default(),
    };

    let (mut all, to_encrypt) = split_for_encryption(&fm.files, &union_prot)?;
    let (encrypted, fresh_wrapped) = protect::encrypt_protected(to_encrypt)?;
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
        protection: Protection {
            prefixes: union_prefixes,
            wrapped,
        },
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
    ///
    /// `mainline` (P19 Task 4, `--mainline <N>`) selects which parent of a
    /// merge commit to replay relative to: required (else
    /// [`Error::CannotReplayMerge`], text extended to point at the flag) when
    /// `picked_tip` has 2+ parents, and `1 <= N <= parents.len()` (else
    /// [`Error::InvalidArgument`]); `N` picks `parents[N-1]` as the base, so
    /// the replayed delta is "what changed relative to that parent". `Some`
    /// on a non-merge commit is also [`Error::InvalidArgument`] — mainline
    /// only makes sense when there is more than one parent to choose among.
    pub fn cherry_pick(
        &self,
        refname: &str,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
        mainline: Option<u32>,
    ) -> Result<PickResult> {
        if crate::merge_state::in_progress(&self.layout) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(&self.layout) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
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

        let base_override = match mainline {
            Some(n) => {
                if picked_snap.parents.len() < 2 {
                    return Err(Error::InvalidArgument(
                        "--mainline only applies to merge commits".into(),
                    ));
                }
                let idx = usize::try_from(n)
                    .ok()
                    .filter(|&i| i >= 1 && i <= picked_snap.parents.len());
                let idx = idx.ok_or_else(|| {
                    Error::InvalidArgument(format!(
                        "--mainline {n} is out of range (commit has {} parents)",
                        picked_snap.parents.len()
                    ))
                })?;
                Some(picked_snap.parents[idx - 1])
            }
            None => None,
        };

        // Registry three-way (P15 Task 9), hoisted above the file replay so a
        // registry conflict fails fast — even on a pick whose FILES would
        // conflict, the typed `SecretMergeConflict` surfaces here with refs
        // and working tree untouched, instead of being deferred to the
        // completing `sc commit`. `base_override` (P19 Task 4 review fix)
        // threads the SAME mainline-resolved parent into the registry base
        // as the file replay below uses — a mainline pick's registry three-
        // way must agree with its file three-way about what "unchanged"
        // means, else the non-mainline side's secret edits silently leak
        // into (or get dropped from) the new tip.
        let merged_secrets = merged_registry_for_replay(
            self,
            &picked_snap.parents,
            &picked_snap.secrets,
            &ours_snap.secrets,
            base_override,
        )?;

        match replay_commit(
            self,
            picked_tip,
            (ours_root, &ours_snap.protection),
            identity,
            base_override,
        )? {
            ReplayOutcome::Empty => {
                // Tree AND this commit's own protection-prefix delta are both
                // no-ops (see `replay_commit`'s Empty gate) — but the secret
                // registry is merged independently (P15 Task 9): a
                // secrets-only commit still needs to land as a
                // registry-only snapshot rather than being dropped.
                if merged_secrets == ours_snap.secrets {
                    Ok(PickResult::AlreadyApplied)
                } else {
                    let msg_first_line = picked_snap.message.lines().next().unwrap_or("");
                    let message = format!(
                        "{msg_first_line} (cherry-picked from {})",
                        picked_tip.short()
                    );
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
                let msg_first_line = picked_snap.message.lines().next().unwrap_or("");
                let message = format!(
                    "{msg_first_line} (cherry-picked from {})",
                    picked_tip.short()
                );
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
                    let mut cache = self.open_protected_cache()?;
                    worktree::materialize(
                        &self.layout,
                        &mut store,
                        root,
                        Some(ours_root),
                        &protection,
                        identity,
                        &self.sparse_spec()?,
                        Some(&mut cache),
                    )?;
                    cache.save()?;
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
            ReplayOutcome::Conflicts {
                files,
                sidecars,
                paths,
            } => {
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
                let union_prefixes = crate::protect::merge_prefixes(
                    &ours_snap.protection.prefixes,
                    &picked_snap.protection.prefixes,
                );
                let union_prot = scl_core::Protection {
                    prefixes: union_prefixes.clone(),
                    wrapped: Default::default(),
                };
                let (carried, to_encrypt) = split_for_encryption(&files, &union_prot)?;
                // Wraps for the conflict materialize: ours ∪ picked (a carried
                // blob survives from one of the two sides, so their unioned
                // maps cover every carried PROTECTED entry — the same
                // coverage `wrapped_carry` provides on the merge path).
                let mut wrapped = ours_snap.protection.wrapped.clone();
                for (id, wks) in &picked_snap.protection.wrapped {
                    let entry = wrapped.entry(*id).or_default();
                    *entry = crate::protect::union_wraps(entry, wks);
                }
                let conflict_prot = scl_core::Protection {
                    prefixes: union_prefixes,
                    wrapped,
                };
                let conflict_root = self.materialize_conflict_state(
                    &carried,
                    &to_encrypt,
                    &sidecars,
                    &conflict_prot,
                    ours_root,
                    identity,
                    &paths,
                )?;
                // Markers are on disk; record pick state last (its PICK_HEAD
                // write is the in-progress signal). The decided carried tree
                // (`conflict_root`) is persisted alongside so completion
                // carries absent protected files from the pick's DECISION
                // rather than re-reading the stale tip.
                crate::pick_state::write(
                    &self.layout,
                    &picked_tip,
                    &paths,
                    Some(&conflict_root),
                    base_override.as_ref(),
                )?;
                Err(Error::PickConflicts(paths.len()))
            }
        }
    }

    /// Abandon a cherry-pick stopped on conflict: clear the pick state and
    /// re-materialize the untouched current tip — mirrors
    /// [`rebase_abort`][Repo::rebase_abort]'s shape exactly, including its
    /// deletion-baseline fix: pass the pick's `PICK_DECIDED_ROOT` (the tree
    /// the working tree actually, currently reflects — a conflicted pick may
    /// have materialized theirs-side-only files onto disk) as `old_root`, so
    /// the deletion pass drops them. Falls back to a full clean materialize
    /// (`old_root = None`) only for residue where the decided root is
    /// unexpectedly absent (older pick state). No oplog record — no ref ever
    /// moved, so abort is its own inverse; nothing to undo. Errors
    /// [`Error::InvalidArgument`] if no cherry-pick is in progress.
    ///
    /// Returns the protected paths that could not be restored (P21): no
    /// identity is available at abort time, so protected files in the
    /// restored tree are skipped (left absent) rather than decrypted —
    /// mirrors [`crate::repo::Repo::merge_abort`]'s contract exactly.
    pub fn cherry_pick_abort(&self) -> Result<Vec<String>> {
        if !crate::pick_state::in_progress(&self.layout) {
            return Err(Error::InvalidArgument(
                "no cherry-pick in progress — nothing to abort".into(),
            ));
        }
        for path in crate::pick_state::read_conflicts(&self.layout)? {
            let _ = std::fs::remove_file(self.layout.root.join(format!("{path}.theirs")));
        }
        let decided = crate::pick_state::read_decided_root(&self.layout)?;
        let ours_tip = self.head_tip()?;
        let mut skipped = Vec::new();
        if let Some(tip) = ours_tip {
            let snap = self.snapshot(&tip)?;
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let mut cache = self.open_protected_cache()?;
            skipped = worktree::materialize(
                &self.layout,
                &mut store,
                snap.root,
                decided,
                &snap.protection,
                None,
                &self.sparse_spec()?,
                Some(&mut cache),
            )?;
            cache.save()?;
        }
        crate::pick_state::clear(&self.layout)?;
        Ok(skipped)
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
    /// commit is replayed.
    ///
    /// **Resumable (P19/ADR-0029, new default):** the first conflicting
    /// commit STOPS the fold rather than aborting it — its progress is
    /// persisted (`rebase_state`) and P4-style conflict markers are written
    /// to the working tree (mirroring `cherry_pick`'s Conflicts arm), but
    /// the branch ref does NOT move ([`RebaseResult::Stopped`]). Resolve the
    /// markers and call [`rebase_continue`][Repo::rebase_continue] to land
    /// the resolved commit and keep folding (stopping again on the next
    /// conflict, as many times as needed), or
    /// [`rebase_abort`][Repo::rebase_abort] to abandon and restore the
    /// pre-rebase tree untouched. An identity/authorization failure (as
    /// opposed to a plain conflict) still aborts the WHOLE rebase atomically
    /// — nothing outside the CAS has been written when it fires, so refs and
    /// the working tree stay byte-identical; only a real `Conflicts` outcome
    /// stops. The fold and its completion tail are shared with
    /// `rebase_continue` via `rebase_fold_and_finish`, which is what makes a
    /// rebase that stops N times still collapse into ONE oplog record (its
    /// `before` is always the ORIGINAL pre-rebase tip) and ONE `sc undo`.
    /// Same crash discipline as `cherry_pick`'s clean path on completion:
    /// snapshots land in the CAS, then the working tree is materialized,
    /// then the branch ref is moved (the atomic commit point).
    ///
    /// Protected paths (P15 Task 8) resolve per replayed commit exactly like
    /// [`cherry_pick`][Repo::cherry_pick]'s: ciphertext-id fast paths need no
    /// `identity`; a protected path that diverged in content on both sides
    /// needs one. The fold threads the ACCUMULATED protection — each clean
    /// replay's assembled protection (union rules, carry ∪ fresh wraps)
    /// becomes both the new snapshot's policy and the onto-side policy for
    /// the next commit in the range, so a file freshly encrypted by an
    /// earlier replay keeps its wraps through the rest of the fold. The
    /// final (and ff fast-path) materialize decrypts for `identity` where
    /// possible and skips the rest — never writes ciphertext to disk.
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
        if crate::rebase_state::in_progress(&self.layout) {
            return Err(Error::RebaseInProgress);
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
        let ours_root = self.snapshot(&ours_tip)?.root;

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
                let mut cache = self.open_protected_cache()?;
                worktree::materialize(
                    &self.layout,
                    &mut store,
                    target_root,
                    Some(ours_root),
                    &target_protection,
                    identity,
                    &self.sparse_spec()?,
                    Some(&mut cache),
                )?;
                cache.save()?;
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
                    // Rebase-specific contextualization (P19 review fix):
                    // rebase replays a whole linear range, so there is no
                    // single "relative to which parent" choice to offer —
                    // unlike cherry-pick's per-commit `--mainline`, the fix
                    // here is to linearize the range or drop the merge.
                    return Err(Error::CannotReplayMerge(
                        cur,
                        format!(
                            "rebase cannot replay merge commit {cur}; linearize or drop it first"
                        ),
                    ));
                }
                range.push(cur);
                cur = snap
                    .parents
                    .first()
                    .copied()
                    .ok_or(Error::NoCommonAncestor)?;
            }
        }
        range.reverse();
        let total = range.len();

        self.rebase_fold_and_finish(
            head,
            ours_tip,
            target,
            target_tip,
            range,
            total,
            author,
            identity,
            (0, 0),
        )
    }

    /// Shared fold + completion tail for [`rebase`][Repo::rebase] and
    /// [`rebase_continue`][Repo::rebase_continue] (P19 Task 2): replay
    /// `range` (oldest first) onto `acc_tip`, landing each clean/empty/
    /// registry-only commit as a snapshot and advancing the in-memory
    /// accumulator exactly like `rebase`'s original single-shot fold. The
    /// first `ReplayOutcome::Conflicts` persists the fold's progress
    /// (`rebase_state::write`, `write_conflicts`, `write_decided_root`) and
    /// materializes P4-style conflict markers into the working tree —
    /// reusing `cherry_pick`'s Conflicts-arm discipline verbatim, pointed at
    /// the rebase state files — WITHOUT moving the branch ref
    /// (`RebaseResult::Stopped`). Reaching the end of `range` cleanly
    /// materializes the final tree, moves the branch ref exactly once, and
    /// records ONE oplog entry whose `before` is `original_tip` — NOT the
    /// current ref value — which is what makes a rebase that stops any
    /// number of times still collapse into a single undo-able operation.
    ///
    /// `disk_root` (what the working tree actually, currently, contains) is
    /// derived rather than threaded as its own parameter: `range.len() ==
    /// total` means this is `rebase`'s first pass, where nothing has been
    /// materialized yet and disk still shows `original_tip`'s tree;
    /// otherwise this is a resumed fold, where disk already reflects the
    /// just-completed accumulator (`acc_tip`'s tree) because
    /// `assemble_completion_snapshot` only READS the user's resolution off
    /// disk, it never writes to it.
    fn rebase_fold_and_finish(
        &self,
        head: String,
        original_tip: ObjectId,
        target: &str,
        acc_tip: ObjectId,
        range: Vec<ObjectId>,
        total: usize,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
        counters_seed: (usize, usize),
    ) -> Result<RebaseResult> {
        let original_root = self.snapshot(&original_tip)?.root;
        let acc_snap = self.snapshot(&acc_tip)?;
        let disk_root = if range.len() == total {
            original_root
        } else {
            acc_snap.root
        };

        let mut acc_tip = acc_tip;
        let mut acc_root = acc_snap.root;
        let mut acc_protection = acc_snap.protection;
        let mut acc_secrets = acc_snap.secrets;
        // Seeded from the rebase's cumulative counts so far (0,0 on the
        // first pass; the persisted `RebaseState.replayed`/`.skipped` — plus
        // the just-completed conflicted commit, see `rebase_continue` — on a
        // resumed fold), so a rebase that stops N times still reports ONE
        // cumulative "M replayed, K skipped" at final completion instead of
        // resetting to the last segment's counts.
        let mut replayed = counters_seed.0;
        let mut skipped = counters_seed.1;
        let mut remaining: std::collections::VecDeque<ObjectId> = range.into();

        while let Some(commit) = remaining.pop_front() {
            let commit_snap = self.snapshot(&commit)?;
            // `base_override: None` — the pre-scan above already refused any
            // merge commit in the replayed range, so this is always a
            // first-parent-base replay (no mainline selection applies).
            let merged_secrets = merged_registry_for_replay(
                self,
                &commit_snap.parents,
                &commit_snap.secrets,
                &acc_secrets,
                None,
            )?;
            let secrets_changed = merged_secrets != acc_secrets;
            // A rebase spans a range, so an identity/authorization abort must
            // name WHICH replay tripped, not just the path. Nothing outside
            // the CAS has been written when these fire, so the abort leaves
            // refs and the working tree byte-identical — unlike a real
            // `Conflicts` outcome below, an identity failure still aborts
            // the WHOLE rebase rather than stopping it.
            let outcome = replay_commit(self, commit, (acc_root, &acc_protection), identity, None)
                .map_err(|e| match e {
                    Error::ProtectedMergeNeedsIdentity(path) => Error::ProtectedMergeNeedsIdentity(
                        format!("{path} (replaying commit {})", commit.short()),
                    ),
                    Error::NotAuthorized(path) => Error::NotAuthorized(format!(
                        "{path} (replaying commit {})",
                        commit.short()
                    )),
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
                ReplayOutcome::Conflicts {
                    files,
                    sidecars,
                    paths,
                } => {
                    // Stop, don't abort (P19/ADR-0029): persist the fold's
                    // progress and put P4 markers in the working tree. The
                    // branch ref does NOT move — the atomic commit point
                    // stays at final completion. This is the same
                    // materialize discipline as `cherry_pick`'s Conflicts
                    // arm (union rules = everything accumulated so far ∪
                    // this commit's own; carried ciphertext + plain content
                    // through the CAS-safe tree, needs_encrypt plaintext
                    // written straight to disk, never through the CAS).
                    let union_prefixes = crate::protect::merge_prefixes(
                        &acc_protection.prefixes,
                        &commit_snap.protection.prefixes,
                    );
                    let union_prot = scl_core::Protection {
                        prefixes: union_prefixes.clone(),
                        wrapped: Default::default(),
                    };
                    let (carried, to_encrypt) = split_for_encryption(&files, &union_prot)?;
                    let mut wrapped = acc_protection.wrapped.clone();
                    for (id, wks) in &commit_snap.protection.wrapped {
                        let entry = wrapped.entry(*id).or_default();
                        *entry = crate::protect::union_wraps(entry, wks);
                    }
                    let conflict_prot = scl_core::Protection {
                        prefixes: union_prefixes,
                        wrapped,
                    };
                    let conflict_root = self.materialize_conflict_state(
                        &carried,
                        &to_encrypt,
                        &sidecars,
                        &conflict_prot,
                        disk_root,
                        identity,
                        &paths,
                    )?;
                    let remaining_after_current: Vec<ObjectId> = remaining.into_iter().collect();
                    let done = total
                        .saturating_sub(remaining_after_current.len())
                        .saturating_sub(1);
                    // Decided root, then conflicts, then REBASE_STATE last —
                    // REBASE_STATE is the in_progress signal (mirrors
                    // pick_state/merge_state crash discipline: a crash
                    // between these writes must leave no announced rebase).
                    crate::rebase_state::write_decided_root(&self.layout, conflict_root)?;
                    crate::rebase_state::write_conflicts(&self.layout, &paths)?;
                    crate::rebase_state::write(
                        &self.layout,
                        &crate::rebase_state::RebaseState {
                            branch: head.clone(),
                            original_tip,
                            target: target.to_string(),
                            acc_tip,
                            conflicted: commit,
                            remaining: remaining_after_current,
                            total,
                            author: author.to_string(),
                            resolved: false,
                            replayed,
                            skipped,
                        },
                    )?;
                    return Ok(RebaseResult::Stopped {
                        conflicted: commit,
                        paths,
                        done,
                        total,
                    });
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
            let mut cache = self.open_protected_cache()?;
            worktree::materialize(
                &self.layout,
                &mut store,
                acc_root,
                Some(disk_root),
                &acc_protection,
                identity,
                &self.sparse_spec()?,
                Some(&mut cache),
            )?;
            cache.save()?;
        }
        refs::write_branch_tip(&self.layout, &head, &acc_tip)?;
        crate::oplog::record(
            &self.layout,
            &format!("rebase onto {target} ({replayed} replayed, {skipped} skipped)"),
            &head,
            &head,
            &[(head.clone(), Some(original_tip), Some(acc_tip))],
        )?;
        // Clear any resumable-rebase state here, at the completion tail, NOT
        // up front in `rebase_continue` (P19 review fix): this is the point
        // where the operation is actually done — the ref has moved and the
        // oplog record is written. A no-op (removes nothing) on `rebase`'s
        // own first pass, where no state exists yet.
        //
        // Crash-window discipline (P21): the three writes above/below are
        // ordered ref-write -> oplog -> state-clear, same as `cherry_pick`'s
        // clean-completion tail. A crash between the ref write and the oplog
        // record is invisible to `--continue`/`--abort` (both key off
        // `REBASE_STATE`, still present) and simply re-lands on the next
        // `--continue` attempt with the branch already at `acc_tip` — a
        // harmless idempotent re-write, since `write_branch_tip` is a plain
        // overwrite. A crash between the oplog record and this clear leaves
        // `REBASE_STATE` present with `resolved` state that DID land (the ref
        // already moved to the final `acc_tip`): the next `--continue` sees
        // `remaining` empty, so `assemble_completion_snapshot`/the fold below
        // are no-ops over an empty range, and this same tail runs again,
        // producing a SECOND oplog record for a no-op operation. That
        // duplicate is recoverable (both records describe the same before ->
        // after transition; `sc undo` of the second is a no-op ref-write,
        // `sc undo` again reaches the real undo point) rather than corrupting
        // state — documented here rather than closed, matching this
        // function's existing crash-discipline comments elsewhere.
        crate::rebase_state::clear(&self.layout)?;
        Ok(RebaseResult::Rebased {
            new_tip: acc_tip,
            replayed,
            skipped,
        })
    }

    /// Resume a rebase [`rebase`][Repo::rebase] stopped on conflict: complete
    /// the conflicted commit from the resolved working tree (single
    /// completion parent = the fold's `acc_tip`, via the same extracted
    /// pick-completion assembly `commit` uses for a resolved pick —
    /// `assemble_completion_snapshot`), then keep folding the remaining
    /// commits via `rebase_fold_and_finish` — stopping again on the next
    /// conflict (`RebaseResult::Stopped`, as many times as needed) or
    /// completing (`RebaseResult::Rebased`, moving the branch ref once and
    /// recording ONE oplog entry whose `before` is the rebase's original
    /// pre-rebase tip, no matter how many stops preceded it).
    ///
    /// **Error-recoverable and idempotent (P19 review fix):** state is only
    /// cleared by the fold's OWN completion tail (full `Rebased`) or
    /// overwritten by its next stop (`Stopped`) — never up front here. If the
    /// resumed fold errors on a LATER commit in `remaining` (a typed
    /// `ProtectedMergeNeedsIdentity`/`NotAuthorized`/`SecretMergeConflict`,
    /// e.g. `--continue` was called without `--identity`), the rebase is
    /// still in progress afterward: the user can retry `--continue` with the
    /// right identity, or `--abort`. Retrying must not re-complete `conflicted`
    /// a second time — `RebaseState::resolved` tracks whether that step
    /// already ran: once `assemble_completion_snapshot` succeeds, state is
    /// immediately rewritten with `acc_tip` advanced and `resolved = true`
    /// BEFORE the fold is attempted, so a retry after a fold error sees
    /// `resolved == true` and skips straight to the fold using the
    /// already-advanced `acc_tip`.
    ///
    /// Errors [`Error::InvalidArgument`] if no rebase is in progress, or if
    /// `st.branch`'s tip no longer matches `st.original_tip` (P19
    /// final-review fix I1: an unguarded op such as `sc secret add` or `sc
    /// protect` moved the branch while the rebase was stopped — completing
    /// would force-write over that commit). Rebase state is left untouched
    /// in that case, so `--abort` still works.
    pub fn rebase_continue(
        &self,
        author: &str,
        identity: Option<&scl_crypto::SecretKey>,
    ) -> Result<RebaseResult> {
        let Some(st) = crate::rebase_state::read(&self.layout)? else {
            return Err(Error::InvalidArgument(
                "no rebase in progress — nothing to continue".into(),
            ));
        };
        // P19 final-review fix (I1): `sc secret add`/`sc protect`/friends have
        // no in-progress guards of their own and can move `st.branch`'s tip
        // while the rebase is stopped. The fold below force-writes `acc_tip`
        // over whatever the ref currently is, which would silently discard
        // any such intervening commit. Refuse up front instead — state is
        // untouched, so `--abort` still works, and the user can re-run the
        // rebase after inspecting what moved the branch.
        let current_tip = refs::read_branch_tip(&self.layout, &st.branch)?;
        if current_tip != Some(st.original_tip) {
            let current_hex = current_tip.map(|id| id.to_hex()[..8].to_string());
            return Err(Error::InvalidArgument(format!(
                "the branch moved while the rebase was stopped (tip {} != {}); \
                 `sc rebase --abort` and re-run the rebase",
                current_hex.as_deref().unwrap_or("<unborn>"),
                &st.original_tip.to_hex()[..8],
            )));
        }
        let (new_tip, counters_seed) = if st.resolved {
            // A previous `--continue` already completed `st.conflicted` into
            // `st.acc_tip` but the resumed fold errored before finishing (or
            // stopping on a new conflict, which would have overwritten this
            // state already). Re-running `assemble_completion_snapshot` here
            // would double-apply the resolved commit — skip straight to the
            // fold. `st.replayed`/`.skipped` already counted `st.conflicted`
            // (the write below, on the ORIGINAL `--continue` attempt that set
            // `resolved = true`, incremented `replayed` for it) — no further
            // adjustment needed.
            (st.acc_tip, (st.replayed, st.skipped))
        } else {
            let decided = crate::rebase_state::read_decided_root(&self.layout)?;
            let completed_msg = self.snapshot(&st.conflicted)?.message;
            // `pick_registry_base: None` — a rebase fold has no `--mainline`
            // concept (its replayed commits are single-parent by
            // construction; `rebase` refuses up front if a merge commit is
            // in the replayed range), so the registry base is always the
            // conflicted commit's own first parent.
            let new_tip = self.assemble_completion_snapshot(
                st.acc_tip,
                st.conflicted,
                decided,
                None,
                author,
                &completed_msg,
            )?;
            // Clean up this conflict's ".theirs" sidecars (mirrors
            // `merge_abort`'s cleanup): once resolved, they're pure
            // working-tree litter — never part of the tracked tree, so
            // `materialize` never touches them itself.
            for path in crate::rebase_state::read_conflicts(&self.layout)? {
                let _ = std::fs::remove_file(self.layout.root.join(format!("{path}.theirs")));
            }
            // Advance state BEFORE attempting the fold, so an error from the
            // fold below (on a later commit) leaves a retryable, idempotent
            // `--continue` rather than losing resumability. `rebase_abort`
            // reads `decided_root`/`conflicted`/`remaining` from this same
            // state, all still valid: `conflicted` is now purely historical
            // (its completion already landed in `acc_tip`) and `--abort`
            // restores to `original_tip` regardless. Completing `conflicted`
            // lands it as a new snapshot, so it counts toward the cumulative
            // `replayed` total — incremented here, once, at the same moment
            // `resolved` flips true, so a later retry (which skips straight
            // to the fold above) reads the already-incremented value instead
            // of double-counting it.
            let replayed = st.replayed + 1;
            crate::rebase_state::write(
                &self.layout,
                &crate::rebase_state::RebaseState {
                    acc_tip: new_tip,
                    resolved: true,
                    replayed,
                    ..st.clone()
                },
            )?;
            (new_tip, (replayed, st.skipped))
        };
        self.rebase_fold_and_finish(
            st.branch,
            st.original_tip,
            &st.target,
            new_tip,
            st.remaining,
            st.total,
            author,
            identity,
            counters_seed,
        )
    }

    /// Abandon a rebase stopped on conflict: clear the rebase state and
    /// re-materialize the untouched original tip — no oplog record, since no
    /// ref ever moved. Errors [`Error::InvalidArgument`] if no rebase is in
    /// progress.
    ///
    /// Returns the protected paths that could not be restored (P21): no
    /// identity is available at abort time, so protected files in the
    /// restored tree are skipped (left absent) rather than decrypted —
    /// mirrors [`crate::repo::Repo::merge_abort`]'s contract exactly.
    pub fn rebase_abort(&self) -> Result<Vec<String>> {
        let Some(st) = crate::rebase_state::read(&self.layout)? else {
            return Err(Error::InvalidArgument(
                "no rebase in progress — nothing to abort".into(),
            ));
        };
        for path in crate::rebase_state::read_conflicts(&self.layout)? {
            let _ = std::fs::remove_file(self.layout.root.join(format!("{path}.theirs")));
        }
        // The stop's own conflict-materialize wrote `REBASE_DECIDED_ROOT`
        // (`conflict_root` in `rebase_fold_and_finish`'s Conflicts arm) to
        // disk as the tree the working tree currently, actually reflects —
        // pass it as `old_root` so the deletion pass drops files the stop
        // pulled in from the target side (e.g. a target-only new file) that
        // `original_tip` never had (P19 review fix, mirrors `merge_abort`'s
        // `theirs_root`-as-`old_root` pattern in `crates/repo/src/repo.rs`).
        // Falls back to `None` (full clean materialize) only for residue
        // where the decided root is unexpectedly absent.
        let decided = crate::rebase_state::read_decided_root(&self.layout)?;
        let snap = self.snapshot(&st.original_tip)?;
        let skipped = {
            let store_arc = self.vfs().store();
            let mut store = store_arc.lock().unwrap();
            let mut cache = self.open_protected_cache()?;
            let skipped = worktree::materialize(
                &self.layout,
                &mut store,
                snap.root,
                decided,
                &snap.protection,
                None,
                &self.sparse_spec()?,
                Some(&mut cache),
            )?;
            cache.save()?;
            skipped
        };
        crate::rebase_state::clear(&self.layout)?;
        Ok(skipped)
    }
}

/// Outcome of [`Repo::rebase`] / [`Repo::rebase_continue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebaseResult {
    /// Target already reachable from the current tip — nothing to do.
    AlreadyUpToDate,
    /// Current tip was an ancestor of target — ref fast-forwarded.
    FastForwarded(ObjectId),
    /// Commits replayed; branch now points at the last new snapshot.
    Rebased {
        new_tip: ObjectId,
        replayed: usize,
        skipped: usize,
    },
    /// The fold stopped on a conflicting commit (P19, new default): its
    /// progress is persisted and P4-style markers are on disk, but the
    /// branch ref has NOT moved. Resolve the markers then
    /// `sc rebase --continue`, or `sc rebase --abort`. `done`/`total` are
    /// "k of n" over the ORIGINAL replay range (not just this fold segment).
    Stopped {
        conflicted: ObjectId,
        paths: Vec<String>,
        done: usize,
        total: usize,
    },
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
        let outcome = replay_commit(
            &repo,
            b_tip,
            (onto_snap.root, &onto_snap.protection),
            None,
            None,
        )
        .unwrap();
        match outcome {
            ReplayOutcome::Clean {
                root: merged_root, ..
            } => {
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
        let outcome = replay_commit(
            &repo,
            b_tip,
            (onto_snap.root, &onto_snap.protection),
            None,
            None,
        )
        .unwrap();
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
        let outcome = replay_commit(
            &repo,
            b_tip,
            (onto_snap.root, &onto_snap.protection),
            None,
            None,
        )
        .unwrap();
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
            let outcome = replay_commit(
                &repo_b,
                copied_commit,
                (onto_snap.root, &onto_snap.protection),
                None,
                None,
            )
            .unwrap();
            match outcome {
                ReplayOutcome::Clean {
                    root: merged_root, ..
                } => {
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
        let err = replay_commit(
            &repo,
            merged,
            (onto_snap.root, &onto_snap.protection),
            None,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::CannotReplayMerge(id, _) if id == merged),
            "got {err:?}"
        );
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

        let outcome = repo.cherry_pick("work-1", "me", None, None).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked, got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(id));

        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![old_main_tip]);
        assert!(
            snap.message
                .ends_with(&format!("(cherry-picked from {})", picked.short())),
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

        let err = repo.cherry_pick("work-1", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(main_tip),
            "main tip must not move"
        );
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

    // ---- P19 Task 4: cherry-pick --abort and --mainline ----

    #[test]
    fn cherry_pick_abort_restores_pre_pick_tree() {
        // work (theirs) both conflicts with main on x.txt AND adds a brand-new
        // file (new.txt) — the pick's conflict-materialize pulls that
        // theirs-only file onto disk (mirrors rebase_abort's
        // target-only-file review finding). --abort must drop it, not leave
        // it as untracked residue the next commit would silently absorb.
        let root = tmp_root("cp-abort");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        std::fs::write(root.join("stable.txt"), b"stable\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();
        let main_tip = repo.head_tip().unwrap().unwrap();

        repo.switch("work").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        std::fs::write(root.join("new.txt"), b"from-work\n").unwrap();
        repo.commit("me", "work edits x, adds new.txt").unwrap();
        repo.switch("main").unwrap();
        assert_eq!(repo.head_tip().unwrap(), Some(main_tip));

        let before_x = std::fs::read(root.join("x.txt")).unwrap();
        let before_stable = std::fs::read(root.join("stable.txt")).unwrap();
        let ops_before = repo.oplog().unwrap().len();

        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert!(
            root.join("new.txt").exists(),
            "the pick's conflict-materialize must pull in work's new.txt"
        );

        // Dirty the tree further beyond the markers/pulled-in file themselves.
        std::fs::write(root.join("x.txt"), b"garbage\n").unwrap();
        std::fs::write(root.join("stable.txt"), b"also garbage\n").unwrap();

        repo.cherry_pick_abort().unwrap();

        assert!(!repo.pick_in_progress(), "state cleared");
        assert_eq!(repo.pick_head().unwrap(), None);
        assert_eq!(repo.pick_conflicts().unwrap(), Vec::<String>::new());
        assert_eq!(
            crate::pick_state::read_decided_root(&repo.layout).unwrap(),
            None,
            "PICK_DECIDED_ROOT cleared"
        );
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(main_tip),
            "branch tip unchanged"
        );
        assert_eq!(
            std::fs::read(root.join("x.txt")).unwrap(),
            before_x,
            "x.txt byte-identical"
        );
        assert_eq!(
            std::fs::read(root.join("stable.txt")).unwrap(),
            before_stable,
            "stable.txt byte-identical"
        );
        assert!(
            !root.join("new.txt").exists(),
            "abort must drop the pick-materialized theirs-only file"
        );
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no oplog record from abort"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cherry_pick_abort_without_pick_errors() {
        let root = tmp_root("cp-abort-no-state");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();

        let err = repo.cherry_pick_abort().unwrap_err();
        match err {
            Error::InvalidArgument(msg) => {
                assert!(msg.contains("no cherry-pick in progress"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn mainline_pick_applies_delta_relative_to_chosen_parent() {
        // M = merge of a-side (adds a.txt) and b-side (adds b.txt), so
        // M.parents == [a_tip, b_tip] (`Repo::merge`'s `[ours, theirs]`
        // convention). target1/target2 are fresh branches at a_tip.
        let root = tmp_root("cp-mainline");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();

        repo.branch("a-side").unwrap();
        repo.branch("b-side").unwrap();

        repo.switch("a-side").unwrap();
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        repo.commit("me", "a-side adds a.txt").unwrap();
        let a_tip = repo.head_tip().unwrap().unwrap();
        repo.branch("target1").unwrap();
        repo.branch("target2").unwrap();

        repo.switch("b-side").unwrap();
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "b-side adds b.txt").unwrap();
        let b_tip = repo.head_tip().unwrap().unwrap();

        repo.switch("a-side").unwrap();
        let m = repo.merge("b-side", "me").unwrap();
        let m_snap = repo.snapshot(&m).unwrap();
        assert_eq!(m_snap.parents, vec![a_tip, b_tip]);

        // --mainline 1: base = parents[0] (a-side) → the delta is b-side's
        // addition. Onto a fresh a-side branch (already has a.txt), the pick
        // lands b.txt.
        repo.switch("target1").unwrap();
        let outcome = repo.cherry_pick("a-side", "me", None, Some(1)).unwrap();
        assert!(matches!(outcome, PickResult::Picked(_)), "got {outcome:?}");
        assert!(
            root.join("b.txt").exists(),
            "mainline 1 lands b-side's addition"
        );
        assert!(root.join("a.txt").exists());

        // --mainline 2: base = parents[1] (b-side) → the delta is a-side's
        // addition. Onto a fresh a-side branch (already has a.txt and lacks
        // b.txt), nothing new lands — already applied.
        repo.switch("target2").unwrap();
        let outcome = repo.cherry_pick("a-side", "me", None, Some(2)).unwrap();
        assert!(
            matches!(outcome, PickResult::AlreadyApplied),
            "got {outcome:?}"
        );
        assert!(root.join("a.txt").exists());
        assert!(
            !root.join("b.txt").exists(),
            "mainline 2 excludes b-side's addition"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn mainline_validation() {
        let root = tmp_root("cp-mainline-validation");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();

        repo.branch("a-side").unwrap();
        repo.branch("b-side").unwrap();

        repo.switch("a-side").unwrap();
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        repo.commit("me", "a-side adds a.txt").unwrap();
        // "target" points at a-side's single-parent tip, BEFORE the merge
        // below advances a-side to the two-parent merge commit — used to
        // exercise the non-merge --mainline case.
        repo.branch("target").unwrap();

        repo.switch("b-side").unwrap();
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "b-side adds b.txt").unwrap();

        repo.switch("a-side").unwrap();
        repo.merge("b-side", "me").unwrap();
        // a-side now points at the 2-parent merge commit.

        // A merge without --mainline is refused, and the error names the flag.
        repo.switch("target").unwrap();
        let err = repo.cherry_pick("a-side", "me", None, None).unwrap_err();
        match err {
            Error::CannotReplayMerge(_, _) => {
                assert!(err.to_string().contains("--mainline"), "got: {err}");
            }
            other => panic!("expected CannotReplayMerge, got {other:?}"),
        }

        // --mainline 3 on a 2-parent merge is out of range.
        let err = repo.cherry_pick("a-side", "me", None, Some(3)).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

        // --mainline on a non-merge commit (target's own single-parent tip,
        // picked from b-side) is refused.
        repo.switch("b-side").unwrap();
        let err = repo.cherry_pick("target", "me", None, Some(1)).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => {
                assert!(msg.contains("--mainline"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// P19 review fix: a mainline pick's secret-registry three-way must base
    /// off the SAME chosen parent as the file three-way, not always the
    /// picked commit's first parent. M = merge(a_tip, b_tip) where ONLY
    /// b-side added SECRET_X, so M.parents == [a_tip, b_tip] and relative to
    /// b_tip (mainline 2) the secret delta is empty — landing that pick on a
    /// target that lacks SECRET_X must NOT introduce it. Before the fix, the
    /// registry base was unconditionally `commit_parents.first()` (a_tip,
    /// which lacks the secret), so `merge_secrets` saw onto==base (both
    /// missing) and resolved to theirs (M, which has it) — a spurious add.
    /// Mainline 1 (base = a_tip, correct even before the fix) is asserted
    /// too so the pair pins both the fixed direction and the still-working
    /// one.
    #[test]
    fn mainline_pick_registry_bases_off_chosen_parent() {
        let root = tmp_root("cp-mainline-registry");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("base.txt"), b"base\n").unwrap();
        repo.commit("me", "base").unwrap();

        repo.branch("a-side").unwrap();
        repo.branch("b-side").unwrap();

        repo.switch("a-side").unwrap();
        std::fs::write(root.join("a.txt"), b"a\n").unwrap();
        repo.commit("me", "a-side adds a.txt").unwrap();
        let a_tip = repo.head_tip().unwrap().unwrap();
        // Both mainline targets are branched here, at a_tip — BEFORE b-side
        // adds its secret below — so neither target starts with SECRET_X in
        // its registry (mirrors `mainline_pick_applies_delta_relative_to_
        // chosen_parent`'s target1/target2 setup).
        repo.branch("target-m1").unwrap();
        repo.branch("target-m2").unwrap();

        repo.switch("b-side").unwrap();
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "b-side adds b.txt").unwrap();
        // A second, registry-only commit on b-side adds the secret —
        // `secret_add` commits against HEAD's existing tree, it does not
        // pick up uncommitted working-tree changes.
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("SECRET_X", b"v1", &[pk]).unwrap();
        let b_tip = repo.head_tip().unwrap().unwrap();
        assert!(repo
            .snapshot(&b_tip)
            .unwrap()
            .secrets
            .contains_key("SECRET_X"));

        repo.switch("a-side").unwrap();
        let m = repo.merge("b-side", "me").unwrap();
        let m_snap = repo.snapshot(&m).unwrap();
        assert_eq!(m_snap.parents, vec![a_tip, b_tip]);
        assert!(
            m_snap.secrets.contains_key("SECRET_X"),
            "merge carries the secret forward"
        );

        // --mainline 2: base = b_tip, which ALREADY has SECRET_X — the
        // delta relative to it is empty, so picking onto a target that
        // lacks the secret must not add it.
        repo.switch("target-m2").unwrap();
        repo.cherry_pick("a-side", "me", None, Some(2)).unwrap();
        let tip2 = repo.head_tip().unwrap().unwrap();
        assert!(
            !repo
                .snapshot(&tip2)
                .unwrap()
                .secrets
                .contains_key("SECRET_X"),
            "mainline 2's base (b_tip) already has SECRET_X, so no delta should land it"
        );

        // --mainline 1: base = a_tip, which lacks SECRET_X — the delta
        // relative to it is "add SECRET_X", so it DOES land on the target.
        repo.switch("target-m1").unwrap();
        repo.cherry_pick("a-side", "me", None, Some(1)).unwrap();
        let tip1 = repo.head_tip().unwrap().unwrap();
        assert!(
            repo.snapshot(&tip1)
                .unwrap()
                .secrets
                .contains_key("SECRET_X"),
            "mainline 1's base (a_tip) lacks SECRET_X, so the delta adds it"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// P19 final-review fix I2: a CONFLICTED mainline pick's completion must
    /// also base its secret-registry three-way on the SAME chosen parent as
    /// the (already-persisted) decided file tree — not silently fall back to
    /// the picked commit's first parent, which is exactly the T4 bug class
    /// `mainline_pick_registry_bases_off_chosen_parent` closed for the CLEAN
    /// path. Same M = merge(a_tip, b_tip) shape as that test (only b-side
    /// adds SECRET_X), but target-m2 also independently edits x.txt so the
    /// mainline-2 delta (b_tip -> M) conflicts with target's own edit,
    /// forcing `PickConflicts` and a completing `sc commit` instead of a
    /// clean pick. Mainline 2's base (b_tip) already has SECRET_X, so — as
    /// in the clean-path test — completing on a target that lacks it must
    /// NOT introduce it. Before the fix (pick_state not persisting the
    /// mainline selection), completion would base the registry off a_tip
    /// (which lacks SECRET_X), reading the secret as newly added and landing
    /// it on the target — a spurious add this test would catch.
    #[test]
    fn conflicted_mainline_pick_completion_bases_registry_off_chosen_parent() {
        let root = tmp_root("cp-mainline-conflict-registry");
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
        // (b_tip -> M, "x\n" -> "a-edit\n") conflicts with it.
        repo.switch("target-m2").unwrap();
        std::fs::write(root.join("x.txt"), b"target-edit\n").unwrap();
        repo.commit("me", "target independently edits x.txt")
            .unwrap();

        repo.switch("b-side").unwrap();
        std::fs::write(root.join("b.txt"), b"b\n").unwrap();
        repo.commit("me", "b-side adds b.txt").unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        repo.secret_add("SECRET_X", b"v1", &[pk]).unwrap();
        let b_tip = repo.head_tip().unwrap().unwrap();
        assert!(repo
            .snapshot(&b_tip)
            .unwrap()
            .secrets
            .contains_key("SECRET_X"));

        repo.switch("a-side").unwrap();
        let m = repo.merge("b-side", "me").unwrap();
        let m_snap = repo.snapshot(&m).unwrap();
        assert_eq!(m_snap.parents, vec![a_tip, b_tip]);
        assert!(
            m_snap.secrets.contains_key("SECRET_X"),
            "merge carries the secret forward"
        );

        // --mainline 2 onto target-m2: conflicts on x.txt (forced above).
        repo.switch("target-m2").unwrap();
        let err = repo.cherry_pick("a-side", "me", None, Some(2)).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        let on_disk = std::fs::read_to_string(root.join("x.txt")).unwrap();
        assert!(on_disk.contains("<<<<<<<"), "got: {on_disk}");

        // Resolve and complete via `sc commit`.
        std::fs::write(root.join("x.txt"), b"resolved\n").unwrap();
        let resolved = repo.commit("me", "resolve mainline-2 conflict").unwrap();
        assert!(!repo.pick_in_progress());

        let resolved_snap = repo.snapshot(&resolved).unwrap();
        assert!(
            !resolved_snap.secrets.contains_key("SECRET_X"),
            "mainline 2's base (b_tip) already has SECRET_X, so the conflicted \
             pick's completion must not spuriously add it (T4 bug class)"
        );

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

        let outcome = repo.cherry_pick("work-1", "me", None, None).unwrap();
        assert!(
            matches!(outcome, PickResult::AlreadyApplied),
            "got {outcome:?}"
        );
        assert_eq!(repo.head_tip().unwrap(), Some(merged), "tip must not move");
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no new oplog record"
        );

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
        let err = repo.cherry_pick("work-1", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();

        // Merge in progress.
        let ours_tip = repo.head_tip().unwrap().unwrap();
        crate::merge_state::write(&repo.layout, &ours_tip, &[], None).unwrap();
        let err = repo.cherry_pick("work-1", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        crate::merge_state::clear(&repo.layout).unwrap();

        // Pick in progress.
        crate::pick_state::write(&repo.layout, &ours_tip, &[], None, None).unwrap();
        let err = repo.cherry_pick("work-1", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickInProgress), "got {err:?}");
        crate::pick_state::clear(&repo.layout).unwrap();

        // Unknown ref.
        let err = repo
            .cherry_pick("no-such-branch", "me", None, None)
            .unwrap_err();
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
        let err = repo.cherry_pick("work-1", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::MergeInProgress), "got {err:?}");
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(ours_tip),
            "tip must not move"
        );

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
        let outcome = repo.cherry_pick("work", "me", None, None).unwrap();
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
        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
        assert!(
            matches!(err, Error::ProtectedMergeNeedsIdentity(ref p) if p == "secret/a.txt"),
            "got {err:?}"
        );
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(main_tip),
            "tip must not move"
        );
        assert!(
            !repo.pick_in_progress(),
            "no pick state on the identity refusal"
        );

        // With identity: clean pick, merged content re-encrypted.
        let outcome = repo
            .cherry_pick("work", "me", Some(&alice_sk), None)
            .unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked, got {other:?}"),
        };
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);
        let (blob_id, perms) = tree_entry(&repo, &id, "secret/a.txt");
        assert_ne!(perms & scl_core::PROTECTED, 0, "PROTECTED preserved");
        let bytes = blob_bytes_of(&repo, &blob_id);
        assert!(
            !bytes.windows(4).any(|w| w == b"OURS"),
            "plaintext leaked into the CAS blob"
        );
        for (who, sk) in [("alice", &alice_sk), ("bob", &bob_sk)] {
            let pt = crate::protect::decrypt_with(
                &bytes,
                &blob_id,
                &[&snap.protection],
                sk,
                "secret/a.txt",
            )
            .unwrap();
            assert_eq!(
                &pt[..],
                b"OURS\nl2\nTHEIRS\n",
                "{who} must decrypt the merged content"
            );
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

        let err = repo
            .cherry_pick("work", "me", Some(&alice_sk), None)
            .unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert_eq!(repo.head_tip().unwrap(), Some(ours), "tip must not move");
        assert_eq!(repo.pick_head().unwrap(), Some(picked));
        assert!(
            crate::pick_state::read_decided_root(&repo.layout)
                .unwrap()
                .is_some(),
            "conflict path records the pick's decided carried tree"
        );

        // Markers are on disk as editable plaintext...
        let marked = std::fs::read(root.join("secret/a.txt")).unwrap();
        assert!(
            marked.windows(7).any(|w| w == b"<<<<<<<"),
            "markers on disk"
        );
        assert!(marked.windows(9).any(|w| w == b"OURS-EDIT"));
        assert!(marked.windows(11).any(|w| w == b"THEIRS-EDIT"));
        // ...and NO CAS object contains the marker plaintext.
        assert!(
            !cas_blob_contains(&repo, b"<<<<<<<"),
            "marker plaintext leaked into the CAS"
        );
        assert!(
            !cas_blob_contains(&repo, b"OURS-EDIT"),
            "protected plaintext leaked into the CAS"
        );

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
        assert_ne!(
            perms & scl_core::PROTECTED,
            0,
            "PROTECTED preserved through completion"
        );
        let bytes = blob_bytes_of(&repo, &blob_id);
        assert!(
            !bytes.windows(8).any(|w| w == b"RESOLVED"),
            "resolved plaintext in CAS blob"
        );
        for (who, sk) in [("alice", &alice_sk), ("bob", &bob_sk)] {
            let pt = crate::protect::decrypt_with(
                &bytes,
                &blob_id,
                &[&snap.protection],
                sk,
                "secret/a.txt",
            )
            .unwrap();
            assert_eq!(
                &pt[..],
                b"RESOLVED\nl2\nl3\n",
                "{who} must decrypt the resolution"
            );
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
        let picked = repo
            .commit("me", "work updates secret + edits shared")
            .unwrap();
        let (v1_id, _) = tree_entry(&repo, &picked, "secret/x.txt");

        // KEYLESS hop back to main (secret/x.txt leaves the disk).
        repo.switch("main").unwrap();

        // KEYLESS conflicted pick: x.txt is decided clean (take picked) but
        // cannot materialize without a key; shared.txt conflicts.
        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert!(
            !root.join("secret/x.txt").exists(),
            "keyless: v1 stays off disk"
        );

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
        assert_eq!(
            &pt[..],
            b"v1",
            "the carried blob decrypts to the picked update"
        );

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
        let picked = repo
            .commit("me", "work updates secret + edits shared")
            .unwrap();
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
        assert!(
            !crate::merge_state::in_progress(&repo.layout),
            "no MERGE_HEAD"
        );

        // Keyless conflicted pick, resolve, complete.
        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
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
        assert_eq!(
            crate::merge_state::read_decided_root(&repo.layout).unwrap(),
            None
        );

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
        let picked = repo
            .commit("me", "work adds protected keys/k2.txt")
            .unwrap();
        let (k2_id, _) = tree_entry(&repo, &picked, "keys/k2.txt");

        repo.switch("main").unwrap();

        // KEYLESS clean pick.
        let outcome = repo.cherry_pick("work", "me", None, None).unwrap();
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
        assert_ne!(
            k1_perms & scl_core::PROTECTED,
            0,
            "I2: plain file under union rule encrypts"
        );
        let k1_bytes = blob_bytes_of(&repo, &k1_id);
        assert_ne!(
            &k1_bytes[..],
            b"k1 contents\n",
            "no plaintext in the CAS tree"
        );
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
        assert!(
            !root.join("keys/k1.txt").exists(),
            "keyless: protected file leaves the disk"
        );

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
            RebaseResult::Rebased {
                new_tip,
                replayed,
                skipped,
            } => (new_tip, replayed, skipped),
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
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(feature_tip),
            "tip must not move"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn conflicting_rebase_stops_with_refs_byte_identical_but_markers_on_disk() {
        // P19: a plain conflict now STOPS the rebase (persists progress,
        // writes P4 markers) rather than aborting it — the branch ref still
        // doesn't move until final completion, so the ref-byte-identical
        // invariant survives unchanged; only the "working tree untouched"
        // half of the old assertion flips (that's the whole point of
        // resumability: markers ARE on disk to resolve).
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
        let snapshot_refs =
            |dir: &std::path::Path| -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
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
        let ops_before = repo.oplog().unwrap().len();

        let outcome = repo.rebase("main", "me", None).unwrap();
        match outcome {
            RebaseResult::Stopped {
                paths, done, total, ..
            } => {
                assert_eq!(paths, vec!["x.txt".to_string()]);
                assert_eq!((done, total), (0, 1));
            }
            other => panic!("expected Stopped, got {other:?}"),
        }
        assert!(repo.rebase_in_progress());

        let after_refs = snapshot_refs(&refs_dir);
        assert_eq!(
            before_refs, after_refs,
            "refs dir must be byte-identical while stopped"
        );
        let after_x = std::fs::read(root.join("x.txt")).unwrap();
        assert!(
            after_x.windows(7).any(|w| w == b"<<<<<<<"),
            "P4 markers must be on disk: {after_x:?}"
        );
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no oplog record while stopped"
        );

        repo.rebase_abort().unwrap();
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
        repo.commit("me", "main makes same edit as feature's A")
            .unwrap();

        // Rebase feature onto main.
        repo.switch("feature").unwrap();
        let outcome = repo.rebase("main", "me", None).unwrap();
        match outcome {
            RebaseResult::Rebased {
                replayed, skipped, ..
            } => {
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
            RebaseResult::Rebased {
                new_tip,
                replayed,
                skipped,
            } => {
                assert_eq!(
                    (replayed, skipped),
                    (2, 0),
                    "secrets-only commit replays, not skips"
                );
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
        assert_eq!(
            tip_snap.root, parent_snap.root,
            "registry-only snapshot keeps the tree"
        );
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

        let outcome = repo.cherry_pick("work", "me", None, None).unwrap();
        let id = match outcome {
            PickResult::Picked(id) => id,
            other => panic!("expected Picked (not AlreadyApplied), got {other:?}"),
        };
        assert_eq!(repo.head_tip().unwrap(), Some(id));

        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(
            snap.parents,
            vec![main_tip],
            "single-parent pick completion"
        );
        assert!(
            snap.secrets.contains_key("API_KEY"),
            "tip registry gains the secret"
        );
        assert_eq!(
            snap.root, main_root,
            "tree unchanged by a secrets-only pick"
        );
        assert_eq!(repo.secret_list().unwrap().len(), 1);
        let ops = repo.oplog().unwrap();
        assert_eq!(ops.last().unwrap().desc, "cherry-pick work");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Task 9 fix follow-on: a CONFLICTED pick whose picked commit ALSO
    /// carries a registry delta must keep that delta through the completing
    /// `sc commit` — the completion previously carried the tip's registry
    /// verbatim (silent drop). No public surface mints combined
    /// file+registry commits yet, so the picked commit is built via
    /// `build_snapshot` directly.
    #[test]
    fn conflicted_pick_completion_merges_picked_registry_delta() {
        let root = tmp_root("cp-conflict-registry");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        // ours: conflicting edit of shared.txt.
        std::fs::write(root.join("shared.txt"), b"a\nOURS\nc\n").unwrap();
        let main_tip = repo.commit("me", "main edits shared").unwrap();

        // work: conflicting edit + a registry delta on the SAME commit.
        repo.switch("work").unwrap();
        std::fs::write(root.join("shared.txt"), b"a\nWORK\nc\n").unwrap();
        let plain = repo.commit("me", "work edits shared").unwrap();
        let plain_snap = repo.snapshot(&plain).unwrap();
        let (_sk, pk) = scl_crypto::generate_keypair();
        let sealed = scl_crypto::seal("PICKED_SECRET", b"v1", &[pk]);
        let sid = {
            let store_arc = repo.vfs().store();
            let mut s = store_arc.lock().unwrap();
            s.put(scl_core::Object::Secret(sealed)).unwrap()
        };
        let mut secrets = plain_snap.secrets.clone();
        secrets.insert("PICKED_SECRET".to_string(), sid);
        let combined = repo
            .build_snapshot(
                plain_snap.root,
                plain_snap.parents.clone(),
                secrets,
                plain_snap.protection.clone(),
                "me",
                "work edits shared + adds secret",
            )
            .unwrap();
        let head = refs::current_branch(&repo.layout).unwrap();
        refs::write_branch_tip(&repo.layout, &head, &combined).unwrap();

        repo.switch("main").unwrap();
        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(1)), "got {err:?}");
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(main_tip),
            "tip must not move"
        );

        // Resolve + complete: the picked registry delta survives.
        std::fs::write(root.join("shared.txt"), b"a\nRESOLVED\nc\n").unwrap();
        let id = repo.commit("me", "resolve pick conflict").unwrap();
        assert!(!repo.pick_in_progress());
        let snap = repo.snapshot(&id).unwrap();
        assert_eq!(
            snap.parents,
            vec![main_tip],
            "pick completion is single-parent"
        );
        assert!(
            snap.secrets.contains_key("PICKED_SECRET"),
            "completion registry must carry the picked commit's registry delta"
        );
        assert_eq!(repo.secret_list().unwrap().len(), 1);

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
        repo.secret_add("TOKEN", b"v0", std::slice::from_ref(&pk))
            .unwrap();
        repo.branch("feature").unwrap();

        // main rotates TOKEN one way...
        repo.secret_rotate("TOKEN", Some(b"main-v"), std::slice::from_ref(&pk), None)
            .unwrap();
        // ...feature rotates it differently.
        repo.switch("feature").unwrap();
        repo.secret_rotate("TOKEN", Some(b"feat-v"), &[pk], None)
            .unwrap();
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
        assert_eq!(
            repo.head_tip().unwrap(),
            feature_tip,
            "feature tip must not move"
        );
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no new oplog record"
        );

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
            RebaseResult::Rebased {
                new_tip,
                replayed,
                skipped,
            } => {
                assert_eq!(
                    (replayed, skipped),
                    (1, 0),
                    "rules-only commit replays, not skips"
                );
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
        assert_eq!(
            snap.root, main_tip_snap.root,
            "rules-only replay keeps the tree"
        );

        // A file later committed under the rule lands PROTECTED and decrypts
        // for the rule's recipient.
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/k.txt"), b"k contents\n").unwrap();
        let c = repo.commit("me", "add keys/k.txt").unwrap();
        let (k_id, perms) = tree_entry(&repo, &c, "keys/k.txt");
        assert_ne!(
            perms & scl_core::PROTECTED,
            0,
            "file under the replayed rule is PROTECTED"
        );
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

        let outcome = repo.cherry_pick("work", "me", None, None).unwrap();
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
        assert_ne!(
            perms & scl_core::PROTECTED,
            0,
            "file under the picked rule is PROTECTED"
        );

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
        assert!(
            matches!(err, Error::CannotReplayMerge(id, _) if id == merged),
            "got {err:?}"
        );
        // Rebase-side contextualization (P19 review fix): no `--mainline`
        // hint (rebase has no such flag), and the message names rebase.
        let msg = err.to_string();
        assert!(!msg.contains("--mainline"), "got: {msg}");
        assert!(msg.contains("rebase"), "got: {msg}");
        assert_eq!(
            repo.head_tip().unwrap(),
            feature_tip_before,
            "feature tip must not move"
        );

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
        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("secret/db.txt"), b"v2").unwrap();
        let feature_tip = repo.commit("me", "feature updates secret").unwrap();
        let (v2_id, _) = tree_entry(&repo, &feature_tip, "secret/db.txt");

        // KEYLESS rebase of feature onto main.
        let outcome = repo.rebase("main", "me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased {
                new_tip,
                replayed,
                skipped,
            } => {
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
        assert!(
            !root.join("secret/db.txt").exists(),
            "keyless: protected file leaves the disk"
        );

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
        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nTHEIRS\n").unwrap();
        let feature_tip = repo.commit("me", "feature edits line 3").unwrap();

        let before_refs = snapshot_dir(&root.join(".sc/refs"));
        let before_a = std::fs::read(root.join("secret/a.txt")).unwrap();
        let ops_before = repo.oplog().unwrap().len();

        let err = repo.rebase("main", "me", None).unwrap_err();
        match err {
            Error::ProtectedMergeNeedsIdentity(ref msg) => {
                assert!(
                    msg.contains("secret/a.txt"),
                    "error must name the path: {msg}"
                );
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
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(feature_tip),
            "feature tip must not move"
        );
        assert_eq!(std::fs::read(root.join("secret/a.txt")).unwrap(), before_a);
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no new oplog record"
        );

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

        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nTHEIRS\n").unwrap();
        repo.commit("me", "feature edits line 3").unwrap();

        let outcome = repo.rebase("main", "me", Some(&alice_sk)).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased {
                new_tip,
                replayed,
                skipped,
            } => {
                assert_eq!((replayed, skipped), (1, 0));
                new_tip
            }
            other => panic!("expected Rebased, got {other:?}"),
        };
        let snap = repo.snapshot(&new_tip).unwrap();
        assert_eq!(snap.parents, vec![main_tip]);

        let (blob_id, perms) = tree_entry(&repo, &new_tip, "secret/a.txt");
        assert_ne!(
            perms & scl_core::PROTECTED,
            0,
            "PROTECTED preserved at the new tip"
        );
        let bytes = blob_bytes_of(&repo, &blob_id);
        assert!(
            !bytes.windows(4).any(|w| w == b"OURS"),
            "plaintext leaked into the CAS blob"
        );
        for (who, sk) in [("alice", &alice_sk), ("bob", &bob_sk)] {
            let pt = crate::protect::decrypt_with(
                &bytes,
                &blob_id,
                &[&snap.protection],
                sk,
                "secret/a.txt",
            )
            .unwrap();
            assert_eq!(
                &pt[..],
                b"OURS\nl2\nTHEIRS\n",
                "{who} must decrypt the merged content"
            );
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
        repo.commit("me", "A: feature adds plain keys/k1.txt")
            .unwrap();
        std::fs::write(root.join("other.txt"), b"o\n").unwrap();
        repo.commit("me", "B: feature adds other.txt").unwrap();

        // KEYLESS rebase (fresh encryption uses public keys only).
        let outcome = repo.rebase("main", "me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased {
                new_tip,
                replayed,
                skipped,
            } => {
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
        assert_ne!(
            perms & scl_core::PROTECTED,
            0,
            "I2: plain file under union rule encrypts"
        );
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
        assert!(
            !root.join("keys/k1.txt").exists(),
            "keyless: protected file leaves the disk"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- P19 Task 2: resumable rebase (stop / --continue / --abort) ----

    #[test]
    fn rebase_stops_on_conflict_and_continue_completes() {
        // main and feature diverge on x.txt; feature's FIRST commit
        // conflicts with main's edit, its SECOND commit (unrelated file)
        // doesn't. The rebase must stop at the first, leave refs untouched,
        // and `--continue` must land both and finish in ONE oplog record.
        let root = tmp_root("rebase-stop-continue");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        let main_tip = repo.commit("me", "main edits x").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        let feature_a = repo.commit("me", "feature edits x").unwrap();
        std::fs::write(root.join("y.txt"), b"y\n").unwrap();
        repo.commit("me", "feature adds y").unwrap();
        let original_feature_tip = repo.head_tip().unwrap().unwrap();

        let ops_before = repo.oplog().unwrap().len();

        // rebase -> Stopped: refs untouched, markers present, status reports.
        let outcome = repo.rebase("main", "me", None).unwrap();
        match outcome {
            RebaseResult::Stopped {
                conflicted,
                paths,
                done,
                total,
            } => {
                assert_eq!(conflicted, feature_a);
                assert_eq!(paths, vec!["x.txt".to_string()]);
                assert_eq!((done, total), (0, 2));
            }
            other => panic!("expected Stopped, got {other:?}"),
        }
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(original_feature_tip),
            "feature tip must not move"
        );
        assert!(repo.rebase_in_progress());
        let (progress_conflicted, progress_done, progress_total) =
            repo.rebase_progress().unwrap().unwrap();
        assert_eq!(
            (progress_conflicted, progress_done, progress_total),
            (feature_a, 0, 2)
        );
        let on_disk = std::fs::read_to_string(root.join("x.txt")).unwrap();
        assert!(
            on_disk.contains("<<<<<<<"),
            "P4 markers must be on disk: {on_disk}"
        );
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no oplog record while stopped"
        );

        // Resolve; continue completes the conflicted commit and finishes the
        // fold (feature's second commit replays cleanly).
        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();
        let outcome = repo.rebase_continue("me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased {
                new_tip, replayed, ..
            } => {
                // P21: cumulative across the whole rebase, not just this
                // fold segment — the completed conflicted commit (feature_a)
                // plus the tail commit that replays cleanly after it.
                assert_eq!(
                    replayed, 2,
                    "cumulative: the completed conflict + the clean tail commit"
                );
                new_tip
            }
            other => panic!("expected Rebased, got {other:?}"),
        };
        assert!(!repo.rebase_in_progress());
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(new_tip),
            "branch ref moved ONCE, to completion"
        );
        assert!(root.join("y.txt").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("x.txt")).unwrap(),
            "a\nresolved\nc\n"
        );

        let snap = repo.snapshot(&new_tip).unwrap();
        assert_eq!(snap.parents.len(), 1);
        let parent_snap = repo.snapshot(&snap.parents[0]).unwrap();
        assert_eq!(
            parent_snap.parents,
            vec![main_tip],
            "the completed conflict commit's parent is main"
        );

        // Exactly one oplog record for the whole rebase.
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before + 1,
            "exactly one oplog record"
        );
        let last_op = repo.oplog().unwrap().last().unwrap().clone();
        assert!(
            last_op.desc.starts_with("rebase onto main"),
            "got: {}",
            last_op.desc
        );

        // One undo restores the original (pre-rebase) tip.
        repo.undo().unwrap();
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(original_feature_tip),
            "undo restores the original tip"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_continue_refuses_when_branch_moved() {
        // P19 final-review fix I1: `sc secret add`/`sc protect` and friends
        // have no in-progress guard of their own. If one moves the stopped
        // rebase's branch tip directly (probe P3: via the registry/protect
        // commit path), `--continue` must refuse instead of force-writing
        // `acc_tip` over the ref and silently discarding that commit.
        let root = tmp_root("rebase-continue-branch-moved");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();
        let original_feature_tip = repo.head_tip().unwrap().unwrap();

        // Stop on conflict.
        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(matches!(outcome, RebaseResult::Stopped { .. }));
        assert_eq!(repo.head_tip().unwrap(), Some(original_feature_tip));

        // Simulate an unguarded op (e.g. `sc secret add`) moving the branch
        // ref directly while the rebase is stopped.
        let moved_tip = ObjectId::of(b"unguarded-op-moved-the-branch");
        refs::write_branch_tip(&repo.layout, "feature", &moved_tip).unwrap();

        // Resolve the conflict on disk and attempt to continue.
        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();
        let err = repo.rebase_continue("me", None).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidArgument(msg) if msg.contains("branch moved while the rebase was stopped")),
            "expected branch-moved InvalidArgument, got {err:?}"
        );

        // State is untouched: still in progress, ref still at the moved tip
        // (rebase_continue must not have written anything).
        assert!(repo.rebase_in_progress());
        assert_eq!(
            refs::read_branch_tip(&repo.layout, "feature").unwrap(),
            Some(moved_tip)
        );
        let st = crate::rebase_state::read(&repo.layout).unwrap().unwrap();
        assert!(!st.resolved, "must not have advanced past the guard");

        // `--abort` still works (state was untouched by the refused continue).
        repo.rebase_abort().unwrap();
        assert!(!repo.rebase_in_progress());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_multi_stop_resumes_twice() {
        // Two commits in the replayed range BOTH conflict with the target
        // line: stop, continue (completes #1, immediately hits #2 -> stop
        // again), continue (completes #2, fold ends -> Completed). Still
        // exactly one oplog record for the whole operation.
        let root = tmp_root("rebase-multi-stop");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"orig\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("f.txt"), b"main-edit\n").unwrap();
        repo.commit("me", "main edits f").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"feat-A\n").unwrap();
        let commit_a = repo.commit("me", "feature A").unwrap();
        // B further edits the SAME line differently from A's own version, so
        // once A's conflict is resolved to something else, B's replay (base
        // = A's ORIGINAL tree) conflicts again against the resolved value.
        std::fs::write(root.join("f.txt"), b"feat-B\n").unwrap();
        let commit_b = repo.commit("me", "feature B").unwrap();
        let original_feature_tip = repo.head_tip().unwrap().unwrap();
        let _ = commit_b;

        let ops_before = repo.oplog().unwrap().len();

        let outcome = repo.rebase("main", "me", None).unwrap();
        match outcome {
            RebaseResult::Stopped {
                conflicted,
                done,
                total,
                ..
            } => {
                assert_eq!(conflicted, commit_a);
                assert_eq!((done, total), (0, 2));
            }
            other => panic!("expected Stopped (first), got {other:?}"),
        }
        assert_eq!(repo.head_tip().unwrap(), Some(original_feature_tip));

        std::fs::write(root.join("f.txt"), b"resolved-A\n").unwrap();
        let outcome = repo.rebase_continue("me", None).unwrap();
        let second_conflicted = match outcome {
            RebaseResult::Stopped {
                conflicted,
                done,
                total,
                ..
            } => {
                assert_eq!((done, total), (1, 2));
                conflicted
            }
            other => panic!("expected Stopped (second), got {other:?}"),
        };
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(original_feature_tip),
            "still not moved"
        );
        assert!(repo.rebase_in_progress());
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "still no oplog record"
        );

        std::fs::write(root.join("f.txt"), b"resolved-B\n").unwrap();
        let outcome = repo.rebase_continue("me", None).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased { new_tip, .. } => new_tip,
            other => panic!("expected Rebased, got {other:?}"),
        };
        let _ = second_conflicted;
        assert!(!repo.rebase_in_progress());
        assert_eq!(repo.head_tip().unwrap(), Some(new_tip));
        assert_eq!(
            std::fs::read_to_string(root.join("f.txt")).unwrap(),
            "resolved-B\n"
        );

        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before + 1,
            "exactly one oplog record"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn multi_stop_rebase_oplog_reports_cumulative_counts() {
        // P21: the P19 ledger repro (`rebase_multi_stop_resumes_twice`) stops
        // twice, landing commit A's completion at the first `--continue` and
        // commit B's completion at the second. Before P21, each fold segment
        // seeded its `replayed`/`skipped` locals at 0, so the FINAL oplog
        // record only reported the last segment's count ("0 replayed" — the
        // second `--continue` completes B via `assemble_completion_snapshot`
        // directly, then folds over an EMPTY remaining range). The record
        // must instead report the cumulative count across the whole
        // operation: both A and B landed, so "2 replayed".
        let root = tmp_root("rebase-multi-stop-cumulative");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), b"orig\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("f.txt"), b"main-edit\n").unwrap();
        repo.commit("me", "main edits f").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("f.txt"), b"feat-A\n").unwrap();
        repo.commit("me", "feature A").unwrap();
        std::fs::write(root.join("f.txt"), b"feat-B\n").unwrap();
        repo.commit("me", "feature B").unwrap();

        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(
            matches!(outcome, RebaseResult::Stopped { .. }),
            "expected first stop"
        );

        std::fs::write(root.join("f.txt"), b"resolved-A\n").unwrap();
        let outcome = repo.rebase_continue("me", None).unwrap();
        assert!(
            matches!(outcome, RebaseResult::Stopped { .. }),
            "expected second stop"
        );

        std::fs::write(root.join("f.txt"), b"resolved-B\n").unwrap();
        let outcome = repo.rebase_continue("me", None).unwrap();
        match outcome {
            RebaseResult::Rebased {
                replayed, skipped, ..
            } => {
                assert_eq!(
                    (replayed, skipped),
                    (2, 0),
                    "both A and B must count cumulatively"
                );
            }
            other => panic!("expected Rebased, got {other:?}"),
        }

        let last = repo.oplog().unwrap().into_iter().next_back().unwrap();
        assert!(
            last.desc.contains("2 replayed"),
            "oplog record must report the cumulative count, not just the last segment: {}",
            last.desc
        );
        assert!(
            !last.desc.contains("0 replayed"),
            "must not report the last segment alone: {}",
            last.desc
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn status_distinguishes_resolved_awaiting_continue() {
        // P21: reuses `rebase_continue_error_preserves_state_and_retry_succeeds`'s
        // setup — commit A plain-conflicts with main, commit B diverges a
        // PROTECTED path's content from main and needs `--identity`. After
        // resolving A and calling `--continue` WITHOUT an identity, A
        // completes (advancing `RebaseState::resolved` to true) but the fold
        // then errors on B. In that window, the repo-level accessor must
        // report `resolved == true` — nothing left to resolve on disk, the
        // caller just needs to retry `--continue` — distinct from the
        // initial "stopped, markers on disk" window where it must be false.
        let root = tmp_root("rebase-status-resolved-window");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nMAIN\nc\n").unwrap();
        std::fs::write(root.join("secret/a.txt"), b"OURS\nl2\nl3\n").unwrap();
        repo.commit("me", "main edits x and secret").unwrap();

        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("x.txt"), b"a\nFEATURE\nc\n").unwrap();
        repo.commit("me", "feature edits x (conflicts)").unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nTHEIRS\n").unwrap();
        repo.commit("me", "feature edits secret (protected divergence)")
            .unwrap();

        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(matches!(outcome, RebaseResult::Stopped { .. }));
        assert!(
            !repo.rebase_resolved().unwrap(),
            "stopped, not yet resolved: markers still on disk"
        );

        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();
        let err = repo.rebase_continue("me", None).unwrap_err();
        assert!(matches!(
            err,
            Error::ProtectedMergeNeedsIdentity(_) | Error::NotAuthorized(_)
        ));
        assert!(
            repo.rebase_resolved().unwrap(),
            "A completed before B's fold errored — the resolved window must be visible"
        );

        let outcome = repo.rebase_continue("me", Some(&alice_sk)).unwrap();
        assert!(matches!(outcome, RebaseResult::Rebased { .. }));
        assert!(
            !repo.rebase_resolved().unwrap(),
            "no rebase in progress once completed"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn aborts_surface_protected_skip_list() {
        // P21: both `cherry_pick_abort` and `rebase_abort` re-materialize the
        // pre-op tip with NO identity (abort time has none available) — a
        // protected file in that tip must be reported skipped, not silently
        // dropped, mirroring `Repo::merge_abort`'s existing contract. Each
        // scenario stops on a PLAIN conflict (x.txt) unrelated to the
        // protected path (secret/a.txt), which is untouched on both sides —
        // so the stop/abort exercises pure restore-without-identity, not the
        // content-divergent-protected-merge path (which aborts atomically
        // with no state to abort in the first place).

        // -- cherry-pick --
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let root = tmp_root("abort-skip-list-pick");
        let repo = Repo::init(&root).unwrap();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"top secret").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("work").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nMAIN\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch_with_identity("work", Some(&alice_sk)).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nWORK\nc\n").unwrap();
        repo.commit("me", "work edits x").unwrap();

        repo.switch_with_identity("main", Some(&alice_sk)).unwrap();
        let err = repo.cherry_pick("work", "me", None, None).unwrap_err();
        assert!(matches!(err, Error::PickConflicts(_)), "got {err:?}");

        let skipped = repo.cherry_pick_abort().unwrap();
        assert_eq!(
            skipped,
            vec!["secret/a.txt".to_string()],
            "no identity at abort: must be skipped"
        );
        assert!(
            !root.join("secret/a.txt").exists(),
            "skipped means absent, not stale plaintext"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();

        // -- rebase --
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let root = tmp_root("abort-skip-list-rebase");
        let repo = Repo::init(&root).unwrap();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"top secret").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nMAIN\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("x.txt"), b"a\nFEATURE\nc\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();

        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(matches!(outcome, RebaseResult::Stopped { .. }));

        let skipped = repo.rebase_abort().unwrap();
        assert_eq!(
            skipped,
            vec!["secret/a.txt".to_string()],
            "no identity at abort: must be skipped"
        );
        assert!(
            !root.join("secret/a.txt").exists(),
            "skipped means absent, not stale plaintext"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_abort_restores_byte_identical_tree_and_refs() {
        let root = tmp_root("rebase-abort");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        std::fs::write(root.join("stable.txt"), b"stable\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        repo.commit("me", "main edits x").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();
        let original_tip = repo.head_tip().unwrap().unwrap();

        let before_x = std::fs::read(root.join("x.txt")).unwrap();
        let before_stable = std::fs::read(root.join("stable.txt")).unwrap();
        let ops_before = repo.oplog().unwrap().len();

        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(matches!(outcome, RebaseResult::Stopped { .. }));
        assert!(repo.rebase_in_progress());

        // Dirty the tree further beyond the markers themselves.
        std::fs::write(root.join("x.txt"), b"garbage\n").unwrap();
        std::fs::write(root.join("stable.txt"), b"also garbage\n").unwrap();

        repo.rebase_abort().unwrap();

        assert!(!repo.rebase_in_progress(), "state cleared");
        assert!(repo.rebase_progress().unwrap().is_none());
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(original_tip),
            "branch tip unchanged"
        );
        assert_eq!(
            std::fs::read(root.join("x.txt")).unwrap(),
            before_x,
            "x.txt byte-identical"
        );
        assert_eq!(
            std::fs::read(root.join("stable.txt")).unwrap(),
            before_stable,
            "stable.txt byte-identical"
        );
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no oplog record from abort"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_continue_without_state_errors() {
        let root = tmp_root("rebase-continue-no-state");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\n").unwrap();
        repo.commit("me", "base").unwrap();

        let err = repo.rebase_continue("me", None).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => {
                assert!(msg.contains("no rebase in progress"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        let err = repo.rebase_abort().unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn stopped_rebase_survives_process_boundary() {
        let root = tmp_root("rebase-process-boundary");
        {
            let repo = Repo::init(&root).unwrap();
            std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
            repo.commit("me", "base").unwrap();
            repo.branch("feature").unwrap();

            std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
            repo.commit("me", "main edits x").unwrap();

            repo.switch("feature").unwrap();
            std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
            repo.commit("me", "feature edits x").unwrap();

            let outcome = repo.rebase("main", "me", None).unwrap();
            assert!(matches!(outcome, RebaseResult::Stopped { .. }));
            drop(repo);
        }

        // Reopen a fresh `Repo` handle — no identity key material is (or
        // could be) carried across the boundary; state lives entirely under
        // `.sc/` as plain files (rebase_state's own documented contract).
        let repo = Repo::open(&root).unwrap();
        assert!(repo.rebase_in_progress());
        let (conflicted, done, total) = repo.rebase_progress().unwrap().unwrap();
        assert_eq!((done, total), (0, 1));
        let _ = conflicted;

        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();
        let outcome = repo.rebase_continue("me", None).unwrap();
        assert!(matches!(outcome, RebaseResult::Rebased { .. }));
        assert!(!repo.rebase_in_progress());

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- P19 review fixes: error-recoverable/idempotent --continue, and
    // --abort dropping stop-materialized target-only files ----

    #[test]
    fn rebase_continue_error_preserves_state_and_retry_succeeds() {
        // feature's first commit (A) plain-conflicts with main on x.txt;
        // feature's second commit (B) diverges main's content edit to a
        // PROTECTED path — a genuine content-divergent protected merge that
        // needs `--identity`. Stop at A, resolve, `--continue` WITHOUT an
        // identity: A completes (assemble_completion_snapshot needs no
        // identity — it only reads the resolved plaintext off disk), then
        // the resumed fold hits B and errors typed
        // (`ProtectedMergeNeedsIdentity`). The rebase must still be in
        // progress afterward (state not cleared by the failed attempt), and
        // a retry WITH the identity must complete WITHOUT re-resolving A
        // (proving the completion was not re-applied) and land in exactly
        // ONE oplog record for the whole operation.
        let root = tmp_root("rebase-continue-error-recoverable");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", &[alice_pk], None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nl3\n").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        // main (target): edits x.txt (will conflict with feature's A) AND
        // edits secret/a.txt line 1 (will diverge from feature's B).
        std::fs::write(root.join("x.txt"), b"a\nMAIN\nc\n").unwrap();
        std::fs::write(root.join("secret/a.txt"), b"OURS\nl2\nl3\n").unwrap();
        let main_tip = repo.commit("me", "main edits x and secret").unwrap();

        // feature commit A: conflicting x.txt edit only.
        repo.switch_with_identity("feature", Some(&alice_sk))
            .unwrap();
        std::fs::write(root.join("x.txt"), b"a\nFEATURE\nc\n").unwrap();
        let commit_a = repo.commit("me", "feature edits x (conflicts)").unwrap();

        // feature commit B: edits secret/a.txt line 3 — mergeable but
        // content-divergent from main's line-1 edit.
        std::fs::write(root.join("secret/a.txt"), b"l1\nl2\nTHEIRS\n").unwrap();
        repo.commit("me", "feature edits secret (protected divergence)")
            .unwrap();
        let original_feature_tip = repo.head_tip().unwrap().unwrap();

        let ops_before = repo.oplog().unwrap().len();

        let outcome = repo.rebase("main", "me", None).unwrap();
        match outcome {
            RebaseResult::Stopped { conflicted, .. } => assert_eq!(conflicted, commit_a),
            other => panic!("expected Stopped at commit A, got {other:?}"),
        }
        assert_eq!(repo.head_tip().unwrap(), Some(original_feature_tip));

        // Resolve A's conflict.
        std::fs::write(root.join("x.txt"), b"a\nresolved\nc\n").unwrap();

        // --continue without identity: A completes, then B's replay errors.
        let err = repo.rebase_continue("me", None).unwrap_err();
        assert!(
            matches!(
                err,
                Error::ProtectedMergeNeedsIdentity(_) | Error::NotAuthorized(_)
            ),
            "expected a typed identity error, got {err:?}"
        );
        assert!(
            repo.rebase_in_progress(),
            "state must survive the failed --continue for retry"
        );
        assert_eq!(
            repo.head_tip().unwrap(),
            Some(original_feature_tip),
            "branch ref must still not have moved"
        );
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before,
            "no oplog record from the failed retry"
        );

        // Retry with the identity: must NOT re-ask for A's resolution — the
        // working tree still holds A's resolved x.txt, untouched by the
        // failed attempt, and completion must not re-run against it.
        let outcome = repo.rebase_continue("me", Some(&alice_sk)).unwrap();
        let new_tip = match outcome {
            RebaseResult::Rebased { new_tip, .. } => new_tip,
            other => panic!("expected Rebased on retry, got {other:?}"),
        };
        assert!(!repo.rebase_in_progress());
        assert_eq!(repo.head_tip().unwrap(), Some(new_tip));
        assert_eq!(
            std::fs::read_to_string(root.join("x.txt")).unwrap(),
            "a\nresolved\nc\n",
            "A's resolution must be preserved, not re-asked"
        );
        assert_eq!(
            repo.oplog().unwrap().len(),
            ops_before + 1,
            "exactly ONE new oplog record for the whole stop+retry rebase"
        );
        // Discriminating check (not just "the visible result looks right"):
        // walk the parent chain and confirm A was completed EXACTLY ONCE,
        // directly atop main_tip. If the failed retry had re-completed A
        // (the bug `resolved` prevents), B's snapshot would have an extra
        // no-op A'' between A' and main_tip — every assertion above would
        // still pass despite the double-application.
        let b_snap = repo.snapshot(&new_tip).unwrap();
        assert_eq!(b_snap.parents.len(), 1, "B's completion is single-parent");
        let a_completion = repo.snapshot(&b_snap.parents[0]).unwrap();
        assert_eq!(
            a_completion.parents,
            vec![main_tip],
            "A must have completed exactly once, directly atop main_tip — \
             the failed retry must not have re-applied it"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rebase_abort_drops_stop_materialized_target_files() {
        // main (target) both edits x.txt (conflicting with feature) AND adds
        // a brand-new file the stop's conflict-materialize pulls onto disk.
        // `--abort` must drop that target-only file, not leave it as
        // untracked residue the next commit would silently absorb.
        let root = tmp_root("rebase-abort-drops-target-only");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("x.txt"), b"a\nb\nc\n").unwrap();
        repo.commit("me", "base").unwrap();
        repo.branch("feature").unwrap();

        std::fs::write(root.join("x.txt"), b"a\nB\nc\n").unwrap();
        std::fs::write(root.join("new.txt"), b"from-main\n").unwrap();
        repo.commit("me", "main edits x, adds new.txt").unwrap();

        repo.switch("feature").unwrap();
        std::fs::write(root.join("x.txt"), b"a\nZ\nc\n").unwrap();
        repo.commit("me", "feature edits x").unwrap();
        let original_tip = repo.head_tip().unwrap().unwrap();

        let outcome = repo.rebase("main", "me", None).unwrap();
        assert!(matches!(outcome, RebaseResult::Stopped { .. }));
        assert!(
            root.join("new.txt").exists(),
            "the stop's conflict-materialize must pull in target's new.txt"
        );

        repo.rebase_abort().unwrap();

        assert!(!repo.rebase_in_progress());
        assert!(
            !root.join("new.txt").exists(),
            "abort must drop the stop-materialized target-only file"
        );
        assert_eq!(
            std::fs::read(root.join("x.txt")).unwrap(),
            b"a\nZ\nc\n",
            "x.txt restored to feature's pre-rebase content"
        );
        assert_eq!(repo.head_tip().unwrap(), Some(original_tip));

        let status = repo.status().unwrap();
        assert!(
            status.added.is_empty() && status.modified.is_empty() && status.deleted.is_empty(),
            "status must report clean after abort: {status:?}"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).ok();
    }
}
