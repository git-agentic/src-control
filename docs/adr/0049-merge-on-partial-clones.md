# ADR-0049: Merge on partial clones (P37c)

- **Status:** Proposed (37c-i engine, 37c-ii clean merge, 37c-iii conflicts and 37c-iv replay built; sessions are ADR-0050)
- **Date:** 2026-10-17
- **Phase:** 37c
- **Builds on:** ADR-0048 (presence-based partial clones), ADR-0047 (want-by-id fetch), ADR-0012 (three-way merge), ADR-0025 (protected merge and replay), ADR-0043 (randomized sealing)

## Context

ADR-0048 left merge, cherry-pick/rebase and sessions refused on a partial clone and listed what a correct implementation must respect. This record turns the merge half of that list into a design. Replay and sessions follow from it and are sketched at the end. A first draft of this record was reviewed against the source (Codex Sol, adversarial, read-only); it found five design flaws, all confirmed in the code and all fixed below. The corrections are folded into the decisions, and the review's counterexamples are required test cases.

Today `sc merge` on a partial clone fast-forwards or adopts (no tree is rebuilt) and otherwise stops at `repo.rs:1349` with `PartialCloneUnsupported`. The reason is how a real merge works:

1. `three_way_files` (`merge.rs:191`) flattens all three trees to `path -> (blob id, mode, perms)` maps, merges path by path, and returns a flat `files` list.
2. `merge_with_identity` (`repo.rs:1385-1530`) routes that list through the protection rules (any plain survivor under a union rule is encrypted, whatever side it came from, `repo.rs:1403`), rebuilds the whole tree with `write_tree_with_perms`, unions the wraps, prunes them to blobs reachable in the merged tree, materializes, and commits a two-parent snapshot.
3. A conflict leaves marker files, a persisted decided root (`merge_state`) and sidecars; plaintext of protected content never enters the CAS (`repo.rs:1420`, `:1427`). Completion (`sc commit`) rebuilds from the working tree plus the decided root.

Every step reads every file of both sides, and a partial clone does not hold them. But for a subtree where the three sides agree **by tree id**, the answer is known without reading below it, so a merge only has to look inside the subtrees that differ. That is the idea ADR-0048 withdrew as unsafe as first written. It is safe only with the restrictions here.

## Decisions

### 1. Content and mode are merged as separate dimensions, in both engines

The flatten merge resolves a plain path by **blob id alone** (`merge.rs:229-249`) and a protected path by `(blob id, PROTECTED)` (`merge.rs:312`); the mode of the result then simply follows whichever side's entry was kept. A mode-only change therefore loses today: base and ours hold blob X at `0644`, theirs holds X at `0755`; the ids agree, ours is kept, and `0755` is dropped. A tree-level shortcut compares whole entries and would pick `0755`, so the two engines would disagree on the same merge.

A single composite key `(id, mode, perms)` is not the answer. It turns a metadata change into a false content divergence: base `(X,0644)`, ours `(Y,0644)`, theirs `(Y,0755)` agree on Y, yet every composite key differs, which would demand an identity for protected Y, report a conflict for identical binary Y, and could re-seal unchanged ciphertext (`merge.rs:283`, `:377`, `:399`).

So 37c-i separates the dimensions, in **both** engines:

- **Content** resolves exactly as today: by blob id (and the `PROTECTED` bit for protected paths). Nothing about content resolution, diff3, sealing or wraps changes.
- **Mode** is merged afterwards, independently, as a three-way on the modes of the entries that exist. It only votes between entries that are both present: when one side has no entry (a delete/modify conflict, where content keeps the surviving side), the result takes the **surviving entry's mode**, and a deletion contributes no mode. Between two present entries: equal on both sides, take it; one side equal to base, take the other's; both sides changed differently, executable if either is (today's rule for that case, kept as the tiebreak). Example: base `(X,0755)`, ours `(X,0644)`, theirs `(Y,0755)` resolves content to Y (ours is unchanged from base by id, so theirs wins) and mode to `0644` (ours changed it, theirs did not), so ours' executable removal is kept.

This is a deliberate, small behavior change on full clones: a mode-only change on one side now merges. It also makes the tree-level shortcuts below exact, because identical tree ids imply equal content and equal mode at every leaf, so "carry the differing side" is the per-dimension three-way answer. ADR-0012 gets an amendment note, and the cases above are regression tests (mode-only, identical-content/different-mode on binary and protected-keyless content, executable removal).

### 2. A tree-recursive merge that carries only what it can prove safe

Add `merge::merge_trees` beside the flatten implementation. It works one directory level at a time over the union of entry names. A subtree is **carried by id, unread**, when:

- it is identical (same tree id) on all three sides, or
- the three sides do not all differ (`ours == theirs`, `base == theirs`, or `base == ours`, by tree id), **and** the subtree is policy-disjoint (decision 3).

Everything else is **enumerated**: read, flattened for that subtree, and resolved by the existing leaf rules (diff3, the protected arm, delete/modify), unchanged. Absence is explicit:

| Situation at a name | Result |
|---|---|
| tree on all three sides, all differ | recurse |
| tree on some sides, absent on others | the carry rules above apply first (a one-sided add or delete carries or drops the subtree); when all three differ it recurses with the missing side as an empty tree, so delete/modify and add/add keep their flatten meaning |
| blob on one side and a tree on another | enumerate both and apply the per-path rules, then apply the collision check below |
| blobs on all three, all differ | the existing leaf merge |

**File/directory collisions are rejected up front, in both engines.** The existing path does not reject them: with an empty base, ours adding file `x` and theirs adding `x/child`, the leaf merge reports two clean additions, the writer emits both a blob and a tree named `x` (`vfs/lib.rs:155`, `:175`; `Tree::new` only sorts duplicates, `object.rs:134`), and materialization can write `x` and then fail creating `x/` after changing files (`worktree.rs:839`). 37c-i makes the merge fail before any output write when a resolved name is a file and also a directory, or a file is an ancestor of another resolved path, including across the boundary between carried subtrees and enumerated files. The error names the path. This is a small fix to full-clone merge too.

### 3. Policy-intersecting subtrees are always enumerated

A subtree is policy-disjoint when no rule in the **union** of the sides' rules covers it or lies inside it, checked in both directions at `/` boundaries (`protect::matching_prefix` semantics: boundary-aware, longest prefix wins). Every rule counts, including rules present on only one side and rules whose recipients have all been revoked: tombstones gate future seals and do not remove the prefix (`protect.rs:10`, `:30`). A subtree that intersects a union rule and is not identical on all three sides is enumerated, never carried.

The first draft tested only whether a rule was *new* relative to the side being carried. That is not enough: the rule can already be on that side while plaintext sits under it. `protect` records the rule in a policy-only snapshot and encrypts in a second commit (`protect_ops.rs:85-105`), and a partial-clone commit encrypts only the sparse view and grafts the rest unchanged (`repo.rs:667`). The full merge encrypts every plain survivor under a union rule (`repo.rs:1403`) and would repair it; a carry would preserve it.

One accepted divergence: a subtree identical on all three sides is carried even under a rule, so a merge does not force a partial clone to fetch every protected prefix. Plaintext under a rule that is identical on all three sides was already in both parents; the merge introduces nothing. A full merge would repair it and a partial one leaves it. A `sc verify` check for that state is a follow-on. The differential test (decision 9) excludes this state from its protection-perms equivalence on purpose.

Recipient-list changes alone do not require re-wrapping a carried ciphertext: the full merge already carries ciphertext unchanged and unions the wraps it knows (`repo.rs:1413`, `merge.rs:454`).

### 4. Wraps: keep the complete input union whenever anything was carried

`protection.wrapped` maps blob ids to wrapped DEKs. The full merge rebuilds it from surviving files and prunes to reachable blobs. A carried subtree is never enumerated, so pruning would drop the wraps of blobs inside it, which permanently loses every recipient's ability to decrypt them (the defect class the commit-graft fix closed, `repo.rs:699`).

A per-id rule ("prune what you enumerated") is unsound: a blob id seen as deleted at one path may survive under a carried subtree elsewhere, since ids alias across paths. So the rule is coarse: **if the merge carried any subtree, the merged map is the complete union of the input wraps** (ours, theirs, base, with the existing ours/theirs/base precedence and per-recipient dedup), plus fresh wraps. If it carried nothing, the existing prune applies. Union resurrecting a wrap for a recipient revoked since is the intended P16 behavior (tombstones gate future seals, not historical wraps; ADR-0026).

Over-retention costs size: wraps are inline in the snapshot, and an object above `MAX_OBJECT_SIZE` fails transfer. Nothing prunes dead entries today (`sc rewrap` refuses partial clones and only removes ids it upgrades, `rewrap.rs:164`, `:308`). So the growth is real and bounded by the repo's protected blob count; it is measured before any prune is designed.

### 5. The engine is pull-based; filling happens outside the store lock

`Filler` takes the store mutex (`fill.rs:283`), and the current merge engine runs while holding it (`repo.rs:1362`). A callback from inside the merge would deadlock. Instead `merge_trees` returns either a finished `TreeMerge` or `Needs(missing)`, where each entry is `(ObjectId, path)`: a subtree **or blob** it must read and does not hold (the leaf merge and the encryption step read blob bytes, so a differing or rule-intersecting region outside the filter needs its blobs too), with the path at which the traversal found it (an id alone does not identify a path, since subtrees alias, and an absent root has no path to recover from tree data; the root is reported as the empty path). The caller drops the lock, fills those ids (lazy and online; blobs are ordinary by-id requests, batched and split like trees) or fails with the gap error for the first reported path (`GapOutsideFilter`, whose message names `sc backfill <path>`; the whole-clone refusal when the path is the root) otherwise, and calls again. Each round is idempotent, and progress is by presence.

The merged tree can also carry a subtree that is absent **inside the sparse view** (the fetch case from ADR-0048). So after the merge and before materializing, the caller runs `ensure_view(merged_root, sparse)`, as every other materializer site does. The claim that network traffic is bounded to the differing region is therefore "the differing region, the rule-intersecting region, and the view's closure".

The order of a partial merge is: merge registries and files (a `Needs` result loops back through fill and recomputes, with no output writes during the retries) → refuse conflicts and collisions → encrypt → assemble the final root and wraps → `ensure_view(merged_root)` and the materialize preflight → materialize → snapshot and ref move. The repo lock stays held throughout; only the store mutex is released around fills.

Failure contract: fetched objects persist (fill rounds write immutable CAS additions, so "before anything is written" cannot mean literally nothing), and so may the merged tree objects of the output step. No ref, spec, working-tree file or merge state is written until `ensure_view` and the preflight have succeeded.

### 6. The result keeps plaintext out of the CAS

`TreeMerge` is not a bare tree id. It returns what `FileMerge` returns today (the enumerated `MergedFile` list with `needs_encrypt` plaintext, sidecars, conflicts, `wrapped_carry`) **plus** the carried subtrees as `(path, TreeEntry)` pairs. The existing pipeline (`repo.rs:1385-1530`) handles the enumerated files unchanged (routing through union rules, encryption, plaintext never written to the CAS). The carried entries are overlaid by id when the final tree is assembled. A carry at the **root** (the empty path) has no enclosing entry or ancestor directory, so it is its own variant: `TreeMerge` holds either a carried root id, which is the merged root as is (this is what two branches with disjoint secret-registry changes, or a secrets-only commit merged with a file-changing sibling, produce when the root ids agree), or a list of `(path, TreeEntry)` carries to overlay. Otherwise: a recursive overlay rebuilds each ancestor directory from the enumerated files at that level, inserts the carried entries verbatim (id, mode, perms untouched), and keeps the enumerated siblings, with the collision check above run over the combined names. No new code path touches plaintext.

### 7. Tree semantics, stated plainly

Flatten drops empty directories and directory metadata and rebuilds directories with mode `0755`/perms `0` (`worktree.rs:348`, `vfs/lib.rs:175`); a carried subtree keeps whatever it has, including an empty directory entry that `graft_out_of_sparse` can produce (`worktree.rs:313`). Equivalence is defined on **file sets, modes and perms**, not on tree ids. A merged tree on a partial clone may differ from the full-clone merge by an empty directory entry. The differential test compares file sets, not ids.

### 8. Conflicts: the contract (amended in 37c-iii)

37c-i and 37c-ii refused every conflict because the state contract was unspecified, and the review showed why it is not a detail:

- a conflicted merge's protected content merges produce plaintext that must live only on disk, with the CAS-safe decided root carrying everything else (`repo.rs:1420-1520`, `:1636`);
- an in-view conflict can coexist with a **clean protected content merge outside the view**; today that clean plaintext is written straight to disk, and a decided root alone does not preserve it, so completion would lose it;
- newly sealed decided blobs' wraps must survive a process restart, but merge state stores only the root (`merge_state.rs:68`) and completion reconstructs protection from the parents (`repo.rs:359`);
- presence does not imply the sparse view: a conflict outside the view needs the existing `sc sparse set` refusal, and abort must preflight and fill before it deletes sidecars (today it deletes them first, `repo.rs:1666`);
- `sc conflicts` and `sc resolve` flatten whole trees and need path-directed lookup (`conflicts.rs:147`, `:263`, `:329`).

37c-iii answers each, and the answers are mostly "the full-clone design already does this, so keep it and fix what a gap breaks".

**State is unchanged.** A conflicted merge on a partial clone writes the same three files as a full clone (`MERGE_HEAD`, `MERGE_CONFLICTS`, `MERGE_DECIDED_ROOT`). The decided root is built by `write_tree_with_carried`: the CAS-safe enumerated entries (surviving ciphertext, plain files, marker text for plain conflicts) plus the carried subtrees verbatim. Nothing is sealed while the merge is open. Sealing happens at completion, from the plaintext on disk, which is why no fresh wrap needs to be persisted: every ciphertext in the decided root is an existing blob whose wraps sit in ours or theirs. A carried subtree equals the ours or theirs subtree, and a leaf keeps the side that changed, so every ciphertext in the decided root has its wraps in one of the two parents. Completion's policy is the union of both parents' prefixes and wraps, exactly as on a full clone, so the two engines agree by construction and need no second persistence format. One consequence is recorded in open question 13: a clean merge also unions the base's wraps and a conflicted completion does not.

**Three refusals, all before any merge-output, merge-state or working-tree write** (fetched objects persist, as in decision 5):

1. A conflicted path outside the sparse view. This is the existing `materialize_conflict_state` refusal, and the widen hint stays: `sc sparse set` on a lazy clone, `sc backfill` on a non-lazy one.
2. A sidecar (`<path>.theirs`, written for a binary conflict) whose conflicted path is outside the view: it is plaintext beside the conflicted file, and outside the view completion neither expects nor protects it. The sidecar counts as in view when its base path is, so a file-exact spec such as `src/a.bin` no longer refuses an in-view binary conflict (#224; the conflicted path itself already passed refusal 1, so this check is a guard and does not fire in practice).
3. A result that must be sealed at completion (protected plaintext from a clean content merge, or a plain file under a union rule) at a path outside the view. Completion reads that plaintext back from disk. A partial clone completes from the view only, so plaintext left outside it would be silently dropped, and on any clone writing it outside the view leaves plaintext on disk where the user asked for none (and `commit` never sweeps it). The combination is refused with a message that names the path, on full and partial clones alike (#210; a full clone was first allowed to write it, which left the plaintext behind after completion, ADR-0034). Sealing it into the decided root at conflict time would lift the refusal, but it needs the fresh wraps persisted (a fourth state file), and nothing yet asks for it.

**Completion** (`sc commit` with `MERGE_HEAD` set) is allowed on a partial clone only when a decided root is recorded, which every partial conflict writes. It builds `all` from the working tree and the in-view carry exactly as today, then splices every out-of-view subtree back in **from the decided root** by id (`graft_out_of_sparse` with the decided root as the parent), where a plain commit grafts from the tip. The wrap map keeps the complete union of both parents' wraps (decision 4's coarse rule: nothing is pruned when a subtree was grafted), since a grafted subtree's blobs never pass through the seal loop. A merge without a decided root, and every cherry-pick or rebase completion, still refuse; replay is 37c-iv.

**The view only widens across the merge.** `sc sparse set` refuses while a merge, pick or rebase is stopped unless the new spec is a strict superset of the current one and the stop recorded its decided root (#224, ADR-0034). A widen fills the new view's closure of the decided root, the tip and a rebase's accumulator (lazy clones; a non-lazy clone gets the usual gap error from the preflight), then lays out only the files that come into view, from the decided root. The spec the conflict was checked against therefore stays inside the spec completion runs under, and nothing the stop wrote is rewritten.

**The conflict materialization fills first.** `materialize_conflict_state` runs `ensure_view(conflict_root)` before the first working-tree write, as every other materializer does, because a carried subtree can sit inside the view.

**Abort** checks the view before it removes anything. `merge --abort` runs `ensure_view(ours_root)` and the materialize preflight first and deletes the `.theirs` sidecars last, so a `GapInView` leaves the conflicted state intact and retryable. Its removal walk is the existing gap-tolerant present-only walk, so theirs' absent subtrees are skipped.

**`sc conflicts` and `sc resolve`** look a path up by descending its components (`entry_at`) instead of flattening a whole tree. A missing tree on the way is a gap error that names the path, never `Absent`: an absent side means the path is not in that snapshot, and a gap must not read as a deletion. On a full clone the result is identical.

### 9. Acceptance: differential tests built from real operations

`merge_trees` is checked against the flatten implementation, with both using the content/mode split of decision 1. The comparison is on **decrypted file sets, modes, perms, conflict sets, sidecars, effective rules and tombstones, the recipient set each protected blob is wrapped for, and actual decryption by each relevant identity**, not on wrap-map key coverage (which can pass with a missing recipient or a wrong DEK). Carried objects compare by bytes; freshly sealed output after decryption, because sealing is randomized. Cases are generated through real operations (`protect`, `grant`, `revoke`, commit, fetch) as well as arbitrary trees, and gaps are randomized independently of the sparse view and the filter. Required named cases:

- the mode and content cases from decision 1 (mode-only change, identical content with different mode on binary and on protected-keyless content, executable removal);
- file/directory collisions, including across a carried/enumerated boundary;
- plaintext under an existing rule on the carried side (decision 3), including the interrupted-`protect` state and the partial-clone graft state;
- shared blob ids across a deleted path and a carried path (decision 4);
- crossed revokes and regrants; nested prefix overrides (longest prefix wins);
- randomized equal-plaintext independent seals;
- every absence and kind combination in decision 2's table;
- an empty-directory entry on a carried side;
- merge then gc, and an interrupted fill then retry.

A second differential runs each merge on a partial clone and a full clone. The new engine is wired only for partial clones first; full clones keep the flatten path (with the decision 1 leaf key) until the differential has run clean for a release.

### 10. Replay: cherry-pick and rebase (amended in 37c-iv)

Replay is a three-way merge with a different base, and `replay_commit` is the only place cherry-pick and the rebase fold reach the file merge (its guard against partial clones, `partial_clone_unsupported("cherry-pick/rebase replay")`, is what this decision removes). So replay uses the engine of decisions 2 to 5 and the conflict contract of decision 8, and adds only what the fold needs.

- **The merge.** On a partial clone `replay_commit` calls `tree_merge_filled` with base = the replayed commit's parent (or the `--mainline` parent, or none for a root commit), ours = the onto tree, theirs = the commit. It fills outside the store lock, as merge does. Registry merging is unchanged: it is snapshot-level and already runs before the file replay.
- **Clean result.** The root is the enumerated files plus the carried subtrees (or the carried root), exactly as in merge. The wrap map is `merged_wraps` (the complete input union when anything was carried, else the existing prune). An `Empty` outcome still means the root equals the onto root and the commit's own rule delta is nil.
- **The fold's accumulator** (`acc_root`, `acc_protection`) may itself contain absent subtrees, because an earlier step carried them. That needs nothing new: the next step's engine pass sees an onto tree it may not hold and asks for what it reads. What the fold must add is the view: before the final materialize, `ensure_view(acc_root)` runs outside the store lock, and no ref, spec or working-tree file is written until it and the preflight succeed. The intermediate snapshots are CAS-only, so they stay unconstrained.
- **Conflict state** is decision 8 applied: `PICK_DECIDED_ROOT` and `REBASE_DECIDED_ROOT` hold the CAS-safe entries plus the carried subtrees, nothing is sealed while the op is open, and the same three refusals fire before any write (conflict outside the view, sidecar outside the view or over a tracked file, plaintext to seal outside the view). `ReplayOutcome::Conflicts` therefore carries the subtrees.
- **Completion.** `snapshot_files` accepts a recorded decided root for a pick or a rebase step as it does for a merge, grafts the out-of-view part from it, and keeps the union of the tip's and the picked commit's wraps. `rebase --continue` reads its parent's view first, since the accumulator can hold an in-view subtree no earlier step filled. A pick or rebase completion with no decided root still refuses.
- **Abort.** `cherry-pick --abort` and `rebase --abort` check the view before they delete anything and remove only sidecars the restored tree does not track, the same as `merge --abort`. `rebase --continue` removes only sidecars its completion parent does not track. A sidecar the user left behind and a commit swept up is the existing defect of q19's kind: completion reads untracked files.
- **Unchanged.** A rebase over a range that contains a merge commit still refuses before replaying anything. Sessions (`sc ws`, `sc work`) are ADR-0050.

## Phasing

- **37c-i, engine (built).** The content/mode split and the collision check on the flatten merge (with the ADR-0012 amendment and tests), `merge_trees` returning `TreeMerge` or `Needs`, the policy-intersection test, `TreeMergeDone::merged_wraps` (the wrap-union rule; assembling and pruning the merged snapshot's `protection.wrapped` from it is 37c-ii), and the differential tests (file sets with modes and perms, conflicts, sidecars, wraps, carried-subtree policy, and fills on a store with objects removed). Nothing calls the new engine yet except tests. Decision 9's cases built from real operations (protect, grant, revoke, with decryption by each identity), equal plaintext sealed independently, an empty-directory entry on a carried side, merge then gc, and an interrupted fill then retry need the repo layer and land with 37c-ii.
- **37c-ii, clean merge on a partial clone (built).** `merge_with_identity` uses the engine when the clone is partial: `Repo::tree_merge_filled` runs a pass under the store lock, fills what it asked for outside it (`Repo::fill_needs`, batched and split like every by-id fetch) and repeats; a conflict is refused with `PartialCloneUnsupported` before any write; the merged root is built by `Vfs::write_tree_with_carried` (enumerated files plus carried subtrees verbatim, or the carried root as is); `merged_wraps` is the wrap map, unpruned when anything was carried; `ensure_view(merged_root)` runs before the first ref, spec or working-tree write. The differing region's blobs are fetched too: the leaf merge returns file bytes even when one side wins by id, so a region both sides touched is read in full while an untouched subtree (identical on all three sides) is not. Cases from decision 9 that need real repo operations are covered by `partial_merge.rs`: disjoint carry without a fetch, the differing region (fill when lazy, gap error otherwise), a conflict refused, a carried protected subtree keeping its wraps, a keyless protected merge refusing before fetching (the merged result decrypts for the recipient and its plaintext never reaches the CAS), a carried subtree inside the view, and an interrupted fill followed by a retry. The carried wraps are checked byte for byte and by decrypting the carried ciphertext under the merged policy. Merge then gc is covered by the disjoint-carry test. Still open from decision 9: equal plaintext sealed independently, crossed revokes and regrants, an empty-directory entry on a carried side, and a randomized partial-versus-full differential. Demo: `demo/run_lazy_fetch_demo.sh` section 9.
- **37c-iii, conflicts (built).** The amendment to decision 8, then markers for in-view conflicts, completion from the decided root, abort, `sc conflicts` and `sc resolve`. A conflict outside the view, or a result that needs sealing outside it, is refused before any write. Tests in `partial_merge.rs` (conflict in view completes with the same tree as a full merge, carried subtree never fetched, abort, out-of-view refusals, carried protected subtree keeps its wraps through completion) and the CLI test `conflicting_merge_on_a_partial_clone_resolves_and_commits`. Demo section 10.
- **37c-iv, replay (built).** `cherry-pick` and `rebase` call the same engine through `replay_commit` (decision 10). Tests in `partial_replay.rs` compare each result with the same operation on a full repository by root tree id: a carried subtree never fetched, a differing region filled when lazy and refused otherwise, a conflict in the view completing like a full pick, abort and a view gap on abort, a carried protected subtree keeping its wraps, a rebase carrying the target's subtree through every step, a rebase stopping, aborting, resolving and continuing, and in-view carried subtrees filled on both paths. CLI test `cherry_pick_and_rebase_work_on_a_partial_clone`. Demo section 11.
- **Sessions** (`sc ws`, `sc work`): decided in ADR-0050. Workspaces see the host's view, and harvest lands through this engine.

## Consequences

- A partial clone can merge without holding the other side's whole tree, which is what a partial clone is for. A merge whose differing region intersects a protection rule fetches that region.
- Mode-only changes now merge on full clones too (decision 1), and a file/directory collision is rejected before any write instead of failing during materialization. Both are deliberate fixes and are called out in the release notes.
- A merged snapshot that carried subtrees holds the complete input wrap union, so it can be larger than the same merge on a full clone.
- Merge becomes an allow-listed network site for lazy clones.
- No wire change.

## Open questions

1. **Ciphertext fetched before a refusal it cannot avoid.** *Resolved in 37c-ii:* `plain_input` checks the identity requirement before it reads the blob, so a keyless lazy merge refuses without fetching the ciphertext (test `keyless_protected_merge_refuses_before_fetching_the_ciphertext`). The identity-free paths are unchanged.
2. **Fill progress.** *Resolved in 37c-ii:* `Repo::tree_merge_filled` fails with `Error::Protocol` when a pass asks again for an id an earlier round filled (a stale index entry would otherwise loop forever), and `fill_needs` verifies presence after each fill. Covered by `fill_loop_fails_when_a_filled_id_is_asked_for_again`.
3. **Mode change against a delete.** Ours changes only the mode and theirs deletes the file: the delete wins silently (content decides, as before). Git reports modify/delete. Unchanged by this work; decide separately.
4. **Pre-existing collisions.** Before the collision check, a clean cherry-pick or rebase that produced a file and a directory with the same name may already have committed such a snapshot. The fix prevents new ones and does not repair old ones.
5. **A `sc verify` check for plaintext under a rule** (decision 3's accepted divergence).
6. **Wrap growth.** Measure before designing a prune; `sc rewrap` on a partial clone is refused today.
7. **Switching full clones to the new engine.** Out of scope; decide after the differential has soaked.
8. **Merging a public branch INTO a private one** routes through `merge_into_private` and stays refused on a partial clone (ADR-0048 q10).
9. **Empty-directory normalization.** Decision 7 accepts the divergence; revisit if it shows up in real histories.
10. **Fill round trips.** A leaf reads its inputs one at a time and a pass records only the first missing blob per path, so a diff3-merged file both sides edited can take up to three rounds (ours, theirs, base), and every round re-walks the region. One connection serves all rounds of a merge (`NeedsFiller`). Collecting every missing input of a leaf in one pass, or having a pass skip finished regions, is a follow-on; measure first.
11. **Gap error names one path.** On a non-lazy clone the error names the first missing path; a second gap shows only after the first `sc backfill`. Whether `sc backfill <file path>` fetches the merge-base version of a file (the gap can be a blob path) is unverified.
12. **Plaintext copies across rounds.** A pass that returns `Needs` discards decrypted protected inputs held in plain `Vec`s that are not wiped. The full merge has the same exposure once; the fill loop repeats it per round. Memory hygiene only.

13. **Wrap sets differ between a clean and a conflicted completion.** A clean partial merge that carried a subtree keeps the union of ours, theirs and base wraps; a conflicted completion keeps ours and theirs, as a full clone does. No blob whose wrap exists only in base can reach the decided root, so nothing readable is lost, but the same merge can record a different `protection.wrapped` depending on whether it conflicted. A recipient revoked on both branches whose base wrap would otherwise come back is the visible case. Decide whether completion should read the merge base's wraps too.
14. **A sidecar next to an exact-file protection rule.** A protected binary conflict at `secret.bin` writes plaintext `secret.bin.theirs`; if the rule covers exactly `secret.bin`, the sidecar matches no rule and a later commit would read it back as a plain file. This predates partial clones (the scanner is the only guard). `sc resolve` removes it; a commit that leaves it behind should probably refuse.
15. **State durability.** `merge_state` renames without syncing, as the other state files do. A power loss between the decided-root write and `MERGE_HEAD` leaves a state that partial completion refuses and `merge --abort` clears.
16. **A protected delete-versus-modify conflict resolved to the absent side.** *Resolved:* a stopped merge, pick or rebase records the paths it wrote to disk in plaintext in `.sc/CONFLICT_PLAINTEXT` (`conflict_plaintext.rs`), and completion does not carry such a path back from a parent when it is absent from disk. The conflict path is not in the decided root (protected conflict plaintext lives on disk only), so before this the absent-protected carry restored it from the first parent, on full clones too. Test `resolving_a_protected_delete_modify_conflict_to_deletion_sticks`.
17. **Single-tip graft keeps what the built side decided.** `graft_out_of_sparse` carries an out-of-view file standing where the view expects a directory, unless the built side already holds that name (a file replaced by a directory in an ordinary commit).
18. **Abort can leave decrypted conflict plaintext behind.** *Resolved:* abort removes every recorded plaintext path the restored tree does not track as a plain file. The case was a protected delete-versus-modify conflict whose text is in neither the original nor the decided root, so the abort's removal walk never saw it. Test `aborting_a_conflict_whose_text_is_in_no_root_leaves_no_plaintext`.
19. **Completion can drop a newly tracked ignored file.** *Resolved:* completion reads the working tree with the decided root's paths counted as tracked, so an ignore rule cannot hide a file the operation itself added. Test `completing_a_conflicted_pick_keeps_an_added_file_the_parent_ignores`.
20. **A stopped pick or rebase without its decided root.** `PICK_DECIDED_ROOT` and `REBASE_DECIDED_ROOT` are written before the state's in-progress signal, so the state cannot normally be missing. If it is (a lost file, a power loss before the data reached disk), a partial clone's completion refuses, because grafting from the tip would keep the old out-of-view content; `--abort` still works.

21. **A conflict stop overwrites an ignored or untracked file at a plaintext path.** *Resolved for merge, cherry-pick and rebase:* `materialize_conflict_state` refuses, before any write, when a plaintext or sidecar path already exists on disk (as a file or directory, including a leftover sidecar) and the tree the working tree reflects does not track it, or when a file stands where a parent directory must be. A lookup that fails counts as untracked. *Also resolved for the clean paths:* `refuse_untracked_overwrite` runs before the first write of a merge (fast-forward, clean and conflict stop), `switch`, cherry-pick and rebase (fast-forward and the fold's final write) and refuses when a file the result adds, or a directory it needs, lands on something the tree the working tree reflects does not track. It reads the working tree only, skips paths outside the sparse view, and leaves a partial-clone gap to `materialize`'s own view check. A symlink at a written path always counts as occupied (a write would follow it out of the tree), and a tracked path outside the sparse view does not excuse a file in the way. `undo`, `sparse set` and `sparse disable` are guarded the same way (a sparse-spec change against the tree its old view laid out). Not guarded: merging into an unborn branch (there is no tree to call a file untracked against). The private-branch switch and merge are guarded inside `materialize_private` against the decrypted target paths. Tracking is compared by exact path, plus a case alias of a tracked path that is provably the same file (same device and inode, unix only), so a case-only rename on a case-insensitive filesystem is not refused; a non-unix build still compares exact paths. The private-branch merge stop (`merge_into_private`) writes its files directly and has no such guard. Tests `a_conflict_stop_refuses_to_overwrite_an_untracked_local_copy`, `a_conflict_stop_refuses_an_out_of_view_sealing_input_and_keeps_the_local_copy` (the sparse refusal now comes first for an out-of-view path), `a_binary_conflict_stop_refuses_over_an_untracked_sidecar` and `a_conflict_stop_refuses_when_a_file_blocks_a_parent_directory`.

## Alternatives considered

- **Fetch everything a merge might need first (`backfill --all`, then merge).** Correct and simple, and what the refusal message says today. It defeats the partial clone.
- **Make the flatten gap-tolerant and skip absent files.** Skipping absent paths silently drops them from the merged tree, the failure the commit graft's id-carry exists to prevent.
- **Carry every unchanged-by-id subtree and ignore protection rules.** The unsafe version ADR-0048 withdrew.
- **A "newly covered by a rule" carry test.** The first draft of this record. Unsound, because a side can already hold plaintext under its own rule (decision 3).
- **Server-side merge.** Still deferred (ROADMAP). It needs the server to hold keys for protected content or to refuse protected paths.
