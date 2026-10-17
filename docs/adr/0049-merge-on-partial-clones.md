# ADR-0049: Merge on partial clones (P37c)

- **Status:** Proposed
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

### 1. Leaf equality is one rule, shared by both engines

The flatten merge resolves a plain path by **blob id alone** (`merge.rs:229-249`), and a protected path by `(blob id, PROTECTED)` (`merge.rs:312`). A mode-only change therefore loses today: base and ours hold blob X at `0644`, theirs holds X at `0755`; flatten sees ours' id equal to theirs' and keeps `0644`. A tree-level shortcut that compares whole entries would pick `0755`, so the two engines would disagree on the same merge.

Rather than keep two behaviors, 37c-i changes the flatten leaf comparison to the entry key `(blob id, mode, perms & PROTECTED)` and uses that key in both engines. This is a deliberate, small behavior change on full clones: a mode-only change on one side now merges (it is currently dropped). `RANDOMIZED` stays out of the key because it is a property of the blob. ADR-0012 gets an amendment note and a regression test (the 0644/0755 example).

### 2. A tree-recursive merge that carries only what it can prove safe

Add `merge::merge_trees` beside the flatten implementation. It works one directory level at a time over the union of entry names. A subtree is **carried by id, unread**, when:

- it is identical (same tree id) on all three sides, or
- the three sides do not all differ (`ours == theirs`, `base == theirs`, or `base == ours`, by tree id), **and** the subtree is policy-disjoint (decision 3).

Everything else is **enumerated**: read, flattened for that subtree, and resolved by the existing leaf rules (diff3, the protected arm, delete/modify), unchanged. Absence is explicit:

| Situation at a name | Result |
|---|---|
| tree on all three sides, all differ | recurse |
| tree on some sides, absent (or a blob) on others | enumerate the subtrees that exist and apply the per-path rules, so delete/modify and add/add keep their flatten meaning |
| blob on one side and a tree on another | enumerate both and apply the per-path rules; if that yields both `x` and `x/child`, the existing tree writer's error stands (this is unchanged) |
| blobs on all three, all differ | the existing leaf merge |

### 3. Policy-intersecting subtrees are always enumerated

A subtree is policy-disjoint when no rule in the **union** of the sides' rules covers it or lies inside it (`protect::matching_prefix` semantics: boundary-aware, longest prefix wins). A subtree that intersects a union rule and is not identical on all three sides is enumerated, never carried.

The first draft tested only whether a rule was *new* relative to the side being carried. That is not enough: the rule can already be on that side while plaintext sits under it. `protect` records the rule in a policy-only snapshot and encrypts in a second commit (`protect_ops.rs:85-105`), and a partial-clone commit encrypts only the sparse view and grafts the rest unchanged (`repo.rs:667`). The full merge encrypts every plain survivor under a union rule (`repo.rs:1403`) and would repair it; a carry would preserve it.

One accepted divergence: a subtree identical on all three sides is carried even under a rule, so a merge does not force a partial clone to fetch every protected prefix. Plaintext under a rule that is identical on all three sides was already in both parents; the merge introduces nothing. A full merge would repair it and a partial one leaves it. A `sc verify` check for that state is a follow-on.

Recipient-list changes alone do not require re-wrapping a carried ciphertext: the full merge already carries ciphertext unchanged and unions the wraps it knows (`repo.rs:1413`, `merge.rs:454`).

### 4. Wraps: keep the complete input union whenever anything was carried

`protection.wrapped` maps blob ids to wrapped DEKs. The full merge rebuilds it from surviving files and prunes to reachable blobs. A carried subtree is never enumerated, so pruning would drop the wraps of blobs inside it, which permanently loses every recipient's ability to decrypt them (the defect class the commit-graft fix closed, `repo.rs:699`).

A per-id rule ("prune what you enumerated") is unsound: a blob id seen as deleted at one path may survive under a carried subtree elsewhere, since ids alias across paths. So the rule is coarse: **if the merge carried any subtree, the merged map is the complete union of the input wraps** (ours, theirs, base, with the existing ours/theirs/base precedence and per-recipient dedup), plus fresh wraps. If it carried nothing, the existing prune applies. Union resurrecting a wrap for a recipient revoked since is the intended P16 behavior (tombstones gate future seals, not historical wraps; ADR-0026).

Over-retention costs size: wraps are inline in the snapshot, and an object above `MAX_OBJECT_SIZE` fails transfer. Nothing prunes dead entries today (`sc rewrap` refuses partial clones and only removes ids it upgrades, `rewrap.rs:164`, `:308`). So the growth is real and bounded by the repo's protected blob count; it is measured before any prune is designed.

### 5. The engine is pull-based; filling happens outside the store lock

`Filler` takes the store mutex (`fill.rs:283`), and the current merge engine runs while holding it (`repo.rs:1362`). A callback from inside the merge would deadlock. Instead `merge_trees` returns either a finished `TreeMerge` or `Needs(ids)`: the subtrees it must read and does not hold. The caller drops the lock, fills those ids (lazy and online) or fails with `GapInView` naming the path and the `sc backfill` prefix (otherwise), and calls again. Each round is idempotent, and progress is by presence.

The merged tree can also carry a subtree that is absent **inside the sparse view** (the fetch case from ADR-0048). So after the merge and before materializing, the caller runs `ensure_view(merged_root, sparse)`, as every other materializer site does. The claim that network traffic is bounded to the differing region is therefore "the differing region, the rule-intersecting region, and the view's closure".

Failure contract: a fill that fails midway leaves only immutable CAS additions. No ref, spec, working-tree file or merge state is written before the last fill and `ensure_view` have succeeded.

### 6. The result keeps plaintext out of the CAS

`TreeMerge` is not a bare tree id. It returns what `FileMerge` returns today (the enumerated `MergedFile` list with `needs_encrypt` plaintext, sidecars, conflicts, `wrapped_carry`) **plus** the carried subtrees as `(path, TreeEntry)` pairs. The existing pipeline (`repo.rs:1385-1530`) handles the enumerated files unchanged (routing through union rules, encryption, plaintext never written to the CAS). The carried entries are overlaid by id when the final tree is assembled. No new code path touches plaintext.

### 7. Tree semantics, stated plainly

Flatten drops empty directories and directory metadata and rebuilds directories with mode `0755`/perms `0` (`worktree.rs:348`, `vfs/lib.rs:175`); a carried subtree keeps whatever it has, including an empty directory entry that `graft_out_of_sparse` can produce (`worktree.rs:313`). Equivalence is defined on **file sets, modes and perms**, not on tree ids. A merged tree on a partial clone may differ from the full-clone merge by an empty directory entry. The differential test compares file sets, not ids.

### 8. Conflicts are deferred until their contract is specified

A conflict needs a state contract this record does not yet fix, and the review showed why it is not a detail:

- a conflicted merge's protected content merges produce plaintext that must live only on disk, with the CAS-safe decided root carrying everything else (`repo.rs:1420-1520`, `:1636`);
- an in-view conflict can coexist with a **clean protected content merge outside the view**; today that clean plaintext is written straight to disk, and a decided root alone does not preserve it, so completion would lose it;
- newly sealed decided blobs' wraps must survive a process restart, but merge state stores only the root (`merge_state.rs:68`) and completion reconstructs protection from the parents (`repo.rs:359`);
- presence does not imply the sparse view: a conflict outside the view needs the existing `sc sparse set` refusal, and abort must preflight and fill before it deletes sidecars (today it deletes them first, `repo.rs:1666`);
- `sc conflicts` and `sc resolve` flatten whole trees and need path-directed lookup (`conflicts.rs:147`, `:263`, `:329`).

37c-i and 37c-ii therefore support **clean merges only**: any conflict on a partial clone is refused with a message saying so, before anything is written. 37c-iii amends this record with the conflict contract (a CAS-safe decided root, ephemeral conflict plaintext, persisted fresh wraps or an explicit refusal of the conflict-plus-out-of-view-protected-merge combination) before it builds anything.

### 9. Acceptance: differential tests built from real operations

`merge_trees` is checked against the flatten implementation, with both on the shared leaf key of decision 1. The comparison is on **decrypted file sets, modes, perms, conflict sets, sidecars, effective rules and tombstones, the recipient set each protected blob is wrapped for, and actual decryption by each relevant identity**, not on wrap-map key coverage (which can pass with a missing recipient or a wrong DEK). Carried objects compare by bytes; freshly sealed output after decryption, because sealing is randomized. Cases are generated through real operations (`protect`, `grant`, `revoke`, commit, fetch) as well as arbitrary trees, and gaps are randomized independently of the sparse view and the filter. Required named cases:

- the mode-only change (0644/0755) from decision 1;
- plaintext under an existing rule on the carried side (decision 3), including the interrupted-`protect` state and the partial-clone graft state;
- shared blob ids across a deleted path and a carried path (decision 4);
- crossed revokes and regrants; nested prefix overrides (longest prefix wins);
- randomized equal-plaintext independent seals;
- every absence and kind combination in decision 2's table;
- an empty-directory entry on a carried side;
- merge then gc, and an interrupted fill then retry.

A second differential runs each merge on a partial clone and a full clone. The new engine is wired only for partial clones first; full clones keep the flatten path (with the decision 1 leaf key) until the differential has run clean for a release.

## Phasing

- **37c-i, engine.** The leaf-key fix on the flatten merge (with its ADR-0012 amendment and test), `merge_trees` returning `TreeMerge` or `Needs`, the policy-intersection test, the wrap-union rule, and the differential tests. Nothing calls the new engine yet except tests.
- **37c-ii, clean merge on a partial clone.** `merge_with_identity` uses the engine when the clone is partial: fill loop outside the lock, `ensure_view(merged_root)`, then the existing pipeline. A conflict is refused up front. Demo: two branches touching disjoint directories merge on a `--filter` clone without fetching either side's out-of-view content; a merge whose differing region is outside the view fills it on a lazy clone and is refused on a non-lazy one.
- **37c-iii, conflicts.** First an amendment to this record that fixes decision 8's contract, then markers for present in-view conflicts, completion from the decided root, abort, `sc conflicts` and `sc resolve`.
- **37c-iv, replay.** `cherry-pick` and `rebase` call the same engine; `replay.rs:176` is the only guard that blocks them, and `three_way_files` is already their merge. Replay adds protected re-encryption under the replayed rules and the resumable-rebase state.
- **Sessions** (`sc ws`, `sc work`): undecided. They materialize whole checkouts per agent and auto-merge on harvest. Whether they should work on a partial clone at all is a product question.

## Consequences

- A partial clone can merge without holding the other side's whole tree, which is what a partial clone is for. A merge whose differing region intersects a protection rule fetches that region.
- Mode-only changes now merge on full clones too (decision 1). This is a deliberate fix and is called out in the release notes.
- A merged snapshot that carried subtrees holds the complete input wrap union, so it can be larger than the same merge on a full clone.
- Merge becomes an allow-listed network site for lazy clones.
- No wire change.

## Open questions

1. **A `sc verify` check for plaintext under a rule** (decision 3's accepted divergence).
2. **Wrap growth.** Measure before designing a prune; `sc rewrap` on a partial clone is refused today.
3. **Switching full clones to the new engine.** Out of scope; decide after the differential has soaked.
4. **Merging a public branch INTO a private one** routes through `merge_into_private` and stays refused on a partial clone (ADR-0048 q10).
5. **Empty-directory normalization.** Decision 7 accepts the divergence; revisit if it shows up in real histories.

## Alternatives considered

- **Fetch everything a merge might need first (`backfill --all`, then merge).** Correct and simple, and what the refusal message says today. It defeats the partial clone.
- **Make the flatten gap-tolerant and skip absent files.** Skipping absent paths silently drops them from the merged tree, the failure the commit graft's id-carry exists to prevent.
- **Carry every unchanged-by-id subtree and ignore protection rules.** The unsafe version ADR-0048 withdrew.
- **A "newly covered by a rule" carry test.** The first draft of this record. Unsound, because a side can already hold plaintext under its own rule (decision 3).
- **Server-side merge.** Still deferred (ROADMAP). It needs the server to hold keys for protected content or to refuse protected paths.
