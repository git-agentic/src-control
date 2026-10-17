# ADR-0049: Merge on partial clones (P37c)

- **Status:** Proposed
- **Date:** 2026-10-17
- **Phase:** 37c
- **Builds on:** ADR-0048 (presence-based partial clones), ADR-0047 (want-by-id fetch), ADR-0012 (three-way merge), ADR-0025 (protected merge and replay), ADR-0037 (partial clone)

## Context

ADR-0048 left merge, cherry-pick/rebase and sessions refused on a partial clone and listed what a correct implementation must respect. This record turns the merge half of that list into a design, after reading the code. Replay and sessions follow from it and are sketched at the end.

Today `sc merge` on a partial clone fast-forwards or adopts (no tree is rebuilt) and otherwise stops at `repo.rs:1349` with `PartialCloneUnsupported`. The reason is how a real merge works:

1. `three_way_files` (`merge.rs:191`) flattens all three trees to `path -> (blob id, mode, perms)` maps, merges path by path, and returns a flat `files` list.
2. `merge_with_identity` (`repo.rs:1385-1530`) routes that list through the protection rules (a carried plain file under a union rule is re-encrypted), rebuilds the whole tree with `write_tree_with_perms`, unions the wraps (`wrapped_carry` plus fresh wraps), prunes the wrap map to blobs reachable in the merged tree, materializes, and commits a two-parent snapshot.
3. A conflict leaves marker files and a persisted decided root (`merge_state`), and completion (`sc commit`) rebuilds from the working tree plus that decided root.

Every step reads every file of both sides. A partial clone does not hold them, so the flatten fails with a raw `NotFound` (hence the explicit refusal).

Almost all of that work is unnecessary. For a subtree where `ours == theirs`, `base == theirs`, or `base == ours` **by tree id**, the answer is known without reading anything below it. A merge only has to look inside a subtree where all three sides differ, and a partial clone typically has the changed region in its view. That is also how a tree-recursive merge becomes proportional to the change instead of to the repository.

ADR-0048 withdrew an earlier tree-recursive proposal because carrying a subtree by id is not always safe. This record keeps the idea and adds the checks that make it safe.

## Decisions

### 1. A tree-recursive three-way merge, with id-carry only where it is provably equal

Add `merge::merge_trees` next to the flatten implementation. It merges one directory level at a time over the union of entry names:

| Situation at a name | Result |
|---|---|
| `ours == theirs` (tree or blob id, mode and perms) | take ours |
| `base == theirs` | take ours |
| `base == ours` | take theirs |
| all three differ, all blobs | the existing file merge (diff3, protected-arm rules), unchanged |
| all three differ, all trees | recurse |
| kinds differ (file on one side, directory on another) | flatten **both** subtrees at that name and use the existing path rules; needs both present |

A subtree is read only in the recurse and flatten rows. In every other row its id is carried and its content is never read, so it may be absent.

The new function returns a merged tree id built bottom-up (so no `write_tree_with_perms` over a flat list), the set of conflicted paths, sidecars, and the wrap information described below. Verdicts are by presence-independent id equality, so the result does not depend on which subtrees the clone happens to hold, except where a row needs content.

### 2. Rows that need content are filled or refused, never failed raw

The recurse and flatten rows need all three subtrees present. A callback `ensure_present(&[ObjectId]) -> Result<()>` is passed in, so `merge.rs` stays network-free and `Store::get` stays network-free (the ADR-0047 rule):

- lazy and online: the callback fills the missing ids by id (`Filler`, same batching and splitting as ADR-0048);
- otherwise: it fails with `GapInView` naming the path and the `sc backfill` prefix, before anything is written.

Merge becomes an allow-listed network site for lazy clones, like the 37b-ii materializer sites. The fill touches only the region where all three sides differ, which is the region the merge is about.

### 3. The carry shortcut must respect protection rules

Carrying a subtree by id skips the step in `repo.rs:1395-1405` that encrypts a plain file under a union rule. A subtree may be carried from side S only if no rule in the **union** of the sides' rules newly covers a path under it, relative to S's own rules. A rule `R` newly covers a subtree at path `P` when `R` is not in S's rule set and either `R.prefix` is a prefix of `P` (it covers the whole subtree) or `R.prefix` lies inside `P` (it covers part of it).

When a rule newly covers a candidate subtree, that subtree is not carried: it is treated as a recurse row (read, route through the rules, re-encrypt). That needs the subtree present, so it follows decision 2. Rule sets are small, so the check is cheap; the common case (no new rule) carries.

### 4. Wraps are never dropped for a subtree that is not enumerated

`protection.wrapped` maps blob ids to wrapped DEKs. Today the merged map is rebuilt from the files that survive and pruned to blobs reachable in the merged tree. A carried subtree is never enumerated, so its blobs' wraps would be pruned, which permanently loses the ability of any recipient to decrypt that ciphertext. This is the same defect class as the commit-graft wrap bug fixed in P27 (`repo.rs:680-695`).

The rule for a partial merge is the one the graft already uses: **union in every wrap the inputs held** (ours, theirs, base) for ids the merge could not enumerate, and prune only against what it did enumerate. Over-retention of a wrap for a blob that is no longer reachable is harmless (history keeps the ciphertext and the wraps anyway; rotation is not erasure). Under-retention is data loss. A later `sc rewrap` prunes.

### 5. Conflicts in a partial merge

A conflict can only arise in a recurse or flatten row, which is already present. So conflict materialization writes markers only for present, in-view paths. A conflict outside the sparse view is refused with the `sc sparse set` hint the existing code uses (`repo.rs:1590`).

Completion needs more than today:

- the completion commit must graft from the **decided root** persisted in `merge_state`, not from HEAD's tree, because the decided root is what carries theirs-side changes outside the view (`graft_out_of_sparse` currently grafts from one parent only, `repo.rs:667`);
- the commit's guard at `repo.rs:411` (`merge/pick completion` refused on a partial clone) is replaced by that graft;
- `sc conflicts` and `sc resolve` (`conflicts.rs:147`, `:263`) flatten whole trees and need the same gap tolerance;
- gc's decided-root walk is already presence-based (ADR-0048, 37b-i).

Because completion is the riskiest piece, it is a separate phase after the clean case.

### 6. Secrets, rules and tombstones are unaffected

`merge_secrets` and the rule/tombstone union work on snapshot metadata, not trees, so they are unchanged.

### 7. Acceptance: a differential test, not a code-review argument

`merge_trees` is checked against the flatten implementation. On full clones, over randomly generated base/ours/theirs trees (varied depth, shared subtrees, protected and plain files, rule sets that newly cover subtrees, deletions, mode changes, file/directory kind changes), both must produce the same decrypted file set, the same conflict set and the same sidecars. Bytes are compared for carried objects; freshly sealed output is compared after decryption, because sealing is randomized (ADR-0043). A second differential runs the same merges on a partial clone and a full clone and compares the same things. A full-clone-only test cannot catch the wrap-pruning divergence in decision 4, so the partial/full comparison also compares the merged `protection.wrapped` coverage: every blob reachable in the merged tree must have a wrap whenever the full clone's merge has one.

The new engine is first wired only for partial clones. Full clones keep the flatten path until the differential has run clean for a release; switching them is a separate, optional step.

## Phasing

- **37c-i, engine.** `merge_trees` (pure, store-backed), the rule-aware carry check, wrap union for unenumerated subtrees, the `ensure_present` callback, and the differential tests (full-vs-full and partial-vs-full). No behavior change: nothing calls it yet.
- **37c-ii, clean merge on a partial clone.** Wire `merge_with_identity` to the engine when the clone is partial. A conflict is still refused (clean merges only), with a message that says so. Demo: two branches touching disjoint directories merge on a `--filter` clone without fetching either side's out-of-view content; a merge that touches an out-of-view conflict region fills it on a lazy clone and is refused on a non-lazy one.
- **37c-iii, conflicts.** Markers for present in-view conflicts, completion grafting from the decided root, `sc conflicts` and `sc resolve` on a partial clone, abort.
- **37c-iv, replay.** `cherry-pick` and `rebase` call the same engine (`replay.rs:176` is the only guard that blocks them; `three_way_files` is already their merge). Replay adds its own constraints: protected re-encryption under the replayed rules and the resumable-rebase state.
- **Sessions** (`sc ws`, `sc work`): undecided. They materialize whole checkouts per agent and auto-merge on harvest. Whether they should work on a partial clone at all is a product question, not an engine one.

## Consequences

- A partial clone can merge without ever holding the other side's whole tree, which is the point of a partial clone.
- The same engine is a candidate to make full-clone merges proportional to the change. This ADR does not take that step.
- A new network site (merge) exists for lazy clones, bounded to the all-differ region.
- The merged snapshot on a partial clone can carry more wraps than the same merge on a full clone. That is deliberate and documented (decision 4).
- No wire change.

## Open questions

1. **Tree id equality of rebuilt subtrees.** A tree built by `merge_trees` must hash exactly like the same tree built by `write_tree_with_perms` from a flat list (entry order, directory modes and perms, the empty-subtree case in ADR-0048 open question 8). The differential test compares ids for the no-conflict, no-encrypt case.
2. **Kind changes (file vs directory).** Decision 1 sends them through the flatten row. If real histories hit this often on partial clones, a dedicated row is worth adding; until then it needs both subtrees present.
3. **Rule check cost and shape.** The "newly covers" test assumes prefix rules. If rules ever grow beyond prefixes the check changes.
4. **Wrap over-retention growth.** Repeated partial merges accumulate wraps for dead blobs until a `sc rewrap`. Probably fine; measure before adding a prune.
5. **Switching full clones to the new engine.** Out of scope; decide after the differential has soaked.
6. **Interaction with private branches.** Merging a public branch INTO a private one routes through `merge_into_private`, a separate path. It stays refused on a partial clone (ADR-0048 q10).

## Alternatives considered

- **Fetch everything a merge might need first (`backfill --all`, then merge).** Correct and simple, and it is what the refusal message says today. It defeats the partial clone: a partial clone merging is exactly the case that wants to avoid the full transfer.
- **Make the flatten gap-tolerant and skip absent files.** Skipping absent paths silently drops them from the merged tree. Rejected: this is the failure the commit graft's id-carry exists to prevent.
- **Server-side merge.** Still deferred (ROADMAP). It would also solve this but needs the server to hold keys for protected content or to refuse protected paths.
- **Carry every unchanged-by-id subtree and ignore protection rules.** This is the unsafe version ADR-0048 withdrew: a union rule newly covering a carried plain subtree would leave plaintext in the merged snapshot.
