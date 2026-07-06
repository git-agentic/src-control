# P15 — Protected Merge & Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift the fail-closed protected-content guards from `sc merge`, `sc rebase`, and `sc cherry-pick` — id-level cases merge ciphertext without any key; content-divergent protected paths merge with `--identity`; the secret registry replays through rebase/cherry-pick.

**Architecture:** `three_way_files` becomes perms-aware: ciphertext-id fast paths (sound because convergent encryption maps equal plaintext to equal ciphertext id) need no identity and carry wrapped DEKs; content-divergent protected paths decrypt-on-demand with the caller's identity and emit plaintext flagged `needs_encrypt`, which lands through the same encrypt-and-reuse-wraps helper `commit` uses (extracted, single-sourced). Protection rules merge by union (fail-closed); replay reuses the whole core, preserving atomic rebase.

**Tech Stack:** Rust stable, edition 2021. Zero new dependencies, zero new crypto primitives (only existing `scl_crypto::{encrypt_path, decrypt_path, wrap_dek_for, unwrap_dek_with}`).

**Spec:** `docs/superpowers/specs/2026-07-06-p15-protected-merge-design.md` — read it first; the identity gate, union rules, `Empty` redefinition, and plaintext-never-enters-the-CAS invariant there are binding.

## Global Constraints

- **Plaintext never enters the CAS:** every `needs_encrypt` output is encrypted before any `write_tree`/`write_tree_with_perms` on every CAS path. Plaintext (incl. conflict markers/sidecars) may only reach the working tree of a caller holding a valid identity.
- **Identity gate:** id-resolvable protected cases require no identity; only content-divergent cases do (`ProtectedMergeNeedsIdentity(path)` when absent, `NotAuthorized(path)` when it cannot unwrap).
- **Union rules, fail-closed:** merged protection prefixes = union by `prefix`; recipients unioned (dedup by pubkey bytes) for a prefix present on both sides. `PROTECTED` perms survive every path; perms-divergence resolves protected.
- **Atomic rebase preserved:** all snapshots CAS-only until the single ref move; materialize before ref move; oplog record last (P14 discipline).
- Crypto quarantined in `crates/crypto`; `gitio` untouched; dependency direction unchanged; no new deps.
- Content addressing/encoding unchanged; oplog semantics unchanged; P9/P10 export confidentiality gate untouched.
- Errors: thiserror variants in `crates/repo/src/error.rs`. `Error::MergeProtected` retires in Task 5, `Error::ReplayProtected` in Task 8.
- Plain-content behavior must stay byte-identical (the existing merge/replay test corpus is the regression net).
- Every public type/fn gets an intent doc comment; disk tests clean up + assert gone; `cargo test` green before every commit.

## Verified interfaces you build on

- `Protection { prefixes: Vec<ProtectPrefix>, wrapped: BTreeMap<ObjectId, Vec<WrappedKey>> }`; `ProtectPrefix { prefix: String, recipients: Vec<[u8; 32]> }`; `WrappedKey { recipient_id: String, wrapped_dek: Vec<u8> }` (crates/core/src/object.rs:25-36,110-113)
- `protect::matching_prefix(&Protection, path) -> Option<&ProtectPrefix>` (crates/repo/src/protect.rs:6)
- `scl_crypto::encrypt_path(&[u8]) -> (Vec<u8>, Zeroizing<[u8;32]>)` (convergent); `decrypt_path(&[u8], &[u8;32]) -> Result<Zeroizing<Vec<u8>>>`; `wrap_dek_for(&dek, &PublicKey) -> WrappedKey`; `unwrap_dek_with(&WrappedKey, &SecretKey) -> Result<Zeroizing<[u8;32]>>` (crates/crypto/src/envelope.rs)
- `merge::three_way_files(store, base_root: Option<ObjectId>, ours_root, theirs_root) -> Result<FileMerge>` where `FileMerge { files: Vec<(String, FileMode, Vec<u8>)>, sidecars, conflicts }` (crates/repo/src/merge.rs:60-110); `merge::three_way(store, base, ours, theirs) -> Result<Merge>` (merge.rs:81); `merge_secrets(base, ours, theirs)` (merge.rs:213)
- `worktree::tree_file_entries_with_perms(store, root) -> BTreeMap<String, (ObjectId, FileMode, u8)>`; `scl_core::PROTECTED`
- `snapshot_files`'s encrypt block (crates/repo/src/repo.rs:184-200) and wrap-reuse block (further down, `let prior = std::mem::take(&mut protection.wrapped)`)
- `replay::{replay_commit, ReplayOutcome}` (crates/repo/src/replay.rs:33,55); `Repo::{cherry_pick, rebase}` same file; guards: merge's `MergeProtected` loop (repo.rs, search `MergeProtected`), replay's guard (replay.rs, search `ReplayProtected`)
- CLI: `resolve_identity_opt(Option<PathBuf>) -> Result<Option<SecretKey>>` (soft; crates/cli/src/main.rs); `Merge`/`Rebase`/`CherryPick` clap variants

---

### Task 1: Roadmap P15 entry + ADR-0025 (Proposed)

**Files:**
- Modify: `ROADMAP.md`
- Create: `docs/adr/0025-protected-merge-and-replay.md`

**Interfaces:** docs only; Task 11 flips to Accepted.

- [ ] **Step 1: ROADMAP Active section**

Insert after `## Done`:

```markdown
## Active

- **Phase 15 — Protected merge & replay.** Lift the fail-closed guards:
  `sc merge`/`sc rebase`/`sc cherry-pick` work on protected content.
  Id-level cases (unchanged / one side changed / clean deletes) resolve on
  ciphertext ids — sound under convergent encryption — carrying wrapped
  DEKs, with no identity required; only a content-divergent protected path
  needs `--identity` (typed error otherwise). Protection rules merge by
  union (nothing silently unprotects); merged plaintext re-encrypts through
  the same wrap-reuse helper commit uses; the secret registry replays
  through rebase/cherry-pick (closing P14's warning). Plaintext never
  enters the CAS.
  Spec: `docs/superpowers/specs/2026-07-06-p15-protected-merge-design.md`.
  (ADR-0025, Proposed.)
```

- [ ] **Step 2: ADR-0025 (Proposed)** — match ADR-0024's header format:

```markdown
# ADR-0025: Protected merge & replay — perms-aware three-way with decrypt-on-demand

- **Status:** Proposed
- **Date:** 2026-07-06
- **Phase:** 15
- **Builds on:** ADR-0012 (three-way merge), ADR-0014 (encrypted paths),
  ADR-0019 (lifecycle/escrow), ADR-0024 (history editing)

## Context

Since P7, every merge/rebase/cherry-pick fails closed when any involved
tree carries a PROTECTED entry (`three_way` flattens trees without perms;
replaying ciphertext as plain blobs would corrupt it). The confidentiality
pillar therefore blocks the core collaboration workflow. P14 added the
replay toolkit, widening the gap.

## Decision

- **Id-level resolution on ciphertext is sound** because path encryption is
  convergent: equal plaintext ⇒ equal ciphertext blob id. Unchanged /
  one-side-changed / clean-delete protected cases resolve by id comparison,
  carrying ciphertext + wrapped DEKs (union when both sides know a blob),
  with no identity — a non-recipient can merge non-colliding protected
  branches.
- **Decrypt-on-demand for content divergence only.** Both-changed,
  delete-vs-modify, and perms-divergent protected paths require an
  authorized `--identity`; the plaintexts are diff3-merged and the output
  is re-encrypted before any CAS write via the same encrypt-and-reuse-
  prior-wraps helper `commit` uses (extracted; single-sourced).
- **Protection rules merge by union, fail-closed:** prefix union;
  recipient-set union per shared prefix. Nothing silently unprotects.
- **Secret registry replays** through rebase/cherry-pick via the existing
  `merge_secrets`; replay's `Empty` now means tree-empty AND
  registry-delta-empty, so secrets-only commits replay instead of skipping.
- Conflicted protected merges write plaintext markers only to the working
  tree of the identity-holder — P7's existing checkout trust boundary.

## Alternatives considered

- Decrypt-everything-first: contradicts the identity gate (trivial cases
  would demand a key) and churns wraps on untouched files.
- Working-tree-mediated merge: maximum reuse but dirties the tree on clean
  merges and breaks rebase's all-in-CAS atomicity.
- Conflict-on-any-protected-divergence (never decrypt): every concurrent
  edit becomes a manual conflict; weak capability.

## Consequences

- Merge/replay of protected content is identity-gated exactly where
  plaintext is required, and nowhere else.
- Re-encryption of merged content produces fresh wraps for new blob ids;
  prior-wrap reuse keeps unchanged content's encoding stable.
- Rule narrowing cannot happen via merge (union); explicit unprotect
  remains a future operation.
```

- [ ] **Step 3: Commit**

```bash
git add ROADMAP.md docs/adr/0025-protected-merge-and-replay.md
git commit -m "docs: roadmap P15 active — protected merge & replay; ADR-0025 proposed"
```

---

### Task 2: `protect` helpers — rules union + DEK unwrap/decrypt

Small pure functions the core needs, testable in isolation.

**Files:**
- Modify: `crates/repo/src/protect.rs`
- Test: same file's `#[cfg(test)] mod tests` (create if absent)

**Interfaces:**
- Produces (used by Tasks 4-8):

```rust
/// Union of two protection policies' prefix rules: prefixes united by
/// `prefix` string; a prefix present on both sides unions its recipient
/// sets (deduped by pubkey bytes). Fail-closed: nothing present on either
/// side is dropped.
pub(crate) fn union_prefixes(a: &[ProtectPrefix], b: &[ProtectPrefix]) -> Vec<ProtectPrefix>

/// Decrypt a protected blob's ciphertext using `identity`, searching the
/// given protection maps (in order) for its wrapped DEKs. Errors:
/// `NotAuthorized(path)` when no wrap unwraps; `ProtectedMergeNeedsIdentity(path)`
/// is the CALLER's error when identity is None — this fn requires one.
pub(crate) fn decrypt_with(
    ciphertext: &[u8],
    blob_id: &ObjectId,
    protections: &[&Protection],
    identity: &scl_crypto::SecretKey,
    path: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>>

/// Union two wrapped-DEK lists, deduped by recipient_id (first occurrence wins).
pub(crate) fn union_wraps(a: &[WrappedKey], b: &[WrappedKey]) -> Vec<WrappedKey>
```

(If the `zeroize` re-export isn't visible from `scl-repo`, return the plain `Vec<u8>` inner type via `.to_vec()` — check how `scl_crypto` exposes `Zeroizing` first; `run_with_secret` handling in cli shows the pattern.)

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn union_prefixes_unions_by_prefix_and_recipients() {
    let a = vec![ProtectPrefix { prefix: "secret/".into(), recipients: vec![[1; 32]] }];
    let b = vec![
        ProtectPrefix { prefix: "secret/".into(), recipients: vec![[1; 32], [2; 32]] },
        ProtectPrefix { prefix: "keys/".into(), recipients: vec![[3; 32]] },
    ];
    let u = union_prefixes(&a, &b);
    assert_eq!(u.len(), 2);
    let secret = u.iter().find(|p| p.prefix == "secret/").unwrap();
    assert_eq!(secret.recipients.len(), 2); // [1;32] deduped, [2;32] added
    assert!(u.iter().any(|p| p.prefix == "keys/"));
}

#[test]
fn decrypt_with_unwraps_for_recipient_and_rejects_stranger() {
    let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
    let (mallory_sk, _) = scl_crypto::generate_keypair();
    let (cipher, dek) = scl_crypto::encrypt_path(b"hello");
    let blob_id = scl_core::Object::blob(cipher.clone()).id();
    let mut prot = Protection::default();
    prot.wrapped.insert(blob_id, vec![scl_crypto::wrap_dek_for(&dek, &alice_pk)]);
    let pt = decrypt_with(&cipher, &blob_id, &[&prot], &alice_sk, "secret/x").unwrap();
    assert_eq!(&pt[..], b"hello");
    let err = decrypt_with(&cipher, &blob_id, &[&prot], &mallory_sk, "secret/x").unwrap_err();
    assert!(matches!(err, Error::NotAuthorized(_)));
}

#[test]
fn union_wraps_dedups_by_recipient_id() {
    // two wraps for the same recipient + one different → 2 entries.
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo protect::` → FAIL (fns missing).

- [ ] **Step 3: Implement** (straightforward; `decrypt_with` searches each protection's `wrapped.get(blob_id)`, tries `unwrap_dek_with` per wrap, `decrypt_path` on first success; exhausted → `Err(Error::NotAuthorized(path.to_string()))`).

- [ ] **Step 4: Run tests** — `cargo test -p scl-repo protect` → green; whole crate green.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/protect.rs
git commit -m "feat(repo): protect helpers — prefix-rule union, wrap union, identity decrypt (P15)"
```

---

### Task 3: Extract the shared encrypt-and-reuse-wraps helper

Pure refactor of `snapshot_files`: the encrypt loop (repo.rs:184-200) and the prior-wrap-reuse block become one shared helper. Behavior byte-identical; existing tests are the net.

**Files:**
- Modify: `crates/repo/src/protect.rs` (new helper), `crates/repo/src/repo.rs` (`snapshot_files` calls it)

**Interfaces:**
- Produces (used by Tasks 5-8):

```rust
/// Convergently encrypt `plaintexts` (path, bytes, mode, rule recipients),
/// wrapping each fresh DEK to its recipients. Returns the ciphertext write-set
/// entries (PROTECTED perms) and fresh wraps keyed by ciphertext blob id.
pub(crate) fn encrypt_protected(
    plaintexts: Vec<(String, Vec<u8>, FileMode, Vec<[u8; 32]>)>,
) -> (Vec<(String, Vec<u8>, FileMode, u8)>, BTreeMap<ObjectId, Vec<WrappedKey>>)

/// Prior-wrap reuse: for each (blob_id, recipient_id) already wrapped in
/// `prior`, keep the prior wrap bytes so unchanged content's protection
/// encoding (and thus snapshot ids) stays stable. Mutates `fresh` in place.
pub(crate) fn reuse_prior_wraps(
    fresh: &mut BTreeMap<ObjectId, Vec<WrappedKey>>,
    prior: &BTreeMap<ObjectId, Vec<WrappedKey>>,
)
```

- [ ] **Step 1: Green baseline** — `cargo test -p scl-repo` (record count).
- [ ] **Step 2: Extract** — move the two blocks verbatim (comments included) into the helpers; `snapshot_files` calls them; the carry-forward block between them stays in place.
- [ ] **Step 3: Run** — `cargo test` same count, all green.
- [ ] **Step 4: Commit**

```bash
git add crates/repo/src/protect.rs crates/repo/src/repo.rs
git commit -m "refactor(repo): extract encrypt_protected + reuse_prior_wraps — merge/replay reuse commit's crypto discipline (P15)"
```

---

### Task 4: Perms-aware `three_way_files` (the core)

**Files:**
- Modify: `crates/repo/src/merge.rs` (`FileMerge`, `three_way_files`, `three_way`)
- Modify: `crates/repo/src/error.rs`:

```rust
#[error("protected path {0} changed on both sides; re-run with --identity <key> to merge its content")]
ProtectedMergeNeedsIdentity(String),
```

- Modify: `crates/repo/src/repo.rs` + `crates/repo/src/replay.rs` — mechanical adaptation to the new output type ONLY (their protected guards STAY in this task, so `needs_encrypt` outputs are unreachable from them; map `MergedFile` down to the old triples with a `debug_assert!(!f.needs_encrypt)`).
- Test: `crates/repo/src/merge.rs` tests

**Interfaces:**
- Produces (used by Tasks 5-8):

```rust
pub(crate) struct MergedFile {
    pub path: String,
    pub mode: FileMode,
    pub bytes: Vec<u8>,      // ciphertext when carried; plaintext when needs_encrypt
    pub perms: u8,           // PROTECTED preserved
    pub needs_encrypt: bool,
}

pub(crate) struct FileMerge {
    pub files: Vec<MergedFile>,
    pub sidecars: Vec<(String, Vec<u8>)>,   // plaintext for protected binary conflicts
    pub conflicts: Vec<String>,
    pub wrapped_carry: BTreeMap<ObjectId, Vec<WrappedKey>>,
}

pub(crate) fn three_way_files(
    store: &mut Store,
    base: Option<(ObjectId, &Protection)>,
    ours: (ObjectId, &Protection),
    theirs: (ObjectId, &Protection),
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<FileMerge>

pub fn three_way(
    store: &mut Store,
    base: ObjectId,
    ours: ObjectId,
    theirs: ObjectId,
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<Merge>   // Merge.files becomes Vec<MergedFile>; secrets unchanged
```

Resolution rules (binding, from the spec):
- Read all sides with `tree_file_entries_with_perms`. A path is "protected" if ANY side's entry has the `PROTECTED` bit.
- **All-plain path:** existing logic verbatim (`perms: 0, needs_encrypt: false`).
- **Protected, id-resolvable** (ciphertext-id equality gives: same both sides / only one side differs from base / cleanly deleted): winner's raw ciphertext bytes carried, `perms: PROTECTED, needs_encrypt: false`; wraps for the surviving blob copied into `wrapped_carry` via `protect::union_wraps` over whichever side(s') `protection.wrapped` know it.
- **Protected, content-divergent** (both differ from base and from each other; delete-vs-modify; or the PROTECTED bit itself differs between sides): `identity` required — `None` → `Err(ProtectedMergeNeedsIdentity(path))`. Decrypt each protected input via `protect::decrypt_with` (plain-side inputs used as-is); diff3 the plaintexts with the existing text/binary/delete rules; output plaintext `needs_encrypt: true, perms: PROTECTED`. Conflicts/markers/sidecars in plaintext.
- Base entry PROTECTED handling: a protected base with plain sides (rule was removed historically) — decrypt base too (identity path) so diff3 has the true ancestor.

- [ ] **Step 1: Write the failing tests**

Build fixtures with a real temp `Repo` + `sc protect`-style seeding (see `protect_ops.rs` tests) so wraps exist. Tests:

```rust
#[test] fn protected_id_fast_paths_need_no_identity() {
    // one side edits secret/a.txt, other side edits secret/b.txt (disjoint);
    // three_way_files with identity None → both changes present as ciphertext,
    // needs_encrypt false everywhere, wrapped_carry has both blob ids,
    // conflicts empty.
}
#[test] fn protected_both_changed_requires_identity() {
    // both sides edit secret/a.txt differently; identity None →
    // Err(ProtectedMergeNeedsIdentity("secret/a.txt")).
}
#[test] fn protected_both_changed_merges_plaintext_with_identity() {
    // non-overlapping line edits; with alice's identity → one MergedFile,
    // needs_encrypt true, bytes contain both edits, conflicts empty.
}
#[test] fn protected_conflict_carries_plaintext_markers() {
    // same-line edits; with identity → conflicts=["secret/a.txt"],
    // bytes contain "<<<<<<<" and both plaintexts.
}
#[test] fn unauthorized_identity_is_not_authorized() {
    // mallory's key → Err(NotAuthorized(_)).
}
#[test] fn perms_divergence_resolves_protected() {
    // ours committed x.txt plain; theirs committed it protected (rule added
    // there); with identity → output perms has PROTECTED, needs_encrypt true.
}
#[test] fn plain_merges_unchanged() {
    // an all-plain three-way produces byte-identical outcome to a captured
    // pre-change expectation (also implicitly guarded by the whole existing suite).
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo three_way` → FAIL.
- [ ] **Step 3: Implement** per the rules above. Keep the per-path plain logic verbatim inside the all-plain arm.
- [ ] **Step 4: Mechanical adaptation of existing consumers** — `Repo::merge` (guard still present) and `replay_commit` (guard still present) map `MergedFile { path, mode, bytes, .. }` to their existing triple usage with `debug_assert!(!f.needs_encrypt)`; `three_way` callers pass `None` identity for now.
- [ ] **Step 5: Run** — `cargo test` whole workspace all green (existing corpus proves plain behavior intact).
- [ ] **Step 6: Commit**

```bash
git add crates/repo/src/merge.rs crates/repo/src/error.rs crates/repo/src/repo.rs crates/repo/src/replay.rs
git commit -m "feat(repo): perms-aware three_way_files — ciphertext-id fast paths + identity-gated content merge (P15)"
```

---

### Task 5: `Repo::merge` — clean protected merges + CLI `--identity`

**Files:**
- Modify: `crates/repo/src/repo.rs` (`merge` → `merge_with_identity`; guard removal), `crates/repo/src/error.rs` (delete `MergeProtected`), `crates/cli/src/main.rs`
- Test: repo.rs tests

**Interfaces:**
- Produces: `pub fn merge_with_identity(&self, branch: &str, author: &str, identity: Option<&scl_crypto::SecretKey>) -> Result<ObjectId>`; `pub fn merge(&self, branch, author)` delegates with `None` (signature unchanged for existing callers/tests).

Flow changes inside the real-three-way arm:
1. **Delete the `MergeProtected` guard loop** (and the error variant; fix the one demo/tests referencing it if any — grep).
2. Call `three_way(store, base, ours, theirs, identity)?`.
3. Build the write set with perms: carried entries as-is; `needs_encrypt` entries → collect `(path, bytes, mode, recipients)` where recipients come from `protect::matching_prefix` against the **union rules** (`protect::union_prefixes(&ours_prot.prefixes, &theirs_prot.prefixes)`) — a `needs_encrypt` path with no matching union rule falls back to the perms bit side's rule; if genuinely none (rule removed on both sides), keep it protected using the union of the blob's prior recipients from `wrapped_carry`… simpler and binding: **encrypt to the union-rule recipients; if no union rule matches, error `NotProtected(path)`** (cannot happen when perms came from a rule — assert-style guard).
4. `protect::encrypt_protected` + escrow auto-append exactly as commit does (reuse how `snapshot_files` collects recipients incl. escrow — read it; if escrow append lives in the CLI layer, keep parity with commit's behavior, not more).
5. Merged tree via `write_tree_with_perms`; merged protection: `prefixes = union_prefixes`, `wrapped = wrapped_carry ∪ fresh` then `reuse_prior_wraps` against ours' prior map, pruned to blobs in the merged tree (commit's rebuild discipline — copy that pruning approach).
6. Clean merge commits two parents as today (materialize before ref advance is already merge's order; keep it), with protection-aware materialize: pass the merged protection + identity so protected files decrypt for recipients and skip otherwise (replaces the `Protection::default()` shortcut).
7. ff/adopt fast paths unchanged (single-side content; already protection-aware via `switch`-style materialize — verify they pass the right protection; they do today).

CLI: `Merge` variant gains `#[arg(long)] identity: Option<PathBuf>`; handler resolves via `resolve_identity_opt` and calls `merge_with_identity`; skipped-paths from materialize printed as in switch (check what merge prints today and keep parity).

- [ ] **Step 1: Failing tests**

```rust
#[test] fn non_recipient_merges_disjoint_protected_branches() {
    // alice protects secret/ + commits a.txt; branch b1 edits secret/a.txt,
    // branch b2 (from same base) adds secret/b.txt. A repo clone WITHOUT any
    // identity merges b2 into b1's line via merge(None) → succeeds; both
    // ciphertext blobs present; alice (identity) can still decrypt both via
    // switch_with_identity materialize.
}
#[test] fn content_divergent_merge_without_identity_refuses_cleanly() {
    // colliding edits; merge(None) → Err(ProtectedMergeNeedsIdentity);
    // refs untouched, working tree untouched, no merge state.
}
#[test] fn content_merge_with_identity_reencrypts_for_all_recipients() {
    // secret/ protected to alice AND bob; colliding-but-mergeable edits;
    // merge_with_identity(alice) → clean two-parent snapshot; the merged
    // blob decrypts with BOTH alice's and bob's keys (unwrap via protection.wrapped).
}
#[test] fn rules_union_survives_merge_and_governs_future_commits() {
    // theirs adds protect rule keys/ + a protected file; ours never had it;
    // merge → merged snapshot's prefixes contain keys/; then commit a NEW
    // plaintext file under keys/ → it lands PROTECTED (the leak test).
}
#[test] fn merged_plaintext_never_lands_in_cas() {
    // after content merge, iterate the merged tree entries: every PROTECTED
    // entry's blob bytes != the known plaintext (and decrypt_path with the
    // right DEK == plaintext).
}
#[test] fn convergent_merge_ids_are_stable_across_repos() {
    // build the identical protected divergence in two independent temp repos
    // (same base plaintext, same edits both sides); content-merge each with
    // its own recipient identity → the merged PROTECTED blob id is IDENTICAL
    // in both repos (convergence: equal merged plaintext ⇒ equal ciphertext id).
}
```

- [ ] **Step 2: Run to verify failure** — the guard currently returns `MergeProtected`; tests FAIL.
- [ ] **Step 3: Implement** per flow above.
- [ ] **Step 4: Run** — `cargo test` whole workspace; existing merge corpus green.
- [ ] **Step 5: Commit**

```bash
git add crates/repo/src crates/cli/src/main.rs
git commit -m "feat: sc merge handles protected paths — ciphertext fast paths keyless, content merges via --identity (P15)"
```

---

### Task 6: Conflicted protected merges + merge-completion rules union

**Files:**
- Modify: `crates/repo/src/repo.rs` (merge conflict path; `snapshot_files` merge-completion protection)
- Test: repo.rs tests

**Interfaces:**
- Consumes: Task 4/5 outputs. Produces: behavior only.

Changes:
1. **Conflict path:** the conflicted working set now contains plaintext `needs_encrypt` files (markers) — reachable only with identity. Materialize them to the working tree as plaintext (they must be editable); carried ciphertext entries materialize via the protection-aware path (decrypt for the identity; skip + report if some other prefix's key is missing). Plaintext sidecars written as today. Merge state unchanged. **The marker tree written to the CAS for materialize purposes must NOT contain plaintext** — restructure so conflicted files are written to the working tree directly (like sidecars) rather than through a CAS tree, OR encrypt marker files before the CAS write; choose the direct-write restructure (no throwaway plaintext CAS objects; document in a comment). Check how merge currently materializes the conflict set (via `merged_root` + `materialize`) and restructure accordingly: build the CAS tree from carried/plain entries only, write `needs_encrypt` conflict files straight to disk with `safe_join`.
2. **Merge completion:** in `snapshot_files`, when `merge_head` is `Some`, protection prefixes = `union_prefixes(tip's, merge_head's)` (instead of tip-only), so re-encryption at `sc commit` honors theirs-side rules. Wrap-reuse gets the union of both parents' `wrapped` as `prior`.

- [ ] **Step 1: Failing tests**

```rust
#[test] fn conflicted_protected_merge_resolves_via_commit_reencryption() {
    // same-line edits on secret/a.txt, both alice-and-bob recipients;
    // merge_with_identity(alice) → Err(MergeConflicts(1)); on-disk
    // secret/a.txt contains "<<<<<<<" plaintext; NO CAS object contains the
    // marker plaintext (scan store loose objects for the marker bytes);
    // resolve the file, commit → two-parent snapshot; merged blob decrypts
    // for bob too.
}
#[test] fn merge_completion_honors_theirs_side_rules() {
    // theirs adds keys/ rule + file AND a conflicting plain-file edit (so the
    // merge conflicts on the plain file); resolve + commit; committing also a
    // new file under keys/ in the same commit → it lands PROTECTED.
}
```

- [ ] **Step 2: Run to verify failure**, **Step 3: implement**, **Step 4: `cargo test` green**, **Step 5: Commit**

```bash
git add crates/repo/src/repo.rs
git commit -m "feat(repo): conflicted protected merges — plaintext markers to worktree only; completion unions rules (P15)"
```

---

### Task 7: Replay core threading + `cherry_pick --identity`

**Files:**
- Modify: `crates/repo/src/replay.rs` (`replay_commit` signature, `ReplayOutcome`, `cherry_pick`), `crates/cli/src/main.rs` (CherryPick `--identity`)
- Test: replay.rs tests

**Interfaces:**
- Produces (Task 8 consumes):

```rust
pub(crate) enum ReplayOutcome {
    Clean {
        root: ObjectId,
        /// Assembled protection for the replayed snapshot: union rules
        /// (onto-side ∪ commit-side), wrapped = carry ∪ fresh (wrap-reused).
        protection: Protection,
    },
    Empty,
    Conflicts { files: Vec<MergedFile>, sidecars: Vec<(String, Vec<u8>)>, paths: Vec<String> },
}

pub(crate) fn replay_commit(
    repo: &Repo,
    commit_id: ObjectId,
    onto: (ObjectId /*root*/, &Protection),
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<ReplayOutcome>

pub fn cherry_pick(&self, refname: &str, author: &str, identity: Option<&scl_crypto::SecretKey>) -> Result<PickResult>
```

- Remove replay's protected guard; `ReplayProtected` stays until Task 8 deletes it (rebase still references it until then — actually remove uses here and delete the variant in Task 8 when the last reference goes; if rebase doesn't reference it, delete the variant HERE and note it).
- Clean path builds the tree with `write_tree_with_perms` (needs_encrypt entries encrypted first via `protect::encrypt_protected` against the union rules, wrap-reuse against onto-side prior). `build_snapshot` gets the assembled protection instead of the onto-side's verbatim.
- Cherry-pick conflict path: same worktree-direct-write restructure as Task 6 for `needs_encrypt` conflict files (no plaintext CAS objects); pick state unchanged; the completing commit picks up union rules the same way merge completion does — pick has no `merge_head`, so `snapshot_files` needs the picked commit's rules too: persist the picked commit id in PICK_HEAD (already done) and have `snapshot_files` union tip's rules with the picked commit's when pick state is present (mirror the merge-completion change; read PICK_HEAD in `commit`).
- CLI: `--identity` soft-resolve; ordering (materialize before ref move, oplog last) unchanged.

- [ ] **Step 1: Failing tests**

```rust
#[test] fn cherry_pick_disjoint_protected_commit_needs_no_identity() { /* ciphertext carried; branch advanced; recipients decrypt */ }
#[test] fn cherry_pick_content_divergent_requires_identity_and_reencrypts() { /* None → typed error, refs untouched; with identity → Picked; all recipients decrypt */ }
#[test] fn cherry_pick_protected_conflict_writes_plaintext_markers_worktree_only() { /* markers on disk, none in CAS; resolve + commit completes; PROTECTED preserved */ }
```

- [ ] **Step 2-5:** fail → implement → `cargo test` green → commit

```bash
git add crates/repo/src crates/cli/src/main.rs
git commit -m "feat: sc cherry-pick handles protected paths via the perms-aware replay core (P15)"
```

---

### Task 8: `rebase --identity` + retire `ReplayProtected`

**Files:**
- Modify: `crates/repo/src/replay.rs` (`rebase` threading), `crates/repo/src/error.rs` (delete `ReplayProtected`, and `MergeProtected` if any straggler), `crates/cli/src/main.rs` (Rebase `--identity`)
- Test: replay.rs tests

**Interfaces:**
- Produces: `pub fn rebase(&self, target: &str, author: &str, identity: Option<&scl_crypto::SecretKey>) -> Result<RebaseResult>`.

Flow: the fold threads `(acc_root, &acc_protection)` — each `Clean { root, protection }` becomes the next accumulator; `build_snapshot` uses the assembled protection. Abort semantics unchanged: `ProtectedMergeNeedsIdentity`/`NotAuthorized`/conflicts abort with refs byte-identical, naming the commit. Final materialize passes the last assembled protection + identity.

- [ ] **Step 1: Failing tests**

```rust
#[test] fn rebase_protected_branch_by_non_recipient_disjoint_edits() { /* succeeds keyless; recipients decrypt at new tip */ }
#[test] fn rebase_content_divergent_without_identity_aborts_byte_identical() { /* refs dir byte-compare; typed error names commit+path */ }
#[test] fn rebase_content_divergent_with_identity_succeeds() { /* re-encrypted; PROTECTED perms at new tip; wraps for all recipients */ }
```

- [ ] **Step 2-5:** fail → implement (+ delete the retired error variants; `grep -rn "ReplayProtected\|MergeProtected" crates` must come back empty) → `cargo test` green → commit

```bash
git add crates/repo/src crates/cli/src/main.rs
git commit -m "feat: sc rebase handles protected paths atomically; retire fail-closed guards (P15)"
```

---

### Task 9: Secret-registry replay

**Files:**
- Modify: `crates/repo/src/replay.rs`
- Test: replay.rs tests

**Interfaces:**
- Consumes: `merge::merge_secrets(base, ours, theirs)`.
- Behavior (binding):
  - `rebase` fold: per commit, `registry = merge_secrets(&parent_registry, &acc_registry, &commit_registry)?` — `SecretMergeConflict` aborts atomically. `acc_registry` starts from the target tip's; each replayed snapshot is built with it.
  - `cherry_pick`: `merge_secrets(&picked_parent's, &current_tip's, &picked's)` for the new snapshot.
  - **`Empty` redefinition:** `Empty` only when the replayed tree equals onto AND the registry delta is empty; a tree-empty registry-changed commit produces a snapshot with the same tree + merged registry (counts as `replayed`, not `skipped`).
  - Delete P14's "secret-registry changes ... were not replayed" warnings (both sites) and their detection code.

- [ ] **Step 1: Failing tests**

```rust
#[test] fn rebase_replays_secrets_only_commit_as_registry_only_snapshot() {
    // branch has: file commit + secret_add commit; rebase onto advanced main
    // → Rebased{replayed: 2, skipped: 0}; new tip's registry contains the
    // secret; tree of the registry-only snapshot equals its parent's.
}
#[test] fn cherry_pick_secret_add_commit_replays_registry() {
    // pick the secrets-only commit → Picked (not AlreadyApplied); tip
    // registry gains the secret; tree unchanged.
}
#[test] fn registry_conflict_aborts_rebase_atomically() {
    // same secret name changed differently on both lines → SecretMergeConflict,
    // refs byte-identical.
}
```

(The removal of P14's warning is verified by the grep step below, not a test.)

- [ ] **Step 2: Run to verify failure**, **Step 3: implement**, **Step 4:** `grep -rn "not replayed" crates` → empty; `cargo test` green.
- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/replay.rs
git commit -m "feat(repo): replay the secret registry through rebase/cherry-pick — Empty now means tree AND registry (P15)"
```

---

### Task 10: `demo/run_protected_merge_demo.sh`

**Files:**
- Create: `demo/run_protected_merge_demo.sh` (chmod +x)

House style: copy `demo/run_history_demo.sh`'s structure (pipefail, `fail()` gates, TMPDIR normalization, zero-residue check, RESULT line). Proof obligations, each a real gate:

1. Setup: repo, alice + bob keypairs (`sc keygen`), `.sc/recipients.toml`, `sc protect secret/ --to alice,bob` pattern (check the real CLI: `sc protect <prefix> --to <recipient>` — read `run_lifecycle_demo.sh`/`run_repo_demo.sh` for recipient bootstrap), base commit with `secret/creds.txt`.
2. Two branches with DISJOINT protected edits; merge one into the other **with no identity available** (unset SC_IDENTITY, no default file) → succeeds; `sc switch --identity alice` materializes both files decrypted; same for bob.
3. Colliding protected edits on fresh branches; keyless merge → fails with the needs-identity error (grep stderr); `sc merge --identity <alice>` → succeeds; bob decrypts the merged file.
4. `sc secret add TOKEN --to alice` on a branch; `sc rebase main --identity <alice>` (or keyless if disjoint) → `sc secret list` at the new tip shows TOKEN.
5. Unauthorized isolation: `sc clone` the repo to a second dir; checkout with no identity → `secret/` files absent (skipped); plaintext strings absent from the working tree.
6. Zero-residue + RESULT line.

- [ ] **Step 1: Write the script** per obligations above (verify every CLI flag against `--help` before committing; fix the script to match the CLI).
- [ ] **Step 2: Run it twice** (non-stateful) + `bash demo/run_history_demo.sh` + `bash demo/run_repo_demo.sh` for regression.
- [ ] **Step 3: Commit**

```bash
chmod +x demo/run_protected_merge_demo.sh
git add demo/run_protected_merge_demo.sh
git commit -m "demo: protected merge & replay proof — keyless disjoint merges, identity-gated content merges, registry replay (P15)"
```

---

### Task 11: Docs + ADR-0025 → Accepted

**Files:**
- Modify: `CLAUDE.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `docs/adr/0025-protected-merge-and-replay.md`

- [ ] **Step 1: CLAUDE.md**
  - Commands block: add `--identity` notes to the merge/rebase/cherry-pick lines + `bash demo/run_protected_merge_demo.sh`.
  - New `**Phase 15 is built.**` paragraph after Phase 14's: id-level-on-ciphertext fast paths (convergence argument), identity gate for content divergence only, union rules fail-closed, shared encrypt helper, registry replay + Empty redefinition, plaintext-never-in-CAS (markers worktree-direct), guards + `MergeProtected`/`ReplayProtected` retired.
  - Update Phase 14's paragraph: remove the "protected content fails closed" sentence in favor of "protected content fails closed → lifted in P15 (ADR-0025)". Same for the P4/ADR-0014 fail-closed notes wherever CLAUDE.md mentions them.
- [ ] **Step 2: ARCHITECTURE.md** — `## Phase 15 — protected merge & replay (built)` section (condensed) + fix the fail-closed mentions the same way.
- [ ] **Step 3: ROADMAP.md** — P15 Active→Done (past tense, ADR cite), completed-phases table row:

```markdown
| **P15 — Protected merge & replay** | Confidentiality composes with collaboration | keyless merge of disjoint protected edits; `sc merge --identity` content-merges colliding ones; registry replays through rebase; proven by `demo/run_protected_merge_demo.sh` | [0025](docs/adr/0025-protected-merge-and-replay.md) |
```

  Retire from Deferred: "protected-path replay" and "secret-registry replay" (inside the history-editing follow-ons bullet — trim it), and any ADR-0014-limitation mention. Keep ADR-0014 itself immutable.
- [ ] **Step 4: ADR-0025** — Status → Accepted; append `## Refinements during the build` with real deviations.
- [ ] **Step 5: Final check** — `cargo test && bash demo/run_protected_merge_demo.sh && bash demo/run_history_demo.sh && bash demo/run_work_demo.sh && bash demo/run_repo_demo.sh` all green.
- [ ] **Step 6: Commit**

```bash
git add CLAUDE.md ARCHITECTURE.md ROADMAP.md docs/adr/0025-protected-merge-and-replay.md
git commit -m "docs: accept ADR-0025 protected merge & replay; record P15 across CLAUDE/ARCHITECTURE/ROADMAP"
```
