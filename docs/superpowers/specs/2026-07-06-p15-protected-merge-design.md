# Protected merge & replay (Phase 15) — design

- **Date:** 2026-07-06
- **Status:** Approved for planning
- **Depends on:** P7 protected paths (convergent encryption, wrapped DEKs,
  `Protection`), P4 merge + P14 `three_way_files` (the core being extended),
  P14 replay/rebase/cherry-pick (guards being lifted), P11 escrow
  (auto-append on seal), P14 oplog (unchanged, records the ops as before)

## Goal

Make the confidentiality pillar compose with the everyday VCS. Today every
merge, rebase, and cherry-pick fails closed the moment any involved tree
contains a `PROTECTED` entry — teams using per-file permissions cannot
collaborate on those branches at all. P15 threads perms and wrapped DEKs
through the three-way core so all three operations work on protected
content, and replays the secret registry through rebase/cherry-pick (closing
P14's "not replayed" warning).

**Success bar:** `demo/run_protected_merge_demo.sh` proves: a **non-recipient**
merges branches with disjoint protected edits (ciphertext + wraps move, both
recipients still decrypt afterward); a **recipient** content-merges colliding
protected edits with `--identity` and the re-encrypted result is readable by
every rule recipient; a rebase carries a `secret add` into the new history;
an unauthorized clone still receives only ciphertext. Zero new dependencies,
zero new crypto primitives.

## Decisions (from brainstorm)

1. **Identity gate — only for content merges.** Id-level cases (same
   ciphertext both sides, only one side changed, clean deletes) resolve
   without any identity, for any user. Only a content-divergent protected
   path requires `--identity`, failing with a typed error naming the path.
2. **Scope — merge + replay + secret registry.** All three fail-closed
   guards lifted; registry replayed through rebase/cherry-pick.
3. **Rules merge — union, fail-closed.** Merged snapshots carry the union of
   both sides' prefix rules; a prefix ruled on both sides unions its
   recipient sets. Nothing silently unprotects.

## Core: perms-aware three-way

`merge::three_way_files` (extracted in P14) is extended:

```
pub(crate) struct MergedFile {
    pub path: String,
    pub mode: FileMode,
    pub bytes: Vec<u8>,      // ciphertext when carried; plaintext when needs_encrypt
    pub perms: u8,           // PROTECTED bit preserved through the merge
    pub needs_encrypt: bool, // true => bytes are plaintext awaiting the encrypt helper
}

pub(crate) struct FileMerge {
    pub files: Vec<MergedFile>,
    pub sidecars: Vec<(String, Vec<u8>)>,
    pub conflicts: Vec<String>,
    /// Wrapped DEKs for carried ciphertext blobs (union when both sides know a blob).
    pub wrapped_carry: BTreeMap<ObjectId, Vec<WrappedKey>>,
}

three_way_files(
    store,
    base:  Option<(ObjectId /*root*/, &Protection)>,
    ours:  (ObjectId, &Protection),
    theirs:(ObjectId, &Protection),
    identity: Option<&scl_crypto::SecretKey>,
) -> Result<FileMerge>
```

Per-path resolution (entries read with `tree_file_entries_with_perms`):

- **No `PROTECTED` bit on any side:** existing plain logic verbatim
  (`needs_encrypt: false`, perms 0).
- **Protected, id-resolvable:** same-ciphertext-both-sides, only-one-side-
  changed, and clean-delete cases resolve by **ciphertext blob id** — sound
  because convergent encryption maps equal plaintext to equal ciphertext id.
  Winner's ciphertext carries with `needs_encrypt: false`, `PROTECTED`
  perms; its wraps are copied into `wrapped_carry` from whichever side's
  `protection.wrapped` knows the blob (union of `WrappedKey`s, deduped by
  `recipient_id`, when both do). **No identity required.**
- **Protected, content-divergent** — both sides changed; delete-vs-modify;
  or perms diverge between sides (one side's rules protect the path, the
  other's don't): requires the identity.
  - `identity: None` → `Err(ProtectedMergeNeedsIdentity(path))`.
  - Identity cannot unwrap any relevant DEK → `Err(NotAuthorized(path))`
    (existing variant).
  - Otherwise: decrypt the protected inputs (plain-side inputs used as-is),
    diff3 the plaintexts. Output is plaintext with `needs_encrypt: true` and
    `PROTECTED` perms (divergent-perms cases resolve protected —
    fail-closed). Conflicted text gets markers *in the plaintext*; binary
    conflicts keep ours + a plaintext sidecar. Delete-vs-modify keeps the
    surviving side decrypted with `needs_encrypt: true` and marks the
    conflict.
- The non-UTF-8-base fallback and mode resolution rules are unchanged.

`three_way` (snapshot-level wrapper) passes each snapshot's protection and
keeps its public behavior for plain content byte-identical.

## Landing results: one shared encryption helper

The encrypt-protected-files block inside `snapshot_files` (convergent
`encrypt_path`, fresh DEK wraps to the matching rule's recipients + escrow
auto-append, **prior-wrap reuse** keyed by `(blob_id, recipient_id)` for
snapshot-id stability) is extracted into a shared `protect` helper used
identically by commit, merge, and replay. No second implementation of the
wrap-reuse subtlety.

- **Clean merge:** `needs_encrypt` files run through the helper (rule lookup
  against the **union** rules, ours-side recipient sets unioned with theirs
  per shared prefix); carried ciphertext lands as-is. Tree assembled with
  `write_tree_with_perms`; merged snapshot protection = union rules +
  (`wrapped_carry` ∪ fresh wraps), pruned to blobs present in the merged
  tree (commit's rebuild discipline). Two-parent snapshot committed
  directly — the working tree is not involved.
- **Conflicted merge:** the merged working set materializes to the working
  tree **of the identity-holder** — plaintext with markers, the same trust
  boundary as P7 authorized checkout (a conflicted protected merge can only
  be reached with a valid identity). Merge state written as today. The
  completing `sc commit` re-encrypts through the normal pipeline; when a
  merge is in progress, `commit` computes the **rules union of both
  parents** (instead of tip-only rules) so theirs-side protections govern
  the completion too.
- Merge's materialize of a conflicted protected working set writes
  decrypted content for entries the identity can unwrap; this replaces the
  current `Protection::default()` shortcut on the conflict path (which was
  only sound because protected content was refused).

## Replay coverage (rebase / cherry-pick)

- `replay_commit` gains `identity: Option<&SecretKey>` and passes the three
  snapshots' protections into the new core. `ReplayOutcome::Clean` now
  carries the assembled protection (union rules + wraps) alongside the
  root; `Conflicts` carries the perms-aware working set for cherry-pick's
  conflict materialize.
- Rebase keeps all-in-CAS atomicity: any `ProtectedMergeNeedsIdentity` /
  `NotAuthorized` / conflict during the fold aborts with refs and working
  tree untouched, naming the commit and path.
- Replayed snapshots' protection: target-side rules ∪ replayed commit's
  rules, wraps carried/freshened per the helper.
- `Error::MergeProtected` and `Error::ReplayProtected` are **retired**
  (removed along with their guards); the precise errors replace them.
- CLI: `sc merge`, `sc rebase`, `sc cherry-pick` gain `--identity <key>`
  with the same soft resolution as `sc switch`
  (`$SC_IDENTITY` / `~/.sc/identity`; absent file → None, not an error).

## Secret-registry replay

- **Rebase:** per replayed commit, registry =
  `merge_secrets(base = commit's parent's registry, ours = accumulated
  registry (starting from target tip's), theirs = commit's registry)`.
  A `SecretMergeConflict` aborts the rebase atomically.
- **Cherry-pick:** `merge_secrets(base = picked commit's parent's, ours =
  current tip's, theirs = picked commit's)`.
- **`Empty` is redefined:** tree-empty AND registry-delta-empty. A
  secrets-only commit replays to a registry-only snapshot (same tree,
  merged registry) instead of being skipped.
- P14's "secret-registry changes were not replayed" warnings are deleted —
  replaced by actual replay.

## Invariants

- **Plaintext never enters the CAS.** Every `needs_encrypt` output is
  encrypted before any `write_tree_with_perms` on every CAS path (clean
  merge, replay). Plaintext — including conflict markers and sidecars —
  reaches only the working tree of a caller holding a valid identity,
  which is precisely P7's existing checkout trust boundary.
- **Convergence preserved:** equal merged plaintext yields equal ciphertext
  blob ids; prior-wrap reuse keeps snapshot encodings stable for unchanged
  content.
- **No silent unprotect:** union rules; `PROTECTED` perms survive every
  path; divergent-perms cases resolve protected; a file committed under a
  theirs-added prefix after the merge is encrypted.
- **Atomic rebase preserved** (all snapshots CAS-only until the single ref
  move; materialize before ref move, oplog last — P14 discipline).
- **Crypto quarantine:** only existing `scl_crypto` functions
  (`encrypt_path`, `decrypt_path`, `wrap_dek_for`, `unwrap_dek_with`);
  no new primitives, no new dependencies. `gitio` untouched; the P9/P10
  export confidentiality gate is untouched.
- Content addressing and object encoding unchanged; oplog semantics
  unchanged.

## Error handling

- New variant: `ProtectedMergeNeedsIdentity(String /*path*/)` — message
  tells the user to re-run with `--identity <key>`.
- `NotAuthorized(String)` reused for an identity that cannot unwrap.
- All identity failures occur **before any ref or working-tree write** in
  merge; in rebase they abort the fold with refs byte-identical; in
  cherry-pick they occur before markers/state are written.
- Registry conflicts surface the existing `SecretMergeConflict` typed error.

## Testing

- Core: id-fast-path table (same/one-side/delete × identity-absent);
  content-divergence with identity (merged plaintext re-encrypted; every
  rule recipient can decrypt the result); identity absent → typed error;
  unauthorized identity → `NotAuthorized`; perms-divergence resolves
  protected; delete-vs-modify protected; plain-content behavior
  byte-identical to pre-P15 (regression corpus: existing merge tests).
- Rules union: theirs-side new prefix survives the merge AND a post-merge
  commit of a new file under it is encrypted (the leak test); recipient
  union per shared prefix.
- Replay: rebase of a protected branch by a non-recipient with disjoint
  edits succeeds; content-divergent protected commit without identity
  aborts with refs byte-identical; with identity succeeds; cherry-pick
  conflict path writes plaintext markers + pick state for the
  identity-holder and completes via `sc commit` re-encryption.
- Registry: secrets-only commit replays to a registry-only snapshot;
  registry conflict aborts rebase atomically; P14's warning is gone.
- Convergent stability: merging identical concurrent edits produces the
  identical ciphertext blob id on both of two independent repos.
- All disk tests clean up and assert the path is gone.

## Demo

`demo/run_protected_merge_demo.sh` (house style: pipefail, fail() gates,
zero-residue check): alice + bob recipients of `secret/`, mallory holds no
key. (1) mallory merges two branches with disjoint protected edits — both
recipients decrypt both files afterward; (2) alice content-merges colliding
protected edits with `--identity`, bob decrypts the merged result; (3) a
rebase carries a `secret add` commit — registry present at the new tip;
(4) an unauthorized clone + checkout yields no plaintext for protected
paths. RESULT line + zero residue.

## Documentation

- **ADR-0025 — protected merge & replay** (Proposed → Accepted at build
  completion): id-level-on-ciphertext soundness argument (convergence),
  identity gate, union rules, shared encrypt helper, registry replay.
- **ROADMAP.md:** P15 Active at start; at completion move to Done and
  retire three deferred items: protected-path replay, secret-registry
  replay, and ADR-0014's documented protected-merge limitation (note the
  lift in ADR-0025; ADR-0014 itself stays immutable).
- **CLAUDE.md / ARCHITECTURE.md:** Phase 15 sections at completion; update
  the P4/P14 fail-closed notes to point at the lift.

## Out of scope (deferred, recorded in ROADMAP.md)

- Re-keying on merge (rotating DEKs of carried ciphertext — meaningless
  under convergent encryption, per ADR-0019's rotation analysis).
- Rule *narrowing* semantics (removing a prefix rule via merge always
  loses to union; explicit unprotect is a future operation).
- Protected-path support in `sc export` / git remotes beyond the existing
  `--include-encrypted` gate.
- Mainline selection for merge-commit replay (unchanged from P14).
