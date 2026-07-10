# P33: Randomized protected-path encryption (dual-read, randomized-write)

- **Issue:** #40 (part of the #24 audit-response map; decisions locked in #30)
- **Date:** 2026-07-10
- **Status:** Approved design, pre-implementation

## Goal

Close the convergent-equality boundary (ADR-0014's accepted dictionary /
equality-confirmation oracle on protected paths). All **new** protected
content is sealed under a fresh random DEK + random nonce, so two seals of
the same plaintext yield different ciphertext ids — the oracle is closed for
everything sealed from this phase on. Convergent ciphertext already in
history stays readable forever (dual-read); nothing is rewritten or forcibly
migrated.

## Locked decisions honored (from #30 / issue #40)

1. Randomized seals for all new protected content, with a format tag.
2. Dual-read, randomized-write; no hard break; a rewrap-shaped one-command
   eager re-seal upgrades the live tip on demand.
3. Unchanged-detection at commit via a local stat cache + keyed-hash
   fallback; commit still needs only public keys.
4. Accepted costs: (a) independent identical edits on two branches now
   conflict; (b) `sc rewrap` is no longer policy-only/tree-identical when it
   randomizes content; (c) identical plaintext at two paths no longer dedups.
5. Rotate-for-paths becomes meaningful; recorded as a follow-on, not built.

## Design decisions made in this brainstorm

- **Format tag = perms-byte flag.** A `RANDOMIZED` bit alongside `PROTECTED`
  in the tree-entry perms byte. Blob layout and `decrypt_path` are untouched.
- **`sc rewrap` itself performs the eager upgrade** (no new command, no flag).
- **The stat cache is per-checkout, including ws workspaces**, keyed by one
  per-repo local key.
- **The commit rule is format-dispatched, not cache-only** (see §3) — this is
  what prevents a silent mass-migration commit on first use after upgrade.

## 1. Seal primitive (`crates/crypto`)

New `encrypt_path_randomized(plaintext) -> (blob, dek)`: fresh random DEK and
random nonce from `OsRng`, plus an `encrypt_path_randomized_with_rng` variant
for deterministic tests. Blob layout is the existing `nonce(24) ‖
AEAD-ciphertext` with the existing `PATH_AAD` — both formats decrypt through
the unchanged `decrypt_path`, which is why dual-read needs zero read-path
code. `encrypt_path` (convergent) remains for the legacy-format
unchanged-comparison only; no new seal call site uses it. Wrapping/unwrapping
(`wrap_dek_for` / `unwrap_dek_with`) unchanged. The RustCrypto quarantine
holds: only `crates/crypto` grows crypto code.

## 2. Format tag (`crates/core`)

A new perms bit, `RANDOMIZED` (always set together with `PROTECTED`), on
every newly sealed tree entry. No encoding change and no snapshot-tag bump: a
pre-P33 store decodes with zero `RANDOMIZED` bits and behaves byte-for-byte
as today. Carry-by-id preserves the source entry's perms (the P24
discipline), so the format bit rides through merge, replay, graft, and sparse
carry with no new plumbing. Format identification never requires fetching
blob bytes.

Old binaries reading a new store mask-check `PROTECTED` and would misreport
randomized entries as modified in `status`; accepted (no deployed old peers,
same posture as prior phases).

## 3. Unchanged detection (new `crates/repo/src/cache.rs`)

- `.sc/local-key`: 32 random bytes, mode 0600, created lazily, never
  committed, never transferred.
- Per-checkout cache files: `.sc/protected-cache` for the main working tree;
  `.sc/ws/cache-<i>` per ws workspace — beside the checkout dir, NOT inside
  it (a file inside `.sc/ws/<i>/` would be read back as an untracked working
  file at harvest), removed with the workspace at teardown. Entries: `path → (mtime, size, keyed_tag,
  blob_id)` where `keyed_tag = BLAKE3-keyed(local_key, plaintext)`.

Commit's per-protected-path rule (format-dispatched):

| Prior tip entry | Rule |
|---|---|
| **Convergent** (no `RANDOMIZED` bit) | Today's convergent re-encrypt-and-compare. Unchanged → carry as-is (stays convergent, history stays quiet with no cache needed). Edited → seal randomized. |
| **Randomized** | Stat hit (mtime+size) → carry cached `blob_id`. Stat miss → keyed-tag compare; match → carry + refresh entry; mismatch or no entry → seal randomized, update entry. |
| **New protected path** | Seal randomized. |

Degradation: a lost or stale cache produces spurious re-seals (new blob ids
for unchanged plaintext), never incorrectness. The cache file alone leaks
nothing — tags are PRF outputs under a key that never leaves `.sc/` — so the
cache does not reintroduce the equality oracle. Commit continues to need
only public keys; decrypt-and-compare is not used anywhere.

## 4. Status / diff

`diff_worktree` (`crates/repo/src/worktree.rs`) and `diff_unified`
(`crates/repo/src/repo.rs`) get the same format dispatch: convergent entries
keep the re-encrypt-and-compare trick; randomized entries consult the cache
**read-only** (stat, then keyed tag); a missing entry reports the path as
modified — spurious-but-safe, same degradation rule as commit.

## 5. Cache population

Every site that writes authorized plaintext to disk records a cache entry:

- checkout / `sc switch` (materialize)
- merge / pick / rebase completion materialization
- `sc resolve` writes
- ws fork workspace materialization (per-workspace cache)
- sparse re-lay (`sc sparse set` / `disable`)
- commit itself (authoritative refresh)
- `sc rewrap` (it holds the plaintext while upgrading; see §7)

Per-workspace caches preserve two P20 properties that a main-tree-only cache
would regress: untouched protected files in forked workspaces remain provably
unchanged (no false identical-edit conflicts at harvest, no spurious
`work-<i>` fallbacks), and crash-recovery re-harvest still converges to the
idempotent `UpToDate` no-op because cache hits reproduce the same tree id.

## 6. Merge / replay semantics (the accepted P15 adjustment)

- Unchanged and one-side-changed fast paths survive unchanged via
  carry-by-id.
- Both sides editing a protected path — **including identical edits, which
  under convergent encryption used to id-match and fast-path** — now
  conflict by construction. Resolution: P23 `sc conflicts` / `sc resolve`,
  or diff3-with-`--identity`, which merges identical plaintexts cleanly and
  re-seals the result randomized.
- The content-merge re-encryption site in `merge.rs` and replay's
  `encrypt_protected` path switch to the randomized primitive.
- Protection-rule union, wrap union, and tombstone semantics (P15/P16) are
  unchanged. Mixed convergent+randomized trees need no special casing: every
  path is carried by id or re-sealed randomized.

## 7. `sc rewrap` eager upgrade

While unwrapping each protected blob's DEK (by wrap presence, as today),
rewrap additionally decrypts any still-convergent blob and re-seals it
randomized (fresh DEK + nonce, `RANDOMIZED` bit set), replaces the wrap list
with the rule's `granted_keys() + escrow` as before, and populates the
main-tree cache with the plaintext it already holds. Output gains a
`re-sealed N convergent blob(s)` line; the commit is no longer tree-identical
when any blob was upgraded (accepted cost 4b). Already-randomized blobs get
wrap-replacement only — ciphertext id unchanged — so a second rewrap
converges back to policy-only. One command, one commit, one oplog record,
skip-and-report semantics unchanged.

## 8. Out of scope (recorded, not built)

- Rotate-for-paths (unlocked follow-on; ADR records that ADR-0019's
  objection dissolves for randomized content).
- Per-prefix convergent/randomized choice (rejected on #30).
- `sc secret` changes (already randomized) and the P28 low-entropy nudge
  (stays — steering low-entropy values to `sc secret` remains right).
- History rewriting or forced migration.

## 9. Error handling

- Sealing to an empty granted set still fails loudly
  (`encrypt_protected`'s existing guard).
- A corrupt cache file is treated as absent (spurious re-seal, warning on
  stderr), never an error that blocks commit.
- A missing `.sc/local-key` is minted lazily; a permissions failure creating
  it is a hard error (the cache cannot be safely keyed without it).
- `decrypt_path` failures keep the P15 corruption-vs-authorization
  distinction (`Error::Crypto` vs `NotAuthorized`).

## 10. Testing & proof

Tests (per the acceptance criteria on #40):

- Randomized seal round trip; equality-oracle regression (two seals of the
  same plaintext yield different blob ids).
- Dual-read of pre-phase convergent objects (fixture built with
  `encrypt_path`).
- Format-dispatched commit: unchanged convergent content carries convergent
  with no cache; unchanged randomized content carries via stat hit, via
  keyed-tag fallback, and re-seals (correctly, spuriously) on lost cache.
- Eager tip re-seal via rewrap: convergent→randomized, second rewrap
  policy-only, skip-and-report on unopenable entries.
- The new identical-edit conflict resolving via `sc resolve` and via
  diff3-`--identity`.
- Merge/replay/rewrap over mixed convergent+randomized trees.
- ws fork/harvest with untouched protected files: no false conflicts; the
  per-workspace cache reproduces the base tree id.

Demos: all existing protected-path demos stay green over mixed-format
stores; new `demo/run_randomized_demo.sh` proves the oracle is closed (same
plaintext, different ciphertext ids), old history still decrypts, and rewrap
upgrades the tip — run twice, zero residue.

Docs: ADR-0043 (format change, dual-read posture, cache design and why it
doesn't reintroduce the oracle, accepted costs 4a–c, P15/P17 semantic
adjustments, rotate-for-paths follow-on); THREAT-MODEL and
CLAUDE.md/ARCHITECTURE.md updated — ADR-0014's caveat superseded for new
content.
