# ADR-0043: Randomized protected-path encryption (dual-read, randomized-write)

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 33
- **Builds on:** ADR-0014 (P7 convergent protected paths — superseded *for
  newly sealed content only*, dual-read retained), ADR-0025 (P15 carry-by-id
  discipline the format bit rides through merge/replay), ADR-0027 (P17
  `sc rewrap` — the vehicle for the eager tip upgrade), ADR-0034 (P24
  perms-preserving carry predicate)
- **Issue:** #40 (part of the #24 audit-response map; decisions locked in #30)
- **Spec:** `docs/superpowers/specs/2026-07-10-p33-randomized-protected-encryption-design.md`

## Context

ADR-0014's protected paths use **convergent** encryption: the DEK and nonce
derive from `BLAKE3(plaintext)`, so identical plaintext seals to an identical
ciphertext blob id. That preserves the project's bedrock content-addressing
and dedup invariant, but it carries an accepted caveat (ADR-0014, consequence
"Accepted caveat of convergent encryption"): an observer who already holds a
candidate plaintext can confirm whether it is present in the repo, or that two
protected files are identical, from the ciphertext id alone — a
dictionary/equality-confirmation oracle. The 2026-07-09 security audit (ticket
#24's map) flagged this as the remaining protected-path confidentiality
boundary. ADR-0014 itself named the fix — "random per-encryption (fresh DEK +
nonce each time)… may be offered as an opt-in per-policy mode" — and deferred
it as the cost of dedup. P28's `sc protect` low-entropy nudge surfaced the
boundary to operators but did not close it.

## Decision

All **new** protected content is sealed under a **fresh random DEK + random
nonce**, so two seals of the same plaintext yield different ciphertext ids —
the oracle is closed for everything sealed from P33 on. Convergent ciphertext
already in history stays readable forever (**dual-read**); nothing is rewritten
or forcibly migrated, and no operator is forced through an upgrade. `sc rewrap`
gains an **eager, on-demand** upgrade of the live tip for operators who want
the old ciphertext gone from the current snapshot.

### The format change: a perms-byte flag, not a blob-layout change

The blob layout is **unchanged** — a randomized protected blob is still
`nonce(24) ‖ AEAD-ciphertext` under the same `PATH_AAD` (`b"scl-path-v1"`),
decrypted by the same `decrypt_path`. The only new bit is a format **tag**:
`RANDOMIZED` (`0b0000_0010`, `crates/core/src/object.rs`), always set together
with `PROTECTED` on a newly sealed `TreeEntry.perms` byte. `encrypt_path_randomized`
(`crates/crypto/src/envelope.rs`, plus an `_with_rng` variant for deterministic
tests) is the one new seal primitive; `encrypt_path` (convergent) survives only
for the legacy-format unchanged-comparison described below — no new seal call
site uses it. The tag lives in the **tree entry, not the blob**, for two
reasons: (1) format identification never requires fetching or decrypting blob
bytes — `status`, `diff`, commit, merge, and rewrap all read the perms byte
they already hold; and (2) putting a format discriminator *inside* the blob
would change the blob's bytes and therefore its id, reintroducing exactly the
determinism the change exists to break. The RustCrypto quarantine holds — only
`crates/crypto` grew crypto code; `crates/repo` links `blake3` directly (already
a workspace dependency) for the cache tag below.

### Dual-read posture: no tag bump, no migration, format-dispatched commit

There is **no snapshot-tag bump** (`TAG_SNAPSHOT` stays at P16's value 4) and
**no `PROTOCOL_VERSION` change** (stays 3). A pre-P33 store decodes with zero
`RANDOMIZED` bits and behaves byte-for-byte as it did before — a genuine
pre-P33 store reads identically, pinned by library-built convergent-tree
fixtures in the `rewrap`/`merge`/`replay` unit tests. Carry-by-id (the ADR-0025
P15 discipline, generalized by ADR-0034 to preserve the *source* entry's own
perms) rides the format bit through merge, replay, graft, and sparse carry with
no new plumbing.

Commit's per-protected-path rule is **format-dispatched, not cache-only** — the
load-bearing choice that prevents a silent mass-migration commit on first use
after upgrade. Dispatched on the *prior tip entry's* format:

| Prior tip entry | Rule |
|---|---|
| **Convergent** (no `RANDOMIZED` bit) | Convergent re-encrypt-and-compare. Unchanged → carry as-is (stays convergent, history stays quiet, no cache needed). Edited → seal randomized. |
| **Randomized** | Consult the unchanged-detection cache (below); a hit carries the cached id, a miss seals randomized. |
| **New protected path** | Seal randomized. |

Had dispatch been cache-only — "no cache entry ⇒ re-seal" — the first commit
after upgrading to a P33 binary would have found an empty cache and re-sealed
**every** unchanged protected file randomized, a mass-migration commit nobody
asked for. Format dispatch means unchanged convergent content stays convergent
**forever** until an edit or an explicit `sc rewrap` touches it; the store
migrates only what actually changes.

### Unchanged detection: a keyed-PRF cache that does not reintroduce the oracle

Commit still needs only **public keys** — it never decrypts to decide whether a
file changed. Detection is a per-checkout stat cache (`crates/repo/src/cache.rs`):

- `.sc/local-key`: 32 random bytes, mode **0600 from first byte** (via
  `OpenOptions::create_new` + `mode(0o600)`, so the file is never briefly
  world-readable between creation and permission-setting), created lazily,
  **never committed, never transferred**. The per-checkout cache file itself
  (below) is written via `atomic_write_durable`.
- Per-checkout cache files: `.sc/protected-cache` for the main working tree;
  `.sc/ws/cache-<i>` per ws workspace (see below). Each entry is
  `path → (mtime, size, keyed_tag, blob_id)` where
  `keyed_tag = BLAKE3-keyed(local_key, plaintext)`.

**The cache does not reintroduce the equality oracle** precisely because the
tag is a PRF output under a key that never leaves `.sc/` and never travels: the
cache file alone leaks nothing — two identical plaintexts have identical tags
only to a holder of the local key, who by construction already has the working
tree. **Degradation rule:** a lost, stale, or corrupt cache produces spurious
re-seals (fresh randomized ids for unchanged plaintext) — never incorrectness,
never a wrong tree. A corrupt cache line is treated as absent with a stderr
warning; a `.sc/local-key` that cannot be created is a hard error (the cache
cannot be safely keyed without it).

### Accepted costs (from #40, all landed as predicted)

- **(4a) Independent identical edits on two branches now conflict.** Under
  convergent encryption, both sides editing a protected path to the *same*
  plaintext produced the same ciphertext id and merged with an id-level fast
  path. Randomized seals give the two edits different ids, so the merge now
  conflicts **by construction — even when the plaintexts are trivially
  identical** and needs `--identity` (or P23 `sc conflicts`/`sc resolve`) to
  resolve, at which point diff3 merges the identical plaintexts cleanly and
  re-seals the result randomized.
- **(4b) `sc rewrap` is no longer policy-only / tree-identical when it
  upgrades.** A rewrap that re-seals any convergent blob randomized changes
  that blob's id and therefore the root tree — the commit is content-changing,
  not the byte-identical policy-only commit ADR-0027 described. A second rewrap
  over an all-randomized tip converges back to policy-only (wrap-replacement
  only, ids unchanged).
- **(4c) Identical plaintext at two paths no longer dedups.** Two protected
  paths with byte-identical plaintext seal to two different randomized blob ids
  — the intended cost of closing the intra-tip equality oracle between them.

### P15 merge / P17 rewrap semantic adjustments

- **P15 (ADR-0025):** unchanged and one-side-changed protected fast paths
  survive unchanged (carry-by-id). Both-sides-edited paths now conflict by
  construction (cost 4a). The content-merge re-encryption site in `merge.rs`
  and replay's `encrypt_protected` path switch to the randomized primitive.
  Protection-rule union, wrap union, and revocation-tombstone semantics
  (P15/P16) are unchanged; mixed convergent+randomized trees need no special
  casing — every path is either carried by id or re-sealed randomized.
- **P17 (ADR-0027):** `sc rewrap` performs the eager upgrade with no new
  command or flag. While unwrapping each protected blob's DEK by wrap presence
  (as today), it additionally decrypts any still-**convergent** blob and
  re-seals it randomized, replaces the wrap list with the rule's
  `granted_keys() + escrow`, and records the plaintext it already holds into
  the main-tree cache (so the next `sc status`/`commit` stays quiet — rewrap
  never rematerializes the working tree). Output gains a `re-sealed N
  convergent blob(s)` line. Already-randomized blobs get wrap-replacement only.
  One command, one commit, one oplog record, skip-and-report semantics
  unchanged; sealing to an empty granted set still fails loudly.

### Unlocked follow-on: rotate-for-paths (recorded, not built)

ADR-0019 declared per-path DEK rotation "security-meaningless" under convergent
encryption — the DEK is a deterministic function of the plaintext, so
"rotating" it is either dedup-breaking or a no-op. **That objection dissolves
for randomized content:** a randomized DEK is independent of the plaintext, so
re-sealing a protected path under a fresh DEK is a genuine cryptographic
cutover, exactly as `sc secret rotate` already is for secrets. A
`sc protect … rotate`-style surface is now a coherent follow-on, recorded here
and in `ROADMAP.md`, **not built** in this phase.

## Consequences

- The convergent-equality oracle (ADR-0014) is closed for all content sealed
  from P33 on; pre-P33 convergent ciphertext already in history stays
  equality-confirmable **forever** to anyone holding a clone — the same
  rotation ≠ erasure boundary ADR-0019 names for secrets, since content
  addressing keeps the old object reachable regardless of what happens at the
  tip. `sc rewrap` stops a still-convergent blob's plaintext from propagating
  into *future* snapshots at the live tip; it does not erase the historical
  convergent object. Real cutover of guessable content means changing the
  content (or underlying credential) itself. THREAT-MODEL and ARCHITECTURE are
  updated to state this split honestly.
- Zero new dependencies: `blake3`/`hex` were already workspace deps; `scl-repo`
  now links `blake3` directly for the keyed cache tag.
- Old binaries reading a new store mask-check `PROTECTED` and would misreport
  randomized entries as modified in `status` — accepted (no deployed old peers,
  same posture as prior format-touching phases).
- The proof splits by concern, recorded honestly: dual-read of genuine pre-P33
  stores is pinned by **library-built convergent-tree fixtures** in the
  `rewrap`/`merge`/`replay` unit tests (the current binary can no longer *write*
  a convergent blob, so the fixtures build them directly via `encrypt_path`),
  while `demo/run_randomized_demo.sh` proves oracle-closure (same plaintext →
  different ciphertext ids), quiet history, cost-4a conflicts, and `sc rewrap`
  policy-only idempotence on an all-randomized tip against the current binary —
  run twice, zero residue. The convergent→randomized rewrap **upgrade** path
  (the `re-sealed N convergent blob(s)` line firing) is unit-pinned rather than
  demo-pinned, for the same reason the dual-read fixtures are library-built: the
  current binary cannot mint a convergent blob to feed a demo.

## Alternatives considered

- **Cache-only dispatch (no format tag).** Rejected: an empty cache after a
  binary upgrade would mass-migrate every unchanged protected file to
  randomized on the first commit. The perms-byte format tag is what makes
  "unchanged convergent content stays convergent" hold. See Decision §Dual-read.
- **A snapshot-tag bump / forced migration.** Rejected: dual-read needs zero
  read-path changes and lets pre-P33 stores decode byte-for-byte identically; a
  forced migration would rewrite history and break dedup for every existing
  protected repo with no consent.
- **Per-prefix convergent/randomized choice.** Rejected on #30 — one format for
  all new content, upgraded in bulk by `sc rewrap`, is simpler than a per-rule
  mode the merge/replay/graft paths would each have to branch on.
- **A separate `sc rewrap --randomize` flag or a new upgrade command.**
  Rejected: `sc rewrap` already holds each protected plaintext while re-wrapping
  and already commits one policy cutover; folding the re-seal into it needs no
  new surface.

## Refinements discovered during the build

Every prior phase's Refinements section holds this one to the same bar: every
claim below is checked against the shipped code, not the plan.

1. **The keyed tag is authoritative in every cache lookup — a deliberate
   deviation from #30 decision-3's letter AND the spec §3 table.** Both #30 and
   the spec described a stat-hit shortcut (mtime+size match ⇒ carry the cached
   id without hashing). The shipped `ProtectedCache::unchanged`
   (`crates/repo/src/cache.rs`) **never trusts the stat alone** — the recorded
   `(mtime, size)` fields are advisory, and the keyed BLAKE3 tag is recomputed
   and compared on every lookup. This closes the classic git "racy-stat" data-
   loss class: a same-size edit that lands within the filesystem's mtime
   granularity, with the recorded mtime, would otherwise be misread as unchanged
   and silently dropped from the commit (pinned by
   `racy_stat_same_size_same_mtime_still_misses` and
   `tag_is_authoritative_for_hits_and_misses`). The stat shortcut was traded
   away because the plaintext is already in memory at every call site (commit,
   status, diff all hold the working-tree bytes to seal or compare), keyed
   hashing is ~free against that, and "never incorrectness" outranks the stat
   shortcut. Stat fields are still recorded for a future fast-path that can
   afford the risk; today nothing relies on them.

2. **`sc protect <existing-prefix> --to <new>` no longer wraps UNCHANGED content
   at the next commit — an accepted semantic adjustment.** Under convergent
   encryption, re-protecting an already-protected prefix for a new recipient
   caused the next commit's re-encrypt-and-compare to re-derive each unchanged
   file's convergent DEK and wrap it for the new recipient. Under P33, unchanged
   protected files carry their **prior wrap list verbatim** (carry-by-id), so a
   bare `sc protect … --to <new>` does not grant the new recipient access to
   files that are not re-sealed. This fails **safe** — it under-grants, never
   over-grants — and `sc grant <prefix> --to <new> --identity` (re-wraps every
   affected file's existing DEK) and `sc rewrap` (bulk cutover) are the covering
   flows. Operator guidance: use `sc grant`, not a second `sc protect`, to add a
   recipient to already-committed protected content.

3. **Rewrap's shared-blob upgrade: deferred old-id wrap removal (review
   Critical).** Two protected paths can share ONE convergent blob id (pre-P33
   dedup of identical plaintext at two paths). An earlier draft removed the old
   blob's wrap-map entry **inside** the per-path upgrade loop; when the first
   path re-sealed and stripped the shared entry, the second path was then found
   with "no wrapped DEKs recorded for blob," skipped, and left pointing at a
   wrap-orphaned blob at the tip — silent access loss no re-run could repair
   (`crates/repo/src/rewrap.rs`). The fix **defers** old-id wrap removal past
   the path loop: an old id's wraps are removed only once no kept tree entry
   still references it. Each shared path mints its **own** randomized blob, which
   also closes the intra-tip equality oracle between those two paths (cost 4c
   applied intra-tip). Pinned by the shared-blob rewrap regression test
   asserting `blobs_resealed == 2` and two distinct randomized ids.

4. **The cache is per-checkout, and ws workspaces get their own — a false-
   conflict hazard, not a nicety.** The main tree uses `.sc/protected-cache`; a
   ws workspace uses `.sc/ws/cache-<i>`, placed **beside** the checkout dir,
   never inside `.sc/ws/<i>/` (a file inside the checkout would be read back as
   an untracked working file at harvest and land in the branch), and removed
   with the workspace at teardown; `sc work`'s one-shot ephemeral agents use an
   **in-memory** cache (`ProtectedCache::open(..., None)`, never touches disk).
   Without per-workspace caches, an untouched protected file in a forked
   workspace has no cache entry, so harvest's format-dispatched detection would
   re-seal it randomized — giving it a different id from the base and turning
   every untouched protected file into an identical-edit **conflict** at harvest
   (the cost-4a mechanism, fired spuriously), with a `work-<i>` fallback instead
   of a clean auto-merge. The per-workspace cache reproduces the base tree id on
   an untouched file, preserving P20's clean-auto-merge and crash-recovery
   `UpToDate` idempotency.

5. **A cache save never gates an operation, and the ref move stays the commit
   point.** This is not "every save is strictly ordered after every ref move"
   — `assemble_completion_snapshot` deliberately saves the cache *before* its
   callers move the ref (documented in-code; benign, since a crash between the
   two just costs a spurious re-seal next time, not a lost edit) and several
   call sites move no ref at all. The property that actually holds everywhere:
   a cache save is best-effort (a save failure warns on stderr, never errors)
   and never blocks or gates the operation it's attached to, while the ref
   move — wherever one occurs — remains the sole atomic commit point, unchanged
   from every prior phase. Combined with the 0600-from-first-byte local key and
   the keyed-PRF tag, this is why the cache is pure optimization — its worst
   failure mode is a spurious re-seal, never a lost edit or a leaked oracle.
