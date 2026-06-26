# P5 — Accidental-plaintext secret scanner: design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-06-26
- **Phase:** 5
- **Refines:** ADR-0017 (firm to Accepted at build time)
- **Complements:** Phase 2 committed secrets (ADR-0008/0009/0010)

## Goal

Stop developers from *accidentally* committing plaintext secrets (a `.env`, an
API key, a private key) as ordinary files. A `put`/commit-time scanner inspects
file content, and **hard-rejects** a commit whose files contain matched secret
patterns or high-entropy tokens, with a hash-scoped allowlist for false
positives. This is the complement to Phase 2, which lets you *deliberately*
commit *encrypted* secrets: P5 catches the *accidental, plaintext* ones.

## Decisions (locked: brainstorm + ADR-0017)

1. **Scan scope:** every file in the working-tree snapshot on each commit (not
   just changed-vs-HEAD). Strongest coverage; the allowlist handles legacy/false
   positives.
2. **Detection:** compile-time `RegexSet` of high-precision token patterns +
   a Shannon-entropy heuristic (contiguous base64-alphabet runs ≥ 20 chars with
   entropy > 4.5 bits/char). One pass per blob, byte-oriented (UTF-8-lossy).
3. **On a hit:** `commit` fails with `Error::SecretDetected` and writes nothing.
   **No override flag** — the fix is to remove the secret (or commit it properly
   via `sc secret`) or allowlist the specific blob.
4. **Allowlist:** `.sc/scanner-allowlist.toml`, hash-scoped to exact blob
   `ObjectId`s (64 hex), each with an optional `note`. Manually edited.
5. **Preview:** a read-only `sc scan` reports what a commit would reject and
   exits non-zero on findings (CI-gateable); it is how you discover the blob
   hashes to allowlist.

## Out of scope (this round)

- A `sc scan --allow <hash>` helper (allowlist is edited by hand this round).
- Streaming/large-blob scanning, scan-on-read, operator-supplied custom patterns,
  regex-based allowlists.
- Encrypted-path interaction (P7) — see "Forward interaction" below.

## Architecture

All work is in `scl-repo`. New modules:

- **`crates/repo/src/scanner.rs`** — pure detection + allowlist:
  - `scan(name: &str, bytes: &[u8]) -> Vec<Hit>` where
    `Hit { rule: HitKind, line: usize }` and
    `HitKind { Pattern(&'static str), Entropy }`.
  - Pattern detection: a lazily-built `RegexSet` from `scanner_patterns::PATTERNS`
    run once over the (UTF-8-lossy) text; each match records the responsible
    pattern name and the 1-based line.
  - Entropy detection: a single forward pass flagging contiguous runs of
    base64-alphabet chars (`A–Z a–z 0–9 + / - _ =`) of length ≥ 20 whose Shannon
    entropy (bits/char) > 4.5.
  - `Allowlist` — load `.sc/scanner-allowlist.toml` into a `HashSet<ObjectId>`;
    `is_allowed(&ObjectId) -> bool`. Missing file → empty allowlist.
- **`crates/repo/src/scanner_patterns.rs`** — `pub const PATTERNS: &[Pattern]`
  with `Pattern { name: &'static str, regex: &'static str, description: &'static str }`.
  Starting set (PR-reviewed): `github_pat` (`gh[posr]_[A-Za-z0-9_]{36,}`),
  `aws_access_key` (`AKIA[0-9A-Z]{16}`), `anthropic_api_key`
  (`sk-ant-(api|admin)[A-Za-z0-9_-]{20,}`), `openai_api_key`
  (`sk-(proj-)?[A-Za-z0-9]{40,}`), `stripe_live` (`(sk|pk)_live_[A-Za-z0-9]{20,}`),
  `gcp_service_account` (`"type"\s*:\s*"service_account"`), `private_key_pem`
  (`-----BEGIN [A-Z ]*PRIVATE KEY-----`). High precision over recall — broad
  recall is the entropy detector's job.

### Driver on `Repo`

```text
scan_worktree() -> Result<ScanReport>
```

- Read the working tree (`worktree::read_worktree`). For each `(path, bytes, _mode)`:
  compute its blob `ObjectId`; if the allowlist contains it, skip; otherwise run
  `scanner::scan(path, bytes)` and turn each `Hit` into a
  `Finding { path, rule: String, blob_id: ObjectId, line: usize }`.
- `ScanReport { findings: Vec<Finding> }` with `is_empty()` and a `Display`
  rendering (`path:line  rule  blob <hex>` + the allowlist hint).

## Components & data flow

### `commit` integration

`Repo::commit` calls `scan_worktree()` **before** `write_tree`/snapshot
construction:

```text
let report = self.scan_worktree()?;
if !report.is_empty() { return Err(Error::SecretDetected(report)); }
// ... existing write_tree + commit_snapshot ...
```

Nothing is written when a secret is detected. The merge-finalizing `commit`
(P4) goes through the same path, so resolved merge content is scanned too.
Secret operations (`secrets.rs::commit_registry`) do not read working-tree blobs
and so are unaffected — they manipulate `Secret` registry objects, which are
ciphertext and never scanned.

### `sc scan` (CLI, read-only)

`sc scan` opens the repo, runs `scan_worktree()`, prints each finding and, if any,
the "add `<hash>` to `.sc/scanner-allowlist.toml`" guidance; **exits non-zero**
when findings exist, `0` when clean. It does not modify the repo.

### `sc commit` rejection

On `Error::SecretDetected`, the CLI prints the findings + guidance and exits
non-zero (a real error — unlike P4's exit-0 conflict UX). No `--force`.

## The "exempt encrypted objects" rule (ADR-0017) & forward interaction

Satisfied by construction now: the scanner runs only on **working-tree file
content** (all plaintext), never on `Secret` registry objects (which are not
files).

**Forward interaction with P7 (encrypted paths):** once protected paths exist,
files under a protected path sit in the working tree as plaintext *by design*
(they get encrypted on commit). P7 must let protected paths **bypass** the
content scanner, so a to-be-encrypted secret file is not rejected before it can
be protected. Recorded as a P7 interaction; not built here.

## Error handling

- New `Error::SecretDetected(ScanReport)` (thiserror). The `ScanReport`'s
  `Display` renders the findings; the CLI absorbs via `anyhow` and exits non-zero.
- A malformed `.sc/scanner-allowlist.toml` yields a typed `BadRef`/parse error,
  not a panic. A bad blob-hash entry (not 64 hex) is reported clearly.

## Dependencies

Add to `crates/repo/Cargo.toml`: `regex`, `toml`, `serde` (with `derive`). No new
dependency in `core`.

## Testing

- **scanner unit tests (pure):** each pattern matches a representative sample
  (e.g. `AKIA…`, `-----BEGIN … PRIVATE KEY-----`); the entropy detector flags a
  44-char base64 token and does NOT flag ordinary prose/source lines; clean text
  → no hits; binary/non-UTF-8 bytes → no panic; line numbers are correct.
- **allowlist:** a blob whose id is allowlisted is skipped (no finding) while an
  identical-pattern non-allowlisted blob is flagged; missing allowlist file →
  empty; malformed file → typed error.
- **repo:** `commit` of a working tree containing a file with `AKIA…` →
  `Err(SecretDetected)` and HEAD unchanged (nothing committed); after adding the
  blob hash to the allowlist, the same `commit` succeeds; `scan_worktree` returns
  the expected findings; a clean tree commits normally.
- **CLI:** `sc scan` exits non-zero with findings, `0` when clean.
- Phase 1–4 flows unaffected: `sc demo`, `sc secret-demo`, and existing repo
  tests still pass (none of their fixtures contain matched secrets).

## ADR

Firm **ADR-0017** Proposed → Accepted when this ships, recording the as-built
specifics: scan-all-committed-files scope, the `sc scan` preview, the pattern
set + entropy thresholds, and the P7 bypass interaction.

## Open follow-ons (not this round)

- `sc scan --allow <hash>` allowlist helper.
- Operator-supplied / org-custom patterns behind an explicit opt-in.
- Streaming scan for very large blobs.
- P7: protected-path bypass of the content scanner.
