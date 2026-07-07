# ADR-0027: Bulk re-wrap and multiple escrow keys

- **Status:** Accepted
- **Date:** 2026-07-07
- **Phase:** 17
- **Builds on:** ADR-0019 (secret lifecycle), ADR-0009 (key management), ADR-0026 (revocation tombstones)
- **Spec:** `docs/superpowers/specs/2026-07-07-p17-bulk-rewrap-design.md`

## Context

ADR-0019 ships rotation and re-wrap one secret / one path at a time, and a
single break-glass escrow key that reaches an entry only when it is next
individually touched (forward-only). An org-wide change (offboarding,
escrow rotation) requires touching every entry manually. ADR-0026
sharpened the need: merging a pre-revoke branch re-attaches a revoked
recipient's old wraps to the live tip (`union_wraps` keeps historical
facts — verified empirically at the P16 final review), and the practical
cutover is a bulk re-wrap.

## Decision

`sc rewrap --identity <key> [--dry-run]`: one command, one commit, one
oplog record (undoable). Secrets are recovered with the identity and
re-sealed under a fresh DEK to their current recipient set plus the full
escrow list (P11 rotate machinery, batched into a single registry
commit). Every PROTECTED blob at the tip has its DEK unwrapped
(wrap-presence, the `grant` pattern) and its wrap list **replaced** with
exactly the governing rule's `granted_keys()` + escrow list — stripping
tombstoned recipients' re-attached wraps from the tip. Convergent DEKs
keep ciphertext ids unchanged, so the commit is policy-only (root tree
byte-identical).

**Skip-and-report:** entries the identity cannot open are skipped and
reported (name + reason); the command commits what succeeded and exits
non-zero when incomplete. Chosen over atomic-refuse because escrow is
forward-only — no identity is guaranteed to open pre-escrow entries, and
all-or-nothing would fail exactly when the command is most needed.

Escrow becomes a managed list: `.sc/recipients.toml [escrow]` grows from
`key = "…"` to `keys = […]` (old form still read, migrated on write);
`sc escrow add/remove/show`, with `set` kept as replace-with-one sugar.
All seal paths auto-append every escrow key, deduped. Escrow rotation is
composition (`add` new → `remove` old → `rewrap`), not a command.

Guards: `secrets::require_recipients` on secret reseals; the
empty-granted check on wrap-list rebuilds (a rule emptied by crossed
revokes is reported, never sealed to nobody). `crates/crypto` is
unchanged. The `sc revoke` / `secret revoke` hints are re-worded to name
`sc rewrap` as the tip-cutover step (closing the P16-T3 wording finding).

## Consequences

- One-command cutover after a recipient/escrow change; the demo changes
  the escrow key and shows every entry re-sealed, and proves the ADR-0026
  R1 scenario closed (post-merge re-attached wraps stripped by rewrap).
- Rewrap ≠ erasure (ADR-0019's boundary, restated in command output):
  old snapshots in history keep old wraps and old secret objects — the
  cutover is for reads through the live tip; real cutover of an external
  credential still means rotating the credential itself.
- A partial rewrap (non-zero exit) is a valid committed state: the report
  names the identities still needed, and a later `rewrap` with them
  completes the sweep.

## Alternatives considered

- **Script the per-entry commands:** no single-commit atomicity, no one
  oplog record, easy to miss entries.
- **Auto-rewrap on every revoke:** hidden expensive writes; an explicit
  bulk command keeps the destructive-operation gate visible.
- **Atomic all-or-nothing rewrap:** unusable in the presence of
  forward-only escrow (one pre-escrow secret blocks the whole cutover);
  rejected for skip-and-report with a non-zero exit.

## Refinements discovered during the build

- **Known-key pool for reverse `recipient_id` resolution lives in the CLI,
  not `repo`.** `run_rewrap` assembles it from `[recipients]` in
  `recipients.toml` + every escrow key + the identity's own public key,
  deduped by `recipient_id`; a missing or unreadable `recipients.toml`
  degrades to escrow + self rather than failing the command outright.
  `repo::rewrap` takes the resolved `known_keys: &[PublicKey]` as a plain
  argument and never reads `recipients.toml` itself.
- **Exit-code plumbing reuses the `run_merge` pattern.** `run_rewrap` calls
  `drop(repo)` before `std::process::exit(1)` when the report has any
  skipped entries, so the repo's single-writer lock file is released before
  the process exits. The `rewrapped N secret(s), M protected blob(s)`
  summary (and commit id) print to stdout; the skipped-entry list, the
  "re-run with an identity that can open them" hint, and the ADR-0019
  honesty caveat all print to stderr.
- **Wrap-list rebuild is target-set-driven, not reuse-everything.**
  `repo::rewrap` builds the new wrap list by iterating exactly
  `granted_keys() ∪ escrow` and, for each target, reuses the prior wrap
  bytes only when that recipient is already present in `prior` — otherwise
  it mints a fresh wrap. Recipients present in `prior` but absent from the
  target set are never copied forward. This is what strips a tombstoned
  recipient's re-attached wrap (the ADR-0026 R1 corollary) rather than
  merely leaving it stale; the acceptance test
  (`rewrap_strips_reattached_wraps_after_pre_revoke_merge`, rewrap.rs)
  reproduces the R1 scenario end to end — merges a pre-revoke branch,
  confirms bob's wrap is back at the tip as a precondition, runs `rewrap`,
  and asserts no wrap in the resulting snapshot's `protection.wrapped`
  carries bob's `recipient_id` while the root tree id is unchanged.
- **Authorization surfaces stay distinct, per the P16 review's correction.**
  Rewrap *opens* an entry by wrap presence: the secrets half calls
  `scl_crypto::open` (fails if the identity holds no wrap on the secret),
  and the paths half looks up the caller's own wrap in
  `protection.wrapped` before unwrapping the DEK. Rewrap *seals* the
  rebuilt entry: paths to the tombstone-aware `rule.granted_keys() + escrow`,
  secrets to their current (wrap-derived) recipient set `+ escrow` — both by
  the resolved set, not wrap presence. Conflating the two would either lock
  out a still-wrapped-but-revoked recipient's rewrap attempt (they can open)
  or reseal to them (they must not be resealed to) — this ADR keeps them
  separate exactly as ADR-0026 established for `grant`/decrypt vs. sealing.
- **`sc undo` and `sc switch` interact with the demo, not the design.**
  `sc undo` reverts only the single most recent oplog record, and `sc
  switch` records its own oplog entry even when it is a no-op (same branch,
  same tip) — so `demo/run_rewrap_demo.sh` asserts the undo/redo round trip
  immediately after `rewrap`, before any further `switch`, to keep the
  targeted record the rewrap commit.
- **`crates/repo/src/secrets.rs` grew one new visibility, not a new
  module.** `append_dedup` (dedup-appending escrow keys onto a resolved
  target list) is `pub(crate)` so `rewrap.rs` can reuse it; `Repo::store_arc`
  widened from private to `pub(crate)` for the same reason. No new public
  API surface.
- **Escrow TOML back-compat is a parse-time union, write-time
  normalization.** `EscrowSection { key: Option<String>, keys: Vec<String> }`
  reads both the old singular `key` and the new `keys` list (chained,
  deduped by `recipient_id`); every write normalizes to `keys` only, and an
  empty list drops the `[escrow]` section entirely rather than writing
  `keys = []`.
