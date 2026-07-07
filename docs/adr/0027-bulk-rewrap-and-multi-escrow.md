# ADR-0027: Bulk re-wrap and multiple escrow keys

- **Status:** Proposed
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
