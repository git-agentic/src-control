# P17 — Bulk re-wrap + multiple escrow keys: design

**Date:** 2026-07-07
**Status:** Approved
**ADR:** 0027 (Proposed → Accepted when built)
**Horizon:** `2026-07-07-roadmap-horizon-p16-p20-design.md`

## Problem

P11 ships recipient/escrow retrofit one entry at a time: `secret rotate`
re-seals one secret, `grant`/`revoke` re-wrap one prefix, and the single
escrow key reaches an entry only when it is next individually touched
(forward-only). An org-wide change — escrow rotation, offboarding — means
touching every entry by hand. P16 sharpened the motivation: merging a
pre-revoke branch re-attaches a revoked recipient's old wraps to the live
tip (`union_wraps` keeps historical facts), and the practical cutover is a
bulk re-wrap. P16's final review verified this empirically (ADR-0026
Consequences).

## Decided design

### `sc rewrap --identity <key> [--dry-run]`

One command, one commit, one oplog record (undoable via `sc undo`).

**Secrets half.** For every secret in the tip registry: recover the value
with `--identity` (the P11 `secret_rotate` recovery path), re-seal under a
**fresh DEK** to the secret's *current* recipient set — reverse-resolved
by `recipient_id` against `.sc/recipients.toml`, the P11 pattern — plus
the **full current escrow list**. Closes P11's "existing secrets gain
escrow only when next rotated" gap in one shot. The new secret objects
are accumulated and committed as **one** registry snapshot (not N
`commit_registry` calls).

**Paths half.** For every PROTECTED blob at the tip: unwrap its DEK with
`--identity` (wrap-presence lookup, the `grant` pattern), then **replace**
its wrap list with exactly the governing rule's `granted_keys()` + escrow
list. Convergent DEKs mean the ciphertext ids do not change — a
policy-only commit like `grant`/`revoke`, root tree untouched. This is
the P16 cutover: tombstoned recipients' re-attached wraps are stripped
from the live tip.

**Skip-and-report (decided).** Entries the identity cannot open are
skipped, each reported (name/path + reason); the command commits what
succeeded, prints a summary — `rewrapped N secrets, M blobs; skipped K —
need identities: …` — and **exits non-zero when incomplete**. `--dry-run`
prints the same report without committing, with the same exit semantics
(non-zero when the sweep would be incomplete) so scripts can probe. Rationale: escrow is
forward-only, so no single identity is guaranteed to open pre-escrow
entries; atomic-refuse would make the command unusable exactly when it is
most needed. `sc undo` reverts the whole commit either way.

**Guards.** `secrets::require_recipients` on every secret reseal;
the empty-granted check on every wrap-list rebuild — a rule emptied by
crossed revokes reports that blob as unrewappable (pointing at `sc
grant`) rather than silently skipping or sealing to nobody.

**Honesty caveat (docs + command output).** Rewrap cuts the **live tip**
only. Old snapshots in history still carry the old wraps and old secret
objects — content addressing means rewrap ≠ erasure, the same boundary as
rotation (ADR-0019). Real cutover of an external credential still means
rotating the credential itself. The command prints this caveat.

### Multi-key escrow

`.sc/recipients.toml [escrow]` grows from `key = "scl-pk-…"` to
`keys = ["scl-pk-…", …]`. The old single-`key` format is still read
(back-compat) and migrated to `keys` on the next write.

Commands:
- `sc escrow add <pubkey-or-name>` — append (deduped by key).
- `sc escrow remove <recipient-id-or-name>` — drop one entry.
- `sc escrow show` — list all keys (and the recovery non-guarantee note).
- `sc escrow set <pubkey-or-name>` — kept as replace-the-whole-list-
  with-one sugar (back-compat with P11 scripts/demos).

Every seal path (`secret add`, `secret rotate`, `protect`, `rewrap`)
auto-appends **all** escrow keys, deduped — extending P11's single-key
auto-append. Escrow rotation is composition, not a command: `escrow add
<new>` → `escrow remove <old>` → `sc rewrap`.

### Revoke-hint wording pass (P16 deferral, in scope)

- `sc revoke` (path prefixes): the note now names `sc rewrap` as the
  tip-cutover step — fixing the P16-T3 finding where it pointed at the
  secrets surface (`secret rotate`).
- `sc secret revoke`: hint gains `sc rewrap` alongside `secret rotate`.

## Constraints (binding)

- `crates/crypto` unchanged — pure composition of existing `seal`/`open`/
  `unwrap_dek_with`/`wrap_dek_for` + P11 machinery.
- One commit, one oplog record; ref update is the atomic commit point.
- Root tree byte-identical across rewrap (policy-only; assert in tests).
- Decrypted values/DEKs held in `Zeroizing` buffers, plaintext never
  written to CAS or disk.

## Testing & demo

- Unit: escrow list load/migrate (old `key` form)/dedupe; skip-report
  shape; empty-granted rule reported not skipped.
- Integration:
  - The P16 R1 scenario closed: merge a pre-revoke branch (revoked
    recipient's wrap re-attached at tip) → `sc rewrap` → tip wraps no
    longer include the revoked recipient; root unchanged; one oplog
    record; `sc undo` restores.
  - A pre-escrow secret gains every escrow key in one rewrap.
  - Identity that cannot open one secret: command exits non-zero, commits
    the rest, report names the skipped entry.
  - `--dry-run` commits nothing (tip id unchanged).
- Demo `demo/run_rewrap_demo.sh` (self-checking, house style): escrow
  change → one `sc rewrap` → `secret list` / `protect --list --json`
  prove every entry sealed to the new set, plus the R1 strip end to end.

## Out of scope

Re-encrypting historical snapshots (impossible under content addressing —
documented caveat instead); per-prefix or per-secret selective rewrap
flags (`--secrets-only`/`--paths-only` — YAGNI until asked for); escrow
key *rotation* as a dedicated command (composition covers it); any change
to `crates/crypto`.
