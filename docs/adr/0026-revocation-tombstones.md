# ADR-0026: Revocation tombstones — durable prefix-rule revocation across merges

- **Status:** Accepted
- **Date:** 2026-07-07
- **Phase:** 16
- **Builds on:** ADR-0014 (encrypted paths), ADR-0025 (protected merge & replay)
- **Spec:** `docs/superpowers/specs/2026-07-07-p16-revocation-tombstones-design.md`

## Context

ADR-0025 merges protection rules by union (`union_prefixes`): nothing can
shrink a rule via merge, so nothing silently unprotects. The documented
cost is that a prefix-rule `sc revoke` is not durable — merging any branch
created before the revoke re-adds the recipient via the union, and future
commits under that prefix seal fresh DEKs to them. The per-file-permissions
pillar therefore carries a known bypass.

## Decision

Each `(prefix, recipient)` becomes a last-writer-wins register:
`ProtectPrefix.recipients` changes from a bare key list to sorted entries
`{key, epoch: u32, state: Granted | Revoked}`. A `Revoked` entry is the
tombstone and is retained forever. Grant/revoke write
`epoch = max(current) + 1`; merge keeps the higher-epoch entry per
recipient, and an epoch tie with disagreeing states resolves **Revoked**
(fail-closed). The effective recipient set — the Granted entries only —
gates commit-time sealing (`granted_keys()`). Grant checks and
`--identity` authorization are a separate surface: they work by wrap
presence in `protection.wrapped`, unaffected by the register, so a
tombstoned recipient can still open ciphertext sealed before the revoke
(historical wraps). `secrets::require_recipients` continues to guard the
PublicKey-typed seal paths (`protect`/`secret add`/`secret rotate`); the
effective-set (Granted-only) guard for sealing under a prefix rule lives
in `encrypt_protected`. Replay (rebase/cherry-pick) inherits the
semantics via the shared rule-merge helper; `union_wraps` is untouched
(wrapped DEKs on existing ciphertext are historical facts — tombstones
govern future seals only).

Scope is recipient narrowing only: no `sc unprotect`, whole-prefix rules
still never shrink via merge. Revoke remains re-wrap-free; cryptographic
cutover stays with rotation (ADR-0019) and bulk re-wrap (ADR-0027).

This is a rules-format break: `Protection`'s canonical encoding changes,
so affected snapshot ids change. Clean break per the CLAUDE.md
format-break rule — old-format objects fail to decode with a clear error;
no versioned decode.

## Consequences

- The ADR-0025 boundary scenario (branch → revoke on main → merge the
  pre-revoke branch) ends with the recipient still revoked and future
  commits sealing no DEK to them; `demo/run_revoke_demo.sh` proves it,
  including a deliberate re-grant out-epoching the tombstone.
- Concurrent revoke vs. re-grant at the same epoch resolves revoked —
  a user who re-granted concurrently must re-grant again, which is the
  correct fail-closed cost.
- Rules grow by ~37 bytes per revoked recipient, forever; tombstones are
  never GC'd (they are load-bearing against future merges).
- `sc protect --list` shows per-recipient state and epoch, replacing the
  ADR-0025 "re-check rules after merges" caveat with visible evidence.
- Merging a pre-revoke branch re-attaches the revoked recipient's old
  wraps to the live tip (`union_wraps` keeps historical facts), and since
  `grant` authorizes by wrap presence, a revoked-but-wrap-holding
  recipient can still grant others access to that pre-revoke ciphertext.
  Standing and fresh seals stay tombstone-gated regardless; the full
  cutover for old ciphertext remains rotation (ADR-0019) / bulk re-wrap
  (ADR-0027). Verified empirically at the P16 final review.

## Alternatives considered

- **Keep union + document the boundary** (status quo, ADR-0025): rejected
  as a durable end state for a confidentiality-first VCS.
- **OR-set with tombstoned grant tags** (CRDT remove-wins): equivalent
  outcomes on all worked cases, but requires deterministic tag minting
  (encoding forbids randomness) and grows a tag+tombstone log per
  recipient; the epoch register is simpler and equally fail-closed.
- **Permanent tombstones (2P-set):** revoked-forever blocks legitimate
  re-grant without issuing a new keypair; too blunt.
- **Last-writer-wins by wall clock:** no trustworthy global clock in a
  DVCS; epochs are causal enough and deterministic.

## Refinements discovered during the build

- **Format break needed a clear-error mechanism, not silent misreads.** The
  snapshot tag bumped `2 → 4` (`TAG_SNAPSHOT_LEGACY = 2`) so a pre-P16 store
  refuses to decode with an explicit "pre-P16 snapshot encoding" `Malformed`
  error instead of misparsing the new `Protection` layout.
- **`protect` on an already-protected prefix changed from replace to
  extend/re-grant.** The spec's implicit assumption — a second `sc protect
  <prefix>` replaces the rule wholesale — would silently drop tombstones.
  It now (re-)grants the named recipients at the rule's next epoch, so
  existing `Revoked` entries survive a later `protect` call on the same
  prefix.
- **`encrypt_protected` became fallible.** The zero-effective-recipients
  guard (crossed revokes emptying a rule) lives inside `encrypt_protected`
  itself rather than at a caller checkpoint, so every commit path that seals
  protected content gets the loud failure for free.
- **`sc protect --list` gained `--json` and per-recipient state rendering**
  (`granted@eN` / `REVOKED@eN`), turning the ADR-0025 "re-check rules after
  merges" caveat into something a user can actually see.
