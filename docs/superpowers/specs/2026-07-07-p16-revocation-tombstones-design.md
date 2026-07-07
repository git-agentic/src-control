# P16 — Revocation tombstones / rule narrowing: design

**Date:** 2026-07-07
**Status:** Approved
**ADR:** 0026 (Proposed → Accepted when built)
**Horizon:** `2026-07-07-roadmap-horizon-p16-p20-design.md`

## Problem

ADR-0025 merges protection rules by recipient-set union
(`union_prefixes`, `crates/repo/src/protect.rs`), so a prefix-rule
`sc revoke` is reversed by merging any branch created before the revoke:
the union re-adds the recipient, and future commits under the prefix seal
fresh DEKs to them. The per-file-permissions pillar carries a documented
bypass.

## Decided semantics: per-recipient epoch LWW, revoke-wins ties

Each `(prefix, recipient)` pair is a last-writer-wins register ordered by
an integer epoch, with a fail-closed tiebreak.

### Data model

`ProtectPrefix.recipients` changes from `Vec<[u8; 32]>` to a sorted
per-recipient register list:

```
RecipientEntry {
    key:   [u8; 32],          // X25519 public key
    epoch: u32,               // monotone per (prefix, recipient)
    state: Granted | Revoked, // Revoked entry IS the tombstone
}
```

- Entries are kept **sorted by key** for canonical encoding.
- A `Revoked` entry is retained indefinitely (~37 bytes/recipient); it is
  never GC'd — it is load-bearing against future union merges.
- The **effective recipient set** — used by commit-time sealing, grant
  checks, and `--identity` authorization — is the `Granted` entries only.
  [Correction (P16 as shipped): this held only for commit-time sealing
  (`granted_keys()`). `sc grant`'s authorization check and `--identity`
  decryption (`decrypt_with`) work by wrap presence in
  `protection.wrapped`, independent of the register — a revoked
  recipient can still decrypt ciphertext sealed before the revoke. See
  ADR-0026's Decision section.]
- The existing empty-set guard generalizes: any operation that would
  leave a prefix with zero *effective* recipients is refused.
  `secrets::require_recipients` remains the single chokepoint.
  [Correction: as shipped, `require_recipients` guards the PublicKey-typed
  seal paths (`protect`/`secret add`/`secret rotate`); the effective-set
  guard for sealing under a prefix rule lives in `encrypt_protected`.]

### Operations

- `sc protect <prefix> --to <recipients>` (new rule): all recipients
  minted at `epoch: 1, Granted`.
- `sc grant <prefix> --to <r>`: writes `{epoch: max(current epochs on
  the prefix) + 1, Granted}` for `r` — a re-grant after a revoke
  therefore out-epochs the tombstone.
- `sc revoke <prefix> --recipient-id <id>`: writes `{epoch:
  max(current) + 1, Revoked}`. Otherwise unchanged: still
  commit-creating, still **no re-wrap** — cryptographic cutover remains
  rotation's job (ADR-0019) and, at scale, P17's bulk re-wrap. The
  existing "run rotate for a real cutover" hint stays.
- **No `sc unprotect`.** Whole-prefix rules never shrink via merge;
  P16 narrows recipient standing only. (Decided scope cut.)

### Merge & replay

`union_prefixes` becomes `merge_prefixes`:

- Union by prefix, as today (rules themselves never disappear).
- Per recipient key present on either side: keep the **higher-epoch**
  entry.
- Equal epochs with disagreeing states → **Revoked wins** (fail-closed,
  the narrowing direction of P15's philosophy).
- Equal epochs, same state → identical entries, keep one.
- Disjoint recipients compose independently (per-recipient registers).

Rebase and cherry-pick inherit the semantics automatically: P15 routed
replay's rule handling through the same rule-merge helper.

`union_wraps` is **untouched**: wrapped DEKs on existing ciphertext are
historical facts about who could read an object when it was sealed;
tombstones govern *future* seals only.

### Worked cases

| Scenario | Outcome |
|----------|---------|
| Branch B forked with `R@1:Granted`; main revokes → `R@2:Revoked`; merge B | `R@2:Revoked` — durable (the ADR-0025 boundary case) |
| After the above, main re-grants → `R@3:Granted` | Granted — deliberate re-grant beats the old tombstone |
| Concurrent: main `R@2:Revoked`, B re-grants `R@2:Granted` | Tie → Revoked (fail-closed) |
| B revokes then re-grants (`R@3:Granted`) unaware main revoked (`R@2:Revoked`) | `R@3:Granted` — B acted with knowledge of a revoke and deliberately re-granted |
| Two branches grant different new recipients | Both granted — registers compose |

## Format break

`Protection`'s canonical encoding changes, so every snapshot id embedding
a protection rule changes. Per the CLAUDE.md format-break rule and
project precedent: **clean break** — no versioned decode of pre-P16
objects. Decoding an old-format object must fail with a clear error, not
garble. Encode/decode round-trip tests and any fixture ids update; demo
repos are re-created by their scripts anyway.

## Observability

`sc protect --list` (text and `--json`) shows per-recipient `state` and
`epoch`, tombstones included. This replaces the ADR-0025 "re-check after
merges" caveat with visible evidence that revokes hold.

## Testing & demo

- Unit tests on `merge_prefixes`: higher-epoch wins in both directions,
  tie → revoke, re-grant after revoke, disjoint recipients, prefix union
  still grows.
- Integration test + `demo/run_revoke_demo.sh` proving end to end:
  branch → revoke on main → merge the pre-revoke branch → recipient still
  revoked **and** a fresh commit under the prefix seals no DEK to them →
  deliberate re-grant wins over the tombstone.
- Replay coverage: cherry-pick/rebase of a pre-revoke commit does not
  resurrect the recipient.

## Out of scope

Durable whole-prefix removal (`sc unprotect`), bulk re-wrap on revoke
(P17), secret-registry revocation semantics (unchanged; `secret revoke`
stays metadata-only per ADR-0019), tombstone GC (never).
