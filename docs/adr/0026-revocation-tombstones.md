# ADR-0026: Revocation tombstones — durable prefix-rule revocation across merges

- **Status:** Proposed
- **Date:** 2026-07-07
- **Phase:** 16
- **Builds on:** ADR-0014 (encrypted paths), ADR-0025 (protected merge & replay)

## Context

ADR-0025 merges protection rules by union (`union_prefixes`): nothing can
shrink a rule via merge, so nothing silently unprotects. The documented
cost is that a prefix-rule `sc revoke` is not durable — merging any branch
created before the revoke re-adds the recipient via the union, and future
commits under that prefix seal fresh DEKs to them. The per-file-permissions
pillar therefore carries a known bypass.

## Decision

Protection rules become grant/revoke **events** rather than a bare
recipient set. Merge unions the events; the effective recipient set is
derived from them, with an ordering (per-prefix epoch or DAG causality —
to be fixed in the phase spec) that lets a revoke recorded *after* a grant
win over that grant regardless of which branch carries it. Concurrent
grant + revoke resolves revoke-wins (fail-closed). Tombstones are retained
indefinitely.

This is a rules-format break: encodings embedding protection rules change,
so affected snapshot ids change. Handled per the CLAUDE.md format-break
rule.

## Consequences

- The ADR-0025 boundary scenario (branch → revoke on main → merge the
  pre-revoke branch) ends with the recipient still revoked; demo script
  proves it.
- Rules grow monotonically in event count; effective-set derivation is a
  fold over events.
- Cryptographic cutover still requires re-wrap/rotation (ADR-0019,
  ADR-0027) — tombstones govern *future* seals, not old ciphertext.

## Alternatives considered

- **Keep union + document the boundary** (status quo, ADR-0025): rejected
  as a durable end state for a confidentiality-first VCS.
- **Last-writer-wins recipient sets:** loses fail-closed behavior on
  concurrent edits and silently drops grants.
