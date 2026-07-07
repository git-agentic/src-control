# ADR-0027: Bulk re-wrap and multiple escrow keys

- **Status:** Proposed
- **Date:** 2026-07-07
- **Phase:** 17
- **Builds on:** ADR-0019 (secret lifecycle), ADR-0009 (key management), ADR-0026 (revocation tombstones)

## Context

ADR-0019 ships rotation and re-wrap one secret / one path at a time, and a
single break-glass escrow key. An org-wide recipient change (offboarding,
escrow rotation) requires touching every entry manually, and once ADR-0026
makes revocation durable, acting on it across a whole repo should be one
operation.

## Decision

A bulk operation (working name `sc rewrap`) re-wraps every secret and
every protected prefix to the current recipient/escrow sets in one
invocation, composed entirely from the existing `seal`/`open` and ADR-0019
rotate machinery — `crates/crypto` is unchanged. Escrow becomes a managed
list (add/remove/rotate) instead of a single key. The operation is
oplog-recorded and undoable; every seal path goes through
`secrets::require_recipients`.

## Consequences

- One-command cutover after a recipient/escrow change; the demo changes
  the escrow key and shows every entry re-sealed.
- Rotation ≠ erasure still holds (ADR-0019): old ciphertext in history
  remains readable to holders of old DEKs; real cutover also rotates the
  external credential.

## Alternatives considered

- **Script the per-entry commands:** no atomicity, no oplog record, easy
  to miss entries.
- **Auto-rewrap on every revoke:** hidden expensive writes; explicit bulk
  command keeps the destructive-operation gate visible.
