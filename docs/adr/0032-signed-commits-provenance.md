# ADR-0032: Signed commits & provenance

- **Status:** Proposed
- **Date:** 2026-07-08
- **Phase:** 22
- **Builds on:** ADR-0002 (content addressing), ADR-0009 (key management), ADR-0019 (recipients.toml conventions)

## Context

The security thesis covers confidentiality (secrets, protected paths,
revocation, rewrap) but not integrity attribution: nothing binds a
snapshot to the identity that created it, and a clone can rewrite history
undetectably. Signed commits are the last unbuilt governance pillar,
gestured at since ADR-0009.

## Decision (direction — firmed by the phase brainstorm)

Commits gain optional signatures over the canonical snapshot encoding,
made with the existing identity infrastructure. The carrier must not
change content-addressed ids — a signature-bearing snapshot would change
its own id, so signatures live beside objects (sidecar registry keyed by
snapshot id vs. detached signature store is the central design question
for the phase brainstorm, along with how signatures travel over
clone/fetch/push and the sc↔git boundary). `sc log` shows per-commit
verification status; `sc verify` walks a range; trust policy (which
public keys are trusted signers) rides `recipients.toml` alongside
escrow. Signing crypto is added to `crates/crypto` only (Ed25519 is the
expected, justified new dependency; the RustCrypto quarantine holds).

## Consequences

- Tampered history in a clone becomes detectable (`sc verify` fails);
  unsigned or untrusted-key commits are visibly flagged, not hidden.
- Signatures are attribution, not confidentiality: they compose with, and
  do not alter, the P7/P16 encryption model.
- Git interop: exported/pushed commits cannot carry sc signatures in a
  form git verifies — the boundary behavior (drop with a warning, or
  best-effort mapping) is a phase-brainstorm decision.

## Alternatives considered

- **Signature inside the snapshot encoding:** changes every id and makes
  signing retroactively impossible; rejected on ADR-0002 grounds.
- **GPG/SSH-signature reuse:** heavier dependency surface and a second
  identity system beside the X25519 recipients; rejected in favor of one
  identity infrastructure.
