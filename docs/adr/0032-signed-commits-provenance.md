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

## Decision

Signatures are CAS OBJECTS — a new kind, `TAG_SIGNATURE = 5`:
`Signature { snapshot: ObjectId, signer: ed25519-pk, sig }`, signing the
domain-separated snapshot id (`"sc-snapshot-sig-v1" || id`, attesting the
full canonical encoding under BLAKE3 collision resistance). Snapshot ids
are untouched; retroactive signing is natural; duplicates dedup. A local
gc-rooted index (`.sc/signatures`, snapshot → signature ids) provides
lookup and reachability, and gc drops entries whose snapshot died so
signatures never retain dead history. Transfer needs ZERO wire changes:
senders include indexed signatures for transferred snapshots in the
existing pack; receivers detect TAG_SIGNATURE among received ids and
index them — identical over local and ssh transports. Git boundary drops
signatures with a warning count.

Identity is UNIFIED v2 (user-decided): one keyfile seed derives both the
X25519 encryption key and an Ed25519 signing key; `sc keygen` emits v2,
v1 files keep encrypting but cannot sign (re-key to sign — a signing key
cannot be derived from an X25519 key). `recipients.toml` gains
`[signing]` and `[signers] trusted`. Surface: `sc commit --sign`,
`sc amend --sign`, retroactive `sc sign <ref>` (also the MVP path for
merge/pick/rebase results), `sc log` markers (trusted ✓ / untrusted ? /
INVALID ✗ / unsigned), `sc verify [--require]` walking all parents.
Ed25519 lives in `crates/crypto` only; the quarantine holds.

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
