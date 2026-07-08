# ADR-0032: Signed commits & provenance

- **Status:** Accepted
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

## Refinements discovered during the build

Code-verified against `crates/crypto/src/signing.rs`,
`crates/repo/src/signatures.rs`, `crates/repo/src/sync.rs`, and
`crates/cli/src/main.rs` at acceptance.

- **Identity v2 derivation.** A v2 identity is one random seed
  (`scl-id-<hex64>`), fed through HKDF-SHA256 twice with distinct domain
  strings — `"scl-id-v2-enc"` for the X25519 encryption secret,
  `"scl-id-v2-sig"` for the Ed25519 signing seed — so one keyfile yields
  both halves deterministically and the two secrets are cryptographically
  independent. `parse_identity` (`crates/crypto/src/signing.rs`) accepts
  both the v2 `scl-id-` form and the legacy v1 `scl-sk-` form; a v1 file
  parses encryption-only (`identity.signing == None`), and any attempt to
  sign with it fails with a clear "v1 identity, re-key to sign" error
  rather than silently no-op'ing.
- **Signature object shape.** `TAG_SIGNATURE = 5` stays bytes-only in
  `crates/core` (no crypto dependency crosses the quarantine): a
  `SignatureObj { snapshot, signer, sig }`. The signed message is the
  domain-separated string `"sc-snapshot-sig-v1" || id`, so a signature
  attests one exact canonical encoding via BLAKE3 collision resistance.
  Verification uses `verify_strict` and returns `false` — never
  panics — on corrupt or adversarial signature bytes.
  `decrypt_with`/verification distinguish ciphertext corruption from a
  genuine authorization failure, matching P15's discipline.
- **Four-state precedence is order-independent.** `sig_status` walks every
  indexed signature for a snapshot and returns on the first `Invalid`
  found, regardless of position — a snapshot with one invalid signature
  and one valid-and-trusted signature is `Invalid`, full stop. Only once
  every signature verifies does trust ranking apply: `Trusted` beats
  `Untrusted` beats `Unsigned` (no signatures at all).
- **Transfer needs zero wire changes.** Signatures are ordinary CAS
  objects, so they ride the existing pack format unmodified. The receiver
  side runs `put_pack` then `index_incoming` over the newly-written ids;
  `index_incoming` treats a missing snapshot for an incoming signature as
  a **hard error** (`NotFound`), not a skip — the seam's contract is that
  every id just written by `put_pack` is retrievable, so a `NotFound`
  here means the transfer itself is broken, not that the signature is
  stale.
  - **Review-caught Critical:** the first cut of `fetch` conflated
    "already have the snapshot" with "already have its signatures" —
    a re-fetch of an already-possessed commit skipped resending its
    signature, so a signature added to a remote *after* the first fetch
    never reached a repo that had fetched before the signing. Fixed by
    over-sending every indexed signature for the full transfer set
    (cheap: signature objects are small) with idempotent dedup on the
    receiving `index_incoming`/`append_index` (a repeated `(snapshot,
    sig_id)` entry is a no-op). Pinned as
    `retroactive_signature_propagates_on_refetch`. `sc clone` sidesteps
    the whole class by reindexing from a full post-copy object scan
    (`crate::signatures::reindex`) rather than depending on transfer-time
    bookkeeping precision.
  - Git export drops signatures (no Git-native representation is wired up
    in this phase) and reports a `signatures_dropped` count rather than
    silently discarding them.
- **`sc keygen` output, twice review-caught.** The pre-existing `public
  key:` line and its exact column spacing had to be restored
  byte-for-byte — eight other demos parse that line with `awk`, and a
  reflow broke all of them. The new signing key gets its **own** distinct
  `signing key:` line rather than being folded into the existing one, for
  the same parseability reason.
- **`sc log` pipe safety.** `sc log`'s per-commit signature status is now
  pre-computed for the whole history before any line is printed (batching
  the signature-index I/O ahead of output), and `print_line` catches
  `BrokenPipe` and exits 0 instead of panicking — closing a regression
  where `sc log | grep -q <pattern>` under `set -o pipefail` (this demo's
  own idiom, and others') could hit a broken-pipe panic once `grep -q`
  closed its stdin early.
- **Dependency footprint.** `ed25519-dalek` is the only new dependency,
  added to `crates/crypto` only (the quarantine holds — see CLAUDE.md).
  It pulls in `curve25519-dalek 5.0` alongside the `4.x` series X25519
  already depends on; the two major versions coexist as a cosmetic
  duplicate in `Cargo.lock` with no functional conflict (Ed25519 and
  X25519 use their own curve types, not a shared one).

### Threat model honesty

- **Defends:** history rewriting in clones/remotes — a rewritten snapshot
  gets a new id and starts unsigned, so `sc verify --require` flags it —
  and attribution disputes over who authored a given snapshot.
- **Does NOT defend:** a trusted signer acting maliciously (signing is
  attribution, not a code-quality or intent guarantee); code quality or
  correctness of signed content in any way; replay of a legitimately
  signed snapshot into a different branch position (a signature binds
  identity to a snapshot id, not a snapshot to a branch or position in
  history).
- **By design, not a gap:** `sc amend`/`sc rebase`/`sc merge` all produce
  new snapshot ids, which start unsigned — the new object is a new claim,
  and re-signing (`sc sign`) is a deliberate, visible act rather than
  something the tooling carries forward silently.
