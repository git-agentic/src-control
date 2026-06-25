# ADR-0014: Per-file permissions as encrypted paths (convergent encryption)

- **Status:** Proposed
- **Date:** 2026-06-25
- **Phase:** 7

## Context

The third thesis pillar is per-file permissions. We scope the first cut to
**read confidentiality**: designate paths/subtrees as private so their content is
readable only by authorized recipients. This generalizes the Phase 2 committed-
secrets envelope from named env vars to arbitrary file content, and — combined
with clone (P6) — yields the headline property: an unauthorized clone receives the
protected files but only as ciphertext.

A tension with the project's bedrock invariant (content addressing, "identical
content stored once") is that conventional encryption with a random key/nonce
makes the same plaintext encrypt to different ciphertext every commit — new
`ObjectId` each time, dedup broken, noisy history.

## Decision

1. **Protection policy on the snapshot.** Add a per-snapshot policy — an ordered
   list of `(path_prefix, [recipient_id])` — stored alongside the existing
   `secrets` registry on `Snapshot`. A file under a protected prefix is encrypted;
   the per-entry `perms` byte on `TreeEntry` carries a `PROTECTED` flag so read
   and checkout know an entry is an encrypted object rather than a plain blob.

2. **Convergent (content-derived) encryption.** Derive the per-file data key from
   the plaintext: `DEK = HKDF(BLAKE3(plaintext))`, then `ciphertext =
   XChaCha20-Poly1305(DEK, plaintext)` with a nonce also derived deterministically
   from the plaintext hash. Identical plaintext therefore yields identical
   ciphertext and a stable `ObjectId` — **content addressing and dedup are
   preserved**, and history stays quiet when content doesn't change. The DEK is
   wrapped per recipient exactly as in Phase 2 (X25519 → HKDF → AEAD), reusing
   `scl-crypto`.

3. **Authorization, grant, revoke** mirror Phase 2: holding a recipient private
   key is authorization; `sc protect <path> --to …` wraps the DEK for those
   recipients; granting access to a protected path re-wraps each affected file's
   DEK for the added recipient; revoking removes wrapped-key entries (true secrecy
   of already-disclosed content still requires rotating the plaintext).

4. **Checkout/read behavior.** An authorized context decrypts protected files
   transparently on checkout/read. An unauthorized context **skips** protected
   files (with a clear notice) rather than writing ciphertext to the working tree;
   plaintext is never written to disk except via the normal authorized checkout
   path.

## Consequences

- The content-addressing invariant (ADR-0002) survives encryption; protected and
  unprotected files share the same store, dedup, and stable-id properties.
- **Accepted caveat of convergent encryption:** an attacker who already holds a
  candidate plaintext can confirm whether it is present in the repo (the ciphertext
  /id is a deterministic function of the plaintext). This is the standard trade-off
  for encrypted content-addressed stores and is acceptable for source content; it
  is documented so users with low-entropy secret files choose Phase 2 secrets
  instead.
- Reuses `scl-crypto` and the recipient model wholesale; no new crypto primitives.
- The protection policy is a snapshot-level object like the secrets registry, so
  it versions and travels with the code.

## Alternatives considered

- **Random per-encryption (fresh DEK + nonce each time).** Strongest secrecy (no
  confirmation attack) but breaks dedup and makes history noisy, requiring a
  plaintext→object cache to avoid re-encrypting unchanged files every commit.
  Rejected as the default because it sacrifices the project's bedrock content-
  addressing/dedup invariant; may be offered as an opt-in per-policy mode for
  high-sensitivity paths.
- **Whole-repo encryption.** Coarse, all-or-nothing, and incompatible with
  per-path recipients; rejected (same reasoning as ADR-0008).
- **Policy-only (no encryption), tool-enforced read refusal.** Doesn't protect
  content in an unauthorized clone — the whole point — so rejected for the read-
  confidentiality goal.
