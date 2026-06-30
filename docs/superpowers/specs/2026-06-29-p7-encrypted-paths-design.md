# P7 — Per-file permissions / encrypted paths: design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-06-29
- **Phase:** 7
- **Refines:** ADR-0014 (firm to Accepted at build time)
- **Builds on:** Phase 2 crypto (ADR-0008/0009/0010), P6 clone (ADR-0013), P5 scanner (ADR-0017)

## Goal

Read-confidentiality for designated paths: `sc protect <prefix> --to <recipients>`
marks a subtree private; its files are envelope-encrypted so only authorized
recipients can read them. Combined with P6 clone, this realizes the third thesis
pillar end to end — **an unauthorized clone receives protected files as ciphertext
it cannot decrypt**.

## Decisions (locked: brainstorm + ADR-0014)

1. **Split envelope.** The on-disk encrypted object is a **plain `Blob` of
   `nonce‖ciphertext`** (tree entry's `perms` byte sets a `PROTECTED` bit). Its
   `ObjectId` is a deterministic function of the plaintext → perfect dedup. The
   per-recipient wrapped DEKs live in the snapshot **protection policy**, keyed by
   ciphertext blob id. No new object kind.
2. **Convergent encryption.** `DEK = HKDF(BLAKE3(plaintext))`, deterministic nonce
   from the plaintext hash, XChaCha20-Poly1305. Identical plaintext → identical
   ciphertext → stable id. (Accepted caveat: confirmation-of-known-plaintext, per
   ADR-0014.) DEK wrapped per recipient via the Phase 2 X25519→HKDF→AEAD path.
3. **Persisted prefix rules.** `protect` records `(prefix → recipient pubkeys)` in
   the policy; existing matching files are encrypted at protect time; thereafter
   **`commit` auto-encrypts** any new/changed file under a protected prefix for
   that prefix's recipients. Protected files **bypass the P5 secret scanner**.
4. **Recipients stored as public keys** in the policy → self-contained and
   clone-portable; `commit` can wrap new files' DEKs without reading
   `.sc/recipients.toml`. (`protect`/`grant` resolve names → pubkeys via
   `recipients.toml` at the CLI; the resolved pubkeys are what's stored.)
5. **Unauthorized checkout skips** protected files (with a notice); plaintext is
   never written except via an authorized decrypt. Ciphertext is never written to
   the working tree.
6. **grant/revoke are policy-only** — they touch `policy.wrapped` (+ prefix
   membership), never the file objects, so no tree/snapshot churn on the file
   content and dedup is preserved.

## Out of scope (this round)

- Write authorization / per-file write permissions (this cut is read-only).
- Random per-encryption opt-in for high-sensitivity paths (ADR-0014 follow-on).
- Re-encryption/rotation tooling beyond grant/revoke (rotating already-disclosed
  content is the user's call).
- Encrypting the file *names*/tree structure (paths remain visible; only content
  is encrypted).

## Architecture

### `core` — object model + policy (pure data, no crypto)

- `TreeEntry.perms`: define `pub const PROTECTED: u8 = 0b0000_0001;` (a bit in the
  existing reserved byte). A blob entry with this bit set means "the blob bytes
  are a `nonce‖ciphertext` envelope, not plaintext."
- `Snapshot` gains `protection: Protection` (after `secrets`). **Format break** —
  snapshot ids change (acceptable pre-release, as with the secrets registry).
  Encode/decode + all constructors updated.
- New `core` types (data only):
  ```rust
  pub struct ProtectPrefix { pub prefix: String, pub recipients: Vec<[u8; 32]> } // recipient pubkeys
  pub struct Protection {
      pub prefixes: Vec<ProtectPrefix>,                  // sorted by prefix, canonical
      pub wrapped: BTreeMap<ObjectId, Vec<WrappedKey>>,  // ciphertext id -> wrapped DEKs
  }
  ```
  Reuses the existing `core::WrappedKey { recipient_id, wrapped_dek }`. `Protection`
  encodes canonically (sorted prefixes, BTreeMap is ordered) so the snapshot id is
  order-independent.

### `scl-crypto` — convergent path encryption (no new primitive)

```rust
/// Deterministically encrypt file content. dek = HKDF(BLAKE3(plaintext)); nonce
/// derived from the plaintext hash. Returns the `nonce‖ciphertext` blob bytes
/// plus the DEK (to be wrapped per recipient).
pub fn encrypt_path(plaintext: &[u8]) -> (Vec<u8>, Zeroizing<[u8; 32]>);
/// Inverse: given the blob bytes and the DEK, recover plaintext (AEAD-verified).
pub fn decrypt_path(blob: &[u8], dek: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>>;
/// Wrap a DEK for a recipient (X25519→HKDF→AEAD); returns a core::WrappedKey.
pub fn wrap_dek(dek: &[u8; 32], recipient: &PublicKey) -> WrappedKey;
/// Unwrap a DEK with an identity, if it is the wrapped recipient.
pub fn unwrap_dek(wrapped: &WrappedKey, identity: &SecretKey) -> Result<Zeroizing<[u8; 32]>>;
```

`wrap_dek`/`unwrap_dek` expose the existing internal envelope logic (the same code
Phase 2 `seal`/`open` use). `encrypt_path` reuses the XChaCha20-Poly1305 AEAD with
a content-derived key+nonce. Plaintext/DEK are `Zeroizing`.

### `scl-repo` — policy plumbing, commit, checkout, protect/grant/revoke

- **`Protection` carried through `fork`/`commit`** like `secrets`.
- **`commit`**: build the file set; for each file whose path matches a protected
  prefix: `encrypt_path` → put the blob (stable id) → mark its tree entry
  `PROTECTED` → `wrap_dek` for each of the prefix's recipients → set
  `policy.wrapped[blob_id]`. Protected paths are **excluded from the scanner**
  (`scan_files` skips them). The protection policy carries forward; stale
  `wrapped` entries for blobs no longer referenced are pruned at commit (only keep
  entries for blob ids present in the new tree).
- **checkout/materialize** gains an optional `identity: Option<&SecretKey>`: for a
  `PROTECTED` entry, look up `policy.wrapped[blob_id]`, `unwrap_dek` with the
  identity, `decrypt_path`, write plaintext. No identity / not a recipient → skip
  the file and record it in a returned "skipped" list the CLI reports.
- **`protect(prefix, recipients: &[PublicKey])`**: add/replace the prefix rule;
  re-encrypt existing matching working-tree files; commit. **`grant(prefix,
  authorized: &SecretKey, new: &PublicKey)`**: for each blob id whose path is under
  the prefix, recover the DEK via `unwrap_dek` with `authorized`, `wrap_dek` for
  `new`, append to `policy.wrapped[blob_id]`; add `new` to the prefix recipients;
  commit a policy-only snapshot. **`revoke(prefix, recipient_id)`**: drop that
  recipient's wrapped entries + prefix membership; commit.

### CLI

- `sc protect <prefix> --to a,b,c` (resolve via `.sc/recipients.toml`),
  `sc protect --list`.
- `sc grant <prefix> --to d [--identity <path>]`, `sc revoke <prefix> --recipient-id <id>`.
- `sc checkout`/`switch` decrypt transparently using the resolved identity
  (`--identity`/`SC_IDENTITY`/`~/.sc/identity`); skipped protected files are listed.

## Data flow: the headline property

`sc protect secrets/ --to alice` → `secrets/*` become `PROTECTED` ciphertext
blobs; `policy.wrapped` holds DEKs wrapped to alice. `sc push`/`clone` (P6)
transfers the ciphertext blobs + the policy verbatim. A clone held by **mallory**
(no key): `sc switch`/checkout finds the `PROTECTED` entries, no wrapped DEK
unwraps with mallory's key → the files are **skipped** (present in the store as
ciphertext, absent from the working tree). With **alice**'s key they decrypt.

## Error handling

New `scl-repo::Error`: `NotProtected(String)` (grant/revoke on an unprotected
prefix), `NotAuthorized(String)` (explicit read/grant needs a DEK your key can't
unwrap). Checkout *skips* rather than errors (returns the skipped list). The CLI
absorbs via `anyhow`. A `decrypt_path` AEAD failure → `Crypto`/`Decrypt`.

## Testing

- **crypto:** `encrypt_path` determinism (same plaintext → identical bytes & id;
  different plaintext → different); `decrypt_path` round-trip; tamper → AEAD error;
  `wrap_dek`/`unwrap_dek` round-trip + wrong-key fails.
- **core:** `Snapshot` with a `Protection` policy round-trips; canonical
  (prefix/key order-independent) id.
- **repo:** protect encrypts existing files (tree entries `PROTECTED`, blobs are
  `nonce‖ciphertext`, `policy.wrapped` populated); commit auto-encrypts a new file
  under a protected prefix; authorized checkout decrypts, unauthorized **skips**
  (file absent, listed as skipped); grant adds a recipient **without changing any
  blob/tree id** (policy-only); revoke removes access; the scanner does not reject
  a secret-looking file under a protected prefix; an unprotected file is untouched.
- **headline / e2e:** clone a repo with a protected path to a no-key context →
  protected file absent from the checkout but present as ciphertext in
  `.sc/objects`; with the recipient key it decrypts. A `demo/run_protect_demo.sh`.

Every new behavior ships with a test.

## ADR

Firm **ADR-0014** Proposed → Accepted at build time, recording the as-built
specifics: the split envelope (PROTECTED blob + policy-side wrapped DEKs),
`encrypt_path`/`decrypt_path` convergent API, persisted prefix rules with
commit-time auto-encryption + scanner bypass, pubkeys-in-policy, skip-on-
unauthorized checkout, and policy-only grant/revoke.

## Open follow-ons (not this round)

- Write permissions / signed-commit authorization for protected paths.
- Opt-in random (non-convergent) mode for high-sensitivity, low-entropy files.
- Encrypted file names / tree structure.
- Rotation tooling for already-disclosed content.
