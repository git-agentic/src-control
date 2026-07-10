# ADR-0014: Per-file permissions as encrypted paths (convergent encryption)

- **Status:** Accepted
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
  instead. **Superseded for newly sealed content by ADR-0043 (P33):** all
  content sealed from P33 on uses a fresh random DEK + nonce, closing this
  oracle; convergent dual-read is retained, so the caveat remains true for
  pre-P33 ciphertext still in history until a `sc rewrap` upgrades the tip.
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

## As built (P7)

The decision shipped as designed; the concrete shape settled as follows.

- **Split envelope.** An encrypted file is a normal, content-addressed `Blob`
  whose bytes are `nonce(24)‖ciphertext`; its `TreeEntry.perms` carries the
  `PROTECTED` bit (`0b0000_0001`). The per-recipient *wrapped DEKs* live entirely
  on the policy side — `Snapshot.protection.wrapped: BTreeMap<ObjectId,
  Vec<WrappedKey>>`, keyed by the ciphertext blob's id — never inside the blob.
  This keeps the encrypted blob a deterministic function of the plaintext (stable
  id, dedup) while the necessarily-random per-recipient wraps churn off to the
  side without affecting any object id.
- **Convergent API in `scl-crypto`.** `encrypt_path(plaintext) -> (nonce‖ct,
  Zeroizing<DEK>)` derives `DEK = HKDF-SHA256(BLAKE3(plaintext), info=
  "scl-path-dek-v1")` and `nonce = HKDF(... "scl-path-nonce-v1")[..24]`, AEAD
  AAD `b"scl-path-v1"`; `decrypt_path(blob, dek)` is the AEAD-verified inverse.
  DEK wrapping reuses Phase 2's X25519→HKDF→AEAD via public `wrap_dek_for` /
  `unwrap_dek_with`. Recipient pubkeys are reconstructed in `repo` through
  `PublicKey::from_bytes`.
- **Persisted prefix rules + commit-time auto-encryption.** `protection.prefixes`
  is a list of `ProtectPrefix { prefix, recipients: Vec<[u8;32]> }` (recipient
  *pubkeys*, not ids, so commit can re-wrap freshly minted DEKs without an
  identity). `commit` partitions working files by `matching_prefix` (longest
  prefix wins), encrypts matching files, marks their entries `PROTECTED`, and
  populates `policy.wrapped`. **Protected paths bypass the P5 secret scanner** —
  scanning only the plaintext partition — so a deliberately secret-looking file
  under a protected prefix is encrypted rather than rejected.
- **Skip-on-unauthorized checkout, with carry-forward.** `materialize` takes an
  optional identity; for a `PROTECTED` entry it unwraps the matching `WrappedKey`
  and `decrypt_path`s, writing plaintext only on success. With no identity or no
  matching key it **skips** the file (removing any stale on-disk copy) and reports
  the path. Crucially, `commit` carries forward the wrapped DEKs (and ciphertext
  ids) for protected files a non-recipient committer never decrypted, so a commit
  by someone lacking the key cannot silently drop protected content.
- **Policy-only grant/revoke.** `grant` recovers each affected DEK with an
  authorized identity and re-wraps it for the new recipient (deduped by recipient
  id), `revoke` drops a recipient's wraps and prefix membership; both commit a
  snapshot reusing the tip's exact root tree — **no blob or tree id changes**.
- **CLI.** `sc protect <prefix> --to <names>` / `sc protect --list`,
  `sc grant <prefix> --to <names> [--identity]`, `sc revoke <prefix>
  --recipient-id <id>`. `sc switch [--identity]` resolves the identity softly
  (`--identity`/`SC_IDENTITY`/`~/.sc/identity`): a missing key is not an error —
  protected files are simply skipped and listed. `demo/run_protect_demo.sh`
  proves the headline end-to-end (commit→clone→keyless skip→keyed decrypt) with a
  positive control guaranteeing the ciphertext assertion is non-vacuous.
