# Phase 2 — Native committed secrets: design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-06-24
- **Scope:** Full Phase 2 as specified in ADR-0008 and ADR-0009
- **Supersedes choices in:** brainstorming dialogue 2026-06-24

## Goal

Let env vars / keys be committed directly into repo state, encrypted at rest and
in transit, and decrypted only inside an authorized execution context — with no
external vault. This delivers the full Phase 2 wedge: the `scl-crypto` crate,
multi-recipient envelope encryption, grant/revoke by re-wrapping, a `KeyProvider`
abstraction, environment injection on run, and a standalone proof command.

The headline property to prove: **a context that does not hold an authorized
private key sees only ciphertext; an authorized context decrypts in memory and
injects the value into a child process environment — plaintext never touches
disk.**

## Decisions (locked during brainstorming)

1. **Scope:** full Phase 2 as ADR'd (not a thin slice).
2. **Secret model:** secrets are a namespace *separate from the file tree*. The
   `Snapshot` carries a side registry `secrets: [(name, ObjectId)]`. Secrets are
   env vars, not files; `checkout` never materializes them.
3. **Recipients:** a committed `.sc/recipients.toml` maps human-readable names →
   X25519 public keys. `--to alice,ci,prod` resolves through this file.
4. **Identity:** `sc keygen` generates an X25519 keypair (own format); the
   private key is supplied for decryption via a `KeyProvider` (`FileKeyProvider`
   now; env/agent/KMS later). Resolution order: `--identity` > `SC_IDENTITY` env
   > `~/.sc/identity`.
5. **Proof:** a **separate `sc secret-demo` command** (the default `sc demo`
   stays the clean Phase 1 zero-residue proof, untouched).
6. **Persistence:** **in-session only this round.** Phase 2 crypto, model, and
   ops are built as library operations and proven end-to-end inside
   `sc secret-demo` and tests. A persistent on-disk native object store is out of
   scope and tracked as a follow-on.

## Out of scope (this round)

- Persistent on-disk native object store / cross-invocation `sc secret add` then
  later `sc run`. Everything is demonstrated within a single process/session.
- Standalone `sc secret add` / `sc run` against a persisted repo (depends on the
  persistence wedge above). The same library ops exist and are exercised by the
  demo and tests; only the persisted multi-invocation CLI workflow is deferred.
- bech32 `scl1…` key strings (using prefixed hex; bech32 is a later nicety).
- age key-format interop.

## Architecture

### Crate & dependency structure

A new crate `crates/crypto` (package `scl-crypto`) extends the dependency graph:

```
cli → {vfs, gitio, crypto} → core
```

- `crypto` depends on `core` to construct/consume `core::Secret`. This is
  consistent with the existing rule that all dependencies point toward `core`.
- `core` gains **no** new dependencies; it stays a pure data model.
- `gix` stays quarantined in `gitio`. `crypto` becomes the **only** crate that
  links the cryptographic stack.

**New invariant (add to CLAUDE.md):** `core` must never depend on crypto, just as
it must never depend on Git or worktrees. All cryptographic code lives behind the
`crypto` boundary, mirroring the `gix`-in-`gitio` rule. `vfs` stays crypto-free —
it moves `Secret` objects around mechanically but never seals or opens them.

### Cryptographic construction (per ADR-0008 / ADR-0009)

- **Value encryption:** a fresh 32-byte data-encryption key (DEK) per secret.
  The value is encrypted with **XChaCha20-Poly1305** (24-byte random nonce,
  AEAD). The AEAD associated data (AAD) is the secret's `name`, binding the name
  to the ciphertext so a value cannot be silently relabeled.
- **DEK wrapping (per recipient):** ephemeral X25519 keypair → ECDH with the
  recipient public key → HKDF-SHA256 to derive a wrapping key → XChaCha20-Poly1305
  wraps the DEK. This is the age X25519 recipient construction without the age
  file format.
- **`recipient_id`:** a stable fingerprint = the first 16 bytes (128 bits) of
  `BLAKE3(recipient_pubkey)`, hex-encoded (32 hex chars). 128 bits is ample to
  avoid accidental collisions in a recipients list while staying compact.
- **`wrapped_dek` layout (opaque to `core`):**
  `ephemeral_pubkey (32) ‖ wrap_nonce (24) ‖ wrapped-DEK ciphertext+tag`.
  `core` treats `wrapped_dek` as opaque bytes; only `crypto` knows this layout.

### Dependencies to add (via `cargo add`, latest stable)

- `crypto`: `chacha20poly1305` (XChaCha20-Poly1305), `x25519-dalek`, `hkdf`,
  `sha2`, `rand_core` + `getrandom`, `zeroize`, `subtle`, `blake3` (fingerprint),
  `hex`, `thiserror`.
- `cli`: `toml` + `serde` (parse `.sc/recipients.toml`).

## Components

### 1. `core` changes

- `Snapshot` gains `secrets: Vec<(String, ObjectId)>`, kept sorted by name for
  canonical encoding and written after `message` in `Object::encode`/`decode`.
  - **Format break:** adding the registry changes every `Snapshot`'s BLAKE3 id.
    This is deliberate and acceptable pre-release. All affected tests are updated.
  - Empty `secrets` is the common case (Git import, plain commits) and encodes as
    a zero-length list.
- `WrappedKey` stays `{ recipient_id: String, wrapped_dek: Vec<u8> }` — unchanged.
  No `ephemeral_pubkey` field; it lives inside the opaque `wrapped_dek`.
- Add `Store::get_secret(&ObjectId) -> Result<Secret>` (mirrors `get_tree` /
  `get_snapshot`).
- No budget/eviction change needed: `Secret` has `blob_size() == 0`, so secrets
  are resident and never evicted — matching the existing invariant.

### 2. `scl-crypto` API

Types:

- `SecretKey` — X25519 static secret, `Zeroize` on drop.
- `PublicKey` — 32-byte X25519 public key; `Display`/`FromStr` with `scl-pk-` hex
  prefix.
- `RecipientId` — fingerprint string.
- `KeyProvider` trait: `fn identity(&self) -> Result<SecretKey>`.
- `FileKeyProvider { path: PathBuf }` — reads/parses an identity file.

Functions:

- `generate_keypair() -> (SecretKey, PublicKey)`.
- `seal(name: &str, plaintext: &[u8], recipients: &[PublicKey]) -> core::Secret`.
- `open(secret: &core::Secret, identity: &SecretKey) -> Result<Zeroizing<Vec<u8>>>`
  — selects the matching `WrappedKey` by `recipient_id`, unwraps the DEK, decrypts
  the value; typed error if the identity is not a recipient or on tamper.
- `rewrap_for(secret: &core::Secret, authorized: &SecretKey, new: &PublicKey) ->
  Result<core::Secret>` — grant: recover the DEK with an authorized key, wrap it
  for the new recipient, return a new `Secret` with the added `WrappedKey`.
- `revoke(secret: &core::Secret, recipient: &RecipientId) -> core::Secret` —
  metadata-only: drop a `WrappedKey`; no DEK access required.

All randomness (DEK, nonces, ephemeral keys) goes through an injectable RNG seam
so unit tests are deterministic and reproducible.

### 3. `vfs` changes

`Worktree` carries the base snapshot's secrets registry and manipulates it
mechanically — it never calls `crypto`:

- `fork` copies the base snapshot's registry into the worktree.
- `add_secret(secret: core::Secret)` — `put` the object, record `name → id`.
- `revoke_secret(name)` / `replace_secret(name, secret)` — registry edits.
- `list_secrets() -> Vec<(String, ObjectId)>`, `get_secret(name)`.
- `commit` writes the effective registry into the new `Snapshot`.
- `checkout` is **unchanged**: secrets are not in the file tree, so no plaintext
  (or even ciphertext) is ever written as a file. The Phase 1 invariant holds for
  free.

### 4. `cli` changes

- `sc keygen [--out PATH]` — generate a keypair; write the private key `0600`
  (default `~/.sc/identity`); print the public key + `recipient_id` for pasting
  into `.sc/recipients.toml`.
- Identity resolution helper: `--identity PATH` > `SC_IDENTITY` env >
  `~/.sc/identity`.
- Recipients resolution helper: parse `.sc/recipients.toml`, resolve `--to
  a,b,c` to `PublicKey`s.
- `sc secret-demo` — the Phase 2 proof (below).

The library-level ops behind `sc secret add` / `sc secret grant` / `sc secret
revoke` / `sc run` are implemented (in `cli` + `crypto`) and exercised by the
demo and tests; the persisted multi-invocation CLI workflow is deferred (see Out
of scope).

## Data flow: `sc secret-demo`

All in-RAM; no disk writes except the existing checkout path (which never touches
secrets). The command proves the headline property end-to-end:

1. Generate two identities in memory: `alice` (authorized) and `mallory` (not).
2. `seal("DB_URL", value, [alice_pub])`; add to the base snapshot's registry.
3. Fork agent worktrees in two contexts: some hold `alice`'s key, some hold
   `mallory`'s.
4. Each agent attempts a run-inject: `open` the secret with its identity and build
   a child-process environment map.
   - **alice** succeeds; the demo asserts the injected value equals the original
     plaintext.
   - **mallory** fails with `NotARecipient`; the demo asserts the stored `Secret`
     object is **still ciphertext** (its `ciphertext` field is unchanged and is
     not the plaintext).
5. `grant` mallory: `rewrap_for(secret, alice_key, mallory_pub)` adds a
   `WrappedKey`; produce a new snapshot. Mallory re-runs and **now succeeds** —
   proving grant is a cheap re-wrap that does **not** rotate the value.
6. Teardown: drop everything; assert the session leaves zero residual files
   (reusing the Phase 1 proof) and that no plaintext was ever written to disk.
   Identities are RAM-only in the demo.

Output is a clear authorized/unauthorized table plus the zero-residue result.

## Error handling

- New `scl-crypto::Error` (thiserror): `NotARecipient`, `Decrypt` (AEAD tag
  failure / tamper), `BadKey`, `KeyIo`.
- `cli` absorbs crypto/vfs errors via `anyhow` and `?`.
- Decryption **never panics** on a wrong or missing key — it returns a typed
  error the caller handles.
- Decrypted plaintext is held in `Zeroizing<Vec<u8>>`, never logged, and never
  written to disk; it is injected only into a child process environment (or, in
  the demo, into an in-memory env map that is dropped on teardown).

## Testing

- **crypto unit tests:** seal/open roundtrip; wrong identity fails with
  `NotARecipient`; **tamper (flip a ciphertext byte) fails the AEAD tag**;
  multi-recipient (each recipient opens independently); `rewrap_for` grants
  access; `revoke` removes a `WrappedKey` and that identity then fails; fingerprint
  stability; key-string encode/decode roundtrip. RNG injected for determinism.
- **core test:** a `Snapshot` carrying secrets roundtrips through encode/decode;
  document that adding the registry changes snapshot ids (format break).
- **vfs tests:** `fork` carries the registry forward; `commit` persists it; a
  secret **never** appears in `checkout` output or `list()`.
- **invariant guard:** assert the checkout path writes no file for a secret name,
  and that the decryption path performs no `fs::write`.
- **integration:** `sc secret-demo`'s own assertions (authorized success,
  unauthorized ciphertext-only, grant-then-success, zero residue) serve as the
  end-to-end proof.

Every new behavior ships with a test, per the project convention.

## Documentation updates

- Flip **ADR-0008** and **ADR-0009** from Proposed to Accepted.
- Add **ADR-0010**: two new decisions not covered by existing ADRs —
  (a) secrets live in a **snapshot-side registry**, not in the file tree;
  (b) `wrapped_dek` is an **opaque blob** owned by `crypto`
  (`ephemeral_pubkey ‖ nonce ‖ ciphertext`), keeping `core` crypto-agnostic.
- Update `ARCHITECTURE.md` (Phase 2 section: from "designed" to "built", with the
  registry + run-inject model) and `CLAUDE.md` (new `core`-never-depends-on-crypto
  invariant; `sc secret-demo`; `crypto` crate in the layout/dependency rule).

## Open follow-ons (not this round)

- Persistent on-disk native object store enabling cross-invocation `sc secret
  add` / `sc run`.
- Additional `KeyProvider` backends (env, agent, KMS/HSM).
- Break-glass / escrow recipient and rotation policy (noted in ADR-0009).
- Git export and bech32 key strings.
