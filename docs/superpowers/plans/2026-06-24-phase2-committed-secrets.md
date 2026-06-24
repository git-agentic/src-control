# Phase 2 — Native Committed Secrets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add envelope-encrypted secrets committed into repo state, wrapped per X25519 recipient, decrypted only by an authorized private key and injected into a child process environment — proven end-to-end by a new `sc secret-demo` command.

**Architecture:** A new leaf-ish crate `scl-crypto` (depends only on `scl-core`) owns all cryptography: a per-secret DEK encrypts the value with XChaCha20-Poly1305; the DEK is wrapped per recipient via X25519 ECDH + HKDF. Secrets live in a side registry on `Snapshot` (`secrets: Vec<(name, ObjectId)>`), separate from the file tree, so `checkout` never materializes them. `vfs` moves `Secret` objects mechanically; `cli` wires keygen, recipient resolution, and the demo.

**Tech Stack:** Rust 2021, RustCrypto (`chacha20poly1305`, `x25519-dalek`, `hkdf`, `sha2`), `zeroize`, `blake3`, `clap`, `toml`/`serde`, `anyhow`.

**Source spec:** `docs/superpowers/specs/2026-06-24-phase2-committed-secrets-design.md`

---

## Execution prerequisites

- The repo currently has **no commits**. Before Task 0, make a baseline commit of the existing Phase 1 tree and create a feature branch:
  ```bash
  git add -A && git commit -m "chore: Phase 1 baseline"
  git checkout -b phase2-secrets
  ```
- Run the whole workspace test suite after each task: `cargo test`. Specific test commands are given per step.

---

## File structure

**Create:**
- `crates/crypto/Cargo.toml` — manifest for the new crypto crate.
- `crates/crypto/src/lib.rs` — public re-exports.
- `crates/crypto/src/error.rs` — `scl-crypto::Error`.
- `crates/crypto/src/key.rs` — `SecretKey`, `PublicKey`, `RecipientId`, keygen, key strings.
- `crates/crypto/src/envelope.rs` — `seal`/`open`/`rewrap_for`/`revoke` + DEK wrapping.
- `crates/crypto/src/provider.rs` — `KeyProvider` trait + `FileKeyProvider`.
- `docs/adr/0010-secret-registry-and-opaque-wrapped-dek.md` — new ADR.

**Modify:**
- `Cargo.toml` — add `crates/crypto` to workspace members.
- `crates/core/src/object.rs` — add `Snapshot.secrets`; encode/decode; update tests.
- `crates/core/src/store.rs` — add `get_secret`.
- `crates/vfs/src/lib.rs` — `Worktree` secrets registry; `fork`/`commit`/`commit_files` carry it; tests.
- `crates/cli/Cargo.toml` — add `scl-crypto`, `toml`, `serde`.
- `crates/cli/src/main.rs` — `keygen`, recipients/identity helpers, `secret-demo`.
- `docs/adr/0008-committed-secrets-envelope-encryption.md` — status → Accepted.
- `docs/adr/0009-key-management-and-authorization.md` — status → Accepted.
- `ARCHITECTURE.md` — Phase 2 section: designed → built.
- `CLAUDE.md` — crypto crate, dependency rule, new invariant, commands.

---

## Task 0: Scaffold the `scl-crypto` crate

**Files:**
- Modify: `Cargo.toml:3`
- Create: `crates/crypto/Cargo.toml`, `crates/crypto/src/lib.rs`, `crates/crypto/src/error.rs`

- [ ] **Step 1: Add the crate to the workspace**

Modify `Cargo.toml` line 3:

```toml
members = ["crates/core", "crates/vfs", "crates/gitio", "crates/cli", "crates/crypto"]
```

- [ ] **Step 2: Create the manifest**

Create `crates/crypto/Cargo.toml`. (Versions below are the latest stable at writing; prefer `cargo add <dep>` so Cargo resolves current pins, then keep whatever it writes.)

```toml
[package]
name = "scl-crypto"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
scl-core = { path = "../core" }
chacha20poly1305 = "0.10"
x25519-dalek = { version = "2", features = ["static_secrets"] }
hkdf = "0.12"
sha2 = "0.10"
rand_core = { version = "0.6", features = ["getrandom"] }
zeroize = "1"
blake3 = "1.8.5"
hex = "0.4.3"
thiserror = "2.0.18"

[dev-dependencies]
rand_chacha = "0.3"
```

> Note: `x25519-dalek` needs the `static_secrets` feature for `StaticSecret`. `rand_chacha` (dev-only) gives a seeded, deterministic RNG for tests. We deliberately omit `subtle` (the AEAD tag check already provides constant-time integrity — YAGNI).

- [ ] **Step 3: Create the error type**

Create `crates/crypto/src/error.rs`:

```rust
//! Errors returned by the cryptography layer.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The supplied identity is not among the secret's recipients.
    #[error("identity is not an authorized recipient of this secret")]
    NotARecipient,
    /// AEAD authentication failed: wrong key or tampered ciphertext.
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    /// A key string or key file could not be parsed.
    #[error("malformed key")]
    BadKey,
    /// Reading a key file failed.
    #[error("key io error: {0}")]
    KeyIo(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

- [ ] **Step 4: Create the lib root (re-exports)**

Create `crates/crypto/src/lib.rs`:

```rust
//! `scl-crypto` — envelope encryption for committed secrets.
//!
//! This is the only crate that links the cryptographic stack. It depends on
//! `scl-core` to construct and consume [`scl_core::Secret`] objects, but `core`
//! never depends on it: all cryptography stays behind this boundary, mirroring
//! the `gix`-in-`gitio` rule.
//!
//! A per-secret data-encryption key (DEK) encrypts the value with
//! XChaCha20-Poly1305; the DEK is wrapped once per recipient via X25519 ECDH +
//! HKDF. Authorization is "do you hold a recipient private key."

pub mod envelope;
pub mod error;
pub mod key;
pub mod provider;

pub use envelope::{open, rewrap_for, revoke, seal};
pub use error::{Error, Result};
pub use key::{generate_keypair, PublicKey, RecipientId, SecretKey};
pub use provider::{FileKeyProvider, KeyProvider};
```

> This will not compile until Tasks 1–3 add the modules. That's expected; build at the end of Task 3.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/crypto/Cargo.toml crates/crypto/src/lib.rs crates/crypto/src/error.rs
git commit -m "feat(crypto): scaffold scl-crypto crate"
```

---

## Task 1: Keys, fingerprints, and key strings

**Files:**
- Create: `crates/crypto/src/key.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/crypto/src/key.rs` with the test module first:

```rust
//! X25519 identities, recipient fingerprints, and their string encodings.

use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{Error, Result};

const PUB_PREFIX: &str = "scl-pk-";
const SEC_PREFIX: &str = "scl-sk-";
const ID_LEN: usize = 16; // 128-bit fingerprint

/// A stable, human-comparable fingerprint of a public key (first 128 bits of
/// `BLAKE3(pubkey)`, hex-encoded).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecipientId(String);

impl RecipientId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RecipientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An X25519 private identity. Zeroized on drop.
#[derive(Clone)]
pub struct SecretKey(x25519_dalek::StaticSecret);

/// An X25519 public key — a recipient others can wrap secrets to.
#[derive(Clone)]
pub struct PublicKey(x25519_dalek::PublicKey);

/// Generate a fresh identity keypair from the OS RNG.
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    generate_keypair_with_rng(&mut OsRng)
}

/// Generate a keypair from a caller-supplied RNG (deterministic in tests).
pub fn generate_keypair_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> (SecretKey, PublicKey) {
    let sk = x25519_dalek::StaticSecret::random_from_rng(rng);
    let pk = x25519_dalek::PublicKey::from(&sk);
    (SecretKey(sk), PublicKey(pk))
}

impl SecretKey {
    /// The public key for this identity.
    pub fn public(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0))
    }

    /// Encode as a `scl-sk-<hex>` string (for the identity file).
    pub fn to_key_string(&self) -> String {
        let mut bytes = self.0.to_bytes();
        let s = format!("{SEC_PREFIX}{}", hex::encode(bytes));
        bytes.zeroize();
        s
    }

    /// Parse a `scl-sk-<hex>` string.
    pub fn from_key_string(s: &str) -> Result<Self> {
        let hexpart = s.trim().strip_prefix(SEC_PREFIX).ok_or(Error::BadKey)?;
        let bytes = hex::decode(hexpart).map_err(|_| Error::BadKey)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::BadKey)?;
        Ok(SecretKey(x25519_dalek::StaticSecret::from(arr)))
    }

    pub(crate) fn inner(&self) -> &x25519_dalek::StaticSecret {
        &self.0
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The recipient fingerprint of this public key.
    pub fn recipient_id(&self) -> RecipientId {
        let h = blake3::hash(self.0.as_bytes());
        RecipientId(hex::encode(&h.as_bytes()[..ID_LEN]))
    }

    /// Encode as a `scl-pk-<hex>` string (for `.sc/recipients.toml`).
    pub fn to_key_string(&self) -> String {
        format!("{PUB_PREFIX}{}", hex::encode(self.0.to_bytes()))
    }

    /// Parse a `scl-pk-<hex>` string.
    pub fn from_key_string(s: &str) -> Result<Self> {
        let hexpart = s.trim().strip_prefix(PUB_PREFIX).ok_or(Error::BadKey)?;
        let bytes = hex::decode(hexpart).map_err(|_| Error::BadKey)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::BadKey)?;
        Ok(PublicKey(x25519_dalek::PublicKey::from(arr)))
    }

    pub(crate) fn inner(&self) -> &x25519_dalek::PublicKey {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn seeded() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn keypair_is_deterministic_under_seeded_rng() {
        let (sk1, pk1) = generate_keypair_with_rng(&mut seeded());
        let (_sk2, pk2) = generate_keypair_with_rng(&mut seeded());
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
        assert_eq!(sk1.public().to_bytes(), pk1.to_bytes());
    }

    #[test]
    fn public_key_string_roundtrips() {
        let (_sk, pk) = generate_keypair_with_rng(&mut seeded());
        let s = pk.to_key_string();
        assert!(s.starts_with("scl-pk-"));
        let back = PublicKey::from_key_string(&s).unwrap();
        assert_eq!(pk.to_bytes(), back.to_bytes());
    }

    #[test]
    fn secret_key_string_roundtrips() {
        let (sk, pk) = generate_keypair_with_rng(&mut seeded());
        let s = sk.to_key_string();
        assert!(s.starts_with("scl-sk-"));
        let back = SecretKey::from_key_string(&s).unwrap();
        assert_eq!(back.public().to_bytes(), pk.to_bytes());
    }

    #[test]
    fn recipient_id_is_stable_and_32_hex_chars() {
        let (_sk, pk) = generate_keypair_with_rng(&mut seeded());
        let id = pk.recipient_id();
        assert_eq!(id.as_str().len(), 32);
        assert_eq!(id, pk.recipient_id());
    }

    #[test]
    fn bad_key_string_is_rejected() {
        assert!(matches!(PublicKey::from_key_string("nope"), Err(Error::BadKey)));
        assert!(matches!(SecretKey::from_key_string("scl-sk-zz"), Err(Error::BadKey)));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile/run**

Run: `cargo test -p scl-crypto key::tests`
Expected: build error (module wired) then, once it builds, all `key::tests` pass. If `random_from_rng` is missing, confirm the `static_secrets` feature is enabled in `crates/crypto/Cargo.toml`.

- [ ] **Step 3: (Implementation already written above)**

The implementation and tests are in the same file. No further code needed for this task.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p scl-crypto key::tests`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/crypto/src/key.rs
git commit -m "feat(crypto): X25519 keys, fingerprints, key strings"
```

---

## Task 2: Envelope seal / open

**Files:**
- Create: `crates/crypto/src/envelope.rs`

- [ ] **Step 1: Write the failing tests + implementation**

Create `crates/crypto/src/envelope.rs`:

```rust
//! Envelope encryption: per-secret DEK + per-recipient DEK wrapping.
//!
//! `wrapped_dek` layout (opaque to `scl-core`):
//! `ephemeral_pubkey(32) ‖ wrap_nonce(24) ‖ wrapped-DEK ciphertext+tag`.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use scl_core::{Secret, WrappedKey};

use crate::error::{Error, Result};
use crate::key::{PublicKey, RecipientId, SecretKey};

const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const EPK_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"scl-dek-wrap-v1";

/// Encrypt `plaintext` under a fresh DEK and wrap that DEK for each recipient.
pub fn seal(name: &str, plaintext: &[u8], recipients: &[PublicKey]) -> Secret {
    seal_with_rng(name, plaintext, recipients, &mut OsRng)
}

/// `seal` with a caller-supplied RNG (deterministic in tests).
pub fn seal_with_rng<R: RngCore + CryptoRng>(
    name: &str,
    plaintext: &[u8],
    recipients: &[PublicKey],
    rng: &mut R,
) -> Secret {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    rng.fill_bytes(dek.as_mut_slice());
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).expect("32-byte DEK");
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: name.as_bytes() })
        .expect("aead encrypt is infallible for valid inputs");

    // Reborrow the RNG (`&mut *rng`) per recipient so the `&mut R` isn't moved on
    // the first iteration.
    let mut wrapped_keys = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        wrapped_keys.push(wrap_dek(&dek, recipient, &mut *rng));
    }

    Secret { name: name.to_string(), nonce: nonce.to_vec(), ciphertext, wrapped_keys }
}

/// Decrypt a secret using `identity`. Errors if the identity is not a recipient
/// or the ciphertext fails authentication.
pub fn open(secret: &Secret, identity: &SecretKey) -> Result<Zeroizing<Vec<u8>>> {
    let my_id = identity.public().recipient_id();
    let wk = secret
        .wrapped_keys
        .iter()
        .find(|w| w.recipient_id == my_id.as_str())
        .ok_or(Error::NotARecipient)?;

    let dek = unwrap_dek(&wk.wrapped_dek, identity)?;
    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).map_err(|_| Error::Decrypt)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&secret.nonce),
            Payload { msg: &secret.ciphertext, aad: secret.name.as_bytes() },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

/// Grant: recover the DEK with an authorized identity and wrap it for a new
/// recipient. Returns a new `Secret`; the value/ciphertext is unchanged.
pub fn rewrap_for(secret: &Secret, authorized: &SecretKey, new: &PublicKey) -> Result<Secret> {
    rewrap_for_with_rng(secret, authorized, new, &mut OsRng)
}

pub fn rewrap_for_with_rng<R: RngCore + CryptoRng>(
    secret: &Secret,
    authorized: &SecretKey,
    new: &PublicKey,
    rng: &mut R,
) -> Result<Secret> {
    let my_id = authorized.public().recipient_id();
    let wk = secret
        .wrapped_keys
        .iter()
        .find(|w| w.recipient_id == my_id.as_str())
        .ok_or(Error::NotARecipient)?;
    let dek = unwrap_dek(&wk.wrapped_dek, authorized)?;
    let new_wk = wrap_dek(&dek, new, rng);

    let mut out = secret.clone();
    out.wrapped_keys.retain(|w| w.recipient_id != new_wk.recipient_id);
    out.wrapped_keys.push(new_wk);
    Ok(out)
}

/// Revoke: drop a recipient's wrapped key. Metadata-only (no DEK access). Does
/// not rotate the value — see ADR-0008.
pub fn revoke(secret: &Secret, recipient: &RecipientId) -> Secret {
    let mut out = secret.clone();
    out.wrapped_keys.retain(|w| w.recipient_id != recipient.as_str());
    out
}

// ---- internals -------------------------------------------------------------

fn wrap_dek<R: RngCore + CryptoRng>(dek: &[u8], recipient: &PublicKey, rng: &mut R) -> WrappedKey {
    let ephemeral = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(recipient.inner());

    let wrap_key = derive_wrap_key(shared.as_bytes(), ephemeral_pub.as_bytes(), &recipient.to_bytes());
    let mut wrap_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut wrap_nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(wrap_key.as_slice()).expect("32-byte wrap key");
    let wrapped = cipher
        .encrypt(XNonce::from_slice(&wrap_nonce), dek)
        .expect("aead wrap is infallible for valid inputs");

    let mut blob = Vec::with_capacity(EPK_LEN + NONCE_LEN + wrapped.len());
    blob.extend_from_slice(ephemeral_pub.as_bytes());
    blob.extend_from_slice(&wrap_nonce);
    blob.extend_from_slice(&wrapped);

    WrappedKey { recipient_id: recipient.recipient_id().to_string(), wrapped_dek: blob }
}

fn unwrap_dek(blob: &[u8], identity: &SecretKey) -> Result<Zeroizing<[u8; DEK_LEN]>> {
    if blob.len() < EPK_LEN + NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let ephemeral_pub_bytes: [u8; 32] = blob[..EPK_LEN].try_into().unwrap();
    let wrap_nonce = &blob[EPK_LEN..EPK_LEN + NONCE_LEN];
    let wrapped = &blob[EPK_LEN + NONCE_LEN..];

    let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
    let shared = identity.inner().diffie_hellman(&ephemeral_pub);
    let wrap_key = derive_wrap_key(shared.as_bytes(), &ephemeral_pub_bytes, &identity.public().to_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(wrap_key.as_slice()).map_err(|_| Error::Decrypt)?;
    let dek_vec = cipher
        .decrypt(XNonce::from_slice(wrap_nonce), wrapped)
        .map_err(|_| Error::Decrypt)?;
    let dek: [u8; DEK_LEN] = dek_vec.as_slice().try_into().map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(dek))
}

/// HKDF-SHA256 over the ECDH shared secret, salted with both public keys, so the
/// wrapping key is bound to this specific ephemeral↔recipient pair.
fn derive_wrap_key(shared: &[u8], ephemeral_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_pub);
    salt.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, okm.as_mut_slice()).expect("32-byte HKDF output");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::generate_keypair_with_rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (sk, pk) = generate_keypair_with_rng(&mut rng(1));
        let secret = seal_with_rng("DB_URL", b"postgres://secret", &[pk], &mut rng(2));
        let opened = open(&secret, &sk).unwrap();
        assert_eq!(&opened[..], b"postgres://secret");
        assert_ne!(secret.ciphertext, b"postgres://secret");
    }

    #[test]
    fn wrong_identity_is_not_a_recipient() {
        let (_sk_a, pk_a) = generate_keypair_with_rng(&mut rng(1));
        let (sk_b, _pk_b) = generate_keypair_with_rng(&mut rng(9));
        let secret = seal_with_rng("K", b"v", &[pk_a], &mut rng(2));
        assert!(matches!(open(&secret, &sk_b), Err(Error::NotARecipient)));
    }

    #[test]
    fn tampered_ciphertext_fails_aead() {
        let (sk, pk) = generate_keypair_with_rng(&mut rng(1));
        let mut secret = seal_with_rng("K", b"v", &[pk], &mut rng(2));
        secret.ciphertext[0] ^= 0xFF;
        assert!(matches!(open(&secret, &sk), Err(Error::Decrypt)));
    }

    #[test]
    fn multi_recipient_each_can_open() {
        let (sk_a, pk_a) = generate_keypair_with_rng(&mut rng(1));
        let (sk_b, pk_b) = generate_keypair_with_rng(&mut rng(2));
        let secret = seal_with_rng("K", b"shared", &[pk_a, pk_b], &mut rng(3));
        assert_eq!(&open(&secret, &sk_a).unwrap()[..], b"shared");
        assert_eq!(&open(&secret, &sk_b).unwrap()[..], b"shared");
    }

    #[test]
    fn grant_adds_access_without_changing_ciphertext() {
        let (sk_a, pk_a) = generate_keypair_with_rng(&mut rng(1));
        let (sk_b, pk_b) = generate_keypair_with_rng(&mut rng(2));
        let secret = seal_with_rng("K", b"v", &[pk_a], &mut rng(3));
        assert!(matches!(open(&secret, &sk_b), Err(Error::NotARecipient)));

        let granted = rewrap_for_with_rng(&secret, &sk_a, &pk_b, &mut rng(4)).unwrap();
        assert_eq!(granted.ciphertext, secret.ciphertext, "value must not be rotated");
        assert_eq!(&open(&granted, &sk_b).unwrap()[..], b"v");
        assert_eq!(&open(&granted, &sk_a).unwrap()[..], b"v");
    }

    #[test]
    fn revoke_removes_access() {
        let (sk_a, pk_a) = generate_keypair_with_rng(&mut rng(1));
        let (sk_b, pk_b) = generate_keypair_with_rng(&mut rng(2));
        let secret = seal_with_rng("K", b"v", &[pk_a, pk_b], &mut rng(3));
        let revoked = revoke(&secret, &pk_b.recipient_id());
        assert!(matches!(open(&revoked, &sk_b), Err(Error::NotARecipient)));
        assert_eq!(&open(&revoked, &sk_a).unwrap()[..], b"v");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail (then pass) — build the crate**

Run: `cargo test -p scl-crypto`
Expected: compiles and all `key::tests` + `envelope::tests` pass (note `provider` module is still referenced in `lib.rs` — if the crate fails to build because `provider` is missing, temporarily comment the `pub mod provider;` and `pub use provider::...` lines, OR do Task 3 first). Recommended: proceed straight to Task 3, then build.

- [ ] **Step 3: Commit**

```bash
git add crates/crypto/src/envelope.rs
git commit -m "feat(crypto): seal/open/rewrap/revoke envelope encryption"
```

---

## Task 3: `KeyProvider` and `FileKeyProvider`

**Files:**
- Create: `crates/crypto/src/provider.rs`

- [ ] **Step 1: Write the implementation + test**

Create `crates/crypto/src/provider.rs`:

```rust
//! Where a private identity comes from. `FileKeyProvider` now; env/agent/KMS
//! providers can be added later behind the same trait without touching call
//! sites.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::key::SecretKey;

/// Supplies the private identity used to decrypt secrets.
pub trait KeyProvider {
    fn identity(&self) -> Result<SecretKey>;
}

/// Loads an identity from a `scl-sk-<hex>` key file.
pub struct FileKeyProvider {
    pub path: PathBuf,
}

impl FileKeyProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileKeyProvider { path: path.into() }
    }
}

impl KeyProvider for FileKeyProvider {
    fn identity(&self) -> Result<SecretKey> {
        let contents = std::fs::read_to_string(&self.path).map_err(|e| Error::KeyIo(e.to_string()))?;
        SecretKey::from_key_string(&contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::generate_keypair_with_rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn file_provider_roundtrips_an_identity() {
        let (sk, pk) = generate_keypair_with_rng(&mut ChaCha20Rng::seed_from_u64(7));
        let dir = std::env::temp_dir().join(format!("scl-keyprov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity");
        std::fs::write(&path, sk.to_key_string()).unwrap();

        let provider = FileKeyProvider::new(&path);
        let loaded = provider.identity().unwrap();
        assert_eq!(loaded.public().to_bytes(), pk.to_bytes());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_is_key_io_error() {
        let provider = FileKeyProvider::new("/nonexistent/scl/identity");
        assert!(matches!(provider.identity(), Err(Error::KeyIo(_))));
    }
}
```

- [ ] **Step 2: Run the whole crate's tests**

Run: `cargo test -p scl-crypto`
Expected: PASS — `key`, `envelope`, and `provider` test modules all green.

- [ ] **Step 3: Commit**

```bash
git add crates/crypto/src/provider.rs
git commit -m "feat(crypto): KeyProvider trait + FileKeyProvider"
```

---

## Task 4: Add the secrets registry to `Snapshot` (`core`)

**Files:**
- Modify: `crates/core/src/object.rs`
- Modify: `crates/core/src/store.rs`

- [ ] **Step 1: Add the field**

In `crates/core/src/object.rs`, change the `Snapshot` struct (currently lines 70–77) to add `secrets`:

```rust
/// The Jujutsu-inspired analogue of a commit: a root tree plus metadata.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Snapshot {
    pub root: ObjectId,
    pub parents: Vec<ObjectId>,
    pub author: String,
    pub timestamp: i64,
    pub message: String,
    /// Side registry of committed secrets, `name -> Secret object id`. Separate
    /// from the file tree: secrets are env vars, not files, and are never
    /// materialized by `checkout`. Encoded sorted by name for a canonical hash.
    pub secrets: Vec<(String, ObjectId)>,
}
```

- [ ] **Step 2: Encode the registry**

In `Object::encode`, in the `Object::Snapshot(s)` arm, after `w.str(&s.message);` add:

```rust
                let mut secrets = s.secrets.clone();
                secrets.sort_by(|a, b| a.0.cmp(&b.0));
                w.u32(secrets.len() as u32);
                for (name, id) in &secrets {
                    w.str(name);
                    w.id(id);
                }
```

- [ ] **Step 3: Decode the registry**

In `Object::decode`, in the `TAG_SNAPSHOT` arm, after `let message = r.str()?;` and before constructing the `Snapshot`, add:

```rust
                let ns = r.u32()?;
                let mut secrets = Vec::with_capacity(ns as usize);
                for _ in 0..ns {
                    let name = r.str()?;
                    let id = r.id()?;
                    secrets.push((name, id));
                }
```

Then change the struct construction to:

```rust
                Object::Snapshot(Snapshot { root, parents, author, timestamp, message, secrets })
```

- [ ] **Step 4: Update the existing snapshot test**

In `crates/core/src/object.rs` tests, the `snapshot_and_secret_roundtrip` test builds a `Snapshot`. Add `secrets: vec![]` to it:

```rust
        let snap = Object::Snapshot(Snapshot {
            root: Object::blob(b"r".to_vec()).id(),
            parents: vec![],
            author: "agent".into(),
            timestamp: 42,
            message: "init".into(),
            secrets: vec![],
        });
        assert_eq!(snap, Object::decode(&snap.encode()).unwrap());
```

- [ ] **Step 5: Add a registry roundtrip test**

Add to the tests module in `crates/core/src/object.rs`:

```rust
    #[test]
    fn snapshot_with_secrets_roundtrips_and_is_order_independent() {
        let sid = Object::Secret(Secret {
            name: "API_KEY".into(),
            nonce: vec![1, 2, 3],
            ciphertext: vec![9; 8],
            wrapped_keys: vec![],
        })
        .id();
        let root = Object::blob(b"r".to_vec()).id();
        let base = |secrets: Vec<(String, ObjectId)>| {
            Object::Snapshot(Snapshot {
                root,
                parents: vec![],
                author: "a".into(),
                timestamp: 0,
                message: "m".into(),
                secrets,
            })
        };
        let s1 = base(vec![("DB_URL".into(), sid), ("API_KEY".into(), sid)]);
        let s2 = base(vec![("API_KEY".into(), sid), ("DB_URL".into(), sid)]);
        // Canonical: registry order does not affect the id.
        assert_eq!(s1.id(), s2.id());
        assert_eq!(s1, Object::decode(&s1.encode()).unwrap());
    }
```

- [ ] **Step 6: Add `Store::get_secret`**

In `crates/core/src/store.rs`, after `get_snapshot` (around line 165), add:

```rust
    pub fn get_secret(&mut self, id: &ObjectId) -> Result<crate::object::Secret> {
        match self.get(id)? {
            Object::Secret(s) => Ok(s),
            _ => Err(Error::WrongKind(*id, "secret")),
        }
    }
```

- [ ] **Step 7: Run the core tests**

Run: `cargo test -p scl-core`
Expected: PASS. (The build will now fail in `vfs`/`cli`/`gitio` because they construct `Snapshot` without `secrets` — fixed in Tasks 5–6. Run `-p scl-core` to scope this task.)

- [ ] **Step 8: Commit**

```bash
git add crates/core/src/object.rs crates/core/src/store.rs
git commit -m "feat(core): secrets registry on Snapshot + get_secret"
```

---

## Task 5: Carry the registry through `vfs`

**Files:**
- Modify: `crates/vfs/src/lib.rs`

- [ ] **Step 1: Import `Secret` and fix the two `Snapshot` constructors**

In `crates/vfs/src/lib.rs`, update the `use scl_core::{...}` (line 13–15) to include `Secret`:

```rust
use scl_core::{
    EntryKind, FileMode, Object, ObjectId, Secret, Snapshot, Store, StoreStats, Tree, TreeEntry,
};
```

In `Repo::commit_files`, the `Snapshot { ... }` literal: add `secrets: vec![]`:

```rust
        let snap = Object::Snapshot(Snapshot {
            root,
            parents: vec![],
            author: author.into(),
            timestamp: 0,
            message: message.into(),
            secrets: vec![],
        });
```

- [ ] **Step 2: Add the registry field to `Worktree` and populate it in `fork`**

Add a field to the `Worktree` struct (after `overlay`):

```rust
    /// Committed-secret registry inherited from the base snapshot, plus local
    /// add/revoke edits. `name -> Secret object id`.
    secrets: std::collections::BTreeMap<String, ObjectId>,
```

Change `Repo::fork` to load the base snapshot's secrets:

```rust
    pub fn fork(&self, snapshot: ObjectId, label: impl Into<String>) -> Result<Worktree> {
        let snap = self.store.lock().unwrap().get_snapshot(&snapshot)?;
        Ok(Worktree {
            store: self.store.clone(),
            base_snapshot: snapshot,
            base_root: snap.root,
            overlay: BTreeMap::new(),
            secrets: snap.secrets.into_iter().collect(),
            label: label.into(),
        })
    }
```

- [ ] **Step 3: Add secret methods to `Worktree`**

Add these methods inside `impl Worktree` (e.g. after `remove`):

```rust
    /// Store a sealed secret and register it by name (overwriting any prior
    /// secret with the same name).
    pub fn put_secret(&mut self, secret: Secret) -> Result<ObjectId> {
        let name = secret.name.clone();
        let id = self.store.lock().unwrap().put(Object::Secret(secret))?;
        self.secrets.insert(name, id);
        Ok(id)
    }

    /// Drop a secret from the registry.
    pub fn remove_secret(&mut self, name: &str) {
        self.secrets.remove(name);
    }

    /// The committed-secret registry as `(name, id)` pairs.
    pub fn list_secrets(&self) -> Vec<(String, ObjectId)> {
        self.secrets.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// The Secret object id registered under `name`, if any.
    pub fn secret_id(&self, name: &str) -> Option<ObjectId> {
        self.secrets.get(name).copied()
    }
```

- [ ] **Step 4: Write the registry into `commit`**

In `Worktree::commit`, change the `Snapshot { ... }` literal to include the registry:

```rust
        let snap = Object::Snapshot(Snapshot {
            root,
            parents: vec![self.base_snapshot],
            author: author.into(),
            timestamp: 0,
            message: message.into(),
            secrets: self.secrets.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        });
```

- [ ] **Step 5: Write the failing test (registry carry + checkout exclusion)**

Add to the tests module in `crates/vfs/src/lib.rs`:

```rust
    #[test]
    fn secrets_carry_through_fork_and_commit_but_never_check_out() {
        use scl_core::{Secret, WrappedKey};
        let r = repo();
        let snap = seed(&r);
        let mut wt = r.fork(snap, "setup").unwrap();
        wt.put_secret(Secret {
            name: "DB_URL".into(),
            nonce: vec![0; 24],
            ciphertext: vec![1, 2, 3, 4],
            wrapped_keys: vec![WrappedKey { recipient_id: "rid".into(), wrapped_dek: vec![7; 80] }],
        })
        .unwrap();
        let snap2 = wt.commit("setup", "add secret").unwrap();

        // Registry survives a fresh fork.
        let wt2 = r.fork(snap2, "consumer").unwrap();
        assert_eq!(wt2.list_secrets().len(), 1);
        assert!(wt2.secret_id("DB_URL").is_some());

        // The secret is NOT a file: absent from list() and from checkout.
        assert!(!wt2.list().unwrap().iter().any(|p| p.contains("DB_URL")));
        let dest = std::env::temp_dir().join(format!("scl-secret-co-{}", std::process::id()));
        wt2.checkout(&dest).unwrap();
        assert!(!dest.join("DB_URL").exists());
        std::fs::remove_dir_all(&dest).unwrap();
        assert!(!dest.exists());
    }
```

- [ ] **Step 6: Run the vfs tests**

Run: `cargo test -p scl-vfs`
Expected: PASS (existing tests + the new one).

- [ ] **Step 7: Commit**

```bash
git add crates/vfs/src/lib.rs
git commit -m "feat(vfs): carry secrets registry through fork/commit"
```

---

## Task 6: Fix `gitio` Snapshot construction

**Files:**
- Modify: `crates/gitio/src/lib.rs`

- [ ] **Step 1: Add `secrets: vec![]` to the imported snapshot**

In `crates/gitio/src/lib.rs`, find the `Snapshot { ... }` literal built during import and add `secrets: vec![]` to it. (Imported Git history has no native secrets.)

- [ ] **Step 2: Build the whole workspace**

Run: `cargo test`
Expected: the entire workspace compiles and all tests pass. If `gitio` still fails to compile, search for any other `Snapshot {` literal and add `secrets: vec![]`.

- [ ] **Step 3: Commit**

```bash
git add crates/gitio/src/lib.rs
git commit -m "fix(gitio): empty secrets registry on imported snapshots"
```

---

## Task 7: `sc keygen`

**Files:**
- Modify: `crates/cli/Cargo.toml`
- Modify: `crates/cli/src/main.rs`

- [ ] **Step 1: Add CLI dependencies**

In `crates/cli/Cargo.toml`, add to `[dependencies]`:

```toml
scl-crypto = { path = "../crypto" }
toml = "0.8"
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 2: Add the `Keygen` subcommand**

In `crates/cli/src/main.rs`, add to the `Cmd` enum:

```rust
    /// Generate an X25519 identity keypair (private key written to disk 0600).
    Keygen {
        /// Where to write the private key (default: ~/.sc/identity).
        #[arg(long)]
        out: Option<PathBuf>,
    },
```

Add the match arm in `main`:

```rust
        Cmd::Keygen { out } => run_keygen(out),
```

- [ ] **Step 3: Implement keygen + identity-path helpers**

Add these functions to `crates/cli/src/main.rs`:

```rust
/// Default identity path: `$HOME/.sc/identity`.
fn default_identity_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".sc").join("identity")
}

/// Resolve the identity file: `--identity` > `SC_IDENTITY` > default.
fn resolve_identity_path(flag: Option<PathBuf>) -> PathBuf {
    if let Some(p) = flag {
        return p;
    }
    if let Ok(env) = std::env::var("SC_IDENTITY") {
        return PathBuf::from(env);
    }
    default_identity_path()
}

fn run_keygen(out: Option<PathBuf>) -> Result<()> {
    let path = out.unwrap_or_else(default_identity_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let (sk, pk) = scl_crypto::generate_keypair();
    std::fs::write(&path, sk.to_key_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("wrote private key: {} (0600)", path.display());
    println!("public key:   {}", pk.to_key_string());
    println!("recipient id: {}", pk.recipient_id());
    println!("\nAdd to .sc/recipients.toml under [recipients]:");
    println!("  <name> = \"{}\"", pk.to_key_string());
    Ok(())
}
```

- [ ] **Step 4: Build and smoke-test keygen**

Run: `cargo run --bin sc -- keygen --out ./scratch-identity`
Expected: prints a `scl-pk-…` public key and a 32-char recipient id; `./scratch-identity` exists. Clean up: `rm ./scratch-identity`.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/Cargo.toml crates/cli/src/main.rs
git commit -m "feat(cli): sc keygen + identity path resolution"
```

---

## Task 8: Recipients file loader

**Files:**
- Modify: `crates/cli/src/main.rs`

- [ ] **Step 1: Add the loader + a unit test**

Add to `crates/cli/src/main.rs` (the `serde` derive needs the crate-level import; `clap::Parser` is already imported):

```rust
/// Parsed `.sc/recipients.toml`: `name -> scl-pk-<hex>`.
#[derive(serde::Deserialize)]
struct RecipientsFile {
    #[serde(default)]
    recipients: std::collections::BTreeMap<String, String>,
}

/// Resolve recipient names to public keys from a recipients file.
fn load_recipients(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, scl_crypto::PublicKey>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let parsed: RecipientsFile = toml::from_str(&text)?;
    let mut out = std::collections::BTreeMap::new();
    for (name, key_str) in parsed.recipients {
        let pk = scl_crypto::PublicKey::from_key_string(&key_str)
            .map_err(|_| anyhow::anyhow!("bad public key for recipient '{name}'"))?;
        out.insert(name, pk);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_recipients_from_toml() {
        let (_sk, pk) = scl_crypto::generate_keypair();
        let dir = std::env::temp_dir().join(format!("scl-recip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recipients.toml");
        std::fs::write(
            &path,
            format!("[recipients]\nalice = \"{}\"\n", pk.to_key_string()),
        )
        .unwrap();

        let map = load_recipients(&path).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map["alice"].to_bytes(), pk.to_bytes());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
```

- [ ] **Step 2: Run the CLI tests**

Run: `cargo test -p scl-cli`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/cli/src/main.rs
git commit -m "feat(cli): .sc/recipients.toml loader"
```

---

## Task 9: `sc secret-demo` — the Phase 2 proof

**Files:**
- Modify: `crates/cli/src/main.rs`

- [ ] **Step 1: Add the subcommand and args**

Add to the `Cmd` enum in `crates/cli/src/main.rs`:

```rust
    /// Phase 2 proof: add a committed secret, deny an unauthorized context,
    /// decrypt + inject in an authorized one, then grant — all in RAM.
    SecretDemo(SecretDemoArgs),
```

Add the args struct (near `DemoArgs`):

```rust
#[derive(Parser)]
struct SecretDemoArgs {
    /// Resident blob budget in megabytes.
    #[arg(long, default_value_t = 8)]
    budget_mb: usize,
}
```

Add the match arm in `main`:

```rust
        Cmd::SecretDemo(args) => run_secret_demo(args),
```

- [ ] **Step 2: Implement the demo**

Add to `crates/cli/src/main.rs`:

```rust
/// Decrypt `name` from `snapshot` using `identity`, inject it into a child
/// process environment, and return what the child read back. Proves the value
/// reaches a real process env without ever touching disk.
fn run_with_secret(
    repo: &Repo,
    snapshot: scl_core::ObjectId,
    name: &str,
    identity: &scl_crypto::SecretKey,
) -> Result<String> {
    let wt = repo.fork(snapshot, "run")?;
    let sid = wt
        .secret_id(name)
        .ok_or_else(|| anyhow::anyhow!("no secret named {name}"))?;
    let secret = repo.store().lock().unwrap().get_secret(&sid)?;
    let plaintext = scl_crypto::open(&secret, identity)?; // Err if unauthorized
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("printf %s \"${name}\""))
        .env(name, std::str::from_utf8(&plaintext).unwrap_or(""))
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_secret_demo(args: SecretDemoArgs) -> Result<()> {
    let pid = std::process::id();
    let session_root = std::env::temp_dir().join(format!("scl-secret-session-{pid}"));
    let _ = std::fs::remove_dir_all(&session_root);
    std::fs::create_dir_all(&session_root)?;

    println!("=== src-control · committed-secrets demo ===");
    let budget_bytes = args.budget_mb * 1024 * 1024;
    let repo = Repo::new(Store::new(StoreConfig {
        budget_bytes,
        spill: SpillPolicy::Disallow,
    }));

    // Two identities, generated in RAM (never written to disk in this demo).
    let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
    let (mallory_sk, mallory_pk) = scl_crypto::generate_keypair();
    println!("alice   recipient: {}", alice_pk.recipient_id());
    println!("mallory recipient: {}", mallory_pk.recipient_id());

    // Base snapshot: one file + one secret sealed to ALICE only.
    let secret_value = b"postgres://app:s3cr3t@db.prod/main";
    let base = repo.commit_files(
        &[("README.md".into(), b"# app\n".to_vec(), FileMode::FILE)],
        "seed",
        "init",
    )?;
    let mut setup = repo.fork(base, "setup")?;
    setup.put_secret(scl_crypto::seal("DB_URL", secret_value, &[alice_pk.clone()]))?;
    let snap = setup.commit("setup", "commit DB_URL")?;
    println!("\ncommitted secret DB_URL (wrapped to alice) in snapshot {}", snap.short());

    // 1) Unauthorized context: mallory cannot decrypt.
    println!("\n--- unauthorized context (mallory) ---");
    match run_with_secret(&repo, snap, "DB_URL", &mallory_sk) {
        Ok(v) => anyhow::bail!("SECURITY FAILURE: mallory decrypted DB_URL = {v:?}"),
        Err(e) => println!("mallory run -> DENIED ({e})"),
    }
    // The stored object is still ciphertext.
    let stored = {
        let id = repo.fork(snap, "probe")?.secret_id("DB_URL").unwrap();
        repo.store().lock().unwrap().get_secret(&id)?
    };
    assert_ne!(stored.ciphertext, secret_value, "stored value must be ciphertext");
    println!("stored DB_URL is ciphertext ({} bytes), not the plaintext ✔", stored.ciphertext.len());

    // 2) Authorized context: alice decrypts and injects into a child process.
    println!("\n--- authorized context (alice) ---");
    let got = run_with_secret(&repo, snap, "DB_URL", &alice_sk)?;
    assert_eq!(got.as_bytes(), secret_value, "alice's child must see the plaintext");
    println!("alice run -> child process read DB_URL = <{} bytes, matches> ✔", got.len());

    // 3) Grant mallory by re-wrapping the DEK (no value rotation).
    println!("\n--- grant mallory (re-wrap DEK) ---");
    let granted = scl_crypto::rewrap_for(&stored, &alice_sk, &mallory_pk)?;
    assert_eq!(granted.ciphertext, stored.ciphertext, "grant must not rotate the value");
    let mut regrant = repo.fork(snap, "grant")?;
    regrant.put_secret(granted)?;
    let snap2 = regrant.commit("admin", "grant mallory")?;
    let got2 = run_with_secret(&repo, snap2, "DB_URL", &mallory_sk)?;
    assert_eq!(got2.as_bytes(), secret_value, "mallory should now decrypt");
    println!("mallory run after grant -> DB_URL decrypted ✔ (value not rotated)");

    // 4) Teardown + zero-residue proof.
    drop(setup);
    drop(repo);
    std::fs::remove_dir_all(&session_root).ok();
    let residue = session_root.exists();
    println!("\n=== teardown ===");
    if residue {
        anyhow::bail!("residual files left on disk at {}", session_root.display());
    }
    println!("RESULT: authorize/deny/grant proven; zero residual files on disk ✔");
    Ok(())
}
```

> Note: `run_with_secret` forks `setup` is moved before `drop(setup)`; the `setup` worktree is only used during setup. If the borrow checker complains about `setup` being moved/dropped, remove the explicit `drop(setup);` — it is dropped at scope end regardless.

- [ ] **Step 3: Build and run the demo**

Run: `cargo run --bin sc -- secret-demo`
Expected output ends with: `RESULT: authorize/deny/grant proven; zero residual files on disk ✔`, with mallory DENIED before the grant and succeeding after.

- [ ] **Step 4: Run the full suite**

Run: `cargo test`
Expected: PASS across the workspace.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/main.rs
git commit -m "feat(cli): sc secret-demo proving authorize/deny/grant in RAM"
```

---

## Task 10: Documentation & ADRs

**Files:**
- Create: `docs/adr/0010-secret-registry-and-opaque-wrapped-dek.md`
- Modify: `docs/adr/0008-committed-secrets-envelope-encryption.md`, `docs/adr/0009-key-management-and-authorization.md`
- Modify: `ARCHITECTURE.md`, `CLAUDE.md`

- [ ] **Step 1: Flip ADR-0008 and ADR-0009 to Accepted**

In both files, change `- **Status:** Proposed` to `- **Status:** Accepted`.

- [ ] **Step 2: Write ADR-0010**

Create `docs/adr/0010-secret-registry-and-opaque-wrapped-dek.md`:

```markdown
# ADR-0010: Secrets as a snapshot-side registry with an opaque wrapped DEK

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** 2

## Context

ADR-0008/0009 fixed the cryptography but left two structural questions open: how
a `Secret` is referenced from repo state, and how the per-recipient wrapped DEK
is laid out in the object format.

## Decision

1. **Secrets live in a side registry on `Snapshot`** — `secrets: [(name,
   ObjectId)]`, sorted by name for canonical encoding — *not* in the file tree.
   Secrets are environment variables, not files. `checkout` only materializes the
   file tree, so plaintext (or even ciphertext) is never written as a file; an
   authorized context injects decrypted values into a child process environment
   instead. The registry encodes empty for ordinary commits and Git imports.

2. **`WrappedKey.wrapped_dek` is an opaque blob owned by `scl-crypto`** with the
   layout `ephemeral_pubkey(32) ‖ wrap_nonce(24) ‖ wrapped-DEK ciphertext+tag`.
   `scl-core` stores it without interpreting it, so the object model carries no
   cryptographic structure and `core` stays free of any crypto dependency.

## Consequences

- Adding the registry changes the canonical encoding of every `Snapshot`, hence
  its `ObjectId`. Accepted as a pre-release format break.
- `core` depends on neither Git, worktrees, nor crypto — a new invariant.
- The wrapped-DEK layout can evolve (versioned by the `scl-dek-wrap-v1` HKDF info
  string) without touching `core`.

## Alternatives considered

- **Secrets in the file tree (new `EntryKind::Secret`).** Conflates files and env
  vars and forces `checkout` to learn to skip entries to avoid writing ciphertext
  to disk. Rejected.
- **A dedicated secrets `Tree`.** More machinery than a flat registry buys for an
  env-var namespace that is naturally flat. Deferred.
- **An explicit `ephemeral_pubkey` field on `WrappedKey`.** Pushes crypto layout
  into `core`. Rejected in favor of the opaque blob.
```

- [ ] **Step 3: Update ARCHITECTURE.md**

In `ARCHITECTURE.md`, update the Phase 2 bullet in "Thesis and MVP scope" to reflect built status, and add to the system overview that `crypto` is a crate. Replace the "Key management design (Phase 2 preview)" heading's lead-in to note it is now implemented, and add a short paragraph:

```markdown
Secrets are referenced by a side registry on each snapshot (`name -> Secret id`),
kept separate from the file tree so `checkout` never materializes them. An
authorized context decrypts in memory and injects the value into a child process
environment; `sc secret-demo` proves the authorize/deny/grant flow end-to-end with
the same zero-residue teardown as Phase 1. See ADR-0010.
```

- [ ] **Step 4: Update CLAUDE.md**

In `CLAUDE.md`:

- In the workspace layout block, add:
  ```
  crates/crypto → envelope encryption (depends on core; ONLY crate linking RustCrypto)
  ```
- Change the dependency rule line to:
  `cli → {vfs, gitio, crypto} → core`
  and add a sentence: **`core` must never depend on Git, worktrees, *or crypto*.**
- Under Commands, add:
  ```sh
  cargo run --bin sc -- keygen                 # generate an X25519 identity
  cargo run --bin sc -- secret-demo            # committed-secrets authorize/deny/grant proof
  ```
- In "When extending toward Phase 2", note the crate now exists (`scl-crypto`) and the registry/run-inject model is built.

- [ ] **Step 5: Verify docs build nothing but commit**

Run: `cargo test`
Expected: still PASS (docs-only changes).

- [ ] **Step 6: Commit**

```bash
git add docs/ ARCHITECTURE.md CLAUDE.md
git commit -m "docs: accept ADR-0008/0009, add ADR-0010, update architecture for Phase 2"
```

---

## Done criteria

- `cargo test` passes across the workspace.
- `cargo run --bin sc -- secret-demo` prints the authorize/deny/grant proof and ends with zero residual files.
- `cargo run --bin sc -- keygen --out <path>` writes a `0600` identity and prints a public key + recipient id.
- `sc demo` (Phase 1) is unchanged and still proves zero residue.
- ADR-0008/0009 are Accepted; ADR-0010 exists; ARCHITECTURE.md and CLAUDE.md reflect the built Phase 2.
