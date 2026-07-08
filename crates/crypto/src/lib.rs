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
pub mod signing;

pub use envelope::{decrypt_path, encrypt_path, open, rewrap_for, revoke, seal, unwrap_dek_with, wrap_dek_for};
pub use error::{Error, Result};
pub use key::{generate_keypair, PublicKey, RecipientId, SecretKey};
pub use provider::{FileKeyProvider, KeyProvider};
pub use signing::{
    generate_identity_v2, parse_identity, sign_snapshot_id, verify_snapshot_sig, Identity,
    SigPublicKey, SigningKey,
};
/// Re-exported so downstream crates can name the zeroizing-on-drop wrapper
/// type returned by `decrypt_path`/`open` without adding a direct `zeroize`
/// dependency of their own (keeps RustCrypto-family deps quarantined here).
pub use zeroize::Zeroizing;
