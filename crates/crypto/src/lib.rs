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

/// Generate `n` cryptographically-random bytes from the OS CSPRNG, rendered as
/// lowercase hex. Lives here because the RNG (`rand_core`/`OsRng`) is quarantined
/// to this crate; callers outside `crates/crypto` get randomness through this
/// helper without taking a second RNG dependency.
pub fn random_hex(n: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    #[test]
    fn random_hex_is_right_length_and_varies() {
        let a = crate::random_hex(32);
        let b = crate::random_hex(32);
        assert_eq!(a.len(), 64, "32 bytes -> 64 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two draws must differ (probabilistically certain)");
    }
}
