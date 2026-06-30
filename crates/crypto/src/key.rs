//! X25519 identities, recipient fingerprints, and their string encodings.

use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

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

    /// Parse a 32 hex-char recipient id (16 bytes). Returns `Error::BadKey` on
    /// bad input. Accepts upper- or lower-case hex and normalizes to lowercase.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != ID_LEN * 2 {
            return Err(Error::BadKey);
        }
        // Validate it's all hex chars.
        if s.bytes().any(|b| !b.is_ascii_hexdigit()) {
            return Err(Error::BadKey);
        }
        Ok(RecipientId(s.to_lowercase()))
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
        // Decode into a zeroizing buffer: these are raw private-key bytes.
        let bytes = Zeroizing::new(hex::decode(hexpart).map_err(|_| Error::BadKey)?);
        if bytes.len() != 32 {
            return Err(Error::BadKey);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        // `StaticSecret::from` takes `arr` by value (it's `Copy`), so the source
        // array survives the call — wipe it before returning.
        let sk = x25519_dalek::StaticSecret::from(arr);
        arr.zeroize();
        Ok(SecretKey(sk))
    }

    pub(crate) fn inner(&self) -> &x25519_dalek::StaticSecret {
        &self.0
    }
}

impl PublicKey {
    /// Construct a `PublicKey` from its raw 32-byte representation. Used to
    /// reconstruct recipient keys from the 32-byte values stored in the
    /// snapshot's `Protection` policy (P7).
    pub fn from_bytes(b: [u8; 32]) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(b))
    }

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

    #[test]
    fn from_bytes_roundtrip() {
        let (_sk, pk) = generate_keypair_with_rng(&mut seeded());
        let back = PublicKey::from_bytes(pk.to_bytes());
        assert_eq!(pk.to_bytes(), back.to_bytes());
    }
}
