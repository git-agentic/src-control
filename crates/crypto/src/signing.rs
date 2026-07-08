//! Ed25519 commit signing and the unified seed-derived identity (v2).
//!
//! P22 adds provenance on top of P7's per-file confidentiality: a v2
//! identity file (`scl-id-<hex64 seed>`) carries a single 32-byte seed from
//! which BOTH halves of the identity are derived deterministically, reusing
//! the crate's existing HKDF-SHA256 machinery (the same primitive the DEK
//! envelope already uses, just with distinct info strings so the two
//! derivations can never collide):
//!
//! ```text
//! x25519_secret = HKDF-SHA256(salt = None, ikm = seed, info = "scl-id-v2-enc")[..32]
//! ed25519_seed  = HKDF-SHA256(salt = None, ikm = seed, info = "scl-id-v2-sig")[..32]
//! ```
//!
//! The X25519 half is fed through `x25519_dalek::StaticSecret::from` — the
//! same construction `SecretKey::from_key_string` uses for v1 identities —
//! so a v2 identity's encryption half behaves identically to a v1
//! `SecretKey` once derived. The Ed25519 half is fed through
//! `ed25519_dalek::SigningKey::from_bytes`.
//!
//! v1 identity files (`scl-sk-<hex>`) remain encryption-only: every existing
//! caller of `SecretKey::from_key_string` is untouched, and `parse_identity`
//! is a purely additive parse that recognizes both prefixes.
//!
//! Signatures are domain-separated: the signed message is always
//! `"sc-snapshot-sig-v1" || id`, never the bare 32-byte snapshot id, so a
//! signature can never be replayed as if it covered different domain data.

use ed25519_dalek::Signer;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::key::SecretKey;

const ID_PREFIX: &str = "scl-id-";
const SIG_PUB_PREFIX: &str = "scl-sig-";
const SIG_DOMAIN: &[u8] = b"sc-snapshot-sig-v1";
const ENC_INFO: &[u8] = b"scl-id-v2-enc";
const SIG_INFO: &[u8] = b"scl-id-v2-sig";

/// Ed25519 signing half of a v2 identity. Zeroized on drop (the inner
/// `ed25519_dalek::SigningKey` zeroizes its bytes).
pub struct SigningKey(ed25519_dalek::SigningKey);

/// Ed25519 verifying key; string form `scl-sig-<hex>`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigPublicKey(ed25519_dalek::VerifyingKey);

impl SigningKey {
    /// The verifying key for this signing key.
    pub fn public(&self) -> SigPublicKey {
        SigPublicKey(self.0.verifying_key())
    }
}

impl SigPublicKey {
    /// Encode as a `scl-sig-<hex>` string.
    pub fn to_key_string(&self) -> String {
        format!("{SIG_PUB_PREFIX}{}", hex::encode(self.0.to_bytes()))
    }

    /// Parse a `scl-sig-<hex>` string.
    pub fn from_key_string(s: &str) -> Result<Self> {
        let hexpart = s.trim().strip_prefix(SIG_PUB_PREFIX).ok_or(Error::BadKey)?;
        let bytes = hex::decode(hexpart).map_err(|_| Error::BadKey)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::BadKey)?;
        Self::from_bytes(arr)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Construct from raw 32-byte verifying-key bytes. Rejects bytes that
    /// are not a valid Ed25519 point (`Error::BadKey`).
    pub fn from_bytes(b: [u8; 32]) -> Result<Self> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&b).map_err(|_| Error::BadKey)?;
        Ok(SigPublicKey(vk))
    }
}

/// A parsed identity file: v1 (`scl-sk-…`, encryption only) or v2
/// (`scl-id-<hex64 seed>`, seed-derived encryption + signing keys).
pub struct Identity {
    pub enc: SecretKey,
    pub signing: Option<SigningKey>,
}

/// Parse an identity file's contents, accepting both the v1 `scl-sk-`
/// encryption-only form and the v2 `scl-id-` seed-derived form.
pub fn parse_identity(text: &str) -> Result<Identity> {
    let s = text.trim();
    if let Some(hexpart) = s.strip_prefix(ID_PREFIX) {
        let seed_bytes = Zeroizing::new(hex::decode(hexpart).map_err(|_| Error::BadKey)?);
        if seed_bytes.len() != 32 {
            return Err(Error::BadKey);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let identity = derive_identity_v2(&seed);
        use zeroize::Zeroize;
        seed.zeroize();
        Ok(identity)
    } else {
        // Falls through to the v1 form; `SecretKey::from_key_string` already
        // validates the `scl-sk-` prefix and returns `Error::BadKey` on any
        // other malformed input.
        let enc = SecretKey::from_key_string(s)?;
        Ok(Identity { enc, signing: None })
    }
}

/// Derive a v2 identity's encryption + signing halves from a 32-byte seed.
fn derive_identity_v2(seed: &[u8; 32]) -> Identity {
    let hk = Hkdf::<Sha256>::new(None, seed);

    let mut enc_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(ENC_INFO, enc_bytes.as_mut_slice())
        .expect("32-byte HKDF output");
    let x25519_secret = x25519_dalek::StaticSecret::from(*enc_bytes);
    let enc = SecretKey::from_static_secret(x25519_secret);

    let mut sig_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(SIG_INFO, sig_bytes.as_mut_slice())
        .expect("32-byte HKDF output");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sig_bytes);

    Identity {
        enc,
        signing: Some(SigningKey(signing_key)),
    }
}

/// Generate a fresh v2 identity from the OS RNG: a random 32-byte seed,
/// encoded as `scl-id-<hex>`, plus the derived [`Identity`].
pub fn generate_identity_v2() -> (String, Identity) {
    use rand_core::{OsRng, RngCore};
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let identity = derive_identity_v2(&seed);
    let s = format!("{ID_PREFIX}{}", hex::encode(seed));
    use zeroize::Zeroize;
    seed.zeroize();
    (s, identity)
}

/// Sign a snapshot id under the domain-separated message
/// `"sc-snapshot-sig-v1" || id`.
pub fn sign_snapshot_id(key: &SigningKey, id: &[u8; 32]) -> [u8; 64] {
    let mut message = Vec::with_capacity(SIG_DOMAIN.len() + id.len());
    message.extend_from_slice(SIG_DOMAIN);
    message.extend_from_slice(id);
    key.0.sign(&message).to_bytes()
}

/// Verify a domain-separated snapshot-id signature. Returns `false` on a
/// malformed signer key (bad Ed25519 point) as well as on a genuine
/// verification failure — callers only need one "not valid" outcome.
pub fn verify_snapshot_sig(signer: &[u8; 32], id: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(signer) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);

    let mut message = Vec::with_capacity(SIG_DOMAIN.len() + id.len());
    message.extend_from_slice(SIG_DOMAIN);
    message.extend_from_slice(id);

    vk.verify_strict(&message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{open, seal};

    #[test]
    fn sign_verify_round_trip_and_domain_separation() {
        let (_s, identity) = generate_identity_v2();
        let signing = identity.signing.expect("v2 identity carries a signing key");
        let signer_bytes = signing.public().to_bytes();

        let id = [7u8; 32];
        let sig = sign_snapshot_id(&signing, &id);
        assert!(verify_snapshot_sig(&signer_bytes, &id, &sig));

        // A different id must not verify against this signature.
        let other_id = [9u8; 32];
        assert!(!verify_snapshot_sig(&signer_bytes, &other_id, &sig));

        // A signature produced over the BARE id (no domain prefix) must not
        // verify — proving the domain string is load-bearing.
        let bare_sig = signing.0.sign(&id).to_bytes();
        assert!(!verify_snapshot_sig(&signer_bytes, &id, &bare_sig));
    }

    #[test]
    fn identity_v2_round_trip_and_deterministic_derivation() {
        let (s, identity) = generate_identity_v2();
        assert!(s.starts_with(ID_PREFIX));

        let parsed1 = parse_identity(&s).unwrap();
        let parsed2 = parse_identity(&s).unwrap();
        assert!(parsed1.signing.is_some());
        assert!(parsed2.signing.is_some());

        assert_eq!(
            parsed1.enc.public().to_bytes(),
            parsed2.enc.public().to_bytes()
        );
        assert_eq!(
            parsed1.signing.as_ref().unwrap().public().to_bytes(),
            parsed2.signing.as_ref().unwrap().public().to_bytes()
        );
        assert_eq!(
            identity.enc.public().to_bytes(),
            parsed1.enc.public().to_bytes()
        );

        // The enc half encrypts/decrypts interoperably through the existing
        // envelope machinery (reusing the envelope tests' idiom).
        let secret = seal("k", b"hello world", &[parsed1.enc.public()]);
        let opened = open(&secret, &parsed2.enc).unwrap();
        assert_eq!(opened.as_slice(), b"hello world");
    }

    #[test]
    fn identity_v1_parses_encryption_only() {
        use crate::key::generate_keypair_with_rng;
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        let (sk, _pk) = generate_keypair_with_rng(&mut ChaCha20Rng::seed_from_u64(1));
        let s = sk.to_key_string();
        assert!(s.starts_with("scl-sk-"));

        let identity = parse_identity(&s).unwrap();
        assert!(identity.signing.is_none());
        assert_eq!(identity.enc.public().to_bytes(), sk.public().to_bytes());

        // No regression: from_key_string still works unchanged on the same string.
        let back = SecretKey::from_key_string(&s).unwrap();
        assert_eq!(back.public().to_bytes(), sk.public().to_bytes());
    }

    #[test]
    fn sig_pubkey_string_form_round_trips() {
        let (_s, identity) = generate_identity_v2();
        let signing = identity.signing.unwrap();
        let pk = signing.public();

        let s = pk.to_key_string();
        assert!(s.starts_with(SIG_PUB_PREFIX));
        let back = SigPublicKey::from_key_string(&s).unwrap();
        assert_eq!(pk.to_bytes(), back.to_bytes());

        assert!(matches!(SigPublicKey::from_key_string("nope"), Err(Error::BadKey)));
        assert!(matches!(
            SigPublicKey::from_key_string("scl-sig-zz"),
            Err(Error::BadKey)
        ));
        // Wrong length (valid hex, wrong byte count).
        assert!(matches!(
            SigPublicKey::from_key_string("scl-sig-aabb"),
            Err(Error::BadKey)
        ));
    }
}
