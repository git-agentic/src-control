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
        wrapped_keys.push(wrap_dek(dek.as_slice(), recipient, &mut *rng));
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

    // Guard against a malformed stored nonce: `XNonce::from_slice` panics on a
    // length mismatch, and a committed `Secret` is attacker-influenced data.
    if secret.nonce.len() != NONCE_LEN {
        return Err(Error::Decrypt);
    }

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
    let new_wk = wrap_dek(dek.as_slice(), new, rng);

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
    let ephemeral_pub_bytes: [u8; 32] = blob[..EPK_LEN].try_into().expect("32-byte slice after length check");
    let wrap_nonce = &blob[EPK_LEN..EPK_LEN + NONCE_LEN];
    let wrapped = &blob[EPK_LEN + NONCE_LEN..];

    // We intentionally do NOT do a low-order / contributory-point check on the
    // ephemeral pubkey: authorization lives outside this crate, and an attacker
    // who can craft this blob can already craft an entire `Secret`, so the check
    // would buy nothing here.
    let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
    let shared = identity.inner().diffie_hellman(&ephemeral_pub);
    let wrap_key = derive_wrap_key(shared.as_bytes(), &ephemeral_pub_bytes, &identity.public().to_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(wrap_key.as_slice()).map_err(|_| Error::Decrypt)?;
    // Wrap the decrypted DEK so the cleartext key is zeroized on drop.
    let dek_vec = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(wrap_nonce), wrapped)
            .map_err(|_| Error::Decrypt)?,
    );
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
    fn malformed_nonce_length_errors_instead_of_panicking() {
        let (sk, pk) = generate_keypair_with_rng(&mut rng(1));
        let mut secret = seal_with_rng("K", b"v", &[pk], &mut rng(2));
        // Truncate the otherwise-valid stored nonce: `open` must reject it, not
        // panic inside `XNonce::from_slice`.
        secret.nonce.truncate(NONCE_LEN - 1);
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
        let secret = seal_with_rng("K", b"v", &[pk_a, pk_b.clone()], &mut rng(3));
        let revoked = revoke(&secret, &pk_b.recipient_id());
        assert!(matches!(open(&revoked, &sk_b), Err(Error::NotARecipient)));
        assert_eq!(&open(&revoked, &sk_a).unwrap()[..], b"v");
    }
}
