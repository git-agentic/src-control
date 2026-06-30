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

// ---- convergent path encryption (P7) --------------------------------------

const PATH_AAD: &[u8] = b"scl-path-v1";

/// Convergent file encryption: the data key and nonce are derived from the
/// plaintext, so identical plaintext yields identical `nonce‖ciphertext` bytes
/// (stable content-addressed id, perfect dedup). Returns the blob bytes and the
/// DEK (to be wrapped per recipient and stored in the snapshot policy).
pub fn encrypt_path(plaintext: &[u8]) -> (Vec<u8>, Zeroizing<[u8; DEK_LEN]>) {
    let ikm = blake3::hash(plaintext);
    let hk = Hkdf::<Sha256>::new(None, ikm.as_bytes());
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    hk.expand(b"scl-path-dek-v1", dek.as_mut_slice()).expect("32-byte okm");
    let mut nonce = [0u8; NONCE_LEN];
    hk.expand(b"scl-path-nonce-v1", &mut nonce).expect("24-byte okm");

    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).expect("32-byte DEK");
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: PATH_AAD })
        .expect("aead encrypt is infallible for valid inputs");

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    (blob, dek)
}

/// Decrypt a `nonce‖ciphertext` blob with its DEK (AEAD-verified).
pub fn decrypt_path(blob: &[u8], dek: &[u8; DEK_LEN]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| Error::Decrypt)?;
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: PATH_AAD })
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(pt))
}

/// Wrap a DEK for `recipient` (X25519→HKDF→AEAD); the wrap uses a random
/// ephemeral key, so the wrapped bytes vary — but they live in the snapshot
/// policy, NOT in the content-addressed blob, so dedup is unaffected.
pub fn wrap_dek_for(dek: &[u8; DEK_LEN], recipient: &PublicKey) -> WrappedKey {
    wrap_dek(dek.as_slice(), recipient, &mut OsRng)
}

/// Unwrap a DEK from a `WrappedKey` with `identity` (errors if not the recipient).
pub fn unwrap_dek_with(wrapped: &WrappedKey, identity: &SecretKey) -> Result<Zeroizing<[u8; DEK_LEN]>> {
    unwrap_dek(&wrapped.wrapped_dek, identity)
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

    #[test]
    fn encrypt_path_is_convergent_and_roundtrips() {
        let pt = b"the database password is hunter2";
        let (blob1, dek1) = encrypt_path(pt);
        let (blob2, _dek2) = encrypt_path(pt);
        assert_eq!(blob1, blob2, "same plaintext -> identical bytes (convergent)");
        let out = decrypt_path(&blob1, &dek1).unwrap();
        assert_eq!(&out[..], pt);
        let (blob3, _) = encrypt_path(b"different");
        assert_ne!(blob1, blob3);
    }

    #[test]
    fn decrypt_path_rejects_tamper_and_wrong_key() {
        let (mut blob, dek) = encrypt_path(b"secret");
        let n = blob.len();
        blob[n - 1] ^= 0xFF;
        assert!(decrypt_path(&blob, &dek).is_err());
        let (good, _) = encrypt_path(b"secret");
        let wrong = [0u8; 32];
        assert!(decrypt_path(&good, &wrong).is_err());
    }

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        use crate::key::generate_keypair_with_rng;
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        let (sk, pk) = generate_keypair_with_rng(&mut ChaCha20Rng::seed_from_u64(1));
        let (_blob, dek) = encrypt_path(b"x");
        let wk = wrap_dek_for(&dek, &pk);
        let got = unwrap_dek_with(&wk, &sk).unwrap();
        assert_eq!(got.as_slice(), dek.as_slice());
        let (other_sk, _) = generate_keypair_with_rng(&mut ChaCha20Rng::seed_from_u64(2));
        assert!(unwrap_dek_with(&wk, &other_sk).is_err());
    }
}
