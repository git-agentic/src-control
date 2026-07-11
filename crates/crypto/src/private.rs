//! Private-branch primitives (P34, ADR-0044): sealed objects, the branch KEK,
//! and the encrypted branch index.
//!
//! A private branch's object bodies are sealed one-by-one under fresh random
//! per-object DEKs (`seal_object`). The DEKs — and the mapping from *inner*
//! (plaintext) object ids to *sealed* (ciphertext) object ids — live in a
//! [`BranchIndex`], which travels only as one AEAD blob encrypted under the
//! per-branch KEK (`BranchIndex::encrypt`). The KEK itself is wrapped per
//! recipient with the exact P2 X25519 envelope (`wrap_kek_for`). Revocation
//! rewrap is therefore: fresh KEK, re-encrypt the index, re-wrap the KEK —
//! no content plaintext, no sealed-object id churn.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use scl_core::{ObjectId, WrappedKey};

use crate::error::{Error, Result};
use crate::key::{PublicKey, SecretKey};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
/// AAD domains: a sealed object body and an encrypted index can never be
/// swapped for one another (or for a P7 path blob, which uses `scl-path-v1`).
const SEALED_AAD: &[u8] = b"scl-sealed-object-v1";
const INDEX_AAD: &[u8] = b"scl-branch-index-v1";

/// Generate a fresh branch KEK from the OS CSPRNG.
pub fn generate_kek() -> Zeroizing<[u8; KEY_LEN]> {
    generate_kek_with_rng(&mut OsRng)
}

/// `generate_kek` with a caller-supplied RNG (deterministic in tests).
pub fn generate_kek_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<[u8; KEY_LEN]> {
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    rng.fill_bytes(kek.as_mut_slice());
    kek
}

/// Wrap the branch KEK for one recipient. Same X25519→HKDF→AEAD envelope as a
/// secret DEK wrap — a KEK is 32 key bytes like any DEK.
pub fn wrap_kek_for(kek: &[u8; KEY_LEN], recipient: &PublicKey) -> WrappedKey {
    crate::envelope::wrap_dek_for(kek, recipient)
}

/// Unwrap the branch KEK with `identity` (errors if not the wrap's recipient).
pub fn unwrap_kek_with(wrapped: &WrappedKey, identity: &SecretKey) -> Result<Zeroizing<[u8; 32]>> {
    crate::envelope::unwrap_dek_with(wrapped, identity)
}

/// Seal an inner object's canonical encoding under a fresh random DEK + nonce.
/// Returns the sealed payload (`nonce ‖ ciphertext`, the bytes of a
/// `Object::Sealed`) and the DEK to be recorded in the branch index.
pub fn seal_object(encoding: &[u8]) -> (Vec<u8>, Zeroizing<[u8; KEY_LEN]>) {
    seal_object_with_rng(encoding, &mut OsRng)
}

/// `seal_object` with a caller-supplied RNG (deterministic in tests).
pub fn seal_object_with_rng<R: RngCore + CryptoRng>(
    encoding: &[u8],
    rng: &mut R,
) -> (Vec<u8>, Zeroizing<[u8; KEY_LEN]>) {
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    rng.fill_bytes(dek.as_mut_slice());
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).expect("32-byte DEK");
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: encoding,
                aad: SEALED_AAD,
            },
        )
        .expect("aead encrypt is infallible for valid inputs");

    let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    (payload, dek)
}

/// Open a sealed payload with its DEK (AEAD-verified). Returns the inner
/// object's canonical encoding.
pub fn open_object(payload: &[u8], dek: &[u8; KEY_LEN]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() < NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = payload.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(dek).map_err(|_| Error::Decrypt)?;
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: SEALED_AAD,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(pt))
}

/// One branch-index entry: where an inner object's ciphertext lives and the
/// DEK that opens it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IndexEntry {
    pub sealed: ObjectId,
    pub dek: [u8; KEY_LEN],
}

/// The decrypted branch index: the inner (plaintext-id) tip snapshot plus the
/// `inner id -> (sealed id, DEK)` map for every object sealed by this branch.
/// An inner id *absent* from the map is a public object, read directly from
/// the store — that resolution rule is what makes sealing copy-on-write.
///
/// Inner ids are BLAKE3 hashes of plaintext encodings, so the index is exactly
/// as sensitive as the DEKs it carries: it exists in plaintext only inside an
/// authorized process and is zeroized on drop (best-effort).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BranchIndex {
    pub inner_tip: Option<ObjectId>,
    pub entries: BTreeMap<ObjectId, IndexEntry>,
}

impl Drop for BranchIndex {
    fn drop(&mut self) {
        for e in self.entries.values_mut() {
            e.dek.zeroize();
        }
    }
}

impl BranchIndex {
    /// Serialize to the fixed-width index codec (all fields are 32-byte ids or
    /// keys, so no length-prefixing is needed beyond the entry count).
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Zeroizing::new(Vec::with_capacity(33 + self.entries.len() * 96));
        match &self.inner_tip {
            Some(id) => {
                buf.push(1u8);
                buf.extend_from_slice(id.as_bytes());
            }
            None => buf.push(0u8),
        }
        buf.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for (inner, e) in &self.entries {
            buf.extend_from_slice(inner.as_bytes());
            buf.extend_from_slice(e.sealed.as_bytes());
            buf.extend_from_slice(&e.dek);
        }
        buf
    }

    fn decode(bytes: &[u8]) -> Result<BranchIndex> {
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> Result<&[u8]> {
            if *pos + n > bytes.len() {
                return Err(Error::Decrypt);
            }
            let s = &bytes[*pos..*pos + n];
            *pos += n;
            Ok(s)
        };
        let id32 = |pos: &mut usize| -> Result<ObjectId> {
            let mut a = [0u8; 32];
            a.copy_from_slice(take(pos, 32)?);
            Ok(ObjectId::from_bytes(a))
        };
        let inner_tip = match take(&mut pos, 1)?[0] {
            0 => None,
            1 => Some(id32(&mut pos)?),
            _ => return Err(Error::Decrypt),
        };
        let mut nb = [0u8; 4];
        nb.copy_from_slice(take(&mut pos, 4)?);
        let n = u32::from_be_bytes(nb) as usize;
        // Every entry is exactly 96 bytes; a count that overruns the buffer is
        // fabricated (same guard idiom as core's object decoder).
        if n.checked_mul(96).map(|need| pos + need != bytes.len()) != Some(false) {
            return Err(Error::Decrypt);
        }
        let mut entries = BTreeMap::new();
        for _ in 0..n {
            let inner = id32(&mut pos)?;
            let sealed = id32(&mut pos)?;
            let mut dek = [0u8; KEY_LEN];
            dek.copy_from_slice(take(&mut pos, KEY_LEN)?);
            entries.insert(inner, IndexEntry { sealed, dek });
        }
        Ok(BranchIndex { inner_tip, entries })
    }

    /// Encrypt the index under the branch KEK with a fresh random nonce.
    /// Returns `nonce ‖ ciphertext` (the manifest's `index_ct` field).
    pub fn encrypt(&self, kek: &[u8; KEY_LEN]) -> Vec<u8> {
        self.encrypt_with_rng(kek, &mut OsRng)
    }

    /// `encrypt` with a caller-supplied RNG (deterministic in tests).
    pub fn encrypt_with_rng<R: RngCore + CryptoRng>(
        &self,
        kek: &[u8; KEY_LEN],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(kek).expect("32-byte KEK");
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: self.encode().as_slice(),
                    aad: INDEX_AAD,
                },
            )
            .expect("aead encrypt is infallible for valid inputs");
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob
    }

    /// Decrypt and decode an index blob with the branch KEK (AEAD-verified).
    pub fn decrypt(index_ct: &[u8], kek: &[u8; KEY_LEN]) -> Result<BranchIndex> {
        if index_ct.len() < NONCE_LEN {
            return Err(Error::Decrypt);
        }
        let (nonce, ct) = index_ct.split_at(NONCE_LEN);
        let cipher = XChaCha20Poly1305::new_from_slice(kek).map_err(|_| Error::Decrypt)?;
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: ct,
                        aad: INDEX_AAD,
                    },
                )
                .map_err(|_| Error::Decrypt)?,
        );
        BranchIndex::decode(&pt)
    }
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

    fn oid(b: u8) -> ObjectId {
        ObjectId::from_bytes([b; 32])
    }

    #[test]
    fn seal_open_object_roundtrip_is_randomized() {
        let encoding = b"tag+payload of some inner object";
        let (p1, d1) = seal_object(encoding);
        let (p2, d2) = seal_object(encoding);
        assert_ne!(p1, p2, "sealing must be randomized (no equality oracle)");
        assert_ne!(d1.as_slice(), d2.as_slice());
        assert_eq!(&open_object(&p1, &d1).unwrap()[..], encoding);
        assert_eq!(&open_object(&p2, &d2).unwrap()[..], encoding);
        // Wrong DEK / tampered payload fail AEAD.
        assert!(open_object(&p1, &d2).is_err());
        let mut tampered = p1.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0xFF;
        assert!(open_object(&tampered, &d1).is_err());
    }

    #[test]
    fn sealed_object_aad_differs_from_path_blob() {
        // A sealed object cannot be opened by the path decryptor even with the
        // right DEK: the AAD domains are distinct on purpose.
        let (payload, dek) = seal_object(b"x");
        assert!(crate::envelope::decrypt_path(&payload, &dek).is_err());
    }

    #[test]
    fn index_roundtrip_through_kek() {
        let kek = generate_kek_with_rng(&mut rng(1));
        let mut idx = BranchIndex {
            inner_tip: Some(oid(9)),
            entries: BTreeMap::new(),
        };
        idx.entries.insert(
            oid(1),
            IndexEntry {
                sealed: oid(2),
                dek: [3; 32],
            },
        );
        idx.entries.insert(
            oid(4),
            IndexEntry {
                sealed: oid(5),
                dek: [6; 32],
            },
        );
        let ct = idx.encrypt_with_rng(&kek, &mut rng(2));
        let back = BranchIndex::decrypt(&ct, &kek).unwrap();
        assert_eq!(back, idx);
        // Wrong KEK fails AEAD rather than yielding garbage.
        let other = generate_kek_with_rng(&mut rng(7));
        assert!(BranchIndex::decrypt(&ct, &other).is_err());
    }

    #[test]
    fn empty_index_roundtrips() {
        let kek = generate_kek_with_rng(&mut rng(1));
        let idx = BranchIndex::default();
        let ct = idx.encrypt_with_rng(&kek, &mut rng(2));
        assert_eq!(BranchIndex::decrypt(&ct, &kek).unwrap(), idx);
    }

    #[test]
    fn index_decode_rejects_fabricated_count_and_trailing_bytes() {
        let kek = generate_kek_with_rng(&mut rng(1));
        // Build a valid plaintext then corrupt the count field before
        // encrypting: decode must reject it after a successful AEAD open.
        let idx = BranchIndex {
            inner_tip: None,
            entries: BTreeMap::new(),
        };
        let mut pt = idx.encode().to_vec();
        // count = 1 but no entry bytes follow.
        let len = pt.len();
        pt[len - 1] = 1;
        let cipher = XChaCha20Poly1305::new_from_slice(kek.as_slice()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        rng(3).fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: INDEX_AAD,
                },
            )
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        assert!(BranchIndex::decrypt(&blob, &kek).is_err());
    }

    #[test]
    fn kek_wrap_unwrap_roundtrip_per_recipient() {
        let (sk_a, pk_a) = generate_keypair_with_rng(&mut rng(1));
        let (sk_b, _pk_b) = generate_keypair_with_rng(&mut rng(2));
        let kek = generate_kek_with_rng(&mut rng(3));
        let wk = wrap_kek_for(&kek, &pk_a);
        assert_eq!(
            unwrap_kek_with(&wk, &sk_a).unwrap().as_slice(),
            kek.as_slice()
        );
        assert!(
            unwrap_kek_with(&wk, &sk_b).is_err(),
            "non-recipient must fail"
        );
    }
}
