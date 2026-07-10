//! SubjectPublicKeyInfo extraction from a certificate DER, and the
//! `sha256:<hex>` fingerprint every P32 surface uses (pin file, banner,
//! `sc serve fingerprint`, `SC_HTTPS_FINGERPRINT`).
//!
//! The extraction is a minimal hand-written DER TLV walk rather than a full
//! x509 parser dependency: we need exactly one field, the walk is ~40 lines,
//! and a malformed certificate simply fails the connection (fail-closed).
//! Correctness is anchored by the test comparing against rcgen's own
//! `PublicKeyData::subject_public_key_info()` for a cert we minted.

use crate::{Error, Result};

/// One DER TLV: returns (tag, content_start..content_end, total_len).
fn der_tlv(buf: &[u8]) -> Option<(u8, core::ops::Range<usize>, usize)> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, header..end, end))
}

/// Extract the full SubjectPublicKeyInfo TLV (header included) from a
/// certificate DER. Layout: `Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signature }`; `TBSCertificate ::= SEQUENCE {
/// [0] version OPTIONAL, serialNumber, signature, issuer, validity,
/// subject, subjectPublicKeyInfo, ... }` — so: descend two SEQUENCEs, skip
/// the optional context-0 version, skip five fields, take the sixth.
pub fn spki_der(cert_der: &[u8]) -> Result<&[u8]> {
    let (tag, body, _) = der_tlv(cert_der).ok_or(Error::BadCert)?;
    if tag != 0x30 {
        return Err(Error::BadCert);
    }
    let tbs_buf = &cert_der[body];
    let (tag, body, _) = der_tlv(tbs_buf).ok_or(Error::BadCert)?;
    if tag != 0x30 {
        return Err(Error::BadCert);
    }
    let mut rest = &tbs_buf[body];
    if rest.first() == Some(&0xa0) {
        let (_, _, used) = der_tlv(rest).ok_or(Error::BadCert)?;
        rest = &rest[used..];
    }
    for _ in 0..5 {
        let (_, _, used) = der_tlv(rest).ok_or(Error::BadCert)?;
        rest = &rest[used..];
    }
    let (tag, _, used) = der_tlv(rest).ok_or(Error::BadCert)?;
    if tag != 0x30 {
        return Err(Error::BadCert);
    }
    Ok(&rest[..used])
}

/// SHA-256 over the SPKI TLV — the pin. ring's digest, not a RustCrypto
/// crate (RustCrypto stays quarantined in crates/crypto); ring is already
/// in-tree as rustls's crypto provider.
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]> {
    let spki = spki_der(cert_der)?;
    let d = ring::digest::digest(&ring::digest::SHA256, spki);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    Ok(out)
}

/// Render a pin as `sha256:<lowercase hex>` — the one fingerprint format.
pub fn fingerprint_hex(spki_hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(spki_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_der_matches_rcgen_public_key_der() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["sc-serve".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let extracted = spki_der(cert.der()).unwrap();
        assert_eq!(
            extracted,
            rcgen::PublicKeyData::subject_public_key_info(&key).as_slice()
        );
    }

    #[test]
    fn spki_sha256_is_stable_across_same_key_remint() {
        let key = rcgen::KeyPair::generate().unwrap();
        let c1 = rcgen::CertificateParams::new(vec!["a".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let c2 = rcgen::CertificateParams::new(vec!["b".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        // Different cert bytes, same key → same SPKI hash (the whole point
        // of pinning the SPKI, not the cert).
        assert_ne!(c1.der().as_ref(), c2.der().as_ref());
        assert_eq!(
            spki_sha256(c1.der()).unwrap(),
            spki_sha256(c2.der()).unwrap()
        );
    }

    #[test]
    fn fingerprint_hex_format() {
        let h = [0xabu8; 32];
        let s = fingerprint_hex(&h);
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), "sha256:".len() + 64);
    }

    #[test]
    fn spki_der_rejects_garbage() {
        assert!(spki_der(b"not a certificate").is_err());
        assert!(spki_der(&[]).is_err());
        assert!(spki_der(&[0x30, 0x82, 0xff]).is_err()); // truncated length
    }
}
