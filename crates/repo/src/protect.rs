//! Encrypted-path policy helpers.

use scl_core::{ObjectId, ProtectPrefix, Protection, WrappedKey};

use crate::error::{Error, Result};

/// The protecting prefix rule for `path`, if any (longest-prefix wins).
pub fn matching_prefix<'a>(protection: &'a Protection, path: &str) -> Option<&'a ProtectPrefix> {
    protection
        .prefixes
        .iter()
        .filter(|p| {
            // Match only at a path boundary: a path is governed by a prefix iff it
            // equals the prefix's bare form or lies under it at a `/` boundary.
            // `starts_with` alone would over-match (e.g. `secret` -> `secretstuff`).
            let bare = p.prefix.trim_end_matches('/');
            path == bare || path.starts_with(&format!("{bare}/"))
        })
        .max_by_key(|p| p.prefix.len())
}

/// Union of two protection policies' prefix rules: prefixes united by
/// `prefix` string; a prefix present on both sides unions its recipient
/// sets (deduped by pubkey bytes). Fail-closed: nothing present on either
/// side is dropped.
pub(crate) fn union_prefixes(a: &[ProtectPrefix], b: &[ProtectPrefix]) -> Vec<ProtectPrefix> {
    let mut out: Vec<ProtectPrefix> = Vec::new();
    for p in a.iter().chain(b.iter()) {
        match out.iter_mut().find(|existing| existing.prefix == p.prefix) {
            Some(existing) => {
                for r in &p.recipients {
                    if !existing.recipients.contains(r) {
                        existing.recipients.push(*r);
                    }
                }
            }
            None => out.push(p.clone()),
        }
    }
    out
}

/// Union two wrapped-DEK lists, deduped by recipient_id (first occurrence wins).
pub(crate) fn union_wraps(a: &[WrappedKey], b: &[WrappedKey]) -> Vec<WrappedKey> {
    let mut out: Vec<WrappedKey> = Vec::new();
    for w in a.iter().chain(b.iter()) {
        if !out.iter().any(|existing| existing.recipient_id == w.recipient_id) {
            out.push(w.clone());
        }
    }
    out
}

/// Decrypt a protected blob's ciphertext using `identity`, searching the
/// given protection maps (in order) for its wrapped DEKs. Errors:
/// `NotAuthorized(path)` when no wrap unwraps; `ProtectedMergeNeedsIdentity(path)`
/// is the CALLER's error when identity is None — this fn requires one.
///
/// NOTE: the brief's signature spells the return type `zeroize::Zeroizing<Vec<u8>>`.
/// `scl-repo` does not depend on the `zeroize` crate directly (and per
/// CLAUDE.md's quarantine rule, RustCrypto-adjacent deps should stay behind
/// `crates/crypto`), so `scl_crypto::Zeroizing` — a re-export added in this
/// task (`crates/crypto/src/lib.rs`) — is used here instead of naming
/// `zeroize` directly. Same type, reached through the quarantine boundary.
pub(crate) fn decrypt_with(
    ciphertext: &[u8],
    blob_id: &ObjectId,
    protections: &[&Protection],
    identity: &scl_crypto::SecretKey,
    path: &str,
) -> Result<scl_crypto::Zeroizing<Vec<u8>>> {
    for protection in protections {
        let Some(wraps) = protection.wrapped.get(blob_id) else {
            continue;
        };
        for wrap in wraps {
            let Ok(dek) = scl_crypto::unwrap_dek_with(wrap, identity) else {
                continue;
            };
            if let Ok(plaintext) = scl_crypto::decrypt_path(ciphertext, &dek) {
                return Ok(plaintext);
            }
        }
    }
    Err(Error::NotAuthorized(path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prot(prefixes: &[&str]) -> Protection {
        Protection {
            prefixes: prefixes
                .iter()
                .map(|p| ProtectPrefix { prefix: p.to_string(), recipients: vec![] })
                .collect(),
            wrapped: Default::default(),
        }
    }

    #[test]
    fn matches_under_prefix_longest_wins() {
        let p = prot(&["secrets/", "secrets/prod/"]);
        assert_eq!(
            matching_prefix(&p, "secrets/prod/db").unwrap().prefix,
            "secrets/prod/"
        );
        assert_eq!(matching_prefix(&p, "secrets/x").unwrap().prefix, "secrets/");
        assert!(matching_prefix(&p, "src/main.rs").is_none());
    }

    #[test]
    fn prefix_matches_only_at_path_boundary() {
        // A prefix without a trailing slash must match only the bare path or a
        // child under a `/` boundary — never a sibling sharing a textual prefix.
        let p = prot(&["secret"]);
        assert!(matching_prefix(&p, "secret/db").is_some());
        assert!(matching_prefix(&p, "secret").is_some());
        assert!(matching_prefix(&p, "secretstuff.txt").is_none());
        assert!(matching_prefix(&p, "secret-evil/x").is_none());
    }

    #[test]
    fn union_prefixes_unions_by_prefix_and_recipients() {
        let a = vec![ProtectPrefix { prefix: "secret/".into(), recipients: vec![[1; 32]] }];
        let b = vec![
            ProtectPrefix { prefix: "secret/".into(), recipients: vec![[1; 32], [2; 32]] },
            ProtectPrefix { prefix: "keys/".into(), recipients: vec![[3; 32]] },
        ];
        let u = union_prefixes(&a, &b);
        assert_eq!(u.len(), 2);
        let secret = u.iter().find(|p| p.prefix == "secret/").unwrap();
        assert_eq!(secret.recipients.len(), 2); // [1;32] deduped, [2;32] added
        assert!(u.iter().any(|p| p.prefix == "keys/"));
    }

    #[test]
    fn decrypt_with_unwraps_for_recipient_and_rejects_stranger() {
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _) = scl_crypto::generate_keypair();
        let (cipher, dek) = scl_crypto::encrypt_path(b"hello");
        let blob_id = scl_core::Object::blob(cipher.clone()).id();
        let mut prot = Protection::default();
        prot.wrapped.insert(blob_id, vec![scl_crypto::wrap_dek_for(&dek, &alice_pk)]);
        let pt = decrypt_with(&cipher, &blob_id, &[&prot], &alice_sk, "secret/x").unwrap();
        assert_eq!(&pt[..], b"hello");
        let err = decrypt_with(&cipher, &blob_id, &[&prot], &mallory_sk, "secret/x").unwrap_err();
        assert!(matches!(err, Error::NotAuthorized(_)));
    }

    #[test]
    fn union_wraps_dedups_by_recipient_id() {
        let (_sk_a, pk_a) = scl_crypto::generate_keypair();
        let (_sk_b, pk_b) = scl_crypto::generate_keypair();
        let (_cipher, dek) = scl_crypto::encrypt_path(b"x");
        let wa = scl_crypto::wrap_dek_for(&dek, &pk_a);
        let wa_dup = scl_crypto::wrap_dek_for(&dek, &pk_a);
        let wb = scl_crypto::wrap_dek_for(&dek, &pk_b);
        let u = union_wraps(&[wa.clone()], &[wa_dup, wb]);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].recipient_id, wa.recipient_id);
    }
}
