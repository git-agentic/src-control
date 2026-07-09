//! Encrypted-path policy helpers.

use std::collections::BTreeMap;

use scl_core::{FileMode, Object, ObjectId, ProtectPrefix, Protection, WrappedKey};

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

/// Merge two protection policies' prefix rules. Prefixes unite by `prefix`
/// string (rules never disappear — fail-closed, ADR-0025). Within a shared
/// prefix each recipient key is a last-writer-wins register: the higher-epoch
/// entry survives, and an epoch tie with disagreeing states resolves
/// `Revoked` (fail-closed, ADR-0026) — this is what makes `sc revoke` durable
/// against merging a pre-revoke branch.
pub(crate) fn merge_prefixes(a: &[ProtectPrefix], b: &[ProtectPrefix]) -> Vec<ProtectPrefix> {
    use scl_core::RecipientState;
    let mut out: Vec<ProtectPrefix> = Vec::new();
    for p in a.iter().chain(b.iter()) {
        match out.iter_mut().find(|existing| existing.prefix == p.prefix) {
            Some(existing) => {
                for r in &p.recipients {
                    match existing.recipients.iter_mut().find(|e| e.key == r.key) {
                        Some(e) => {
                            if r.epoch > e.epoch
                                || (r.epoch == e.epoch && r.state == RecipientState::Revoked)
                            {
                                e.epoch = r.epoch;
                                e.state = r.state;
                            }
                        }
                        None => existing.recipients.push(r.clone()),
                    }
                }
            }
            None => out.push(p.clone()),
        }
    }
    out
}

/// Union two wrapped-DEK lists: deduped by `recipient_id` (first occurrence
/// wins), then sorted by `recipient_id` for encoding determinism — wrap order
/// inside a `wrapped`-map value feeds the snapshot's canonical encoding (the
/// encoder does not sort `Vec<WrappedKey>`), so equivalent unions must encode
/// identically regardless of argument order. Caveat: first-wins means that when
/// the SAME recipient_id carries different wrap bytes on each side, the
/// surviving bytes still depend on which argument came first.
pub(crate) fn union_wraps(a: &[WrappedKey], b: &[WrappedKey]) -> Vec<WrappedKey> {
    let mut out: Vec<WrappedKey> = Vec::new();
    for w in a.iter().chain(b.iter()) {
        if !out
            .iter()
            .any(|existing| existing.recipient_id == w.recipient_id)
        {
            out.push(w.clone());
        }
    }
    out.sort_by(|x, y| x.recipient_id.cmp(&y.recipient_id));
    out
}

/// Decrypt a protected blob's ciphertext using `identity`, searching the
/// given protection maps (in order) for its wrapped DEKs. Errors:
/// `NotAuthorized(path)` when no wrap unwraps for this identity;
/// `Error::Crypto` when a wrap DOES unwrap but the ciphertext then fails to
/// decrypt — under convergent encryption that combination means corruption
/// (tampered ciphertext or a stale/foreign wrap), not missing access, and the
/// two must not be conflated (cf. `grant_surfaces_tampered_wrap_as_crypto_error_not_unauthorized`).
/// `ProtectedMergeNeedsIdentity(path)` is the CALLER's error when identity is
/// None — this fn requires one.
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
            // A failed unwrap just means this wrap belongs to someone else —
            // keep looking. But once a wrap unwraps, we HAVE the DEK: a decrypt
            // failure past this point is corruption, not authorization, so
            // propagate it (as Error::Crypto) instead of falling through to
            // NotAuthorized.
            let Ok(dek) = scl_crypto::unwrap_dek_with(wrap, identity) else {
                continue;
            };
            return Ok(scl_crypto::decrypt_path(ciphertext, &dek)?);
        }
    }
    Err(Error::NotAuthorized(path.to_string()))
}

/// Convergently encrypt `plaintexts` (path, bytes, mode, rule recipients),
/// wrapping each fresh DEK to its recipients. Returns the ciphertext write-set
/// entries (PROTECTED perms) and fresh wraps keyed by ciphertext blob id.
/// Errors `InvalidArgument` if any file's recipient list is empty: a rule whose
/// every recipient is tombstoned (e.g. crossed revokes merged together) must fail
/// the seal loudly — sealing to nobody mints permanently unreadable ciphertext.
pub(crate) fn encrypt_protected(
    plaintexts: Vec<(String, Vec<u8>, FileMode, Vec<[u8; 32]>)>,
) -> Result<(
    Vec<(String, Vec<u8>, FileMode, u8)>,
    BTreeMap<ObjectId, Vec<WrappedKey>>,
)> {
    // Encrypt protected files; accumulate fresh wrapped DEKs keyed by blob id.
    let mut all: Vec<(String, Vec<u8>, FileMode, u8)> = Vec::new();
    let mut fresh_wrapped: BTreeMap<ObjectId, Vec<WrappedKey>> = BTreeMap::new();
    for (path, bytes, mode, recipients) in plaintexts {
        if recipients.is_empty() {
            return Err(Error::InvalidArgument(format!(
                "{path} is protected but its rule has no granted recipients \
                 (all revoked?); run `sc grant` before committing under this prefix"
            )));
        }
        let (blob_bytes, dek) = scl_crypto::encrypt_path(&bytes);
        // Build the blob object once for its id; `write_tree_with_perms` does
        // the (idempotent) store insert below — no second explicit `put`.
        let blob_id = Object::blob(blob_bytes.clone()).id();
        let wks: Vec<WrappedKey> = recipients
            .iter()
            .map(|pk| scl_crypto::wrap_dek_for(&dek, &scl_crypto::PublicKey::from_bytes(*pk)))
            .collect();
        fresh_wrapped.insert(blob_id, wks);
        all.push((path, blob_bytes, mode, scl_core::PROTECTED));
    }
    Ok((all, fresh_wrapped))
}

/// Prior-wrap reuse: for each (blob_id, recipient_id) already wrapped in
/// `prior`, keep the prior wrap bytes so unchanged content's protection
/// encoding (and thus snapshot ids) stays stable. Mutates `fresh` in place.
pub(crate) fn reuse_prior_wraps(
    fresh: &mut BTreeMap<ObjectId, Vec<WrappedKey>>,
    prior: &BTreeMap<ObjectId, Vec<WrappedKey>>,
) {
    for (blob_id, wks) in fresh.iter_mut() {
        if let Some(prior_wks) = prior.get(blob_id) {
            for wk in wks.iter_mut() {
                if let Some(existing) = prior_wks.iter().find(|p| p.recipient_id == wk.recipient_id)
                {
                    *wk = existing.clone();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prot(prefixes: &[&str]) -> Protection {
        Protection {
            prefixes: prefixes
                .iter()
                .map(|p| ProtectPrefix {
                    prefix: p.to_string(),
                    recipients: vec![],
                })
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

    fn entry(key: u8, epoch: u32, granted: bool) -> scl_core::RecipientEntry {
        scl_core::RecipientEntry {
            key: [key; 32],
            epoch,
            state: if granted {
                scl_core::RecipientState::Granted
            } else {
                scl_core::RecipientState::Revoked
            },
        }
    }

    fn rule(prefix: &str, entries: Vec<scl_core::RecipientEntry>) -> ProtectPrefix {
        ProtectPrefix {
            prefix: prefix.into(),
            recipients: entries,
        }
    }

    #[test]
    fn merge_prefixes_higher_epoch_wins_both_directions() {
        // The ADR-0025 boundary case: ours revoked B at epoch 2, theirs (a
        // pre-revoke branch) still has B granted at epoch 1. Revoke holds —
        // in either argument order.
        let ours = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
        let theirs = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 1, true)])];
        for (a, b) in [(&ours, &theirs), (&theirs, &ours)] {
            let m = merge_prefixes(a, b);
            let r = m.iter().find(|p| p.prefix == "secret/").unwrap();
            assert_eq!(r.granted_keys(), vec![[1; 32]]);
            let b_entry = r.recipients.iter().find(|e| e.key == [2; 32]).unwrap();
            assert_eq!(
                (b_entry.epoch, b_entry.state),
                (2, scl_core::RecipientState::Revoked)
            );
        }
    }

    #[test]
    fn merge_prefixes_regrant_beats_older_tombstone() {
        // B was revoked at epoch 2, then deliberately re-granted at epoch 3 on
        // one side; the other side still carries the epoch-2 tombstone.
        let regranted = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 3, true)])];
        let tombstoned = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
        let m = merge_prefixes(&regranted, &tombstoned);
        let r = m.iter().find(|p| p.prefix == "secret/").unwrap();
        let mut granted = r.granted_keys();
        granted.sort_unstable();
        assert_eq!(granted, vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn merge_prefixes_epoch_tie_resolves_revoked() {
        // Concurrent revoke and re-grant minted the same epoch: fail-closed.
        let revoked = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
        let granted = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, true)])];
        for (a, b) in [(&revoked, &granted), (&granted, &revoked)] {
            let m = merge_prefixes(a, b);
            let r = m.iter().find(|p| p.prefix == "secret/").unwrap();
            assert_eq!(r.granted_keys(), vec![[1; 32]], "tie must resolve Revoked");
        }
    }

    #[test]
    fn merge_prefixes_disjoint_recipients_and_prefixes_compose() {
        let a = vec![rule("secret/", vec![entry(1, 1, true)])];
        let b = vec![
            rule("secret/", vec![entry(2, 1, true)]),
            rule("keys/", vec![entry(3, 1, true)]),
        ];
        let m = merge_prefixes(&a, &b);
        assert_eq!(m.len(), 2);
        let secret = m.iter().find(|p| p.prefix == "secret/").unwrap();
        assert_eq!(secret.recipients.len(), 2);
        assert!(m.iter().any(|p| p.prefix == "keys/"));
    }

    #[test]
    fn decrypt_with_unwraps_for_recipient_and_rejects_stranger() {
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _) = scl_crypto::generate_keypair();
        let (cipher, dek) = scl_crypto::encrypt_path(b"hello");
        let blob_id = scl_core::Object::blob(cipher.clone()).id();
        let mut prot = Protection::default();
        prot.wrapped
            .insert(blob_id, vec![scl_crypto::wrap_dek_for(&dek, &alice_pk)]);
        let pt = decrypt_with(&cipher, &blob_id, &[&prot], &alice_sk, "secret/x").unwrap();
        assert_eq!(&pt[..], b"hello");
        let err = decrypt_with(&cipher, &blob_id, &[&prot], &mallory_sk, "secret/x").unwrap_err();
        assert!(matches!(err, Error::NotAuthorized(_)));
    }

    #[test]
    fn decrypt_with_surfaces_corruption_as_crypto_error_not_unauthorized() {
        // An authorized identity whose wrap unwraps fine, but whose ciphertext
        // was tampered with: this is corruption, not lack of access, and must
        // NOT be reported as NotAuthorized.
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mut cipher, dek) = scl_crypto::encrypt_path(b"hello");
        let blob_id = scl_core::Object::blob(cipher.clone()).id();
        let mut prot = Protection::default();
        prot.wrapped
            .insert(blob_id, vec![scl_crypto::wrap_dek_for(&dek, &alice_pk)]);
        let n = cipher.len();
        cipher[n - 1] ^= 0xFF; // flip one ciphertext byte
        let err = decrypt_with(&cipher, &blob_id, &[&prot], &alice_sk, "secret/x").unwrap_err();
        assert!(
            !matches!(err, Error::NotAuthorized(_)),
            "corruption misreported as NotAuthorized: {err}"
        );
        assert!(
            matches!(err, Error::Crypto(_)),
            "expected Error::Crypto, got: {err}"
        );
    }

    #[test]
    fn union_wraps_dedups_by_recipient_id() {
        let (_sk_a, pk_a) = scl_crypto::generate_keypair();
        let (_sk_b, pk_b) = scl_crypto::generate_keypair();
        let (_cipher, dek) = scl_crypto::encrypt_path(b"x");
        let wa = scl_crypto::wrap_dek_for(&dek, &pk_a);
        let wa_dup = scl_crypto::wrap_dek_for(&dek, &pk_a);
        let wb = scl_crypto::wrap_dek_for(&dek, &pk_b);
        let u = union_wraps(&[wa.clone()], &[wa_dup, wb.clone()]);
        assert_eq!(u.len(), 2);
        // Dedup keeps a's wrap for pk_a (first occurrence wins).
        let kept_a = u
            .iter()
            .find(|w| w.recipient_id == wa.recipient_id)
            .unwrap();
        assert_eq!(kept_a.wrapped_dek, wa.wrapped_dek);

        // Order-independence: equivalent contents (distinct recipients — for
        // the SAME recipient_id with differing wrap bytes, first-wins makes the
        // surviving bytes order-dependent by design) must union to identical
        // output regardless of argument order, so the snapshot encoding is
        // deterministic.
        let ab = union_wraps(&[wa.clone()], &[wb.clone()]);
        let ba = union_wraps(&[wb], &[wa]);
        assert_eq!(ab, ba);
        // And the output is sorted by recipient_id.
        assert!(ab
            .windows(2)
            .all(|w| w[0].recipient_id <= w[1].recipient_id));
    }

    #[test]
    fn encrypt_protected_refuses_empty_recipient_list() {
        let err = encrypt_protected(vec![(
            "secret/x".into(),
            b"v".to_vec(),
            FileMode::FILE,
            vec![],
        )])
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "sealing to nobody must fail loudly, got {err:?}"
        );
        assert!(
            format!("{err}").contains("secret/x"),
            "error must name the path"
        );
    }

    #[test]
    fn merge_prefixes_crossed_revokes_can_empty_a_rule() {
        // Each side revoked a DIFFERENT one of the two recipients: the merged
        // rule has zero granted keys. This is exactly why sealing must guard.
        let a = vec![rule("secret/", vec![entry(1, 2, false), entry(2, 1, true)])];
        let b = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
        let m = merge_prefixes(&a, &b);
        assert!(m[0].granted_keys().is_empty());
    }
}
