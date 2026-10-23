//! Credential primitives for `sc-forge`: password hashing, access-token
//! generation and hashing, constant-time comparison. Lives here because
//! RustCrypto (argon2, blake3) and the RNG stay quarantined in this crate.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::sync::OnceLock;

/// Hash `password` with Argon2id and a fresh random salt; returns a PHC string.
pub fn hash_password(password: &str) -> String {
    use rand_core::{OsRng, RngCore};
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).expect("16 bytes is a valid salt length");
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing with default parameters cannot fail")
        .to_string()
}

static DUMMY: OnceLock<String> = OnceLock::new();

/// Compute the dummy hash now. Call once at startup so the first unknown-login
/// attempt does not pay for hashing on top of verifying, which would make it
/// measurably slower than a wrong password for a real account.
pub fn warm_up() {
    DUMMY.get_or_init(|| hash_password("sc-forge-dummy"));
}

/// Verify `password` against a PHC `stored` hash. With `None` (no such account)
/// it still spends one full verification against a fixed dummy hash and returns
/// `false`, so response time does not reveal whether the login exists.
pub fn verify_password(password: &str, stored: Option<&str>) -> bool {
    // An empty or unparsable stored hash (an organization row, a damaged row)
    // takes the same dummy-verification path as a missing account, so it costs
    // the same time and cannot be told apart.
    let real = stored.and_then(|s| PasswordHash::new(s).ok());
    let dummy;
    let (parsed, real_account) = match real {
        Some(p) => (p, true),
        None => {
            dummy = DUMMY.get_or_init(|| hash_password("sc-forge-dummy"));
            (
                PasswordHash::new(dummy).expect("our own hash parses"),
                false,
            )
        }
    };
    let ok = Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();
    ok && real_account
}

/// A fresh access token: 40 lowercase hex characters (the length Gitea issues;
/// clients treat it as opaque) from the OS CSPRNG.
pub fn generate_token() -> String {
    crate::random_hex(20)
}

/// The stored form of an access token: BLAKE3, hex. Tokens are high-entropy
/// random values, so a fast hash is enough and lets lookups be an index probe.
pub fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Constant-time equality: unequal lengths are unequal, equal lengths fold every
/// XOR into one accumulator and never short-circuit.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip_and_rejection() {
        let h = hash_password("correct horse");
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", Some(&h)));
        assert!(!verify_password("correct horsf", Some(&h)));
        assert!(!verify_password("", Some(&h)));
    }

    #[test]
    fn same_password_hashes_differently() {
        assert_ne!(hash_password("pw"), hash_password("pw"));
    }

    #[test]
    fn absent_account_and_garbage_hash_never_verify() {
        assert!(!verify_password("anything", None));
        assert!(!verify_password("anything", Some("not-a-phc-string")));
    }

    #[test]
    fn token_is_40_hex_and_varies() {
        let (a, b) = (generate_token(), generate_token());
        assert_eq!(a.len(), 40);
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        assert_ne!(a, b);
    }

    #[test]
    fn token_hash_is_stable_hex_and_not_the_token() {
        let t = generate_token();
        assert_eq!(hash_token(&t), hash_token(&t));
        assert_eq!(hash_token(&t).len(), 64);
        assert_ne!(hash_token(&t), t);
        assert_ne!(hash_token(&t), hash_token(&generate_token()));
    }

    #[test]
    fn ct_eq_matches_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }
}
