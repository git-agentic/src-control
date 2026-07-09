//! Server access tokens (P29): `.sc/serve-tokens.toml` gates `sc serve --http`.
//! Each entry stores a label, the BLAKE3 hash of the raw bearer token (the raw
//! token is never persisted), and a scope. Presence of ≥1 token turns on auth
//! for every connection (loopback included); a matched token's scope drives the
//! connection's read-only flag. Distinct surface from `recipients.toml`.

use scl_core::ObjectId;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::layout::Layout;

/// A token's permission scope. `Ro` behaves like `--read-only` for that
/// connection; `Rw` permits mutating verbs (subject to a server-wide
/// `--read-only` floor).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Ro,
    Rw,
}

/// One stored token: label + `hash = hex(BLAKE3(raw token string))` + scope.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenEntry {
    pub label: String,
    pub hash: String,
    pub scope: Scope,
}

#[derive(Serialize, Deserialize, Default)]
struct TokenFile {
    #[serde(default, rename = "token")]
    tokens: Vec<TokenEntry>,
}

/// Load all tokens (empty when the file is absent — the "no auth" state).
pub fn load(layout: &Layout) -> Result<Vec<TokenEntry>> {
    match std::fs::read_to_string(layout.serve_tokens_path()) {
        Ok(s) => Ok(toml::from_str::<TokenFile>(&s)
            .map_err(|e| Error::BadConfig(format!("bad serve-tokens.toml: {e}")))?
            .tokens),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Error::Io(e)),
    }
}

fn save(layout: &Layout, tokens: &[TokenEntry]) -> Result<()> {
    let file = TokenFile { tokens: tokens.to_vec() };
    let text = toml::to_string(&file).map_err(|e| Error::BadConfig(e.to_string()))?;
    scl_core::fsutil::atomic_write_durable(&layout.serve_tokens_path(), text.as_bytes())?;
    Ok(())
}

/// Generate a fresh `sct-<hex>` token (256-bit) and its stored entry. The raw
/// token is the caller's to print once; only the entry is persisted.
pub fn generate(label: &str, scope: Scope) -> (String, TokenEntry) {
    let raw = format!("sct-{}", scl_crypto::random_hex(32));
    let hash = ObjectId::of(raw.as_bytes()).to_hex();
    (raw, TokenEntry { label: label.to_string(), hash, scope })
}

/// Generate + persist a token, returning the raw value to show once. Errors if
/// the label already exists.
pub fn add(layout: &Layout, label: &str, scope: Scope) -> Result<String> {
    let mut tokens = load(layout)?;
    if tokens.iter().any(|t| t.label == label) {
        return Err(Error::InvalidArgument(format!(
            "serve token label already exists: {label}"
        )));
    }
    let (raw, entry) = generate(label, scope);
    tokens.push(entry);
    save(layout, &tokens)?;
    Ok(raw)
}

/// Remove a token by label; errors if none matched.
pub fn remove(layout: &Layout, label: &str) -> Result<()> {
    let mut tokens = load(layout)?;
    let before = tokens.len();
    tokens.retain(|t| t.label != label);
    if tokens.len() == before {
        return Err(Error::InvalidArgument(format!("no serve token with label: {label}")));
    }
    save(layout, &tokens)
}

/// Constant-time verify a presented raw token against the stored hashes,
/// returning the matched scope or `None`. Iterates ALL tokens without an
/// early return, and compares the 32 hash bytes with a fold-XOR, so timing
/// leaks neither which token matched nor how many leading bytes agreed.
pub fn verify(tokens: &[TokenEntry], presented: &str) -> Option<Scope> {
    let want = ObjectId::of(presented.as_bytes());
    let mut matched: Option<Scope> = None;
    for t in tokens {
        let ok = t
            .hash
            .parse::<ObjectId>()
            .ok()
            .map_or(false, |stored| ct_eq(want.as_bytes(), stored.as_bytes()));
        if ok {
            matched = Some(t.scope);
        }
    }
    matched
}

/// Constant-time equality for equal-length byte slices: fold every XOR into an
/// accumulator, never short-circuit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
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
    use crate::layout::Layout;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-servetokens-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn add_generates_sct_token_and_persists_hash_only() {
        let layout = tmp_layout("add");
        let raw = add(&layout, "ci", Scope::Ro).unwrap();
        assert!(raw.starts_with("sct-"), "raw token is sct-prefixed: {raw}");
        let text = std::fs::read_to_string(layout.serve_tokens_path()).unwrap();
        assert!(!text.contains(&raw), "raw token must NEVER be persisted");
        assert!(text.contains("ci") && text.contains("ro"));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn verify_matches_correct_token_and_returns_scope() {
        let layout = tmp_layout("verify");
        let raw_ro = add(&layout, "reader", Scope::Ro).unwrap();
        let raw_rw = add(&layout, "writer", Scope::Rw).unwrap();
        let tokens = load(&layout).unwrap();
        assert_eq!(verify(&tokens, &raw_ro), Some(Scope::Ro));
        assert_eq!(verify(&tokens, &raw_rw), Some(Scope::Rw));
        assert_eq!(verify(&tokens, "sct-deadbeef"), None, "unknown token rejected");
        assert_eq!(verify(&tokens, ""), None);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn duplicate_label_rejected_and_remove_absent_errors() {
        let layout = tmp_layout("dup");
        add(&layout, "dup", Scope::Ro).unwrap();
        assert!(add(&layout, "dup", Scope::Rw).is_err(), "duplicate label");
        assert!(remove(&layout, "nope").is_err(), "removing an absent label errors");
        remove(&layout, "dup").unwrap();
        assert!(load(&layout).unwrap().is_empty());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn load_absent_file_is_empty() {
        let layout = tmp_layout("absent");
        assert!(load(&layout).unwrap().is_empty());
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
