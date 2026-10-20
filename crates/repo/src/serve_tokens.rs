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

/// One stored token: label + `hash = hex(BLAKE3(raw token string))` + scope +
/// optional expiry. `expires_at` is Unix seconds (UTC); absent means the token
/// never expires, and files written before expiry existed load unchanged.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenEntry {
    pub label: String,
    pub hash: String,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl TokenEntry {
    /// True once `now` (Unix seconds) has reached `expires_at`; the expiry
    /// instant itself is already expired. Never true without an expiry.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }
}

/// Current wall-clock time as Unix seconds (0 if the clock is before 1970).
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
    let file = TokenFile {
        tokens: tokens.to_vec(),
    };
    let text = toml::to_string(&file).map_err(|e| Error::BadConfig(e.to_string()))?;
    scl_core::fsutil::atomic_write_durable(&layout.serve_tokens_path(), text.as_bytes())?;
    Ok(())
}

/// Generate a fresh `sct-<hex>` token (256-bit) and its stored entry. The raw
/// token is the caller's to print once; only the entry is persisted.
pub fn generate(label: &str, scope: Scope, expires_at: Option<u64>) -> (String, TokenEntry) {
    let raw = format!("sct-{}", scl_crypto::random_hex(32));
    let hash = ObjectId::of(raw.as_bytes()).to_hex();
    (
        raw,
        TokenEntry {
            label: label.to_string(),
            hash,
            scope,
            expires_at,
        },
    )
}

/// Generate + persist a token, returning the raw value to show once. Errors if
/// the label already exists.
pub fn add(layout: &Layout, label: &str, scope: Scope) -> Result<String> {
    add_expiring(layout, label, scope, None)
}

/// [`add`] with an optional expiry (Unix seconds). Expired entries stay in the
/// file (see ADR-0040); `verify` just refuses them.
pub fn add_expiring(
    layout: &Layout,
    label: &str,
    scope: Scope,
    expires_at: Option<u64>,
) -> Result<String> {
    let mut tokens = load(layout)?;
    if tokens.iter().any(|t| t.label == label) {
        return Err(Error::InvalidArgument(format!(
            "serve token label already exists: {label}"
        )));
    }
    let (raw, entry) = generate(label, scope, expires_at);
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
        return Err(Error::InvalidArgument(format!(
            "no serve token with label: {label}"
        )));
    }
    save(layout, &tokens)
}

/// Replace the secret of the token labelled `label` with a fresh one, keeping
/// its label, scope and absolute `expires_at`; the old secret stops verifying
/// at once. Returns the new raw token (print once). An already-expired token
/// is refused: rotating would mint a dead token, so `remove` + `add` instead
/// (that is how an operator extends or resets an expiry).
pub fn rotate(layout: &Layout, label: &str, now: u64) -> Result<String> {
    let mut tokens = load(layout)?;
    let Some(slot) = tokens.iter_mut().find(|t| t.label == label) else {
        return Err(Error::InvalidArgument(format!(
            "no serve token with label: {label}"
        )));
    };
    if slot.is_expired(now) {
        return Err(Error::InvalidArgument(format!(
            "serve token '{label}' is expired; remove it and add a new one"
        )));
    }
    let (raw, fresh) = generate(label, slot.scope, slot.expires_at);
    *slot = fresh;
    save(layout, &tokens)?;
    Ok(raw)
}

/// Constant-time verify a presented raw token against the stored hashes at
/// `now` (Unix seconds), returning the matched scope or `None`. An expired
/// token is indistinguishable from an unknown one. Iterates ALL tokens
/// without an early return, and compares the 32 hash bytes with a fold-XOR,
/// so timing leaks neither which token matched nor how many leading bytes
/// agreed.
pub fn verify(tokens: &[TokenEntry], presented: &str, now: u64) -> Option<Scope> {
    let want = ObjectId::of(presented.as_bytes());
    let mut matched: Option<Scope> = None;
    for t in tokens {
        let ok = t
            .hash
            .parse::<ObjectId>()
            .ok()
            .is_some_and(|stored| ct_eq(want.as_bytes(), stored.as_bytes()));
        if ok && !t.is_expired(now) {
            matched = Some(t.scope);
        }
    }
    matched
}

/// Parse an `--expires` value into Unix seconds, relative to `now`. Accepts a
/// duration (`90s`, `30m`, `12h`, `7d`, `2w`) or a UTC date (`YYYY-MM-DD`,
/// meaning 00:00:00 UTC that day). Rejects anything not strictly in the future.
pub fn parse_expiry(spec: &str, now: u64) -> Result<u64> {
    let bad = || {
        Error::InvalidArgument(format!(
            "bad --expires '{spec}': use e.g. 30d, 12h, or 2030-01-31"
        ))
    };
    let at = if let Some((y, m, d)) = parse_date(spec) {
        let days = days_from_civil(y, m, d);
        // Round-trip rejects impossible dates such as 2025-02-30.
        if civil_from_days(days) != (y, m, d) {
            return Err(bad());
        }
        u64::try_from(days)
            .ok()
            .and_then(|d| d.checked_mul(86_400))
            .ok_or_else(bad)?
    } else {
        let unit = spec.chars().last().ok_or_else(bad)?;
        let secs: u64 = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(bad()),
        };
        let n: u64 = spec[..spec.len() - 1].parse().map_err(|_| bad())?;
        n.checked_mul(secs)
            .and_then(|s| s.checked_add(now))
            .ok_or_else(bad)?
    };
    if at <= now {
        return Err(Error::InvalidArgument(format!(
            "--expires '{spec}' is not in the future"
        )));
    }
    // TOML integers are signed 64-bit; a larger value would write an unreadable file.
    if i64::try_from(at).is_err() {
        return Err(bad());
    }
    Ok(at)
}

/// Render Unix seconds as `YYYY-MM-DD HH:MM:SSZ` (UTC) for `token list`.
pub fn format_time(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let r = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        r / 3_600,
        r % 3_600 / 60,
        r % 60
    )
}

fn parse_date(s: &str) -> Option<(i64, u32, u32)> {
    let mut it = s.split('-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    Some((y.parse().ok()?, m.parse().ok()?, d.parse().ok()?))
}

// Howard Hinnant's civil-date algorithms (proleptic Gregorian, days since 1970-01-01).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * i64::from((m + 9) % 12) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
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
        let root =
            std::env::temp_dir().join(format!("scl-servetokens-{tag}-{}", std::process::id()));
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
        let t0 = now();
        assert_eq!(verify(&tokens, &raw_ro, t0), Some(Scope::Ro));
        assert_eq!(verify(&tokens, &raw_rw, t0), Some(Scope::Rw));
        assert_eq!(
            verify(&tokens, "sct-deadbeef", t0),
            None,
            "unknown token rejected"
        );
        assert_eq!(verify(&tokens, "", t0), None);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn duplicate_label_rejected_and_remove_absent_errors() {
        let layout = tmp_layout("dup");
        add(&layout, "dup", Scope::Ro).unwrap();
        assert!(add(&layout, "dup", Scope::Rw).is_err(), "duplicate label");
        assert!(
            remove(&layout, "nope").is_err(),
            "removing an absent label errors"
        );
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

    #[test]
    fn expiry_boundary_and_unknown_look_identical() {
        let layout = tmp_layout("expiry");
        let raw = add_expiring(&layout, "e", Scope::Rw, Some(1_000)).unwrap();
        let forever = add(&layout, "f", Scope::Ro).unwrap();
        let tokens = load(&layout).unwrap();
        assert_eq!(verify(&tokens, &raw, 999), Some(Scope::Rw), "valid before");
        assert_eq!(verify(&tokens, &raw, 1_000), None, "expired AT the instant");
        assert_eq!(verify(&tokens, &raw, 1_001), None);
        assert_eq!(verify(&tokens, "sct-unknown", 1_001), None);
        assert_eq!(verify(&tokens, &forever, u64::MAX), Some(Scope::Ro));
        // An expired entry still counts as configured, so auth stays mandatory.
        assert_eq!(tokens.len(), 2);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn file_without_expires_field_loads_and_never_writes_it() {
        let layout = tmp_layout("legacy");
        let hash = ObjectId::of(b"sct-old").to_hex();
        std::fs::write(
            layout.serve_tokens_path(),
            format!("[[token]]\nlabel = \"old\"\nhash = \"{hash}\"\nscope = \"ro\"\n"),
        )
        .unwrap();
        let tokens = load(&layout).unwrap();
        assert_eq!(tokens[0].expires_at, None);
        assert_eq!(verify(&tokens, "sct-old", u64::MAX), Some(Scope::Ro));
        add(&layout, "new", Scope::Rw).unwrap();
        let text = std::fs::read_to_string(layout.serve_tokens_path()).unwrap();
        assert!(
            !text.contains("expires_at"),
            "no-expiry stays absent: {text}"
        );
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn rotate_swaps_secret_keeps_label_scope_expiry() {
        let layout = tmp_layout("rotate");
        let old = add_expiring(&layout, "ci", Scope::Rw, Some(5_000)).unwrap();
        add(&layout, "other", Scope::Ro).unwrap();
        let new = rotate(&layout, "ci", 100).unwrap();
        assert_ne!(old, new);
        let tokens = load(&layout).unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(verify(&tokens, &old, 100), None, "old secret dead");
        assert_eq!(verify(&tokens, &new, 100), Some(Scope::Rw));
        let e = tokens.iter().find(|t| t.label == "ci").unwrap();
        assert_eq!(e.expires_at, Some(5_000), "expiry carried over");
        assert!(rotate(&layout, "nope", 100).is_err());
        assert!(rotate(&layout, "ci", 5_000).is_err(), "expired is refused");
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn parse_expiry_durations_dates_and_rejects() {
        assert_eq!(parse_expiry("90s", 10).unwrap(), 100);
        assert_eq!(parse_expiry("2w", 0).unwrap(), 1_209_600);
        assert_eq!(parse_expiry("1d", 5).unwrap(), 86_405);
        assert_eq!(parse_expiry("1970-01-02", 0).unwrap(), 86_400);
        assert_eq!(parse_expiry("2024-02-29", 0).unwrap(), 1_709_164_800);
        for bad in [
            "",
            "d",
            "5",
            "5x",
            "-1d",
            "2025-02-30",
            "2025-13-01",
            "2025-1-1",
            "99999999999999999999d",
            "10000000000000000000s",
            "9223372036854775808s",
        ] {
            assert!(parse_expiry(bad, 0).is_err(), "{bad}");
        }
        assert!(parse_expiry("1970-01-01", 0).is_err(), "not in the future");
        assert!(
            parse_expiry("2020-01-01", 2_000_000_000).is_err(),
            "past date"
        );
        assert_eq!(format_time(1_709_164_800), "2024-02-29 00:00:00Z");
        assert_eq!(format_time(86_399), "1970-01-01 23:59:59Z");
    }
}
