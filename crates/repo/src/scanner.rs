//! Secret detection: high-precision token patterns + a Shannon-entropy
//! heuristic. Byte-oriented and UTF-8-lossy — never panics on binary input.

use std::sync::OnceLock;

use regex::RegexSet;

use crate::scanner_patterns::PATTERNS;

/// What kind of detection fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitKind {
    /// A named pattern from `scanner_patterns::PATTERNS`.
    Pattern(&'static str),
    /// A high-entropy token (likely a key/credential).
    Entropy,
}

/// A single detection within a blob, with its 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: HitKind,
    pub line: usize,
}

const B64_MIN_RUN: usize = 20;
const ENTROPY_THRESHOLD: f64 = 4.5;

fn pattern_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        RegexSet::new(PATTERNS.iter().map(|p| p.regex)).expect("scanner patterns must compile")
    })
}

/// Scan `bytes` for secret patterns and high-entropy tokens. `name` is reserved
/// for future per-path rules. Invalid UTF-8 is decoded lossily; never panics.
pub fn scan(_name: &str, bytes: &[u8]) -> Vec<Hit> {
    let text = String::from_utf8_lossy(bytes);
    let set = pattern_set();
    let mut hits = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let lineno = i + 1;
        for idx in set.matches(line).into_iter() {
            hits.push(Hit { rule: HitKind::Pattern(PATTERNS[idx].name), line: lineno });
        }
        if has_high_entropy_run(line) {
            hits.push(Hit { rule: HitKind::Entropy, line: lineno });
        }
    }
    hits
}

/// True if `line` contains a base64-alphabet run of >= B64_MIN_RUN chars whose
/// Shannon entropy exceeds ENTROPY_THRESHOLD bits/char.
fn has_high_entropy_run(line: &str) -> bool {
    let is_tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '=');
    let mut run = String::new();
    let check = |run: &str| run.chars().count() >= B64_MIN_RUN && shannon_entropy(run) > ENTROPY_THRESHOLD;
    for c in line.chars() {
        if is_tok(c) {
            run.push(c);
        } else {
            if check(&run) {
                return true;
            }
            run.clear();
        }
    }
    check(&run)
}

/// Shannon entropy (bits per character) of `s`.
fn shannon_entropy(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0usize) += 1;
    }
    let mut h = 0.0;
    for &c in counts.values() {
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(hits: &[Hit]) -> Vec<&HitKind> {
        hits.iter().map(|h| &h.rule).collect()
    }

    #[test]
    fn detects_aws_and_pem_patterns() {
        let aws = scan("f", b"key = AKIAIOSFODNN7EXAMPLE\n");
        assert!(rules(&aws).contains(&&HitKind::Pattern("aws_access_key")));
        let pem = scan("f", b"-----BEGIN RSA PRIVATE KEY-----\n");
        assert!(rules(&pem).contains(&&HitKind::Pattern("private_key_pem")));
    }

    #[test]
    fn entropy_flags_a_random_base64_token_but_not_prose() {
        // 44-char high-entropy base64 token.
        let token = "Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=";
        let hit = scan("f", format!("secret = {token}\n").as_bytes());
        assert!(rules(&hit).contains(&&HitKind::Entropy), "expected entropy hit, got {hit:?}");
        let prose = scan("f", b"the quick brown fox jumps over the lazy dog repeatedly\n");
        assert!(!rules(&prose).contains(&&HitKind::Entropy), "prose should not flag");
    }

    #[test]
    fn clean_source_has_no_hits() {
        let src = b"fn main() {\n    println!(\"hello, world\");\n}\n";
        assert!(scan("f", src).is_empty());
    }

    #[test]
    fn binary_input_does_not_panic() {
        let bin = [0u8, 159, 146, 150, 255, 254, 0, 1, 2, 3];
        let _ = scan("f", &bin); // must not panic
    }

    #[test]
    fn line_numbers_are_one_based() {
        let body = b"clean line\nkey = AKIAIOSFODNN7EXAMPLE\n";
        let hits = scan("f", body);
        assert!(hits.iter().any(|h| h.line == 2 && h.rule == HitKind::Pattern("aws_access_key")));
    }
}
