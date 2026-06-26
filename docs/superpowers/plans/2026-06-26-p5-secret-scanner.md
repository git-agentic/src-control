# P5 — Accidental-Plaintext Secret Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A commit-time scanner that hard-rejects committing files containing plaintext secrets (matched patterns or high-entropy tokens), with a hash-scoped allowlist and a read-only `sc scan` preview.

**Architecture:** A pure detection module (`scl-repo::scanner` + compile-time `scanner_patterns`) does pattern (`RegexSet`) + Shannon-entropy detection per blob. `Repo::scan_worktree` skips allowlisted blob hashes and collects findings; `Repo::commit` runs it before `write_tree` and errors with `Error::SecretDetected` on any finding. `sc scan` previews; `sc commit` hard-fails.

**Tech Stack:** Rust 2021; reuses `scl-repo`/`scl-core`; new deps `regex`, `toml`, `serde` (in `scl-repo` only).

**Source spec:** `docs/superpowers/specs/2026-06-26-p5-secret-scanner-design.md` · **ADR:** 0017 (firm to Accepted at the end).

## Global Constraints

- New dependencies go in `crates/repo/Cargo.toml` only — **never** add `regex`/`toml`/`serde` to `crates/core`. Pin latest stable via `cargo add`.
- The scanner runs only on **plaintext working-tree file bytes**; it never scans `Secret` registry objects.
- **No override flag** — a detected secret hard-fails the commit. The only escapes are removing the secret or allowlisting the exact blob hash.
- Allowlist is hash-scoped to exact 64-hex `ObjectId`s in `.sc/scanner-allowlist.toml`.
- Every new behavior ships with a test (project convention).

---

## Execution prerequisites

- Branch off `main`: `git checkout -b p5-secret-scanner`. Baseline-commit the spec+plan.
- Run `cargo test -p scl-repo` after each task; full `cargo test` + `cargo clippy --workspace --all-targets` at the end.

## File structure

**Create:**
- `crates/repo/src/scanner.rs` — detection (`scan`), `Hit`/`HitKind`, `Allowlist`, `ScanReport`/`Finding`.
- `crates/repo/src/scanner_patterns.rs` — `const PATTERNS`.

**Modify:**
- `crates/repo/Cargo.toml` — add `regex`, `toml`, `serde`.
- `crates/repo/src/lib.rs` — declare modules; re-export `ScanReport`.
- `crates/repo/src/error.rs` — add `SecretDetected(ScanReport)`.
- `crates/repo/src/repo.rs` — `scan_files`/`scan_worktree`; scan in `commit`.
- `crates/cli/src/main.rs` — `sc scan`; `commit` rejection rendering.
- `docs/adr/0017-secret-scanner.md`, `docs/adr/README.md` — Proposed → Accepted.

---

## Task 1: Detection core (`scanner` + patterns)

**Files:**
- Modify: `crates/repo/Cargo.toml`
- Create: `crates/repo/src/scanner_patterns.rs`, `crates/repo/src/scanner.rs`
- Modify: `crates/repo/src/lib.rs`

**Interfaces:**
- Produces: `scanner::scan(name: &str, bytes: &[u8]) -> Vec<scanner::Hit>`; `Hit { rule: HitKind, line: usize }`; `HitKind { Pattern(&'static str), Entropy }`; `scanner_patterns::PATTERNS: &[Pattern { name, regex, description }]`.

- [ ] **Step 1: Add the regex dependency**

In `crates/repo/Cargo.toml` under `[dependencies]` add:

```toml
regex = "1"
```

- [ ] **Step 2: Create the pattern set**

Create `crates/repo/src/scanner_patterns.rs`:

```rust
//! Compile-time secret-detection patterns. Reviewed at PR time, never loaded at
//! runtime. High precision over recall — the entropy detector handles recall.

/// One detection pattern.
pub struct Pattern {
    pub name: &'static str,
    pub regex: &'static str,
    pub description: &'static str,
}

/// The active pattern set. Each regex is high-precision (low false-positive).
pub const PATTERNS: &[Pattern] = &[
    Pattern { name: "github_pat", regex: r"gh[posr]_[A-Za-z0-9_]{36,}", description: "GitHub personal access token" },
    Pattern { name: "aws_access_key", regex: r"AKIA[0-9A-Z]{16}", description: "AWS access key id" },
    Pattern { name: "anthropic_api_key", regex: r"sk-ant-(?:api|admin)[A-Za-z0-9_-]{20,}", description: "Anthropic API key" },
    Pattern { name: "openai_api_key", regex: r"sk-(?:proj-)?[A-Za-z0-9]{40,}", description: "OpenAI API key" },
    Pattern { name: "stripe_live", regex: r"(?:sk|pk)_live_[A-Za-z0-9]{20,}", description: "Stripe live key" },
    Pattern { name: "gcp_service_account", regex: r#""type"\s*:\s*"service_account""#, description: "GCP service-account JSON marker" },
    Pattern { name: "private_key_pem", regex: r"-----BEGIN [A-Z ]*PRIVATE KEY-----", description: "PEM private-key header" },
];
```

- [ ] **Step 3: Create the scanner with detection + tests**

Create `crates/repo/src/scanner.rs` (allowlist/report come in Task 2; this task is detection only):

```rust
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
    let mut check = |run: &str| run.chars().count() >= B64_MIN_RUN && shannon_entropy(run) > ENTROPY_THRESHOLD;
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
```

- [ ] **Step 4: Declare the modules**

In `crates/repo/src/lib.rs`, add with the other `pub mod` lines:

```rust
pub mod scanner;
pub mod scanner_patterns;
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p scl-repo scanner`
Expected: PASS (5 detection tests). If a pattern regex fails to compile, `pattern_set()` panics on first use — fix the regex.

- [ ] **Step 6: Commit**

```bash
git add crates/repo/Cargo.toml crates/repo/src/scanner.rs crates/repo/src/scanner_patterns.rs crates/repo/src/lib.rs
git commit -m "feat(repo): secret-detection scanner (patterns + entropy)"
```

---

## Task 2: Allowlist, report, and `commit` integration

**Files:**
- Modify: `crates/repo/Cargo.toml`, `crates/repo/src/scanner.rs`, `crates/repo/src/error.rs`, `crates/repo/src/repo.rs`, `crates/repo/src/lib.rs`

**Interfaces:**
- Consumes: `scanner::scan`, `scanner::Hit`, `scanner::HitKind` (Task 1); `worktree::read_worktree` → `Vec<(String, Vec<u8>, FileMode)>`; `scl_core::Object::blob(bytes).id() -> ObjectId`; `ObjectId::from_str`.
- Produces: `scanner::Allowlist::{load(&Path)->Result<Allowlist>, is_allowed(&ObjectId)->bool}`; `scanner::Finding { path: String, rule: String, blob_id: ObjectId, line: usize }`; `scanner::ScanReport { findings: Vec<Finding> }` with `is_empty()` + `Display`; `Error::SecretDetected(ScanReport)`; `Repo::scan_files(&[(String,Vec<u8>,FileMode)]) -> Result<ScanReport>`; `Repo::scan_worktree() -> Result<ScanReport>`.

- [ ] **Step 1: Add toml + serde deps**

In `crates/repo/Cargo.toml` `[dependencies]` add:

```toml
toml = "0.8"
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 2: Add Allowlist + ScanReport to `scanner.rs`**

Append to `crates/repo/src/scanner.rs`:

```rust
use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

use scl_core::ObjectId;

use crate::error::{Error, Result};

/// Hash-scoped allowlist: exact blob `ObjectId`s exempt from scanning.
#[derive(Default)]
pub struct Allowlist {
    ids: HashSet<ObjectId>,
}

#[derive(serde::Deserialize, Default)]
struct AllowlistFile {
    #[serde(default)]
    allow: Vec<AllowEntry>,
}

#[derive(serde::Deserialize)]
struct AllowEntry {
    blob: String,
    #[allow(dead_code)]
    #[serde(default)]
    note: Option<String>,
}

impl Allowlist {
    /// Load from `.sc/scanner-allowlist.toml`. Missing file => empty allowlist.
    pub fn load(path: &Path) -> Result<Allowlist> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Allowlist::default()),
            Err(e) => return Err(e.into()),
        };
        let parsed: AllowlistFile =
            toml::from_str(&text).map_err(|e| Error::BadRef(format!("bad scanner-allowlist.toml: {e}")))?;
        let mut ids = HashSet::new();
        for entry in parsed.allow {
            let id = ObjectId::from_str(entry.blob.trim())
                .map_err(|_| Error::BadRef(format!("bad blob id in allowlist: {}", entry.blob)))?;
            ids.insert(id);
        }
        Ok(Allowlist { ids })
    }

    pub fn is_allowed(&self, id: &ObjectId) -> bool {
        self.ids.contains(id)
    }
}

/// One scan finding tied to a working-tree path and the offending blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub rule: String,
    pub blob_id: ObjectId,
    pub line: usize,
}

/// The result of scanning a working tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

impl std::fmt::Display for ScanReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for fd in &self.findings {
            writeln!(f, "{}:{}  {}  blob {}", fd.path, fd.line, fd.rule, fd.blob_id.to_hex())?;
        }
        if !self.findings.is_empty() {
            writeln!(
                f,
                "secret(s) detected; remove them, commit via `sc secret`, or allowlist the blob hash(es) in .sc/scanner-allowlist.toml"
            )?;
        }
        Ok(())
    }
}

/// Convert a `HitKind` into the report's rule string.
pub(crate) fn rule_label(kind: &HitKind) -> String {
    match kind {
        HitKind::Pattern(name) => format!("pattern:{name}"),
        HitKind::Entropy => "entropy".to_string(),
    }
}
```

- [ ] **Step 3: Add the `SecretDetected` error variant**

In `crates/repo/src/error.rs`, add to the `Error` enum (before the `#[from]` variants):

```rust
    #[error("{0}")]
    SecretDetected(crate::scanner::ScanReport),
```

- [ ] **Step 4: Add the driver and wire into `commit`**

In `crates/repo/src/repo.rs`, add `Repo` methods (near `status`):

```rust
    /// Scan a set of working-tree files for plaintext secrets, skipping any blob
    /// whose content hash is in `.sc/scanner-allowlist.toml`.
    pub fn scan_files(
        &self,
        files: &[(String, Vec<u8>, scl_core::FileMode)],
    ) -> Result<crate::scanner::ScanReport> {
        let allow =
            crate::scanner::Allowlist::load(&self.layout.dot_sc.join("scanner-allowlist.toml"))?;
        let mut findings = Vec::new();
        for (path, bytes, _mode) in files {
            let id = Object::blob(bytes.clone()).id();
            if allow.is_allowed(&id) {
                continue;
            }
            for hit in crate::scanner::scan(path, bytes) {
                findings.push(crate::scanner::Finding {
                    path: path.clone(),
                    rule: crate::scanner::rule_label(&hit.rule),
                    blob_id: id,
                    line: hit.line,
                });
            }
        }
        Ok(crate::scanner::ScanReport { findings })
    }

    /// Scan the current working tree for plaintext secrets (read-only).
    pub fn scan_worktree(&self) -> Result<crate::scanner::ScanReport> {
        let files = worktree::read_worktree(&self.layout)?;
        self.scan_files(&files)
    }
```

Then modify `commit` to scan before writing. Replace the first two lines of `commit`:

```rust
    pub fn commit(&self, author: &str, message: &str) -> Result<ObjectId> {
        let files = worktree::read_worktree(&self.layout)?;
        let report = self.scan_files(&files)?;
        if !report.is_empty() {
            return Err(Error::SecretDetected(report));
        }
        let root = self.vfs.write_tree(&files)?;
        // ... unchanged: tip / merge_head / secrets / parents / commit_snapshot / clear ...
```

(Keep the rest of `commit` exactly as it is now.)

- [ ] **Step 5: Re-export `ScanReport`**

In `crates/repo/src/lib.rs`, add:

```rust
pub use scanner::ScanReport;
```

- [ ] **Step 6: Add tests**

Add to the `tests` module in `crates/repo/src/repo.rs`:

```rust
    #[test]
    fn commit_rejects_a_plaintext_secret_and_writes_nothing() {
        let root = tmp_root("scan-reject");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("clean.txt"), b"hello").unwrap();
        std::fs::write(root.join("creds.txt"), b"aws = AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let err = repo.commit("me", "leak").unwrap_err();
        assert!(matches!(err, Error::SecretDetected(_)), "got {err:?}");
        // Nothing committed: the branch is still unborn.
        assert_eq!(repo.head_tip().unwrap(), None);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn allowlisted_blob_hash_lets_commit_through() {
        let root = tmp_root("scan-allow");
        let repo = Repo::init(&root).unwrap();
        let secret = b"aws = AKIAIOSFODNN7EXAMPLE\n";
        std::fs::write(root.join("creds.txt"), secret).unwrap();
        // Compute the blob hash the scanner will object to.
        let id = scl_core::Object::blob(secret.to_vec()).id();
        std::fs::create_dir_all(&repo.layout().dot_sc).unwrap();
        std::fs::write(
            repo.layout().dot_sc.join("scanner-allowlist.toml"),
            format!("[[allow]]\nblob = \"{}\"\nnote = \"test fixture\"\n", id.to_hex()),
        )
        .unwrap();
        // Now the commit succeeds.
        let cid = repo.commit("me", "allowed").unwrap();
        assert!(repo.head_tip().unwrap() == Some(cid));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn clean_tree_commits_normally() {
        let root = tmp_root("scan-clean");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"just some text\n").unwrap();
        assert!(repo.commit("me", "ok").is_ok());
        let rep = repo.scan_worktree().unwrap();
        assert!(rep.is_empty());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
```

- [ ] **Step 7: Run tests and commit**

Run: `cargo test -p scl-repo`
Expected: PASS (existing + scanner detection + 3 new repo tests). The CLI won't compile against a new error variant only if it matches exhaustively — it uses `anyhow`, so it still builds; full workspace build is fixed in Task 3 anyway. Scope here: `cargo test -p scl-repo`.

```bash
git add crates/repo/Cargo.toml crates/repo/src/scanner.rs crates/repo/src/error.rs crates/repo/src/repo.rs crates/repo/src/lib.rs
git commit -m "feat(repo): allowlist + scan-on-commit (reject plaintext secrets)"
```

---

## Task 3: CLI `sc scan` + commit rejection + ADR

**Files:**
- Modify: `crates/cli/src/main.rs`, `docs/adr/0017-secret-scanner.md`, `docs/adr/README.md`

**Interfaces:**
- Consumes: `Repo::scan_worktree() -> Result<ScanReport>`; `Repo::commit` returning `Err(scl_repo::Error::SecretDetected(report))`; `ScanReport: Display`.

- [ ] **Step 1: Add the `Scan` subcommand**

In `crates/cli/src/main.rs`, add to the `Cmd` enum:

```rust
    /// Scan the working tree for plaintext secrets without committing.
    Scan,
```

Add the match arm in `main`:

```rust
        Cmd::Scan => run_scan(),
```

- [ ] **Step 2: Implement `run_scan` and make `commit` reject cleanly**

Add `run_scan` to `crates/cli/src/main.rs`:

```rust
fn run_scan() -> Result<()> {
    let repo = open_repo()?;
    let report = repo.scan_worktree()?;
    if report.is_empty() {
        println!("scan clean (no secrets detected)");
        return Ok(());
    }
    print!("{report}");
    std::process::exit(1);
}
```

Update the commit handler (`run_commit`) to render a `SecretDetected` rejection and exit non-zero. Replace its body:

```rust
fn run_commit(author: &str, message: &str) -> Result<()> {
    let repo = open_repo()?;
    match repo.commit(author, message) {
        Ok(id) => {
            println!("committed {}", id.short());
            Ok(())
        }
        Err(scl_repo::Error::SecretDetected(report)) => {
            eprint!("{report}");
            std::process::exit(1);
        }
        Err(e) => Err(e.into()),
    }
}
```

(If `run_commit` has a different current shape, preserve its signature and just add the `SecretDetected` match arm + keep the `Ok`/other-error behavior.)

- [ ] **Step 3: Build, run the suite, smoke-test**

Run:
```bash
cargo test
cargo clippy --workspace --all-targets
```
Expected: all green; clippy clean. Then a manual smoke test:
```bash
sc=/Users/tonibergholm/Developer/claude/src-control/target/debug/sc
cargo build --bin sc
cd "$(mktemp -d)"
"$sc" init
printf 'aws = AKIAIOSFODNN7EXAMPLE\n' > creds.txt
"$sc" scan; echo "scan exit: $?"          # expect findings + exit 1
"$sc" commit -m leak; echo "commit exit: $?"   # expect rejection + exit 1
# allowlist it
HASH=$("$sc" scan | grep -o 'blob [0-9a-f]*' | head -1 | awk '{print $2}')
mkdir -p .sc; printf '[[allow]]\nblob = "%s"\n' "$HASH" > .sc/scanner-allowlist.toml
"$sc" commit -m allowed; echo "commit exit: $?"   # expect success + exit 0
```
Expected: scan exits 1 with the finding; commit exits 1 (rejected); after allowlisting, commit succeeds (exit 0).

- [ ] **Step 4: Firm ADR-0017**

In `docs/adr/0017-secret-scanner.md`, change `**Status:** Proposed` to `**Status:** Accepted`, and append under Decision:

```markdown
**As built (P5):** the scanner runs in `scl-repo` on every working-tree file at
commit time (`Repo::commit` → `scan_files` before `write_tree`); `sc scan`
previews and exits non-zero on findings; detection is a compile-time `RegexSet`
+ a Shannon-entropy pass (base64 runs ≥ 20 chars, > 4.5 bits/char); the allowlist
is hash-scoped in `.sc/scanner-allowlist.toml`. Encrypted-path bypass is a P7
interaction (not built here).
```

Update `docs/adr/README.md` to mark ADR-0017 Accepted.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/main.rs docs/adr/0017-secret-scanner.md docs/adr/README.md
git commit -m "feat(cli): sc scan + commit rejects plaintext secrets; accept ADR-0017"
```

---

## Done criteria

- `cargo test` green across the workspace; `cargo clippy --workspace --all-targets` clean.
- `sc commit` hard-fails (exit non-zero) when a working-tree file contains a matched pattern or high-entropy token; nothing is written.
- Allowlisting the blob hash in `.sc/scanner-allowlist.toml` lets the same commit through.
- `sc scan` previews findings and exits non-zero when any exist, `0` when clean.
- Phase 1 `sc demo`, Phase 2 `sc secret-demo`, Phase 3/4 repo flows still pass (their fixtures contain no matched secrets).
- ADR-0017 is Accepted.
