# P29 — sc+http access control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only mode, a fail-closed non-loopback bind, and dep-free bearer-token auth to `sc serve --http`, closing the security audit's remaining unauthenticated-server High.

**Architecture:** Three composed gates on the P26 sc+http server: (1) a fail-closed bind check in `serve_http`; (2) bearer-token auth verified at the HTTP opening in `handle_http_connection` before the `200`/wire handoff; (3) a per-connection `read_only` flag threaded into a new `wire::serve_with_policy` that rejects mutating verbs before any store write. Tokens live in `.sc/serve-tokens.toml` as `{label, hash, scope}`; the client presents the raw token via `SC_HTTP_TOKEN`.

**Tech Stack:** Rust (stable, edition 2021). Reuses `scl_core::ObjectId::of` (BLAKE3) for token hashing, `scl-crypto`'s `OsRng` for token generation, `toml`+`serde` for config (the `remote.rs` pattern). No new dependency; no TLS.

**Spec:** `docs/superpowers/specs/2026-07-09-p29-sc-http-access-control-design.md`. **ADR:** 0040 (Proposed).

## Global Constraints

- **Security-only phase**; no new feature axis beyond access control.
- **NO new dependency.** Token hash = `scl_core::ObjectId::of(raw_token.as_bytes()).to_hex()` (that IS BLAKE3 — reuse it). Token randomness via a new `scl_crypto::random_hex` (OsRng already a crypto dep — RNG stays quarantined in `crates/crypto`). Constant-time compare is a std fold-XOR. **NO TLS.**
- **Wire format unchanged except one new error code** `EC_READONLY = 5` (append; do NOT renumber `EC_NOT_A_REPO=1`/`EC_NON_FAST_FORWARD=2`/`EC_NOT_FOUND=3`/`EC_PROTOCOL=4`/`EC_OTHER=255`). `PROTOCOL_VERSION` stays **3**.
- **ssh `--stdio` path is UNCHANGED.** `wire::serve` stays a thin wrapper delegating to `wire::serve_with_policy(root, r, w, read_only=false)`, so the ~10 existing callers (stdio transport, sync, tests) don't change.
- **Every existing P26 sc+http test stays green** — the no-auth, no-read-only default path is unchanged.
- **The audit repro becomes pinned regression tests:** an unauthenticated sc+http server accepting arbitrary read+write (now gated by tokens), and a silent non-loopback bind (now fail-closed).
- `.sc/serve-tokens.toml` is `.sc/` persistent config, like `recipients.toml`. The raw token is NEVER persisted (only its hash).
- **This phase SHIPS a new demo** `demo/run_http_auth_demo.sh` (unlike P28).
- Per-crate `thiserror` enums; CLI uses `anyhow`; every public type/fn gets a doc comment explaining intent. Tests live in `#[cfg(test)] mod tests` next to the code.

---

### Task 1: Token store module + crypto RNG helper

**Files:**
- Modify: `crates/crypto/src/lib.rs` (add `random_hex`)
- Create: `crates/repo/src/serve_tokens.rs`
- Modify: `crates/repo/src/lib.rs` (add `pub mod serve_tokens;`)
- Modify: `crates/repo/src/layout.rs` (add `serve_tokens_path`)
- Modify: `crates/repo/src/error.rs` (add `ReadOnly` used in Task 3 — add it now so the enum is stable)

**Interfaces:**
- Consumes: `scl_core::ObjectId::of`, `scl_core::fsutil::atomic_write_durable`, `crate::layout::Layout`, `crate::error::{Error, Result}`.
- Produces: `scl_crypto::random_hex(n: usize) -> String`; `serve_tokens::{Scope, TokenEntry, load, add, remove, verify}`; `Layout::serve_tokens_path`; `Error::ReadOnly`.

- [ ] **Step 1: Write the failing test** for the crypto RNG helper (`crates/crypto/src/lib.rs`, in the crate's `#[cfg(test)] mod tests` — add one if absent):

```rust
#[test]
fn random_hex_is_right_length_and_varies() {
    let a = crate::random_hex(32);
    let b = crate::random_hex(32);
    assert_eq!(a.len(), 64, "32 bytes -> 64 hex chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b, "two draws must differ (probabilistically certain)");
}
```

- [ ] **Step 2: Run it to confirm it fails** — `cargo test -p scl-crypto random_hex_is_right_length_and_varies` → FAIL (`random_hex` not found).

- [ ] **Step 3: Implement `random_hex`** in `crates/crypto/src/lib.rs`:

```rust
/// Generate `n` cryptographically-random bytes from the OS CSPRNG, rendered as
/// lowercase hex. Lives here because the RNG (`rand_core`/`OsRng`) is quarantined
/// to this crate; callers outside `crates/crypto` get randomness through this
/// helper without taking a second RNG dependency.
pub fn random_hex(n: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}
```

- [ ] **Step 4: Run it to confirm it passes** — `cargo test -p scl-crypto random_hex_is_right_length_and_varies` → PASS.

- [ ] **Step 5: Add `serve_tokens_path` to `Layout`** (`crates/repo/src/layout.rs`, beside `signatures_path`):

```rust
/// `.sc/serve-tokens.toml` — server access-control tokens (P29): each entry is
/// `{label, hash = BLAKE3(raw token), scope}`. Presence of ≥1 entry turns on
/// bearer auth for `sc serve --http`. Distinct from `recipients.toml`
/// (encryption/signing trust); this is server access control.
pub fn serve_tokens_path(&self) -> std::path::PathBuf {
    self.dot_sc.join("serve-tokens.toml")
}
```

- [ ] **Step 6: Add `Error::ReadOnly`** to `crates/repo/src/error.rs` (used by the wire gate in Task 3; adding now keeps the enum stable across tasks):

```rust
    /// The server rejected a mutating verb because the connection is read-only
    /// (`--read-only` or an `ro`-scope token). P29.
    #[error("server is read-only")]
    ReadOnly,
```

- [ ] **Step 7: Write the failing tests** for the token store (`crates/repo/src/serve_tokens.rs`, in a `#[cfg(test)] mod tests`). Create the file with only the test module first so it compiles-fails on the missing items:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Layout;

    fn tmp_layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        (dir, layout)
    }

    #[test]
    fn add_generates_sct_token_and_persists_hash_only() {
        let (_d, layout) = tmp_layout();
        let raw = add(&layout, "ci", Scope::Ro).unwrap();
        assert!(raw.starts_with("sct-"), "raw token is sct-prefixed: {raw}");
        let text = std::fs::read_to_string(layout.serve_tokens_path()).unwrap();
        assert!(!text.contains(&raw), "raw token must NEVER be persisted");
        assert!(text.contains("ci") && text.contains("ro"));
    }

    #[test]
    fn verify_matches_correct_token_and_returns_scope() {
        let (_d, layout) = tmp_layout();
        let raw_ro = add(&layout, "reader", Scope::Ro).unwrap();
        let raw_rw = add(&layout, "writer", Scope::Rw).unwrap();
        let tokens = load(&layout).unwrap();
        assert_eq!(verify(&tokens, &raw_ro), Some(Scope::Ro));
        assert_eq!(verify(&tokens, &raw_rw), Some(Scope::Rw));
        assert_eq!(verify(&tokens, "sct-deadbeef"), None, "unknown token rejected");
        assert_eq!(verify(&tokens, ""), None);
    }

    #[test]
    fn duplicate_label_rejected_and_remove_absent_errors() {
        let (_d, layout) = tmp_layout();
        add(&layout, "dup", Scope::Ro).unwrap();
        assert!(add(&layout, "dup", Scope::Rw).is_err(), "duplicate label");
        assert!(remove(&layout, "nope").is_err(), "removing an absent label errors");
        remove(&layout, "dup").unwrap();
        assert!(load(&layout).unwrap().is_empty());
    }

    #[test]
    fn load_absent_file_is_empty() {
        let (_d, layout) = tmp_layout();
        assert!(load(&layout).unwrap().is_empty());
    }
}
```

- [ ] **Step 8: Run the tests to confirm they fail** — `cargo test -p scl-repo serve_tokens` → FAIL (module items not defined). (`tempfile` is already a scl-repo dev-dependency — confirm with `grep tempfile crates/repo/Cargo.toml`; if absent, it is used pervasively in existing repo tests, so it is present.)

- [ ] **Step 9: Implement the module** above the test block in `crates/repo/src/serve_tokens.rs`:

```rust
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
```

- [ ] **Step 10: Run all Task-1 tests** — `cargo test -p scl-crypto -p scl-repo serve_tokens` and `cargo test -p scl-crypto random_hex` → PASS.

- [ ] **Step 11: Commit**

```bash
git add crates/crypto/src/lib.rs crates/repo/src/serve_tokens.rs crates/repo/src/lib.rs crates/repo/src/layout.rs crates/repo/src/error.rs
git commit -m "feat(repo,crypto): serve-token store + scl_crypto::random_hex; Error::ReadOnly (P29 t1)"
```

---

### Task 2: HTTP opening parse extension (bearer + 401)

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`read_client_opening`, `write_client_opening`, `write_status`, the `ClientOpening` struct, and the one caller `handle_http_connection`)

**Interfaces:**
- Consumes: `read_bounded_opening` (existing).
- Produces: `pub(crate) struct ClientOpening { target: String, bearer: Option<String> }`; `read_client_opening -> Result<ClientOpening>`; `write_client_opening(w, host, path, bearer: Option<&str>)`; `write_status` supports `401`.

- [ ] **Step 1: Write the failing tests** (`crates/repo/src/http_transport.rs` `mod tests`):

```rust
#[test]
fn opening_parses_bearer_case_insensitively() {
    let mut buf = Vec::new();
    write_client_opening(&mut buf, "h", "/repo", Some("sct-abc")).unwrap();
    let opening = read_client_opening(&mut &buf[..]).unwrap();
    assert_eq!(opening.target, "/repo");
    assert_eq!(opening.bearer.as_deref(), Some("sct-abc"));
}

#[test]
fn opening_without_auth_has_no_bearer() {
    let mut buf = Vec::new();
    write_client_opening(&mut buf, "h", "/repo", None).unwrap();
    let opening = read_client_opening(&mut &buf[..]).unwrap();
    assert_eq!(opening.target, "/repo");
    assert_eq!(opening.bearer, None);
}

#[test]
fn opening_parses_lowercase_authorization_header() {
    // Servers must accept a client that lowercases the header name.
    let raw = "POST /r HTTP/1.1\r\nHost: h\r\nauthorization: Bearer sct-xyz\r\n\r\n";
    let opening = read_client_opening(&mut raw.as_bytes()).unwrap();
    assert_eq!(opening.bearer.as_deref(), Some("sct-xyz"));
}

#[test]
fn write_status_supports_401() {
    let mut buf = Vec::new();
    write_status(&mut buf, 401).unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
}
```

- [ ] **Step 2: Run to confirm failure** — `cargo test -p scl-repo opening_parses_bearer` → FAIL (signature mismatch / `ClientOpening` missing).

- [ ] **Step 3: Add the `ClientOpening` struct and rewrite `read_client_opening`** (replace the existing fn, keeping the request-line validation):

```rust
/// A parsed client HTTP opening: the request-target and an optional
/// `Authorization: Bearer` token. Only the bearer header is extracted (P29);
/// all other headers are ignored.
pub(crate) struct ClientOpening {
    pub target: String,
    pub bearer: Option<String>,
}

/// SERVER: read the request line + headers up to the blank line (bounded by
/// [`MAX_OPENING_BYTES`]). Returns the request-target and the bearer token if
/// an `Authorization: Bearer <token>` header (case-insensitive name) is present.
pub(crate) fn read_client_opening(r: &mut impl Read) -> Result<ClientOpening> {
    let buf = read_bounded_opening(r)?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| Error::InvalidArgument("empty HTTP request line".to_string()))?;
    let mut parts = request_line.split(' ');
    let _method = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP request line: {request_line}")))?;
    let target = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP request line: {request_line}")))?;
    let version = parts
        .next()
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP request line: {request_line}")))?;
    if !version.starts_with("HTTP/") {
        return Err(Error::InvalidArgument(format!(
            "bad HTTP request line (missing HTTP/ version): {request_line}"
        )));
    }

    let mut bearer = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                let v = value.trim();
                if let Some(tok) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
                    bearer = Some(tok.trim().to_string());
                }
            }
        }
    }

    Ok(ClientOpening { target: target.to_string(), bearer })
}
```

- [ ] **Step 4: Extend `write_client_opening`** to accept an optional bearer:

```rust
/// CLIENT: write the request line + `Host`/`User-Agent`, plus an
/// `Authorization: Bearer` header when a token is supplied.
pub(crate) fn write_client_opening(
    w: &mut impl Write,
    host: &str,
    path: &str,
    bearer: Option<&str>,
) -> Result<()> {
    write!(w, "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sc/2\r\n")
        .map_err(|e| Error::InvalidArgument(format!("HTTP opening write failed: {e}")))?;
    if let Some(tok) = bearer {
        write!(w, "Authorization: Bearer {tok}\r\n")
            .map_err(|e| Error::InvalidArgument(format!("HTTP opening write failed: {e}")))?;
    }
    write!(w, "\r\n").map_err(|e| Error::InvalidArgument(format!("HTTP opening write failed: {e}")))
}
```

Note: `ScHttpUrl::parse` already rejects `\r`/`\n` in host/path; the bearer token comes from `SC_HTTP_TOKEN` and must likewise not contain CR/LF — Task 5 rejects such a token client-side before it reaches here.

- [ ] **Step 5: Add `401` to `write_status`** (extend the match):

```rust
        401 => "Unauthorized",
```

(insert alongside `200`/`404`/`400`.)

- [ ] **Step 6: Update the existing callers.** In `handle_http_connection`, change `let target = match read_client_opening(...)` to bind `let opening = ...` and use `opening.target` where `target` was used (Task 4 will consume `opening.bearer`). In the existing test `client_opening_round_trips`, update the `write_client_opening(&mut buf, "h", "/repo")` call to `write_client_opening(&mut buf, "h", "/repo", None)` and assert `read_client_opening(...).unwrap().target == "/repo"`. Update the `mod tests` server harness at line ~527 (`handle_http_connection`-style manual server) if it calls `write_client_opening`/`read_client_opening` directly.

- [ ] **Step 7: Run to confirm pass** — `cargo test -p scl-repo http` → PASS (all P26 sc+http tests + the new ones green).

- [ ] **Step 8: Commit**

```bash
git add crates/repo/src/http_transport.rs
git commit -m "feat(repo): HTTP opening parses Authorization: Bearer; write_status 401; ClientOpening (P29 t2)"
```

---

### Task 3: Read-only enforcement in the wire dispatch

**Files:**
- Modify: `crates/repo/src/wire.rs` (`serve` → `serve_with_policy`, `EC_READONLY`, `err_to_wire`, `err_from_wire`)

**Interfaces:**
- Consumes: `Error::ReadOnly` (Task 1).
- Produces: `pub fn serve_with_policy(root, r, w, read_only: bool)`; `pub fn serve(root, r, w)` delegates with `read_only=false`; `EC_READONLY = 5`.

- [ ] **Step 1: Write the failing test** (`crates/repo/src/wire.rs` `mod tests`) — drive a read-only `serve_with_policy` over an in-process pipe and assert mutating verbs are rejected while reads work. Model it on the existing `wire::serve` pipe harness in `stdio_transport.rs`/`wire.rs` tests:

```rust
#[test]
fn read_only_policy_rejects_mutations_allows_reads() {
    let root = tmp_repo("readonly"); // existing test helper that inits a repo with one commit
    // Client on one end, serve_with_policy(read_only=true) on the other.
    let (mut client, server_join) = spawn_wire_pair_with_policy(&root, /*read_only=*/ true);
    // A read verb succeeds:
    assert!(client.list_refs().is_ok(), "reads allowed under read-only");
    // A mutating verb is rejected with the read-only error:
    let err = client
        .update_ref("main", &ObjectId::of(b"x"), None)
        .unwrap_err();
    assert!(
        matches!(err, Error::ReadOnly) || matches!(&err, Error::Remote(m) if m.contains("read-only")),
        "update_ref rejected read-only, got {err:?}"
    );
    drop(client);
    let _ = server_join.join();
}
```

Add a small `spawn_wire_pair_with_policy` test helper in the same `mod tests` that mirrors the existing pipe harness (two `os_pipe`/`Duplex` halves; spawn `wire::serve_with_policy(&root, &mut sr, &mut sw, read_only)` on a thread; return a `WireClient::handshake` over the other halves). If the existing harness helper is `spawn_wire_pair`, copy it and add the `read_only` parameter.

- [ ] **Step 2: Run to confirm failure** — `cargo test -p scl-repo read_only_policy_rejects_mutations_allows_reads` → FAIL (`serve_with_policy` missing).

- [ ] **Step 3: Add `EC_READONLY`** near the other codes (`crates/repo/src/wire.rs` ~line 79):

```rust
const EC_READONLY: u8 = 5;
```

- [ ] **Step 4: Map `Error::ReadOnly` in both directions.** In `err_to_wire` (~line 446) add the arm:

```rust
        Error::ReadOnly => EC_READONLY,
```

In `err_from_wire` (the reconstruct fn just below), add:

```rust
        EC_READONLY => Error::ReadOnly,
```

- [ ] **Step 5: Rename `serve` to `serve_with_policy` and add the wrapper.** Change the signature at ~line 558 to:

```rust
/// Serve the repo at `root` to one wire-protocol peer. `read_only` (P29): when
/// true, the three mutating verbs (`PutObject`/`PutPack`/`UpdateRef`) are
/// rejected with [`Error::ReadOnly`] BEFORE any store write; read verbs are
/// always allowed. `wire::serve` is the `read_only = false` wrapper every
/// pre-P29 caller uses unchanged.
pub fn serve_with_policy(
    root: &std::path::Path,
    r: &mut impl Read,
    w: &mut impl Write,
    read_only: bool,
) -> Result<()> {
```

Then add, immediately after it, the thin wrapper preserving the old name/signature:

```rust
/// Serve with full read/write access — the pre-P29 behavior. Every existing
/// caller (stdio transport, sync, tests) uses this unchanged.
pub fn serve(root: &std::path::Path, r: &mut impl Read, w: &mut impl Write) -> Result<()> {
    serve_with_policy(root, r, w, false)
}
```

- [ ] **Step 6: Gate the mutating verbs.** Inside `serve_with_policy`'s per-request dispatch loop, BEFORE the match that handles the request (i.e. before any `transport.put_object`/`put_pack`/`update_ref` call), add:

```rust
        // P29 read-only gate: reject mutating verbs before any store write.
        if read_only
            && matches!(
                req,
                Request::PutObject { .. } | Request::PutPack | Request::UpdateRef { .. }
            )
        {
            let (code, msg) = err_to_wire(&Error::ReadOnly);
            write_err(w, code, &msg)?;
            continue; // stay in the loop; the client surfaces Error::ReadOnly
        }
```

Match the exact variable names in the loop (`req` is the decoded `Request`; `write_err(w, code, msg)` is the existing error-reply helper used at the HELLO mismatch — confirm its signature at ~line 552 and reuse it verbatim). Place the gate so `PutPack`'s stream is never read and no object is written.

- [ ] **Step 7: Run to confirm pass** — `cargo test -p scl-repo read_only_policy_rejects_mutations_allows_reads` → PASS, and `cargo test -p scl-repo wire` → all green (the `serve` wrapper keeps every existing caller working).

- [ ] **Step 8: Commit**

```bash
git add crates/repo/src/wire.rs
git commit -m "feat(repo): wire::serve_with_policy read-only gate + EC_READONLY; serve() is the rw wrapper (P29 t3)"
```

---

### Task 4: Server wiring — bind gate + auth gate + read-only threading

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`serve_http`, `serve_http_listener`, `handle_http_connection`, a loopback classifier)

**Interfaces:**
- Consumes: `serve_tokens::{load, verify, Scope}` (T1), `ClientOpening` (T2), `wire::serve_with_policy` (T3).
- Produces: `serve_http(addr, root, read_only: bool, allow_public: bool)`; `serve_http_listener(listener, root, read_only)`; `fn is_loopback_host(host: &str) -> bool`.

- [ ] **Step 1: Write the failing tests** (`crates/repo/src/http_transport.rs` `mod tests`) — loopback classification + the fail-closed bind + the auth matrix over real loopback TCP. Use `TcpListener::bind("127.0.0.1:0")` + `local_addr()` for the integration cases (the existing P26 tests already do this — reuse their helpers):

```rust
#[test]
fn loopback_classification() {
    assert!(is_loopback_host("127.0.0.1"));
    assert!(is_loopback_host("127.5.6.7"));
    assert!(is_loopback_host("::1"));
    assert!(is_loopback_host("localhost"));
    assert!(!is_loopback_host("0.0.0.0"));
    assert!(!is_loopback_host("192.168.1.9"));
    assert!(!is_loopback_host("::"));
}

#[test]
fn bind_refuses_public_without_justification() {
    let root = tmp_repo("bindgate");
    // Non-loopback, no --read-only / --allow-public / tokens → refused.
    let err = serve_http("0.0.0.0:0", root.path(), false, false).unwrap_err();
    assert!(matches!(err, Error::InvalidArgument(_)), "public bind refused: {err:?}");
    // Justified by --allow-public → the bind itself succeeds (we can't easily
    // run the accept loop here, so assert the classifier path via a helper):
    assert!(bind_is_allowed("0.0.0.0:0", root.path(), false, true).unwrap());
    // Justified by tokens:
    crate::serve_tokens::add(&Layout::new(root.path()), "t", crate::serve_tokens::Scope::Rw).unwrap();
    assert!(bind_is_allowed("0.0.0.0:0", root.path(), false, false).unwrap());
}

#[test]
fn tokens_configured_requires_bearer_even_on_loopback() {
    // Full integration: token-configured server on 127.0.0.1:0; a no-token
    // client connect returns 401; the right ro token connects and can read but
    // not push; an rw token can push. Model on the P26 `http_clone_round_trips`
    // test harness (spawn serve_http_listener on a thread, connect a client).
    // (Body written against the existing harness in this module.)
}
```

Split the third test into concrete cases as the harness allows (no-token → `Error::` from the 401; ro-token clone ok; ro-token push → `Error::ReadOnly`; rw-token push ok). Add a small `bind_is_allowed(addr, root, read_only, allow_public) -> Result<bool>` helper used by both the test and `serve_http` (see Step 3) so the gate logic is unit-testable without binding a public port.

- [ ] **Step 2: Run to confirm failure** — `cargo test -p scl-repo bind_refuses_public loopback_classification` → FAIL.

- [ ] **Step 3: Implement the loopback classifier + bind gate.** Add:

```rust
/// Is `host` a loopback address (always safe to bind)? IPv4 `127.0.0.0/8`,
/// IPv6 `::1`, or the literal `localhost`. Everything else (`0.0.0.0`, a LAN
/// IP, `::`) is non-loopback and subject to the fail-closed bind gate.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

/// The fail-closed bind decision: a non-loopback `addr` is allowed only if
/// justified by `--read-only`, `--allow-public`, or ≥1 configured token.
/// Loopback always binds.
fn bind_is_allowed(
    addr: &str,
    root: &std::path::Path,
    read_only: bool,
    allow_public: bool,
) -> Result<bool> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    // Strip optional [..] brackets around an IPv6 literal.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if is_loopback_host(host) {
        return Ok(true);
    }
    let tokens_configured = !crate::serve_tokens::load(&crate::layout::Layout::new(root))?.is_empty();
    Ok(read_only || allow_public || tokens_configured)
}
```

Then thread it through `serve_http`:

```rust
pub fn serve_http(
    addr: &str,
    root: &std::path::Path,
    read_only: bool,
    allow_public: bool,
) -> Result<()> {
    if !bind_is_allowed(addr, root, read_only, allow_public)? {
        return Err(Error::InvalidArgument(format!(
            "refusing to bind non-loopback address {addr} without --read-only, \
             --allow-public, or a configured token (sc serve token add). Use \
             127.0.0.1 for local-only serving."
        )));
    }
    let listener = TcpListener::bind(addr)
        .map_err(|e| Error::ConnectionLost(format!("sc+http bind {addr}: {e}")))?;
    serve_http_listener(listener, root, read_only)
}
```

- [ ] **Step 4: Thread `read_only` + the auth gate through the accept loop and connection handler.** `serve_http_listener` gains a `read_only: bool` param and passes it into the per-connection closure:

```rust
pub fn serve_http_listener(
    listener: TcpListener,
    root: &std::path::Path,
    read_only: bool,
) -> Result<()> {
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sc serve --http: accept error: {e}");
                continue;
            }
        };
        let root = root.to_path_buf();
        std::thread::spawn(move || {
            if let Err(e) = handle_http_connection(stream, &root, read_only) {
                eprintln!("sc serve --http: connection error: {e}");
            }
        });
    }
    Ok(())
}
```

`handle_http_connection` gains `server_read_only: bool`, consumes `opening.bearer`, runs the auth gate, and computes the per-connection `read_only`:

```rust
fn handle_http_connection(
    mut stream: TcpStream,
    root: &std::path::Path,
    server_read_only: bool,
) -> Result<()> {
    stream
        .set_read_timeout(Some(OPENING_READ_TIMEOUT))
        .map_err(|e| Error::ConnectionLost(format!("sc+http set_read_timeout: {e}")))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| Error::ConnectionLost(format!("sc+http socket clone: {e}")))?,
    );

    let opening = match read_client_opening(&mut reader) {
        Ok(o) => o,
        Err(_) => {
            let _ = write_status(&mut stream, 400);
            return Ok(());
        }
    };
    let _ = &opening.target; // one repo per listener; target isn't used to route

    if !root.join(".sc").is_dir() {
        write_status(&mut stream, 404)?;
        return Ok(());
    }

    // ② Auth gate: if any tokens are configured, a valid bearer is REQUIRED on
    // every connection (loopback included). A matched token's scope sets the
    // connection's read-only flag.
    let tokens = crate::serve_tokens::load(&crate::layout::Layout::new(root))?;
    let token_read_only = if tokens.is_empty() {
        false // no auth configured — connection proceeds (bind gate already applied)
    } else {
        match opening.bearer.as_deref().and_then(|t| crate::serve_tokens::verify(&tokens, t)) {
            Some(crate::serve_tokens::Scope::Ro) => true,
            Some(crate::serve_tokens::Scope::Rw) => false,
            None => {
                write_status(&mut stream, 401)?;
                return Ok(());
            }
        }
    };

    write_status(&mut stream, 200)?;

    stream
        .set_read_timeout(None)
        .map_err(|e| Error::ConnectionLost(format!("sc+http clear read_timeout: {e}")))?;

    // ③ --read-only is a server-wide floor an rw token cannot elevate.
    let read_only = server_read_only || token_read_only;
    crate::wire::serve_with_policy(root, &mut reader, &mut stream, read_only)
}
```

- [ ] **Step 5: Update the in-module test server harness** (the manual server thread at ~line 527) to call `handle_http_connection(stream, &root, false)` / `serve_http_listener(listener, &root, false)` with the new arity so existing P26 tests compile.

- [ ] **Step 6: Run to confirm pass** — `cargo test -p scl-repo http` and `cargo test -p scl-repo bind loopback tokens_configured` → PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/repo/src/http_transport.rs
git commit -m "feat(repo): fail-closed bind gate + bearer auth gate + read-only threading in sc+http server (P29 t4)"
```

---

### Task 5: Client token + CLI (`sc serve --read-only/--allow-public`, `sc serve token`)

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`HttpTransport::connect` — `SC_HTTP_TOKEN`, 401 mapping)
- Modify: `crates/cli/src/main.rs` (`Serve` command flags + `ServeTokenOp` subcommand + handlers)

**Interfaces:**
- Consumes: `write_client_opening(.., bearer)` (T2), `serve_http(.., read_only, allow_public)` (T4), `serve_tokens::{add, remove, load, Scope}` (T1).
- Produces: client sends `SC_HTTP_TOKEN`; `sc serve --http <addr> <path> [--read-only] [--allow-public]`; `sc serve token add/remove/list`.

- [ ] **Step 1: Write the failing client test** — an auth round trip over loopback: a token-configured server, `SC_HTTP_TOKEN` set to a valid rw token → clone works; unset/invalid → a clear auth error. Model on the P26 client harness in this module. Assert the no-token path yields an `Error` whose message mentions authentication (not `NotARepo`).

```rust
#[test]
fn client_presents_sc_http_token_and_maps_401() {
    // token-configured server on 127.0.0.1:0 (rw token "T"); serve_http_listener
    // on a thread. With SC_HTTP_TOKEN=<raw T>, HttpTransport::connect(url) is Ok
    // and list_refs works. With SC_HTTP_TOKEN unset, connect returns an Err whose
    // message mentions "authentication". (Use a std::env lock or pass the token
    // explicitly if the harness prefers — see note below.)
}
```

Note on env in tests: `std::env::set_var` is process-global and racy under parallel tests. Prefer threading the token into `HttpTransport::connect` via reading `SC_HTTP_TOKEN` inside `connect` in production, but for the test, add a `connect_with_token(url, Option<&str>)` that `connect` calls with `std::env::var("SC_HTTP_TOKEN").ok()`. Test `connect_with_token` directly (no env mutation).

- [ ] **Step 2: Run to confirm failure** — FAIL (`connect_with_token` missing).

- [ ] **Step 3: Implement the client.** Refactor `HttpTransport::connect` to read the env once and delegate:

```rust
pub fn connect(url: &ScHttpUrl) -> Result<HttpTransport> {
    let token = std::env::var("SC_HTTP_TOKEN").ok().filter(|s| !s.is_empty());
    Self::connect_with_token(url, token.as_deref())
}

/// Connect presenting an explicit bearer token (or none). `connect` reads it
/// from `SC_HTTP_TOKEN`; this split keeps the env read out of the socket logic
/// and testable without mutating process env.
pub fn connect_with_token(url: &ScHttpUrl, token: Option<&str>) -> Result<HttpTransport> {
    if let Some(t) = token {
        if t.contains(['\r', '\n']) {
            return Err(Error::InvalidArgument(
                "SC_HTTP_TOKEN must not contain CR or LF".to_string(),
            ));
        }
    }
    let mut stream = TcpStream::connect(url.authority())
        .map_err(|e| Error::ConnectionLost(format!("sc+http connect to {url:?}: {e}")))?;
    write_client_opening(&mut stream, &url.host, &url.path, token)?;

    let mut r = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| Error::ConnectionLost(format!("sc+http socket clone: {e}")))?,
    );
    let w = stream;

    let status = read_status(&mut r)?;
    match status {
        200 => {}
        401 => {
            return Err(Error::Remote(
                "sc+http authentication required or token rejected; set SC_HTTP_TOKEN to a valid \
                 token (sc serve token add on the server)"
                    .to_string(),
            ))
        }
        404 => return Err(Error::NotARepo),
        other => {
            return Err(Error::Protocol(format!(
                "sc+http server returned unexpected status {other}"
            )))
        }
    }

    let client = WireClient::handshake(r, w)?;
    Ok(HttpTransport { client })
}
```

- [ ] **Step 4: Run the client test to confirm pass** — `cargo test -p scl-repo client_presents_sc_http_token` → PASS.

- [ ] **Step 5: Add the CLI flags + token subcommand** (`crates/cli/src/main.rs`). Restructure the `Serve` variant to carry an optional token subcommand without breaking `sc serve --http <addr> <path>`, using `args_conflicts_with_subcommands`:

```rust
    /// Serve a repo to a remote `sc` client, or manage server access tokens.
    #[command(args_conflicts_with_subcommands = true)]
    Serve {
        /// Manage `.sc/serve-tokens.toml` access tokens.
        #[command(subcommand)]
        token: Option<ServeTokenOp>,
        /// Speak the wire protocol on stdin/stdout.
        #[arg(long)]
        stdio: bool,
        /// Listen on this address and serve `sc+http://` clients.
        #[arg(long)]
        http: Option<String>,
        /// Reject all mutating verbs (server-wide read-only floor).
        #[arg(long)]
        read_only: bool,
        /// Permit a non-loopback bind with no auth (open public read/write).
        #[arg(long)]
        allow_public: bool,
        /// Repo root to serve (required unless a `token` subcommand is used).
        path: Option<PathBuf>,
    },
```

Add the subcommand enum near the other `*Op` enums:

```rust
#[derive(Subcommand)]
enum ServeTokenOp {
    /// Generate a token, print the raw value ONCE, store its hash + scope.
    Add {
        #[arg(long)]
        label: String,
        /// Access scope: `ro` (read-only) or `rw` (read-write).
        #[arg(long)]
        scope: String,
    },
    /// Remove a token by label.
    Remove { label: String },
    /// List token labels + scopes (never the token value).
    List {
        #[arg(long)]
        json: bool,
    },
}
```

- [ ] **Step 6: Wire the dispatch + handlers.** Update the `Cmd::Serve` arm:

```rust
        Cmd::Serve { token, stdio, http, read_only, allow_public, path } => {
            if let Some(op) = token {
                run_serve_token(op)
            } else {
                let path = path.ok_or_else(|| anyhow::anyhow!("sc serve requires a <path>"))?;
                run_serve(stdio, http, read_only, allow_public, path)
            }
        }
```

Extend `run_serve` to pass the new flags to `serve_http` (and error if `--read-only`/`--allow-public` are combined with `--stdio`, which ignores them):

```rust
fn run_serve(
    stdio: bool,
    http: Option<String>,
    read_only: bool,
    allow_public: bool,
    path: PathBuf,
) -> Result<()> {
    match (stdio, http) {
        (true, None) => {
            // ssh path unchanged; --read-only/--allow-public are http-only.
            let mut stdin = std::io::stdin().lock();
            let mut stdout = std::io::stdout().lock();
            scl_repo::wire::serve(&path, &mut stdin, &mut stdout)?;
            Ok(())
        }
        (false, Some(addr)) => {
            scl_repo::http_transport::serve_http(&addr, &path, read_only, allow_public)?;
            Ok(())
        }
        _ => Err(anyhow::anyhow!("sc serve requires exactly one of --stdio or --http")),
    }
}
```

Add the token handler:

```rust
fn run_serve_token(op: ServeTokenOp) -> Result<()> {
    let repo = open_repo()?;
    let layout = repo.layout();
    match op {
        ServeTokenOp::Add { label, scope } => {
            let scope = match scope.as_str() {
                "ro" => scl_repo::serve_tokens::Scope::Ro,
                "rw" => scl_repo::serve_tokens::Scope::Rw,
                other => return Err(anyhow::anyhow!("scope must be 'ro' or 'rw', got {other}")),
            };
            let raw = scl_repo::serve_tokens::add(layout, &label, scope)?;
            println!("{raw}");
            eprintln!("token '{label}' ({scope:?}) added — store this value now; it is not recoverable");
            Ok(())
        }
        ServeTokenOp::Remove { label } => {
            scl_repo::serve_tokens::remove(layout, &label)?;
            eprintln!("removed serve token '{label}'");
            Ok(())
        }
        ServeTokenOp::List { json } => {
            let tokens = scl_repo::serve_tokens::load(layout)?;
            if json {
                let v: Vec<_> = tokens.iter().map(|t| serde_json::json!({
                    "label": t.label,
                    "scope": format!("{:?}", t.scope).to_lowercase(),
                })).collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                for t in tokens {
                    println!("{}  {}", t.label, format!("{:?}", t.scope).to_lowercase());
                }
            }
            Ok(())
        }
    }
}
```

Ensure `serve_tokens` is re-exported: `crates/repo/src/lib.rs` already has `pub mod serve_tokens;` (T1) and `http_transport` is `pub` — confirm both are reachable as `scl_repo::serve_tokens` / `scl_repo::http_transport`.

- [ ] **Step 7: Run** — `cargo test -p scl-repo -p scl-cli` → PASS; smoke `cargo run --bin sc -- serve token list` in a scratch repo prints nothing (no tokens) and `sc serve token add --label t --scope ro` prints one `sct-…` line.

- [ ] **Step 8: Commit**

```bash
git add crates/repo/src/http_transport.rs crates/cli/src/main.rs
git commit -m "feat(cli,repo): SC_HTTP_TOKEN client + 401 mapping; sc serve --read-only/--allow-public + token add/remove/list (P29 t5)"
```

---

### Task 6: Demo + docs + ADR acceptance

**Files:**
- Create: `demo/run_http_auth_demo.sh`
- Modify: `docs/adr/0040-sc-http-access-control.md` (Proposed → Accepted), `docs/adr/README.md` (0040 → Accepted)
- Modify: `ROADMAP.md` (P29 Active → Done + Completed-phases row + Deferred follow-ons), `CLAUDE.md` (a `**Phase 29 is built.**` paragraph + the new `sc serve` commands in the command list)

**Interfaces:** none (docs + a shell demo).

- [ ] **Step 1: Write the demo** `demo/run_http_auth_demo.sh` — real loopback TCP (model on `demo/run_http_remote_demo.sh`), asserting the matrix. Use a fixed loopback port derived to avoid collisions or bind `127.0.0.1:0` and parse the port from a `--print-addr` if available; otherwise pick a high port and retry. Structure:

```bash
#!/usr/bin/env bash
set -euo pipefail
# P29 sc+http access-control demo: token auth + read-only + fail-closed bind.
# ... (scratch dirs, trap cleanup, build sc) ...

# origin repo with one signed-or-plain commit; add an rw and an ro token.
sc -C origin serve token add --label writer --scope rw >/tmp/rw.tok
sc -C origin serve token add --label reader --scope ro >/tmp/ro.tok

# start server on 127.0.0.1:$PORT (tokens configured -> auth on), background.
sc serve --http "127.0.0.1:$PORT" origin &  SRV=$!; trap 'kill $SRV' EXIT
# wait for listen ...

# (1) no token -> 401 (clone fails with an auth error)
if SC_HTTP_TOKEN= sc clone "sc+http://127.0.0.1:$PORT/origin" c-noauth 2>err.txt; then
  echo "FAIL: no-token clone should have been rejected"; exit 1
fi
grep -qi "authentication" err.txt || { echo "FAIL: expected auth error"; exit 1; }

# (2) ro token -> clone ok, push rejected read-only
SC_HTTP_TOKEN=$(cat /tmp/ro.tok) sc clone "sc+http://127.0.0.1:$PORT/origin" c-ro
# make a commit in c-ro, then:
if SC_HTTP_TOKEN=$(cat /tmp/ro.tok) sc -C c-ro push origin 2>err2.txt; then
  echo "FAIL: ro push should be rejected"; exit 1
fi
grep -qi "read-only" err2.txt || { echo "FAIL: expected read-only error"; exit 1; }

# (3) rw token -> push lands; a fresh ro clone sees it
SC_HTTP_TOKEN=$(cat /tmp/rw.tok) sc -C c-ro push origin
SC_HTTP_TOKEN=$(cat /tmp/ro.tok) sc clone "sc+http://127.0.0.1:$PORT/origin" c-verify
# assert c-verify sees the pushed commit ...

# (4) fail-closed bind: non-loopback without justification refused; with --allow-public accepted.
if sc serve --http "0.0.0.0:$PORT2" origin 2>bind.txt & sleep 0.3; kill %% 2>/dev/null; then :; fi
grep -qi "refusing to bind" bind.txt || { echo "FAIL: public bind should be refused"; exit 1; }

# assert zero .sc/tmp residue on origin and each clone ...
echo "P29 http-auth demo: OK"
```

Fill in every `...` with concrete commands (scratch dirs under `$(mktemp -d)`, a port picked and probed, `sc -C <dir>` if that flag exists — else `cd`), matching the exact style and residue assertions of `demo/run_http_remote_demo.sh`. Run it twice in CI style to prove idempotence.

- [ ] **Step 2: Run the demo** — `bash demo/run_http_auth_demo.sh` → prints `OK`, exit 0. Run it a second time → still `OK`.

- [ ] **Step 3: Accept ADR-0040** — flip `Status: Proposed` → `Accepted` in `docs/adr/0040-sc-http-access-control.md`; update the `docs/adr/README.md` 0040 row Status → `Accepted`.

- [ ] **Step 4: ROADMAP** — move P29 out of `## Active` into `## Done` as a narrative bullet (house style, ending `(ADR-0040.)`); set `## Active` to `**None.** The security horizon (P28 + P29) is complete; the next horizon (agent/workspace depth, anchored by P30 session transcripts, ADR-0038) is next up.`; add a P29 row to the `## Completed phases` table; add the deferred follow-ons to `## Deferred`: **per-path/per-ref ACLs**, **token expiry/rotation metadata**, **`sc+https://`/TLS** (fronting-proxy's job today).

- [ ] **Step 5: CLAUDE.md** — add a `**Phase 29 is built.**` paragraph (house style, four sentences max, ends "See ADR-0040.") covering the three gates + the accepted boundaries (no TLS; loopback-no-tokens stays unauthenticated; bearer tokens crossing plaintext need a fronting proxy for a public deployment). Add the new commands to the command list: `sc serve --http <addr> <path> [--read-only] [--allow-public]`, `sc serve token add/remove/list`, and the `SC_HTTP_TOKEN` client env.

- [ ] **Step 6: Full verification** — `cargo test` (whole workspace, green), then `bash demo/run_http_remote_demo.sh` and `bash demo/run_ssh_remote_demo.sh` (both green — the ssh path and no-auth http path are unchanged), then `bash demo/run_http_auth_demo.sh` (green), then `git diff main -- '*Cargo.toml' '*Cargo.lock'` (EMPTY — no new dependency).

- [ ] **Step 7: Commit**

```bash
git add demo/run_http_auth_demo.sh docs/adr/0040-sc-http-access-control.md docs/adr/README.md ROADMAP.md CLAUDE.md
git commit -m "docs+demo: accept ADR-0040; P29 sc+http access control done; run_http_auth_demo.sh (P29 t6)"
```

---

## Self-review (author checklist, completed)

- **Spec coverage:** Bind gate → T4; auth gate + tokens → T1/T2/T4; read-only enforcement → T3; token format/hash/const-time → T1; opening parse → T2; client `SC_HTTP_TOKEN`/401 → T5; CLI → T5; demo → T6; boundaries/docs → T6. All spec sections mapped.
- **No-new-dep:** token randomness via `scl_crypto::random_hex` (OsRng already a crypto dep); hash via `scl_core::ObjectId::of`; const-time is std. `git diff main -- '*Cargo.toml'` must stay empty (T6 Step 6).
- **Type consistency:** `Scope`/`TokenEntry`/`verify -> Option<Scope>` (T1) consumed unchanged in T4/T5; `ClientOpening{target,bearer}` (T2) consumed in T4; `serve_with_policy(.., read_only)` (T3) called by T4; `serve_http(addr, root, read_only, allow_public)` (T4) called by T5.
- **Wire stability:** only `EC_READONLY = 5` added; `PROTOCOL_VERSION` untouched; `wire::serve` wrapper keeps all pre-P29 callers unchanged.
