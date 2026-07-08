# P26 — sc-native HTTP Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc+http://host:port/repo` clone/fetch/push over a dep-free persistent TCP connection, reusing the existing wire session verbatim (spec: `docs/superpowers/specs/2026-07-08-p26-http-transport-design.md`, ADR-0036). Second phase of the P25–P27 scale horizon.

**Architecture:** `wire::serve` and `WireClient` already run the whole interactive session over any `Read`+`Write`. P26 adds a minimal hand-rolled HTTP/1.1 opening that establishes a TCP connection, then hands the raw `TcpStream` (split via `try_clone()`) to that existing machinery. A dedicated `sc+http://` scheme keeps P18's http(s):// and P12's ssh:// routing untouched.

**Tech Stack:** Rust stable, `std::net` (TcpListener/TcpStream), **no new dependencies**.

## Global Constraints

- Dep-free — hand-rolled minimal HTTP/1.1 over `std::net`; NO HTTP-library or TLS dependency (spec).
- Dedicated `sc+http://` scheme only; `http://`/`https://` (P18 git bridge) and `ssh://` (P12) routing MUST stay untouched (spec).
- The wire session (Hello handshake, 8 verbs, P25 chunk stream, client temp-spill) is REUSED VERBATIM — no protocol change, no double-framing (the chunk stream is the wire's own framing, not HTTP `Transfer-Encoding`) (spec).
- Server: one repo per `sc serve --http` (like `--stdio`); thread-per-connection; the `.sc/` single-writer lock serializes pushes; concurrent fetches are read-only (spec).
- The HTTP opening is UNTRUSTED input — bound the header read (cap total bytes, e.g. 8 KiB), 400 on malformed / unterminated (spec + the P25 review's untrusted-input lesson).
- Client maps status BEFORE the wire handshake: 404 → `Error::NotARepo`, non-200 → a clear error (spec).
- Boundaries explicit: plaintext only (no TLS), no auth (spec).
- No new dependencies; tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: `sc+http://` URL parse (+ ROADMAP flip)

**Files:**
- Create: `crates/repo/src/http_transport.rs` (module skeleton + `ScHttpUrl`)
- Modify: `crates/repo/src/lib.rs` (register `mod http_transport;` + any re-export)
- Modify: `ROADMAP.md` (Active → P26; mirror how P25's Task 1 flipped it — Active currently names P26 as next up, make it the active phase)

**Interfaces (produced, consumed by Tasks 3–4):**
```rust
/// A parsed sc-native HTTP URL: `sc+http://host[:port]/repo/path`.
/// Port defaults to 8730 when omitted. The path is everything after the
/// authority (leading '/' kept; may be empty → "/").
pub struct ScHttpUrl { pub host: String, pub port: u16, pub path: String }
impl ScHttpUrl {
    pub fn parse(url: &str) -> Result<ScHttpUrl>;   // Err(Protocol) on a non-sc+http:// or malformed authority
    pub fn authority(&self) -> String;              // "host:port" for TcpStream::connect
}
```

- [ ] **Step 1: ROADMAP flip.**
- [ ] **Step 2: Failing tests** (http_transport.rs in-module):
  - `parse_full`: `sc+http://example.com:8730/srv/repo` → host `example.com`, port 8730, path `/srv/repo`.
  - `parse_default_port`: `sc+http://host/repo` → port 8730, path `/repo`.
  - `parse_empty_path`: `sc+http://host:9000` → path `/`.
  - `parse_rejects_other_schemes`: `http://h/r`, `ssh://h/r`, `/local/path` each → `Err`.
  - `authority_form`: builds `host:port`.
- [ ] **Step 3: Implement** `ScHttpUrl::parse` (strip the `sc+http://` prefix, split the authority at the first `/`, split host/port at `:`, parse the port or default 8730, keep the remainder as the path defaulting to `/`). Mirror `SshUrl::parse`'s error style (grep it in stdio_transport.rs).
- [ ] **Step 4: Run** `cargo test -p scl-repo http_transport` + `cargo test` → green. **Step 5: Commit** — `git commit -am "feat(repo): sc+http:// URL parse + http_transport module skeleton (P26)"`

---

### Task 2: the HTTP opening codec — dep-free, bounded, robust

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (the opening read/write functions over generic `Read`/`Write`)

**Interfaces (produced, consumed by Tasks 3–4):**
```rust
/// Max bytes of request-line + headers the server will read before the
/// blank line, guarding against an unterminated/hostile opening.
pub(crate) const MAX_OPENING_BYTES: usize = 8 * 1024;

/// CLIENT: write `POST <path> HTTP/1.1\r\nHost: <host>\r\nUser-Agent: sc/2\r\n\r\n`.
pub(crate) fn write_client_opening(w: &mut impl Write, host: &str, path: &str) -> Result<()>;

/// SERVER: read the request line + headers up to the blank line (bounded by
/// MAX_OPENING_BYTES). Returns the request-target (the `<path>`). Errors
/// (→ the caller sends 400) on: a bad request line, no `\r\n\r\n` within the
/// cap, or non-HTTP bytes.
pub(crate) fn read_client_opening(r: &mut impl Read) -> Result<String>;

/// SERVER: write `HTTP/1.1 <code> <reason>\r\nContent-Length: 0\r\n\r\n`.
/// Supports 200 OK / 404 Not Found / 400 Bad Request.
pub(crate) fn write_status(w: &mut impl Write, code: u16) -> Result<()>;

/// CLIENT: read the status line + headers up to the blank line (bounded).
/// Returns the numeric status code.
pub(crate) fn read_status(r: &mut impl Read) -> Result<u16>;
```

- [ ] **Step 1: Failing tests** (in-module; drive over `Vec<u8>`/`&[u8]` cursors, no TCP):
  - `client_opening_round_trips`: `write_client_opening(&mut buf, "h", "/repo")` then `read_client_opening(&mut &buf[..])` returns `/repo`.
  - `read_opening_rejects_malformed`: bytes with no `\r\n\r\n` within `MAX_OPENING_BYTES` → Err; a bad first line (`garbage`) → Err; an opening exceeding the cap (9 KiB of headers, no blank line) → Err (bounded, no unbounded read).
  - `status_round_trips`: `write_status(&mut buf, 200)` then `read_status` → 200; same for 404, 400.
  - `read_status_rejects_non_http`: `read_status` on `garbage\r\n\r\n` → Err.
- [ ] **Step 2: Implement** with a bounded line reader: read byte-by-byte (or via a small `BufRead` wrapper) accumulating into a `Vec`, stopping at `\r\n\r\n`, erroring if the accumulator exceeds `MAX_OPENING_BYTES` before the terminator. Parse the request line (`METHOD SP target SP HTTP/1.1`) — accept any method, extract the target; require the `HTTP/` version token. `read_status` parses `HTTP/1.1 SP <code> SP <reason>`, returns `<code>` as `u16`.
- [ ] **Step 3: Run** `cargo test -p scl-repo http_transport` + `cargo test` → green. **Step 4: Commit** — `git commit -am "feat(repo): bounded dep-free HTTP/1.1 opening codec (client write / server parse / status) (P26)"`

---

### Task 3: client transport + `open_transport` routing

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`HttpTransport` + `connect`)
- Modify: `crates/repo/src/stdio_transport.rs` (`open_transport` gains the `sc+http://` arm)

**Interfaces:**
```rust
/// A Transport speaking the wire protocol over a TcpStream established via
/// the HTTP opening. Wraps WireClient<BufReader<TcpStream>, TcpStream>.
pub struct HttpTransport { client: WireClient<std::io::BufReader<std::net::TcpStream>, std::net::TcpStream> }
impl HttpTransport {
    /// Connect, write the opening, map the status (404 → NotARepo,
    /// non-200 → Protocol error naming the code) BEFORE the handshake,
    /// then run WireClient::handshake over the split stream.
    pub fn connect(url: &ScHttpUrl) -> Result<HttpTransport>;
}
impl Transport for HttpTransport { /* delegate all 8 verbs to self.client, like StdioTransport */ }
```
- Consumes: Task 1 (`ScHttpUrl`), Task 2 (opening codec), existing `WireClient` (stdio_transport.rs) and `Transport` trait.

- [ ] **Step 1: Failing test** (http_transport.rs tests) — spin a minimal loopback server in a thread so the client is tested end-to-end WITHOUT Task 4's CLI:
```rust
#[test]
fn client_clones_over_loopback_http() {
    // Build a source repo with a commit (reuse the repo-building idiom
    // from sync.rs's ssh tests — grep `signatures_ride_ssh_transport`).
    // Spin a server thread: TcpListener::bind("127.0.0.1:0"); on accept,
    //   read_client_opening -> write_status(200) -> wire::serve(&src, &mut
    //   BufReader::new(sock.try_clone()?), &mut sock).
    // Client: ScHttpUrl::parse("sc+http://127.0.0.1:<port>/repo"),
    //   HttpTransport::connect, then drive clone via sync::clone / the
    //   Transport verbs; assert the destination store matches the source
    //   (same tip id / object set). Force SC_PACK_CHUNK small to stream
    //   many chunks over TCP.
    // Also: a second server that write_status(404) -> client connect maps
    //   to Error::NotARepo BEFORE any handshake.
}
```
- [ ] **Step 2: Implement** `HttpTransport::connect`: `TcpStream::connect(url.authority())`; `write_client_opening(&mut stream, &url.host, &url.path)`; `read_status(&mut BufReader)` — match 200 → proceed, 404 → `Error::NotARepo`, other → `Error::Protocol`; split `let r = BufReader::new(stream.try_clone()?); let w = stream;`; `WireClient::handshake(r, w)`. Delegate the 8 `Transport` verbs to `self.client` exactly as `StdioTransport` does (grep its impl). `open_transport`: add `else if url.starts_with("sc+http://") { Ok(Box::new(HttpTransport::connect(&ScHttpUrl::parse(url)?)?)) }` BEFORE the local-path fallback; ssh:// and the local arm unchanged.
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test` → green. **Step 4: Commit** — `git commit -am "feat(repo): HttpTransport client + sc+http:// routing in open_transport (P26)"`

---

### Task 4: server — `serve_http` listener + `sc serve --http`

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`serve_http`)
- Modify: `crates/cli/src/main.rs` (the `Serve` command gains `--http <addr>`; `run_serve` dispatches)

**Interfaces:**
```rust
/// Bind `addr`, serve the single repo at `root` to sc+http:// clients until
/// the listener is dropped. Thread-per-connection: read_client_opening →
/// validate root has `.sc/` (else 404) → write_status(200) → wire::serve
/// over the split TcpStream. A malformed opening → 400 and close. Errors
/// on one connection never kill the listener.
pub fn serve_http(addr: &str, root: &std::path::Path) -> Result<()>;
```
- Consumes: Task 2 (codec), existing `wire::serve`.

- [ ] **Step 1: Failing test** (http_transport.rs or a cli/tests integration file): bind `serve_http` on `127.0.0.1:0` in a thread (expose the bound port — bind a `TcpListener` first, read `.local_addr()`, then hand it in, OR have `serve_http` accept a pre-bound listener via a small helper so the test can learn the port); then over `sc+http://127.0.0.1:<port>/repo`: (a) `sync::clone` lands byte-identical (tip id matches), (b) a `push` from a second repo lands and a subsequent fetch sees it, (c) a signed commit (P22) verifies in the clone, (d) `sc+http://127.0.0.1:<port>/<nonexistent>` against a server whose root lacks `.sc/` → `NotARepo`. Force `SC_PACK_CHUNK` small.
- [ ] **Step 2: Implement** `serve_http`: `TcpListener::bind(addr)`; `for stream in listener.incoming()` → `std::thread::spawn` per connection running: `read_client_opening` (Err → `write_status(400)`, close); check `root.join(".sc").is_dir()` (false → `write_status(404)`, close); `write_status(200)`; `wire::serve(root, &mut BufReader::new(stream.try_clone()?), &mut stream)` (a serve error just ends that connection — log to stderr, don't propagate to the accept loop). The `.sc/` single-writer lock inside the commit/push path already serializes concurrent pushes; concurrent read-only fetches need no extra guard. CLI: `Serve { #[arg(long)] stdio: bool, #[arg(long)] http: Option<String>, path: PathBuf }`; `run_serve`: if `http` is `Some(addr)` → `serve_http(&addr, &path)`; else if `stdio` → current stdio path; else bail requiring one mode. (For the test's port discovery, factor the accept loop to also accept an already-bound `TcpListener`.)
- [ ] **Step 3: Run** `cargo test -p scl-repo` + `cargo test -p scl-cli` + `cargo test` → green (existing ssh/stdio tests undisturbed). **Step 4: Commit** — `git commit -am "feat(repo,cli): sc serve --http listener — thread-per-connection wire::serve over TCP (P26)"`

---

### Task 5: Demo + docs

**Files:**
- Create: `demo/run_http_remote_demo.sh` (mode 755)
- Modify: `docs/adr/0036-http-transport.md` (→ Accepted + refinements, code-verified — the opening byte format, the bounded parse + cap, the try_clone split, the 404-before-handshake mapping, the thread-per-conn + lock model), `docs/adr/README.md` (0036 → Accepted), `ROADMAP.md` (P26 → Done + BOTH a `## Done` narrative bullet AND the completed-phases table row — the P22 missing-bullet lesson; Active → "None — P26 done; P27 partial clone is next up"), `CLAUDE.md` (commands: `sc serve --http <addr> <path>`, `sc clone sc+http://…`; a `**Phase 26 is built.**` paragraph WITH the plaintext/no-auth/no-TLS boundaries)

- [ ] **Step 1: Demo** (house style; read `demo/run_ssh_remote_demo.sh` first — but HTTP needs NO shim, it's real loopback TCP). Sequence: init a source repo, commit a large-ish blob (generate ~1 MB) — sign it if easy; pick a free port (or a fixed high port like 8731 with a fallback); start `sc serve --http 127.0.0.1:<port> <src>` in the background (`&`, capture PID, `trap` to kill it + a readiness wait-loop on the port); `sc clone sc+http://127.0.0.1:<port>/repo <dst>` with a small `SC_PACK_CHUNK`; assert dst objects/`sc log` match the origin byte-for-byte AND (if signed) `sc verify --require` clean; make a commit in `<dst>` and `sc push sc+http://…` back (or push from a third clone), assert it lands; assert zero `.sc/tmp` residue on both ends; kill the server. Run twice; zero-residue trap.
- [ ] **Step 2: Docs** (P25-completion commit shape; refinement candidates: the exact opening bytes, `MAX_OPENING_BYTES`, the `try_clone` R/W split, that the P25 chunk stream rides the TcpStream with no double-framing, the concurrency/lock model).
- [ ] **Step 3: Full verification** — `cargo test && bash demo/run_http_remote_demo.sh && bash demo/run_ssh_remote_demo.sh && bash demo/run_streaming_demo.sh && bash demo/run_provenance_demo.sh && git diff main -- '*Cargo.toml'` (all green; empty dep diff — NO new dependency; the ssh/streaming/provenance demos are the transport + signature-riding regression gates; run_protect_demo.sh pre-P8 failure known — skip).
- [ ] **Step 4: Commit** — `git commit -am "docs+demo: accept ADR-0036 sc-native HTTP transport; sc+http:// clone/push demo (P26)"`
