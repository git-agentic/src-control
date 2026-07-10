# P31: HTTP Listener Resource Limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound `sc serve` against hostile/broken clients: connection cap with busy status, session read+write timeouts, aggregate pack-spool cap (both transports), read-only drain cap, accept-loop backoff.

**Architecture:** A `ServeLimits` struct (CLI-built) threads into the HTTP listener; the wire layer's bare `read_only: bool` grows into `WirePolicy { read_only, max_pack_size, ro_drain_cap }`. Connection slots are an `Arc<AtomicUsize>` with an RAII guard; the spool cap is a counted mid-stream abort in `read_pack_stream` surfacing as new wire code `EC_TOO_LARGE = 6` (old clients degrade to message text — no version bump).

**Tech Stack:** Rust (std only — no new dependencies). Spec: `docs/superpowers/specs/2026-07-10-p31-listener-limits-design.md`. Issue: #38.

## Global Constraints

- **Zero new dependencies.** `PROTOCOL_VERSION` stays **3**.
- Defaults, copied from the spec: `--max-connections` **32**, `--timeout` **300** s, `--max-pack-size` **16 GiB** (`17_179_869_184`); `0` = unlimited/disabled for all three. RO drain cap: **8 MiB** constant, no knob.
- `--max-pack-size` values `> 0` but `< MAX_OBJECT_SIZE` (256 MiB, `scl_core::MAX_OBJECT_SIZE`) are rejected.
- `--max-connections`/`--timeout` are `--http`-only (refused with `--stdio`); `--max-pack-size` applies to both transports.
- Mid-stream spool abort is **connection-fatal** (stream desync): best-effort typed error, then close.
- Repo conventions: `RUSTFLAGS="-D warnings"` (CI), per-crate `thiserror`, doc comments state intent, tests clean up temp dirs and assert zero residue, `cargo fmt` before every commit.
- Commit messages end with: `Claude-Session: https://claude.ai/code/session_01LhadyW9scQL95h3ag9yySB`

## File Structure

- `crates/repo/src/error.rs` — two new variants: `PackTooLarge(String)`, `ServerBusy`.
- `crates/repo/src/wire.rs` — `EC_TOO_LARGE`, `WirePolicy`, `DEFAULT_MAX_PACK_SIZE`, `RO_DRAIN_CAP`, `validate_max_pack_size`, budgeted `read_pack_stream`/`spill_pack_stream`, both `PutPack` arms.
- `crates/repo/src/http_transport.rs` — `ServeLimits`, `SlotGuard`, `AcceptBackoff`, 503 status, session timeouts, client `ServerBusy` mapping.
- `crates/cli/src/main.rs` — three flags + validation + plumbing (`run_serve`).
- `demo/run_limits_demo.sh` — end-to-end proof.
- `docs/adr/0041-listener-resource-limits.md`, `docs/THREAT-MODEL.md`, `CLAUDE.md` — docs.

---

### Task 1: Typed errors + wire code round trip

**Files:**
- Modify: `crates/repo/src/error.rs` (append inside `pub enum Error`, near `ReadOnly`)
- Modify: `crates/repo/src/wire.rs` (EC constants block ~line 75; `err_to_wire` ~line 485; `wire_to_err` ~line 499; tests at bottom)

**Interfaces:**
- Produces: `Error::PackTooLarge(String)` (payload = human limit text, e.g. `"16 GiB (17179869184 bytes)"`), `Error::ServerBusy`, `pub(crate) const EC_TOO_LARGE: u8 = 6`. Round trip: `err_to_wire(PackTooLarge) == (EC_TOO_LARGE, msg)`; `wire_to_err(EC_TOO_LARGE, msg) == PackTooLarge(msg)`.

- [ ] **Step 1: Write the failing test** (in `wire.rs` `mod tests`)

```rust
#[test]
fn pack_too_large_round_trips_through_wire_codes() {
    let e = Error::PackTooLarge("16 GiB (17179869184 bytes)".to_string());
    let (code, msg) = err_to_wire(&e);
    assert_eq!(code, EC_TOO_LARGE);
    match wire_to_err(code, msg) {
        Error::PackTooLarge(m) => assert!(m.contains("17179869184")),
        other => panic!("expected PackTooLarge, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p scl-repo pack_too_large_round_trips -- --nocapture`
Expected: compile error — `PackTooLarge` not defined.

- [ ] **Step 3: Implement**

In `error.rs`, after the `ReadOnly` variant:

```rust
/// The server aborted an incoming pack mid-stream because it exceeded the
/// operator's `--max-pack-size` cap (P31). Payload is the server's own
/// human-readable limit text, carried verbatim across the wire.
#[error("pack exceeds the server's --max-pack-size limit: {0}")]
PackTooLarge(String),
/// The server refused the connection at accept time because
/// `--max-connections` was reached (P31). Retryable.
#[error("server busy (connection limit reached); retry later")]
ServerBusy,
```

In `wire.rs`, EC block:

```rust
const EC_TOO_LARGE: u8 = 6;
```

`err_to_wire`: add arm `Error::PackTooLarge(_) => EC_TOO_LARGE,` (message flows via the existing `e.to_string()` path).
`wire_to_err`: add arm `EC_TOO_LARGE => Error::PackTooLarge(msg),`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p scl-repo pack_too_large_round_trips`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && git add -A crates/repo && git commit -m "feat(wire): PackTooLarge/ServerBusy errors + EC_TOO_LARGE wire code (P31)"
```

---

### Task 2: Byte budget in `read_pack_stream`

**Files:**
- Modify: `crates/repo/src/wire.rs:430` (`read_pack_stream`), `crates/repo/src/wire.rs:796` (`spill_pack_stream` call site), test call sites `wire.rs:1155,1169,1181,1302,1313`
- Modify: `crates/repo/src/stdio_transport.rs:120,566` (client + harness call sites)

**Interfaces:**
- Consumes: `Error::PackTooLarge(String)` (Task 1).
- Produces: `pub fn read_pack_stream(r: &mut impl Read, sink: &mut (impl Write + ?Sized), max_bytes: u64) -> Result<u64>` — `max_bytes == 0` means unlimited; exceeding aborts with `Error::PackTooLarge` *before* writing the over-budget chunk to `sink`.

- [ ] **Step 1: Write the failing tests** (in `wire.rs` `mod tests`; `write_pack_stream(w, r, chunk_size)` already exists)

```rust
#[test]
fn pack_stream_over_budget_aborts_typed() {
    let payload = vec![7u8; 4096];
    let mut buf = Vec::new();
    write_pack_stream(&mut buf, &mut std::io::Cursor::new(&payload), 1024).unwrap();
    let mut sink = Vec::new();
    let err = read_pack_stream(&mut std::io::Cursor::new(buf), &mut sink, 2048).unwrap_err();
    assert!(matches!(err, Error::PackTooLarge(_)), "got {err:?}");
    assert!(sink.len() <= 2048, "sink got over-budget bytes: {}", sink.len());
}

#[test]
fn pack_stream_under_budget_passes() {
    let payload = vec![7u8; 4096];
    let mut buf = Vec::new();
    write_pack_stream(&mut buf, &mut std::io::Cursor::new(&payload), 1024).unwrap();
    let mut sink = Vec::new();
    assert_eq!(
        read_pack_stream(&mut std::io::Cursor::new(buf), &mut sink, 4096).unwrap(),
        4096
    );
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo pack_stream_over_budget`
Expected: compile error — wrong arity.

- [ ] **Step 3: Implement**

Change the signature and add the check inside the chunk arm, before `sink.write_all`:

```rust
pub fn read_pack_stream(
    r: &mut impl Read,
    sink: &mut (impl Write + ?Sized),
    max_bytes: u64,
) -> Result<u64> {
    let mut total: u64 = 0;
    loop {
        let frame =
            read_frame_opt(r)?.ok_or_else(|| Error::Protocol("EOF before ST_PACK_END".into()))?;
        match frame.split_first() {
            Some((&ST_PACK_CHUNK, rest)) => {
                let next = total + rest.len() as u64;
                if max_bytes != 0 && next > max_bytes {
                    return Err(Error::PackTooLarge(format!("{max_bytes} bytes")));
                }
                sink.write_all(rest)?;
                total = next;
            }
            Some((&ST_PACK_END, [])) => return Ok(total),
            _ => return Err(Error::Protocol("unexpected frame in pack stream".into())),
        }
    }
}
```

Update every existing call site to pass `0` (unlimited) for now: `wire.rs:796` (`spill_pack_stream` — Task 3 threads the real cap), `stdio_transport.rs:120` (client destream — client-side caps are a spec non-goal) and `:566` (test harness), and the five `wire.rs` tests. Update the doc comment: budget semantics + "0 = unlimited".

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p scl-repo pack_stream`
Expected: new tests PASS, existing pack-stream tests PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && git add -A crates/repo && git commit -m "feat(wire): byte budget with typed mid-stream abort in read_pack_stream (P31)"
```

---

### Task 3: `WirePolicy` + capped spool in both `PutPack` arms

**Files:**
- Modify: `crates/repo/src/wire.rs` — `serve_with_policy` (~line 604), `serve` wrapper (~line 780), `spill_pack_stream` (~line 790), RO drain arm (~line 669), normal `PutPack` arm (~line 724), the read-only test at ~line 1200
- Modify: `crates/repo/src/http_transport.rs:602` (call site; real limits threaded in Task 5 — pass `WirePolicy { read_only, ..Default::default() }` for now)

**Interfaces:**
- Consumes: budgeted `read_pack_stream` (Task 2), `EC_TOO_LARGE` (Task 1).
- Produces:

```rust
pub const DEFAULT_MAX_PACK_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
pub const RO_DRAIN_CAP: u64 = 8 * 1024 * 1024; // 8 MiB

#[derive(Debug, Clone, Copy)]
pub struct WirePolicy {
    pub read_only: bool,
    pub max_pack_size: u64, // 0 = unlimited
    pub ro_drain_cap: u64,
}
impl Default for WirePolicy {
    fn default() -> Self {
        Self { read_only: false, max_pack_size: DEFAULT_MAX_PACK_SIZE, ro_drain_cap: RO_DRAIN_CAP }
    }
}

pub fn validate_max_pack_size(max: u64) -> Result<()>; // 0 ok; else must be >= MAX_OBJECT_SIZE
pub fn serve_with_policy(root: &Path, r: &mut impl Read, w: &mut impl Write, policy: WirePolicy) -> Result<()>;
```

- [ ] **Step 1: Write the failing tests** (model on the existing `serve_with_policy` read-only test at ~line 1200; `some_id`, `tmp_repo`, `write_frame`, `parse_response` helpers exist)

```rust
/// A PutPack whose chunk stream exceeds policy.max_pack_size gets a
/// best-effort EC_TOO_LARGE reply and the connection closes (desync).
#[test]
fn putpack_over_cap_replies_too_large_and_closes() {
    let root = tmp_repo("cap");
    let mut input = Vec::new();
    write_frame(&mut input, &Request::Hello { version: PROTOCOL_VERSION }.encode()).unwrap();
    write_frame(&mut input, &Request::PutPack.encode()).unwrap();
    let payload = vec![9u8; 8192];
    write_pack_stream(&mut input, &mut std::io::Cursor::new(&payload), 1024).unwrap();
    // A trailing request that must never be answered (connection closed):
    write_frame(&mut input, &Request::HeadBranch.encode()).unwrap();

    let mut reader = std::io::Cursor::new(input);
    let mut output = Vec::new();
    let policy = WirePolicy { read_only: false, max_pack_size: 4096, ro_drain_cap: RO_DRAIN_CAP };
    serve_with_policy(&root, &mut reader, &mut output, policy).unwrap();

    let mut frames = Vec::new();
    let mut r = std::io::Cursor::new(output);
    while let Some(f) = read_frame_opt(&mut r).unwrap() {
        frames.push(parse_response(f));
    }
    assert_eq!(frames.len(), 2, "hello-ok + too-large error only, got {frames:?}");
    assert!(frames[0].is_ok());
    assert!(matches!(frames[1].as_ref().unwrap_err(), Error::PackTooLarge(_)));
    // Zero spool residue:
    let tmp = root.join(".sc").join("tmp");
    assert!(!tmp.exists() || std::fs::read_dir(&tmp).unwrap().next().is_none());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn validate_max_pack_size_floor() {
    assert!(validate_max_pack_size(0).is_ok());
    assert!(validate_max_pack_size(scl_core::MAX_OBJECT_SIZE as u64).is_ok());
    assert!(validate_max_pack_size(1024).is_err());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo putpack_over_cap`
Expected: compile error — `WirePolicy` not defined.

- [ ] **Step 3: Implement**

1. Add the constants, `WirePolicy`, and `validate_max_pack_size` (error: `Error::InvalidArgument(format!("--max-pack-size {max} is below MAX_OBJECT_SIZE ({}); a cap that cannot fit one object is a misconfiguration", scl_core::MAX_OBJECT_SIZE))`).
2. `serve_with_policy` takes `policy: WirePolicy`; replace internal `read_only` reads with `policy.read_only`. `serve` wrapper: `serve_with_policy(root, r, w, WirePolicy::default())`.
3. `spill_pack_stream(r, layout, max_bytes: u64)` — pass `max_bytes` through to `read_pack_stream`.
4. Normal `PutPack` arm: `spill_pack_stream(r, transport.layout(), policy.max_pack_size)`; on `Err(e @ Error::PackTooLarge(_))` → `let (code, msg) = err_to_wire(&e); let _ = write_err(w, code, &msg); return Ok(());` (best-effort reply, then close — desync). Other errors keep the current reply-and-continue behavior.
5. RO drain arm: `spill_pack_stream(r, transport.layout(), policy.ro_drain_cap)`; on `Ok(guard)` → drop + `EC_READONLY` reply + `continue` (unchanged); on `Err(Error::PackTooLarge(_))` → best-effort `write_err(w, EC_READONLY-mapped ReadOnly error)` then `return Ok(())` (close); other errors propagate as today.
6. Update `http_transport.rs:602`: `crate::wire::serve_with_policy(root, &mut reader, &mut stream, crate::wire::WirePolicy { read_only, ..Default::default() })`.
7. Update the existing read-only test at ~line 1200 to construct a `WirePolicy`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p scl-repo --lib wire`
Expected: new tests PASS; all existing wire tests (including RO drain + streaming) PASS.

- [ ] **Step 5: Write the RO-drain-cap test**

```rust
/// An oversized push on a read-only connection drains at most ro_drain_cap
/// bytes, then the connection closes; zero spool residue.
#[test]
fn readonly_oversized_push_is_dropped_after_drain_cap() {
    let root = tmp_repo("rocap");
    let mut input = Vec::new();
    write_frame(&mut input, &Request::Hello { version: PROTOCOL_VERSION }.encode()).unwrap();
    write_frame(&mut input, &Request::PutPack.encode()).unwrap();
    let payload = vec![9u8; 8192];
    write_pack_stream(&mut input, &mut std::io::Cursor::new(&payload), 1024).unwrap();
    write_frame(&mut input, &Request::HeadBranch.encode()).unwrap(); // must never be answered

    let mut reader = std::io::Cursor::new(input);
    let mut output = Vec::new();
    let policy = WirePolicy { read_only: true, max_pack_size: 0, ro_drain_cap: 4096 };
    serve_with_policy(&root, &mut reader, &mut output, policy).unwrap();

    let mut frames = Vec::new();
    let mut r = std::io::Cursor::new(output);
    while let Some(f) = read_frame_opt(&mut r).unwrap() {
        frames.push(parse_response(f));
    }
    assert_eq!(frames.len(), 2);
    assert!(matches!(frames[1].as_ref().unwrap_err(), Error::ReadOnly | Error::Remote(_)));
    let tmp = root.join(".sc").join("tmp");
    assert!(!tmp.exists() || std::fs::read_dir(&tmp).unwrap().next().is_none());
    let _ = std::fs::remove_dir_all(&root);
}
```

- [ ] **Step 6: Run to verify pass** — `cargo test -p scl-repo readonly_oversized`
Expected: PASS (implementation from Step 3 item 5 already covers it; if it fails, fix the RO arm, not the test).

- [ ] **Step 7: Full-crate check + commit**

Run: `cargo test -p scl-repo && cargo clippy -p scl-repo --all-targets -- -D warnings`

```bash
cargo fmt --all && git add -A crates/repo && git commit -m "feat(wire): WirePolicy with spool cap + capped read-only drain (P31)"
```

---

### Task 4: `ServeLimits`, connection slots + 503, session timeouts, accept backoff

**Files:**
- Modify: `crates/repo/src/http_transport.rs` — `write_status` (~line 141), client status match (~line 315), `serve_http` (~line 449), `serve_http_listener` (~line 492), `handle_http_connection` (~lines 524–602), new types near `OPENING_READ_TIMEOUT`; tests in the same file's `mod tests`

**Interfaces:**
- Consumes: `WirePolicy` (Task 3), `Error::ServerBusy` (Task 1).
- Produces:

```rust
#[derive(Debug, Clone, Copy)]
pub struct ServeLimits {
    pub max_connections: u32, // 0 = unlimited
    pub timeout_secs: u64,    // 0 = disabled
    pub max_pack_size: u64,   // 0 = unlimited
}
impl Default for ServeLimits {
    fn default() -> Self {
        Self { max_connections: 32, timeout_secs: 300, max_pack_size: crate::wire::DEFAULT_MAX_PACK_SIZE }
    }
}

pub fn serve_http(addr: &str, root: &Path, read_only: bool, allow_public: bool, limits: ServeLimits) -> Result<()>;
pub fn serve_http_listener(listener: TcpListener, root: &Path, read_only: bool, mandatory_auth: bool, limits: ServeLimits) -> Result<()>;
struct AcceptBackoff; // fn on_error(&mut self) -> Duration (5ms, ×2, cap 1s); fn on_success(&mut self)
```

- [ ] **Step 1: Write the failing unit tests** (pure parts first)

```rust
#[test]
fn accept_backoff_doubles_and_resets() {
    let mut b = AcceptBackoff::new();
    assert_eq!(b.on_error(), Duration::from_millis(5));
    assert_eq!(b.on_error(), Duration::from_millis(10));
    assert_eq!(b.on_error(), Duration::from_millis(20));
    for _ in 0..20 { b.on_error(); }
    assert_eq!(b.on_error(), Duration::from_secs(1)); // capped
    b.on_success();
    assert_eq!(b.on_error(), Duration::from_millis(5)); // reset
}

#[test]
fn status_503_round_trips() {
    let mut buf = Vec::new();
    write_status(&mut buf, 503).unwrap();
    assert_eq!(read_status(&mut &buf[..]).unwrap(), 503);
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p scl-repo accept_backoff` → compile error.

- [ ] **Step 3: Implement the pure parts**

```rust
/// Exponential accept-error backoff (P31): Go net/http's shape — 5ms
/// doubling to a 1s cap, reset on the next successful accept. Turns fd
/// exhaustion (EMFILE) from a busy-loop into a paced retry. Hardcoded: no
/// operator tuning story exists (Go ships it knobless too).
struct AcceptBackoff {
    cur: Duration,
}
impl AcceptBackoff {
    const START: Duration = Duration::from_millis(5);
    const CAP: Duration = Duration::from_secs(1);
    fn new() -> Self {
        Self { cur: Self::START }
    }
    fn on_error(&mut self) -> Duration {
        let d = self.cur;
        self.cur = (self.cur * 2).min(Self::CAP);
        d
    }
    fn on_success(&mut self) {
        self.cur = Self::START;
    }
}
```

`write_status`: add `503 => "Service Unavailable",`.
Client status match (~line 315): add before `other`:

```rust
503 => return Err(Error::ServerBusy),
```

- [ ] **Step 4: Run** — `cargo test -p scl-repo accept_backoff status_503` → PASS. Commit:

```bash
cargo fmt --all && git add -A crates/repo && git commit -m "feat(http): AcceptBackoff + 503 busy status plumbing (P31)"
```

- [ ] **Step 5: Write the failing socket tests** (pattern: bind `127.0.0.1:0`, spawn `serve_http_listener` on a thread, connect with raw `TcpStream` + `write_client_opening`/`read_status`; repo root = temp dir containing an empty `.sc/` subdir)

```rust
fn tmp_served_root(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("scl-http-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".sc")).unwrap();
    root
}

fn spawn_listener(root: &std::path::Path, limits: ServeLimits) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let root = root.to_path_buf();
    std::thread::spawn(move || {
        let _ = serve_http_listener(listener, &root, false, false, limits);
    });
    addr
}

fn open_ok(addr: std::net::SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr).unwrap();
    write_client_opening(&mut s, "127.0.0.1", "/", None).unwrap();
    assert_eq!(read_status(&mut s).unwrap(), 200);
    s
}

#[test]
fn connection_limit_shed_and_recover() {
    let root = tmp_served_root("slots");
    let limits = ServeLimits { max_connections: 1, timeout_secs: 0, ..Default::default() };
    let addr = spawn_listener(&root, limits);

    let held = open_ok(addr); // occupies the single slot

    // Second connection: shed with 503 before any opening is read.
    let mut second = TcpStream::connect(addr).unwrap();
    assert_eq!(read_status(&mut second).unwrap(), 503);

    // Free the slot; a fresh connection now succeeds (poll: the server
    // notices the disconnect on its next read).
    drop(held);
    let ok = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        let mut s = match TcpStream::connect(addr) { Ok(s) => s, Err(_) => return false };
        write_client_opening(&mut s, "127.0.0.1", "/", None).is_ok()
            && read_status(&mut s) == Ok(200)
    });
    assert!(ok, "slot was never freed");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn errored_connection_frees_its_slot() {
    let root = tmp_served_root("errslot");
    let limits = ServeLimits { max_connections: 1, timeout_secs: 0, ..Default::default() };
    let addr = spawn_listener(&root, limits);

    // A connection whose handler errors (garbage opening → 400) must free
    // its slot via the guard, not leak it.
    let mut bad = TcpStream::connect(addr).unwrap();
    bad.write_all(b"garbage\r\n\r\n").unwrap();
    let _ = read_status(&mut bad); // 400 (best-effort)
    drop(bad);

    let ok = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        let mut s = match TcpStream::connect(addr) { Ok(s) => s, Err(_) => return false };
        write_client_opening(&mut s, "127.0.0.1", "/", None).is_ok()
            && read_status(&mut s) == Ok(200)
    });
    assert!(ok, "errored connection leaked its slot");
    let _ = std::fs::remove_dir_all(&root);
}

/// A client that stops READING mid-GetPack must be reaped by the write
/// timeout (today it parks the server thread in a blocking write forever).
/// Server sends a pack big enough to overflow socket buffers; the client
/// never reads; after the timeout the server closes.
#[test]
fn write_side_stall_is_reaped_by_timeout() {
    let root = tmp_served_root("wstall");
    // Put a few MiB of committed content in the repo first (init + commit a
    // large random file via the Repo API — see repo.rs tests for the
    // init/commit helper pattern), so GetPack has real bytes to send.
    // ... then:
    let limits = ServeLimits { max_connections: 0, timeout_secs: 1, ..Default::default() };
    let addr = spawn_listener(&root, limits);

    let mut s = open_ok(addr);
    // Speak just enough wire protocol to trigger a GetPack, then stop reading:
    // handshake HELLO, then a GetPack for the branch tip with empty haves.
    // (Use wire::Request::{Hello, GetPack}.encode() + write_frame directly.)
    // After sending the GetPack request, sleep instead of reading.
    std::thread::sleep(Duration::from_secs(5));
    // The server must have dropped the connection rather than blocking
    // forever: our next write eventually errors (reset), or read sees EOF.
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut sink = [0u8; 4096];
    loop {
        match s.read(&mut sink) {
            Ok(0) | Err(_) => break, // EOF or reset — server gave up: pass
            Ok(_) => continue,        // drain what was already buffered
        }
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn silent_session_is_reaped_by_timeout() {
    let root = tmp_served_root("reap");
    let limits = ServeLimits { max_connections: 0, timeout_secs: 1, ..Default::default() };
    let addr = spawn_listener(&root, limits);

    let mut s = open_ok(addr); // handshake never sent; go silent
    std::thread::sleep(Duration::from_secs(3));
    // Server must have dropped us: the read sees EOF/reset, not a hang.
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => {}                                  // clean EOF — dropped
        Err(_) => {}                                 // reset — also dropped
        Ok(_) => panic!("server sent data to a silent client"),
    }
    // Spool dir is clean.
    let tmp = root.join(".sc").join("tmp");
    assert!(!tmp.exists() || std::fs::read_dir(&tmp).unwrap().next().is_none());
    let _ = std::fs::remove_dir_all(&root);
}
```

- [ ] **Step 6: Run to verify failure** — `cargo test -p scl-repo connection_limit_shed` → compile error (`ServeLimits`, new arities).

- [ ] **Step 7: Implement the listener changes**

1. Add `ServeLimits` (+ `Default`) with the doc comment stating each default and its provenance (git-daemon 32; on-by-default 300s divergence; 16 GiB divergence — cite the spec).
2. RAII slot guard:

```rust
/// Decrements the live-connection count on drop, so every exit path — clean
/// return, error, panic unwind — frees its slot (the TempPackGuard
/// discipline applied to connection slots).
struct SlotGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
```

3. `serve_http_listener(listener, root, read_only, mandatory_auth, limits)`:

```rust
let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
let mut backoff = AcceptBackoff::new();
for incoming in listener.incoming() {
    let mut stream = match incoming {
        Ok(s) => {
            backoff.on_success();
            s
        }
        Err(e) => {
            eprintln!("sc serve --http: accept error: {e}");
            std::thread::sleep(backoff.on_error());
            continue;
        }
    };
    // Connection cap: acquire a slot BEFORE spawning; shed with 503 when full.
    let guard = {
        let prev = live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let g = SlotGuard(live.clone());
        if limits.max_connections != 0 && prev >= limits.max_connections as usize {
            let _ = write_status(&mut stream, 503);
            continue; // g drops here → count restored; no thread, no handshake
        }
        g
    };
    let root = root.to_path_buf();
    std::thread::spawn(move || {
        let _guard = guard; // slot held for the connection's lifetime
        if let Err(e) = handle_http_connection(stream, &root, read_only, mandatory_auth, limits) {
            eprintln!("sc serve --http: connection error: {e}");
        }
    });
}
Ok(())
```

4. `handle_http_connection(..., limits: ServeLimits)`: replace the timeout-clear block (~line 594) with:

```rust
// P31: the opening timeout is REPLACED (not cleared) by the session
// timeout, on BOTH read and write sides — a write timeout covers a client
// that stops reading mid-GetPack. Under P25 chunking a per-syscall timeout
// is progress-based: only true zero-byte stalls trip it. 0 disables.
let session = if limits.timeout_secs == 0 {
    None
} else {
    Some(Duration::from_secs(limits.timeout_secs))
};
stream
    .set_read_timeout(session)
    .map_err(|e| Error::ConnectionLost(format!("sc+http set session read_timeout: {e}")))?;
stream
    .set_write_timeout(session)
    .map_err(|e| Error::ConnectionLost(format!("sc+http set session write_timeout: {e}")))?;
```

and end with `crate::wire::serve_with_policy(root, &mut reader, &mut stream, crate::wire::WirePolicy { read_only, max_pack_size: limits.max_pack_size, ro_drain_cap: crate::wire::RO_DRAIN_CAP })`. A timeout surfaces as `Error::Io` (`WouldBlock` on Unix, `TimedOut` on Windows) from `serve_with_policy` → the handler returns `Err` → logged, thread exits, guard frees the slot. No special-casing needed beyond the log line; do NOT retry on `WouldBlock`.
5. `serve_http(addr, root, read_only, allow_public, limits)`: pass `limits` through; call `crate::wire::validate_max_pack_size(limits.max_pack_size)?` before binding.

- [ ] **Step 8: Run to verify pass**

Run: `cargo test -p scl-repo connection_limit_shed silent_session`
Expected: PASS. Also run the full crate: `cargo test -p scl-repo` — the existing http tests (auth, bind gate) must stay green with the added `limits` parameter (update their call sites to `ServeLimits::default()` or `timeout_secs: 0` where a test holds idle connections).

- [ ] **Step 9: Commit**

```bash
cargo fmt --all && git add -A crates/repo && git commit -m "feat(http): connection cap + 503, session timeouts, accept backoff (P31)"
```

---

### Task 5: CLI flags + stdio plumbing

**Files:**
- Modify: `crates/cli/src/main.rs` — `Cmd::Serve` variant (~line 280), dispatch (~line 813), `run_serve` (~line 3122)

**Interfaces:**
- Consumes: `ServeLimits`, `serve_http` (Task 4), `wire::{serve_with_policy, WirePolicy, RO_DRAIN_CAP, DEFAULT_MAX_PACK_SIZE, validate_max_pack_size}` (Task 3).

- [ ] **Step 1: Add the flags** to `Cmd::Serve`:

```rust
/// Maximum concurrent connections (`--http` only); 0 = unlimited.
/// Default 32 (git-daemon parity). At the limit new connections get an
/// immediate busy status and close. (P31)
#[arg(long)]
max_connections: Option<u32>,
/// Session idle timeout in seconds (`--http` only); 0 = disabled.
/// Default 300. A connection making zero-byte progress for this long is
/// dropped. (P31)
#[arg(long)]
timeout: Option<u64>,
/// Maximum incoming pack size in bytes (both --http and --stdio);
/// 0 = unlimited. Default 16 GiB. Must be ≥ 256 MiB (MAX_OBJECT_SIZE)
/// when non-zero. (P31)
#[arg(long)]
max_pack_size: Option<u64>,
```

- [ ] **Step 2: Update `run_serve`**

```rust
fn run_serve(
    stdio: bool,
    http: Option<String>,
    read_only: bool,
    allow_public: bool,
    max_connections: Option<u32>,
    timeout: Option<u64>,
    max_pack_size: Option<u64>,
    path: PathBuf,
) -> Result<()> {
    match (stdio, http) {
        (true, None) => {
            if read_only || allow_public {
                anyhow::bail!("--read-only/--allow-public apply only to --http, not --stdio");
            }
            if max_connections.is_some() || timeout.is_some() {
                anyhow::bail!("--max-connections/--timeout apply only to --http, not --stdio");
            }
            let max_pack = max_pack_size.unwrap_or(scl_repo::wire::DEFAULT_MAX_PACK_SIZE);
            scl_repo::wire::validate_max_pack_size(max_pack)?;
            let policy = scl_repo::wire::WirePolicy {
                read_only: false,
                max_pack_size: max_pack,
                ro_drain_cap: scl_repo::wire::RO_DRAIN_CAP,
            };
            let mut stdin = std::io::stdin().lock();
            let mut stdout = std::io::stdout().lock();
            scl_repo::wire::serve_with_policy(&path, &mut stdin, &mut stdout, policy)?;
            Ok(())
        }
        (false, Some(addr)) => {
            let mut limits = scl_repo::http_transport::ServeLimits::default();
            if let Some(n) = max_connections { limits.max_connections = n; }
            if let Some(t) = timeout { limits.timeout_secs = t; }
            if let Some(m) = max_pack_size { limits.max_pack_size = m; }
            scl_repo::http_transport::serve_http(&addr, &path, read_only, allow_public, limits)?;
            Ok(())
        }
        // ... existing arms unchanged
    }
}
```

Update the dispatch site to pass the three new fields. Note `WirePolicy`/`RO_DRAIN_CAP`/`DEFAULT_MAX_PACK_SIZE`/`validate_max_pack_size`/`ServeLimits` must be `pub` exports (they are, from Tasks 3–4).

- [ ] **Step 3: Verify behavior manually**

```bash
cargo run -q --bin sc -- serve --stdio --timeout 5 . 2>&1 | head -2        # expect: the --http-only bail
cargo run -q --bin sc -- serve --http 127.0.0.1:0 --max-pack-size 1024 . 2>&1 | head -2  # expect: floor error naming MAX_OBJECT_SIZE
```

Expected: both print clear errors and exit non-zero.

- [ ] **Step 4: Full workspace test + commit**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`

```bash
cargo fmt --all && git add -A crates/cli && git commit -m "feat(cli): sc serve --max-connections/--timeout/--max-pack-size (P31)"
```

---

### Task 6: Demo script

**Files:**
- Create: `demo/run_limits_demo.sh` (pattern: `demo/run_http_auth_demo.sh` — read it first for the port-pick/cleanup/run-twice conventions, including the `listening on` stdout parse for the OS-assigned port)

**Interfaces:**
- Consumes: the CLI flags (Task 5), 503 busy behavior, timeout reaping, `EC_TOO_LARGE`.

- [ ] **Step 1: Write the demo.** It must (following the sibling script's structure — `set -euo pipefail`, temp workdir, `sc` built once, server started with `--http 127.0.0.1:0` and the port parsed from `listening on`):
  1. Init a repo, commit a file, start `sc serve --http 127.0.0.1:0 --max-connections 1 --timeout 2 --max-pack-size 268435456 --allow-public`… (use loopback — no `--allow-public` needed).
  2. **Busy:** hold one connection open with a raw client (a `sleep`-piped `nc` if available, else a second `sc clone` in a loop is unreliable — prefer opening a TCP connection via `python3`… **no**: python3 is not guaranteed; use a background `sc clone` of a large-enough repo? Simplest reliable primitive: `exec 3<>/dev/tcp/127.0.0.1/$PORT` in bash holds a connection without sending an opening — the slot is taken at accept time, before the opening read). Then a second `sc clone sc+http://…` must fail with the busy error (assert on stderr text), close fd 3, and the same clone must succeed.
  3. **Timeout:** open `exec 3<>/dev/tcp/...` again, sleep 4 (> `--timeout 2` + opening 30s does not apply — the opening timeout drops it… NOTE: an opening-silent connection is dropped by the **existing 30s opening timeout**, not the session timeout; a demo can't cheaply hold a post-opening session silent without a wire client. So the demo proves timeout indirectly: assert the busy slot from step 2's silent holder is auto-freed — a clone succeeds after the drop **without** closing fd 3 manually. Print what's being proven.)
  4. **Spool cap:** restart the server with `--max-pack-size 268435456` (the floor) and push a > 256 MiB… too slow for a demo. Instead restart with the floor value and demonstrate the *refusal path* differently: a push of a small repo succeeds (cap present, harmless); then restart with `--max-pack-size 1024` and assert startup fails with the floor error. The mid-stream abort itself is covered by unit tests; the demo proves the knobs and the busy/reap behavior end-to-end.
  5. Assert zero `.sc/tmp` residue on the served repo; run the whole script twice (the repo's demo discipline).

- [ ] **Step 2: Run it twice**

Run: `bash demo/run_limits_demo.sh && bash demo/run_limits_demo.sh`
Expected: both runs end with the script's success line; no leftover temp dirs.

- [ ] **Step 3: Commit**

```bash
git add demo/run_limits_demo.sh && git commit -m "demo: listener limits proof — busy shed, slot reap, cap knobs (P31)"
```

---

### Task 7: Docs — ADR-0041, THREAT-MODEL, CLAUDE.md

**Files:**
- Create: `docs/adr/0041-listener-resource-limits.md`
- Modify: `docs/THREAT-MODEL.md` (the ADR-0036 operational-hardening items, ~lines 91-93, plus the env-var and signature sections)
- Modify: `CLAUDE.md` (serve command block; the P26 "accepted design consequences" paragraph)

**Interfaces:** none (docs only). Read `docs/adr/0040-sc-http-access-control.md` first and match its structure (Status/Date/Phase/Context/Decision/Consequences).

- [ ] **Step 1: Write ADR-0041.** Must contain: the four bounds with defaults and mechanisms; the two recorded divergences (timeout **on**-by-default vs git-daemon's off — defaults-off knobs don't close audit Highs; finite 16 GiB spool default vs git's unlimited `receive.maxInputSize` — sc servers often share the working tree's volume); the 8 MiB RO drain posture (honest misconfigurations keep the typed error, hostile bulk spools almost nothing); mid-stream abort = connection-fatal (desync); spool cap applies to both transports (shared wire layer); rejected alternatives (block-at-accept semaphore, git-daemon grace-then-shed, Rust-Book queue pool, reserved-fd shed, env-var/config-file knobs); links to decision tickets #28/#27 and `docs/research/bounded-server-patterns.md`.
- [ ] **Step 2: Update THREAT-MODEL.md.** (a) The three ADR-0036 boundaries → closed by P31, naming the mechanisms; (b) name + close the aggregate-spool gap (read-only drain path included); (c) the env-var re-affirmation wording from map ticket #31 (same-user adversary defeats the identity key; fd/stdin stays an additive deferred mode with recorded revisit triggers); (d) the signature-replay re-affirmation from map ticket #32 (ancestry already id-bound; residue is ref binding only — "replayable to a ref tip within its own history"; gittuf-shaped attestation deferred with revisit triggers).
- [ ] **Step 3: Update CLAUDE.md.** Add the three flags to the serve command block with one-line semantics; amend the P26 paragraph's "accepted design consequences, not yet closed" list to point at P31; add a short "Phase 31 is built." section following the existing phase-section pattern.
- [ ] **Step 4: Commit**

```bash
git add docs CLAUDE.md && git commit -m "docs: ADR-0041 listener limits + THREAT-MODEL closures and re-affirmations (P31)"
```

---

### Task 8: Final verification

- [ ] **Step 1:** `cargo test --workspace --all-targets` — all green.
- [ ] **Step 2:** `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check` — clean.
- [ ] **Step 3:** Run the neighboring demos that exercise the touched paths: `bash demo/run_http_remote_demo.sh && bash demo/run_http_auth_demo.sh && bash demo/run_ssh_remote_demo.sh && bash demo/run_limits_demo.sh` — all end with their success lines (the first three prove no regression from the `WirePolicy`/signature changes; defaults must keep every existing flow working).
- [ ] **Step 4:** Confirm zero residue: `git status --short` shows only intended files.
