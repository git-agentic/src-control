# SSH-Native Network Transport (P12) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc clone / fetch / push` work against `ssh://` remotes by speaking a framed stdio protocol to `sc serve --stdio` spawned on the far side.

**Architecture:** The 8-verb `Transport` trait is mirrored 1:1 onto a length-prefixed binary wire protocol. The server (`sc serve --stdio`) is a dispatch loop around the existing `LocalTransport`, so CAS ref updates, pack verification, and BLAKE3-on-read are reused verbatim. The client (`StdioTransport`) implements `Transport` over a child process's stdin/stdout — `ssh host sc serve --stdio <path>` for real remotes, an `SC_SSH` shim for tests/demo. Spec: `docs/superpowers/specs/2026-07-05-ssh-native-transport-design.md`.

**Tech Stack:** Rust stable, std only (no new dependencies). Tests use `std::io::pipe` (stable since Rust 1.87).

## Global Constraints

- **No new crate dependencies.** Everything is `std` + existing workspace deps.
- **Dependency rule:** `cli → repo → {vfs, gitio, crypto} → core`. All new code lives in `crates/repo` and `crates/cli`. `gix` stays in `gitio`; nothing here touches it.
- Every public type/fn gets a doc comment explaining **intent, not mechanics**.
- Errors: `thiserror` variants in `crates/repo/src/error.rs`; CLI uses `anyhow` + `?`.
- Tests live in `#[cfg(test)] mod tests` next to the code; integration tests in `crates/cli/tests/`. Tests that touch disk create temp dirs under `std::env::temp_dir()` and **remove them at the end** (existing pattern: `tmp_remote` in `crates/repo/src/transport.rs:199`).
- Wire protocol version is `1`. Frames are `u32` big-endian length + payload (max ~4 GiB by construction).
- Known accepted limitation (document, don't fix): repo paths containing spaces are unsupported over real ssh (the remote shell splits the command); the `SC_SSH` shim and tests are unaffected (no shell involved).
- Run `cargo test --workspace` before each commit; all tests must pass.

## File map (whole phase)

| File | Change |
|---|---|
| `crates/repo/src/error.rs` | Add `Protocol`, `ConnectionLost`, `Remote` variants |
| `crates/repo/src/wire.rs` | **New**: frame codec, `Request`, response/error mapping, `serve()` |
| `crates/repo/src/stdio_transport.rs` | **New**: `WireClient`, `StdioTransport`, `SshUrl`, `open_transport()` |
| `crates/repo/src/lib.rs` | Register + re-export the two new modules |
| `crates/repo/src/sync.rs` | `clone_url`, fetch/push via `open_transport`, `&dyn Transport` |
| `crates/cli/src/main.rs` | `sc serve --stdio`, `Clone.src: String`, ssh URL validation on `remote add` |
| `crates/cli/tests/ssh_remote.rs` | **New**: end-to-end integration tests via `SC_SSH` shim |
| `demo/run_ssh_remote_demo.sh` | **New**: self-contained proof script |
| `docs/adr/0022-ssh-native-transport.md` | **New** ADR |
| `ARCHITECTURE.md`, `CLAUDE.md` | Phase 12 section + command list |

---

### Task 1: Wire codec — error variants, framing, `Request`, response encoding

**Files:**
- Modify: `crates/repo/src/error.rs`
- Create: `crates/repo/src/wire.rs`
- Modify: `crates/repo/src/lib.rs`

**Interfaces:**
- Consumes: `scl_core::ObjectId` (`as_bytes() -> &[u8;32]`, `from_bytes([u8;32])`), `crate::error::{Error, Result}`.
- Produces (used by Tasks 2–3):
  - `wire::PROTOCOL_VERSION: u32`
  - `enum Request { Hello{version:u32}, Bye, ListRefs, HeadBranch, HasObject(ObjectId), GetObject(ObjectId), PutObject{id:ObjectId, bytes:Vec<u8>}, UpdateRef{branch:String, id:ObjectId, expected_old:Option<ObjectId>}, GetPack{wants:Vec<ObjectId>, haves:Vec<ObjectId>}, PutPack(Vec<u8>) }` with `encode(&self) -> Vec<u8>` and `decode(&[u8]) -> Result<Request>`; derives `Debug, Clone, PartialEq`.
  - Frame IO: `write_frame(w, payload)`, `read_frame(r) -> Result<Vec<u8>>` (EOF ⇒ `ConnectionLost`), `read_frame_opt(r) -> Result<Option<Vec<u8>>>` (clean EOF at a frame boundary ⇒ `None`).
  - Responses: `write_ok(w, body)`, `write_err(w, code, msg)`, `parse_response(frame) -> Result<Vec<u8>>` (OK body, or the typed error).
  - Error mapping: `err_to_wire(&Error) -> (u8, String)`, `err_from_wire(code, msg) -> Error`.
  - Body builders/decoders (symmetric pairs): `u32_body/decode_u32_body`, `str_body/decode_str_body`, `bool_body/decode_bool_body`, `ids_body/decode_ids_body`, `refs_body/decode_refs_body`.
- New error variants (used everywhere): `Error::Protocol(String)`, `Error::ConnectionLost(String)`, `Error::Remote(String)`.

- [ ] **Step 1: Add error variants**

In `crates/repo/src/error.rs`, add to `enum Error` (after `NoCommonAncestor`):

```rust
    #[error("wire protocol error: {0}")]
    Protocol(String),
    #[error("connection to remote lost: {0}")]
    ConnectionLost(String),
    #[error("remote error: {0}")]
    Remote(String),
```

- [ ] **Step 2: Write the failing tests**

Create `crates/repo/src/wire.rs` with a tests module only (implementation comes in Step 4). Register in `crates/repo/src/lib.rs`: add `pub mod wire;` alphabetically among the existing `pub mod` lines.

```rust
//! Wire protocol for sc-native network transport (P12).
//!
//! Mirrors the [`crate::transport::Transport`] verbs 1:1 over length-prefixed
//! binary frames, so a remote repo behind `sc serve --stdio` behaves exactly
//! like a local one. See ADR-0022.

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::ObjectId;

    fn some_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    #[test]
    fn every_request_encodes_and_decodes_roundtrip() {
        let reqs = vec![
            Request::Hello { version: PROTOCOL_VERSION },
            Request::Bye,
            Request::ListRefs,
            Request::HeadBranch,
            Request::HasObject(some_id(1)),
            Request::GetObject(some_id(2)),
            Request::PutObject { id: some_id(3), bytes: b"payload".to_vec() },
            Request::UpdateRef { branch: "main".into(), id: some_id(4), expected_old: None },
            Request::UpdateRef { branch: "dev".into(), id: some_id(5), expected_old: Some(some_id(6)) },
            Request::GetPack { wants: vec![some_id(7)], haves: vec![some_id(8), some_id(9)] },
            Request::GetPack { wants: vec![], haves: vec![] },
            Request::PutPack(b"packbytes".to_vec()),
        ];
        for req in reqs {
            let bytes = req.encode();
            assert_eq!(Request::decode(&bytes).unwrap(), req, "roundtrip failed for {req:?}");
        }
    }

    #[test]
    fn truncated_and_junk_requests_are_protocol_errors() {
        // Truncated HasObject: opcode but only half an id.
        let mut bytes = Request::HasObject(some_id(1)).encode();
        bytes.truncate(10);
        assert!(matches!(Request::decode(&bytes), Err(crate::error::Error::Protocol(_))));
        // Unknown opcode.
        assert!(matches!(Request::decode(&[0x7f]), Err(crate::error::Error::Protocol(_))));
        // Empty frame.
        assert!(matches!(Request::decode(&[]), Err(crate::error::Error::Protocol(_))));
        // Trailing garbage after a well-formed request.
        let mut bytes = Request::Bye.encode();
        bytes.push(0);
        assert!(matches!(Request::decode(&bytes), Err(crate::error::Error::Protocol(_))));
    }

    #[test]
    fn frame_io_roundtrips_and_eof_is_typed() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut r).unwrap(), b"hello");
        assert_eq!(read_frame(&mut r).unwrap(), b"");
        // Client-style read: EOF is a lost connection.
        assert!(matches!(read_frame(&mut r), Err(crate::error::Error::ConnectionLost(_))));
        // Server-style read: EOF at a frame boundary is a clean end-of-session.
        let mut r2 = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame_opt(&mut r2).unwrap().is_none());
        // EOF mid-frame is a protocol error even for the server.
        let mut r3 = std::io::Cursor::new(vec![0, 0, 0, 9, b'x']);
        assert!(matches!(read_frame_opt(&mut r3), Err(crate::error::Error::Protocol(_))));
    }

    #[test]
    fn responses_carry_ok_bodies_and_typed_errors() {
        let mut buf: Vec<u8> = Vec::new();
        write_ok(&mut buf, b"body").unwrap();
        let mut r = std::io::Cursor::new(buf);
        assert_eq!(parse_response(read_frame(&mut r).unwrap()).unwrap(), b"body");

        // Typed errors survive the wire.
        for (err, expect_nff, expect_nar) in [
            (crate::error::Error::NonFastForward, true, false),
            (crate::error::Error::NotARepo, false, true),
        ] {
            let (code, msg) = err_to_wire(&err);
            let mut buf: Vec<u8> = Vec::new();
            write_err(&mut buf, code, &msg).unwrap();
            let mut r = std::io::Cursor::new(buf);
            let back = parse_response(read_frame(&mut r).unwrap()).unwrap_err();
            assert_eq!(matches!(back, crate::error::Error::NonFastForward), expect_nff);
            assert_eq!(matches!(back, crate::error::Error::NotARepo), expect_nar);
        }

        // Untyped errors become Remote(msg) and keep their message.
        let (code, msg) = err_to_wire(&crate::error::Error::Unborn);
        let back = err_from_wire(code, msg);
        match back {
            crate::error::Error::Remote(m) => assert!(m.contains("unborn"), "message lost: {m}"),
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    #[test]
    fn body_helpers_roundtrip() {
        assert_eq!(decode_u32_body(&u32_body(7)).unwrap(), 7);
        assert_eq!(decode_str_body(&str_body("main")).unwrap(), "main");
        assert!(decode_bool_body(&bool_body(true)).unwrap());
        assert!(!decode_bool_body(&bool_body(false)).unwrap());
        let ids = vec![some_id(1), some_id(2)];
        assert_eq!(decode_ids_body(&ids_body(&ids)).unwrap(), ids);
        let refs = vec![("dev".to_string(), some_id(3)), ("main".to_string(), some_id(4))];
        assert_eq!(decode_refs_body(&refs_body(&refs)).unwrap(), refs);
        // Truncated bodies are protocol errors, not panics.
        assert!(matches!(decode_refs_body(&[0, 0, 0, 5]), Err(crate::error::Error::Protocol(_))));
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p scl-repo wire::`
Expected: FAIL to compile — `PROTOCOL_VERSION`, `Request`, etc. not defined.

- [ ] **Step 4: Implement the codec**

Fill in `crates/repo/src/wire.rs` above the tests module:

```rust
use std::io::{Read, Write};

use scl_core::ObjectId;

use crate::error::{Error, Result};

/// Protocol version spoken by this build. Bumped only on incompatible changes;
/// both sides exchange it in `HELLO` before any repo access.
pub const PROTOCOL_VERSION: u32 = 1;

// Request opcodes (one per Transport verb, plus session control).
const OP_HELLO: u8 = 0x01;
const OP_BYE: u8 = 0x02;
const OP_LIST_REFS: u8 = 0x10;
const OP_HEAD_BRANCH: u8 = 0x11;
const OP_HAS_OBJECT: u8 = 0x12;
const OP_GET_OBJECT: u8 = 0x13;
const OP_PUT_OBJECT: u8 = 0x14;
const OP_UPDATE_REF: u8 = 0x15;
const OP_GET_PACK: u8 = 0x16;
const OP_PUT_PACK: u8 = 0x17;

// Response status bytes.
const ST_OK: u8 = 0;
const ST_ERR: u8 = 1;

// Wire error codes. Typed errors that sync logic relies on get their own code;
// everything else degrades to EC_OTHER and surfaces as `Error::Remote(msg)`.
const EC_NOT_A_REPO: u8 = 1;
const EC_NON_FAST_FORWARD: u8 = 2;
const EC_NOT_FOUND: u8 = 3;
const EC_PROTOCOL: u8 = 4;
const EC_OTHER: u8 = 255;

/// A client request — the wire mirror of one [`crate::transport::Transport`]
/// verb (plus `Hello`/`Bye` session control).
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Hello { version: u32 },
    Bye,
    ListRefs,
    HeadBranch,
    HasObject(ObjectId),
    GetObject(ObjectId),
    PutObject { id: ObjectId, bytes: Vec<u8> },
    UpdateRef { branch: String, id: ObjectId, expected_old: Option<ObjectId> },
    GetPack { wants: Vec<ObjectId>, haves: Vec<ObjectId> },
    PutPack(Vec<u8>),
}

// --- field encoding helpers (length-prefixed, matching core's canonical style) ---

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    // A field can't exceed the u32 frame limit; write_frame enforces the total.
    put_u32(out, u32::try_from(b.len()).expect("field exceeds frame limit"));
    out.extend_from_slice(b);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

fn put_id(out: &mut Vec<u8>, id: &ObjectId) {
    out.extend_from_slice(id.as_bytes());
}

fn put_ids(out: &mut Vec<u8>, ids: &[ObjectId]) {
    put_u32(out, ids.len() as u32);
    for id in ids {
        put_id(out, id);
    }
}

/// Bounds-checked read cursor over one frame's payload.
struct Cur<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Cur<'a> {
        Cur { b, off: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.off.checked_add(n).filter(|&e| e <= self.b.len());
        let end = end.ok_or_else(|| Error::Protocol("truncated frame".into()))?;
        let s = &self.b[self.off..end];
        self.off = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn id(&mut self) -> Result<ObjectId> {
        Ok(ObjectId::from_bytes(self.take(32)?.try_into().unwrap()))
    }
    fn ids(&mut self) -> Result<Vec<ObjectId>> {
        let n = self.u32()? as usize;
        (0..n).map(|_| self.id()).collect()
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| Error::Protocol("non-utf8 string".into()))
    }
    /// The whole frame must be consumed — trailing bytes mean a codec mismatch.
    fn done(&self) -> Result<()> {
        if self.off == self.b.len() {
            Ok(())
        } else {
            Err(Error::Protocol("trailing bytes in frame".into()))
        }
    }
}

impl Request {
    /// Canonical payload bytes for this request (framing is the caller's job).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Request::Hello { version } => {
                out.push(OP_HELLO);
                put_u32(&mut out, *version);
            }
            Request::Bye => out.push(OP_BYE),
            Request::ListRefs => out.push(OP_LIST_REFS),
            Request::HeadBranch => out.push(OP_HEAD_BRANCH),
            Request::HasObject(id) => {
                out.push(OP_HAS_OBJECT);
                put_id(&mut out, id);
            }
            Request::GetObject(id) => {
                out.push(OP_GET_OBJECT);
                put_id(&mut out, id);
            }
            Request::PutObject { id, bytes } => {
                out.push(OP_PUT_OBJECT);
                put_id(&mut out, id);
                put_bytes(&mut out, bytes);
            }
            Request::UpdateRef { branch, id, expected_old } => {
                out.push(OP_UPDATE_REF);
                put_str(&mut out, branch);
                put_id(&mut out, id);
                match expected_old {
                    Some(old) => {
                        out.push(1);
                        put_id(&mut out, old);
                    }
                    None => out.push(0),
                }
            }
            Request::GetPack { wants, haves } => {
                out.push(OP_GET_PACK);
                put_ids(&mut out, wants);
                put_ids(&mut out, haves);
            }
            Request::PutPack(pack) => {
                out.push(OP_PUT_PACK);
                put_bytes(&mut out, pack);
            }
        }
        out
    }

    /// Parse one frame payload. Any malformation is `Error::Protocol`.
    pub fn decode(payload: &[u8]) -> Result<Request> {
        let mut c = Cur::new(payload);
        let req = match c.u8()? {
            OP_HELLO => Request::Hello { version: c.u32()? },
            OP_BYE => Request::Bye,
            OP_LIST_REFS => Request::ListRefs,
            OP_HEAD_BRANCH => Request::HeadBranch,
            OP_HAS_OBJECT => Request::HasObject(c.id()?),
            OP_GET_OBJECT => Request::GetObject(c.id()?),
            OP_PUT_OBJECT => Request::PutObject { id: c.id()?, bytes: c.bytes()? },
            OP_UPDATE_REF => {
                let branch = c.str()?;
                let id = c.id()?;
                let expected_old = match c.u8()? {
                    0 => None,
                    1 => Some(c.id()?),
                    _ => return Err(Error::Protocol("bad expected_old flag".into())),
                };
                Request::UpdateRef { branch, id, expected_old }
            }
            OP_GET_PACK => Request::GetPack { wants: c.ids()?, haves: c.ids()? },
            OP_PUT_PACK => Request::PutPack(c.bytes()?),
            op => return Err(Error::Protocol(format!("unknown opcode 0x{op:02x}"))),
        };
        c.done()?;
        Ok(req)
    }
}

// --- frame IO ---

/// Write one frame: u32 big-endian payload length, then the payload. Flushes.
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol(format!("frame too large: {} bytes", payload.len())))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read one frame; EOF anywhere is a lost connection (client-side semantics —
/// the client always expects a response).
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>> {
    read_frame_inner(r)?.ok_or_else(|| Error::ConnectionLost("unexpected EOF".into()))
}

/// Read one frame; clean EOF *at a frame boundary* is `None` (server-side
/// semantics — the peer hung up between requests). EOF mid-frame is still an
/// error.
pub fn read_frame_opt(r: &mut impl Read) -> Result<Option<Vec<u8>>> {
    read_frame_inner(r)
}

fn read_frame_inner(r: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        let n = r.read(&mut len_bytes[filled..])?;
        if n == 0 {
            if filled == 0 {
                return Ok(None); // clean EOF at a boundary
            }
            return Err(Error::Protocol("EOF inside frame header".into()));
        }
        filled += n;
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|_| Error::Protocol(format!("EOF inside {len}-byte frame body")))?;
    Ok(Some(buf))
}

// --- responses ---

/// Write a success response with `body`.
pub fn write_ok(w: &mut impl Write, body: &[u8]) -> Result<()> {
    let mut p = Vec::with_capacity(1 + body.len());
    p.push(ST_OK);
    p.extend_from_slice(body);
    write_frame(w, &p)
}

/// Write a typed error response.
pub fn write_err(w: &mut impl Write, code: u8, msg: &str) -> Result<()> {
    let mut p = vec![ST_ERR, code];
    put_str(&mut p, msg);
    write_frame(w, &p)
}

/// Split a response frame into its OK body, or reconstruct the typed error.
pub fn parse_response(frame: Vec<u8>) -> Result<Vec<u8>> {
    let (&status, rest) =
        frame.split_first().ok_or_else(|| Error::Protocol("empty response frame".into()))?;
    match status {
        ST_OK => Ok(rest.to_vec()),
        ST_ERR => {
            let mut c = Cur::new(rest);
            let code = c.u8()?;
            let msg = c.str()?;
            c.done()?;
            Err(err_from_wire(code, msg))
        }
        s => Err(Error::Protocol(format!("bad response status {s}"))),
    }
}

/// Map a repo error onto its wire code + message. Errors sync logic matches on
/// keep their identity; the rest carry only their message.
pub fn err_to_wire(e: &Error) -> (u8, String) {
    let code = match e {
        Error::NotARepo => EC_NOT_A_REPO,
        Error::NonFastForward => EC_NON_FAST_FORWARD,
        Error::Core(scl_core::Error::NotFound(_)) => EC_NOT_FOUND,
        Error::Protocol(_) => EC_PROTOCOL,
        _ => EC_OTHER,
    };
    (code, e.to_string())
}

/// Reconstruct a typed error from its wire code; unknown/untyped codes become
/// `Error::Remote(msg)` so the message is never lost.
pub fn err_from_wire(code: u8, msg: String) -> Error {
    match code {
        EC_NOT_A_REPO => Error::NotARepo,
        EC_NON_FAST_FORWARD => Error::NonFastForward,
        EC_PROTOCOL => Error::Protocol(msg),
        _ => Error::Remote(msg), // EC_NOT_FOUND + EC_OTHER: typed enough as text
    }
}

// --- response body builders/decoders (one symmetric pair per verb shape) ---

pub fn u32_body(v: u32) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, v);
    b
}
pub fn decode_u32_body(b: &[u8]) -> Result<u32> {
    let mut c = Cur::new(b);
    let v = c.u32()?;
    c.done()?;
    Ok(v)
}

pub fn str_body(s: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, s);
    b
}
pub fn decode_str_body(b: &[u8]) -> Result<String> {
    let mut c = Cur::new(b);
    let s = c.str()?;
    c.done()?;
    Ok(s)
}

pub fn bool_body(v: bool) -> Vec<u8> {
    vec![v as u8]
}
pub fn decode_bool_body(b: &[u8]) -> Result<bool> {
    let mut c = Cur::new(b);
    let v = c.u8()?;
    c.done()?;
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Protocol("bad bool".into())),
    }
}

pub fn ids_body(ids: &[ObjectId]) -> Vec<u8> {
    let mut b = Vec::new();
    put_ids(&mut b, ids);
    b
}
pub fn decode_ids_body(b: &[u8]) -> Result<Vec<ObjectId>> {
    let mut c = Cur::new(b);
    let ids = c.ids()?;
    c.done()?;
    Ok(ids)
}

pub fn refs_body(refs: &[(String, ObjectId)]) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, refs.len() as u32);
    for (branch, id) in refs {
        put_str(&mut b, branch);
        put_id(&mut b, id);
    }
    b
}
pub fn decode_refs_body(b: &[u8]) -> Result<Vec<(String, ObjectId)>> {
    let mut c = Cur::new(b);
    let n = c.u32()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let branch = c.str()?;
        let id = c.id()?;
        out.push((branch, id));
    }
    c.done()?;
    Ok(out)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p scl-repo wire::`
Expected: PASS (5 tests). Then `cargo test --workspace` — everything still green.

- [ ] **Step 6: Commit**

```bash
git add crates/repo/src/error.rs crates/repo/src/wire.rs crates/repo/src/lib.rs
git commit -m "feat(repo): wire protocol codec — framed requests/responses mirroring the Transport verbs (P12)"
```

---

### Task 2: Server dispatch loop — `wire::serve`

**Files:**
- Modify: `crates/repo/src/wire.rs`

**Interfaces:**
- Consumes: Task 1's codec; `crate::transport::{LocalTransport, Transport}` (existing).
- Produces (used by Tasks 3 and 5): `pub fn serve(root: &std::path::Path, r: &mut impl Read, w: &mut impl Write) -> Result<()>`.
  Session contract: server expects `Hello` first (else `ERR Protocol`), replies `OK u32_body(PROTOCOL_VERSION)` — or `ERR NotARepo` if `root` has no repo. Then serves verbs until `Bye` or clean EOF. Request decode failure ⇒ `ERR Protocol` + session ends.

- [ ] **Step 1: Write the failing tests**

Append to the tests module in `crates/repo/src/wire.rs`:

```rust
    /// Encode a request sequence into one input byte stream, run `serve`
    /// against it (Cursor in, Vec out), return the response frames.
    fn run_session(root: &std::path::Path, reqs: &[Request]) -> Vec<Result<Vec<u8>>> {
        let mut input = Vec::new();
        for r in reqs {
            write_frame(&mut input, &r.encode()).unwrap();
        }
        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        serve(root, &mut reader, &mut output).unwrap();
        let mut out = Vec::new();
        let mut r = std::io::Cursor::new(output);
        while let Some(frame) = read_frame_opt(&mut r).unwrap() {
            out.push(parse_response(frame));
        }
        out
    }

    fn tmp_repo(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("scl-wire-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        crate::repo::Repo::init(&root).unwrap();
        root
    }

    #[test]
    fn serve_answers_hello_then_verbs_until_bye() {
        let root = tmp_repo("serve");
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let tip = crate::repo::Repo::open(&root).unwrap().commit("t", "c1").unwrap();

        let responses = run_session(
            &root,
            &[
                Request::Hello { version: PROTOCOL_VERSION },
                Request::ListRefs,
                Request::HeadBranch,
                Request::HasObject(tip),
                Request::Bye,
            ],
        );
        assert_eq!(responses.len(), 4); // Bye gets no response
        assert_eq!(decode_u32_body(responses[0].as_ref().unwrap()).unwrap(), PROTOCOL_VERSION);
        let refs = decode_refs_body(responses[1].as_ref().unwrap()).unwrap();
        assert_eq!(refs, vec![("main".to_string(), tip)]);
        assert_eq!(decode_str_body(responses[2].as_ref().unwrap()).unwrap(), "main");
        assert!(decode_bool_body(responses[3].as_ref().unwrap()).unwrap());

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serve_rejects_wrong_version_and_missing_hello() {
        let root = tmp_repo("vers");
        let bad_version = run_session(&root, &[Request::Hello { version: 999 }]);
        assert!(matches!(bad_version[0], Err(Error::Protocol(_))));

        let no_hello = run_session(&root, &[Request::ListRefs]);
        assert!(matches!(no_hello[0], Err(Error::Protocol(_))));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serve_reports_not_a_repo_as_typed_error() {
        let root = std::env::temp_dir().join(format!("scl-wire-norepo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap(); // a dir, but no .sc inside

        let responses = run_session(&root, &[Request::Hello { version: PROTOCOL_VERSION }]);
        assert!(matches!(responses[0], Err(Error::NotARepo)));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serve_ends_cleanly_on_eof_without_bye() {
        let root = tmp_repo("eof");
        // No Bye at the end: input just runs out. serve must return Ok.
        let responses =
            run_session(&root, &[Request::Hello { version: PROTOCOL_VERSION }, Request::ListRefs]);
        assert_eq!(responses.len(), 2);
        assert!(responses[1].is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serve_verb_errors_are_replies_not_session_teardown() {
        let root = tmp_repo("verberr");
        let missing = some_id(0xEE);
        let responses = run_session(
            &root,
            &[
                Request::Hello { version: PROTOCOL_VERSION },
                Request::GetObject(missing), // NotFound on the server
                Request::HeadBranch,         // session must still be alive
                Request::Bye,
            ],
        );
        assert!(responses[1].is_err());
        assert_eq!(decode_str_body(responses[2].as_ref().unwrap()).unwrap(), "main");
        std::fs::remove_dir_all(&root).unwrap();
    }
```

Note: `run_session` uses `crate::repo::Repo::open` and `.commit` — the same calls the existing `get_pack_excludes_haves_and_put_pack_verifies` test in `crates/repo/src/transport.rs:301` makes; if `Repo::open`'s actual name differs (e.g. `Repo::open_at`), match whatever `transport.rs`/`repo.rs` tests use.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo wire::`
Expected: FAIL to compile — `serve` not defined.

- [ ] **Step 3: Implement `serve`**

Add to `crates/repo/src/wire.rs` (below the body helpers):

```rust
use crate::transport::{LocalTransport, Transport};

/// Serve the repo at `root` to one wire-protocol peer until `Bye`/EOF.
///
/// This is the whole server: every verb dispatches onto [`LocalTransport`],
/// so CAS ref updates, pack verification, and hash-verified reads behave
/// exactly as for a local remote. Verb failures are *replies*; only protocol
/// violations end the session.
pub fn serve(root: &std::path::Path, r: &mut impl Read, w: &mut impl Write) -> Result<()> {
    // Handshake: HELLO must come first, and versions must match, before any
    // repo access happens.
    let first = match read_frame_opt(r)? {
        Some(f) => f,
        None => return Ok(()), // peer connected and immediately hung up
    };
    match Request::decode(&first) {
        Ok(Request::Hello { version }) if version == PROTOCOL_VERSION => {}
        Ok(Request::Hello { version }) => {
            write_err(
                w,
                EC_PROTOCOL,
                &format!("unsupported protocol version {version} (server speaks {PROTOCOL_VERSION})"),
            )?;
            return Ok(());
        }
        Ok(_) | Err(_) => {
            write_err(w, EC_PROTOCOL, "expected HELLO as the first request")?;
            return Ok(());
        }
    }
    let transport = match LocalTransport::open(root) {
        Ok(t) => {
            write_ok(w, &u32_body(PROTOCOL_VERSION))?;
            t
        }
        Err(e) => {
            let (code, msg) = err_to_wire(&e);
            write_err(w, code, &msg)?;
            return Ok(());
        }
    };

    loop {
        let frame = match read_frame_opt(r)? {
            Some(f) => f,
            None => return Ok(()), // peer hung up between requests
        };
        let req = match Request::decode(&frame) {
            Ok(req) => req,
            Err(e) => {
                let (code, msg) = err_to_wire(&e);
                write_err(w, code, &msg)?;
                return Ok(());
            }
        };
        let result: Result<Vec<u8>> = match req {
            Request::Bye => return Ok(()),
            Request::Hello { .. } => Err(Error::Protocol("unexpected HELLO mid-session".into())),
            Request::ListRefs => transport.list_refs().map(|refs| refs_body(&refs)),
            Request::HeadBranch => transport.head_branch().map(|s| str_body(&s)),
            Request::HasObject(id) => transport.has_object(&id).map(bool_body),
            Request::GetObject(id) => transport.get_object(&id),
            Request::PutObject { id, bytes } => {
                transport.put_object(&id, &bytes).map(|()| Vec::new())
            }
            Request::UpdateRef { branch, id, expected_old } => {
                transport.update_ref(&branch, &id, expected_old.as_ref()).map(|()| Vec::new())
            }
            Request::GetPack { wants, haves } => transport.get_pack(&wants, &haves),
            Request::PutPack(pack) => transport.put_pack(&pack).map(|ids| ids_body(&ids)),
        };
        match result {
            Ok(body) => write_ok(w, &body)?,
            Err(e) => {
                let (code, msg) = err_to_wire(&e);
                write_err(w, code, &msg)?;
            }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-repo wire::`
Expected: PASS (10 tests). Then `cargo test --workspace`.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/wire.rs
git commit -m "feat(repo): wire::serve — protocol server dispatching onto LocalTransport (P12)"
```

---

### Task 3: Client — `WireClient` + `StdioTransport`

**Files:**
- Create: `crates/repo/src/stdio_transport.rs`
- Modify: `crates/repo/src/lib.rs`

**Interfaces:**
- Consumes: Task 1 codec, Task 2 `serve` (in tests), `crate::transport::Transport`.
- Produces (used by Task 4):
  - `pub struct WireClient<R: Read, W: Write>` with `pub fn handshake(r: R, w: W) -> Result<WireClient<R, W>>` and `pub fn bye(&self) -> Result<()>`; implements `Transport`.
  - `pub struct StdioTransport` with `pub fn spawn(cmd: std::process::Command) -> Result<StdioTransport>`; implements `Transport`; `Drop` sends `Bye` and reaps the child.
- Requires Rust ≥ 1.87 (`std::io::pipe` in tests).

- [ ] **Step 1: Write the failing tests**

Create `crates/repo/src/stdio_transport.rs`:

```rust
//! Client side of the wire protocol (P12): a [`Transport`] impl that speaks
//! frames over any byte stream — in practice a child process's stdio, where
//! the child is `ssh <host> sc serve --stdio <path>` (or a test stand-in).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::transport::{LocalTransport, Transport};
    use crate::wire;
    use scl_core::Object;

    fn tmp_repo(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("scl-stdio-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        crate::repo::Repo::init(&root).unwrap();
        root
    }

    /// Connect a WireClient to a `wire::serve` thread over in-process pipes.
    /// Returns the client and the server thread handle.
    fn connect(
        root: std::path::PathBuf,
    ) -> (WireClient<std::io::PipeReader, std::io::PipeWriter>, std::thread::JoinHandle<crate::error::Result<()>>)
    {
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let handle =
            std::thread::spawn(move || wire::serve(&root, &mut server_read, &mut server_write));
        let client = WireClient::handshake(client_read, client_write).unwrap();
        (client, handle)
    }

    #[test]
    fn wire_client_satisfies_the_transport_contract() {
        let root = tmp_repo("contract");
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let tip = crate::repo::Repo::open(&root).unwrap().commit("t", "c1").unwrap();

        let (client, server) = connect(root.clone());

        // refs + head
        assert_eq!(client.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert_eq!(client.head_branch().unwrap(), "main");

        // object roundtrip + corrupt put rejected remotely
        let blob = Object::blob(b"over the wire".to_vec());
        let (id, bytes) = (blob.id(), blob.encode());
        assert!(!client.has_object(&id).unwrap());
        client.put_object(&id, &bytes).unwrap();
        assert!(client.has_object(&id).unwrap());
        assert_eq!(client.get_object(&id).unwrap(), bytes);
        assert!(client.put_object(&id, b"tampered").is_err());

        // pack roundtrip: everything reachable from the tip, no haves
        let pack = client.get_pack(&[tip], &[]).unwrap();
        assert!(!scl_core::pack::parse_pack(&pack).unwrap().is_empty());

        // CAS semantics survive the wire (mirrors transport.rs::update_ref_is_compare_and_swap)
        let c2 = Object::blob(b"c2".to_vec()).id();
        assert!(matches!(client.update_ref("main", &c2, None), Err(Error::NonFastForward)));

        client.bye().unwrap();
        drop(client);
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn handshake_surfaces_not_a_repo_as_typed_error() {
        let root = std::env::temp_dir().join(format!("scl-stdio-norepo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let root2 = root.clone();
        let server =
            std::thread::spawn(move || wire::serve(&root2, &mut server_read, &mut server_write));
        let err = WireClient::handshake(client_read, client_write).unwrap_err();
        assert!(matches!(err, Error::NotARepo), "got {err:?}");
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn handshake_rejects_version_skew() {
        // Hand-rolled "future server" that answers HELLO with version 2.
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let server = std::thread::spawn(move || {
            let f = wire::read_frame(&mut server_read).unwrap();
            assert!(matches!(wire::Request::decode(&f).unwrap(), wire::Request::Hello { .. }));
            wire::write_ok(&mut server_write, &wire::u32_body(2)).unwrap();
        });
        let err = WireClient::handshake(client_read, client_write).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
        server.join().unwrap();
    }

    #[test]
    fn dropped_connection_mid_push_is_typed_and_leaves_remote_ref_intact() {
        // A server that dies exactly when asked to move the ref — the worst
        // moment for a push. Objects are already transferred (put_pack ran);
        // the ref must be untouched and the client must see ConnectionLost.
        let root = tmp_repo("droppush");
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let tip = crate::repo::Repo::open(&root).unwrap().commit("t", "c1").unwrap();

        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let root2 = root.clone();
        let server = std::thread::spawn(move || {
            let f = wire::read_frame(&mut server_read).unwrap();
            assert!(matches!(wire::Request::decode(&f).unwrap(), wire::Request::Hello { .. }));
            wire::write_ok(&mut server_write, &wire::u32_body(wire::PROTOCOL_VERSION)).unwrap();
            let t = LocalTransport::open(&root2).unwrap();
            loop {
                let f = match wire::read_frame_opt(&mut server_read).unwrap() {
                    Some(f) => f,
                    None => return,
                };
                match wire::Request::decode(&f).unwrap() {
                    wire::Request::UpdateRef { .. } => return, // die without replying
                    wire::Request::PutPack(p) => {
                        let ids = t.put_pack(&p).unwrap();
                        wire::write_ok(&mut server_write, &wire::ids_body(&ids)).unwrap();
                    }
                    other => panic!("unexpected request {other:?}"),
                }
            }
        });

        let client = WireClient::handshake(client_read, client_write).unwrap();
        // "Push": transfer a pack, then try to advance the ref.
        let blob = Object::blob(b"new object".to_vec());
        let (pack, _idx) = scl_core::pack::build_pack(&[(blob.id(), blob.encode())]).unwrap();
        client.put_pack(&pack).unwrap();
        let err = client.update_ref("main", &blob.id(), Some(&tip)).unwrap_err();
        assert!(matches!(err, Error::ConnectionLost(_)), "got {err:?}");
        drop(client);
        server.join().unwrap();

        // The remote ref never moved; the transferred object is merely unreachable.
        let t = LocalTransport::open(&root).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert!(t.has_object(&blob.id()).unwrap());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn stdio_transport_spawn_failure_names_the_program() {
        let cmd = std::process::Command::new("/nonexistent/definitely-not-a-program");
        let err = StdioTransport::spawn(cmd).unwrap_err();
        match err {
            Error::ConnectionLost(msg) => assert!(msg.contains("definitely-not-a-program")),
            other => panic!("expected ConnectionLost, got {other:?}"),
        }
    }
}
```

Register in `crates/repo/src/lib.rs`: add `pub mod stdio_transport;` and, next to the crate's existing `pub use` re-exports, `pub use stdio_transport::{SshUrl, StdioTransport};` (SshUrl arrives in Task 4 — for this task re-export only `StdioTransport`, extend in Task 4).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo stdio_transport::`
Expected: FAIL to compile — `WireClient`, `StdioTransport` not defined.

- [ ] **Step 3: Implement `WireClient` and `StdioTransport`**

Fill in `crates/repo/src/stdio_transport.rs` above the tests:

```rust
use std::cell::RefCell;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::wire::{self, Request};

/// A [`Transport`] that speaks the wire protocol over any byte stream pair.
/// Interior-mutable because the trait reads `&self` (same pattern as
/// `LocalTransport`'s store cell).
pub struct WireClient<R: Read, W: Write> {
    rw: RefCell<(R, W)>,
}

impl<R: Read, W: Write> WireClient<R, W> {
    /// Exchange HELLOs and return a ready client. Fails typed: version skew is
    /// `Protocol`, a served non-repo path is `NotARepo`, a dead peer is
    /// `ConnectionLost`.
    pub fn handshake(r: R, w: W) -> Result<WireClient<R, W>> {
        let client = WireClient { rw: RefCell::new((r, w)) };
        let body = client.call(Request::Hello { version: wire::PROTOCOL_VERSION })?;
        let version = wire::decode_u32_body(&body)?;
        if version != wire::PROTOCOL_VERSION {
            return Err(Error::Protocol(format!(
                "server speaks protocol {version}, this client speaks {}",
                wire::PROTOCOL_VERSION
            )));
        }
        Ok(client)
    }

    /// One request/response round trip; returns the OK body or the typed error.
    fn call(&self, req: Request) -> Result<Vec<u8>> {
        let mut rw = self.rw.borrow_mut();
        wire::write_frame(&mut rw.1, &req.encode())?;
        let frame = wire::read_frame(&mut rw.0)?;
        wire::parse_response(frame)
    }

    /// Announce a clean end of session (the peer exits its serve loop).
    pub fn bye(&self) -> Result<()> {
        let mut rw = self.rw.borrow_mut();
        wire::write_frame(&mut rw.1, &Request::Bye.encode())
    }
}

impl<R: Read, W: Write> Transport for WireClient<R, W> {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        wire::decode_refs_body(&self.call(Request::ListRefs)?)
    }
    fn head_branch(&self) -> Result<String> {
        wire::decode_str_body(&self.call(Request::HeadBranch)?)
    }
    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        wire::decode_bool_body(&self.call(Request::HasObject(*id))?)
    }
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.call(Request::GetObject(*id))
    }
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        self.call(Request::PutObject { id: *id, bytes: bytes.to_vec() })?;
        Ok(())
    }
    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        self.call(Request::UpdateRef {
            branch: branch.to_string(),
            id: *id,
            expected_old: expected_old.copied(),
        })?;
        Ok(())
    }
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>> {
        self.call(Request::GetPack { wants: wants.to_vec(), haves: haves.to_vec() })
    }
    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>> {
        wire::decode_ids_body(&self.call(Request::PutPack(pack.to_vec()))?)
    }
}

/// A [`Transport`] whose far end is a child process speaking the wire protocol
/// on its stdio — `ssh <host> sc serve --stdio <path>` for real remotes.
pub struct StdioTransport {
    client: WireClient<std::io::BufReader<ChildStdout>, ChildStdin>,
    child: Child,
}

impl StdioTransport {
    /// Spawn `cmd` with piped stdio and perform the handshake. On a dead or
    /// broken child (ssh auth failure, `sc` missing on the remote), the
    /// child's stderr is folded into the error so the user sees the real cause.
    pub fn spawn(mut cmd: Command) -> Result<StdioTransport> {
        let program = cmd.get_program().to_string_lossy().into_owned();
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::ConnectionLost(format!("failed to spawn {program}: {e}")))?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = std::io::BufReader::new(child.stdout.take().expect("stdout piped"));
        match WireClient::handshake(stdout, stdin) {
            Ok(client) => Ok(StdioTransport { client, child }),
            Err(Error::ConnectionLost(msg)) => {
                let stderr = reap_with_stderr(&mut child);
                Err(Error::ConnectionLost(if stderr.is_empty() {
                    format!("{program}: {msg}")
                } else {
                    format!("{program}: {msg}; remote said: {}", stderr.trim())
                }))
            }
            Err(other) => {
                let _ = reap_with_stderr(&mut child);
                Err(other) // typed errors (NotARepo, Protocol) pass through
            }
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.client.bye(); // best-effort: the server exits its loop
        let _ = self.child.wait();
    }
}

/// Kill + reap the child and return up to 64 KiB of its stderr for error text.
fn reap_with_stderr(child: &mut Child) -> String {
    let _ = child.kill();
    let mut text = String::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(64 * 1024).read_to_string(&mut text);
    }
    let _ = child.wait();
    text
}

impl Transport for StdioTransport {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        self.client.list_refs()
    }
    fn head_branch(&self) -> Result<String> {
        self.client.head_branch()
    }
    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        self.client.has_object(id)
    }
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.client.get_object(id)
    }
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        self.client.put_object(id, bytes)
    }
    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        self.client.update_ref(branch, id, expected_old)
    }
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>> {
        self.client.get_pack(wants, haves)
    }
    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>> {
        self.client.put_pack(pack)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-repo stdio_transport::`
Expected: PASS (5 tests). Then `cargo test --workspace`.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/stdio_transport.rs crates/repo/src/lib.rs
git commit -m "feat(repo): WireClient + StdioTransport — Transport over a child process's stdio (P12)"
```

---

### Task 4: `SshUrl`, `SC_SSH`, transport factory, sync refactor

**Files:**
- Modify: `crates/repo/src/stdio_transport.rs` (SshUrl, ssh_command, open_transport)
- Modify: `crates/repo/src/sync.rs` (`clone_url`, factory dispatch, `&dyn Transport`)
- Modify: `crates/repo/src/lib.rs` (re-export `SshUrl`, `open_transport`)

**Interfaces:**
- Consumes: Task 3's `StdioTransport::spawn`, existing `LocalTransport`.
- Produces (used by Task 5):
  - `pub struct SshUrl { pub user: Option<String>, pub host: String, pub port: Option<u16>, pub path: String }` with `pub fn parse(url: &str) -> Result<SshUrl>`.
  - `pub fn open_transport(url: &str) -> Result<Box<dyn Transport>>` — `ssh://` ⇒ `StdioTransport` via the user's `ssh` binary (overridable with `SC_SSH`); anything else ⇒ `LocalTransport::open(url)`.
  - `Repo::clone_url(src_url: &str, dst: impl AsRef<Path>) -> Result<Repo>`; `Repo::clone_to` becomes a thin wrapper over it. `Repo::fetch`/`Repo::push` transparently work with `ssh://` remote URLs.

- [ ] **Step 1: Write the failing tests**

Append to the tests module in `crates/repo/src/stdio_transport.rs`:

```rust
    #[test]
    fn ssh_url_parses_all_forms() {
        let u = SshUrl::parse("ssh://alice@host.example:2222/srv/repo").unwrap();
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.host, "host.example");
        assert_eq!(u.port, Some(2222));
        assert_eq!(u.path, "/srv/repo");

        let u = SshUrl::parse("ssh://host/repo").unwrap();
        assert_eq!(u.user, None);
        assert_eq!(u.port, None);
        assert_eq!(u.host, "host");
        assert_eq!(u.path, "/repo");
    }

    #[test]
    fn ssh_url_rejects_malformed_forms() {
        for bad in [
            "/plain/path",              // not ssh
            "ssh://host",               // no path
            "ssh:///path",              // empty host
            "ssh://host:notaport/path", // bad port
        ] {
            assert!(
                matches!(SshUrl::parse(bad), Err(Error::InvalidArgument(_))),
                "should reject {bad}"
            );
        }
    }

    #[test]
    fn ssh_command_builds_the_expected_argv() {
        let u = SshUrl::parse("ssh://alice@host:2222/srv/repo").unwrap();
        let cmd = ssh_command(&u);
        let args: Vec<String> =
            cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["-p", "2222", "alice@host", "--", "sc", "serve", "--stdio", "/srv/repo"]);

        let u = SshUrl::parse("ssh://host/repo").unwrap();
        let cmd = ssh_command(&u);
        let args: Vec<String> =
            cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["host", "--", "sc", "serve", "--stdio", "/repo"]);
    }

    #[test]
    fn open_transport_dispatches_local_paths_to_local_transport() {
        let root = tmp_repo("factory");
        // A plain path must open (LocalTransport) and answer verbs.
        let t = open_transport(root.to_str().unwrap()).unwrap();
        assert_eq!(t.head_branch().unwrap(), "main");
        // A malformed ssh URL fails fast in parsing, before spawning anything.
        assert!(matches!(open_transport("ssh://nopath"), Err(Error::InvalidArgument(_))));
        std::fs::remove_dir_all(&root).unwrap();
    }
```

And a clone/fetch/push-over-the-wire test appended to `crates/repo/src/sync.rs`'s tests (create `#[cfg(test)] mod tests` at the bottom if the file has none):

```rust
#[cfg(test)]
mod tests {
    use crate::repo::Repo;

    #[test]
    fn clone_url_with_plain_path_matches_clone_to() {
        let pid = std::process::id();
        let src = std::env::temp_dir().join(format!("scl-cloneurl-src-{pid}"));
        let dst = std::env::temp_dir().join(format!("scl-cloneurl-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
        std::fs::create_dir_all(&src).unwrap();

        let repo = Repo::init(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"one").unwrap();
        let tip = repo.commit("t", "c1").unwrap();

        let cloned = Repo::clone_url(src.to_str().unwrap(), &dst).unwrap();
        assert_eq!(cloned.head_tip().unwrap(), Some(tip));
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"one");
        // origin records the URL string verbatim.
        assert_eq!(
            cloned.remotes().unwrap(),
            vec![("origin".to_string(), src.to_str().unwrap().to_string())]
        );

        std::fs::remove_dir_all(&src).unwrap();
        std::fs::remove_dir_all(&dst).unwrap();
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo stdio_transport:: sync::`
Expected: FAIL to compile — `SshUrl`, `ssh_command`, `open_transport`, `clone_url` not defined.

- [ ] **Step 3: Implement URL parsing, factory, and the sync refactor**

Add to `crates/repo/src/stdio_transport.rs`:

```rust
/// A parsed `ssh://[user@]host[:port]/abs/path` remote URL.
///
/// The path is the repo root *on the server* and keeps its leading `/`.
/// Known limitation: paths containing spaces are unsupported over real ssh
/// (the remote shell splits the command) — see ADR-0022.
#[derive(Debug, Clone, PartialEq)]
pub struct SshUrl {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

impl SshUrl {
    /// Parse an `ssh://` URL; anything malformed is `InvalidArgument` with a
    /// message naming the URL, so `remote add` can fail fast.
    pub fn parse(url: &str) -> Result<SshUrl> {
        let rest = url
            .strip_prefix("ssh://")
            .ok_or_else(|| Error::InvalidArgument(format!("not an ssh:// url: {url}")))?;
        let slash = rest
            .find('/')
            .ok_or_else(|| Error::InvalidArgument(format!("ssh url has no repo path: {url}")))?;
        let (authority, path) = rest.split_at(slash);
        let (user, hostport) = match authority.split_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, authority),
        };
        let (host, port) = match hostport.split_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    Error::InvalidArgument(format!("bad port in ssh url: {url}"))
                })?;
                (h, Some(port))
            }
            None => (hostport, None),
        };
        if host.is_empty() {
            return Err(Error::InvalidArgument(format!("ssh url has empty host: {url}")));
        }
        Ok(SshUrl { user, host: host.to_string(), port, path: path.to_string() })
    }
}

/// The command that reaches `sc serve --stdio` on the far side: the user's
/// `ssh` binary (or `$SC_SSH`, Git's `GIT_SSH` pattern — tests and the demo
/// point it at a shim so the whole ssh:// path runs without an sshd).
pub(crate) fn ssh_command(url: &SshUrl) -> Command {
    let program = std::env::var("SC_SSH").unwrap_or_else(|_| "ssh".to_string());
    let mut cmd = Command::new(program);
    if let Some(port) = url.port {
        cmd.arg("-p").arg(port.to_string());
    }
    match &url.user {
        Some(user) => cmd.arg(format!("{user}@{}", url.host)),
        None => cmd.arg(&url.host),
    };
    cmd.arg("--").arg("sc").arg("serve").arg("--stdio").arg(&url.path);
    cmd
}

/// Open the right [`Transport`] for a remote URL: `ssh://` spawns the wire
/// client; anything else is a local `.sc/` path.
pub fn open_transport(url: &str) -> Result<Box<dyn Transport>> {
    if url.starts_with("ssh://") {
        let parsed = SshUrl::parse(url)?;
        Ok(Box::new(StdioTransport::spawn(ssh_command(&parsed))?))
    } else {
        Ok(Box::new(crate::transport::LocalTransport::open(url)?))
    }
}
```

In `crates/repo/src/lib.rs`, extend the Task 3 re-export to `pub use stdio_transport::{open_transport, SshUrl, StdioTransport};`.

In `crates/repo/src/sync.rs`:

1. Replace the import `use crate::transport::{LocalTransport, Transport};` with `use crate::transport::Transport;` and add `use crate::stdio_transport::open_transport;`.
2. `clone_to` → thin wrapper; the body moves to `clone_url`:

```rust
    /// Clone the repo at local path `src` into a fresh repo at `dst`.
    /// Path-flavored convenience over [`Repo::clone_url`].
    pub fn clone_to(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<Repo> {
        Self::clone_url(&src.as_ref().display().to_string(), dst)
    }

    /// Clone the repo at `src_url` (local path or `ssh://…`) into `dst`.
    /// [doc comment: keep the rest of clone_to's existing doc verbatim]
    pub fn clone_url(src_url: &str, dst: impl AsRef<Path>) -> Result<Repo> {
        let transport = open_transport(src_url)?;
        // ... existing clone_to body, with two changes:
        //   - `transfer_objects(&transport, ...)` becomes
        //     `transfer_objects(transport.as_ref(), ...)`
        //   - `dst_repo.remote_add("origin", &src.display().to_string())?` becomes
        //     `dst_repo.remote_add("origin", src_url)?`
    }
```

3. In `fetch` (line ~98) and `push` (line ~121), replace `let transport = LocalTransport::open(url)?;` with `let transport = open_transport(url)?;`. Method calls (`transport.list_refs()` etc.) auto-deref through the `Box`; the `transfer_objects(&transport, …)` call in `fetch` becomes `transfer_objects(transport.as_ref(), …)`.
4. Change `transfer_objects`'s signature from `transport: &impl Transport` to `transport: &dyn Transport` (body unchanged).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-repo`
Expected: PASS — new tests green, and all existing sync/transport/repo tests still green (the refactor must not change local-path behavior).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/stdio_transport.rs crates/repo/src/sync.rs crates/repo/src/lib.rs
git commit -m "feat(repo): ssh:// remotes — SshUrl, SC_SSH-aware transport factory, clone_url; sync dispatches on URL scheme (P12)"
```

---

### Task 5: CLI — `sc serve --stdio`, ssh-aware clone/remote-add, integration tests

**Files:**
- Modify: `crates/cli/src/main.rs`
- Create: `crates/cli/tests/ssh_remote.rs`

**Interfaces:**
- Consumes: `scl_repo::wire::serve`, `scl_repo::Repo::clone_url`, `scl_repo::SshUrl`.
- Produces: `sc serve --stdio <path>`; `sc clone` accepts `ssh://` sources; `sc remote add` validates `ssh://` URLs eagerly. `sc fetch`/`sc push` need **no** dispatch changes — `Repo::fetch`/`Repo::push` already route via `open_transport` (Task 4); the existing `RemoteKind::Git` CLI dispatch is untouched.

- [ ] **Step 1: Write the failing integration tests**

Create `crates/cli/tests/ssh_remote.rs`:

```rust
//! End-to-end: sc-native transport over the full ssh:// code path, with the
//! SC_SSH shim standing in for ssh (no sshd needed). See ADR-0022.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sc(dir: &Path, args: &[&str]) -> Output {
    sc_env(dir, &[], args)
}

fn sc_env(dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sc"));
    cmd.args(args).current_dir(dir);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("sc runs")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-ssh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write the SC_SSH shim: drops ssh's option/host args and execs the sc
/// binary under test with the remote command's arguments.
fn write_shim(dir: &Path) -> PathBuf {
    let p = dir.join("fake_ssh.sh");
    std::fs::write(
        &p,
        "#!/bin/sh\n\
         while [ $# -gt 0 ] && [ \"$1\" != \"sc\" ]; do shift; done\n\
         [ $# -gt 0 ] || { echo 'shim: no sc command in argv' >&2; exit 65; }\n\
         shift\n\
         exec \"$SC_BIN\" \"$@\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

/// The env that routes ssh:// through the shim.
fn ssh_env(shim: &Path) -> Vec<(String, String)> {
    vec![
        ("SC_SSH".to_string(), shim.to_string_lossy().into_owned()),
        ("SC_BIN".to_string(), env!("CARGO_BIN_EXE_sc").to_string()),
    ]
}

fn sc_ssh(dir: &Path, shim: &Path, args: &[&str]) -> Output {
    let envs = ssh_env(shim);
    let envs_ref: Vec<(&str, &str)> =
        envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    sc_env(dir, &envs_ref, args)
}

/// True if `needle` occurs in any file under `dir` (recursive, raw bytes).
fn tree_contains(dir: &Path, needle: &[u8]) -> bool {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if tree_contains(&path, needle) {
                return true;
            }
        } else if let Ok(bytes) = std::fs::read(&path) {
            if bytes.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn ssh_clone_push_fetch_merge_round_trip() {
    let root = tmp("roundtrip");
    let shim = write_shim(&root);
    let a = root.join("A");
    std::fs::create_dir_all(&a).unwrap();

    // A: the "server-side" repo.
    assert!(sc(&a, &["init"]).status.success());
    std::fs::write(a.join("file.txt"), b"v1").unwrap();
    assert!(sc(&a, &["commit", "-m", "c1", "--author", "t"]).status.success());

    // Clone over ssh:// (through the shim) into B.
    let url = format!("ssh://testhost{}", a.display());
    let b = root.join("B");
    let out = sc_ssh(&root, &shim, &["clone", &url, b.to_str().unwrap()]);
    assert!(out.status.success(), "clone failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(b.join("file.txt")).unwrap(), b"v1");
    // origin recorded the ssh URL verbatim.
    let config = std::fs::read_to_string(b.join(".sc/config")).unwrap();
    assert!(config.contains(&url), "config lacks ssh url: {config}");

    // B: commit and push back over the wire.
    std::fs::write(b.join("file.txt"), b"v2").unwrap();
    assert!(sc(&b, &["commit", "-m", "c2", "--author", "t"]).status.success());
    let out = sc_ssh(&b, &shim, &["push", "origin"]);
    assert!(out.status.success(), "push failed: {}", String::from_utf8_lossy(&out.stderr));

    // A's history now contains c2 (log reads refs + objects; its working tree
    // staying at v1 is expected, like pushing into a non-bare git repo).
    let log = sc(&a, &["log"]);
    let text = String::from_utf8_lossy(&log.stdout).into_owned();
    assert!(text.contains("c2"), "A's log lacks pushed commit: {text}");

    // Fetch direction: B fetches after A's tip moved (it moved via B's own
    // push; a second fetch must be a clean no-op that still succeeds).
    let out = sc_ssh(&b, &shim, &["fetch", "origin"]);
    assert!(out.status.success(), "fetch failed: {}", String::from_utf8_lossy(&out.stderr));

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn racing_pushes_second_gets_non_fast_forward_then_recovers_via_fetch_merge() {
    let root = tmp("race");
    let shim = write_shim(&root);
    let a = root.join("A");
    std::fs::create_dir_all(&a).unwrap();
    assert!(sc(&a, &["init"]).status.success());
    std::fs::write(a.join("base.txt"), b"base").unwrap();
    assert!(sc(&a, &["commit", "-m", "base", "--author", "t"]).status.success());

    let url = format!("ssh://testhost{}", a.display());
    let b = root.join("B");
    let c = root.join("C");
    assert!(sc_ssh(&root, &shim, &["clone", &url, b.to_str().unwrap()]).status.success());
    assert!(sc_ssh(&root, &shim, &["clone", &url, c.to_str().unwrap()]).status.success());

    // C lands first.
    std::fs::write(c.join("from_c.txt"), b"c").unwrap();
    assert!(sc(&c, &["commit", "-m", "from-c", "--author", "t"]).status.success());
    assert!(sc_ssh(&c, &shim, &["push", "origin"]).status.success());

    // B diverged; its push must fail typed, not clobber.
    std::fs::write(b.join("from_b.txt"), b"b").unwrap();
    assert!(sc(&b, &["commit", "-m", "from-b", "--author", "t"]).status.success());
    let out = sc_ssh(&b, &shim, &["push", "origin"]);
    assert!(!out.status.success(), "second push must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("non-fast-forward"), "wrong error: {stderr}");

    // Recovery: fetch + merge + push.
    assert!(sc_ssh(&b, &shim, &["fetch", "origin"]).status.success());
    let merge = sc(&b, &["merge", "origin/main"]);
    assert!(merge.status.success(), "merge failed: {}", String::from_utf8_lossy(&merge.stderr));
    let out = sc_ssh(&b, &shim, &["push", "origin"]);
    assert!(out.status.success(), "push after merge failed: {}", String::from_utf8_lossy(&out.stderr));

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn unauthorized_ssh_clone_receives_ciphertext_it_cannot_read() {
    let root = tmp("cipher");
    let shim = write_shim(&root);
    let a = root.join("A");
    std::fs::create_dir_all(&a).unwrap();
    let secret_plaintext = b"TOP_SECRET_wire_hunter2";
    let public_marker = b"PUBLIC_WIRE_MARKER_xyz";

    // Mirror demo/run_protect_demo.sh's recipient setup.
    assert!(sc(&a, &["init"]).status.success());
    let key = root.join("alice.key");
    let out = sc(&a, &["keygen", "--out", key.to_str().unwrap()]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let pk = stdout
        .lines()
        .find(|l| l.contains("public key:"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("keygen prints the public key")
        .to_string();
    std::fs::write(a.join(".sc/recipients.toml"), format!("[recipients]\nalice = \"{pk}\"\n"))
        .unwrap();
    assert!(sc(&a, &["protect", "secret/", "--to", "alice"]).status.success());
    std::fs::create_dir_all(a.join("secret")).unwrap();
    std::fs::write(a.join("secret/db.txt"), secret_plaintext).unwrap();
    std::fs::write(a.join("README.md"), public_marker).unwrap();
    assert!(sc(&a, &["commit", "-m", "add secret", "--author", "t"]).status.success());

    // Positive control on A: an unprotected file's bytes ARE findable in the
    // object store, so the negative greps below are not vacuous.
    assert!(tree_contains(&a.join(".sc/objects"), public_marker));
    assert!(!tree_contains(&a.join(".sc/objects"), secret_plaintext));

    // Clone over the wire WITHOUT alice's key.
    let url = format!("ssh://testhost{}", a.display());
    let b = root.join("B");
    let out = sc_ssh(&root, &shim, &["clone", &url, b.to_str().unwrap()]);
    assert!(out.status.success(), "clone failed: {}", String::from_utf8_lossy(&out.stderr));

    // The protected file was not materialized, and no plaintext crossed the wire.
    assert!(!b.join("secret/db.txt").exists(), "unauthorized clone wrote protected plaintext");
    assert!(!tree_contains(&b.join(".sc"), secret_plaintext), "plaintext leaked over the wire");
    // The public file arrived intact (transfer itself works).
    assert_eq!(std::fs::read(b.join("README.md")).unwrap(), public_marker);

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn serving_a_non_repo_fails_typed_and_remote_add_validates_ssh_urls() {
    let root = tmp("errors");
    let shim = write_shim(&root);
    let empty = root.join("empty");
    std::fs::create_dir_all(&empty).unwrap();

    // Clone of a served non-repo path: typed NotARepo crosses the wire.
    let url = format!("ssh://testhost{}", empty.display());
    let out = sc_ssh(&root, &shim, &["clone", &url, root.join("dst").to_str().unwrap()]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("not a src-control repo"), "wrong error: {stderr}");

    // remote add rejects malformed ssh URLs eagerly.
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    assert!(sc(&work, &["init"]).status.success());
    let out = sc(&work, &["remote", "add", "up", "ssh://hostonly-no-path"]);
    assert!(!out.status.success(), "malformed ssh url must be rejected at remote add");

    std::fs::remove_dir_all(&root).unwrap();
}
```

Adjust the two `--author` usages if `sc commit` in this codebase takes the author differently (check `everyday.rs`; the `run_protect_demo.sh` script uses `--author me`, so `--author t` is correct).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-cli --test ssh_remote`
Expected: FAIL — `sc clone ssh://…` treats the URL as a local path (or `serve` subcommand missing), so the first assertion in each test fails.

- [ ] **Step 3: Implement the CLI changes**

In `crates/cli/src/main.rs`:

1. Change the `Clone` variant (line ~116): `Clone { src: String, dst: PathBuf }`.
2. Add a `Serve` variant to the command enum:

```rust
    /// Serve a repo over stdin/stdout to a remote `sc` client (invoked by
    /// `ssh` for ssh:// remotes; not intended for interactive use).
    Serve {
        /// Speak the wire protocol on stdin/stdout (required; the only mode).
        #[arg(long)]
        stdio: bool,
        /// Repo root to serve (the directory containing `.sc/`).
        path: PathBuf,
    },
```

3. Dispatch arm (near line ~318): `Cmd::Serve { stdio, path } => run_serve(stdio, path),`.
4. `run_clone` (line ~1214) becomes:

```rust
fn run_clone(src: String, dst: PathBuf) -> Result<()> {
    let repo = scl_repo::Repo::clone_url(&src, &dst)?;
    let n = repo.branches()?.len();
    println!("cloned {} into {} ({} branch(es))", src, dst.display(), n);
    Ok(())
}
```

5. Add `run_serve`:

```rust
fn run_serve(stdio: bool, path: PathBuf) -> Result<()> {
    if !stdio {
        anyhow::bail!("sc serve requires --stdio (the only supported mode)");
    }
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    scl_repo::wire::serve(&path, &mut stdin, &mut stdout)?;
    Ok(())
}
```

6. In the `remote add` arm (non-`--git` branch, near line ~1229), validate ssh URLs before storing:

```rust
                if url.starts_with("ssh://") {
                    scl_repo::SshUrl::parse(&url)?; // fail fast on malformed URLs
                }
                repo.remote_add(&name, &url)?;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-cli --test ssh_remote`
Expected: PASS (4 tests). Then `cargo test --workspace` — the full suite stays green (notably the existing `Clone`-related tests with the `PathBuf`→`String` change).

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/main.rs crates/cli/tests/ssh_remote.rs
git commit -m "feat(cli): sc serve --stdio + ssh:// clone/remote-add — network transport end-to-end (P12)"
```

---

### Task 6: Demo script

**Files:**
- Create: `demo/run_ssh_remote_demo.sh`

**Interfaces:**
- Consumes: the `sc` binary (`serve`, `clone`, `push`, `fetch`, `merge`, `protect`, `keygen`), `SC_SSH`/`SC_BIN` env contract from Task 4.
- Produces: a self-checking script; every claim is an assertion; exits non-zero on any failure before the success line (project demo convention).

- [ ] **Step 1: Write the script**

Create `demo/run_ssh_remote_demo.sh` (mode 755):

```bash
#!/usr/bin/env bash
# Headline proof for P12 (network transport over SSH): clone/push/fetch run
# against an ssh:// remote through the FULL ssh code path — URL parsing, argv
# construction, framed wire protocol, `sc serve --stdio` dispatch — with a
# GIT_SSH-style SC_SSH shim standing in for ssh, so no sshd is required and
# the proof is self-contained. Confidentiality rides along: a protected path
# crosses the wire as ciphertext an unauthorized clone cannot read.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the success line.
set -euo pipefail
cargo build --bin sc >/dev/null 2>&1
SC="$(pwd)/target/debug/sc"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
A="$W/A"; B="$W/B"; C="$W/C"; KEY="$W/alice.key"

SECRET_PLAINTEXT="TOP_SECRET_wire_password_hunter2"
PUBLIC_MARKER="PUBLIC_WIRE_MARKER_xyz"

fail() { echo "FAIL: $1"; exit 1; }

# --- The ssh stand-in: drops ssh's host argument and runs the requested
#     `sc serve` locally. Everything else is the real ssh:// code path. ---
cat > "$W/fake_ssh" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ] && [ "$1" != "sc" ]; do shift; done
[ $# -gt 0 ] || { echo "shim: no sc command in argv" >&2; exit 65; }
shift
exec "$SC_BIN" "$@"
EOF
chmod +x "$W/fake_ssh"
export SC_SSH="$W/fake_ssh" SC_BIN="$SC"

# --- A: the "server" repo — one public file, one protected file. ---
mkdir -p "$A"; cd "$A"
"$SC" init >/dev/null
ALICE_PK="$(awk '/public key:/{print $3}' < <("$SC" keygen --out "$KEY"))"
printf '[recipients]\nalice = "%s"\n' "$ALICE_PK" > .sc/recipients.toml
"$SC" protect secret/ --to alice >/dev/null
mkdir -p secret
printf '%s\n' "$SECRET_PLAINTEXT" > secret/db.txt
printf '%s\n' "$PUBLIC_MARKER" > README.md
"$SC" commit -m "initial" --author server >/dev/null
echo "A: repo with a public file and a protected file ✔"

URL="ssh://demohost$A"

# --- Clone over ssh:// into B (no identity: unauthorized for secret/). ---
cd "$W"
"$SC" clone "$URL" "$B" >/dev/null
[ "$(cat "$B/README.md")" = "$PUBLIC_MARKER" ] || fail "public file did not survive the wire"
[ -f "$B/secret/db.txt" ] && fail "unauthorized ssh clone wrote the protected file"
grep -raq "$SECRET_PLAINTEXT" "$B/.sc" && fail "plaintext crossed the wire"
grep -q "$URL" "$B/.sc/config" || fail "origin does not record the ssh url"
echo "B: cloned over ssh:// — public content intact, secret stays ciphertext ✔"

# --- B commits and pushes back over the wire. ---
cd "$B"
printf 'from B\n' > b.txt
"$SC" commit -m "from-B" --author b >/dev/null
"$SC" push origin >/dev/null
cd "$A"
"$SC" log | grep -q "from-B" || fail "A's history lacks the pushed commit"
echo "B → A: push over ssh:// landed ✔"

# --- Racing writer: C clones, lands first; B's next push must be refused. ---
cd "$W"
"$SC" clone "$URL" "$C" >/dev/null
cd "$C"
printf 'from C\n' > c.txt
"$SC" commit -m "from-C" --author c >/dev/null
"$SC" push origin >/dev/null
cd "$B"
printf 'diverge\n' > d.txt
"$SC" commit -m "diverge-B" --author b >/dev/null
"$SC" push origin >/dev/null 2>&1 && fail "non-fast-forward push was not refused"
echo "B: divergent push refused (non-fast-forward) ✔"

# --- Recovery: fetch + merge + push. ---
"$SC" fetch origin >/dev/null
"$SC" merge origin/main >/dev/null
"$SC" push origin >/dev/null
cd "$A"
"$SC" log | grep -q "diverge-B" || fail "A's history lacks the recovered push"
echo "B: fetch + merge + push recovered ✔"

echo
echo "P12 PROOF COMPLETE: sc-native transport over the ssh:// code path — clone,"
echo "push, fetch, CAS-guarded refs, and ciphertext-only confidentiality, with"
echo "zero sshd required."
```

- [ ] **Step 2: Run it**

Run: `bash demo/run_ssh_remote_demo.sh`
Expected: the five ✔ lines and `P12 PROOF COMPLETE…`; exit code 0. If any assertion trips, fix the underlying code — never weaken an assertion. (Note the `merge origin/main` step assumes no content conflict — `b.txt`/`c.txt`/`d.txt` are distinct files, so the three-way merge is clean by construction.)

- [ ] **Step 3: Commit**

```bash
git add demo/run_ssh_remote_demo.sh
git commit -m "demo: ssh remote round-trip proof — clone/push/fetch over the wire via SC_SSH shim (P12)"
```

---

### Task 7: Docs — ADR-0022, ARCHITECTURE.md, CLAUDE.md

**Files:**
- Create: `docs/adr/0022-ssh-native-transport.md`
- Modify: `ARCHITECTURE.md` (new Phase 12 section; update the "Remaining follow-ons" line)
- Modify: `CLAUDE.md` (command list + phase note)

**Interfaces:** none consumed by code; the ADR is referenced by doc comments written in Tasks 1–4 ("See ADR-0022").

- [ ] **Step 1: Write ADR-0022**

Create `docs/adr/0022-ssh-native-transport.md`:

```markdown
# ADR-0022: sc-native network transport over SSH (trait-mirror wire protocol)

- **Status:** Accepted
- **Date:** 2026-07-05
- **Phase:** 12
- **Builds on:** ADR-0013 (Transport trait), ADR-0015 (packs), ADR-0021 (CAS ref updates)

## Context

P6 proved the sync model over a local-path `Transport`; P8 made bulk transfer
one pack; ADR-0021 made concurrent ref updates safe. The noted follow-on —
network transport — is what turns src-control from local-only into a real
DVCS. The design question: what protocol, and how much new machinery?

## Decision

Mirror the existing 8-verb `Transport` trait 1:1 onto a framed stdio protocol,
and reach the far side by spawning the user's `ssh` binary:

- **Wire format:** `u32` big-endian length + payload frames. Requests are one
  opcode per trait verb plus `HELLO {version}` / `BYE`; responses are
  `OK body` or `ERR code message`. `NonFastForward` and `NotARepo` round-trip
  as typed errors (push semantics depend on the former); everything else
  degrades to a message-carrying generic.
- **Server:** `sc serve --stdio <path>` — a dispatch loop around the existing
  `LocalTransport`, so CAS ref updates, pack verification, and BLAKE3-on-read
  apply verbatim on the serving side. Verb failures are replies; only
  protocol violations end a session. The opcode surface is the only thing a
  client can ask for — no arbitrary path access, no exec.
- **Client:** `StdioTransport` implements `Transport` over a child process's
  stdio. `ssh://[user@]host[:port]/abs/path` remotes spawn
  `$SC_SSH-or-ssh [-p port] [user@]host -- sc serve --stdio <path>`. The
  `SC_SSH` override (Git's `GIT_SSH` pattern) lets tests and the demo drive
  the full ssh:// code path with a local shim, no sshd required.
- **Dispatch:** `open_transport(url)` picks `StdioTransport` for `ssh://`,
  `LocalTransport` otherwise; git remotes keep their existing path above the
  trait (ADR-0018). `clone/fetch/push` gain network support without changes
  to their logic.

Authn/authz is entirely SSH's; we never touch credentials. Confidentiality is
by construction: objects cross the wire as canonical bytes, so protected-path
ciphertext and secrets stay encrypted, and an interrupted push leaves at worst
unreachable objects (pack lands before the ref CAS), never a torn ref.

## Consequences

- Two machines with SSH access and `sc` on `PATH` can collaborate.
- Zero new dependencies; the server side reuses `LocalTransport` wholesale.
- Per-verb RPC is chattier than a session protocol; the heavy payloads
  (packs) are single-round-trip, and composite opcodes can be added behind
  the version handshake if latency ever matters.
- Accepted limitations: frames cap at 4 GiB (packs are in-memory anyway);
  repo paths with spaces break over real ssh (remote shell splitting — same
  class of issue Git has); `sc` must be installed on the server.

## Alternatives considered

- **Purpose-built session protocol (git smart-protocol style).** Fewer round
  trips, but a second sync code path that re-solves CAS/verification the
  trait impls already solved. The trait-mirror protocol can evolve into it.
- **Embedded SSH library (`russh`).** No external ssh dependency, but a large
  crate plus our own key/agent/host-verification handling — against the
  lean-deps taste, and Git proves shelling out is fine.
- **HTTP transport.** Needs a daemon and an auth design; SSH gives auth for
  free. HTTP remains a candidate follow-on for hosting scenarios.
```

- [ ] **Step 2: Update ARCHITECTURE.md**

After the Phase 11 section, add (keeping the established section style):

```markdown
## Phase 12 — Network transport over SSH (built)

`sc clone / fetch / push` work against `ssh://[user@]host[:port]/path`
remotes. The wire protocol mirrors the 8 `Transport` verbs over length-
prefixed frames with a version handshake; the server (`sc serve --stdio`) is
a dispatch loop around `LocalTransport`, so CAS ref updates and pack
verification apply verbatim server-side. The client spawns the user's `ssh`
(overridable via `SC_SSH`, Git's `GIT_SSH` pattern — the demo and tests drive
the full ssh:// path through a local shim, no sshd needed). Typed errors
(`NonFastForward`, `NotARepo`) survive the wire; an interrupted push leaves
at worst unreachable objects, never a torn ref. Confidentiality is unchanged
by construction: objects travel as canonical bytes, ciphertext stays
ciphertext. See ADR-0022.
```

Update the "Remaining follow-ons" line (ARCHITECTURE.md:287) to no longer claim network transport is missing; the remaining items become network Git remotes, HTTP transport, streaming (>4 GiB) frames, bulk re-wrap, and multiple escrow keys.

- [ ] **Step 3: Update CLAUDE.md**

In the command list, after the existing remote commands, add:

```
cargo run --bin sc -- remote add <name> ssh://[user@]host[:port]/path   # ssh-native remote
cargo run --bin sc -- clone ssh://host/path <dst>   # clone over ssh (spawns `ssh … sc serve --stdio`)
cargo run --bin sc -- serve --stdio <path>          # wire-protocol server (invoked via ssh; not interactive)
bash demo/run_ssh_remote_demo.sh                    # ssh transport round-trip proof (SC_SSH shim, no sshd)
```

After the "Phase 11 is built." paragraph, add:

```markdown
**Phase 12 is built.** sc-native network transport over SSH: a framed stdio
wire protocol mirrors the 8 `Transport` verbs (version handshake, typed
`NonFastForward`/`NotARepo` errors); `sc serve --stdio` dispatches onto the
existing `LocalTransport` (CAS, pack verification reused verbatim); the
client spawns the user's `ssh` for `ssh://` URLs, overridable via `SC_SSH`
(GIT_SSH pattern) — tests and `demo/run_ssh_remote_demo.sh` drive the full
ssh:// code path through a shim with no sshd. Zero new dependencies. Accepted
limitations: 4 GiB frame cap, repo paths with spaces unsupported over real
ssh, `sc` must be on the server's PATH. See ADR-0022.
```

Update the "Remaining follow-ons" line in CLAUDE.md to match ARCHITECTURE.md (drop network transport; add HTTP transport / network Git / streaming frames).

- [ ] **Step 4: Verify and commit**

Run: `cargo test --workspace && bash demo/run_ssh_remote_demo.sh && bash demo/run_repo_demo.sh`
Expected: all green (the older demos prove no regression).

```bash
git add docs/adr/0022-ssh-native-transport.md ARCHITECTURE.md CLAUDE.md
git commit -m "docs: accept ADR-0022 ssh-native transport; record P12 in ARCHITECTURE + CLAUDE"
```

---

## Self-review notes (already applied)

- **Spec coverage:** framing/handshake/opcodes/typed errors → Task 1; server → Task 2; client + stderr surfacing + connection-lost semantics + interrupted-push safety → Task 3; URL/`SC_SSH`/factory/`clone_url` → Task 4; CLI + all four spec'd integration scenarios → Task 5; demo → Task 6; ADR/ARCHITECTURE/CLAUDE → Task 7. One deliberate deviation from the spec's code-layout sketch: `SshUrl` parsing and `SC_SSH` resolution live in `crates/repo` (not `cli`), because `Repo::fetch/push` resolve URLs from `.sc/config` inside `repo` — the CLI stays a thin shell. The spec's `UnknownObject` wire code exists (`EC_NOT_FOUND`) but reconstructs as `Error::Remote(msg)` client-side since no sync logic matches on it.
- **Type consistency:** `open_transport` returns `Box<dyn Transport>`; `transfer_objects` takes `&dyn Transport`; `WireClient::handshake(r, w)` takes reader first, writer second everywhere (`connect`, `StdioTransport::spawn`); body helpers named `*_body`/`decode_*_body` consistently.
- **Assumption to verify early (Task 2, Step 1 note):** the exact name of `Repo::open`; match the existing tests if it differs.
```
