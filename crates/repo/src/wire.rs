//! Wire protocol for sc-native network transport (P12).
//!
//! Mirrors the [`crate::transport::Transport`] verbs 1:1 over length-prefixed
//! binary frames, so a remote repo behind `sc serve --stdio` behaves exactly
//! like a local one. See ADR-0022.

use std::io::{Read, Write};

use scl_core::ObjectId;

use crate::error::{Error, Result};

/// Protocol version spoken by this build. Bumped only on incompatible changes;
/// both sides exchange it in `HELLO` before any repo access. Bumped 1 -> 2 in
/// P25: the single-frame pack encoding (`PutPack(Vec<u8>)` request payload,
/// whole-pack `GetPack` response body) is dropped in favor of the chunked
/// pack sub-stream (`write_pack_stream`/`read_pack_stream`), so a v1 peer and
/// a v2 peer can no longer usefully talk to each other — the version check
/// in `serve`/`WireClient::handshake` refuses the mismatch before either
/// side touches a pack verb. Bumped 2 -> 3 in P27: `Request::GetPack` gains a
/// `filter: Vec<String>` field (empty = no filter, full transfer) — a v2
/// peer's decoder doesn't know to read that trailing field, so the versions
/// are wire-incompatible for `GetPack` even though every other verb's
/// encoding is unchanged.
pub const PROTOCOL_VERSION: u32 = 3;

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

// Pack sub-stream frame markers (P25). Distinct from the request opcodes and
// response status bytes above, since a debugging dump of raw frames should
// never have to guess which "namespace" a leading byte belongs to — though
// each frame stream (requests, responses, pack sub-stream) is only ever
// interpreted in its own context.
pub(crate) const ST_PACK_CHUNK: u8 = 0x20;
pub(crate) const ST_PACK_END: u8 = 0x21;

/// Chunk size `write_pack_stream` callers use by default in production: 1 MiB.
/// Bounds peak RAM on both ends of a streamed pack transfer. Additive,
/// unversioned wire addition (P25) — does not change `PROTOCOL_VERSION`.
pub const CHUNK_SIZE: usize = 1 << 20;

/// The chunk size a `write_pack_stream` caller on THIS process should
/// actually use: an `SC_PACK_CHUNK` (bytes, must parse as a nonzero `usize`)
/// override if set, else [`CHUNK_SIZE`]. Read fresh at each stream start —
/// the same pattern `stdio_transport::ssh_command` uses for `SC_SSH` — so
/// both a unit test and `demo/run_ssh_remote_demo.sh` can force many small
/// chunk frames without needing a multi-megabyte fixture to prove the
/// streaming path is real. Both ends of a transfer (the server's `GetPack`
/// sender, the client's `PutPack` sender) call this, so setting the var
/// before either side starts affects the whole round trip.
pub fn pack_chunk_size() -> usize {
    std::env::var("SC_PACK_CHUNK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(CHUNK_SIZE)
}

// Wire error codes. Typed errors that sync logic relies on get their own code;
// everything else degrades to EC_OTHER and surfaces as `Error::Remote(msg)`.
const EC_NOT_A_REPO: u8 = 1;
const EC_NON_FAST_FORWARD: u8 = 2;
const EC_NOT_FOUND: u8 = 3;
const EC_PROTOCOL: u8 = 4;
/// P29: the server is enforcing a read-only serve-token policy and refused a
/// mutating verb before any store write. See [`serve_with_policy`].
const EC_READONLY: u8 = 5;
pub(crate) const EC_TOO_LARGE: u8 = 6;
const EC_OTHER: u8 = 255;

/// A client request — the wire mirror of one [`crate::transport::Transport`]
/// verb (plus `Hello`/`Bye` session control).
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Hello {
        version: u32,
    },
    Bye,
    ListRefs,
    HeadBranch,
    HasObject(ObjectId),
    GetObject(ObjectId),
    PutObject {
        id: ObjectId,
        bytes: Vec<u8>,
    },
    UpdateRef {
        branch: String,
        id: ObjectId,
        expected_old: Option<ObjectId>,
    },
    /// `filter`: partial-clone prefix list (P27 Task 3), empty = no filter
    /// (full transfer, matching pre-P27 behavior byte-for-byte).
    GetPack {
        wants: Vec<ObjectId>,
        haves: Vec<ObjectId>,
        filter: Vec<String>,
    },
    /// Marker only (P25) — the pack body is no longer embedded in this
    /// request's frame. Immediately after this request frame, the sender
    /// streams the pack as `ST_PACK_CHUNK`/`ST_PACK_END` frames
    /// (`write_pack_stream`); the receiver destreams them
    /// (`read_pack_stream`) before replying.
    PutPack,
}

// --- field encoding helpers (length-prefixed, matching core's canonical style) ---

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    // A field can't exceed the u32 frame limit; write_frame enforces the total.
    put_u32(
        out,
        u32::try_from(b.len()).expect("field exceeds frame limit"),
    );
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

/// `u32` count + each string (P27 Task 3's `GetPack.filter` field). Empty
/// slice encodes as a bare `0` count, matching how an absent/None filter
/// round-trips.
fn put_strs(out: &mut Vec<u8>, strs: &[String]) {
    put_u32(out, strs.len() as u32);
    for s in strs {
        put_str(out, s);
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
    /// Read a length prefix used to PRE-SIZE a collection, rejecting a fabricated
    /// count that exceeds the bytes actually remaining in the frame. Every element
    /// consumes >= 1 byte, so `n > remaining` can never be satisfied and is a
    /// hostile/corrupt frame (mirrors `object::Reader::count`, the same guard the
    /// P28 object-decode caps use). Use this — not the raw `u32()` — anywhere the
    /// count drives a `Vec::with_capacity`.
    fn count(&mut self) -> Result<usize> {
        let n = self.u32()? as usize;
        let remaining = self.b.len() - self.off;
        if n > remaining {
            return Err(Error::Protocol(format!(
                "fabricated count {n} exceeds {remaining} remaining bytes"
            )));
        }
        Ok(n)
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| Error::Protocol("non-utf8 string".into()))
    }
    fn strs(&mut self) -> Result<Vec<String>> {
        let n = self.u32()? as usize;
        (0..n).map(|_| self.str()).collect()
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
            Request::UpdateRef {
                branch,
                id,
                expected_old,
            } => {
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
            Request::GetPack {
                wants,
                haves,
                filter,
            } => {
                out.push(OP_GET_PACK);
                put_ids(&mut out, wants);
                put_ids(&mut out, haves);
                put_strs(&mut out, filter);
            }
            Request::PutPack => out.push(OP_PUT_PACK),
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
            OP_PUT_OBJECT => Request::PutObject {
                id: c.id()?,
                bytes: c.bytes()?,
            },
            OP_UPDATE_REF => {
                let branch = c.str()?;
                let id = c.id()?;
                let expected_old = match c.u8()? {
                    0 => None,
                    1 => Some(c.id()?),
                    _ => return Err(Error::Protocol("bad expected_old flag".into())),
                };
                Request::UpdateRef {
                    branch,
                    id,
                    expected_old,
                }
            }
            OP_GET_PACK => Request::GetPack {
                wants: c.ids()?,
                haves: c.ids()?,
                filter: c.strs()?,
            },
            OP_PUT_PACK => Request::PutPack,
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
    if len > scl_core::MAX_OBJECT_SIZE {
        return Err(Error::Protocol(format!(
            "frame length {len} exceeds MAX_OBJECT_SIZE"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|_| Error::Protocol(format!("EOF inside {len}-byte frame body")))?;
    Ok(Some(buf))
}

// --- pack sub-stream (P25) ---
//
// A pack stream is a sequence of ordinary frames (via `write_frame`/
// `read_frame`) layered on top of the existing framing with no format
// change to `Request`/`Response`: each frame's payload starts with either
// `ST_PACK_CHUNK` followed by up to `chunk_size` bytes of pack data, or
// `ST_PACK_END` with no payload. Where in the protocol a stream begins is a
// Task 4 concern (which request/response introduces it); this only defines
// the chunk+end framing itself.

/// Stream everything from `src` to `w` as `ST_PACK_CHUNK` frames of at most
/// `chunk_size` bytes each, terminated by one `ST_PACK_END` frame. Peak RAM
/// is `chunk_size` (one buffer, reused per chunk). `chunk_size` is a
/// parameter so tests can force a tiny value; production callers pass
/// [`CHUNK_SIZE`].
pub fn write_pack_stream(
    w: &mut impl Write,
    src: &mut (impl Read + ?Sized),
    chunk_size: usize,
) -> Result<()> {
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = read_up_to(src, &mut buf)?;
        if n == 0 {
            write_frame(w, &[ST_PACK_END])?;
            return Ok(());
        }
        let mut payload = Vec::with_capacity(1 + n);
        payload.push(ST_PACK_CHUNK);
        payload.extend_from_slice(&buf[..n]);
        write_frame(w, &payload)?;
    }
}

/// Fill `buf` by repeated `read` calls until either `buf` is full or `src`
/// hits EOF, returning the number of bytes filled. Unlike `read_exact`, a
/// short read at EOF is not an error — it's how the last, possibly-ragged
/// chunk is detected.
fn read_up_to(src: &mut (impl Read + ?Sized), buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = src.read(&mut buf[filled..])?;
        if n == 0 {
            break; // EOF
        }
        filled += n;
    }
    Ok(filled)
}

/// Read `ST_PACK_CHUNK` frames from `r`, writing each chunk's bytes to
/// `sink`, until `ST_PACK_END`. Peak RAM is one chunk (frames are read whole,
/// as `read_frame` already requires, but never buffered across chunks).
/// Returns the total number of bytes streamed. Any frame that is neither a
/// well-formed chunk nor the end marker — including EOF before `ST_PACK_END`
/// — is `Err(Error::Protocol(_))`.
///
/// `max_bytes` bounds the total bytes written to `sink`: if `max_bytes != 0`
/// and a chunk would exceed the budget, aborts with `Error::PackTooLarge`
/// *before* writing the chunk. `max_bytes == 0` means unlimited.
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
    let (&status, rest) = frame
        .split_first()
        .ok_or_else(|| Error::Protocol("empty response frame".into()))?;
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
        Error::ReadOnly => EC_READONLY,
        Error::PackTooLarge(_) => EC_TOO_LARGE,
        _ => EC_OTHER,
    };
    (code, e.to_string())
}

/// Reconstruct a typed error from its wire code; unknown/untyped codes become
/// `Error::Remote(msg)` so the message is never lost.
pub fn wire_to_err(code: u8, msg: String) -> Error {
    match code {
        EC_NOT_A_REPO => Error::NotARepo,
        EC_NON_FAST_FORWARD => Error::NonFastForward,
        EC_PROTOCOL => Error::Protocol(msg),
        EC_READONLY => Error::ReadOnly,
        EC_TOO_LARGE => Error::PackTooLarge(msg),
        _ => Error::Remote(msg), // EC_NOT_FOUND + EC_OTHER: typed enough as text
    }
}

/// Alias for backward compatibility with existing call sites.
fn err_from_wire(code: u8, msg: String) -> Error {
    wire_to_err(code, msg)
}

// --- response body builders/decoders (one symmetric pair per verb shape) ---

/// Response body for Hello: the server's protocol version.
pub fn u32_body(v: u32) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, v);
    b
}
/// Decode a Hello response body.
pub fn decode_u32_body(b: &[u8]) -> Result<u32> {
    let mut c = Cur::new(b);
    let v = c.u32()?;
    c.done()?;
    Ok(v)
}

/// Response body for HeadBranch: the current branch name.
pub fn str_body(s: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, s);
    b
}
/// Decode a HeadBranch response body.
pub fn decode_str_body(b: &[u8]) -> Result<String> {
    let mut c = Cur::new(b);
    let s = c.str()?;
    c.done()?;
    Ok(s)
}

/// Response body for HasObject: whether the object is stored.
pub fn bool_body(v: bool) -> Vec<u8> {
    vec![v as u8]
}
/// Decode a HasObject response body.
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

/// Response body for PutPack: the object IDs written to the repo.
pub fn ids_body(ids: &[ObjectId]) -> Vec<u8> {
    let mut b = Vec::new();
    put_ids(&mut b, ids);
    b
}
/// Decode a PutPack response body.
pub fn decode_ids_body(b: &[u8]) -> Result<Vec<ObjectId>> {
    let mut c = Cur::new(b);
    let ids = c.ids()?;
    c.done()?;
    Ok(ids)
}

/// Response body for ListRefs: the remote's (branch, tip) pairs.
pub fn refs_body(refs: &[(String, ObjectId)]) -> Vec<u8> {
    let mut b = Vec::new();
    put_u32(&mut b, refs.len() as u32);
    for (branch, id) in refs {
        put_str(&mut b, branch);
        put_id(&mut b, id);
    }
    b
}
/// Decode a ListRefs response body.
pub fn decode_refs_body(b: &[u8]) -> Result<Vec<(String, ObjectId)>> {
    let mut c = Cur::new(b);
    let n = c.count()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let branch = c.str()?;
        let id = c.id()?;
        out.push((branch, id));
    }
    c.done()?;
    Ok(out)
}

use crate::transport::{LocalTransport, Transport};

/// Default cap on an incoming `PutPack` spool when no operator override is
/// configured (P31): 16 GiB. Threaded through [`WirePolicy::max_pack_size`];
/// `0` means unlimited.
pub const DEFAULT_MAX_PACK_SIZE: u64 = 16 * 1024 * 1024 * 1024;

/// Cap on how much of a read-only connection's rejected `PutPack` stream is
/// drained to disk before the connection is closed rather than kept in sync
/// (P31): 8 MiB. A read-only push is going to be thrown away regardless, so
/// there is no reason to spool an attacker-sized pack just to reject it —
/// unlike the normal `PutPack` arm, which must accept up to
/// [`WirePolicy::max_pack_size`] because that pack might actually be used.
pub const RO_DRAIN_CAP: u64 = 8 * 1024 * 1024;

/// Per-connection policy for [`serve_with_policy`] (P31): read-only gating
/// (P29) plus the two spool caps above. `Default` matches every pre-P31
/// caller's prior unbounded behavior for `read_only`/`ro_drain_cap` sizing
/// intent, but now bounds `max_pack_size` to [`DEFAULT_MAX_PACK_SIZE`] rather
/// than leaving `PutPack` spool growth unbounded.
#[derive(Debug, Clone, Copy)]
pub struct WirePolicy {
    pub read_only: bool,
    /// Cap on a normal (non-read-only) `PutPack` spool, in bytes. `0` means
    /// unlimited.
    pub max_pack_size: u64,
    /// Cap on how much of a read-only connection's rejected `PutPack` stream
    /// is drained before closing the connection, in bytes.
    pub ro_drain_cap: u64,
}

impl Default for WirePolicy {
    fn default() -> Self {
        Self {
            read_only: false,
            max_pack_size: DEFAULT_MAX_PACK_SIZE,
            ro_drain_cap: RO_DRAIN_CAP,
        }
    }
}

/// Validate an operator-supplied `--max-pack-size` value. `0` (unlimited) is
/// always fine; a nonzero cap below [`scl_core::MAX_OBJECT_SIZE`] can never
/// fit even one object and is rejected as a misconfiguration rather than
/// silently failing every push at runtime.
pub fn validate_max_pack_size(max: u64) -> Result<()> {
    if max != 0 && max < scl_core::MAX_OBJECT_SIZE as u64 {
        return Err(Error::InvalidArgument(format!(
            "--max-pack-size {max} is below MAX_OBJECT_SIZE ({}); a cap that cannot fit one object is a misconfiguration",
            scl_core::MAX_OBJECT_SIZE
        )));
    }
    Ok(())
}

/// Serve the repo at `root` to one wire-protocol peer until `Bye`/EOF.
///
/// This is the whole server: every verb dispatches onto [`LocalTransport`],
/// so CAS ref updates, pack verification, and hash-verified reads behave
/// exactly as for a local remote. Verb failures are *replies*; only protocol
/// violations end the session.
///
/// `policy.read_only` (P29): when true, the three mutating verbs
/// (`PutObject`/`PutPack`/`UpdateRef`) are rejected with [`Error::ReadOnly`]
/// BEFORE any store write; read verbs are always allowed. `policy.max_pack_size`
/// / `policy.ro_drain_cap` (P31) bound the `PutPack` spool in both the normal
/// and read-only-drain arms. [`serve`] is the `WirePolicy::default()` wrapper
/// every pre-P31 caller uses unchanged.
pub fn serve_with_policy(
    root: &std::path::Path,
    r: &mut impl Read,
    w: &mut impl Write,
    policy: WirePolicy,
) -> Result<()> {
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
                &format!(
                    "unsupported protocol version {version} (server speaks {PROTOCOL_VERSION})"
                ),
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

        // P29 read-only gate: reject mutating verbs before any store write.
        if policy.read_only {
            match &req {
                Request::PutObject { .. } | Request::UpdateRef { .. } => {
                    // Single request frames — nothing trails them; reject and
                    // continue keeps the connection in sync.
                    let (code, msg) = err_to_wire(&Error::ReadOnly);
                    write_err(w, code, &msg)?;
                    continue;
                }
                Request::PutPack => {
                    // The client streams the whole pack immediately after the
                    // request frame (before reading a response), so drain it
                    // to keep the connection in sync — then reject. The pack
                    // is spilled to a temp file and DROPPED (never ingested),
                    // so no object reaches the store: "rejected before any
                    // store write" holds. `spill_pack_stream` + guard drop is
                    // the same bounded-RAM machinery the normal PutPack arm
                    // uses, bounded to `policy.ro_drain_cap` (P31) rather than
                    // the normal arm's larger `max_pack_size` — a read-only
                    // push is discarded regardless, so there's no reason to
                    // spool an attacker-sized pack just to reject it.
                    match spill_pack_stream(r, transport.layout(), policy.ro_drain_cap) {
                        Ok(guard) => {
                            drop(guard);
                            let (code, msg) = err_to_wire(&Error::ReadOnly);
                            write_err(w, code, &msg)?;
                            continue;
                        }
                        Err(Error::PackTooLarge(_)) => {
                            // Over the drain cap: the stream is desynced (we
                            // stopped reading mid-pack), so a best-effort
                            // reply is all we can do — then close.
                            let (code, msg) = err_to_wire(&Error::ReadOnly);
                            let _ = write_err(w, code, &msg);
                            return Ok(());
                        }
                        Err(e) => return Err(e),
                    }
                }
                _ => {}
            }
        }

        // GetPack and PutPack (P25) can't go through the generic
        // "compute a body, write_ok/write_err it" dispatch below: neither
        // side may ever hold the whole pack in one buffer. Both are handled
        // here, inline, writing their own response frame(s) — including,
        // for GetPack's success case, the chunk-stream frames that follow
        // the initial (empty-body) OK frame.
        match req {
            Request::Bye => return Ok(()),
            Request::GetPack {
                wants,
                haves,
                filter,
            } => {
                let filter_opt = if filter.is_empty() {
                    None
                } else {
                    Some(filter.as_slice())
                };
                match transport.build_pack_tempfile(&wants, &haves, filter_opt) {
                    Ok(guard) => {
                        // Building the temp pack file (bounded RAM: one
                        // object at a time via PackWriter) fully succeeded
                        // before any wire byte for this response was sent,
                        // so an OK/ERR split here is still clean — no
                        // partial stream can ever follow an ERR.
                        write_ok(w, &[])?; // empty body: "stream follows"
                        let mut f = std::fs::File::open(guard.path())?;
                        write_pack_stream(w, &mut f, pack_chunk_size())?;
                        // `guard` drops here — temp pack file removed.
                    }
                    Err(e) => {
                        let (code, msg) = err_to_wire(&e);
                        write_err(w, code, &msg)?;
                    }
                }
            }
            Request::PutPack => {
                match spill_pack_stream(r, transport.layout(), policy.max_pack_size) {
                    Ok(guard) => {
                        match transport.ingest_from(guard.path()) {
                            Ok(ids) => write_ok(w, &ids_body(&ids))?,
                            Err(e) => {
                                let (code, msg) = err_to_wire(&e);
                                write_err(w, code, &msg)?;
                            }
                        }
                        // `guard` drops here — temp pack file removed,
                        // whether ingestion succeeded or failed.
                    }
                    Err(e @ Error::PackTooLarge(_)) => {
                        // Over the cap: the stream is desynced (we stopped
                        // reading mid-pack, so any bytes still on the wire
                        // are neither read nor a subsequent request), so a
                        // best-effort reply is the most we can do — then
                        // close the connection rather than try to serve
                        // further requests off a desynced stream.
                        let (code, msg) = err_to_wire(&e);
                        let _ = write_err(w, code, &msg);
                        return Ok(());
                    }
                    Err(e) => {
                        let (code, msg) = err_to_wire(&e);
                        write_err(w, code, &msg)?;
                    }
                }
            }
            other => {
                let result: Result<Vec<u8>> = match other {
                    Request::Hello { .. } => {
                        Err(Error::Protocol("unexpected HELLO mid-session".into()))
                    }
                    Request::ListRefs => transport.list_refs().map(|refs| refs_body(&refs)),
                    Request::HeadBranch => transport.head_branch().map(|s| str_body(&s)),
                    Request::HasObject(id) => transport.has_object(&id).map(bool_body),
                    Request::GetObject(id) => transport.get_object(&id),
                    Request::PutObject { id, bytes } => {
                        transport.put_object(&id, &bytes).map(|()| Vec::new())
                    }
                    Request::UpdateRef {
                        branch,
                        id,
                        expected_old,
                    } => transport
                        .update_ref(&branch, &id, expected_old.as_ref())
                        .map(|()| Vec::new()),
                    Request::Bye | Request::GetPack { .. } | Request::PutPack => {
                        unreachable!("handled above")
                    }
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
    }
}

/// Serve with full read/write access and default spool caps — the pre-P29
/// behavior for read-only, now with `WirePolicy::default()`'s bounded
/// `max_pack_size`/`ro_drain_cap` (P31). Every existing caller (stdio
/// transport, sync, tests) uses this unchanged.
pub fn serve(root: &std::path::Path, r: &mut impl Read, w: &mut impl Write) -> Result<()> {
    serve_with_policy(root, r, w, WirePolicy::default())
}

/// Destream an incoming pack chunk stream (`ST_PACK_CHUNK`/`ST_PACK_END`
/// frames immediately following a `PutPack` request frame) straight to a
/// fresh temp pack file, bounded to one chunk in RAM at a time. The guard is
/// created before any read, so a stream that errors partway (a malformed
/// frame, a dropped connection) still leaves nothing behind — `Drop` removes
/// whatever was written so far. `max_bytes` bounds the spool (0 = unlimited,
/// P31) — see [`read_pack_stream`].
fn spill_pack_stream(
    r: &mut impl Read,
    layout: &crate::layout::Layout,
    max_bytes: u64,
) -> Result<crate::transport::TempPackGuard> {
    let guard = crate::transport::TempPackGuard::new(layout)?;
    let mut f = std::fs::File::create(guard.path())?;
    read_pack_stream(r, &mut f, max_bytes)?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::ObjectId;

    fn some_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

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
    fn every_request_encodes_and_decodes_roundtrip() {
        let reqs = vec![
            Request::Hello {
                version: PROTOCOL_VERSION,
            },
            Request::Bye,
            Request::ListRefs,
            Request::HeadBranch,
            Request::HasObject(some_id(1)),
            Request::GetObject(some_id(2)),
            Request::PutObject {
                id: some_id(3),
                bytes: b"payload".to_vec(),
            },
            Request::UpdateRef {
                branch: "main".into(),
                id: some_id(4),
                expected_old: None,
            },
            Request::UpdateRef {
                branch: "dev".into(),
                id: some_id(5),
                expected_old: Some(some_id(6)),
            },
            Request::GetPack {
                wants: vec![some_id(7)],
                haves: vec![some_id(8), some_id(9)],
                filter: vec![],
            },
            Request::GetPack {
                wants: vec![some_id(7)],
                haves: vec![],
                filter: vec!["src/".to_string(), "docs/".to_string()],
            },
            Request::GetPack {
                wants: vec![],
                haves: vec![],
                filter: vec![],
            },
            Request::PutPack,
        ];
        for req in reqs {
            let bytes = req.encode();
            assert_eq!(
                Request::decode(&bytes).unwrap(),
                req,
                "roundtrip failed for {req:?}"
            );
        }
    }

    #[test]
    fn truncated_and_junk_requests_are_protocol_errors() {
        // Truncated HasObject: opcode but only half an id.
        let mut bytes = Request::HasObject(some_id(1)).encode();
        bytes.truncate(10);
        assert!(matches!(
            Request::decode(&bytes),
            Err(crate::error::Error::Protocol(_))
        ));
        // Unknown opcode.
        assert!(matches!(
            Request::decode(&[0x7f]),
            Err(crate::error::Error::Protocol(_))
        ));
        // Empty frame.
        assert!(matches!(
            Request::decode(&[]),
            Err(crate::error::Error::Protocol(_))
        ));
        // Trailing garbage after a well-formed request.
        let mut bytes = Request::Bye.encode();
        bytes.push(0);
        assert!(matches!(
            Request::decode(&bytes),
            Err(crate::error::Error::Protocol(_))
        ));
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
        assert!(matches!(
            read_frame(&mut r),
            Err(crate::error::Error::ConnectionLost(_))
        ));
        // Server-style read: EOF at a frame boundary is a clean end-of-session.
        let mut r2 = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame_opt(&mut r2).unwrap().is_none());
        // EOF mid-frame is a protocol error even for the server.
        let mut r3 = std::io::Cursor::new(vec![0, 0, 0, 9, b'x']);
        assert!(matches!(
            read_frame_opt(&mut r3),
            Err(crate::error::Error::Protocol(_))
        ));
    }

    #[test]
    fn frame_over_cap_rejected() {
        // A frame header alone (no body) claiming a length past
        // MAX_OBJECT_SIZE must be rejected before any allocation of the
        // (fictitious) body — feeding only the 4-byte header proves this:
        // if the implementation tried to `vec![0u8; len]` and then
        // `read_exact`, it would hang/OOM here rather than erroring.
        let over = (scl_core::MAX_OBJECT_SIZE + 1) as u32;
        let mut r = std::io::Cursor::new(over.to_be_bytes().to_vec());
        let err = read_frame_opt(&mut r).unwrap_err();
        assert!(
            matches!(err, crate::error::Error::Protocol(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn responses_carry_ok_bodies_and_typed_errors() {
        let mut buf: Vec<u8> = Vec::new();
        write_ok(&mut buf, b"body").unwrap();
        let mut r = std::io::Cursor::new(buf);
        assert_eq!(
            parse_response(read_frame(&mut r).unwrap()).unwrap(),
            b"body"
        );

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
            assert_eq!(
                matches!(back, crate::error::Error::NonFastForward),
                expect_nff
            );
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
        let refs = vec![
            ("dev".to_string(), some_id(3)),
            ("main".to_string(), some_id(4)),
        ];
        assert_eq!(decode_refs_body(&refs_body(&refs)).unwrap(), refs);
        // Truncated bodies are protocol errors, not panics.
        assert!(matches!(
            decode_refs_body(&[0, 0, 0, 5]),
            Err(crate::error::Error::Protocol(_))
        ));
    }

    /// A hostile server can claim a `ListRefs` count beyond the frame's actual
    /// bytes — here 5 entries with ZERO entry bytes following. The old
    /// `Vec::with_capacity(n)` on a raw `u32()` read would pre-size on that
    /// fabricated count on the CLIENT before validating any entry — a
    /// client-side DoS on every clone/fetch/push. `count()` must reject on
    /// `n > remaining` (5 > 0) BEFORE the alloc / the loop. A modest count
    /// (not `0xFFFF_FFFF`) so a reverted guard can't abort the test process on
    /// a non-overcommit allocator; the message check pins that the COUNT guard
    /// fired, not the downstream `str()` truncation error (which would mask a
    /// revert to `u32()`). P28 final review, mirroring `object::Reader::count`.
    #[test]
    fn decode_refs_body_rejects_fabricated_count() {
        let body = 5u32.to_be_bytes();
        let err = decode_refs_body(&body).unwrap_err();
        match err {
            Error::Protocol(m) => assert!(m.contains("fabricated count"), "wrong error: {m}"),
            other => panic!("expected Protocol(fabricated count), got {other:?}"),
        }
    }

    #[test]
    fn serve_answers_hello_then_verbs_until_bye() {
        let root = tmp_repo("serve");
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let tip = crate::repo::Repo::open(&root)
            .unwrap()
            .commit("t", "c1")
            .unwrap();

        let responses = run_session(
            &root,
            &[
                Request::Hello {
                    version: PROTOCOL_VERSION,
                },
                Request::ListRefs,
                Request::HeadBranch,
                Request::HasObject(tip),
                Request::Bye,
            ],
        );
        assert_eq!(responses.len(), 4); // Bye gets no response
        assert_eq!(
            decode_u32_body(responses[0].as_ref().unwrap()).unwrap(),
            PROTOCOL_VERSION
        );
        let refs = decode_refs_body(responses[1].as_ref().unwrap()).unwrap();
        assert_eq!(refs, vec![("main".to_string(), tip)]);
        assert_eq!(
            decode_str_body(responses[2].as_ref().unwrap()).unwrap(),
            "main"
        );
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

        let responses = run_session(
            &root,
            &[Request::Hello {
                version: PROTOCOL_VERSION,
            }],
        );
        assert!(matches!(responses[0], Err(Error::NotARepo)));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serve_ends_cleanly_on_eof_without_bye() {
        let root = tmp_repo("eof");
        // No Bye at the end: input just runs out. serve must return Ok.
        let responses = run_session(
            &root,
            &[
                Request::Hello {
                    version: PROTOCOL_VERSION,
                },
                Request::ListRefs,
            ],
        );
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
                Request::Hello {
                    version: PROTOCOL_VERSION,
                },
                Request::GetObject(missing), // NotFound on the server
                Request::HeadBranch,         // session must still be alive
                Request::Bye,
            ],
        );
        assert!(responses[1].is_err());
        assert_eq!(
            decode_str_body(responses[2].as_ref().unwrap()).unwrap(),
            "main"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn pack_stream_round_trip_many_chunks() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut buf = Vec::new();
        write_pack_stream(&mut buf, &mut std::io::Cursor::new(&data), 7).unwrap();

        // More than one chunk frame must have been written: 10_000 / 7 chunks
        // plus one END frame.
        let mut count = 0;
        let mut r = std::io::Cursor::new(buf.clone());
        while let Some(_frame) = read_frame_opt(&mut r).unwrap() {
            count += 1;
        }
        assert!(count > 1, "expected many chunk frames, got {count}");

        let mut sink = Vec::new();
        let mut r = std::io::Cursor::new(buf);
        let total = read_pack_stream(&mut r, &mut sink, 0).unwrap();
        assert_eq!(total, data.len() as u64);
        assert_eq!(sink, data);
    }

    #[test]
    fn pack_stream_exact_multiple_and_ragged() {
        let chunk_size = 16;
        for extra in [0usize, 3] {
            let len = 2 * chunk_size + extra;
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let mut buf = Vec::new();
            write_pack_stream(&mut buf, &mut std::io::Cursor::new(&data), chunk_size).unwrap();
            let mut sink = Vec::new();
            let total = read_pack_stream(&mut std::io::Cursor::new(buf), &mut sink, 0).unwrap();
            assert_eq!(total, data.len() as u64);
            assert_eq!(sink, data, "mismatch for len={len}");
        }
    }

    #[test]
    fn pack_stream_empty() {
        let data: Vec<u8> = Vec::new();
        let mut buf = Vec::new();
        write_pack_stream(&mut buf, &mut std::io::Cursor::new(&data), 7).unwrap();
        let mut sink = Vec::new();
        let total = read_pack_stream(&mut std::io::Cursor::new(buf), &mut sink, 0).unwrap();
        assert_eq!(total, 0);
        assert!(sink.is_empty());
    }

    /// Connect a `WireClient` to a `serve_with_policy` thread over in-process
    /// pipes. Mirrors `stdio_transport::tests::connect`, adding the
    /// `read_only` parameter (P29 Task 3).
    fn spawn_wire_pair_with_policy(
        root: &std::path::Path,
        read_only: bool,
    ) -> (
        crate::stdio_transport::WireClient<std::io::PipeReader, std::io::PipeWriter>,
        std::thread::JoinHandle<Result<()>>,
    ) {
        let root = root.to_path_buf();
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let handle = std::thread::spawn(move || {
            let policy = WirePolicy {
                read_only,
                ..Default::default()
            };
            serve_with_policy(&root, &mut server_read, &mut server_write, policy)
        });
        let client =
            crate::stdio_transport::WireClient::handshake(client_read, client_write).unwrap();
        (client, handle)
    }

    #[test]
    fn read_only_policy_rejects_mutations_allows_reads() {
        use crate::transport::Transport;

        let root = tmp_repo("readonly");
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        crate::repo::Repo::open(&root)
            .unwrap()
            .commit("t", "c1")
            .unwrap();

        let (client, server_join) = spawn_wire_pair_with_policy(&root, true);

        // A read verb succeeds under read-only.
        assert!(client.list_refs().is_ok(), "reads allowed under read-only");

        // A single-frame mutating verb (UpdateRef) is rejected with the
        // read-only error, and the connection stays usable afterward.
        let err = client.update_ref("main", &some_id(0xAB), None).unwrap_err();
        assert!(
            matches!(err, Error::ReadOnly)
                || matches!(&err, Error::Remote(m) if m.contains("read-only")),
            "update_ref rejected read-only, got {err:?}"
        );

        // PutObject (single-frame) is also rejected.
        let blob = scl_core::Object::blob(b"payload".to_vec());
        let (id, bytes) = (blob.id(), blob.encode());
        let err = client.put_object(&id, &bytes).unwrap_err();
        assert!(
            matches!(err, Error::ReadOnly)
                || matches!(&err, Error::Remote(m) if m.contains("read-only")),
            "put_object rejected read-only, got {err:?}"
        );

        // PutPack streams its whole body before reading a response — the
        // server must DRAIN that stream before rejecting, or the connection
        // desyncs and this call would surface a broken-pipe/IO error rather
        // than a clean Error::ReadOnly. This is the regression the brief's
        // drain-path correction targets.
        let (pack, _idx) = scl_core::pack::build_pack(&[(id, bytes)]).unwrap();
        let err = client
            .put_pack(&mut std::io::Cursor::new(pack))
            .unwrap_err();
        assert!(
            matches!(err, Error::ReadOnly)
                || matches!(&err, Error::Remote(m) if m.contains("read-only")),
            "put_pack rejected read-only (not desynced/IO error), got {err:?}"
        );

        // The connection is still in sync after all three rejections: a
        // further read verb still works.
        assert_eq!(client.head_branch().unwrap(), "main");

        client.bye().unwrap();
        drop(client);
        server_join.join().unwrap().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serve_wrapper_still_permits_mutations() {
        use crate::transport::Transport;

        let root = tmp_repo("rw-wrapper");
        crate::repo::Repo::open(&root).unwrap();

        // `serve` (not `serve_with_policy(.., false)` directly) is the
        // pre-P29 rw path every existing caller uses; it must still allow a
        // mutating verb end to end.
        let root2 = root.clone();
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let server_join =
            std::thread::spawn(move || serve(&root2, &mut server_read, &mut server_write));
        let client =
            crate::stdio_transport::WireClient::handshake(client_read, client_write).unwrap();

        let blob = scl_core::Object::blob(b"rw payload".to_vec());
        let (id, bytes) = (blob.id(), blob.encode());
        client.put_object(&id, &bytes).unwrap();
        assert!(client.has_object(&id).unwrap());

        client.bye().unwrap();
        drop(client);
        server_join.join().unwrap().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn read_pack_stream_rejects_missing_end() {
        // Chunk frames followed by EOF, no ST_PACK_END.
        let mut buf = Vec::new();
        write_frame(&mut buf, &[ST_PACK_CHUNK, b'a', b'b']).unwrap();
        let mut sink = Vec::new();
        let err = read_pack_stream(&mut std::io::Cursor::new(buf), &mut sink, 0).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(_)),
            "expected Protocol error, got {err:?}"
        );

        // A wrong-opcode frame mid-stream.
        let mut buf = Vec::new();
        write_frame(&mut buf, &[ST_PACK_CHUNK, b'a']).unwrap();
        write_frame(&mut buf, &[ST_OK]).unwrap(); // not a valid pack-stream marker
        let mut sink = Vec::new();
        let err = read_pack_stream(&mut std::io::Cursor::new(buf), &mut sink, 0).unwrap_err();
        assert!(
            matches!(err, Error::Protocol(_)),
            "expected Protocol error, got {err:?}"
        );
    }

    #[test]
    fn pack_stream_over_budget_aborts_typed() {
        let payload = vec![7u8; 4096];
        let mut buf = Vec::new();
        write_pack_stream(&mut buf, &mut std::io::Cursor::new(&payload), 1024).unwrap();
        let mut sink = Vec::new();
        let err = read_pack_stream(&mut std::io::Cursor::new(buf), &mut sink, 2048).unwrap_err();
        assert!(matches!(err, Error::PackTooLarge(_)), "got {err:?}");
        assert!(
            sink.len() <= 2048,
            "sink got over-budget bytes: {}",
            sink.len()
        );
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

    /// A PutPack whose chunk stream exceeds policy.max_pack_size gets a
    /// best-effort EC_TOO_LARGE reply and the connection closes (desync).
    #[test]
    fn putpack_over_cap_replies_too_large_and_closes() {
        let root = tmp_repo("cap");
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            }
            .encode(),
        )
        .unwrap();
        write_frame(&mut input, &Request::PutPack.encode()).unwrap();
        let payload = vec![9u8; 8192];
        write_pack_stream(&mut input, &mut std::io::Cursor::new(&payload), 1024).unwrap();
        // A trailing request that must never be answered (connection closed):
        write_frame(&mut input, &Request::HeadBranch.encode()).unwrap();

        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        let policy = WirePolicy {
            read_only: false,
            max_pack_size: 4096,
            ro_drain_cap: RO_DRAIN_CAP,
        };
        serve_with_policy(&root, &mut reader, &mut output, policy).unwrap();

        let mut frames = Vec::new();
        let mut r = std::io::Cursor::new(output);
        while let Some(f) = read_frame_opt(&mut r).unwrap() {
            frames.push(parse_response(f));
        }
        assert_eq!(
            frames.len(),
            2,
            "hello-ok + too-large error only, got {frames:?}"
        );
        assert!(frames[0].is_ok());
        assert!(matches!(
            frames[1].as_ref().unwrap_err(),
            Error::PackTooLarge(_)
        ));
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

    /// An oversized push on a read-only connection drains at most ro_drain_cap
    /// bytes, then the connection closes; zero spool residue.
    #[test]
    fn readonly_oversized_push_is_dropped_after_drain_cap() {
        let root = tmp_repo("rocap");
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            }
            .encode(),
        )
        .unwrap();
        write_frame(&mut input, &Request::PutPack.encode()).unwrap();
        let payload = vec![9u8; 8192];
        write_pack_stream(&mut input, &mut std::io::Cursor::new(&payload), 1024).unwrap();
        write_frame(&mut input, &Request::HeadBranch.encode()).unwrap(); // must never be answered

        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        let policy = WirePolicy {
            read_only: true,
            max_pack_size: 0,
            ro_drain_cap: 4096,
        };
        serve_with_policy(&root, &mut reader, &mut output, policy).unwrap();

        let mut frames = Vec::new();
        let mut r = std::io::Cursor::new(output);
        while let Some(f) = read_frame_opt(&mut r).unwrap() {
            frames.push(parse_response(f));
        }
        assert_eq!(frames.len(), 2);
        assert!(matches!(
            frames[1].as_ref().unwrap_err(),
            Error::ReadOnly | Error::Remote(_)
        ));
        let tmp = root.join(".sc").join("tmp");
        assert!(!tmp.exists() || std::fs::read_dir(&tmp).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
