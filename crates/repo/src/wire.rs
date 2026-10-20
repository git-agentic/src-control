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
/// encoding is unchanged. Bumped 3 -> 4 in P34 (ADR-0044): two additive
/// object kinds (sealed object, branch manifest) now cross the wire inside
/// packs — a v3 peer's `Object::decode` would hit an unknown tag deep in
/// pack ingest, so the mismatch is refused cleanly at the handshake instead.
/// Bumped 4 -> 5 in P37 (ADR-0047): the additive `GetObjects` verb (batched
/// by-id object fetch) — a v4 server would answer its opcode with an
/// "unknown opcode" protocol error mid-session, so the mismatch is refused at
/// the handshake instead. Bumped 5 -> 6 in ADR-0055: `Request::GetPack` gains a
/// trailing optional `blob_limit` (the `--filter blob:limit=<size>` clone
/// filter, evaluated by the server because only it knows a blob's size). A v5
/// peer would reject the longer frame as trailing bytes, or worse, a v6 limit
/// riding in the prefix list would read as a path, so the mismatch is refused
/// at the handshake in both directions instead.
pub const PROTOCOL_VERSION: u32 = 6;

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
const OP_GET_OBJECTS: u8 = 0x18;

/// Most object ids one `GetObjects` request may carry (ADR-0047). Bounds the
/// server's per-request work and the response a client must be ready to read;
/// a client with a longer frontier splits it into several requests.
pub const MAX_GET_OBJECTS_IDS: usize = 1024;

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
    chunk_from(std::env::var("SC_PACK_CHUNK").ok().as_deref())
}

/// The `SC_PACK_CHUNK` decision, pure so it can be tested without touching the
/// process environment: an unset, unparsable or zero value is the default, and
/// anything larger than the smallest valid receiver accepts is clamped. Caps
/// are receiver-local and unnegotiated, and the smallest a receiver can be set
/// to is [`scl_core::MIN_MAX_OBJECT_SIZE`], so the data is capped one byte
/// below that (the `ST_PACK_CHUNK` tag byte makes the frame exactly that size).
/// Every chunk frame therefore fits any valid receiver, and receivers built
/// before the frame limit gained [`FRAME_OVERHEAD`]; an oversized setting would
/// otherwise fail every large transfer with a confusing error.
fn chunk_from(value: Option<&str>) -> usize {
    value
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(CHUNK_SIZE)
        .min(scl_core::MIN_MAX_OBJECT_SIZE - 1)
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
/// #233: the connection's `--max-conn-bytes` write budget ran out. An
/// older peer degrades an unknown code to `Error::Remote(msg)`, so no
/// `PROTOCOL_VERSION` bump is needed.
const EC_BUDGET: u8 = 7;
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
    /// `filter`: partial-clone prefix list (P27 Task 3), empty = no prefix
    /// filter. `blob_limit` (ADR-0055): leave out blobs of at least that many
    /// bytes that no want's own root tree reaches. The transfer is filtered
    /// when `filter` is non-empty or `blob_limit` is set; with neither it is a
    /// full transfer, matching pre-P27 behavior byte-for-byte.
    GetPack {
        wants: Vec<ObjectId>,
        haves: Vec<ObjectId>,
        filter: Vec<String>,
        blob_limit: Option<u64>,
    },
    /// Marker only (P25) — the pack body is no longer embedded in this
    /// request's frame. Immediately after this request frame, the sender
    /// streams the pack as `ST_PACK_CHUNK`/`ST_PACK_END` frames
    /// (`write_pack_stream`); the receiver destreams them
    /// (`read_pack_stream`) before replying.
    PutPack,
    /// Batched by-id object fetch (P37, ADR-0047): the server answers with an
    /// OK frame whose body lists the ids it will NOT send (absent or
    /// refused), then a chunk stream of the objects it found. At most
    /// [`MAX_GET_OBJECTS_IDS`] ids.
    GetObjects {
        ids: Vec<ObjectId>,
    },
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
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn id(&mut self) -> Result<ObjectId> {
        Ok(ObjectId::from_bytes(self.take(32)?.try_into().unwrap()))
    }
    fn ids(&mut self) -> Result<Vec<ObjectId>> {
        let n = self.u32()? as usize;
        (0..n).map(|_| self.id()).collect()
    }
    /// Like [`Cur::ids`], but rejects a count above `max` before decoding any
    /// id, so an oversize request is refused without work proportional to its
    /// claimed length. Nothing is pre-sized from the count.
    fn ids_capped(&mut self, max: usize) -> Result<Vec<ObjectId>> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(Error::PackTooLarge(format!(
                "request names {n} ids, limit is {max}"
            )));
        }
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
                blob_limit,
            } => {
                out.push(OP_GET_PACK);
                put_ids(&mut out, wants);
                put_ids(&mut out, haves);
                put_strs(&mut out, filter);
                match blob_limit {
                    Some(limit) => {
                        out.push(1);
                        out.extend_from_slice(&limit.to_be_bytes());
                    }
                    None => out.push(0),
                }
            }
            Request::PutPack => out.push(OP_PUT_PACK),
            Request::GetObjects { ids } => {
                out.push(OP_GET_OBJECTS);
                put_ids(&mut out, ids);
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
                blob_limit: match c.u8()? {
                    0 => None,
                    1 => Some(c.u64()?),
                    t => return Err(Error::Protocol(format!("bad blob_limit tag {t}"))),
                },
            },
            OP_PUT_PACK => Request::PutPack,
            OP_GET_OBJECTS => Request::GetObjects {
                ids: c.ids_capped(MAX_GET_OBJECTS_IDS)?,
            },
            op => return Err(Error::Protocol(format!("unknown opcode 0x{op:02x}"))),
        };
        c.done()?;
        Ok(req)
    }

    /// [`Request::decode`] for a frame the caller owns. A `PutObject` object
    /// body is moved out of the frame (the header is shifted off in place)
    /// instead of copied, so a near-cap request holds one copy of the object,
    /// not two. Anything malformed falls through to `decode` for its error.
    pub fn decode_owned(mut frame: Vec<u8>) -> Result<Request> {
        const HEADER: usize = 1 + 32 + 4;
        if frame.len() >= HEADER && frame[0] == OP_PUT_OBJECT {
            let n = u32::from_be_bytes(frame[33..HEADER].try_into().unwrap()) as usize;
            if frame.len() - HEADER == n {
                let id = ObjectId::from_bytes(frame[1..33].try_into().unwrap());
                frame.drain(..HEADER);
                return Ok(Request::PutObject { id, bytes: frame });
            }
        }
        Request::decode(&frame)
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
    read_frame_max(r, scl_core::max_object_size())
}

/// Room a frame has beyond the object it carries: the longest header is a
/// `PutObject` request (opcode + 32-byte id + 4-byte length = 37 bytes); a
/// response adds a status byte and a pack chunk a tag byte. Frames may be
/// `cap + FRAME_OVERHEAD` long so an object of exactly `cap` bytes still
/// fits; the object itself is checked against `cap` by [`check_object_len`].
pub const FRAME_OVERHEAD: usize = 64;

/// Reject an object body above the cap `max`. Frames carry [`FRAME_OVERHEAD`]
/// extra bytes, so a single-object payload gets this separate exact check.
pub(crate) fn check_object_len(len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(Error::Protocol(format!(
            "object of {len} bytes exceeds the {max}-byte object size limit ({})",
            scl_core::OBJECT_SIZE_HINT
        )));
    }
    Ok(())
}

/// [`read_frame_opt`] with an explicit object cap `max` (the live
/// [`scl_core::max_object_size`] in production); the frame limit is
/// `max + FRAME_OVERHEAD`.
fn read_frame_max(r: &mut impl Read, max: usize) -> Result<Option<Vec<u8>>> {
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
    if len > max + FRAME_OVERHEAD {
        return Err(Error::Protocol(format!(
            "frame length {len} exceeds the {max}-byte object size limit plus framing ({})",
            scl_core::OBJECT_SIZE_HINT
        )));
    }
    // The length is the peer's claim: grow with the bytes that actually
    // arrive instead of allocating `len` up front.
    let buf = scl_core::read_exact_vec(r, len).map_err(|e| match e.kind() {
        // A read timeout is the peer going quiet, not a malformed frame.
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Error::Io(e),
        _ => Error::Protocol(format!("read inside {len}-byte frame body failed: {e}")),
    })?;
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
                    return Err(Error::PackTooLarge(format!(
                        "server cap is {max_bytes} bytes; raise --max-pack-size on the \
                         server or split the push"
                    )));
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
pub fn parse_response(mut frame: Vec<u8>) -> Result<Vec<u8>> {
    let status = *frame
        .first()
        .ok_or_else(|| Error::Protocol("empty response frame".into()))?;
    match status {
        ST_OK => {
            // Strip the status byte in place: no second copy of a large body.
            frame.remove(0);
            Ok(frame)
        }
        ST_ERR => {
            let mut c = Cur::new(&frame[1..]);
            let code = c.u8()?;
            let msg = c.str()?;
            c.done()?;
            Err(wire_to_err(code, msg))
        }
        s => Err(Error::Protocol(format!("bad response status {s}"))),
    }
}

/// Map a repo error onto its wire code + message. Errors sync logic matches on
/// keep their identity; the rest carry only their message.
///
/// `Error::PackTooLarge(inner)` is special-cased: its `Display` impl already
/// prepends the "pack exceeds the server's --max-pack-size limit: " prefix
/// around `inner`, and [`wire_to_err`] reconstructs a fresh
/// `Error::PackTooLarge(msg)` from whatever we send here — sending
/// `e.to_string()` would carry that prefix as part of `msg`, so the
/// round-tripped error's `Display` would show the prefix twice. Sending only
/// `inner` keeps the prefix appearing exactly once, on display.
pub fn err_to_wire(e: &Error) -> (u8, String) {
    let code = match e {
        Error::NotARepo => EC_NOT_A_REPO,
        Error::NonFastForward => EC_NON_FAST_FORWARD,
        Error::Core(scl_core::Error::NotFound(_)) => EC_NOT_FOUND,
        Error::Protocol(_) => EC_PROTOCOL,
        Error::ReadOnly => EC_READONLY,
        Error::PackTooLarge(_) => EC_TOO_LARGE,
        Error::ConnectionBudgetExceeded(_) => EC_BUDGET,
        _ => EC_OTHER,
    };
    let msg = match e {
        Error::PackTooLarge(inner) | Error::ConnectionBudgetExceeded(inner) => inner.clone(),
        _ => e.to_string(),
    };
    (code, msg)
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
        EC_BUDGET => Error::ConnectionBudgetExceeded(msg),
        _ => Error::Remote(msg), // EC_NOT_FOUND + EC_OTHER: typed enough as text
    }
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

/// Decode an id-list body that may name at most `max` ids. For a `GetObjects`
/// reply `max` is the number of ids requested, so a hostile peer cannot make
/// the client decode a list sized by the frame limit instead of the request.
pub fn decode_ids_body_capped(b: &[u8], max: usize) -> Result<Vec<ObjectId>> {
    let mut c = Cur::new(b);
    let ids = c.ids_capped(max).map_err(|e| match e {
        Error::PackTooLarge(_) => {
            Error::Protocol(format!("reply lists more than the {max} id(s) requested"))
        }
        e => e,
    })?;
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

use crate::bucket_transport::BucketTransport;
use crate::transport::{scan_pack_tally, LocalTransport, PackTally, TempPackGuard, Transport};

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

/// Default `--max-conn-bytes` for a server whose `--max-pack-size` is
/// `max_pack_size` (#233): one maximal pack plus one maximal object
/// ([`scl_core::max_object_size`]), so a legitimate push that fills the pack
/// cap and adds a trailing object still fits on one connection, while the
/// total a peer can make the server write stays finite. An unlimited
/// (`0`) pack cap falls back to [`DEFAULT_MAX_PACK_SIZE`] for this sum.
pub fn default_max_conn_bytes(max_pack_size: u64) -> u64 {
    let pack = if max_pack_size == 0 {
        DEFAULT_MAX_PACK_SIZE
    } else {
        max_pack_size
    };
    pack.saturating_add(scl_core::max_object_size() as u64)
}

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
    /// Per-connection budget over every object-write verb (`PutObject`'s
    /// decoded length, structural objects included; per `PutPack` the larger of its
    /// spooled bytes and the decoded bytes held: structural records on a local
    /// store, every record on a bucket one), in bytes (#233). Exceeding it replies
    /// [`Error::ConnectionBudgetExceeded`] and closes the connection. `0`
    /// means unlimited (embedders and tests; `sc serve` refuses it). Reads
    /// are not budgeted.
    pub max_conn_bytes: u64,
}

impl Default for WirePolicy {
    fn default() -> Self {
        Self {
            read_only: false,
            max_pack_size: DEFAULT_MAX_PACK_SIZE,
            ro_drain_cap: RO_DRAIN_CAP,
            max_conn_bytes: default_max_conn_bytes(DEFAULT_MAX_PACK_SIZE),
        }
    }
}

/// Validate an operator-supplied `--max-conn-bytes`. Zero is refused (there
/// is no unlimited setting from `sc serve`; `0` in [`WirePolicy`] or
/// `ServeLimits` is for embedders and tests); a budget below the object cap could never admit one
/// object, and one below a nonzero `max_pack_size` would silently lower the
/// pack cap, so all three are refused at startup rather than clamped.
pub fn validate_max_conn_bytes(budget: u64, max_pack_size: u64, object_cap: usize) -> Result<()> {
    if budget == 0 {
        return Err(Error::InvalidArgument(
            "--max-conn-bytes must be greater than zero".into(),
        ));
    }
    if budget < object_cap as u64 {
        return Err(Error::InvalidArgument(format!(
            "--max-conn-bytes {budget} is below the max object size ({object_cap}); a budget that cannot fit one object is a misconfiguration"
        )));
    }
    if max_pack_size != 0 && budget < max_pack_size {
        return Err(Error::InvalidArgument(format!(
            "--max-conn-bytes {budget} is below --max-pack-size ({max_pack_size}); a budget below the pack cap is a misconfiguration (a pack is charged by its decoded size, which can still exceed the budget)"
        )));
    }
    Ok(())
}

/// Admit a `PutObject` body of `len` bytes under object cap `cap`: `Err` is a
/// budget refusal (close the connection), `Ok(Some(e))` an over-cap reply that
/// keeps the session open, `Ok(None)` admitted. The bytes are charged first,
/// so a frame that passes the frame limit but not the cap (it may exceed the
/// cap by `FRAME_OVERHEAD - 37`) still uses up the budget.
fn gate_put_object(budget: &mut ConnBudget, len: usize, cap: usize) -> Result<Option<Error>> {
    budget.charge(len as u64)?;
    Ok(check_object_len(len, cap).err())
}

/// Running count of bytes a connection has made the server write (#233).
struct ConnBudget {
    limit: u64,
    used: u64,
}

impl ConnBudget {
    fn refusal(&self) -> Error {
        Error::ConnectionBudgetExceeded(format!(
            "server cap is {} bytes of writes per connection; raise --max-conn-bytes on the server or split the push across connections",
            self.limit
        ))
    }

    /// Account `n` incoming bytes, refusing before they are written when the
    /// budget would be exceeded. Attempts count, accepted or not.
    fn charge(&mut self, n: u64) -> Result<()> {
        self.used = self.used.saturating_add(n);
        if self.limit != 0 && self.used > self.limit {
            return Err(self.refusal());
        }
        Ok(())
    }

    /// Spool cap for the next pack: `max_pack_size` tightened to what is left
    /// of the budget, and whether the budget is the binding one.
    fn pack_cap(&self, max_pack_size: u64) -> (u64, bool) {
        if self.limit == 0 {
            return (max_pack_size, false);
        }
        // `max(1)`: a cap of 0 would mean unlimited to the spool reader.
        let left = self.limit.saturating_sub(self.used).max(1);
        if max_pack_size == 0 || left < max_pack_size {
            (left, true)
        } else {
            (max_pack_size, false)
        }
    }
}

/// Validate an operator-supplied `--max-pack-size` value. `0` (unlimited) is
/// always fine; a nonzero cap below `object_cap` (the live
/// [`scl_core::max_object_size`]) can never fit even one object and is
/// rejected as a misconfiguration rather than silently failing every push at
/// runtime.
pub fn validate_max_pack_size(max: u64, object_cap: usize) -> Result<()> {
    if max != 0 && max < object_cap as u64 {
        return Err(Error::InvalidArgument(format!(
            "--max-pack-size {max} is below the max object size ({object_cap}); a cap that cannot fit one object is a misconfiguration"
        )));
    }
    Ok(())
}

/// Read and validate the session's opening `HELLO` frame — shared by
/// [`serve_with_policy`] and [`serve_bucket_with_policy`] regardless of which
/// backend ends up serving the session: version skew or a non-`HELLO` first
/// frame get a typed error reply here, before either backend is ever opened.
/// Returns `Ok(true)` when the caller should proceed to open its transport;
/// `Ok(false)` when the session is already fully handled (an error was
/// replied, or the peer hung up immediately) and the caller should return
/// `Ok(())` without touching a transport at all.
fn handshake_hello(r: &mut impl Read, w: &mut impl Write) -> Result<bool> {
    let first = match read_frame_opt(r)? {
        Some(f) => f,
        None => return Ok(false), // peer connected and immediately hung up
    };
    match Request::decode(&first) {
        Ok(Request::Hello { version }) if version == PROTOCOL_VERSION => Ok(true),
        Ok(Request::Hello { version }) => {
            write_err(
                w,
                EC_PROTOCOL,
                &format!(
                    "unsupported protocol version {version} (server speaks {PROTOCOL_VERSION})"
                ),
            )?;
            Ok(false)
        }
        Ok(_) | Err(_) => {
            write_err(w, EC_PROTOCOL, "expected HELLO as the first request")?;
            Ok(false)
        }
    }
}

/// RAII scratch dir for a bucket-backed serve session's pack spills (P36c).
/// A bucket remote has no `.sc/tmp/` of its own to spool into, so a bucket
/// session gets one disposable directory under the serve HOME's own
/// `.sc/tmp/` for its lifetime instead — matching CLAUDE.md's and
/// THREAT-MODEL.md's documented "pack-spool scratch lives in the serve
/// home" contract (and local-mode's own `.sc/tmp` convention) rather than
/// the process-wide `std::env::temp_dir()`, which is shared, unbounded, and
/// not scoped to this repo's access control at all. Removed (best-effort)
/// on drop, so the ephemeral-mode disk invariant (zero residue after the
/// session ends) holds for bucket-backed serve exactly as it does for every
/// other ephemeral session.
pub(crate) struct TempServeDir(std::path::PathBuf);

impl TempServeDir {
    /// Create the scratch dir under `<home>/.sc/tmp/serve-bucket-<pid>-<n>`.
    /// `home` is the serve session's HOME directory (the same `path` a local
    /// `serve_with_policy` session materializes into) — callers must have
    /// already confirmed it has a `.sc/` (the same gate `handle_http_connection`
    /// and `LocalTransport::open` apply) before calling this.
    fn create_in(home: &std::path::Path) -> Result<TempServeDir> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = home
            .join(".sc")
            .join("tmp")
            .join(format!("serve-bucket-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(TempServeDir(dir))
    }
}

impl Drop for TempServeDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The two transports [`serve_session`] can sit on (P36c). Every verb except
/// the pack pair dispatches identically through the `Transport` trait (via
/// [`ServeTransport::as_transport`]); `GetPack`/`PutPack` diverge because
/// `LocalTransport` has its own bounded tempfile fast paths
/// (`build_pack_tempfile`/`ingest_from`, sharing the repo's own `.sc/tmp/`)
/// while a bucket only exposes the trait's streaming `get_pack`/`put_pack`,
/// spooling through its own [`TempServeDir`] instead — so those two verbs are
/// handled per-variant in `serve_session`.
pub(crate) enum ServeTransport {
    Local(LocalTransport),
    Bucket {
        transport: BucketTransport,
        tmp: TempServeDir,
    },
}

impl ServeTransport {
    fn as_transport(&self) -> &dyn Transport {
        match self {
            ServeTransport::Local(t) => t,
            ServeTransport::Bucket { transport, .. } => transport,
        }
    }

    /// Scratch dir this session's pack spills go into: the repo's own
    /// `.sc/tmp/` for a local transport, this session's [`TempServeDir`] for
    /// a bucket one.
    fn tmp_dir(&self) -> std::path::PathBuf {
        match self {
            ServeTransport::Local(t) => t.layout().tmp_dir(),
            ServeTransport::Bucket { tmp, .. } => tmp.0.clone(),
        }
    }
}

/// Bucket twin of `LocalTransport::build_pack_tempfile`: builds a `GetPack`
/// response's temp pack file so the same "fully succeeded before any wire
/// byte" invariant (the comment on the `GetPack` arm in [`serve_session`])
/// holds regardless of backend — just built from the trait's streaming
/// `get_pack` (spooled into a fresh guard under the session's
/// [`TempServeDir`]) instead of a local store's own reachability walk.
fn bucket_get_pack_tempfile(
    bt: &BucketTransport,
    tmp_dir: &std::path::Path,
    wants: &[ObjectId],
    haves: &[ObjectId],
    filter: Option<&crate::promisor::PackFilter>,
) -> Result<TempPackGuard> {
    let guard = TempPackGuard::new_in(tmp_dir)?;
    let mut f = std::fs::File::create(guard.path())?;
    bt.get_pack(wants, haves, filter, &mut f)?;
    Ok(guard)
}

/// Bucket twin of `LocalTransport::ingest_from`: hand the already-spilled
/// pack file (produced by [`spill_pack_stream`]) to the trait's `put_pack`,
/// which re-verifies every record and uploads a fresh pack to the bucket —
/// mirroring the local path's own re-verify-then-ingest contract.
fn bucket_put_pack_from_file(
    bt: &BucketTransport,
    path: &std::path::Path,
) -> Result<Vec<ObjectId>> {
    let mut f = std::fs::File::open(path)?;
    bt.put_pack(&mut f)
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
    if !handshake_hello(r, w)? {
        return Ok(());
    }
    let transport = match LocalTransport::open(root) {
        Ok(t) => {
            write_ok(w, &u32_body(PROTOCOL_VERSION))?;
            ServeTransport::Local(t)
        }
        Err(e) => {
            let (code, msg) = err_to_wire(&e);
            write_err(w, code, &msg)?;
            return Ok(());
        }
    };
    serve_session(transport, r, w, policy)
}

/// Open a [`BucketTransport`] plus this session's [`TempServeDir`] as one
/// [`ServeTransport::Bucket`] — a single fallible step so
/// [`serve_bucket_with_policy`] only needs one match to decide whether to
/// reply OK or a typed error. `home` is the serve session's HOME directory
/// (see [`TempServeDir::create_in`]) — the spool dir is created under its
/// `.sc/tmp/`, not the process-wide temp dir.
fn open_bucket_serve_transport(store_url: &str, home: &std::path::Path) -> Result<ServeTransport> {
    let transport = BucketTransport::open(store_url)?;
    let tmp = TempServeDir::create_in(home)?;
    Ok(ServeTransport::Bucket { transport, tmp })
}

/// Serve a bucket WAL (`sc+wal://`/`sc+s3://`) over the same wire protocol
/// `serve_with_policy` speaks for a local repo (P36c): same handshake, same
/// `PROTOCOL_VERSION`, same read-only gate and pack-spool caps — every verb
/// except the pack pair goes through [`Transport`] identically either way.
/// All durable state lives in the bucket; this process holds only an RAII
/// scratch dir (`TempServeDir`) for pack spills, created under `home`'s own
/// `.sc/tmp/` (CLAUDE.md / THREAT-MODEL.md's "pack-spool scratch lives in the
/// serve home" contract) and removed when the session ends. `home` is the
/// same serve-HOME directory `serve_with_policy` materializes a local repo
/// into — callers MUST have already confirmed it has a `.sc/` before calling
/// this, or `TempServeDir::create_in` will silently `create_dir_all` one
/// into existence under an uninitialized directory. Both current callers do:
/// `handle_http_connection` gates on `.sc/` presence before any dispatch
/// (store mode included; the 404 follows the auth gate (#207), so a listener
/// that requires a token answers 401 first) and the CLI's `run_serve`
/// checks `path.join(".sc").is_dir()` itself before reaching this function
/// (P36c review — `--stdio` has no upstream gate the way `--http` does, so
/// it cannot lean on `LocalTransport::open`'s own check the way a
/// non-`--store` `--stdio` session implicitly does).
pub fn serve_bucket_with_policy(
    store_url: &str,
    home: &std::path::Path,
    r: &mut impl Read,
    w: &mut impl Write,
    policy: WirePolicy,
) -> Result<()> {
    if !handshake_hello(r, w)? {
        return Ok(());
    }
    let transport = match open_bucket_serve_transport(store_url, home) {
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
    serve_session(transport, r, w, policy)
}

/// Serve one wire-protocol peer over an already-opened [`ServeTransport`]
/// until `Bye`/EOF — the shared body of [`serve_with_policy`] and
/// [`serve_bucket_with_policy`] once each has finished its own handshake and
/// opened its own backend. See `serve_with_policy`'s doc comment for the
/// full verb-by-verb contract (read-only gate, pack spool caps); it applies
/// identically here no matter which transport variant is behind it.
fn serve_session(
    transport: ServeTransport,
    r: &mut impl Read,
    w: &mut impl Write,
    policy: WirePolicy,
) -> Result<()> {
    let mut budget = ConnBudget {
        limit: policy.max_conn_bytes,
        used: 0,
    };
    loop {
        let frame = match read_frame_opt(r)? {
            Some(f) => f,
            None => return Ok(()), // peer hung up between requests
        };
        let req = match Request::decode_owned(frame) {
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
                    match spill_pack_stream(r, &transport.tmp_dir(), policy.ro_drain_cap) {
                        Ok((guard, _)) => {
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
                blob_limit,
            } => {
                let filter_opt = crate::promisor::PackFilter::new(&filter, blob_limit);
                let result = match &transport {
                    ServeTransport::Local(t) => {
                        t.build_pack_tempfile(&wants, &haves, filter_opt.as_ref())
                    }
                    ServeTransport::Bucket { transport: bt, tmp } => {
                        bucket_get_pack_tempfile(bt, &tmp.0, &wants, &haves, filter_opt.as_ref())
                    }
                };
                match result {
                    Ok(guard) => {
                        // Building the temp pack file (bounded RAM: one
                        // object at a time) fully succeeded before any wire
                        // byte for this response was sent, so an OK/ERR
                        // split here is still clean — no partial stream can
                        // ever follow an ERR. True for both variants: Local's
                        // `build_pack_tempfile` and the bucket path's
                        // `bucket_get_pack_tempfile` each finish writing (and
                        // return Err on any failure) before we touch `w`.
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
            Request::GetObjects { ids } => {
                // Streams like GetPack, so it is handled inline. Bucket
                // remotes refuse: they refuse partial clone (ADR-0046), and
                // by-id reads exist only for partial clones.
                let result = match &transport {
                    ServeTransport::Local(t) => t.build_objects_tempfile(
                        &ids,
                        crate::transport::by_id_reply_cap(policy.max_pack_size),
                    ),
                    ServeTransport::Bucket { .. } => Err(Error::InvalidArgument(
                        "bucket remotes do not support by-id object fetch".into(),
                    )),
                };
                match result {
                    Ok((not_sent, guard)) => {
                        write_ok(w, &ids_body(&not_sent))?;
                        let mut f = std::fs::File::open(guard.path())?;
                        write_pack_stream(w, &mut f, pack_chunk_size())?;
                    }
                    Err(e) => {
                        let (code, msg) = err_to_wire(&e);
                        write_err(w, code, &msg)?;
                    }
                }
            }
            Request::PutPack => {
                let (cap, by_budget) = budget.pack_cap(policy.max_pack_size);
                match spill_pack_stream(r, &transport.tmp_dir(), cap) {
                    Ok((guard, spooled)) => {
                        // A pack costs max(spool bytes, decoded bytes the
                        // receiver holds), not their sum: the spool is the
                        // compressed form of the same records. The decoded
                        // tally (structural records on a local store, every
                        // record on a bucket one) is checked against the
                        // whole remaining budget before any store write.
                        let left = budget.limit.saturating_sub(budget.used);
                        if budget.limit != 0 && spooled > left {
                            let (code, msg) = err_to_wire(&budget.refusal());
                            let _ = write_err(w, code, &msg);
                            return Ok(());
                        }
                        let mut tally = PackTally {
                            limit: (budget.limit != 0).then_some(left),
                            count_blobs: matches!(transport, ServeTransport::Bucket { .. }),
                            seen: 0,
                        };
                        let ingest_result = match &transport {
                            ServeTransport::Local(t) => {
                                t.ingest_from_tallied(guard.path(), &mut tally)
                            }
                            ServeTransport::Bucket { transport: bt, .. } => {
                                scan_pack_tally(guard.path(), &mut tally)
                                    .and_then(|()| bucket_put_pack_from_file(bt, guard.path()))
                            }
                        };
                        // Charge before inspecting the result: an error after
                        // pass 2 began (e.g. an index write) can leave records
                        // stored, and the connection stays open.
                        budget.used = budget.used.saturating_add(spooled.max(tally.seen));
                        match ingest_result {
                            Ok(ids) => write_ok(w, &ids_body(&ids))?,
                            Err(Error::ConnectionBudgetExceeded(_)) => {
                                let (code, msg) = err_to_wire(&budget.refusal());
                                let _ = write_err(w, code, &msg);
                                return Ok(());
                            }
                            Err(e) => {
                                let (code, msg) = err_to_wire(&e);
                                write_err(w, code, &msg)?;
                            }
                        }
                        // `guard` drops here — temp pack file removed,
                        // whether ingestion succeeded or failed.
                    }
                    Err(e) => {
                        // Any spill failure (over the cap, a malformed or
                        // over-cap frame, I/O): we stopped reading mid-pack,
                        // so any bytes still on the wire are neither read
                        // nor a subsequent request. A best-effort reply is
                        // the most we can do; then close the connection
                        // rather than serve further requests off a
                        // desynced stream. When the remaining connection
                        // budget was the binding cap, say so (#233).
                        let over_cap = matches!(e, Error::PackTooLarge(_));
                        let e = match e {
                            Error::PackTooLarge(_) if by_budget => budget.refusal(),
                            e => e,
                        };
                        let (code, msg) = err_to_wire(&e);
                        let _ = write_err(w, code, &msg);
                        if over_cap {
                            // The stream was well-formed, just too big. Closing
                            // with unread bytes makes the OS reset the socket
                            // and can destroy the reply above, so drain a
                            // bounded amount first (best-effort). Reuses the
                            // read-only drain cap: same job, same bound.
                            let _ = read_pack_stream(r, &mut std::io::sink(), policy.ro_drain_cap);
                        }
                        return Ok(());
                    }
                }
            }
            Request::PutObject { id, bytes } => {
                // Distinct structural objects report `blob_size` 0, so the
                // budget counts the encoded length every time (#233).
                match gate_put_object(&mut budget, bytes.len(), scl_core::max_object_size()) {
                    Err(e) => {
                        // Refuse before the store write, then close: a peer
                        // that exhausted its budget gets no further requests.
                        let (code, msg) = err_to_wire(&e);
                        let _ = write_err(w, code, &msg);
                        return Ok(());
                    }
                    Ok(Some(e)) => {
                        let (code, msg) = err_to_wire(&e);
                        write_err(w, code, &msg)?;
                        continue;
                    }
                    Ok(None) => {}
                }
                match transport.as_transport().put_object(&id, &bytes) {
                    Ok(()) => write_ok(w, &[])?,
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
                    Request::ListRefs => transport
                        .as_transport()
                        .list_refs()
                        .map(|refs| refs_body(&refs)),
                    Request::HeadBranch => {
                        transport.as_transport().head_branch().map(|s| str_body(&s))
                    }
                    Request::HasObject(id) => {
                        transport.as_transport().has_object(&id).map(bool_body)
                    }
                    Request::GetObject(id) => transport.as_transport().get_object(&id),
                    Request::UpdateRef {
                        branch,
                        id,
                        expected_old,
                    } => transport
                        .as_transport()
                        .update_ref(&branch, &id, expected_old.as_ref())
                        .map(|()| Vec::new()),
                    Request::Bye
                    | Request::GetPack { .. }
                    | Request::PutPack
                    | Request::PutObject { .. }
                    | Request::GetObjects { .. } => {
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
/// P31) — see [`read_pack_stream`]. `tmp_dir` (P36c) is the caller's scratch
/// dir — a repo's `.sc/tmp/` for a local serve session, a [`TempServeDir`]
/// for a bucket one — so this function itself stays backend-agnostic.
fn spill_pack_stream(
    r: &mut impl Read,
    tmp_dir: &std::path::Path,
    max_bytes: u64,
) -> Result<(TempPackGuard, u64)> {
    let guard = TempPackGuard::new_in(tmp_dir)?;
    let mut f = std::fs::File::create(guard.path())?;
    let n = read_pack_stream(r, &mut f, max_bytes)?;
    Ok((guard, n))
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
    fn get_objects_decode_rejects_more_than_the_id_cap() {
        let ids: Vec<ObjectId> = (0..=MAX_GET_OBJECTS_IDS)
            .map(|i| ObjectId::from_bytes([(i % 251) as u8; 32]))
            .collect();
        let bytes = Request::GetObjects { ids }.encode();
        assert!(matches!(
            Request::decode(&bytes),
            Err(Error::PackTooLarge(_))
        ));
        // Exactly at the cap is fine.
        let ids: Vec<ObjectId> = (0..MAX_GET_OBJECTS_IDS)
            .map(|i| ObjectId::from_bytes([(i % 251) as u8; 32]))
            .collect();
        let bytes = Request::GetObjects { ids: ids.clone() }.encode();
        assert_eq!(
            Request::decode(&bytes).unwrap(),
            Request::GetObjects { ids }
        );
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
                blob_limit: None,
            },
            Request::GetPack {
                wants: vec![some_id(7)],
                haves: vec![],
                filter: vec!["src/".to_string(), "docs/".to_string()],
                blob_limit: None,
            },
            Request::GetPack {
                wants: vec![],
                haves: vec![],
                filter: vec![],
                blob_limit: None,
            },
            Request::GetPack {
                wants: vec![some_id(7)],
                haves: vec![],
                filter: vec!["src/".to_string()],
                blob_limit: Some(1 << 20),
            },
            Request::GetPack {
                wants: vec![some_id(7)],
                haves: vec![],
                filter: vec![],
                blob_limit: Some(0),
            },
            Request::GetPack {
                wants: vec![],
                haves: vec![],
                filter: vec![],
                blob_limit: Some(u64::MAX),
            },
            Request::PutPack,
            Request::GetObjects { ids: vec![] },
            Request::GetObjects {
                ids: vec![some_id(10), some_id(11)],
            },
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
        // A frame header alone (no body) claiming a length past the cap plus
        // framing must be rejected before the (fictitious) body is read or
        // allocated: feeding only the 4-byte header proves this, since
        // reading first would hit EOF and report a different error.
        let cap = scl_core::MIN_MAX_OBJECT_SIZE;
        let over = (cap + FRAME_OVERHEAD + 1) as u32;
        let mut r = std::io::Cursor::new(over.to_be_bytes().to_vec());
        let err = read_frame_max(&mut r, cap).unwrap_err();
        assert!(
            matches!(&err, crate::error::Error::Protocol(m) if m.contains("exceeds")),
            "got {err:?}"
        );
        // The production entry point is the same guard at the live cap.
        let over = (scl_core::max_object_size() + FRAME_OVERHEAD + 1) as u32;
        let mut r = std::io::Cursor::new(over.to_be_bytes().to_vec());
        assert!(matches!(
            read_frame_opt(&mut r),
            Err(crate::error::Error::Protocol(m)) if m.contains("exceeds")
        ));
    }

    #[test]
    fn frame_cap_lowered_rejects_and_raised_accepts_the_same_frame() {
        let low = scl_core::MIN_MAX_OBJECT_SIZE;
        let body = vec![7u8; low + FRAME_OVERHEAD + 1];
        let mut framed = Vec::new();
        write_frame(&mut framed, &body).unwrap();
        assert!(read_frame_max(&mut &framed[..], low).is_err());
        assert_eq!(
            read_frame_max(&mut &framed[..], low + 1).unwrap().unwrap(),
            body
        );
        assert_eq!(
            read_frame_max(&mut &framed[..], low * 4).unwrap().unwrap(),
            body
        );
    }

    /// An object of exactly the cap travels in `PutObject` (37 header bytes)
    /// and `GetObject` (1 status byte) frames; one byte more is refused by
    /// the exact object check even though the frame itself still fits.
    #[test]
    fn object_boundary_exactly_cap_accepted_cap_plus_one_rejected() {
        let cap = scl_core::MIN_MAX_OBJECT_SIZE;
        let id = some_id(7);
        for (len, ok) in [(cap, true), (cap + 1, false)] {
            let bytes = vec![5u8; len];
            // PutObject request.
            let mut framed = Vec::new();
            write_frame(
                &mut framed,
                &Request::PutObject {
                    id,
                    bytes: bytes.clone(),
                }
                .encode(),
            )
            .unwrap();
            let frame = read_frame_max(&mut &framed[..], cap).unwrap().unwrap();
            let Request::PutObject { bytes: got, .. } = Request::decode_owned(frame).unwrap()
            else {
                panic!("not a PutObject");
            };
            assert_eq!(got, bytes);
            assert_eq!(check_object_len(got.len(), cap).is_ok(), ok, "put {len}");
            // GetObject response.
            let mut framed = Vec::new();
            write_ok(&mut framed, &bytes).unwrap();
            let frame = read_frame_max(&mut &framed[..], cap).unwrap().unwrap();
            let body = parse_response(frame).unwrap();
            assert_eq!(body, bytes);
            assert_eq!(check_object_len(body.len(), cap).is_ok(), ok, "get {len}");
        }
    }

    #[test]
    fn decode_owned_matches_decode_and_handles_malformed_put_object() {
        let id = some_id(3);
        let enc = Request::PutObject {
            id,
            bytes: b"hello".to_vec(),
        }
        .encode();
        assert_eq!(
            Request::decode_owned(enc.clone()).unwrap(),
            Request::decode(&enc).unwrap()
        );
        // Declared length disagrees with the frame: same error as decode.
        let mut bad = enc.clone();
        bad.push(0);
        assert!(Request::decode_owned(bad).is_err());
        let mut short = enc;
        short.truncate(10);
        assert!(Request::decode_owned(short).is_err());
    }

    #[test]
    fn frame_claiming_the_ceiling_without_a_body_is_a_short_read_error() {
        // At the ceiling, a 4-byte header can claim 1 GiB and passes the
        // length guard; with no body behind it the read fails as a short
        // frame. (That no cap-sized buffer is allocated is pinned by
        // `read_limited_never_over_allocates_by_more_than_one_step`.)
        let cap = scl_core::MAX_MAX_OBJECT_SIZE;
        let mut r = std::io::Cursor::new((cap as u32).to_be_bytes().to_vec());
        let err = read_frame_max(&mut r, cap).unwrap_err();
        assert!(
            matches!(&err, crate::error::Error::Protocol(m) if m.contains("frame body")),
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
        let back = wire_to_err(code, msg);
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
        assert_eq!(decode_ids_body_capped(&ids_body(&ids), 2).unwrap(), ids);
        assert!(matches!(
            decode_ids_body_capped(&ids_body(&ids), 1),
            Err(Error::Protocol(_))
        ));
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

    /// ADR-0055: a v5 client (no `blob_limit` field) is refused at the
    /// handshake with a message naming both versions, so it never sends a
    /// `GetPack` the v6 decoder would misparse.
    #[test]
    fn serve_rejects_a_v5_client_naming_both_versions() {
        let root = tmp_repo("v5client");
        let r = run_session(&root, &[Request::Hello { version: 5 }]);
        match &r[0] {
            Err(Error::Protocol(m)) => assert_eq!(
                m, "unsupported protocol version 5 (server speaks 6)",
                "got {m}"
            ),
            other => panic!("expected a protocol error, got {other:?}"),
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// ADR-0055, the other direction: a v6 client against a v5 server sees the
    /// v5 server's own refusal (its `handshake_hello` text with its version),
    /// and no `GetPack` is ever sent.
    #[test]
    fn a_v6_client_reports_a_v5_servers_refusal() {
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let server = std::thread::spawn(move || {
            let f = read_frame(&mut server_read).unwrap();
            assert!(matches!(
                Request::decode(&f).unwrap(),
                Request::Hello { version: 6 }
            ));
            write_err(
                &mut server_write,
                EC_PROTOCOL,
                "unsupported protocol version 6 (server speaks 5)",
            )
            .unwrap();
        });
        let Err(err) = crate::stdio_transport::WireClient::handshake(client_read, client_write)
        else {
            panic!("the handshake must fail");
        };
        assert_eq!(
            err.to_string(),
            "wire protocol error: unsupported protocol version 6 (server speaks 5)"
        );
        server.join().unwrap();
    }

    /// The trailing `blob_limit` tag is strict: an unknown tag or a truncated
    /// limit is a protocol error, not a silently unfiltered pack.
    #[test]
    fn get_pack_decode_rejects_a_bad_blob_limit_tag() {
        let mut ok = Request::GetPack {
            wants: vec![],
            haves: vec![],
            filter: vec![],
            blob_limit: Some(7),
        }
        .encode();
        assert!(Request::decode(&ok).is_ok());
        let tag_at = ok.len() - 9;
        ok[tag_at] = 9;
        assert!(matches!(Request::decode(&ok), Err(Error::Protocol(_))));
        let mut truncated = Request::GetPack {
            wants: vec![],
            haves: vec![],
            filter: vec![],
            blob_limit: Some(7),
        }
        .encode();
        truncated.pop();
        assert!(matches!(
            Request::decode(&truncated),
            Err(Error::Protocol(_))
        ));
        // A v5 frame (no trailing field) no longer decodes.
        let mut v5 = Request::GetPack {
            wants: vec![],
            haves: vec![],
            filter: vec![],
            blob_limit: None,
        }
        .encode();
        v5.pop();
        assert!(matches!(Request::decode(&v5), Err(Error::Protocol(_))));
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
            Error::PackTooLarge(m) => {
                assert!(m.contains("17179869184"));
                // The Display prefix ("pack exceeds the server's
                // --max-pack-size limit: ") must appear exactly once, not
                // doubled by a round trip through the wire codes.
                let display = Error::PackTooLarge(m).to_string();
                assert_eq!(
                    display.matches("pack exceeds").count(),
                    1,
                    "expected exactly one occurrence of the Display prefix, got: {display}"
                );
            }
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
            max_conn_bytes: 0,
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
    fn chunk_from_defaults_and_clamps_to_the_smallest_valid_receiver_cap() {
        let min = scl_core::MIN_MAX_OBJECT_SIZE;
        assert_eq!(chunk_from(None), CHUNK_SIZE);
        assert_eq!(chunk_from(Some("")), CHUNK_SIZE);
        assert_eq!(chunk_from(Some("0")), CHUNK_SIZE);
        assert_eq!(chunk_from(Some("junk")), CHUNK_SIZE);
        assert_eq!(chunk_from(Some("4096")), 4096);
        // Independent of this process's own cap: a sender raised to 1 GiB
        // must still produce frames the smallest valid receiver accepts.
        for v in [min, min * 8, scl_core::MAX_MAX_OBJECT_SIZE, usize::MAX] {
            assert_eq!(chunk_from(Some(&v.to_string())), min - 1, "{v}");
        }
        // The resulting frame (tag byte + data) is exactly the minimum cap and
        // is accepted by a receiver at that cap, even with no overhead slack.
        let mut frame = vec![ST_PACK_CHUNK];
        frame.extend(vec![0u8; min - 1]);
        let mut framed = Vec::new();
        write_frame(&mut framed, &frame).unwrap();
        assert!(read_frame_max(&mut &framed[..], min).unwrap().is_some());
        assert!(CHUNK_SIZE < min, "the default chunk fits every receiver");
    }

    #[test]
    fn validate_max_pack_size_floor() {
        let max = scl_core::DEFAULT_MAX_OBJECT_SIZE;
        assert!(validate_max_pack_size(0, max).is_ok());
        assert!(validate_max_pack_size(max as u64, max).is_ok());
        assert!(validate_max_pack_size(1024, max).is_err());
        // The floor tracks the object cap: lowered admits what a default
        // cap refuses, raised refuses what a default cap admits.
        let low = scl_core::MIN_MAX_OBJECT_SIZE;
        assert!(validate_max_pack_size(low as u64, low).is_ok());
        assert!(validate_max_pack_size(max as u64, scl_core::MAX_MAX_OBJECT_SIZE).is_err());
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
            max_conn_bytes: 0,
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

    /// A malformed frame inside a pack stream desyncs the connection: the
    /// server replies once and closes instead of answering what follows.
    #[test]
    fn put_pack_protocol_error_closes_the_connection() {
        let root = tmp_repo("putpack-proto");
        let mut input = Vec::new();
        for req in [
            Request::Hello {
                version: PROTOCOL_VERSION,
            },
            Request::PutPack,
        ] {
            write_frame(&mut input, &req.encode()).unwrap();
        }
        write_frame(&mut input, &[0x7f]).unwrap(); // not a pack chunk or end
        write_frame(&mut input, &Request::HeadBranch.encode()).unwrap(); // must never be answered

        let mut output = Vec::new();
        serve(&root, &mut std::io::Cursor::new(input), &mut output).unwrap();

        let mut frames = Vec::new();
        let mut r = std::io::Cursor::new(output);
        while let Some(f) = read_frame_opt(&mut r).unwrap() {
            frames.push(parse_response(f));
        }
        assert_eq!(frames.len(), 2, "hello ok, one error, then closed");
        assert!(matches!(
            frames[1].as_ref().unwrap_err(),
            Error::Protocol(_)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `GetObjects` is a read verb: a read-only session serves it, and the
    /// `max_pack_size` spool cap applies to its reply.
    #[test]
    fn readonly_session_serves_get_objects_and_caps_the_reply() {
        let root = tmp_repo("ro-getobjs");
        let blob = scl_core::Object::blob(vec![5u8; 4096]);
        crate::transport::LocalTransport::open(&root)
            .unwrap()
            .put_object(&blob.id(), &blob.encode())
            .unwrap();

        let run = |max_pack_size: u64| {
            let mut input = Vec::new();
            write_frame(
                &mut input,
                &Request::Hello {
                    version: PROTOCOL_VERSION,
                }
                .encode(),
            )
            .unwrap();
            write_frame(
                &mut input,
                &Request::GetObjects {
                    ids: vec![blob.id()],
                }
                .encode(),
            )
            .unwrap();
            // A follow-up request proves the session survives a capped reply.
            write_frame(&mut input, &Request::HeadBranch.encode()).unwrap();
            let mut output = Vec::new();
            let policy = WirePolicy {
                read_only: true,
                max_pack_size,
                ro_drain_cap: 4096,
                max_conn_bytes: 0,
            };
            serve_with_policy(&root, &mut std::io::Cursor::new(input), &mut output, policy)
                .unwrap();
            let mut r = std::io::Cursor::new(output);
            let _hello = parse_response(read_frame_opt(&mut r).unwrap().unwrap()).unwrap();
            let reply = parse_response(read_frame_opt(&mut r).unwrap().unwrap());
            (reply, r)
        };

        let (reply, mut rest) = run(0);
        assert!(decode_ids_body(&reply.unwrap()).unwrap().is_empty());
        let mut pack = Vec::new();
        read_pack_stream(&mut rest, &mut pack, 0).unwrap();
        assert_eq!(scl_core::pack::parse_pack(&pack).unwrap().len(), 1);
        let head = parse_response(read_frame_opt(&mut rest).unwrap().unwrap()).unwrap();
        assert_eq!(decode_str_body(&head).unwrap(), "main");

        // A cap below the object's size fails the request, not the session.
        let (reply, mut rest) = run(100);
        assert!(matches!(reply.unwrap_err(), Error::PackTooLarge(_)));
        let head = parse_response(read_frame_opt(&mut rest).unwrap().unwrap()).unwrap();
        assert_eq!(decode_str_body(&head).unwrap(), "main");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A distinct tree whose encoding is ~`len` bytes (one long entry name):
    /// structural, so its `blob_size` is 0 and only its encoded length counts.
    fn big_tree(seed: u8, len: usize) -> (ObjectId, Vec<u8>) {
        use scl_core::object::{EntryKind, FileMode, Tree, TreeEntry};
        let name = format!("{seed:03}{}", "n".repeat(len));
        let obj = scl_core::Object::Tree(Tree::new(vec![TreeEntry {
            name,
            kind: EntryKind::Blob,
            id: some_id(seed),
            mode: FileMode::FILE,
            perms: 0,
        }]));
        assert_eq!(obj.blob_size(), 0);
        (obj.id(), obj.encode())
    }

    /// Run `reqs` (and any raw `PutPack` streams, keyed by request position)
    /// through `serve_with_policy` after a HELLO; returns the reply frames
    /// after the hello reply.
    fn run_budget_session(
        root: &std::path::Path,
        policy: WirePolicy,
        reqs: &[(Request, Option<Vec<u8>>)],
    ) -> Vec<Result<Vec<u8>>> {
        let mut input = Vec::new();
        let hello = Request::Hello {
            version: PROTOCOL_VERSION,
        };
        write_frame(&mut input, &hello.encode()).unwrap();
        for (req, pack) in reqs {
            write_frame(&mut input, &req.encode()).unwrap();
            if let Some(pack) = pack {
                write_pack_stream(&mut input, &mut std::io::Cursor::new(pack), 1024).unwrap();
            }
        }
        let mut output = Vec::new();
        serve_with_policy(root, &mut std::io::Cursor::new(input), &mut output, policy).unwrap();
        let mut r = std::io::Cursor::new(output);
        let mut frames = Vec::new();
        while let Some(f) = read_frame_opt(&mut r).unwrap() {
            frames.push(parse_response(f));
        }
        assert!(frames.remove(0).is_ok(), "hello");
        frames
    }

    fn put_tree(seed: u8, len: usize) -> (Request, Option<Vec<u8>>) {
        let (id, bytes) = big_tree(seed, len);
        (Request::PutObject { id, bytes }, None)
    }

    fn put_pack_of(seed: u8, len: usize) -> (Request, Option<Vec<u8>>) {
        let (id, bytes) = big_tree(seed, len);
        let (pack, _idx) = scl_core::pack::build_pack(&[(id, bytes)]).unwrap();
        (Request::PutPack, Some(pack))
    }

    fn no_spool_residue(root: &std::path::Path) {
        let tmp = root.join(".sc").join("tmp");
        assert!(!tmp.exists() || std::fs::read_dir(&tmp).unwrap().next().is_none());
    }

    /// #233: repeated near-cap `PutObject` of distinct structural objects is
    /// refused once the connection budget is spent, before the store write;
    /// the connection then closes; a fresh connection starts at zero.
    #[test]
    fn put_object_budget_refuses_structural_floods_and_closes() {
        let root = tmp_repo("budget-obj");
        let policy = WirePolicy {
            max_conn_bytes: 2_500_000,
            ..Default::default()
        };
        let reqs = [
            put_tree(1, 1_000_000),
            put_tree(2, 1_000_000),
            put_tree(3, 1_000_000),
            (Request::HeadBranch, None), // must never be answered
        ];
        let frames = run_budget_session(&root, policy, &reqs);
        assert_eq!(
            frames.len(),
            3,
            "two ok, one refusal, then closed: {frames:?}"
        );
        assert!(frames[0].is_ok() && frames[1].is_ok());
        assert!(matches!(
            frames[2].as_ref().unwrap_err(),
            Error::ConnectionBudgetExceeded(m) if m.contains("--max-conn-bytes")
        ));
        let t = crate::transport::LocalTransport::open(&root).unwrap();
        assert!(t.has_object(&big_tree(2, 1_000_000).0).unwrap());
        assert!(
            !t.has_object(&big_tree(3, 1_000_000).0).unwrap(),
            "the refused object never reached the store"
        );

        // The budget is per connection: a new session accepts the next object.
        let frames = run_budget_session(&root, policy, &[put_tree(4, 1_000_000)]);
        assert!(frames[0].is_ok(), "{frames:?}");
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// A legitimate single push under the default budget (one pack plus an
    /// object) is untouched, and a policy of `0` (embedders only) is unlimited.
    #[test]
    fn legit_push_under_default_budget_and_zero_opt_out() {
        let root = tmp_repo("budget-ok");
        let frames = run_budget_session(
            &root,
            WirePolicy::default(),
            &[put_pack_of(10, 1_500_000), put_tree(11, 1_500_000)],
        );
        assert!(frames.iter().all(|f| f.is_ok()), "{frames:?}");

        let policy = WirePolicy {
            max_conn_bytes: 0,
            ..Default::default()
        };
        let reqs: Vec<_> = (20..24).map(|i| put_tree(i, 500_000)).collect();
        let frames = run_budget_session(&root, policy, &reqs);
        assert_eq!(frames.len(), 4);
        assert!(frames.iter().all(|f| f.is_ok()), "{frames:?}");
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// Objects and packs draw on one budget. A pack of compressible structural
    /// records is charged by its encoded size (the spool is tiny), so the
    /// third request is refused by the structural tally, before ingest: the
    /// connection closes, nothing from the refused pack lands, no spool
    /// residue is left.
    #[test]
    fn put_pack_structural_bytes_share_the_budget() {
        let root = tmp_repo("budget-pack");
        let policy = WirePolicy {
            max_pack_size: 0,
            max_conn_bytes: 1_500_000,
            ..Default::default()
        };
        // 500k (pack) + 500k (object) leaves 500k; the 800k pack does not fit.
        let frames = run_budget_session(
            &root,
            policy,
            &[
                put_pack_of(30, 500_000),
                put_tree(31, 500_000),
                put_pack_of(32, 800_000),
                (Request::HeadBranch, None), // must never be answered
            ],
        );
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert!(frames[0].is_ok() && frames[1].is_ok());
        assert!(matches!(
            frames[2].as_ref().unwrap_err(),
            Error::ConnectionBudgetExceeded(_)
        ));
        let t = crate::transport::LocalTransport::open(&root).unwrap();
        assert!(!t.has_object(&big_tree(32, 800_000).0).unwrap());
        no_spool_residue(&root);

        // Same for a pack after a large object: 3M + 2M > 4M.
        let policy = WirePolicy {
            max_pack_size: 4_000_000,
            max_conn_bytes: 4_000_000,
            ..Default::default()
        };
        let frames = run_budget_session(
            &root,
            policy,
            &[put_tree(33, 3_000_000), put_pack_of(34, 2_000_000)],
        );
        assert!(frames[0].is_ok());
        assert!(matches!(
            frames[1].as_ref().unwrap_err(),
            Error::ConnectionBudgetExceeded(_)
        ));
        no_spool_residue(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// Incompressible noise as one blob pack: the spool is the full size and
    /// the structural tally sees nothing, so only the spool cutoff can trip.
    fn put_blob_pack(seed: u8, len: usize) -> (Request, Option<Vec<u8>>) {
        let mut x = 0x9E37_79B9_7F4A_7C15u64 ^ u64::from(seed);
        let noise: Vec<u8> = (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let obj = scl_core::Object::blob(noise);
        let (pack, _) = scl_core::pack::build_pack(&[(obj.id(), obj.encode())]).unwrap();
        (Request::PutPack, Some(pack))
    }

    /// The spool cutoff: a pack whose bytes outrun what is left of the budget
    /// is stopped mid-stream and reported as a budget refusal (not a
    /// pack-size one), leaves no spool residue and closes the connection. With
    /// no remaining budget conflict a same-size pack passes.
    #[test]
    fn pack_spool_cutoff_is_a_budget_refusal() {
        let root = tmp_repo("budget-spool");
        let policy = WirePolicy {
            max_pack_size: 0,
            max_conn_bytes: 1_000_000,
            ..Default::default()
        };
        let frames = run_budget_session(
            &root,
            policy,
            &[
                put_tree(35, 400_000),
                put_blob_pack(36, 700_000), // 400k used, ~700k spool > 600k left
                (Request::HeadBranch, None), // must never be answered
            ],
        );
        assert_eq!(frames.len(), 2, "{frames:?}");
        assert!(frames[0].is_ok());
        assert!(
            matches!(
                frames[1].as_ref().unwrap_err(),
                Error::ConnectionBudgetExceeded(_)
            ),
            "a budget cutoff, not PackTooLarge: {frames:?}"
        );
        no_spool_residue(&root);

        // The same blob pack alone fits.
        let frames = run_budget_session(&root, policy, &[put_blob_pack(36, 700_000)]);
        assert!(frames[0].is_ok(), "{frames:?}");
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// An over-cap `PutObject` body (the frame limit leaves it room) is
    /// answered with a protocol error and the session stays open, but its bytes
    /// are charged, so repeating it cannot run for free.
    #[test]
    fn oversized_put_object_attempts_are_charged() {
        let mut budget = ConnBudget {
            limit: 100,
            used: 0,
        };
        for _ in 0..9 {
            let e = gate_put_object(&mut budget, 11, 10).unwrap();
            assert!(matches!(e, Some(Error::Protocol(_))));
        }
        assert_eq!(budget.used, 99);
        assert!(matches!(
            gate_put_object(&mut budget, 11, 10),
            Err(Error::ConnectionBudgetExceeded(_))
        ));
        assert!(gate_put_object(
            &mut ConnBudget {
                limit: 100,
                used: 0
            },
            10,
            10
        )
        .unwrap()
        .is_none());
    }

    /// The spool half of the max charge: an incompressible blob pack has no
    /// structural bytes, so only its spooled size can use up the budget for
    /// the request that follows (charging the tally alone would pass this).
    #[test]
    fn spool_bytes_of_a_pack_count_toward_later_requests() {
        let root = tmp_repo("budget-spool-count");
        let policy = WirePolicy {
            max_pack_size: 0,
            max_conn_bytes: 1 << 20,
            ..Default::default()
        };
        let frames = run_budget_session(
            &root,
            policy,
            &[put_blob_pack(37, 600_000), put_tree(38, 500_000)],
        );
        assert!(frames[0].is_ok(), "{frames:?}");
        assert!(
            matches!(
                frames[1].as_ref().unwrap_err(),
                Error::ConnectionBudgetExceeded(_)
            ),
            "{frames:?}"
        );
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// Trees of random ids and names: zstd barely shrinks them, so the pack's
    /// spool size is close to its structural bytes.
    fn noisy_tree_pack(seed: u64, entries: usize) -> (Vec<u8>, u64, ObjectId) {
        use scl_core::object::{EntryKind, FileMode, Tree, TreeEntry};
        let mut x = 0x9E37_79B9_7F4A_7C15u64 ^ seed;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let list = (0..entries)
            .map(|_| {
                let mut id = [0u8; 32];
                id.chunks_mut(8)
                    .for_each(|c| c.copy_from_slice(&next().to_le_bytes()));
                TreeEntry {
                    name: format!("{:016x}", next()),
                    kind: EntryKind::Blob,
                    id: ObjectId::from_bytes(id),
                    mode: FileMode::FILE,
                    perms: 0,
                }
            })
            .collect();
        let obj = scl_core::Object::Tree(Tree::new(list));
        let encoded = obj.encode();
        let structural = encoded.len() as u64;
        let (pack, _) = scl_core::pack::build_pack(&[(obj.id(), encoded)]).unwrap();
        (pack, structural, obj.id())
    }

    /// B1: a pack is charged max(spool, structural), not their sum. A pack of
    /// near-incompressible structural records fits a budget equal to its
    /// largest cost and to `--max-pack-size`; one byte less is refused. (The
    /// sum would refuse the exact case: the startup bounds promise that one
    /// maximal pack fits.)
    #[test]
    fn pack_cost_is_the_larger_of_spool_and_structural_bytes() {
        let root = tmp_repo("budget-max");
        let (pack, structural, id) = noisy_tree_pack(7, 20_000);
        let cost = structural.max(pack.len() as u64);
        assert!(
            pack.len() as u64 * 10 > structural * 6,
            "premise: records are not very compressible ({} vs {structural})",
            pack.len()
        );
        let put = |cap: u64| {
            run_budget_session(
                &root,
                WirePolicy {
                    max_pack_size: cap,
                    max_conn_bytes: cap,
                    ..Default::default()
                },
                &[(Request::PutPack, Some(pack.clone()))],
            )
        };
        let frames = put(cost);
        assert!(frames[0].is_ok(), "exact cost fits: {frames:?}");
        let t = crate::transport::LocalTransport::open(&root).unwrap();
        assert!(t.has_object(&id).unwrap());

        let (pack2, _, id2) = noisy_tree_pack(8, 20_000);
        let frames = run_budget_session(
            &root,
            WirePolicy {
                max_pack_size: cost - 1,
                max_conn_bytes: cost - 1,
                ..Default::default()
            },
            &[(Request::PutPack, Some(pack2.clone()))],
        );
        assert!(
            matches!(
                frames[0].as_ref().unwrap_err(),
                Error::ConnectionBudgetExceeded(_)
            ),
            "{frames:?}"
        );
        assert!(!t.has_object(&id2).unwrap(), "refused before any write");
        no_spool_residue(&root);

        // The default policy admits it too.
        let frames = run_budget_session(
            &root,
            WirePolicy::default(),
            &[(Request::PutPack, Some(pack2))],
        );
        assert!(frames[0].is_ok(), "{frames:?}");
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// The budget is exact: a total equal to it is accepted, one byte more is
    /// refused, and the refused object never lands.
    #[test]
    fn put_object_budget_boundary_is_exact() {
        let root = tmp_repo("budget-edge");
        let (_, a) = big_tree(40, 1000);
        let (_, b) = big_tree(41, 1000);
        let total = (a.len() + b.len()) as u64;
        let at = WirePolicy {
            max_conn_bytes: total,
            ..Default::default()
        };
        let frames = run_budget_session(&root, at, &[put_tree(40, 1000), put_tree(41, 1000)]);
        assert!(frames.iter().all(|f| f.is_ok()), "exact: {frames:?}");

        let under = WirePolicy {
            max_conn_bytes: total - 1,
            ..Default::default()
        };
        let frames = run_budget_session(&root, under, &[put_tree(42, 1000), put_tree(43, 1000)]);
        assert!(frames[0].is_ok());
        assert!(matches!(
            frames[1].as_ref().unwrap_err(),
            Error::ConnectionBudgetExceeded(_)
        ));
        let t = crate::transport::LocalTransport::open(&root).unwrap();
        assert!(!t.has_object(&big_tree(43, 1000).0).unwrap());
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// Structural records inside a pack are retained resident, so their
    /// encoded size is budgeted even when zstd makes the spooled pack tiny;
    /// the over-budget pack is refused before any record lands.
    #[test]
    fn highly_compressible_structural_pack_is_budgeted_by_encoded_size() {
        let root = tmp_repo("budget-zip");
        let (id, _) = big_tree(50, 3_000_000);
        let (pack, _) = scl_core::pack::build_pack(&[(id, big_tree(50, 3_000_000).1)]).unwrap();
        assert!(pack.len() < 100_000, "premise: the pack compresses well");
        let policy = WirePolicy {
            max_conn_bytes: 2_000_000,
            ..Default::default()
        };
        let frames = run_budget_session(&root, policy, &[(Request::PutPack, Some(pack))]);
        assert!(matches!(
            frames[0].as_ref().unwrap_err(),
            Error::ConnectionBudgetExceeded(_)
        ));
        let t = crate::transport::LocalTransport::open(&root).unwrap();
        assert!(!t.has_object(&id).unwrap());
        no_spool_residue(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    /// A read-only listener answers `ReadOnly` and never touches the budget:
    /// reads and rejected writes are unaffected even by a tiny one.
    #[test]
    fn read_only_listener_ignores_the_budget() {
        let root = tmp_repo("budget-ro");
        let policy = WirePolicy {
            read_only: true,
            max_conn_bytes: 1,
            ..Default::default()
        };
        let frames = run_budget_session(
            &root,
            policy,
            &[
                put_tree(60, 1000),
                put_tree(61, 1000),
                (Request::HeadBranch, None),
            ],
        );
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert!(matches!(frames[0].as_ref().unwrap_err(), Error::ReadOnly));
        assert!(matches!(frames[1].as_ref().unwrap_err(), Error::ReadOnly));
        assert!(!matches!(
            frames[2].as_ref().err(),
            Some(Error::ConnectionBudgetExceeded(_))
        ));
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn connection_budget_error_round_trips_and_flag_bounds() {
        let e = Error::ConnectionBudgetExceeded("cap is 7".into());
        let (code, msg) = err_to_wire(&e);
        assert_eq!(code, EC_BUDGET);
        assert!(matches!(
            wire_to_err(code, msg),
            Error::ConnectionBudgetExceeded(m) if m == "cap is 7"
        ));

        let obj = 4 << 20;
        assert!(validate_max_conn_bytes(0, 100, obj).is_err());
        assert!(validate_max_conn_bytes(obj as u64 - 1, 0, obj).is_err());
        assert!(validate_max_conn_bytes(obj as u64, 0, obj).is_ok());
        assert!(validate_max_conn_bytes(10 << 20, 20 << 20, obj).is_err());
        assert!(validate_max_conn_bytes(20 << 20, 20 << 20, obj).is_ok());
        assert_eq!(
            default_max_conn_bytes(0),
            default_max_conn_bytes(DEFAULT_MAX_PACK_SIZE)
        );
        assert!(default_max_conn_bytes(1 << 30) > 1 << 30);
    }

    /// Mint a one-commit object set the same way
    /// `bucket_transport::tests::tiny_history` does (blob -> tree -> snapshot
    /// via a real scratch repo), returning `(tip, objects)`. `tag`
    /// disambiguates the scratch repo path between call sites sharing this
    /// process id.
    fn tiny_history_for_bucket(tag: &str, content: &[u8]) -> (ObjectId, Vec<(ObjectId, Vec<u8>)>) {
        let root =
            std::env::temp_dir().join(format!("scl-wire-bkhist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = crate::repo::Repo::init(&root).unwrap();
        std::fs::write(root.join("f.txt"), content).unwrap();
        let tip = repo.commit("t", "c").unwrap();
        let store_arc = repo.vfs().store();
        let mut store = store_arc.lock().unwrap();
        let ids = crate::reachable::reachable_objects(&mut *store, &[tip]).unwrap();
        let objects: Vec<(ObjectId, Vec<u8>)> = ids
            .iter()
            .map(|id| (*id, store.get(id).unwrap().encode()))
            .collect();
        drop(store);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!root.exists());
        (tip, objects)
    }

    /// `serve_bucket_with_policy` speaks the exact same wire protocol as
    /// `serve_with_policy` against a bucket WAL instead of a local `.sc/`:
    /// handshake, `ListRefs`, a streamed `GetPack`, and a `PutPack` +
    /// `UpdateRef` that lands a second commit — verified by a fresh
    /// `BucketTransport::open` on the bucket after the session ends. Also
    /// pins the fix for a review finding: the session's pack-spool scratch
    /// dir must live under the serve HOME's own `.sc/tmp/`, not the
    /// process-wide `std::env::temp_dir()` — asserted below by checking that
    /// `home/.sc/tmp/` is the only place a `serve-bucket-*` dir ever
    /// appears, and that it's gone again once the session ends.
    #[test]
    fn bucket_stdio_serve_round_trips_refs_and_packs() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-wire-bucket-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        let url = format!("sc+wal://{}", broot.display());
        let home = tmp_repo("bucket-serve-home"); // an sc repo used only as the serve HOME

        // Seed a one-commit bucket WAL directly via BucketTransport — same
        // shape as bucket_transport::tests::push_via_trait_round_trips_into_a_fresh_bucket.
        let (tip, objects) = tiny_history_for_bucket("seed", b"hello wal");
        {
            let t = crate::bucket_transport::BucketTransport::open(&url).unwrap();
            let (pack, _idx) = scl_core::pack::build_pack(&objects).unwrap();
            t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
            t.update_ref("main", &tip, None).unwrap();
        }

        // Serve it over an in-memory duplex, exactly like the local serve
        // tests' `spawn_wire_pair_with_policy` pipe setup.
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let url_for_server = url.clone();
        let home_for_server = home.clone();
        let srv = std::thread::spawn(move || {
            serve_bucket_with_policy(
                &url_for_server,
                &home_for_server,
                &mut server_read,
                &mut server_write,
                WirePolicy::default(),
            )
        });
        let client =
            crate::stdio_transport::WireClient::handshake(client_read, client_write).unwrap();

        let refs = client.list_refs().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "main");
        assert_eq!(refs[0].1, tip);

        // GetPack streams a nonempty pack covering the tip's full closure.
        let mut out = Vec::new();
        client.get_pack(&[tip], &[], None, &mut out).unwrap();
        assert!(!out.is_empty());
        let got = scl_core::pack::parse_pack(&out).unwrap();
        assert_eq!(got.len(), objects.len());

        // A served `--store` bucket refuses a partial transfer of either kind
        // (ADR-0046, ADR-0055 B2): a size-only request is "filtered" too.
        for filter in [
            crate::promisor::PackFilter::new(&["src/".to_string()], None),
            crate::promisor::PackFilter::new(&[], Some(1024)),
        ] {
            let err = client
                .get_pack(&[tip], &[], filter.as_ref(), &mut Vec::new())
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("partial clone from bucket remotes"),
                "{err}"
            );
        }

        // PutPack + UpdateRef land a second commit through the same session.
        let (tip2, objects2) = tiny_history_for_bucket("seed2", b"second commit");
        let (pack2, _idx2) = scl_core::pack::build_pack(&objects2).unwrap();
        let ids2 = client.put_pack(&mut std::io::Cursor::new(pack2)).unwrap();
        assert_eq!(ids2.len(), objects2.len());
        client.update_ref("main", &tip2, Some(&tip)).unwrap();

        client.bye().unwrap();
        drop(client);
        srv.join().unwrap().unwrap();

        // A fresh BucketTransport sees the moved tip.
        let t2 = crate::bucket_transport::BucketTransport::open(&url).unwrap();
        assert_eq!(t2.list_refs().unwrap(), vec![("main".to_string(), tip2)]);
        drop(t2);

        // The session's TempServeDir (which the PutPack/GetPack verbs above
        // spooled through) has already been dropped by the time `srv.join`
        // returned — zero residue under the serve HOME, same ephemeral-mode
        // guarantee as every other session kind.
        let home_tmp = home.join(".sc").join("tmp");
        assert!(
            !home_tmp.exists() || std::fs::read_dir(&home_tmp).unwrap().next().is_none(),
            "no serve-bucket-* spool dir may survive the session"
        );

        std::fs::remove_dir_all(&broot).unwrap();
        std::fs::remove_dir_all(&home).unwrap();
        assert!(!broot.exists());
    }

    /// A bucket-backed receiver decodes every record (blobs too) into memory
    /// before upload, so the budget counts all of them: a highly compressible
    /// blob pack is cheap to spool but refused by decoded size (#233).
    #[test]
    fn bucket_serve_budgets_decoded_blob_bytes() {
        let broot =
            std::env::temp_dir().join(format!("scl-wire-bucket-bud-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let url = format!("sc+wal://{}", broot.display());
        let home = tmp_repo("bucket-budget-home");
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let (url2, home2) = (url.clone(), home.clone());
        let srv = std::thread::spawn(move || {
            serve_bucket_with_policy(
                &url2,
                &home2,
                &mut server_read,
                &mut server_write,
                WirePolicy {
                    max_conn_bytes: 2_000_000,
                    ..Default::default()
                },
            )
        });
        let client =
            crate::stdio_transport::WireClient::handshake(client_read, client_write).unwrap();
        let blob = scl_core::Object::blob(vec![0u8; 3_000_000]);
        let (pack, _) = scl_core::pack::build_pack(&[(blob.id(), blob.encode())]).unwrap();
        assert!(pack.len() < 100_000, "premise: the pack compresses well");
        let err = client
            .put_pack(&mut std::io::Cursor::new(pack))
            .unwrap_err();
        assert!(matches!(err, Error::ConnectionBudgetExceeded(_)), "{err:?}");
        drop(client);
        srv.join().unwrap().unwrap();
        std::fs::remove_dir_all(&broot).unwrap();
        assert!(!broot.exists());
        std::fs::remove_dir_all(&home).unwrap();
        assert!(!home.exists());
    }

    /// A bucket-backed serve session refuses `GetObjects` (by-id reads exist
    /// only for partial clones, which bucket remotes refuse, ADR-0046) with a
    /// typed error, and the session stays usable afterwards.
    #[test]
    fn bucket_serve_refuses_get_objects_and_keeps_the_session() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-wire-bucket-byid-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        let url = format!("sc+wal://{}", broot.display());
        let home = tmp_repo("bucket-byid-home");
        let (tip, objects) = tiny_history_for_bucket("byid", b"hello by-id");
        {
            let t = crate::bucket_transport::BucketTransport::open(&url).unwrap();
            let (pack, _idx) = scl_core::pack::build_pack(&objects).unwrap();
            t.put_pack(&mut std::io::Cursor::new(pack)).unwrap();
            t.update_ref("main", &tip, None).unwrap();
        }
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let (url_s, home_s) = (url.clone(), home.clone());
        let srv = std::thread::spawn(move || {
            serve_bucket_with_policy(
                &url_s,
                &home_s,
                &mut server_read,
                &mut server_write,
                WirePolicy::default(),
            )
        });
        let client =
            crate::stdio_transport::WireClient::handshake(client_read, client_write).unwrap();

        let err = client.get_objects(&[tip], &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidArgument(m) | Error::Remote(m) if m.contains("by-id")),
            "got {err:?}"
        );
        // The refusal failed the request, not the session.
        assert_eq!(client.list_refs().unwrap().len(), 1);

        client.bye().unwrap();
        drop(client);
        srv.join().unwrap().unwrap();
        std::fs::remove_dir_all(&broot).unwrap();
        std::fs::remove_dir_all(&home).unwrap();
        assert!(!broot.exists());
    }

    /// Regression for a review finding: a bucket-backed serve session's pack
    /// spool dir must live under the serve HOME's own `.sc/tmp/`, not the
    /// process-wide `std::env::temp_dir()` (CLAUDE.md / THREAT-MODEL.md's
    /// "pack-spool scratch lives in the serve home" contract) — and must be
    /// removed again on drop, exactly like every other ephemeral scratch dir
    /// in this codebase.
    #[test]
    fn temp_serve_dir_lives_under_home_sc_tmp_and_is_removed_on_drop() {
        let home = tmp_repo("bucket-tmpdir-home");
        let path = {
            let guard = TempServeDir::create_in(&home).unwrap();
            let p = guard.0.clone();
            assert!(
                p.starts_with(home.join(".sc").join("tmp")),
                "spool dir {p:?} must live under the serve home's .sc/tmp/"
            );
            assert!(p.is_dir());
            p
        };
        assert!(!path.exists(), "TempServeDir must be removed on drop");
        std::fs::remove_dir_all(&home).unwrap();
    }
}
