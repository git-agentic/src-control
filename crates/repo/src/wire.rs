//! Wire protocol for sc-native network transport (P12).
//!
//! Mirrors the [`crate::transport::Transport`] verbs 1:1 over length-prefixed
//! binary frames, so a remote repo behind `sc serve --stdio` behaves exactly
//! like a local one. See ADR-0022.

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
}
