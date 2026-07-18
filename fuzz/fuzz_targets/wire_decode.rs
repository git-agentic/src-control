//! Fuzz the remote-facing decode surface: the framed wire protocol that
//! `sc serve` parses from untrusted peers, and the canonical object decoding
//! underneath it. ADR-0039 hardened these paths against hostile input and
//! self-identified the frame-length header as the residual weak point — this
//! target exercises exactly that surface (OSTIF audit T-13, G-001).
//!
//! The invariant under test is totality: every entry point returns Ok or Err
//! on arbitrary bytes; a panic, overflow, or runaway allocation is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use scl_repo::wire;

fuzz_target!(|data: &[u8]| {
    // The socket layer: attacker bytes through the frame reader, then each
    // recovered frame through both request and response parsing.
    let mut cur = Cursor::new(data);
    while let Ok(Some(frame)) = wire::read_frame_opt(&mut cur) {
        let _ = wire::Request::decode(&frame);
        let _ = wire::parse_response(frame);
    }

    // The same bytes straight into each body decoder (a hostile peer controls
    // frame payloads independently of the framing).
    let _ = wire::Request::decode(data);
    let _ = wire::decode_refs_body(data);
    let _ = wire::decode_ids_body(data);
    let _ = wire::decode_str_body(data);
    let _ = wire::decode_u32_body(data);
    let _ = wire::decode_bool_body(data);

    // The object layer transfers ultimately deserialize into.
    let _ = scl_core::Object::decode(data);
});
