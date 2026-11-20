//! Harness bodies shared by the fuzz targets and the plain `cargo test` replay
//! below, so a broken harness is caught without nightly. Each function feeds
//! arbitrary bytes to an untrusted-input decoder, in memory only; totality
//! (Ok or Err, never a panic or runaway allocation) is the invariant.

use std::io::Cursor;

/// Per-object cap for the pack readers: small, so a zstd bomb trips the bound
/// instead of the fuzzer's RSS limit.
const CAP: usize = 1 << 20;

/// Pack record, index and bounded-zstd decoding (`scl_core::pack`).
pub fn pack(data: &[u8]) {
    let _ = scl_core::pack::parse_index(data);
    let _ = scl_core::pack::parse_pack_reader_max(Cursor::new(data), CAP, |_, _| Ok(()));
    // Offset is attacker-chosen in a hostile index; derive it from the input.
    let off = data.first().map_or(0, |&b| u64::from(b));
    let id = scl_core::ObjectId::from_bytes([0u8; 32]);
    let _ = scl_core::pack::read_object_at_bounded(data, off, &id, CAP);
}

/// The streamed-pack frame loop (`wire::read_pack_stream`).
pub fn pack_stream(data: &[u8]) {
    let mut sink = Vec::new();
    let _ = scl_repo::wire::read_pack_stream(&mut Cursor::new(data), &mut sink, CAP as u64);
}

/// Bucket WAL metadata (`walfmt`).
pub fn walfmt(data: &[u8]) {
    let _ = scl_repo::walfmt::Manifest::decode(data);
    let _ = scl_repo::walfmt::LogEntry::decode(data);
    let _ = scl_repo::walfmt::Checkpoint::decode(data);
}

/// HTTP opening parsers (server request, client status, bounded reader).
pub fn http_opening(data: &[u8]) {
    scl_repo::http_transport::fuzz_openings(data);
}

/// TLS pin file and serve-token file parsers (text, no disk).
pub fn text_files(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = scl_repo::tls_pins::parse_pin_text(&text);
    let _ = scl_repo::tls_pins::parse_host_port(&text);
    let _ = scl_repo::tls_pins::parse_fingerprint(&text);
    let _ = scl_repo::serve_tokens::parse_tokens(&text);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-made seeds: empty, magic-only, short garbage, valid-looking openings.
    const SEEDS: &[&[u8]] = &[
        b"",
        b"\0",
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        b"SCLP\x01\0\0\0",
        b"POST /x HTTP/1.1\r\nAuthorization: Bearer t\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"example.com:443 sha256:00\n# c\n[::1]:1 zz\n",
        b"[[token]]\nlabel=\"a\"\nhash=\"b\"\nscope=\"rw\"\n",
    ];

    #[test]
    fn harnesses_are_total_on_seeds() {
        for s in SEEDS {
            pack(s);
            pack_stream(s);
            walfmt(s);
            http_opening(s);
            text_files(s);
        }
    }
}
