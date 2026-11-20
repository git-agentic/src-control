//! Harness bodies shared by the fuzz targets and the plain `cargo test` replay
//! below, so a broken harness is caught without nightly. Each function feeds
//! arbitrary bytes to an untrusted-input decoder, in memory only; totality
//! (Ok or Err, never a panic or runaway allocation) is the invariant.

use std::io::Cursor;

/// Per-object cap for the pack readers: small, so a zstd bomb trips the bound
/// instead of the fuzzer's RSS limit.
const CAP: usize = 1 << 20;

/// Pack record, index and bounded-zstd decoding (`scl_core::pack`).
///
/// Input layout for the record reader: `[offset: u64 LE][expected id: 32][pack
/// bytes]`, so the fuzzer controls the offset and the id the hash check
/// compares against. The index and streaming parsers get the whole input.
pub fn pack(data: &[u8]) {
    let _ = scl_core::pack::parse_index(data);
    let _ = scl_core::pack::parse_pack_reader_max(Cursor::new(data), CAP, |_, _| Ok(()));
    if let Some((head, pack)) = data.split_at_checked(40) {
        let offset = u64::from_le_bytes(head[..8].try_into().unwrap());
        let id = scl_core::ObjectId::from_bytes(head[8..].try_into().unwrap());
        let _ = scl_core::pack::read_object_at_bounded(pack, offset, &id, CAP);
    }
}

/// The streamed-pack frame loop (`wire::read_pack_stream`). The byte budget is
/// below libFuzzer's default 4096-byte input cap so the over-budget path is
/// reachable.
pub fn pack_stream(data: &[u8]) {
    let mut sink = Vec::new();
    let _ = scl_repo::wire::read_pack_stream(&mut Cursor::new(data), &mut sink, 1024);
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

    /// The committed corpus seed must decode successfully, so the record
    /// reader's success path stays reachable from the corpus.
    #[test]
    fn pack_decode_seed_reaches_successful_decode() {
        let seed = include_bytes!("../corpus/pack_decode/valid_record");
        let offset = u64::from_le_bytes(seed[..8].try_into().unwrap());
        let id = scl_core::ObjectId::from_bytes(seed[8..40].try_into().unwrap());
        scl_core::pack::read_object_at_bounded(&seed[40..], offset, &id, CAP).unwrap();
        pack(seed);
    }

    /// Generator for the seed above; run with `--ignored` to rewrite it.
    #[test]
    #[ignore]
    fn regenerate_pack_decode_seed() {
        let canonical = scl_core::Object::blob(b"seed".to_vec()).encode();
        let id = scl_core::ObjectId::of(&canonical);
        let (pack, idx) = scl_core::pack::build_pack(&[(id, canonical)]).unwrap();
        let offset = scl_core::pack::parse_index(&idx).unwrap()[0].offset;
        let mut out = offset.to_le_bytes().to_vec();
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&pack);
        std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/pack_decode"))
            .unwrap();
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/corpus/pack_decode/valid_record"
            ),
            out,
        )
        .unwrap();
    }

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
