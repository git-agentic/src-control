//! The object cap is wired into the live wire paths (#232): a `PutObject`
//! through `serve` and a `GetObject` through `WireClient`, with the cap fixed
//! at 2 MiB before the first read. Own test binary: the cap is process-global.

use scl_core::{Object, MIN_MAX_OBJECT_SIZE};
use scl_repo::stdio_transport::WireClient;
use scl_repo::transport::Transport;
use scl_repo::wire::{self, Request};

fn set_cap() {
    scl_core::set_max_object_size(MIN_MAX_OBJECT_SIZE).unwrap();
}

fn setup() -> std::path::PathBuf {
    set_cap();
    let root = std::env::temp_dir().join(format!("scl-wire-cap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    scl_repo::Repo::init(&root).unwrap();
    root
}

/// Canonical encoding of a blob is its payload plus one tag byte.
fn blob_of_canonical_len(n: usize) -> Object {
    Object::blob(vec![0xAB; n - 1])
}

fn put_via_serve(root: &std::path::Path, obj: &Object) -> Vec<Result<Vec<u8>, scl_repo::Error>> {
    let mut input = Vec::new();
    for req in [
        Request::Hello {
            version: wire::PROTOCOL_VERSION,
        },
        Request::PutObject {
            id: obj.id(),
            bytes: obj.encode(),
        },
    ] {
        wire::write_frame(&mut input, &req.encode()).unwrap();
    }
    let mut output = Vec::new();
    wire::serve(root, &mut std::io::Cursor::new(input), &mut output).unwrap();
    let mut r = std::io::Cursor::new(output);
    let mut out = Vec::new();
    while let Some(f) = wire::read_frame_opt(&mut r).unwrap() {
        out.push(wire::parse_response(f));
    }
    out
}

#[test]
fn serve_put_object_exactly_cap_lands_and_cap_plus_one_is_refused() {
    let root = setup();
    let ok = put_via_serve(&root, &blob_of_canonical_len(MIN_MAX_OBJECT_SIZE));
    assert!(ok[1].is_ok(), "exactly the cap lands: {:?}", ok[1]);

    let over = put_via_serve(&root, &blob_of_canonical_len(MIN_MAX_OBJECT_SIZE + 1));
    let err = over[1].as_ref().unwrap_err().to_string();
    assert!(err.contains("object size limit"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn client_get_object_enforces_the_cap_on_the_response() {
    set_cap();
    for (len, ok) in [
        (MIN_MAX_OBJECT_SIZE, true),
        (MIN_MAX_OBJECT_SIZE + 1, false),
    ] {
        let obj = blob_of_canonical_len(len);
        // Canned server: HELLO ok, then the GetObject response.
        let mut canned = Vec::new();
        wire::write_ok(&mut canned, &wire::u32_body(wire::PROTOCOL_VERSION)).unwrap();
        wire::write_ok(&mut canned, &obj.encode()).unwrap();
        let client = WireClient::handshake(std::io::Cursor::new(canned), std::io::sink()).unwrap();
        let got = client.get_object(&obj.id());
        assert_eq!(got.is_ok(), ok, "len {len}: {got:?}");
        if let Err(e) = got {
            assert!(e.to_string().contains("object size limit"), "{e}");
        }
    }
}
