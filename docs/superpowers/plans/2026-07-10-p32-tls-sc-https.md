# P32: `sc+https://` via rustls (`crates/tlsio`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In-binary TLS for the sc-native HTTP transport — `sc+https://` with accept-new TOFU SPKI pinning on the client and `sc serve --http … --tls` (auto-minted or PEM cert) on the server — closing audit High #1 (issue #39).

**Architecture:** A new quarantine crate `crates/tlsio` is the only crate linking rustls (ring provider) + rcgen; it exposes blocking `Read+Write` TLS streams, a hand-written pin-only `ServerCertVerifier`, cert mint/load, and SPKI-SHA-256 fingerprints. `crates/repo` wraps the two existing seam functions (`HttpTransport::connect_*`, `handle_http_connection`) in those streams below the unchanged HTTP opening codec and wire protocol (`PROTOCOL_VERSION` stays 3), adds a known-hosts pin store, and tightens the P29 bind gate. The CLI adds `--tls/--tls-cert/--tls-key` and `sc serve fingerprint`.

**Tech Stack:** Rust (stable, workspace edition 2021), rustls 0.23 (`default-features = false`, features `ring,std,tls12,logging`), rcgen 0.14, rustls-pki-types (PEM), ring (SHA-256 digest only, already in-tree via rustls), hex, thiserror.

**Spec:** `docs/superpowers/specs/2026-07-10-p32-tls-sc-https-design.md`. Work happens on the existing `p32-tls` branch.

## Global Constraints

- `PROTOCOL_VERSION` stays **3**; the opening codec, `serve_tokens`, and all of `wire.rs` are byte-for-byte unchanged.
- rustls/rcgen/ring/rustls-pki-types are linked **only** by `crates/tlsio` (quarantine; the gix→gitio precedent). `tlsio` depends on **no** workspace crate. Only `repo` depends on `tlsio`.
- No RustCrypto crate in `tlsio` (RustCrypto stays quarantined in `crates/crypto`) — SHA-256 comes from `ring::digest`.
- Fingerprint = SHA-256 of the full server **SPKI DER TLV**, rendered `sha256:<lowercase-hex>` everywhere (openssl-verifiable: `openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | shasum -a 256`).
- Pin mismatch always **hard-fails** — never a prompt. Accept-new is the default; `SC_HTTPS_STRICT=1` refuses unknown hosts; `SC_HTTPS_FINGERPRINT=<sha256:hex>` pre-pins without persisting; `SC_HTTPS_KNOWN_HOSTS=<path>` overrides the pin-file path.
- No client application byte (opening line, bearer token) crosses the socket before pin disposition is settled.
- Deps: use `cargo add` (never hand-edit version pins); **stage `Cargo.lock` in the same commit as any dep change** (project memory).
- Every new behavior ships with a test; tests that touch disk clean up and assert the path is gone. Errors: `thiserror` per crate, `?`-converted; CLI uses `anyhow`.
- All commits go on the `p32-tls` branch. Run `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` before each commit (CI enforces clippy).

---

### Task 1: `crates/tlsio` scaffold — SPKI extraction, fingerprints, cert mint/load

**Files:**
- Create: `crates/tlsio/Cargo.toml`
- Create: `crates/tlsio/src/lib.rs`
- Create: `crates/tlsio/src/spki.rs`
- Create: `crates/tlsio/src/identity.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Consumes: nothing (dependency leaf).
- Produces (used by Tasks 2, 4, 5, 7):
  - `pub enum Error { BadCert, Handshake(String), PinMismatch { expected: [u8; 32], seen: [u8; 32] }, UnknownHostStrict, Mint(String), Io(std::io::Error) }` + `pub type Result<T>`
  - `pub fn spki_der(cert_der: &[u8]) -> Result<&[u8]>`
  - `pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]>`
  - `pub fn fingerprint_hex(spki_hash: &[u8; 32]) -> String` → `"sha256:<hex>"`
  - `pub struct ServerIdentity { pub certs: Vec<CertificateDer<'static>>, pub key: PrivateKeyDer<'static>, pub spki_sha256: [u8; 32] }`
  - `pub fn load_or_mint(dir: &Path) -> Result<ServerIdentity>` (dir = `.sc/serve-tls/`; mints `cert.pem` + `key.pem` (0600) only when missing)
  - `pub fn load_pem(cert: &Path, key: &Path) -> Result<ServerIdentity>`
  - Re-exports: `pub use rustls::pki_types::{CertificateDer, PrivateKeyDer};` (so `repo` never names rustls directly)

- [ ] **Step 1: Scaffold the crate and add dependencies**

```bash
mkdir -p crates/tlsio/src && cat > crates/tlsio/Cargo.toml <<'EOF'
[package]
name = "scl-tlsio"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]

[lints]
workspace = true
EOF
printf '' > crates/tlsio/src/lib.rs
```

Add `"crates/tlsio"` to `members` in the root `Cargo.toml`:

```toml
members = ["crates/core", "crates/vfs", "crates/gitio", "crates/crypto", "crates/repo", "crates/cli", "crates/tlsio"]
```

Then add deps (pins latest stable; do not hand-edit versions):

```bash
cargo add -p scl-tlsio rustls --no-default-features -F ring,std,tls12,logging
cargo add -p scl-tlsio rustls-pki-types -F std,pem
cargo add -p scl-tlsio rcgen
cargo add -p scl-tlsio ring
cargo add -p scl-tlsio hex thiserror
```

Note: `ring` is already in the tree via rustls's ring feature — this adds no new crate, only a direct edge for `ring::digest::SHA256`. If `rustls-pki-types` has no `pem` feature at the resolved version, `cargo add` fails loudly — then use `-F std` only (PEM moved into default/std in newer releases; the `pem_file_iter`/`from_pem_file` calls in Step 5 are the real check).

Run: `cargo check -p scl-tlsio` — Expected: PASS (empty lib).

- [ ] **Step 2: Write failing tests for SPKI extraction + fingerprint**

`crates/tlsio/src/spki.rs` (tests first; the correctness anchor is rcgen's own `public_key_der()`, which returns exactly the SPKI DER the cert embeds):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_der_matches_rcgen_public_key_der() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["sc-serve".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let extracted = spki_der(cert.der()).unwrap();
        assert_eq!(extracted, key.public_key_der().as_slice());
    }

    #[test]
    fn spki_sha256_is_stable_across_same_key_remint() {
        let key = rcgen::KeyPair::generate().unwrap();
        let c1 = rcgen::CertificateParams::new(vec!["a".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let c2 = rcgen::CertificateParams::new(vec!["b".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        // Different cert bytes, same key → same SPKI hash (the whole point
        // of pinning the SPKI, not the cert).
        assert_ne!(c1.der().as_ref(), c2.der().as_ref());
        assert_eq!(spki_sha256(c1.der()).unwrap(), spki_sha256(c2.der()).unwrap());
    }

    #[test]
    fn fingerprint_hex_format() {
        let h = [0xabu8; 32];
        let s = fingerprint_hex(&h);
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), "sha256:".len() + 64);
    }

    #[test]
    fn spki_der_rejects_garbage() {
        assert!(spki_der(b"not a certificate").is_err());
        assert!(spki_der(&[]).is_err());
        assert!(spki_der(&[0x30, 0x82, 0xff]).is_err()); // truncated length
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p scl-tlsio` — Expected: COMPILE FAIL (`spki_der` not defined).

- [ ] **Step 4: Implement `lib.rs` (error type) and `spki.rs`**

`crates/tlsio/src/lib.rs`:

```rust
//! TLS quarantine crate (P32, ADR-0042): the ONLY crate linking rustls and
//! rcgen (the gix→gitio / RustCrypto→crypto precedent). Exposes blocking
//! `Read + Write` TLS streams for the sc+https:// transport, a pin-only
//! TOFU certificate verifier, self-signed cert mint/load, and SPKI-SHA-256
//! fingerprints. Depends on no other workspace crate.

mod identity;
mod spki;
mod stream; // Task 2

pub use identity::{load_or_mint, load_pem, ServerIdentity};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer};
pub use spki::{fingerprint_hex, spki_der, spki_sha256};

/// Errors from the TLS layer. `PinMismatch` carries both fingerprints so the
/// caller (crates/repo) can render a recovery hint naming its pin source —
/// this crate knows nothing about known_hosts files or env vars.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not parse the server certificate (DER)")]
    BadCert,
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
    #[error("server key does not match the pinned fingerprint")]
    PinMismatch { expected: [u8; 32], seen: [u8; 32] },
    #[error("unknown host refused (strict mode)")]
    UnknownHostStrict,
    #[error("certificate mint/load failed: {0}")]
    Mint(String),
    #[error("TLS I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
```

(Leave `mod stream;` commented out until Task 2: `// mod stream; // Task 2`.)

`crates/tlsio/src/spki.rs`:

```rust
//! SubjectPublicKeyInfo extraction from a certificate DER, and the
//! `sha256:<hex>` fingerprint every P32 surface uses (pin file, banner,
//! `sc serve fingerprint`, `SC_HTTPS_FINGERPRINT`).
//!
//! The extraction is a minimal hand-written DER TLV walk rather than a full
//! x509 parser dependency: we need exactly one field, the walk is ~40 lines,
//! and a malformed certificate simply fails the connection (fail-closed).
//! Correctness is anchored by the test comparing against rcgen's own
//! `KeyPair::public_key_der()` for a cert we minted.

use crate::{Error, Result};

/// One DER TLV: returns (tag, content_start..content_end, total_len).
fn der_tlv(buf: &[u8]) -> Option<(u8, core::ops::Range<usize>, usize)> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, header..end, end))
}

/// Extract the full SubjectPublicKeyInfo TLV (header included) from a
/// certificate DER. Layout: `Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signature }`; `TBSCertificate ::= SEQUENCE {
/// [0] version OPTIONAL, serialNumber, signature, issuer, validity,
/// subject, subjectPublicKeyInfo, ... }` — so: descend two SEQUENCEs, skip
/// the optional context-0 version, skip five fields, take the sixth.
pub fn spki_der(cert_der: &[u8]) -> Result<&[u8]> {
    let (tag, body, _) = der_tlv(cert_der).ok_or(Error::BadCert)?;
    if tag != 0x30 {
        return Err(Error::BadCert);
    }
    let tbs_buf = &cert_der[body];
    let (tag, body, _) = der_tlv(tbs_buf).ok_or(Error::BadCert)?;
    if tag != 0x30 {
        return Err(Error::BadCert);
    }
    let mut rest = &tbs_buf[body];
    if rest.first() == Some(&0xa0) {
        let (_, _, used) = der_tlv(rest).ok_or(Error::BadCert)?;
        rest = &rest[used..];
    }
    for _ in 0..5 {
        let (_, _, used) = der_tlv(rest).ok_or(Error::BadCert)?;
        rest = &rest[used..];
    }
    let (tag, _, used) = der_tlv(rest).ok_or(Error::BadCert)?;
    if tag != 0x30 {
        return Err(Error::BadCert);
    }
    Ok(&rest[..used])
}

/// SHA-256 over the SPKI TLV — the pin. ring's digest, not a RustCrypto
/// crate (RustCrypto stays quarantined in crates/crypto); ring is already
/// in-tree as rustls's crypto provider.
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32]> {
    let spki = spki_der(cert_der)?;
    let d = ring::digest::digest(&ring::digest::SHA256, spki);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    Ok(out)
}

/// Render a pin as `sha256:<lowercase hex>` — the one fingerprint format.
pub fn fingerprint_hex(spki_hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(spki_hash))
}
```

- [ ] **Step 5: Write failing tests for `identity.rs`, then implement**

`crates/tlsio/src/identity.rs`:

```rust
//! Server TLS identity: load `cert.pem`/`key.pem` from a directory, minting
//! a self-signed pair (rcgen) when absent. The KEY is the identity —
//! regenerate only when missing; the cert carries a far-future not_after so
//! renewal never bites a pinned deployment (pins are on the SPKI anyway).

use std::path::Path;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

use crate::{spki_sha256, Error, Result};

/// A loaded/minted server identity, ready for `server_config` (Task 2).
pub struct ServerIdentity {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub spki_sha256: [u8; 32],
}

/// Load `dir/cert.pem` + `dir/key.pem`, minting both (key mode 0600) when
/// the CERT is absent. A dir with a cert but no key (or vice versa) is an
/// error, not a silent re-mint — regenerating over half an identity would
/// invalidate every client pin without the operator asking for it.
pub fn load_or_mint(dir: &Path) -> Result<ServerIdentity> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => load_pem(&cert_path, &key_path),
        (false, false) => {
            std::fs::create_dir_all(dir)?;
            let key = rcgen::KeyPair::generate().map_err(|e| Error::Mint(e.to_string()))?;
            let mut params = rcgen::CertificateParams::new(vec!["sc-serve".to_string()])
                .map_err(|e| Error::Mint(e.to_string()))?;
            params.not_after = rcgen::date_time_ymd(2126, 1, 1);
            let cert = params
                .self_signed(&key)
                .map_err(|e| Error::Mint(e.to_string()))?;
            std::fs::write(&cert_path, cert.pem())?;
            write_key_0600(&key_path, key.serialize_pem().as_bytes())?;
            load_pem(&cert_path, &key_path)
        }
        _ => Err(Error::Mint(format!(
            "{} holds half a TLS identity (one of cert.pem/key.pem is missing); \
             restore the missing file or remove the directory to re-mint",
            dir.display()
        ))),
    }
}

/// Load a user-supplied PEM pair (certbot etc.). The fingerprint is the
/// leaf's (first cert's) SPKI hash.
pub fn load_pem(cert: &Path, key: &Path) -> Result<ServerIdentity> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| Error::Mint(format!("read {}: {e}", cert.display())))?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Mint(format!("parse {}: {e}", cert.display())))?;
    let leaf = certs.first().ok_or(Error::BadCert)?;
    let spki = spki_sha256(leaf)?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| Error::Mint(format!("read {}: {e}", key.display())))?;
    Ok(ServerIdentity {
        spki_sha256: spki,
        certs,
        key,
    })
}

#[cfg(unix)]
fn write_key_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("scl-tlsio-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn mint_then_load_is_idempotent_and_key_is_0600() {
        let dir = tmp("mint");
        let a = load_or_mint(&dir).unwrap();
        let b = load_or_mint(&dir).unwrap();
        // Second call LOADS (same identity), never re-mints.
        assert_eq!(a.spki_sha256, b.spki_sha256);
        assert_eq!(a.certs, b.certs);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("key.pem")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key.pem must be 0600");
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn half_an_identity_errors_instead_of_silently_reminting() {
        let dir = tmp("half");
        load_or_mint(&dir).unwrap();
        std::fs::remove_file(dir.join("key.pem")).unwrap();
        let err = load_or_mint(&dir).unwrap_err();
        assert!(err.to_string().contains("half a TLS identity"), "got: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_pem_reads_a_minted_pair() {
        let dir = tmp("pem");
        let minted = load_or_mint(&dir).unwrap();
        let loaded = load_pem(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
        assert_eq!(minted.spki_sha256, loaded.spki_sha256);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
```

If the resolved rcgen version's API differs (e.g. `CertificateParams::new` not returning `Result`, or `date_time_ymd` renamed), check `cargo doc -p rcgen --no-deps` and adapt the mint block only — the public `ServerIdentity`/`load_or_mint`/`load_pem` signatures are fixed.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p scl-tlsio` — Expected: all PASS.

- [ ] **Step 7: Commit (Cargo.lock staged with the dep change)**

```bash
cargo clippy -p scl-tlsio --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/tlsio
git commit -m "feat(tlsio): P32 scaffold — SPKI fingerprints + cert mint/load (rustls/rcgen quarantine)"
```

---

### Task 2: `tlsio` streams — pin verifier, `client_connect`, `server_stream`, split halves

**Files:**
- Create: `crates/tlsio/src/stream.rs`
- Modify: `crates/tlsio/src/lib.rs` (enable `mod stream;`, re-export)

**Interfaces:**
- Consumes: Task 1's `ServerIdentity`, `spki_sha256`, `Error`.
- Produces (used by Tasks 4–5):
  - `pub struct TlsServerConfig { /* Arc<rustls::ServerConfig> */ pub spki_sha256: [u8; 32] }` — `Clone`
  - `pub fn server_config(id: ServerIdentity) -> Result<TlsServerConfig>`
  - `pub fn server_stream(cfg: &TlsServerConfig, tcp: TcpStream) -> Result<TlsServerStream>` — handshake driven to completion before returning
  - `pub fn client_connect(tcp: TcpStream, host: &str, expected_pin: Option<[u8; 32]>, strict: bool) -> Result<(TlsClientStream, [u8; 32])>` — returns the observed SPKI hash; handshake completed before returning
  - `TlsClientStream::split(self) -> (TlsClientReadHalf, TlsClientWriteHalf)`; same for `TlsServerStream` → `TlsServerReadHalf`/`TlsServerWriteHalf`
  - Read halves have `pub fn set_socket_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()>`
  - All four halves implement `io::Read`/`io::Write` respectively and are `Send`.

- [ ] **Step 1: Write the failing loopback tests**

Append to `crates/tlsio/src/stream.rs` (module skeleton + tests; implementation lands in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("scl-tlsio-st-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Loopback server: accept one connection, TLS-wrap it, echo one
    /// length-prefixed message back. Returns (addr, join handle, spki).
    fn echo_server(dir: &std::path::Path) -> (String, std::thread::JoinHandle<()>, [u8; 32]) {
        let id = crate::load_or_mint(dir).unwrap();
        let spki = id.spki_sha256;
        let cfg = server_config(id).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let h = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            // A client that aborts its handshake (mismatch/strict tests)
            // surfaces as Err here — that's fine, just return.
            let Ok(stream) = server_stream(&cfg, tcp) else { return };
            let (mut r, mut w) = stream.split();
            let mut buf = [0u8; 5];
            if r.read_exact(&mut buf).is_err() {
                return;
            }
            w.write_all(&buf).unwrap();
            w.flush().unwrap();
        });
        (addr, h, spki)
    }

    #[test]
    fn accept_new_returns_seen_pin_and_data_flows_through_halves() {
        let dir = tmp("tofu");
        let (addr, h, spki) = echo_server(&dir);
        let tcp = TcpStream::connect(&addr).unwrap();
        let (stream, seen) = client_connect(tcp, "127.0.0.1", None, false).unwrap();
        assert_eq!(seen, spki, "observed pin must be the server's SPKI hash");
        let (mut r, mut w) = stream.split();
        w.write_all(b"hello").unwrap();
        w.flush().unwrap();
        let mut back = [0u8; 5];
        r.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        h.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn matching_pin_connects() {
        let dir = tmp("pinok");
        let (addr, h, spki) = echo_server(&dir);
        let tcp = TcpStream::connect(&addr).unwrap();
        assert!(client_connect(tcp, "127.0.0.1", Some(spki), false).is_ok());
        h.join().ok();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mismatched_pin_hard_fails_with_both_fingerprints() {
        let dir = tmp("pinbad");
        let (addr, h, spki) = echo_server(&dir);
        let wrong = [0x42u8; 32];
        assert_ne!(wrong, spki);
        let tcp = TcpStream::connect(&addr).unwrap();
        match client_connect(tcp, "127.0.0.1", Some(wrong), false) {
            Err(crate::Error::PinMismatch { expected, seen }) => {
                assert_eq!(expected, wrong);
                assert_eq!(seen, spki);
            }
            other => panic!("expected PinMismatch, got {other:?}"),
        }
        h.join().ok();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn strict_refuses_unknown_host() {
        let dir = tmp("strict");
        let (addr, h, _) = echo_server(&dir);
        let tcp = TcpStream::connect(&addr).unwrap();
        match client_connect(tcp, "127.0.0.1", None, true) {
            Err(crate::Error::UnknownHostStrict) => {}
            other => panic!("expected UnknownHostStrict, got {other:?}"),
        }
        h.join().ok();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plain_tcp_client_against_tls_server_fails_cleanly() {
        let dir = tmp("plain");
        let (addr, h, _) = echo_server(&dir);
        let mut tcp = TcpStream::connect(&addr).unwrap();
        // A plaintext opening against a TLS listener must error server-side
        // (covered by echo_server's `else return`), and the client just sees
        // a dead/garbled connection — no hang.
        tcp.write_all(b"POST / HTTP/1.1\r\n\r\n").ok();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 16];
        // Read either 0 (close) or a TLS alert — anything but a hang.
        let _ = tcp.read(&mut buf);
        h.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Enable `mod stream;` in `lib.rs` with re-exports:

```rust
pub use stream::{
    client_connect, server_config, server_stream, TlsClientReadHalf, TlsClientStream,
    TlsClientWriteHalf, TlsServerConfig, TlsServerReadHalf, TlsServerStream, TlsServerWriteHalf,
};
```

Run: `cargo test -p scl-tlsio` — Expected: COMPILE FAIL (types not defined).

- [ ] **Step 3: Implement `stream.rs`**

```rust
//! Blocking TLS streams over `TcpStream`, split into Read/Write halves.
//!
//! The wire protocol needs SEPARATE reader/writer values (`WireClient<R, W>`
//! and `wire::serve(r, w)`), but a `rustls::StreamOwned` is one object — so
//! `split` shares it behind `Arc<Mutex<…>>` with a half per side. That is
//! safe (not a deadlock risk) because the sc wire protocol is strictly
//! sequential request-reply on both ends: a read and a write never block
//! concurrently on one connection.
//!
//! Both `client_connect` and `server_stream` drive the handshake to
//! completion before returning: the client's pin disposition must be settled
//! BEFORE any application byte (the HTTP opening, the bearer token) is
//! written, and a garbage/non-TLS peer must fail at the seam, not
//! mid-protocol.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;

use crate::{spki_sha256, Error, Result, ServerIdentity};

/// Pin-only server-cert verifier (v1 trust model, ADR-0042): the SPKI hash
/// is the entire trust decision — names and validity windows are
/// deliberately ignored. Handshake signatures ARE still verified against
/// the presented key (otherwise a MITM could replay the pinned cert without
/// holding its private key).
#[derive(Debug)]
struct PinVerifier {
    expected: Option<[u8; 32]>,
    strict: bool,
    seen: Mutex<Option<[u8; 32]>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let hash = spki_sha256(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        *self.seen.lock().unwrap() = Some(hash);
        match self.expected {
            Some(p) if p == hash => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General("sc: pinned fingerprint mismatch".into())),
            None if self.strict => Err(rustls::Error::General("sc: unknown host (strict)".into())),
            None => Ok(rustls::client::danger::ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A built server config (one per listener), cheap to clone per connection.
#[derive(Clone)]
pub struct TlsServerConfig {
    config: Arc<rustls::ServerConfig>,
    /// The identity's SPKI hash, for the startup banner / `sc serve
    /// fingerprint` without re-reading the PEM.
    pub spki_sha256: [u8; 32],
}

impl std::fmt::Debug for TlsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerConfig").finish_non_exhaustive()
    }
}

pub fn server_config(id: ServerIdentity) -> Result<TlsServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Handshake(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(id.certs, id.key)
        .map_err(|e| Error::Handshake(e.to_string()))?;
    Ok(TlsServerConfig {
        config: Arc::new(config),
        spki_sha256: id.spki_sha256,
    })
}

pub struct TlsServerStream {
    inner: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
}

pub struct TlsClientStream {
    inner: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

/// Accept-side wrap: complete the handshake (bounded by whatever socket
/// timeout the caller set on `tcp`) and return a ready stream.
pub fn server_stream(cfg: &TlsServerConfig, mut tcp: TcpStream) -> Result<TlsServerStream> {
    let mut conn = rustls::ServerConnection::new(cfg.config.clone())
        .map_err(|e| Error::Handshake(e.to_string()))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .map_err(|e| Error::Handshake(format!("server handshake: {e}")))?;
    }
    Ok(TlsServerStream {
        inner: rustls::StreamOwned::new(conn, tcp),
    })
}

/// Connect-side wrap. Returns the ready stream AND the observed SPKI hash
/// (for TOFU recording). Error mapping: a handshake failure caused by our
/// own verifier is translated back into the typed pin errors using the
/// verifier's recorded state.
pub fn client_connect(
    mut tcp: TcpStream,
    host: &str,
    expected_pin: Option<[u8; 32]>,
    strict: bool,
) -> Result<(TlsClientStream, [u8; 32])> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinVerifier {
        expected: expected_pin,
        strict,
        seen: Mutex::new(None),
        algs,
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Handshake(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| Error::Handshake(format!("bad server name {host}: {e}")))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| Error::Handshake(e.to_string()))?;
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut tcp) {
            // Translate our verifier's rejections into typed errors.
            let seen = *verifier.seen.lock().unwrap();
            if let (Some(expected), Some(seen)) = (expected_pin, seen) {
                if expected != seen {
                    return Err(Error::PinMismatch { expected, seen });
                }
            }
            if expected_pin.is_none() && strict && seen.is_some() {
                return Err(Error::UnknownHostStrict);
            }
            return Err(Error::Handshake(format!("client handshake with {host}: {e}")));
        }
    }
    let seen = verifier
        .seen
        .lock()
        .unwrap()
        .ok_or_else(|| Error::Handshake("handshake completed without a certificate".into()))?;
    Ok((
        TlsClientStream {
            inner: rustls::StreamOwned::new(conn, tcp),
        },
        seen,
    ))
}

// ── split halves ───────────────────────────────────────────────────────────

macro_rules! halves {
    ($stream:ident, $read:ident, $write:ident) => {
        pub struct $read(Arc<Mutex<$stream>>);
        pub struct $write(Arc<Mutex<$stream>>);

        impl $stream {
            pub fn split(self) -> ($read, $write) {
                let shared = Arc::new(Mutex::new(self));
                ($read(shared.clone()), $write(shared))
            }
        }

        impl Read for $read {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().inner.read(buf)
            }
        }

        impl Write for $write {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().inner.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().inner.flush()
            }
        }

        impl $read {
            /// Set read/write timeouts on the UNDERLYING socket (SO_RCVTIMEO
            /// / SO_SNDTIMEO apply to the socket, so they govern the TLS
            /// stream's blocking behavior below the record layer) — the P31
            /// session-timeout hook.
            pub fn set_socket_timeouts(
                &self,
                read: Option<Duration>,
                write: Option<Duration>,
            ) -> std::io::Result<()> {
                let g = self.0.lock().unwrap();
                g.inner.get_ref().set_read_timeout(read)?;
                g.inner.get_ref().set_write_timeout(write)
            }
        }
    };
}

halves!(TlsClientStream, TlsClientReadHalf, TlsClientWriteHalf);
halves!(TlsServerStream, TlsServerReadHalf, TlsServerWriteHalf);
```

If the resolved rustls 0.23.x differs on builder method names (`builder_with_provider` / `with_safe_default_protocol_versions` / `.dangerous()`), consult `cargo doc -p rustls --no-deps` — the pattern is rustls's own documented custom-verifier example; keep the public tlsio signatures fixed.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-tlsio` — Expected: all PASS (including Task 1's).

- [ ] **Step 5: Commit**

```bash
cargo clippy -p scl-tlsio --all-targets -- -D warnings
git add crates/tlsio
git commit -m "feat(tlsio): TOFU pin verifier + blocking client/server TLS streams with split halves"
```

---

### Task 3: `repo` pin store (`tls_pins.rs`) + error variants

**Files:**
- Create: `crates/repo/src/tls_pins.rs`
- Modify: `crates/repo/src/lib.rs` (add `pub mod tls_pins;`)
- Modify: `crates/repo/src/error.rs`
- Modify: `crates/repo/Cargo.toml` (dep on `scl-tlsio`)

**Interfaces:**
- Consumes: `scl_tlsio::{Error as TlsError, fingerprint_hex}`.
- Produces (used by Task 5):
  - `pub struct TlsClientPolicy { pub known_hosts: PathBuf, pub pre_pin: Option<[u8; 32]>, pub strict: bool }`
  - `impl TlsClientPolicy { pub fn from_env() -> Result<TlsClientPolicy> }`
  - `pub fn default_known_hosts_path() -> Result<PathBuf>`
  - `pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]>` (accepts `sha256:<hex>` or bare 64-char hex)
  - `pub fn lookup(file: &Path, host: &str, port: u16) -> Result<Option<[u8; 32]>>`
  - `pub fn record(file: &Path, host: &str, port: u16, pin: &[u8; 32]) -> Result<()>`
  - `repo::Error` gains: `Tls(#[from] scl_tlsio::Error)`, `TlsPinMismatch { host, file, pinned, seen }` (all `String`), `TlsStrictUnknownHost(String)`

- [ ] **Step 1: Add the dependency**

```bash
cargo add -p scl-repo --path crates/tlsio scl-tlsio
```

(If the invocation form differs, `cargo add scl-tlsio --package scl-repo --path crates/tlsio`.)

- [ ] **Step 2: Add the error variants**

In `crates/repo/src/error.rs`, after the existing `Remote(String)` variant:

```rust
#[error("TLS: {0}")]
Tls(#[from] scl_tlsio::Error),
#[error(
    "sc+https server key for {host} does not match the pinned fingerprint ({file})\n  \
     pinned: {pinned}\n  server: {seen}\n\
     If the server key legitimately changed, remove that host's line from the pin file \
     and reconnect (the next connect re-pins); verify with `sc serve fingerprint` on the server."
)]
TlsPinMismatch {
    host: String,
    file: String,
    pinned: String,
    seen: String,
},
#[error(
    "sc+https host {0} is not pinned and SC_HTTPS_STRICT=1 refuses unknown hosts; \
     pre-pin with SC_HTTPS_FINGERPRINT=sha256:<hex> or connect once without SC_HTTPS_STRICT"
)]
TlsStrictUnknownHost(String),
```

- [ ] **Step 3: Write failing tests for the pin store**

`crates/repo/src/tls_pins.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("scl-pins-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn record_then_lookup_round_trips() {
        let dir = tmp("rt");
        let file = dir.join("known_hosts");
        let pin = [0x11u8; 32];
        assert_eq!(lookup(&file, "example.com", 8730).unwrap(), None);
        record(&file, "example.com", 8730, &pin).unwrap();
        assert_eq!(lookup(&file, "example.com", 8730).unwrap(), Some(pin));
        // Same host, different port = a different pin slot.
        assert_eq!(lookup(&file, "example.com", 9000).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pin_file_line_format_is_host_port_sha256_hex() {
        let dir = tmp("fmt");
        let file = dir.join("known_hosts");
        record(&file, "h", 8730, &[0xaa; 32]).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text, format!("h:8730 sha256:{}\n", "aa".repeat(32)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lookup_ignores_malformed_lines_and_comments() {
        let dir = tmp("junk");
        let file = dir.join("known_hosts");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, "# comment\n\nnot a pin line\nh:1 sha256:zz\n").unwrap();
        assert_eq!(lookup(&file, "h", 1).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_fingerprint_accepts_both_forms_and_rejects_junk() {
        let hexs = "ab".repeat(32);
        let expected = [0xabu8; 32];
        assert_eq!(parse_fingerprint(&format!("sha256:{hexs}")).unwrap(), expected);
        assert_eq!(parse_fingerprint(&hexs).unwrap(), expected);
        assert!(parse_fingerprint("sha256:short").is_err());
        assert!(parse_fingerprint("md5:abcd").is_err());
        assert!(parse_fingerprint("").is_err());
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p scl-repo tls_pins` — Expected: COMPILE FAIL.

- [ ] **Step 5: Implement `tls_pins.rs`**

```rust
//! Client-side TOFU pin store for sc+https:// (P32): a user-level
//! known_hosts file, one line per `host:port`, format
//! `host:port sha256:<hex>` — plus the env knobs that shape a connection's
//! pin policy. The repo layer owns pin PERSISTENCE and POLICY; the actual
//! in-handshake check lives in scl-tlsio's verifier.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The pin policy for one client connection, resolved from env by
/// [`TlsClientPolicy::from_env`] or built directly by tests (env mutation is
/// process-global and racy under parallel tests — the
/// `connect_with_token`/`connect_with_pins` split exists for this).
#[derive(Debug, Clone)]
pub struct TlsClientPolicy {
    pub known_hosts: PathBuf,
    /// `SC_HTTPS_FINGERPRINT`: verified for this process only, never
    /// persisted (CI-friendly).
    pub pre_pin: Option<[u8; 32]>,
    /// `SC_HTTPS_STRICT=1`: refuse unknown hosts instead of accept-new.
    pub strict: bool,
}

impl TlsClientPolicy {
    pub fn from_env() -> Result<TlsClientPolicy> {
        let known_hosts = match std::env::var_os("SC_HTTPS_KNOWN_HOSTS") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => default_known_hosts_path()?,
        };
        let pre_pin = match std::env::var("SC_HTTPS_FINGERPRINT") {
            Ok(s) if !s.is_empty() => Some(parse_fingerprint(&s)?),
            _ => None,
        };
        let strict = std::env::var("SC_HTTPS_STRICT").map(|v| v == "1").unwrap_or(false);
        Ok(TlsClientPolicy {
            known_hosts,
            pre_pin,
            strict,
        })
    }
}

/// `$XDG_CONFIG_HOME/sc/known_hosts`, falling back to
/// `$HOME/.config/sc/known_hosts`.
pub fn default_known_hosts_path() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("sc").join("known_hosts"));
    }
    match std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        Some(home) => Ok(PathBuf::from(home).join(".config").join("sc").join("known_hosts")),
        None => Err(Error::InvalidArgument(
            "cannot resolve the sc+https pin file: set HOME, XDG_CONFIG_HOME, \
             or SC_HTTPS_KNOWN_HOSTS"
                .to_string(),
        )),
    }
}

/// Parse `sha256:<64 hex>` (or bare hex) into a pin.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let hex_part = s.strip_prefix("sha256:").unwrap_or(s);
    let bytes = hex::decode(hex_part)
        .map_err(|_| Error::InvalidArgument(format!("bad fingerprint (want sha256:<hex>): {s}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidArgument(format!("fingerprint must be 32 bytes: {s}")))?;
    Ok(arr)
}

/// Find the pin for `host:port`, if any. A missing file means no pins; a
/// malformed or comment line is skipped, never an error (the file is
/// user-editable — the documented mismatch recovery is deleting a line).
pub fn lookup(file: &Path, host: &str, port: u16) -> Result<Option<[u8; 32]>> {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::InvalidArgument(format!(
                "read pin file {}: {e}",
                file.display()
            )))
        }
    };
    let key = format!("{host}:{port}");
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(' ') {
            if k == key {
                if let Ok(pin) = parse_fingerprint(v.trim()) {
                    return Ok(Some(pin));
                }
            }
        }
    }
    Ok(None)
}

/// Append a pin line (creating parent dirs and the file as needed).
pub fn record(file: &Path, host: &str, port: u16, pin: &[u8; 32]) -> Result<()> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::InvalidArgument(format!("create {}: {e}", parent.display())))?;
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .map_err(|e| Error::InvalidArgument(format!("open pin file {}: {e}", file.display())))?;
    writeln!(f, "{host}:{port} {}", scl_tlsio::fingerprint_hex(pin))
        .map_err(|e| Error::InvalidArgument(format!("write pin file {}: {e}", file.display())))?;
    Ok(())
}
```

Add `pub mod tls_pins;` to `crates/repo/src/lib.rs` next to the other module declarations. `hex` may need adding to `crates/repo`: `cargo add -p scl-repo hex` (check first — `grep hex crates/repo/Cargo.toml`).

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p scl-repo tls_pins` — Expected: PASS. Also `cargo test -p scl-repo` — Expected: no regressions.

- [ ] **Step 7: Commit**

```bash
cargo clippy -p scl-repo --all-targets -- -D warnings
git add Cargo.lock crates/repo
git commit -m "feat(repo): sc+https pin store (known_hosts), env pin policy, TLS error variants"
```

---

### Task 4: server seam — `TlsMode`, TLS-wrapped `handle_http_connection`, fingerprint helper

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`serve_http`, `serve_http_listener`, `handle_http_connection`)
- Modify: `crates/repo/src/layout.rs` (add `serve_tls_dir()`)
- Modify: `crates/cli/src/main.rs:3191` call site (temporary: pass `TlsMode::Off` so the workspace compiles; real CLI wiring is Task 7)

**Interfaces:**
- Consumes: Task 2's `TlsServerConfig`, `server_config`, `server_stream`, `load_or_mint`, `load_pem`, `fingerprint_hex`; Task 1's `ServerIdentity`.
- Produces (used by Tasks 5–7):
  - `pub enum TlsMode { Off, AutoMint, Pem { cert: PathBuf, key: PathBuf } }`
  - `pub fn serve_http(addr: &str, root: &Path, read_only: bool, allow_public: bool, limits: ServeLimits, tls: TlsMode) -> Result<()>`
  - `pub fn serve_http_listener(listener: TcpListener, root: &Path, read_only: bool, mandatory_auth: bool, limits: ServeLimits, tls: Option<scl_tlsio::TlsServerConfig>) -> Result<()>`
  - `pub fn serve_tls_fingerprint(root: &Path) -> Result<String>` (mints if missing; returns `sha256:<hex>`)
  - `Layout::serve_tls_dir(&self) -> PathBuf` → `.sc/serve-tls`
  - Startup output: line 1 `listening on <addr>` (unchanged — tests parse it), line 2 (TLS only) `tls fingerprint: sha256:<hex>`

**Design note (deliberate spec deviation, record in the ADR):** the spec said the `--max-connections` busy-shed completes the TLS handshake so the 503 arrives readable. That would run a handshake **on the accept-loop thread**, letting one slow client stall all accepts — exactly the property P31 exists to protect. Instead, under TLS the cap-shed **closes the connection without a status** (git-daemon behavior); the plaintext 503 nicety is unchanged. Update the spec's §3 note when doing Task 9.

- [ ] **Step 1: Write the failing tests**

Add to `http_transport.rs`'s test module (the existing harness binds `127.0.0.1:0` and hands the listener to `serve_http_listener` on a thread — extend the existing `spawn_server`-style helper with a `tls: Option<TlsServerConfig>` parameter, defaulting existing call sites to `None`):

```rust
/// Bind a TLS listener over a fresh repo; returns (addr, spki, join guard).
fn spawn_tls_server(root: &std::path::Path) -> (String, [u8; 32]) {
    let id = scl_tlsio::load_or_mint(&root.join(".sc").join("serve-tls")).unwrap();
    let spki = id.spki_sha256;
    let cfg = scl_tlsio::server_config(id).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let root = root.to_path_buf();
    std::thread::spawn(move || {
        let _ = serve_http_listener(
            listener,
            &root,
            false,
            false,
            ServeLimits::default(),
            Some(cfg),
        );
    });
    (addr, spki)
}

#[test]
fn tls_server_answers_opening_over_tls_and_rejects_plaintext() {
    let root = tmp_repo("tls-opening"); // reuse the file's existing repo-fixture helper
    let (addr, spki) = spawn_tls_server(&root);

    // A TLS client (raw tlsio, pinned) gets a 200 through the TLS channel.
    let tcp = std::net::TcpStream::connect(&addr).unwrap();
    let (stream, seen) = scl_tlsio::client_connect(tcp, "127.0.0.1", Some(spki), false).unwrap();
    assert_eq!(seen, spki);
    let (r, mut w) = stream.split();
    write_client_opening(&mut w, "127.0.0.1", "/", None).unwrap();
    use std::io::Write as _;
    w.flush().unwrap();
    let mut br = std::io::BufReader::new(r);
    assert_eq!(read_status(&mut br).unwrap(), 200);

    // A PLAINTEXT client against the TLS listener fails cleanly (the
    // server-side handshake errors; the client sees close/garbage, not 200).
    let mut plain = std::net::TcpStream::connect(&addr).unwrap();
    plain
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    write_client_opening(&mut plain, "127.0.0.1", "/", None).unwrap();
    let mut resp = Vec::new();
    use std::io::Read as _;
    let _ = plain.read_to_end(&mut resp);
    assert!(
        !String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"),
        "plaintext client must not reach the opening handler on a TLS listener"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn serve_tls_fingerprint_mints_and_is_stable() {
    let root = tmp_repo("tls-fpr");
    let f1 = serve_tls_fingerprint(&root).unwrap();
    assert!(f1.starts_with("sha256:"), "got: {f1}");
    assert!(root.join(".sc").join("serve-tls").join("key.pem").exists());
    let f2 = serve_tls_fingerprint(&root).unwrap();
    assert_eq!(f1, f2, "fingerprint must load, not re-mint");
    std::fs::remove_dir_all(&root).unwrap();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo http_transport` — Expected: COMPILE FAIL (`serve_http_listener` arity, `serve_tls_fingerprint` missing).

- [ ] **Step 3: Implement the server seam**

1. `crates/repo/src/layout.rs` — next to `tmp_dir()`:

```rust
/// `.sc/serve-tls/` — the server's TLS identity (`cert.pem` + `key.pem`),
/// auto-minted on first `sc serve --http … --tls` (P32). The key IS the
/// identity: it is regenerated only when missing.
pub fn serve_tls_dir(&self) -> PathBuf {
    self.dot_sc.join("serve-tls")
}
```

2. `http_transport.rs` — the mode enum, config resolution, fingerprint helper:

```rust
/// How `sc serve --http` provides its TLS identity (P32). `Off` keeps the
/// P26 plaintext listener; `AutoMint` loads-or-mints `.sc/serve-tls/`;
/// `Pem` loads an operator-supplied pair (certbot etc.).
#[derive(Debug, Clone)]
pub enum TlsMode {
    Off,
    AutoMint,
    Pem {
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
    },
}

fn resolve_tls(root: &std::path::Path, tls: &TlsMode) -> Result<Option<scl_tlsio::TlsServerConfig>> {
    let identity = match tls {
        TlsMode::Off => return Ok(None),
        TlsMode::AutoMint => {
            scl_tlsio::load_or_mint(&crate::layout::Layout::at(root).serve_tls_dir())?
        }
        TlsMode::Pem { cert, key } => scl_tlsio::load_pem(cert, key)?,
    };
    Ok(Some(scl_tlsio::server_config(identity)?))
}

/// The repo's serve-TLS fingerprint (`sha256:<hex>`), minting the identity
/// if it doesn't exist yet — so an operator can distribute the pin BEFORE
/// first serve (`sc serve fingerprint`, P32). Same load-or-mint path the
/// server uses; no drift possible.
pub fn serve_tls_fingerprint(root: &std::path::Path) -> Result<String> {
    let id = scl_tlsio::load_or_mint(&crate::layout::Layout::at(root).serve_tls_dir())?;
    Ok(scl_tlsio::fingerprint_hex(&id.spki_sha256))
}
```

3. `serve_http`: new `tls: TlsMode` parameter. Resolve the config **before** the bind gate (Task 6 needs `tls_config.is_some()`); after the `listening on {bound}` println, add:

```rust
if let Some(cfg) = &tls_config {
    println!("tls fingerprint: {}", scl_tlsio::fingerprint_hex(&cfg.spki_sha256));
    std::io::Write::flush(&mut std::io::stdout()).ok();
}
```

Pass `bind_is_allowed(addr, root, read_only, allow_public)` unchanged in THIS task (Task 6 tightens it); pass `tls_config` down: `serve_http_listener(listener, root, read_only, mandatory_auth, limits, tls_config)`.

4. `serve_http_listener`: new `tls: Option<scl_tlsio::TlsServerConfig>` parameter. In the cap-shed arm, plaintext keeps its 503; TLS closes silently:

```rust
if limits.max_connections != 0 && prev >= limits.max_connections as usize {
    if tls.is_none() {
        let _ = write_status(&mut stream, 503);
    }
    // Under TLS: close without a status. Sending a readable 503 would
    // require a TLS handshake ON THE ACCEPT THREAD, letting one slow
    // client stall all accepts — the property P31 exists to protect.
    // (git-daemon sheds the same way: plain close.)
    continue; // g drops here → count restored
}
```

Clone `tls` into each connection thread (`let tls = tls.clone();` before `spawn`) and pass `tls.as_ref()` to `handle_http_connection`.

5. `handle_http_connection`: new `tls: Option<&scl_tlsio::TlsServerConfig>` parameter. Introduce the half enums (file-private) and rework the reader/writer construction; every subsequent `write_status(&mut stream, …)` becomes `write_status(&mut writer, …)` and the final `serve_with_policy(root, &mut reader, &mut writer, …)`:

```rust
/// Server-side maybe-TLS halves: the opening codec, status writes, and
/// `wire::serve` are all generic over Read/Write, so one enum layer at the
/// seam keeps plaintext and TLS on the identical code path after wrap.
enum SrvRead {
    Plain(TcpStream),
    Tls(scl_tlsio::TlsServerReadHalf),
}
enum SrvWrite {
    Plain(TcpStream),
    Tls(scl_tlsio::TlsServerWriteHalf),
}
impl Read for SrvRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            SrvRead::Plain(s) => s.read(buf),
            SrvRead::Tls(r) => r.read(buf),
        }
    }
}
impl Write for SrvWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            SrvWrite::Plain(s) => s.write(buf),
            SrvWrite::Tls(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SrvWrite::Plain(s) => s.flush(),
            SrvWrite::Tls(w) => w.flush(),
        }
    }
}
impl SrvRead {
    /// P31 session timeouts, below TLS when wrapped. SO_RCVTIMEO/SO_SNDTIMEO
    /// live on the socket (shared across `try_clone` fds), so setting them
    /// through either half governs the whole connection — the same fact the
    /// plaintext path has relied on since P31.
    fn set_session_timeouts(&self, d: Option<Duration>) -> std::io::Result<()> {
        match self {
            SrvRead::Plain(s) => {
                s.set_read_timeout(d)?;
                s.set_write_timeout(d)
            }
            SrvRead::Tls(r) => r.set_socket_timeouts(d, d),
        }
    }
}
```

Construction, replacing the current `try_clone` block (the opening timeout is set on the raw `TcpStream` FIRST, so it also bounds the TLS handshake — closing the handshake-slow-loris case for free):

```rust
stream
    .set_read_timeout(Some(OPENING_READ_TIMEOUT))
    .map_err(|e| Error::ConnectionLost(format!("sc+http set_read_timeout: {e}")))?;

let (mut reader, mut writer) = match tls {
    None => {
        let r = stream
            .try_clone()
            .map_err(|e| Error::ConnectionLost(format!("sc+http socket clone: {e}")))?;
        (BufReader::new(SrvRead::Plain(r)), SrvWrite::Plain(stream))
    }
    Some(cfg) => {
        let t = scl_tlsio::server_stream(cfg, stream)?;
        let (r, w) = t.split();
        (BufReader::new(SrvRead::Tls(r)), SrvWrite::Tls(w))
    }
};
```

The session-timeout block after the 200 becomes `reader.get_ref().set_session_timeouts(session).map_err(…)?;` (note: `stream` no longer exists at that point — the halves own it).

6. Update in-crate call sites: every existing test calling `serve_http_listener(…)` gains a trailing `None`; the CLI call site at `crates/cli/src/main.rs:3191` gains a trailing `scl_repo::http_transport::TlsMode::Off` (real wiring in Task 7).

- [ ] **Step 4: Run the workspace tests**

Run: `cargo test --workspace` — Expected: new tests PASS; all existing http tests still PASS (plaintext path is byte-identical).

- [ ] **Step 5: Commit**

```bash
cargo clippy --all-targets -- -D warnings
git add crates/repo crates/cli
git commit -m "feat(repo): TLS-wrapped sc serve --http (TlsMode, serve-tls identity, fingerprint helper)"
```

---

### Task 5: client seam — `sc+https://` URLs, TOFU connect flow, `open_transport` routing

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`ScHttpUrl`, `HttpTransport`)
- Modify: `crates/repo/src/stdio_transport.rs` (`open_transport`)

**Interfaces:**
- Consumes: Task 2's `client_connect` + client halves; Task 3's `TlsClientPolicy`/`lookup`/`record`; Task 4's `spawn_tls_server` test helper.
- Produces (used by Task 7 and every existing caller of `open_transport`):
  - `ScHttpUrl` gains `pub tls: bool`; `ScHttpUrl::parse` accepts `sc+http://` and `sc+https://` (same port default 8730)
  - `pub fn connect_with_pins(url: &ScHttpUrl, token: Option<&str>, policy: Option<&crate::tls_pins::TlsClientPolicy>) -> Result<HttpTransport>` — the testable core; `connect_with_token` resolves the policy from env for TLS URLs and delegates; `connect` is unchanged in signature
  - `HttpTransport` field becomes `WireClient<BufReader<HttpReadHalf>, HttpWriteHalf>` (private enums, `Plain`/`Tls`)

- [ ] **Step 1: Write the failing tests**

In `http_transport.rs` tests:

```rust
#[test]
fn parse_sc_https_sets_tls() {
    let u = ScHttpUrl::parse("sc+https://example.com:9443/srv/repo").unwrap();
    assert!(u.tls);
    assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("example.com", 9443, "/srv/repo"));
    let u = ScHttpUrl::parse("sc+https://host/repo").unwrap();
    assert_eq!(u.port, DEFAULT_PORT);
    let u = ScHttpUrl::parse("sc+http://host/repo").unwrap();
    assert!(!u.tls);
    // Plain https:// is a GIT url (P18), never sc-native.
    assert!(ScHttpUrl::parse("https://host/repo").is_err());
}

/// The full client TOFU lifecycle against a real TLS listener:
/// first connect pins, second is quiet, a swapped key hard-fails,
/// pre-pin never persists, strict refuses unknown.
#[test]
fn tofu_lifecycle_end_to_end() {
    let root = tmp_repo("tofu-e2e");
    let (addr, spki) = spawn_tls_server(&root);
    let (host, port) = addr.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap())).unwrap();
    let url = ScHttpUrl { host: host.clone(), port, path: "/".into(), tls: true };

    let pins_dir = std::env::temp_dir().join(format!("scl-tofu-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&pins_dir);
    let kh = pins_dir.join("known_hosts");
    let policy = crate::tls_pins::TlsClientPolicy { known_hosts: kh.clone(), pre_pin: None, strict: false };

    // 1. Unknown host, accept-new: connects AND records the pin.
    HttpTransport::connect_with_pins(&url, None, Some(&policy)).unwrap();
    assert_eq!(crate::tls_pins::lookup(&kh, &host, port).unwrap(), Some(spki));

    // 2. Second connect: pin already known, still connects.
    HttpTransport::connect_with_pins(&url, None, Some(&policy)).unwrap();

    // 3. Strict mode with a pin present: fine. Strict against an UNKNOWN
    //    host (fresh pin file): refused with the typed error.
    let strict_known = crate::tls_pins::TlsClientPolicy { known_hosts: kh.clone(), pre_pin: None, strict: true };
    HttpTransport::connect_with_pins(&url, None, Some(&strict_known)).unwrap();
    let fresh = pins_dir.join("fresh_kh");
    let strict_unknown = crate::tls_pins::TlsClientPolicy { known_hosts: fresh.clone(), pre_pin: None, strict: true };
    match HttpTransport::connect_with_pins(&url, None, Some(&strict_unknown)) {
        Err(Error::TlsStrictUnknownHost(_)) => {}
        other => panic!("expected TlsStrictUnknownHost, got {other:?}"),
    }
    assert!(!fresh.exists(), "strict refusal must not write a pin");

    // 4. Pre-pin (SC_HTTPS_FINGERPRINT semantics): connects, never persists.
    let prepin_file = pins_dir.join("prepin_kh");
    let prepin = crate::tls_pins::TlsClientPolicy { known_hosts: prepin_file.clone(), pre_pin: Some(spki), strict: true };
    HttpTransport::connect_with_pins(&url, None, Some(&prepin)).unwrap();
    assert!(!prepin_file.exists(), "pre-pin must not persist");

    // 5. A WRONG stored pin hard-fails with recovery context.
    let bad = pins_dir.join("bad_kh");
    crate::tls_pins::record(&bad, &host, port, &[0x24u8; 32]).unwrap();
    let badpol = crate::tls_pins::TlsClientPolicy { known_hosts: bad.clone(), pre_pin: None, strict: false };
    match HttpTransport::connect_with_pins(&url, None, Some(&badpol)) {
        Err(Error::TlsPinMismatch { host: h, file, pinned, seen }) => {
            assert!(h.contains(&host));
            assert!(file.contains("bad_kh"));
            assert!(pinned.starts_with("sha256:") && seen.starts_with("sha256:"));
            assert_eq!(seen, scl_tlsio::fingerprint_hex(&spki));
        }
        other => panic!("expected TlsPinMismatch, got {other:?}"),
    }

    std::fs::remove_dir_all(&pins_dir).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}

/// Transport verbs work over TLS end to end (list_refs against the real
/// server — the full clone/push/fetch acceptance rides the CLI test in
/// Task 7).
#[test]
fn transport_verbs_over_tls() {
    let root = tmp_repo("tls-verbs");
    let (addr, spki) = spawn_tls_server(&root);
    let (host, port) = addr.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap())).unwrap();
    let url = ScHttpUrl { host, port, path: "/".into(), tls: true };
    let policy = crate::tls_pins::TlsClientPolicy {
        known_hosts: std::env::temp_dir().join(format!("scl-verbs-kh-{}", std::process::id())),
        pre_pin: Some(spki),
        strict: false,
    };
    let t = HttpTransport::connect_with_pins(&url, None, Some(&policy)).unwrap();
    let refs = t.list_refs().unwrap();
    assert!(!refs.is_empty(), "fresh repo has at least its default branch tip or HEAD");
    let _ = std::fs::remove_file(&policy.known_hosts);
    std::fs::remove_dir_all(&root).unwrap();
}
```

(If a fresh `tmp_repo` has no commits and `list_refs` is legitimately empty, assert on `head_branch()` instead — mirror whatever the existing plaintext `real_server_*` test asserts right after connect.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo http_transport` — Expected: COMPILE FAIL (`tls` field, `connect_with_pins` missing).

- [ ] **Step 3: Implement the client seam**

1. `ScHttpUrl`: add `pub tls: bool`; parse both schemes:

```rust
let (rest, tls) = if let Some(r) = url.strip_prefix("sc+http://") {
    (r, false)
} else if let Some(r) = url.strip_prefix("sc+https://") {
    (r, true)
} else {
    return Err(Error::InvalidArgument(format!(
        "not an sc+http(s):// url: {url}"
    )));
};
```

(and `tls` in the constructed struct; update the existing struct-literal test fixtures.)

2. Client half enums (file-private, beside `SrvRead`/`SrvWrite`):

```rust
enum HttpReadHalf {
    Plain(TcpStream),
    Tls(scl_tlsio::TlsClientReadHalf),
}
enum HttpWriteHalf {
    Plain(TcpStream),
    Tls(scl_tlsio::TlsClientWriteHalf),
}
// impl Read for HttpReadHalf / impl Write for HttpWriteHalf: identical
// match-forwarding shape as SrvRead/SrvWrite above.
```

`HttpTransport` becomes `client: WireClient<BufReader<HttpReadHalf>, HttpWriteHalf>`.

3. `connect_with_token` / `connect_with_pins`:

```rust
pub fn connect_with_token(url: &ScHttpUrl, token: Option<&str>) -> Result<HttpTransport> {
    let policy = if url.tls {
        Some(crate::tls_pins::TlsClientPolicy::from_env()?)
    } else {
        None
    };
    Self::connect_with_pins(url, token, policy.as_ref())
}

/// The testable core: env-free. `policy` must be `Some` iff `url.tls` —
/// the pin policy IS the TLS client decision.
pub fn connect_with_pins(
    url: &ScHttpUrl,
    token: Option<&str>,
    policy: Option<&crate::tls_pins::TlsClientPolicy>,
) -> Result<HttpTransport> {
    if let Some(t) = token {
        if t.contains(['\r', '\n']) {
            return Err(Error::InvalidArgument(
                "SC_HTTP_TOKEN must not contain CR or LF".to_string(),
            ));
        }
    }
    let stream = TcpStream::connect(url.authority())
        .map_err(|e| Error::ConnectionLost(format!("sc+http connect to {url:?}: {e}")))?;

    let (mut r, mut w) = match (url.tls, policy) {
        (false, _) => {
            let rd = stream
                .try_clone()
                .map_err(|e| Error::ConnectionLost(format!("sc+http socket clone: {e}")))?;
            (
                BufReader::new(HttpReadHalf::Plain(rd)),
                HttpWriteHalf::Plain(stream),
            )
        }
        (true, Some(p)) => {
            let expected = match p.pre_pin {
                Some(pin) => Some(pin),
                None => crate::tls_pins::lookup(&p.known_hosts, &url.host, url.port)?,
            };
            let known_before = expected.is_some();
            let pin_source = if p.pre_pin.is_some() {
                "SC_HTTPS_FINGERPRINT".to_string()
            } else {
                p.known_hosts.display().to_string()
            };
            match scl_tlsio::client_connect(stream, &url.host, expected, p.strict) {
                Ok((tls_stream, seen)) => {
                    if !known_before {
                        // Accept-new TOFU: pin silently, ANNOUNCE loudly.
                        crate::tls_pins::record(&p.known_hosts, &url.host, url.port, &seen)?;
                        eprintln!(
                            "sc+https: first connection to {}:{} — pinned {}",
                            url.host,
                            url.port,
                            scl_tlsio::fingerprint_hex(&seen)
                        );
                        eprintln!(
                            "sc+https: verify against `sc serve fingerprint` on the server; \
                             stored in {}",
                            p.known_hosts.display()
                        );
                    }
                    let (rh, wh) = tls_stream.split();
                    (
                        BufReader::new(HttpReadHalf::Tls(rh)),
                        HttpWriteHalf::Tls(wh),
                    )
                }
                Err(scl_tlsio::Error::PinMismatch { expected, seen }) => {
                    return Err(Error::TlsPinMismatch {
                        host: url.authority(),
                        file: pin_source,
                        pinned: scl_tlsio::fingerprint_hex(&expected),
                        seen: scl_tlsio::fingerprint_hex(&seen),
                    })
                }
                Err(scl_tlsio::Error::UnknownHostStrict) => {
                    return Err(Error::TlsStrictUnknownHost(url.authority()))
                }
                Err(e) => return Err(e.into()),
            }
        }
        (true, None) => {
            return Err(Error::InvalidArgument(
                "internal: sc+https connect without a pin policy".to_string(),
            ))
        }
    };

    write_client_opening(&mut w, &url.host, &url.path, token)?;
    use std::io::Write as _;
    w.flush()
        .map_err(|e| Error::ConnectionLost(format!("sc+http opening flush: {e}")))?;

    let status = read_status(&mut r)?;
    // …status match unchanged from today…
    let client = WireClient::handshake(r, w)?;
    Ok(HttpTransport { client })
}
```

(The status-mapping match moves verbatim; keep the doc comments. Note the opening is written AFTER pin disposition — the global constraint.)

4. `open_transport` in `stdio_transport.rs`:

```rust
} else if url.starts_with("sc+http://") || url.starts_with("sc+https://") {
    let parsed = crate::http_transport::ScHttpUrl::parse(url)?;
    Ok(Box::new(crate::http_transport::HttpTransport::connect(&parsed)?))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-repo` — Expected: all PASS (new + existing plaintext http tests).

- [ ] **Step 5: Commit**

```bash
cargo clippy --all-targets -- -D warnings
git add crates/repo
git commit -m "feat(repo): sc+https:// client — TOFU pin flow at the connect seam, open_transport routing"
```

---

### Task 6: P29 gate tightening — plaintext public binds need `--allow-public`

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`bind_is_allowed`, `serve_http`'s refusal message, existing gate tests)

**Interfaces:**
- Consumes: Task 4's `TlsMode`/`resolve_tls` (already resolved before the gate).
- Produces: `fn bind_is_allowed(addr, root, read_only, allow_public, tls: bool) -> Result<bool>` — the decided lattice: loopback always; else `--read-only` or `--allow-public`; else tokens justify **only with TLS**.

- [ ] **Step 1: Write/flip the failing tests**

In the existing `bind_refuses_public_without_justification` test (http_transport.rs:1204) and around it, update to the new lattice (adding the `tls` argument to every existing `bind_is_allowed` call — existing plaintext cases pass `false`):

```rust
#[test]
fn gate_lattice_p32() {
    let root = tmp_repo("gate32");
    let no_tls = false;
    let tls = true;

    // Loopback: always, TLS or not, tokens or not.
    assert!(bind_is_allowed("127.0.0.1:1", &root, false, false, no_tls).unwrap());
    assert!(bind_is_allowed("127.0.0.1:1", &root, false, false, tls).unwrap());

    // Non-loopback, nothing configured: refused either way.
    assert!(!bind_is_allowed("0.0.0.0:1", &root, false, false, no_tls).unwrap());
    assert!(!bind_is_allowed("0.0.0.0:1", &root, false, false, tls).unwrap());

    // --read-only / --allow-public: justify on their own, unchanged.
    assert!(bind_is_allowed("0.0.0.0:1", &root, true, false, no_tls).unwrap());
    assert!(bind_is_allowed("0.0.0.0:1", &root, false, true, no_tls).unwrap());

    // Configure a token…
    add_test_token(&root); // reuse/extract the helper the P29 tests use to write .sc/serve-tokens.toml

    // …tokens + TLS: the blessed public posture.
    assert!(bind_is_allowed("0.0.0.0:1", &root, false, false, tls).unwrap());
    // …tokens WITHOUT TLS: no longer justifies (the P32 break, decision 5).
    assert!(!bind_is_allowed("0.0.0.0:1", &root, false, false, no_tls).unwrap());

    std::fs::remove_dir_all(&root).unwrap();
}
```

(Look at how the existing P29 gate tests configure a token — `serve_tokens::add`/direct file write — and reuse that exact mechanism as `add_test_token`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo gate` — Expected: COMPILE FAIL (arity), then after mechanical arity fixes the P32 assertions FAIL against the old logic.

- [ ] **Step 3: Implement the tightened gate**

```rust
/// The fail-closed bind decision (P29, tightened by P32/ADR-0042): a
/// non-loopback `addr` is allowed only if justified by `--read-only`,
/// `--allow-public`, or — once TLS is available — `--tls` plus ≥1 configured
/// serve token. A PLAINTEXT public bind justified only by tokens (the P29
/// rule) is refused: the token would cross the wire in the clear, which is
/// the exact exposure this phase closes. Deliberate, narrow pre-1.0 break.
fn bind_is_allowed(
    addr: &str,
    root: &std::path::Path,
    read_only: bool,
    allow_public: bool,
    tls: bool,
) -> Result<bool> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if is_loopback_host(host) {
        return Ok(true);
    }
    if read_only || allow_public {
        return Ok(true);
    }
    if !tls {
        return Ok(false);
    }
    let tokens_configured =
        !crate::serve_tokens::load(&crate::layout::Layout::at(root))?.is_empty();
    Ok(tokens_configured)
}
```

In `serve_http`, call it with `tls_config.is_some()` and update the refusal message:

```rust
return Err(Error::InvalidArgument(format!(
    "refusing to bind non-loopback address {addr}: use --tls with a configured serve \
     token (sc serve token add), or --read-only, or --allow-public; a plaintext public \
     bind would send bearer tokens and repo traffic in the clear (use 127.0.0.1 for \
     local-only serving)"
)));
```

`auth_is_mandatory` is UNCHANGED: on a TLS+tokens-justified public bind it already returns true (non-loopback, not ro, not allow-public), preserving the P29 fail-closed 401 when the last token is removed at runtime. Add one line to its doc comment noting the P32 case rides the same rule.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --workspace` — Expected: PASS. Check specifically that P29's `auth_is_mandatory` tests and the existing bind tests (now arity-updated) are green.

- [ ] **Step 5: Commit**

```bash
cargo clippy --all-targets -- -D warnings
git add crates/repo
git commit -m "feat(repo)!: plaintext non-loopback binds now require --allow-public; tokens justify only with --tls (P32 gate)"
```

---

### Task 7: CLI — `--tls/--tls-cert/--tls-key`, `sc serve fingerprint`, acceptance test

**Files:**
- Modify: `crates/cli/src/main.rs` (Serve command ~line 275–320, `ServeSub` ~line 639, `run_serve` ~line 3140)
- Create: `crates/cli/tests/https_remote.rs`

**Interfaces:**
- Consumes: Task 4's `TlsMode`, `serve_tls_fingerprint`; Task 6's gate; Task 5's client (via `sc clone/push/fetch` on `sc+https://` URLs through `open_transport`).
- Produces: user surface — `sc serve --http <addr> --tls [--tls-cert <pem> --tls-key <pem>] <path>`, `sc serve fingerprint [<path>]`.

- [ ] **Step 1: Write the failing CLI tests**

`crates/cli/tests/https_remote.rs` (copy the `sc`/`tmp`/`spawn_http_server` helpers from `crates/cli/tests/http_remote.rs` verbatim — subprocess tests can't share them across files; extend `spawn_http_server` to also return the fingerprint line when `--tls` is among `extra`, reading stdout line 2 `tls fingerprint: sha256:<hex>`):

```rust
//! CLI acceptance for sc+https:// (P32): flag validation, `sc serve
//! fingerprint`, and the spec's round-trip criterion — clone + push + fetch
//! over TLS with a signed ~1 MiB blob under forced SC_PACK_CHUNK,
//! byte-for-byte, zero .sc/tmp residue. Env knobs (SC_HTTPS_*) are safe here
//! because every command is a SUBPROCESS with its own env (Command::env),
//! not a racy in-process set_var.

// …helpers as described…

#[test]
fn tls_flags_validated() {
    let root = tmp("flags");
    assert!(sc(&root, &["init"]).status.success());
    // --tls-cert without --tls
    let out = sc(&root, &["serve", "--http", "127.0.0.1:0", "--tls-cert", "x.pem", root.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--tls"));
    // --tls with --stdio
    let out = sc(&root, &["serve", "--stdio", "--tls", root.to_str().unwrap()]);
    assert!(!out.status.success());
    // --tls-cert without --tls-key
    let out = sc(&root, &["serve", "--http", "127.0.0.1:0", "--tls", "--tls-cert", "x.pem", root.to_str().unwrap()]);
    assert!(!out.status.success());
}

#[test]
fn serve_fingerprint_mints_and_matches_banner() {
    let root = tmp("fpr");
    assert!(sc(&root, &["init"]).status.success());
    let out = sc(&root, &["serve", "fingerprint", root.to_str().unwrap()]);
    assert!(out.status.success());
    let fpr = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(fpr.starts_with("sha256:"));
    // The identity persisted; a TLS serve now banners the SAME fingerprint.
    let (mut child, _addr, banner_fpr) = spawn_tls_http_server(&root, &[]);
    assert_eq!(banner_fpr, fpr);
    child.kill().ok();
}

#[test]
fn https_clone_push_fetch_round_trip_with_signed_chunked_blob() {
    let w = tmp("rt");
    let origin = w.join("origin");
    std::fs::create_dir_all(&origin).unwrap();
    assert!(sc(&origin, &["init"]).status.success());

    // Identity OUTSIDE the working tree (P5 scanner flags scl-id files).
    let keyout = sc(&w, &["keygen"]); // writes into cwd = w, not the repo
    assert!(keyout.status.success());
    let identity = /* parse the emitted path/name from keygen stdout, as provenance.rs does */;

    // ~1 MiB deterministic blob + a signed commit.
    let blob: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(origin.join("big.bin"), &blob).unwrap();
    assert!(sc(&origin, &["commit", "-m", "big", "--sign", "--identity", &identity]).status.success());

    // rw token; capture the raw value from stdout (auth demo pattern).
    let tok_out = sc(&origin, &["serve", "token", "add", "--label", "ci", "--scope", "rw"]);
    assert!(tok_out.status.success());
    let token = String::from_utf8_lossy(&tok_out.stdout).trim().to_string();

    let (mut child, addr, _fpr) = spawn_tls_http_server(&origin, &[]);
    let url = format!("sc+https://{addr}/");
    let kh = w.join("known_hosts");

    // Clone with forced tiny chunks; env is per-subprocess, race-free.
    let clone_dir = w.join("clone");
    let out = sc_env(&w, &["clone", &url, clone_dir.to_str().unwrap()], &[
        ("SC_HTTP_TOKEN", &token),
        ("SC_HTTPS_KNOWN_HOSTS", kh.to_str().unwrap()),
        ("SC_PACK_CHUNK", "4096"),
    ]);
    assert!(out.status.success(), "clone failed: {}", String::from_utf8_lossy(&out.stderr));
    // First-connect TOFU announced + pinned.
    assert!(String::from_utf8_lossy(&out.stderr).contains("pinned"));
    assert!(kh.exists());
    // Byte-for-byte.
    assert_eq!(std::fs::read(clone_dir.join("big.bin")).unwrap(), blob);
    // Signature rode the chunked TLS stream.
    let log = sc(&clone_dir, &["log"]);
    assert!(String::from_utf8_lossy(&log.stdout).contains("signed:"));

    // Push an edit back over TLS (second connect: pin known → NO "pinned").
    std::fs::write(clone_dir.join("new.txt"), "from clone").unwrap();
    assert!(sc(&clone_dir, &["commit", "-m", "edit"]).status.success());
    let out = sc_env(&clone_dir, &["push", "origin"], &[
        ("SC_HTTP_TOKEN", &token),
        ("SC_HTTPS_KNOWN_HOSTS", kh.to_str().unwrap()),
    ]);
    assert!(out.status.success(), "push failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("pinned"), "second connect must be quiet");

    // Fetch from a second clone sees the edit.
    let clone2 = w.join("clone2");
    assert!(sc_env(&w, &["clone", &url, clone2.to_str().unwrap()], &[
        ("SC_HTTP_TOKEN", &token),
        ("SC_HTTPS_KNOWN_HOSTS", kh.to_str().unwrap()),
    ]).status.success());
    assert_eq!(std::fs::read_to_string(clone2.join("new.txt")).unwrap(), "from clone");

    // Zero .sc/tmp residue on every end.
    for repo in [&origin, &clone_dir, &clone2] {
        let tmp_dir = repo.join(".sc").join("tmp");
        let empty = !tmp_dir.exists()
            || std::fs::read_dir(&tmp_dir).unwrap().next().is_none();
        assert!(empty, ".sc/tmp residue in {}", repo.display());
    }

    // Key swap → pin mismatch hard-fails.
    child.kill().ok();
    child.wait().ok();
    std::fs::remove_dir_all(origin.join(".sc").join("serve-tls")).unwrap();
    let (mut child2, addr2, _f) = spawn_tls_http_server(&origin, &[]);
    let url2 = format!("sc+https://{addr2}/");
    let clone3 = w.join("clone3");
    // Re-pin the OLD server's fingerprint under the NEW address first, so
    // the lookup hits: copy the kh line for addr → addr2. Simplest: write a
    // kh containing addr2 mapped to the OLD fingerprint captured earlier.
    let out = sc_env(&w, &["clone", &url2, clone3.to_str().unwrap()], &[
        ("SC_HTTP_TOKEN", &token),
        ("SC_HTTPS_KNOWN_HOSTS", mismatch_kh(&w, &addr2, /*old fpr*/).to_str().unwrap()),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not match the pinned fingerprint"), "got: {err}");
    child2.kill().ok();
}
```

Fill in `sc_env` (a `sc()` variant taking `envs: &[(&str, &str)]`), `spawn_tls_http_server` (spawn with `--tls`, parse stdout lines 1–2), `mismatch_kh` (write a kh file mapping `addr2`'s host:port to the first server's fingerprint), and the keygen-output parsing by copying whatever `crates/cli/tests/provenance.rs` does for identities — mirror, don't invent. The tightened-gate CLI behavior (public plaintext bind refused) is already unit-tested in Task 6 and demo-proven in Task 8; a CLI duplicate would need a real non-loopback bind, which CI can't do reliably.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-cli --test https_remote` — Expected: FAIL (`--tls` unknown flag; `fingerprint` unknown subcommand).

- [ ] **Step 3: Implement the CLI wiring**

1. `Serve` command variant — add after `allow_public`:

```rust
/// Serve TLS (`sc+https://`): auto-mints a self-signed identity into
/// `.sc/serve-tls/` unless --tls-cert/--tls-key supply a PEM pair.
/// `--http` only. (P32)
#[arg(long)]
tls: bool,
/// PEM certificate chain for --tls (requires --tls-key).
#[arg(long, requires = "tls_key", requires = "tls")]
tls_cert: Option<PathBuf>,
/// PEM private key for --tls (requires --tls-cert).
#[arg(long, requires = "tls_cert", requires = "tls")]
tls_key: Option<PathBuf>,
```

(Check the exact clap `requires` key names against the generated field names; if `requires = "tls"` misbehaves with `bool`, do the validation in `run_serve` instead — the tests assert behavior, not mechanism.)

2. `ServeSub` — add:

```rust
/// Print this repo's serve-TLS fingerprint (sha256:<hex> of the SPKI),
/// minting `.sc/serve-tls/` if absent — distribute this to clients as
/// SC_HTTPS_FINGERPRINT or to verify a first-connect pin. (P32)
Fingerprint { path: Option<PathBuf> },
```

with a match arm where `ServeSub::Token` is handled:

```rust
ServeSub::Fingerprint { path } => {
    let root = match path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };
    println!("{}", scl_repo::http_transport::serve_tls_fingerprint(&root)?);
    Ok(())
}
```

3. `run_serve` — thread the three new params; in the `(true, None)` stdio arm add:

```rust
if tls || tls_cert.is_some() || tls_key.is_some() {
    anyhow::bail!("--tls applies only to --http (ssh already provides --stdio's confidential channel)");
}
```

in the `(false, Some(addr))` arm build the mode:

```rust
let tls_mode = match (tls, tls_cert, tls_key) {
    (false, None, None) => scl_repo::http_transport::TlsMode::Off,
    (false, _, _) => anyhow::bail!("--tls-cert/--tls-key require --tls"),
    (true, None, None) => scl_repo::http_transport::TlsMode::AutoMint,
    (true, Some(cert), Some(key)) => scl_repo::http_transport::TlsMode::Pem { cert, key },
    (true, _, _) => anyhow::bail!("--tls-cert and --tls-key must be given together"),
};
scl_repo::http_transport::serve_http(&addr, &path, read_only, allow_public, limits, tls_mode)?;
```

(remove Task 4's temporary `TlsMode::Off` literal.)

4. Clone routing sanity: `sc+https://` must NOT be caught by the P18 hosted-git URL detection (`https://` prefix check). Verify with `grep -n '"https://"' crates/cli/src/main.rs` that the detection uses `starts_with("https://")` (which `sc+https://…` does not match). If any check is looser, tighten it and pin with a small routing unit test.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-cli` then `cargo test --workspace` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo clippy --all-targets -- -D warnings
git add crates/cli
git commit -m "feat(cli): sc serve --tls / --tls-cert / --tls-key + sc serve fingerprint; sc+https acceptance test"
```

---

### Task 8: demo — `demo/run_tls_demo.sh`

**Files:**
- Create: `demo/run_tls_demo.sh` (executable)

**Interfaces:**
- Consumes: the full CLI surface from Task 7.
- Produces: the phase's demoable proof, `run_http_auth_demo.sh` pattern (self-checking assertions, `fail()`, trap cleanup, port picking with `nc -z`, run-twice at the end).

- [ ] **Step 1: Write the script**

Follow `demo/run_http_auth_demo.sh`'s skeleton exactly (shebang, `set -euo pipefail`, `cd "$(dirname "$0")/.."`, `cargo build --quiet --bin sc`, `fail()`, `mktemp -d`, `cleanup` trap killing server PIDs, `pick_port`, `wait_for_port`). Content, in order — every claim an assertion:

1. **Setup:** init `$W/origin`; keygen into `$W` (identity outside the tree); write a ~1 MiB blob (`head -c 1048576 /dev/zero | tr '\0' 'x'` is fine — determinism matters, entropy doesn't); `sc commit --sign --identity`; `sc serve token add --label demo --scope rw` capturing the raw token.
2. **Fingerprint before first serve:** `FPR=$("$SC" serve fingerprint "$W/origin")`; assert `sha256:` prefix; assert `.sc/serve-tls/key.pem` exists with `stat` mode 600.
3. **TLS round trip:** start `sc serve --http 127.0.0.1:$PORT --tls "$W/origin"` in the background; assert its stdout banner contains `tls fingerprint: $FPR`. Clone with `SC_HTTP_TOKEN=$TOKEN SC_HTTPS_KNOWN_HOSTS=$W/kh SC_PACK_CHUNK=4096 sc clone "sc+https://127.0.0.1:$PORT/" "$W/clone"` — assert stderr contains `pinned` AND the fingerprint equals `$FPR` (grep); `cmp` the blob byte-for-byte; `sc log` in the clone contains `signed:`.
4. **Quiet second connect + push/fetch:** commit an edit in the clone, `sc push origin` (same env, no `SC_PACK_CHUNK` needed) — assert stderr does NOT contain `pinned`; second clone sees the edit.
5. **Strict + pre-pin:** `SC_HTTPS_STRICT=1` with a FRESH known_hosts file → clone fails, stderr mentions `SC_HTTPS_STRICT`; adding `SC_HTTPS_FINGERPRINT=$FPR` (still fresh kh) → succeeds AND the fresh kh file was never created.
6. **Mismatch hard-fail:** stop the server; `rm -rf "$W/origin/.sc/serve-tls"`; restart (new key, new fingerprint — assert banner fingerprint differs from `$FPR`); clone with the OLD `$W/kh` → fails, stderr contains `does not match the pinned fingerprint`; assert it names the kh path.
7. **Tightened plaintext gate:** `sc serve --http 0.0.0.0:$PORT2 "$W/origin"` (tokens configured, NO `--tls`) → must exit non-zero, stderr names `--tls`; `sc serve --http 0.0.0.0:$PORT2 --tls "$W/origin"` → binds (assert `listening on`, then kill). (`run_http_auth_demo.sh` already binds `0.0.0.0` for its gate proof — reuse that pattern.)
8. **Zero residue:** assert `.sc/tmp` empty/absent in origin and both clones; assert `$W` cleanup via trap.
9. **Run twice:** the auth demo's pattern — the whole body in a function invoked twice with fresh temp dirs, `echo "RESULT: ok"` at the end.

- [ ] **Step 2: Run it**

Run: `bash demo/run_tls_demo.sh` — Expected: `RESULT: ok` (twice), exit 0. Fix any assertion drift (exact stderr phrasing) by adjusting the demo's greps to the real messages — the messages are the source of truth, they were pinned by tests in Tasks 5–7.

- [ ] **Step 3: Commit**

```bash
chmod +x demo/run_tls_demo.sh
git add demo/run_tls_demo.sh
git commit -m "demo: sc+https TLS round trip, TOFU lifecycle, tightened plaintext gate (run twice)"
```

---

### Task 9: docs — ADR-0042, CLAUDE.md, THREAT-MODEL, ROADMAP, spec amendment

**Files:**
- Create: `docs/adr/0042-in-binary-tls-sc-https.md`
- Modify: `CLAUDE.md` (commands block, dependency rule, quarantine list, P32 section)
- Modify: `docs/THREAT-MODEL.md` (transport section)
- Modify: `ROADMAP.md` (move the TLS deferral to shipped; record follow-ons)
- Modify: `docs/superpowers/specs/2026-07-10-p32-tls-sc-https-design.md` (busy-shed deviation)

- [ ] **Step 1: Write ADR-0042**

Follow the house ADR format (look at `docs/adr/0041-listener-resource-limits.md` for the exact header/section shape). Required content, all decided — write it as prose in the house style:

- **Context:** audit High #1; ADR-0036/0040 boundaries ("no TLS", reverse proxy guidance incomplete — server leg only); research doc `docs/research/tls-options-sc-http.md`; decide tickets #26/#35.
- **Decision — why in-binary TLS is load-bearing here:** Vaultwarden/Garage punt to reverse proxies because they are server-only; sc's CLIENT must reach servers its operator doesn't control, so a proxy can never cover the client leg — the case where in-binary TLS is genuinely load-bearing.
- **Provider:** rustls 0.23, ring provider (`default-features = false`; ~14 new crates measured; C compiler only, no cmake); **aws-lc-rs is the recorded swap-in fallback** (18 crates + cmake); pure-Rust providers rejected as immature (graviola, rustls-rustcrypto).
- **Quarantine:** `crates/tlsio`, the only crate linking rustls/rcgen/ring/pki-types; dependency leaf; `repo → tlsio`; SHA-256 via `ring::digest` (NOT RustCrypto — that quarantine holds).
- **Trust model:** accept-new TOFU; pin = SPKI-SHA-256 (survives same-key renewal, openssl-verifiable); pin-only in v1 — names/validity deliberately ignored; handshake signatures still verified; mismatch always hard-fails, never prompts; `SC_HTTPS_FINGERPRINT` pre-pin; `SC_HTTPS_STRICT`; `~/.config/sc/known_hosts` (`SC_HTTPS_KNOWN_HOSTS` override). First connection remains vulnerable by construction (the SSH known_hosts trade, stated plainly).
- **Server lifecycle:** explicit `--tls`; rcgen auto-mint into `.sc/serve-tls/` (key 0600, key-is-identity, long validity); PEM path; `sc serve fingerprint` mints-if-missing; ACME rejected (async stack — certbot/proxies instead).
- **Gate change (breaking):** the P32 lattice; tokens alone no longer justify plaintext public binds.
- **Accepted consequences:** (1) under TLS the `--max-connections` shed closes without a 503 — a readable busy status would require a handshake on the accept thread (deviation from the phase spec's first draft, deliberate); (2) first TLS dep means tracking the rustls 0.23→0.24 API break; (3) CA-path validation deferred (additive later for PEM deployments); (4) the plaintext-gate break is pre-1.0 and narrow.

- [ ] **Step 2: Update CLAUDE.md**

1. Workspace layout block: add `crates/tlsio → TLS for sc+https (depends on nothing; ONLY crate linking rustls/rcgen)` and extend the dependency-rule sentence: `repo` also depends on `tlsio`; **rustls/rcgen must stay quarantined in `tlsio`**.
2. Commands block, after the P31 serve entries:

```
cargo run --bin sc -- serve --http <addr> <path> --tls [--tls-cert <pem> --tls-key <pem>]
                                              # TLS listener (P32): sc+https://; auto-mints a
                                              # self-signed identity into .sc/serve-tls/ (key
                                              # 0600, key-is-identity) unless PEM given; banner
                                              # prints the SPKI fingerprint; NB gate change:
                                              # tokens justify a non-loopback bind ONLY with
                                              # --tls now — plaintext public needs
                                              # --allow-public (or --read-only)
cargo run --bin sc -- serve fingerprint [<path>]   # print (minting if absent) the serve-TLS
                                              # SPKI fingerprint (sha256:<hex>)
cargo run --bin sc -- clone sc+https://host[:port]/repo <dst>   # TLS clone (P32); accept-new
                                              # TOFU: first connect pins into
                                              # ~/.config/sc/known_hosts (SC_HTTPS_KNOWN_HOSTS
                                              # overrides), mismatch always hard-fails;
                                              # SC_HTTPS_FINGERPRINT=<sha256:hex> pre-pins (CI),
                                              # SC_HTTPS_STRICT=1 refuses unknown hosts;
                                              # remote add/fetch/push accept the same URL form
bash demo/run_tls_demo.sh                     # sc+https proof (P32): TLS round trip w/ signed
                                              # chunked blob, TOFU pin/mismatch/strict/pre-pin,
                                              # tightened plaintext gate — run twice
```

3. Add a `**Phase 32 is built.**` section in the phase history (match the established voice/density: seams touched, the gate break, the busy-shed accepted consequence, boundaries — no CA validation, first-connect trust, plaintext token on loopback-no-token setups unchanged) and update the P26/P29 sections' forward references ("no TLS … deferred" → "closed by P32 (ADR-0042)").
4. Remaining follow-ons list: add CA-path validation, `sc+https` SNI/name validation as an opt-in, TLS session resumption knobs (if rejected, say rejected), pin management UX (`sc tls` list/remove pins).

- [ ] **Step 3: Update docs/THREAT-MODEL.md, ROADMAP.md, and the spec**

- THREAT-MODEL transport section: rewrite around `sc+https://` — bearer tokens and traffic are confidential on TLS transports (`sc+https://`, `ssh://`); the plaintext `sc+http://` boundary statement now applies only to loopback/`--allow-public` deployments; TOFU first-connect exposure stated plainly; reverse-proxy guidance must document **both legs** (server-side TCP-mode termination — nginx `stream` / HAProxy `mode tcp` / stunnel — AND the client-side tunnel: client-mode stunnel or `ssh -L` — OR just use `sc+https://`/`ssh://` now that they exist); promote `ssh://` (ADR-0022) as the long-shipped confidential transport. Pull the both-legs specifics from `docs/research/tls-options-sc-http.md` §B (already written and cited there).
- ROADMAP.md: the "first-party TLS dependency deferred" line moves to shipped-in-P32; add the follow-ons from Step 2.4.
- Spec amendment (`docs/superpowers/specs/2026-07-10-p32-tls-sc-https-design.md` §3): replace the busy-shed sentence with the Task 4 decision (TLS shed = silent close; rationale: no handshake on the accept thread).

- [ ] **Step 4: Full workspace check + all demos**

```bash
cargo test --workspace
cargo clippy --all-targets -- -D warnings
bash demo/run_http_auth_demo.sh   # P29 demo must still pass (loopback binds unchanged;
                                  # check its 0.0.0.0 token-only case — if it asserted the
                                  # OLD gate (tokens justify plaintext public), update that
                                  # demo to expect the P32 refusal and add --tls)
bash demo/run_http_remote_demo.sh
bash demo/run_tls_demo.sh
```

Expected: all green. The `run_http_auth_demo.sh` note is real work: P29's demo proves a token-justified public bind — under the P32 gate that exact case now refuses. Update that demo's assertion to the new behavior (refusal + `--tls` hint) as part of this task.

- [ ] **Step 5: Commit**

```bash
git add docs CLAUDE.md ROADMAP.md demo
git commit -m "docs: ADR-0042 (in-binary TLS), CLAUDE.md P32, THREAT-MODEL transport rewrite, roadmap"
```

---

## Self-Review (performed while writing)

- **Spec coverage:** crate+quarantine (T1–2), TOFU/pins/env knobs (T2–3, 5), server lifecycle+fingerprint (T4, 7), gate (T6), CLI (T7), acceptance tests incl. signed chunked blob + residue (T5, 7), demo (T8), ADR/CLAUDE/THREAT-MODEL/both-legs docs (T9). One deliberate deviation (TLS busy-shed closes silently) is flagged in T4 and folded back into the spec in T9.
- **Type consistency:** `TlsServerConfig`/`server_config(ServerIdentity)`/`client_connect(tcp, host, Option<[u8;32]>, bool) -> (TlsClientStream, [u8;32])`/`connect_with_pins(url, token, Option<&TlsClientPolicy>)`/`serve_http(..., TlsMode)`/`serve_http_listener(..., Option<TlsServerConfig>)`/`bind_is_allowed(..., tls: bool)` are used identically across tasks.
- **Known API risk:** exact rustls-0.23 builder / rcgen-0.14 method names may drift at the resolved patch version; Tasks 1–2 carry explicit "check `cargo doc`, keep public tlsio signatures fixed" notes at the two spots where that can bite.
