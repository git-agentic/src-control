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

/// Build a reusable server TLS config from a minted/loaded identity.
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

/// A completed server-side TLS connection wrapping a `TcpStream`.
pub struct TlsServerStream {
    inner: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
}

/// A completed client-side TLS connection wrapping a `TcpStream`.
pub struct TlsClientStream {
    inner: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

impl std::fmt::Debug for TlsClientStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClientStream").finish_non_exhaustive()
    }
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
        /// TLS read half, sharing the underlying connection with its write
        /// half via `Arc<Mutex<…>>` (safe under sc's strict
        /// request-reply-sequential wire discipline — see the module docs).
        pub struct $read(Arc<Mutex<$stream>>);
        /// TLS write half; see the read half's doc comment for the sharing
        /// model.
        pub struct $write(Arc<Mutex<$stream>>);

        impl $stream {
            /// Split into independent read/write halves that can move to
            /// separate threads (both are `Send`).
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

// Compile-time proof that every half can cross a thread boundary — the sc
// wire server (Task 4/5) spawns a thread per connection and hands one half
// to each side's I/O loop.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<TlsClientReadHalf>();
    assert_send::<TlsClientWriteHalf>();
    assert_send::<TlsServerReadHalf>();
    assert_send::<TlsServerWriteHalf>();
};

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
        assert!(!dir.exists());
    }

    #[test]
    fn matching_pin_connects() {
        let dir = tmp("pinok");
        let (addr, h, spki) = echo_server(&dir);
        let tcp = TcpStream::connect(&addr).unwrap();
        assert!(client_connect(tcp, "127.0.0.1", Some(spki), false).is_ok());
        h.join().ok();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
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
        assert!(!dir.exists());
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
        assert!(!dir.exists());
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
        assert!(!dir.exists());
    }
}
