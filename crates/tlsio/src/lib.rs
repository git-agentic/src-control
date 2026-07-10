//! TLS quarantine crate (P32, ADR-0042): the ONLY crate linking rustls and
//! rcgen (the gix→gitio / RustCrypto→crypto precedent). Exposes blocking
//! `Read + Write` TLS streams for the sc+https:// transport, a pin-only
//! TOFU certificate verifier, self-signed cert mint/load, and SPKI-SHA-256
//! fingerprints. Depends on no other workspace crate.

mod identity;
mod spki;
mod stream;

pub use identity::{load_or_mint, load_pem, ServerIdentity};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer};
pub use spki::{fingerprint_hex, spki_der, spki_sha256};
pub use stream::{
    client_connect, server_config, server_stream, TlsClientReadHalf, TlsClientStream,
    TlsClientWriteHalf, TlsServerConfig, TlsServerReadHalf, TlsServerStream, TlsServerWriteHalf,
};

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
