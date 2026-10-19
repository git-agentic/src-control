//! CA-path validation (ADR-0054): the additive alternative to SPKI pinning for
//! deployments whose server presents a certificate issued by a real CA (a
//! certbot/ACME certificate that rotates, an organisation's private CA).
//!
//! Unlike the pin verifier, this checks everything a browser would: the chain
//! to a trusted root, the validity window, and that the certificate covers the
//! name the client dialled (DNS or IP SAN). Handshake signatures are verified
//! as always. It never falls back to accept-new: a client that asked for CA
//! trust and cannot establish it fails.

use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::RootCertStore;

use crate::stream::TlsClientStream;
use crate::{Error, Result};

/// The trust anchors a CA-validated connection accepts.
#[derive(Clone)]
pub struct CaTrust {
    roots: Arc<RootCertStore>,
    /// How many anchors were loaded (for the caller's diagnostics).
    count: usize,
}

impl CaTrust {
    /// Anchors from a PEM bundle (one or more `CERTIFICATE` blocks). A file
    /// with no usable certificate is an error, never an empty store that would
    /// make every connection fail later with a confusing message.
    pub fn from_pem_file(path: &Path) -> Result<CaTrust> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
            .map_err(|e| Error::Mint(format!("read CA bundle {}: {e}", path.display())))?
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Mint(format!("parse CA bundle {}: {e}", path.display())))?;
        Self::from_der(certs, &path.display().to_string())
    }

    /// Anchors from the platform's trust store (system roots).
    pub fn system() -> Result<CaTrust> {
        let loaded = rustls_native_certs::load_native_certs();
        if loaded.certs.is_empty() {
            let why = loaded
                .errors
                .first()
                .map(|e| format!(": {e}"))
                .unwrap_or_default();
            return Err(Error::Mint(format!(
                "no system root certificates could be loaded{why}"
            )));
        }
        Self::from_der(loaded.certs, "the system trust store")
    }

    fn from_der(certs: Vec<CertificateDer<'static>>, from: &str) -> Result<CaTrust> {
        let mut roots = RootCertStore::empty();
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(Error::Mint(format!(
                "{from} holds no usable CA certificate"
            )));
        }
        Ok(CaTrust {
            roots: Arc::new(roots),
            count: added,
        })
    }

    /// The number of trust anchors loaded.
    pub fn anchors(&self) -> usize {
        self.count
    }
}

/// Connect-side wrap with CA validation: chain, validity and name must all
/// check out before any application byte is written. `host` is the name the
/// caller dialled (a DNS name or an IP address).
pub fn client_connect_ca(
    mut tcp: TcpStream,
    host: &str,
    trust: &CaTrust,
) -> Result<TlsClientStream> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Handshake(e.to_string()))?
        .with_root_certificates(Arc::clone(&trust.roots))
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| Error::Handshake(format!("bad server name {host}: {e}")))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| Error::Handshake(e.to_string()))?;
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut tcp) {
            return Err(Error::Handshake(format!(
                "certificate validation for {host} failed: {e}"
            )));
        }
    }
    Ok(TlsClientStream::from_parts(conn, tcp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{server_config, server_stream, ServerIdentity};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    struct Pki {
        ca_pem: String,
        identity: ServerIdentity,
    }

    /// A throwaway CA and a leaf it issued for `names` (DNS names and, when
    /// they parse as such, IP addresses).
    fn pki(names: &[&str]) -> Pki {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let der = leaf.der().clone();
        let spki = crate::spki_sha256(&der).unwrap();
        Pki {
            ca_pem: ca.pem(),
            identity: ServerIdentity {
                certs: vec![der],
                key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
                ),
                spki_sha256: spki,
            },
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("scl-tlsio-ca-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn trust_from(dir: &std::path::Path, pem: &str) -> CaTrust {
        let f = dir.join("ca.pem");
        std::fs::write(&f, pem).unwrap();
        CaTrust::from_pem_file(&f).unwrap()
    }

    /// One-connection echo server for the identity; returns its address.
    fn serve(identity: ServerIdentity) -> (String, std::thread::JoinHandle<()>) {
        let cfg = server_config(identity).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let h = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let Ok(stream) = server_stream(&cfg, tcp) else {
                return; // a client that rejects the cert aborts the handshake
            };
            let (mut r, mut w) = stream.split();
            let mut buf = [0u8; 5];
            if r.read_exact(&mut buf).is_ok() {
                let _ = w.write_all(&buf);
                let _ = w.flush();
            }
        });
        (addr, h)
    }

    #[test]
    fn a_certificate_issued_by_the_trusted_ca_for_the_dialled_name_connects() {
        let dir = tmp("ok");
        let p = pki(&["localhost", "127.0.0.1"]);
        let trust = trust_from(&dir, &p.ca_pem);
        assert_eq!(trust.anchors(), 1);
        for host in ["localhost", "127.0.0.1"] {
            let (addr, h) = serve(pki_clone(&p));
            let tcp = std::net::TcpStream::connect(&addr).unwrap();
            let stream = client_connect_ca(tcp, host, &trust).unwrap();
            let (mut r, mut w) = stream.split();
            w.write_all(b"hello").unwrap();
            w.flush().unwrap();
            let mut back = [0u8; 5];
            r.read_exact(&mut back).unwrap();
            assert_eq!(&back, b"hello", "dialled as {host}");
            h.join().unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    fn pki_clone(p: &Pki) -> ServerIdentity {
        ServerIdentity {
            certs: p.identity.certs.clone(),
            key: p.identity.key.clone_key(),
            spki_sha256: p.identity.spki_sha256,
        }
    }

    #[test]
    fn a_certificate_from_an_untrusted_ca_is_rejected() {
        let dir = tmp("untrusted");
        let server = pki(&["localhost"]);
        let other_ca = pki(&["unrelated"]); // a different CA entirely
        let trust = trust_from(&dir, &other_ca.ca_pem);
        let (addr, h) = serve(server.identity);
        let tcp = std::net::TcpStream::connect(&addr).unwrap();
        let err = client_connect_ca(tcp, "localhost", &trust).unwrap_err();
        assert!(
            err.to_string()
                .contains("certificate validation for localhost failed"),
            "{err}"
        );
        h.join().ok();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    /// Chain-valid but issued for another name: pinning ignores names, CA
    /// validation must not.
    #[test]
    fn a_certificate_for_another_name_is_rejected_even_from_a_trusted_ca() {
        let dir = tmp("name");
        let p = pki(&["only.example"]);
        let trust = trust_from(&dir, &p.ca_pem);
        let (addr, h) = serve(p.identity);
        let tcp = std::net::TcpStream::connect(&addr).unwrap();
        let err = client_connect_ca(tcp, "localhost", &trust).unwrap_err();
        assert!(err.to_string().contains("failed"), "{err}");
        h.join().ok();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn a_bundle_with_no_certificate_is_an_error_not_an_empty_store() {
        let dir = tmp("empty");
        let f = dir.join("empty.pem");
        std::fs::write(&f, "# nothing here\n").unwrap();
        let err = CaTrust::from_pem_file(&f).err().expect("must fail");
        assert!(
            err.to_string().contains("no usable CA certificate"),
            "{err}"
        );
        let missing = CaTrust::from_pem_file(&dir.join("absent.pem"))
            .err()
            .expect("must fail");
        assert!(missing.to_string().contains("read CA bundle"), "{missing}");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
    }
}
