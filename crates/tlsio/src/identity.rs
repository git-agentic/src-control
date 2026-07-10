//! Server TLS identity: load `cert.pem`/`key.pem` from a directory, minting
//! a self-signed pair (rcgen) when absent. The KEY is the identity —
//! regenerate only when missing; the cert carries a far-future not_after so
//! renewal never bites a pinned deployment (pins are on the SPKI anyway).

use std::path::Path;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

use crate::{spki_sha256, Error, Result};

/// A loaded/minted server identity, ready for `server_config` (Task 2).
#[derive(Debug)]
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
