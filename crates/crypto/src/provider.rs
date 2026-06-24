//! Where a private identity comes from. `FileKeyProvider` now; env/agent/KMS
//! providers can be added later behind the same trait without touching call
//! sites.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::key::SecretKey;

/// Supplies the private identity used to decrypt secrets.
pub trait KeyProvider {
    fn identity(&self) -> Result<SecretKey>;
}

/// Loads an identity from a `scl-sk-<hex>` key file.
pub struct FileKeyProvider {
    pub path: PathBuf,
}

impl FileKeyProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileKeyProvider { path: path.into() }
    }
}

impl KeyProvider for FileKeyProvider {
    fn identity(&self) -> Result<SecretKey> {
        // Wrap in `Zeroizing` so the raw `scl-sk-` material is wiped after parse
        // rather than lingering in the read buffer.
        let contents = zeroize::Zeroizing::new(
            std::fs::read_to_string(&self.path).map_err(|e| Error::KeyIo(e.to_string()))?,
        );
        SecretKey::from_key_string(&contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::generate_keypair_with_rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn file_provider_roundtrips_an_identity() {
        let (sk, pk) = generate_keypair_with_rng(&mut ChaCha20Rng::seed_from_u64(7));
        let dir = std::env::temp_dir().join(format!("scl-keyprov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity");
        std::fs::write(&path, sk.to_key_string()).unwrap();

        let provider = FileKeyProvider::new(&path);
        let loaded = provider.identity().unwrap();
        assert_eq!(loaded.public().to_bytes(), pk.to_bytes());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_is_key_io_error() {
        let provider = FileKeyProvider::new("/nonexistent/scl/identity");
        assert!(matches!(provider.identity(), Err(Error::KeyIo(_))));
    }
}
