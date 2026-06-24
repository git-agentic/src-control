//! Errors returned by the cryptography layer.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The supplied identity is not among the secret's recipients.
    #[error("identity is not an authorized recipient of this secret")]
    NotARecipient,
    /// AEAD authentication failed: wrong key or tampered ciphertext.
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    /// A key string or key file could not be parsed.
    #[error("malformed key")]
    BadKey,
    /// Reading a key file failed.
    #[error("key io error: {0}")]
    KeyIo(String),
}

pub type Result<T> = std::result::Result<T, Error>;
