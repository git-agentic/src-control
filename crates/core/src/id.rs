use std::fmt;

/// A content address: the BLAKE3 hash of an object's canonical serialization.
///
/// Identical content anywhere in history hashes to the same `ObjectId`, which is
/// what gives the store its deduplication and verifiability properties.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Compute the content address of a canonical object encoding.
    pub fn of(bytes: &[u8]) -> Self {
        ObjectId(*blake3::hash(bytes).as_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ObjectId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full 64-char hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First 12 hex chars, for human-readable logs.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..6])
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.short())
    }
}

impl std::str::FromStr for ObjectId {
    type Err = crate::error::Error;

    /// Parse a 64-char hex string into an `ObjectId`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Two distinct failures: the string isn't valid hex at all, vs. it is
        // valid hex but decodes to the wrong number of bytes (not 32).
        let bytes = hex::decode(s).map_err(|_| {
            crate::error::Error::Malformed(format!("ObjectId is not valid hex: {s:?}"))
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            crate::error::Error::Malformed(format!(
                "ObjectId must be 32 bytes (64 hex chars), got {} bytes",
                v.len()
            ))
        })?;
        Ok(ObjectId(arr))
    }
}
