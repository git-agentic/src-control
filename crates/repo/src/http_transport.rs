//! sc-native HTTP transport (P26): `sc+http://` URL parsing + module
//! skeleton. The wire codec (Task 2), client [`Transport`](crate::transport::Transport)
//! impl (Task 3), and server (Task 4) land in later P26 tasks; this module
//! currently holds only [`ScHttpUrl`], the seam those tasks build on.

use crate::error::{Error, Result};

/// Default port for `sc+http://` URLs when the authority omits one.
pub const DEFAULT_PORT: u16 = 8730;

/// A parsed sc-native HTTP URL: `sc+http://host[:port]/repo/path`.
///
/// Port defaults to [`DEFAULT_PORT`] when omitted. `path` is everything
/// after the authority, leading `/` kept; an empty remainder becomes `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScHttpUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl ScHttpUrl {
    /// Parse an `sc+http://` URL; anything malformed is `InvalidArgument`
    /// with a message naming the URL (mirrors `SshUrl::parse`'s style —
    /// URL parsing fails before any connection exists, so `Protocol`'s
    /// wire-protocol-error semantics don't apply here).
    pub fn parse(url: &str) -> Result<ScHttpUrl> {
        let rest = url
            .strip_prefix("sc+http://")
            .ok_or_else(|| Error::InvalidArgument(format!("not an sc+http:// url: {url}")))?;
        let slash = rest.find('/').unwrap_or(rest.len());
        let (authority, path) = rest.split_at(slash);
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    Error::InvalidArgument(format!("bad port in sc+http url: {url}"))
                })?;
                (h, port)
            }
            None => (authority, DEFAULT_PORT),
        };
        if host.is_empty() {
            return Err(Error::InvalidArgument(format!("sc+http url has empty host: {url}")));
        }
        let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
        Ok(ScHttpUrl { host: host.to_string(), port, path })
    }

    /// `host:port`, for `TcpStream::connect`.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full() {
        let u = ScHttpUrl::parse("sc+http://example.com:8730/srv/repo").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 8730);
        assert_eq!(u.path, "/srv/repo");
    }

    #[test]
    fn parse_default_port() {
        let u = ScHttpUrl::parse("sc+http://host/repo").unwrap();
        assert_eq!(u.host, "host");
        assert_eq!(u.port, DEFAULT_PORT);
        assert_eq!(u.path, "/repo");
    }

    #[test]
    fn parse_empty_path() {
        let u = ScHttpUrl::parse("sc+http://host:9000").unwrap();
        assert_eq!(u.host, "host");
        assert_eq!(u.port, 9000);
        assert_eq!(u.path, "/");
    }

    #[test]
    fn parse_rejects_other_schemes() {
        assert!(ScHttpUrl::parse("http://h/r").is_err());
        assert!(ScHttpUrl::parse("ssh://h/r").is_err());
        assert!(ScHttpUrl::parse("/local/path").is_err());
    }

    #[test]
    fn authority_form() {
        let u = ScHttpUrl::parse("sc+http://host:9000/repo").unwrap();
        assert_eq!(u.authority(), "host:9000");
    }
}
