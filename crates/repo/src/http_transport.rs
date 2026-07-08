//! sc-native HTTP transport (P26): `sc+http://` URL parsing + module
//! skeleton. The wire codec (Task 2), client [`Transport`](crate::transport::Transport)
//! impl (Task 3), and server (Task 4) land in later P26 tasks; this module
//! currently holds only [`ScHttpUrl`], the seam those tasks build on.

use std::io::{Read, Write};

use crate::error::{Error, Result};

/// Default port for `sc+http://` URLs when the authority omits one.
pub const DEFAULT_PORT: u16 = 8730;

/// Max bytes of request-line + headers the server (or client, for a status
/// line + headers) will read before the blank line, guarding against an
/// unterminated/hostile opening. Untrusted-input bound: the read loop below
/// errors out once the accumulator crosses this cap, so a peer that never
/// sends `\r\n\r\n` cannot force an unbounded read/allocation.
pub(crate) const MAX_OPENING_BYTES: usize = 8 * 1024;

/// Read from `r` one byte at a time, accumulating into a buffer, until the
/// 4-byte sequence `\r\n\r\n` has been seen or `MAX_OPENING_BYTES` is
/// exceeded. Returns the accumulated bytes (including the terminator).
///
/// This is the untrusted-input-robustness gate for HTTP transport: `r` is a
/// socket the peer controls, so the loop must never read more than
/// `MAX_OPENING_BYTES` before giving up, regardless of what (or how much,
/// or how slowly) the peer sends.
fn read_bounded_opening(r: &mut impl Read) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= MAX_OPENING_BYTES {
            return Err(Error::InvalidArgument(format!(
                "HTTP opening exceeded {MAX_OPENING_BYTES} bytes without a terminating blank line"
            )));
        }
        let n = r
            .read(&mut byte)
            .map_err(|e| Error::InvalidArgument(format!("HTTP opening read failed: {e}")))?;
        if n == 0 {
            return Err(Error::InvalidArgument(
                "HTTP opening ended before a terminating blank line".to_string(),
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

/// CLIENT: write `POST <path> HTTP/1.1\r\nHost: <host>\r\nUser-Agent: sc/2\r\n\r\n`.
pub(crate) fn write_client_opening(w: &mut impl Write, host: &str, path: &str) -> Result<()> {
    write!(w, "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sc/2\r\n\r\n")
        .map_err(|e| Error::InvalidArgument(format!("HTTP opening write failed: {e}")))
}

/// SERVER: read the request line + headers up to the blank line (bounded by
/// [`MAX_OPENING_BYTES`]). Returns the request-target (the `<path>`). Errors
/// (→ the caller sends 400) on: a bad request line, no `\r\n\r\n` within the
/// cap, or non-HTTP bytes.
pub(crate) fn read_client_opening(r: &mut impl Read) -> Result<String> {
    let buf = read_bounded_opening(r)?;
    let text = String::from_utf8_lossy(&buf);
    let request_line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| Error::InvalidArgument("empty HTTP request line".to_string()))?;
    let mut parts = request_line.split(' ');
    let _method = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP request line: {request_line}")))?;
    let target = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP request line: {request_line}")))?;
    let version = parts
        .next()
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP request line: {request_line}")))?;
    if !version.starts_with("HTTP/") {
        return Err(Error::InvalidArgument(format!(
            "bad HTTP request line (missing HTTP/ version): {request_line}"
        )));
    }
    Ok(target.to_string())
}

/// SERVER: write `HTTP/1.1 <code> <reason>\r\nContent-Length: 0\r\n\r\n`.
/// Supports 200 OK / 404 Not Found / 400 Bad Request.
pub(crate) fn write_status(w: &mut impl Write, code: u16) -> Result<()> {
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        400 => "Bad Request",
        _ => return Err(Error::InvalidArgument(format!("unsupported HTTP status code: {code}"))),
    };
    write!(w, "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n")
        .map_err(|e| Error::InvalidArgument(format!("HTTP status write failed: {e}")))
}

/// CLIENT: read the status line + headers up to the blank line (bounded).
/// Returns the numeric status code.
pub(crate) fn read_status(r: &mut impl Read) -> Result<u16> {
    let buf = read_bounded_opening(r)?;
    let text = String::from_utf8_lossy(&buf);
    let status_line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| Error::InvalidArgument("empty HTTP status line".to_string()))?;
    let mut parts = status_line.split(' ');
    let version = parts
        .next()
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP status line: {status_line}")))?;
    if !version.starts_with("HTTP/") {
        return Err(Error::InvalidArgument(format!(
            "bad HTTP status line (missing HTTP/ version): {status_line}"
        )));
    }
    let code = parts
        .next()
        .ok_or_else(|| Error::InvalidArgument(format!("bad HTTP status line: {status_line}")))?
        .parse::<u16>()
        .map_err(|_| Error::InvalidArgument(format!("bad HTTP status code: {status_line}")))?;
    Ok(code)
}

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

    #[test]
    fn client_opening_round_trips() {
        let mut buf = Vec::new();
        write_client_opening(&mut buf, "h", "/repo").unwrap();
        let target = read_client_opening(&mut &buf[..]).unwrap();
        assert_eq!(target, "/repo");
    }

    #[test]
    fn read_opening_rejects_malformed() {
        // No `\r\n\r\n` at all: the peer stops sending (EOF) before a
        // terminator — bounded, not a hang.
        let no_terminator = b"POST /repo HTTP/1.1\r\nHost: h\r\n";
        assert!(read_client_opening(&mut &no_terminator[..]).is_err());

        // Bad first line: no method/target/version structure.
        let garbage = b"garbage\r\n\r\n";
        assert!(read_client_opening(&mut &garbage[..]).is_err());

        // Opening exceeding the cap, no blank line anywhere: must error
        // bounded by MAX_OPENING_BYTES rather than reading forever.
        let oversized = vec![b'a'; MAX_OPENING_BYTES + 1024];
        let err = read_client_opening(&mut &oversized[..]).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => assert!(msg.contains("exceeded")),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn status_round_trips() {
        for code in [200u16, 404, 400] {
            let mut buf = Vec::new();
            write_status(&mut buf, code).unwrap();
            let got = read_status(&mut &buf[..]).unwrap();
            assert_eq!(got, code);
        }
    }

    #[test]
    fn read_status_rejects_non_http() {
        let garbage = b"garbage\r\n\r\n";
        assert!(read_status(&mut &garbage[..]).is_err());
    }

    #[test]
    fn read_status_bounded_against_unterminated_stream() {
        // A hostile/streaming peer that never sends a blank line must not
        // cause an unbounded read: this simulates an infinite reader by
        // supplying more than MAX_OPENING_BYTES of non-terminating bytes.
        let oversized = vec![b'x'; MAX_OPENING_BYTES + 4096];
        let err = read_status(&mut &oversized[..]).unwrap_err();
        match err {
            Error::InvalidArgument(msg) => assert!(msg.contains("exceeded")),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }
}
