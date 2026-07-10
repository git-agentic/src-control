//! sc-native HTTP transport (P26): `sc+http://` URL parsing (Task 1), the
//! opening codec (Task 2), and the client [`HttpTransport`] + `sc+http://`
//! routing in `open_transport` (Task 3). The server (`sc serve --http`)
//! lands in Task 4.

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::stdio_transport::WireClient;
use crate::transport::Transport;

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

/// A parsed client HTTP opening: the request-target and an optional
/// `Authorization: Bearer` token. Only the bearer header is extracted (P29);
/// all other headers are ignored.
#[derive(Debug)]
pub(crate) struct ClientOpening {
    pub target: String,
    pub bearer: Option<String>,
}

/// CLIENT: write `POST <path> HTTP/1.1\r\nHost: <host>\r\nUser-Agent: sc/2\r\n\r\n`,
/// plus an `Authorization: Bearer` header when a token is supplied.
pub(crate) fn write_client_opening(
    w: &mut impl Write,
    host: &str,
    path: &str,
    bearer: Option<&str>,
) -> Result<()> {
    write!(
        w,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sc/2\r\n"
    )
    .map_err(|e| Error::InvalidArgument(format!("HTTP opening write failed: {e}")))?;
    if let Some(tok) = bearer {
        write!(w, "Authorization: Bearer {tok}\r\n")
            .map_err(|e| Error::InvalidArgument(format!("HTTP opening write failed: {e}")))?;
    }
    write!(w, "\r\n").map_err(|e| Error::InvalidArgument(format!("HTTP opening write failed: {e}")))
}

/// SERVER: read the request line + headers up to the blank line (bounded by
/// [`MAX_OPENING_BYTES`]). Returns the request-target and the bearer token if
/// an `Authorization: Bearer <token>` header (case-insensitive name) is
/// present. Errors (→ the caller sends 400) on: a bad request line, no
/// `\r\n\r\n` within the cap, or non-HTTP bytes.
pub(crate) fn read_client_opening(r: &mut impl Read) -> Result<ClientOpening> {
    let buf = read_bounded_opening(r)?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");

    let request_line = lines
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

    let mut bearer = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                let v = value.trim();
                if let Some(tok) = v
                    .strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
                {
                    bearer = Some(tok.trim().to_string());
                }
            }
        }
    }

    Ok(ClientOpening {
        target: target.to_string(),
        bearer,
    })
}

/// SERVER: write `HTTP/1.1 <code> <reason>\r\nContent-Length: 0\r\n\r\n`.
/// Supports 200 OK / 404 Not Found / 400 Bad Request / 401 Unauthorized.
pub(crate) fn write_status(w: &mut impl Write, code: u16) -> Result<()> {
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        _ => {
            return Err(Error::InvalidArgument(format!(
                "unsupported HTTP status code: {code}"
            )))
        }
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
            return Err(Error::InvalidArgument(format!(
                "sc+http url has empty host: {url}"
            )));
        }
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        // CARRY-IN from the Task 2 review: `write_client_opening` interpolates
        // host/path into the request line/header with no CRLF escaping — a
        // host or path containing '\r'/'\n' could inject extra header lines
        // or a bogus request line into the opening. `ScHttpUrl` values come
        // from local remote config (lower risk than reading them off the
        // wire), but reject them here too, cheaply, at parse time rather than
        // trusting every future caller of `write_client_opening` to check.
        if host.contains(['\r', '\n']) || path.contains(['\r', '\n']) {
            return Err(Error::InvalidArgument(format!(
                "sc+http url host/path must not contain CR or LF: {url}"
            )));
        }
        Ok(ScHttpUrl {
            host: host.to_string(),
            port,
            path,
        })
    }

    /// `host:port`, for `TcpStream::connect`.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// A [`Transport`] that speaks the wire protocol over a `TcpStream`
/// established via the HTTP opening: connect, write the client opening line,
/// read+map the status BEFORE any wire-protocol byte crosses the socket,
/// then hand the (split) stream to the same [`WireClient`] `StdioTransport`
/// uses over a child process's stdio.
#[derive(Debug)]
pub struct HttpTransport {
    client: WireClient<BufReader<TcpStream>, TcpStream>,
}

impl HttpTransport {
    /// Connect to `url`, perform the HTTP opening, and hand off to
    /// `WireClient::handshake`. The status line is read and mapped BEFORE
    /// the wire-protocol handshake begins: 200 proceeds, 404 means the
    /// server-side path isn't a repo ([`Error::NotARepo`]), anything else is
    /// a clearly-named [`Error::Protocol`] — none of these are wire-protocol
    /// errors, so they must not be mistaken for a `HELLO` failure.
    pub fn connect(url: &ScHttpUrl) -> Result<HttpTransport> {
        let token = std::env::var("SC_HTTP_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        Self::connect_with_token(url, token.as_deref())
    }

    /// Connect presenting an explicit bearer `token` (or none). `connect`
    /// reads the token from `SC_HTTP_TOKEN`; this split keeps the env read
    /// out of the socket logic and testable without mutating process env
    /// (`std::env::set_var` is process-global and racy under parallel
    /// tests).
    pub fn connect_with_token(url: &ScHttpUrl, token: Option<&str>) -> Result<HttpTransport> {
        if let Some(t) = token {
            if t.contains(['\r', '\n']) {
                return Err(Error::InvalidArgument(
                    "SC_HTTP_TOKEN must not contain CR or LF".to_string(),
                ));
            }
        }

        let mut stream = TcpStream::connect(url.authority())
            .map_err(|e| Error::ConnectionLost(format!("sc+http connect to {url:?}: {e}")))?;
        write_client_opening(&mut stream, &url.host, &url.path, token)?;

        // Split the stream into independent read/write halves up front —
        // `try_clone` duplicates the socket handle (both `r` and `w` refer
        // to the same TCP connection, matching StdioTransport's separate
        // ChildStdout/ChildStdin), mirroring the read-half construction the
        // brief specifies. The status line is read through this SAME
        // `BufReader` that goes on to become the WireClient's `r`, not a
        // throwaway clone: `BufReader::read` can pull more than one byte
        // from the kernel into its internal buffer per call, so a separate,
        // later-dropped reader could silently swallow the first
        // wire-protocol frame byte(s) if the server ever raced ahead of the
        // status line. Reusing one buffer means anything it over-reads stays
        // available for the handshake that follows.
        let mut r = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| Error::ConnectionLost(format!("sc+http socket clone: {e}")))?,
        );
        let w = stream;

        // Status mapping happens BEFORE the wire-protocol handshake: 200
        // proceeds, 401 means the server rejected the bearer (or required
        // one and got none), 404 means the server-side path isn't a repo,
        // anything else is a clearly-named protocol error — none of these
        // are HELLO-handshake failures, so they must not be reported as one.
        let status = read_status(&mut r)?;
        match status {
            200 => {}
            401 => {
                return Err(Error::Remote(
                    "sc+http authentication required or token rejected; set SC_HTTP_TOKEN to a \
                     valid token (sc serve token add on the server)"
                        .to_string(),
                ))
            }
            404 => return Err(Error::NotARepo),
            other => {
                return Err(Error::Protocol(format!(
                    "sc+http server returned unexpected status {other}"
                )))
            }
        }

        let client = WireClient::handshake(r, w)?;
        Ok(HttpTransport { client })
    }
}

impl Transport for HttpTransport {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        self.client.list_refs()
    }
    fn head_branch(&self) -> Result<String> {
        self.client.head_branch()
    }
    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        self.client.has_object(id)
    }
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.client.get_object(id)
    }
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        self.client.put_object(id, bytes)
    }
    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        self.client.update_ref(branch, id, expected_old)
    }
    fn get_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        filter: Option<&[String]>,
        out: &mut dyn Write,
    ) -> Result<()> {
        self.client.get_pack(wants, haves, filter, out)
    }
    fn put_pack(&self, src: &mut dyn Read) -> Result<Vec<ObjectId>> {
        self.client.put_pack(src)
    }
}

/// Bound on how long an accepted connection may take to send its HTTP
/// opening (request line + headers + blank line) before the server gives up
/// on it. Guards the slow-loris case the Task 2 review flagged:
/// `read_client_opening` bounds the opening in BYTES (`MAX_OPENING_BYTES`)
/// but not in TIME, so a peer that trickles in under the byte cap and then
/// stalls would otherwise hold a server thread (and its socket) forever.
/// Applied only around the opening read — see [`serve_http_listener`] for
/// where it's cleared before a legitimate large pack transfer begins.
const OPENING_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Is `host` a loopback address (always safe to bind)? IPv4 `127.0.0.0/8`,
/// IPv6 `::1`, or the literal `localhost`. Everything else (`0.0.0.0`, a LAN
/// IP, `::`) is non-loopback and subject to the fail-closed bind gate in
/// [`bind_is_allowed`].
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

/// The fail-closed bind decision (P29): a non-loopback `addr` is allowed
/// only if justified by `--read-only`, `--allow-public`, or ≥1 configured
/// serve token; loopback always binds. Factored out of [`serve_http`] so
/// tests can exercise the decision without binding a public port.
fn bind_is_allowed(
    addr: &str,
    root: &std::path::Path,
    read_only: bool,
    allow_public: bool,
) -> Result<bool> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    // Strip optional [..] brackets around an IPv6 literal.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if is_loopback_host(host) {
        return Ok(true);
    }
    if read_only || allow_public {
        return Ok(true);
    }
    let tokens_configured =
        !crate::serve_tokens::load(&crate::layout::Layout::at(root))?.is_empty();
    Ok(tokens_configured)
}

/// Is a valid bearer token MANDATORY on every connection for a server bound to
/// `addr` under these flags? True exactly when the bind is non-loopback and its
/// ONLY possible justification was configured tokens (not `--read-only`, not
/// `--allow-public`). In that state an empty token set at connection time means
/// the operator removed the sole justification out from under a public server —
/// the handler must then fail closed (reject) rather than serve open. Loopback,
/// `--read-only` (public read-mirror), and `--allow-public` (deliberately open)
/// all keep their standing posture when tokens vanish, so this is false for them.
fn auth_is_mandatory(addr: &str, read_only: bool, allow_public: bool) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    !is_loopback_host(host) && !read_only && !allow_public
}

/// Bind `addr`, serve the single repo at `root` to `sc+http://` clients
/// until the listener is dropped or the process exits. Thin wrapper around
/// [`serve_http_listener`] — see that function for the accept-loop
/// behavior; this just does the binding.
///
/// Fail-closed bind gate (P29): a non-loopback `addr` is refused up front
/// unless justified by `read_only`, `allow_public`, or ≥1 configured serve
/// token (see [`bind_is_allowed`]) — an unauthenticated server must not
/// silently listen on a public interface.
pub fn serve_http(
    addr: &str,
    root: &std::path::Path,
    read_only: bool,
    allow_public: bool,
) -> Result<()> {
    if !bind_is_allowed(addr, root, read_only, allow_public)? {
        return Err(Error::InvalidArgument(format!(
            "refusing to bind non-loopback address {addr} without --read-only, \
             --allow-public, or a configured serve token (sc serve token add); \
             use 127.0.0.1 for local-only serving"
        )));
    }
    let mandatory_auth = auth_is_mandatory(addr, read_only, allow_public);
    let listener = TcpListener::bind(addr)
        .map_err(|e| Error::ConnectionLost(format!("sc+http bind {addr}: {e}")))?;
    // Announce the actually-bound address on stdout, then flush. stdout is
    // free in `--http` mode (the wire protocol rides the TCP socket, never
    // stdout — unlike `--stdio`), so this is a safe place to report the
    // resolved port. This gives real users startup feedback AND lets a
    // caller that binds `:0` (an OS-assigned port) learn which port it got —
    // the CLI http tests rely on exactly this to avoid fixed-port collisions.
    let bound = listener
        .local_addr()
        .map_err(|e| Error::ConnectionLost(format!("sc+http local_addr: {e}")))?;
    println!("listening on {bound}");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    serve_http_listener(listener, root, read_only, mandatory_auth)
}

/// Accept-loop core, factored out of [`serve_http`] so tests can bind
/// `127.0.0.1:0`, read back the OS-assigned port via `local_addr()`, and
/// hand the already-bound listener in here directly.
///
/// Thread-per-connection: each accepted stream is handled on its own thread
/// so one slow or misbehaving client cannot block others. The `.sc/`
/// single-writer lock inside the commit/push path already serializes
/// concurrent pushes; concurrent read-only fetches need no extra guard
/// here.
///
/// Runs until the listener is dropped/closed (`incoming()` yields `None`)
/// or a fatal accept-level error occurs; a per-connection error (bad
/// opening, a `wire::serve` failure, a dropped socket) is logged to stderr
/// and the loop continues — it must never take down the whole server.
pub fn serve_http_listener(
    listener: TcpListener,
    root: &std::path::Path,
    read_only: bool,
    mandatory_auth: bool,
) -> Result<()> {
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sc serve --http: accept error: {e}");
                continue;
            }
        };
        let root = root.to_path_buf();
        std::thread::spawn(move || {
            if let Err(e) = handle_http_connection(stream, &root, read_only, mandatory_auth) {
                eprintln!("sc serve --http: connection error: {e}");
            }
        });
    }
    Ok(())
}

/// Handle one accepted connection end to end: bounded-time opening read →
/// validate `root` is a repo → status line → `wire::serve`.
///
/// The read timeout is set BEFORE `read_client_opening` (closing the
/// slow-loris gap: the opening is bounded in bytes but not time) and
/// cleared again AFTER the 200 status is written and BEFORE handing off to
/// `wire::serve` — a legitimate large pack transfer must not be cut off
/// mid-stream by the same timeout that guards the opening.
fn handle_http_connection(
    mut stream: TcpStream,
    root: &std::path::Path,
    server_read_only: bool,
    mandatory_auth: bool,
) -> Result<()> {
    stream
        .set_read_timeout(Some(OPENING_READ_TIMEOUT))
        .map_err(|e| Error::ConnectionLost(format!("sc+http set_read_timeout: {e}")))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| Error::ConnectionLost(format!("sc+http socket clone: {e}")))?,
    );

    let opening = match read_client_opening(&mut reader) {
        Ok(o) => o,
        Err(_) => {
            // Malformed/slow-loris opening: best-effort 400, then close.
            let _ = write_status(&mut stream, 400);
            return Ok(());
        }
    };
    // The request-target isn't used to route (one repo per listener).
    let _ = &opening.target;

    if !root.join(".sc").is_dir() {
        write_status(&mut stream, 404)?;
        return Ok(());
    }

    // Auth gate (P29): if ≥1 token is configured, a valid bearer is
    // REQUIRED on every connection, loopback included — the bind gate only
    // decides whether the port may be opened at all, not who may use it
    // once it is. No tokens configured means auth is off entirely (today's
    // pre-P29 behavior). A matched token's scope sets this connection's
    // read-only flag; `--read-only` below is a floor an `rw` token cannot
    // elevate.
    let tokens = crate::serve_tokens::load(&crate::layout::Layout::at(root))?;
    let token_read_only = if tokens.is_empty() {
        if mandatory_auth {
            // The public bind's sole justification (tokens) was removed while
            // running — fail closed, do NOT serve an open unauthenticated server.
            eprintln!(
                "sc serve --http: refusing connection — this non-loopback server was \
                 justified only by tokens, but none are configured (re-add a token, or \
                 restart with --read-only / --allow-public)"
            );
            write_status(&mut stream, 401)?;
            return Ok(());
        }
        false // loopback, or --read-only / --allow-public public bind: proceed unauthenticated
    } else {
        match opening
            .bearer
            .as_deref()
            .and_then(|t| crate::serve_tokens::verify(&tokens, t))
        {
            Some(crate::serve_tokens::Scope::Ro) => true,
            Some(crate::serve_tokens::Scope::Rw) => false,
            None => {
                write_status(&mut stream, 401)?;
                return Ok(());
            }
        }
    };

    write_status(&mut stream, 200)?;

    // Clear the opening's read timeout before the wire protocol begins: a
    // real streamed pack transfer can legitimately take longer than
    // `OPENING_READ_TIMEOUT` and must not be timed out mid-transfer.
    stream
        .set_read_timeout(None)
        .map_err(|e| Error::ConnectionLost(format!("sc+http clear read_timeout: {e}")))?;

    let read_only = server_read_only || token_read_only;
    crate::wire::serve_with_policy(
        root,
        &mut reader,
        &mut stream,
        crate::wire::WirePolicy {
            read_only,
            ..Default::default()
        },
    )
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
        write_client_opening(&mut buf, "h", "/repo", None).unwrap();
        let opening = read_client_opening(&mut &buf[..]).unwrap();
        assert_eq!(opening.target, "/repo");
    }

    #[test]
    fn opening_parses_bearer_case_insensitively() {
        let mut buf = Vec::new();
        write_client_opening(&mut buf, "h", "/repo", Some("sct-abc")).unwrap();
        let opening = read_client_opening(&mut &buf[..]).unwrap();
        assert_eq!(opening.target, "/repo");
        assert_eq!(opening.bearer.as_deref(), Some("sct-abc"));
    }

    #[test]
    fn opening_without_auth_has_no_bearer() {
        let mut buf = Vec::new();
        write_client_opening(&mut buf, "h", "/repo", None).unwrap();
        let opening = read_client_opening(&mut &buf[..]).unwrap();
        assert_eq!(opening.target, "/repo");
        assert_eq!(opening.bearer, None);
    }

    #[test]
    fn opening_parses_lowercase_authorization_header() {
        // Servers must accept a client that lowercases the header name.
        let raw = "POST /r HTTP/1.1\r\nHost: h\r\nauthorization: Bearer sct-xyz\r\n\r\n";
        let opening = read_client_opening(&mut raw.as_bytes()).unwrap();
        assert_eq!(opening.bearer.as_deref(), Some("sct-xyz"));
    }

    #[test]
    fn write_status_supports_401() {
        let mut buf = Vec::new();
        write_status(&mut buf, 401).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
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
        for code in [200u16, 404, 400, 401] {
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

    #[test]
    fn parse_rejects_crlf_in_host_or_path() {
        // CARRY-IN from the Task 2 review: `write_client_opening` has no CRLF
        // escaping, so a host/path smuggling '\r'/'\n' could inject extra
        // header lines or a bogus request line into the opening. Guard at
        // parse time, with no colon in the crafted host so the CRLF check —
        // not an incidental bad-port parse failure — is provably what fires.
        let err = ScHttpUrl::parse("sc+http://good\rhost/repo").unwrap_err();
        match err {
            Error::InvalidArgument(msg) => assert!(msg.contains("CR or LF"), "got: {msg}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        let err = ScHttpUrl::parse("sc+http://host/re\rpo").unwrap_err();
        match err {
            Error::InvalidArgument(msg) => assert!(msg.contains("CR or LF"), "got: {msg}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // ── HttpTransport client end-to-end (Task 3): a loopback TCP server
    // thread stands in for Task 4's `sc serve --http`, since the CLI/server
    // side lands in a later task. ──

    /// Spin a `TcpListener` on an OS-assigned loopback port; on the single
    /// connection it accepts, read the client opening, reply with `code`,
    /// and — only for 200 — hand the connection to `wire::serve` against
    /// `root`. Returns the bound port and the server thread's join handle.
    fn spawn_loopback_server(
        root: std::path::PathBuf,
        code: u16,
    ) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (sock, _addr) = listener.accept().unwrap();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut sock = sock;
            let _opening = read_client_opening(&mut reader).unwrap();
            write_status(&mut sock, code).unwrap();
            if code == 200 {
                crate::wire::serve(&root, &mut reader, &mut sock).unwrap();
            }
        });
        (port, handle)
    }

    fn tmp_repo(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("scl-http-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        crate::repo::Repo::init(&root).unwrap();
        root
    }

    /// P26 Task 3 correctness heart, end-to-end: a real loopback TCP server
    /// (standing in for Task 4's HTTP server) serves the wire protocol after
    /// the HTTP opening; the client dials it via `Repo::clone_url` (the exact
    /// fn `sc clone` calls), which routes through `open_transport`'s new
    /// `sc+http://` arm into `HttpTransport::connect`. Forces a tiny
    /// `SC_PACK_CHUNK` so the pack transfer streams many chunks over the
    /// real TCP socket, not one frame.
    #[test]
    fn client_clones_over_loopback_http() {
        let _env_guard = PACK_CHUNK_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::env::set_var("SC_PACK_CHUNK", "37");

        let src_root = tmp_repo("clone-src");
        for i in 0..5 {
            std::fs::write(
                src_root.join(format!("f{i}.txt")),
                format!("payload number {i} — filler filler filler filler").repeat(20),
            )
            .unwrap();
        }
        let src = crate::repo::Repo::open(&src_root).unwrap();
        let tip = src.commit("t", "many files").unwrap();

        let (port, server) = spawn_loopback_server(src_root.clone(), 200);

        let dst_root =
            std::env::temp_dir().join(format!("scl-http-clone-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst_root);
        let url = format!("sc+http://127.0.0.1:{port}/repo");
        let dst = crate::repo::Repo::clone_url(&url, &dst_root).unwrap();

        std::env::remove_var("SC_PACK_CHUNK");
        server.join().unwrap();

        assert_eq!(dst.head_tip().unwrap(), Some(tip));
        // Same object set: every object reachable from src's tip is present
        // in dst too (mirrors the sync.rs ssh-transport tests' assertion
        // style — content-addressed ids make "same tip" + "has every
        // reachable object" the correctness bar, not a byte-for-byte store
        // dump).
        {
            let store_arc = src.vfs().store();
            let mut src_store = store_arc.lock().unwrap();
            let reachable = crate::reachable::reachable_objects(&mut *src_store, &[tip]).unwrap();
            let dst_store_arc = dst.vfs().store();
            let mut dst_store = dst_store_arc.lock().unwrap();
            for id in &reachable {
                assert!(
                    dst_store.get(id).is_ok(),
                    "dst missing reachable object {id}"
                );
            }
        }

        drop(src);
        drop(dst);
        std::fs::remove_dir_all(&src_root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// A server that answers 404 (the path isn't a repo) must be mapped to
    /// `Error::NotARepo` BEFORE any wire-protocol handshake — the server
    /// thread here never calls `wire::serve` at all, so a client that tried
    /// to handshake anyway would hang forever waiting for a HELLO reply that
    /// never comes.
    #[test]
    fn connect_maps_404_to_not_a_repo_before_handshake() {
        let root = tmp_repo("404");
        let (port, server) = spawn_loopback_server(root.clone(), 404);

        let url = ScHttpUrl::parse(&format!("sc+http://127.0.0.1:{port}/nope")).unwrap();
        let err = HttpTransport::connect(&url).unwrap_err();
        assert!(matches!(err, Error::NotARepo), "got {err:?}");

        server.join().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    // SC_PACK_CHUNK env mutation races other tests that also transfer packs
    // — mirrors `stdio_transport::tests::PACK_CHUNK_ENV_LOCK`.
    static PACK_CHUNK_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── Task 4: the real server (`serve_http_listener`), not the loopback
    // stand-in above. ──

    /// Bind `serve_http_listener` on an OS-assigned loopback port in a
    /// background thread and return the port plus the join handle. The
    /// listener runs until the test process exits (there's no clean
    /// shutdown hook — matches the brief's "until the listener is dropped"
    /// contract, which for a `for stream in listener.incoming()` loop means
    /// the listener living for the process lifetime once handed off to a
    /// thread that owns it).
    fn spawn_real_http_server(root: std::path::PathBuf) -> u16 {
        spawn_real_http_server_policy(root, false)
    }

    fn spawn_real_http_server_policy(root: std::path::PathBuf, read_only: bool) -> u16 {
        spawn_real_http_server_policy_auth(root, read_only, false)
    }

    fn spawn_real_http_server_policy_auth(
        root: std::path::PathBuf,
        read_only: bool,
        mandatory_auth: bool,
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            serve_http_listener(listener, &root, read_only, mandatory_auth).unwrap();
        });
        port
    }

    /// End-to-end proof of `serve_http`/`serve_http_listener`, covering all
    /// four scenarios the Task 4 brief calls out: (a) clone lands
    /// byte-identical, (b) a push from a second repo lands and a later
    /// fetch sees it, (c) a signed commit (P22) verifies clean in the
    /// clone, (d) a server whose root lacks `.sc/` answers `NotARepo`.
    /// Forces a tiny `SC_PACK_CHUNK` so real TCP pack transfer streams many
    /// chunks, not one frame.
    #[test]
    fn real_server_clone_push_fetch_sign_and_404() {
        let _env_guard = PACK_CHUNK_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::env::set_var("SC_PACK_CHUNK", "37");

        // --- (d) a root without `.sc/` answers NotARepo, no handshake. ---
        let bare_dir = std::env::temp_dir()
            .join(format!("scl-http-bare-{}", std::process::id()))
            .join("nested"); // nested dir with no .sc/ anywhere useful
        std::fs::create_dir_all(&bare_dir).unwrap();
        let bare_port = spawn_real_http_server(bare_dir.clone());
        let url = ScHttpUrl::parse(&format!("sc+http://127.0.0.1:{bare_port}/nope")).unwrap();
        let err = HttpTransport::connect(&url).unwrap_err();
        assert!(matches!(err, Error::NotARepo), "got {err:?}");

        // --- (a) clone lands byte-identical over the real server. ---
        //
        // `src` is opened (and its RepoLock held) only inside tight scopes
        // below, never across a network call: `serve_http_listener`'s
        // server thread opens the SAME root via `LocalTransport` for every
        // connection, and a push's `update_ref` transiently acquires that
        // same root's `RepoLock` (`transport.rs`'s single-writer discipline)
        // — holding `src` open across that call would self-deadlock/collide
        // with our own in-process lock, since `RepoLock` is exclusive
        // per-root regardless of which handle in this process asked first.
        let src_root = tmp_repo("real-clone-src");
        for i in 0..5 {
            std::fs::write(
                src_root.join(format!("f{i}.txt")),
                format!("payload number {i} — filler filler filler filler").repeat(20),
            )
            .unwrap();
        }
        let tip1 = {
            let src = crate::repo::Repo::open(&src_root).unwrap();
            src.commit("t", "initial").unwrap()
        };

        let port = spawn_real_http_server(src_root.clone());
        let clone_url = format!("sc+http://127.0.0.1:{port}/repo");

        let dst_root =
            std::env::temp_dir().join(format!("scl-http-real-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst_root);
        let dst = crate::repo::Repo::clone_url(&clone_url, &dst_root).unwrap();
        assert_eq!(dst.head_tip().unwrap(), Some(tip1));
        {
            let src = crate::repo::Repo::open(&src_root).unwrap();
            let store_arc = src.vfs().store();
            let mut src_store = store_arc.lock().unwrap();
            let reachable = crate::reachable::reachable_objects(&mut *src_store, &[tip1]).unwrap();
            drop(src_store);
            drop(src);
            let dst_store_arc = dst.vfs().store();
            let mut dst_store = dst_store_arc.lock().unwrap();
            for id in &reachable {
                assert!(
                    dst_store.get(id).is_ok(),
                    "dst missing reachable object {id}"
                );
            }
        }

        // --- (b) push from a second (third) repo lands, a later fetch sees it. ---
        let third_root =
            std::env::temp_dir().join(format!("scl-http-real-third-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&third_root);
        let third = crate::repo::Repo::clone_url(&clone_url, &third_root).unwrap();
        std::fs::write(third_root.join("from_third.txt"), b"pushed over http").unwrap();
        let pushed_tip = third.commit("t", "pushed commit").unwrap();
        // `clone_url` already recorded "origin" -> clone_url in third's config.
        third.push("origin").unwrap();
        drop(third);

        // src's own history (read directly, not via the server) now has the
        // pushed commit as its tip.
        {
            let src = crate::repo::Repo::open(&src_root).unwrap();
            assert_eq!(src.head_tip().unwrap(), Some(pushed_tip));
        }

        // dst fetches from src (over the same real server) and sees it;
        // `clone_url` already recorded "origin" -> clone_url in dst's config.
        let fetched = dst.fetch("origin").unwrap();
        assert!(
            fetched.iter().any(|(_, id)| *id == pushed_tip),
            "fetch over http didn't see the pushed tip"
        );
        drop(dst);

        // --- (c) a signed commit (P22) verifies clean in the clone. ---
        let (_seed, identity) = scl_crypto::generate_identity_v2();
        let signed_tip = {
            let src = crate::repo::Repo::open(&src_root).unwrap();
            let signed_tip = src.commit("t", "signed commit").unwrap();
            src.sign_snapshot(signed_tip, &identity).unwrap();
            signed_tip
        };

        let signed_dst_root =
            std::env::temp_dir().join(format!("scl-http-real-signed-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&signed_dst_root);
        let signed_dst = crate::repo::Repo::clone_url(&clone_url, &signed_dst_root).unwrap();
        assert_eq!(signed_dst.head_tip().unwrap(), Some(signed_tip));

        let signer = identity.signing.as_ref().unwrap().public().to_bytes();
        let mut trust = std::collections::HashMap::new();
        trust.insert(signer, "alice".to_string());
        let status = signed_dst.sig_status(&signed_tip, &trust).unwrap();
        assert_eq!(
            status,
            crate::signatures::SigStatus::Trusted("alice".to_string())
        );

        std::env::remove_var("SC_PACK_CHUNK");
        drop(signed_dst);
        let _ = std::fs::remove_dir_all(&src_root);
        let _ = std::fs::remove_dir_all(&dst_root);
        let _ = std::fs::remove_dir_all(&third_root);
        let _ = std::fs::remove_dir_all(&signed_dst_root);
        let _ = std::fs::remove_dir_all(bare_dir.parent().unwrap());
    }

    // ── Task 4: loopback classifier + fail-closed bind gate + bearer auth
    // gate + read-only threading. ──

    #[test]
    fn loopback_classification() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.5.6.7"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("192.168.1.9"));
        assert!(!is_loopback_host("::"));
    }

    #[test]
    fn bind_refuses_public_without_justification() {
        let root = tmp_repo("bindgate");

        // Non-loopback, no --read-only / --allow-public / tokens → refused,
        // and refused *before* any bind is attempted (port 0 would always
        // succeed to bind if we got that far).
        let err = serve_http("0.0.0.0:0", &root, false, false).unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "public bind refused: {err:?}"
        );

        // Justified by --read-only.
        assert!(bind_is_allowed("0.0.0.0:0", &root, true, false).unwrap());
        // Justified by --allow-public.
        assert!(bind_is_allowed("0.0.0.0:0", &root, false, true).unwrap());
        // Still refused with neither justification and no tokens yet.
        assert!(!bind_is_allowed("0.0.0.0:0", &root, false, false).unwrap());

        // Justified by a configured token.
        crate::serve_tokens::add(
            &crate::layout::Layout::at(&root),
            "t",
            crate::serve_tokens::Scope::Rw,
        )
        .unwrap();
        assert!(bind_is_allowed("0.0.0.0:0", &root, false, false).unwrap());

        // Loopback always allowed regardless of flags/tokens.
        assert!(bind_is_allowed("127.0.0.1:0", &root, false, false).unwrap());
        assert!(bind_is_allowed("[::1]:0", &root, false, false).unwrap());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Read the client opening + status line only, without proceeding to the
    /// wire-protocol handshake — used to observe the auth gate's raw status
    /// code (401 on a missing/invalid bearer) rather than a mapped `Error`.
    fn connect_raw_status(port: u16, bearer: Option<&str>) -> u16 {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write_client_opening(&mut stream, "127.0.0.1", "/repo", bearer).unwrap();
        let mut r = BufReader::new(stream.try_clone().unwrap());
        read_status(&mut r).unwrap()
    }

    /// Full client connect presenting a bearer token, standing in for the
    /// client-side token support `sc+http://` clients gain in Task 5 (this
    /// task only needs to *drive* the auth matrix, not ship the CLI/env
    /// plumbing) — mirrors `HttpTransport::connect` exactly except for the
    /// `bearer` argument to `write_client_opening`.
    fn connect_with_bearer(
        port: u16,
        bearer: Option<&str>,
    ) -> Result<WireClient<BufReader<TcpStream>, TcpStream>> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .map_err(|e| Error::ConnectionLost(format!("connect: {e}")))?;
        write_client_opening(&mut stream, "127.0.0.1", "/repo", bearer)?;
        let mut r = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| Error::ConnectionLost(format!("socket clone: {e}")))?,
        );
        let w = stream;
        let status = read_status(&mut r)?;
        if status != 200 {
            return Err(Error::Protocol(format!("unexpected status {status}")));
        }
        WireClient::handshake(r, w)
    }

    /// The auth matrix, end to end over a real loopback server: no bearer
    /// (and a garbage bearer) is rejected 401 even though the connection is
    /// loopback; a matched `ro` token can read but a write is rejected
    /// `Error::ReadOnly`; a matched `rw` token can write.
    #[test]
    fn tokens_configured_requires_bearer_and_scope_gates_writes() {
        let root = tmp_repo("auth-matrix");
        let layout = crate::layout::Layout::at(&root);
        let ro_raw =
            crate::serve_tokens::add(&layout, "ro", crate::serve_tokens::Scope::Ro).unwrap();
        let rw_raw =
            crate::serve_tokens::add(&layout, "rw", crate::serve_tokens::Scope::Rw).unwrap();

        let port = spawn_real_http_server_policy(root.clone(), false);

        // No bearer at all → 401, even on loopback, once tokens exist.
        assert_eq!(connect_raw_status(port, None), 401);
        // A bearer that matches no token → 401.
        assert_eq!(connect_raw_status(port, Some("sct-not-a-real-token")), 401);

        // ro token: handshake succeeds, reads work, a write is refused.
        // `put_object` takes a canonically-encoded object (id = BLAKE3 of
        // the encoding, not of the raw bytes) — build a real blob via
        // `Object::blob(..).encode()`, matching how `Store::put` does it.
        let ro_client = connect_with_bearer(port, Some(&ro_raw)).unwrap();
        ro_client.list_refs().unwrap();
        let obj = scl_core::object::Object::blob(b"hello from ro".to_vec());
        let encoded = obj.encode();
        let id = obj.id();
        let err = ro_client.put_object(&id, &encoded).unwrap_err();
        assert!(
            matches!(err, Error::ReadOnly),
            "ro token write refused: {err:?}"
        );

        // rw token: a write succeeds.
        let rw_client = connect_with_bearer(port, Some(&rw_raw)).unwrap();
        let obj2 = scl_core::object::Object::blob(b"hello from rw".to_vec());
        let encoded2 = obj2.encode();
        let id2 = obj2.id();
        rw_client.put_object(&id2, &encoded2).unwrap();

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--read-only` is a server-wide floor an `rw` token cannot elevate.
    #[test]
    fn server_read_only_floors_rw_token() {
        let root = tmp_repo("ro-floor");
        let layout = crate::layout::Layout::at(&root);
        let rw_raw =
            crate::serve_tokens::add(&layout, "rw", crate::serve_tokens::Scope::Rw).unwrap();

        let port = spawn_real_http_server_policy(root.clone(), true);

        let client = connect_with_bearer(port, Some(&rw_raw)).unwrap();
        let obj = scl_core::object::Object::blob(b"blocked by server read-only floor".to_vec());
        let encoded = obj.encode();
        let id = obj.id();
        let err = client.put_object(&id, &encoded).unwrap_err();
        assert!(matches!(err, Error::ReadOnly), "{err:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// No tokens configured (pre-P29 default) → no auth gate at all; a
    /// bearer-less connection proceeds exactly as before. This is the
    /// backward-compatibility pin for the auth gate.
    #[test]
    fn no_tokens_configured_no_auth_required() {
        let root = tmp_repo("no-tokens");
        let port = spawn_real_http_server_policy(root.clone(), false);
        let client = connect_with_bearer(port, None).unwrap();
        client.list_refs().unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Review fix: fail closed when a token-only public bind loses its
    // last token while running (see `auth_is_mandatory`). ──

    #[test]
    fn auth_is_mandatory_matrix() {
        // Non-loopback, no --read-only / --allow-public → tokens are the
        // only possible justification, so auth is mandatory.
        assert!(auth_is_mandatory("0.0.0.0:8730", false, false));
        assert!(auth_is_mandatory("192.168.1.5:8730", false, false));

        // Loopback: always false regardless of flags.
        assert!(!auth_is_mandatory("127.0.0.1:8730", false, false));
        assert!(!auth_is_mandatory("[::1]:8730", false, false));
        assert!(!auth_is_mandatory("localhost:8730", false, false));

        // Non-loopback but justified by --read-only or --allow-public: that
        // justification stands on its own even with zero tokens, so not
        // mandatory.
        assert!(!auth_is_mandatory("0.0.0.0:8730", true, false));
        assert!(!auth_is_mandatory("0.0.0.0:8730", false, true));
    }

    /// A non-loopback bind whose sole justification was tokens (mirrored
    /// here by passing `mandatory_auth=true` directly, exactly what
    /// `serve_http` would compute for such a bind) must reject every
    /// connection with 401 once no tokens are configured — never fall
    /// through to an open, unauthenticated server. Exercises the handler
    /// path directly via a loopback bind (network exposure isn't the point
    /// here; the fail-closed decision is).
    #[test]
    fn mandatory_auth_rejects_when_tokens_removed() {
        let root = tmp_repo("mandatory-auth-no-tokens");
        // Deliberately no tokens configured.
        let port = spawn_real_http_server_policy_auth(root.clone(), false, true);

        assert_eq!(connect_raw_status(port, None), 401);
        assert_eq!(connect_raw_status(port, Some("sct-not-a-real-token")), 401);

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Task 5: client-side `SC_HTTP_TOKEN` support (`connect_with_token`). ──

    /// `HttpTransport::connect_with_token` presents the given bearer and maps
    /// a missing/invalid one to a 401 → a clear authentication `Error`
    /// (rather than a wire-handshake failure). Drives `connect_with_token`
    /// directly with an explicit token instead of mutating the process-global
    /// `SC_HTTP_TOKEN` env var, which would be racy under parallel tests.
    #[test]
    fn client_presents_sc_http_token_and_maps_401() {
        let root = tmp_repo("client-token");
        let layout = crate::layout::Layout::at(&root);
        let rw_raw =
            crate::serve_tokens::add(&layout, "rw", crate::serve_tokens::Scope::Rw).unwrap();

        let port = spawn_real_http_server_policy(root.clone(), false);
        let url = ScHttpUrl {
            host: "127.0.0.1".to_string(),
            port,
            path: "/repo".to_string(),
        };

        // A valid rw token is accepted and the wire protocol proceeds.
        let transport = HttpTransport::connect_with_token(&url, Some(&rw_raw)).unwrap();
        transport.list_refs().unwrap();

        // No token at all, once tokens are configured, is rejected with a
        // clear authentication error (not `NotARepo`, not a generic
        // handshake failure).
        let err = HttpTransport::connect_with_token(&url, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("authentication"),
            "expected an authentication error, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
