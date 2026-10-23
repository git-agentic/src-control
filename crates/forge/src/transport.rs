//! Smart-HTTP git transport: `/{owner}/{repo}.git/...` served by `git http-backend` as a CGI.
//!
//! This module holds the parts that decide *what may be asked of git* and *how git's answer is
//! read*, as plain functions with tests: the path whitelist, the git-specific credential and
//! answer rules, the CGI header block parser, the environment filters, and the disk reservation
//! arithmetic. The process supervision lives in `cgi.rs`.
//!
//! The sub-path handed to the CGI is rebuilt from the whitelist, never from the client's string.

use crate::auth::{self, Cred};
use crate::http::{Req, Resp};
use crate::repos::{self, Access, Perm};
use crate::routes::App;
use crate::scope::{self, Cat, Level, Need};
use crate::store::{self, User};

/// What a git request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sub {
    InfoRefs,
    UploadPack,
    ReceivePack,
    Head,
    InfoPacks,
    /// `objects/xx/<rest>`: the relative path (validated hex).
    Loose(String),
    /// `objects/pack/pack-<hex>.pack|idx`.
    Pack(String),
}

impl Sub {
    /// The `PATH_INFO` for the CGI, rebuilt from the whitelist.
    pub fn path_info(&self) -> String {
        match self {
            Sub::InfoRefs => "/info/refs".into(),
            Sub::UploadPack => "/git-upload-pack".into(),
            Sub::ReceivePack => "/git-receive-pack".into(),
            Sub::Head => "/HEAD".into(),
            Sub::InfoPacks => "/objects/info/packs".into(),
            Sub::Loose(p) | Sub::Pack(p) => format!("/{p}"),
        }
    }

    /// The HTTP method this sub-path accepts.
    pub fn method(&self) -> &'static str {
        match self {
            Sub::UploadPack | Sub::ReceivePack => "POST",
            _ => "GET",
        }
    }
}

/// A parsed `/{owner}/{repo}.git/{sub}` request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPath {
    pub owner: String,
    pub repo: String,
    pub sub: Sub,
}

/// Is `p` a path this server routes to the transport?
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Not a git path at all (the ordinary router handles it).
    NotGit,
    /// A `/{o}/{r}.git/...` path that is not on the whitelist: 404.
    Unknown,
    Git(GitPath),
}

fn name_chars_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn is_hex(s: &str, len: &[usize]) -> bool {
    len.contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sub_of(rest: &str) -> Option<Sub> {
    Some(match rest {
        "info/refs" => Sub::InfoRefs,
        "git-upload-pack" => Sub::UploadPack,
        "git-receive-pack" => Sub::ReceivePack,
        "HEAD" => Sub::Head,
        "objects/info/packs" => Sub::InfoPacks,
        _ => {
            let parts: Vec<&str> = rest.split('/').collect();
            match parts.as_slice() {
                ["objects", d, f] if is_hex(d, &[2]) && is_hex(f, &[38, 62]) => {
                    Sub::Loose(rest.to_string())
                }
                ["objects", "pack", f] => {
                    let stem = f.strip_prefix("pack-")?;
                    let (hex, ext) = stem.rsplit_once('.')?;
                    (is_hex(hex, &[40, 64]) && matches!(ext, "pack" | "idx"))
                        .then(|| Sub::Pack(rest.to_string()))?
                }
                _ => return None,
            }
        }
    })
}

/// Classify a request path. The owner and repository segments are percent-decoded and must be
/// plain name characters (so no `/`, `..` or control character can come out of a decode); the
/// rest must match the whitelist exactly, byte for byte, with no escapes.
pub fn parse(path: &str) -> Route {
    let Some(p) = path.strip_prefix('/') else {
        return Route::NotGit;
    };
    let mut it = p.splitn(3, '/');
    let (Some(owner), Some(repo_git)) = (it.next(), it.next()) else {
        return Route::NotGit;
    };
    let Some(repo_enc) = repo_git.strip_suffix(".git") else {
        return Route::NotGit;
    };
    let rest = it.next().unwrap_or("");
    let (Some(owner), Some(repo)) = (
        crate::routes::percent_decode(owner),
        crate::routes::percent_decode(repo_enc),
    ) else {
        return Route::Unknown;
    };
    if !name_chars_ok(&owner)
        || !name_chars_ok(&repo)
        || [&owner, &repo].iter().any(|n| *n == "." || *n == "..")
    {
        return Route::Unknown;
    }
    match sub_of(rest) {
        Some(sub) => Route::Git(GitPath { owner, repo, sub }),
        None => Route::Unknown,
    }
}

/// The service an `info/refs` or RPC request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Upload,
    Receive,
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Service::Upload => "git-upload-pack",
            Service::Receive => "git-receive-pack",
        }
    }
}

/// An `info/refs` request without a valid smart `service` parameter.
#[derive(Debug, PartialEq, Eq)]
pub struct NotSmart;

/// The service a path asks for: from the sub-path, or for `info/refs` from `?service=`. A smart
/// `info/refs` without a valid `service` (git's dumb listing) is not served: it would ignore
/// `transfer.hideRefs`.
pub fn service_of(sub: &Sub, query_service: Option<&str>) -> Result<Option<Service>, NotSmart> {
    match sub {
        Sub::UploadPack => Ok(Some(Service::Upload)),
        Sub::ReceivePack => Ok(Some(Service::Receive)),
        Sub::InfoRefs => match query_service {
            Some("git-upload-pack") => Ok(Some(Service::Upload)),
            Some("git-receive-pack") => Ok(Some(Service::Receive)),
            _ => Err(NotSmart),
        },
        _ => Ok(None),
    }
}

// ---- answers (plain text, the recorded Gitea bodies) ----

const TEXT: &str = "text/plain;charset=utf-8";

/// The `Cache-Control` Gitea sends on its 401s and on the results of the RPC endpoints (recorded
/// V#1/3/16/18/20/21).
pub const PRIVATE_CACHE: &str = "max-age=0, private, must-revalidate, no-transform";

fn text(status: u16, body: &str) -> Resp {
    Resp {
        status,
        headers: vec![("content-type", TEXT.into())],
        body: body.as_bytes().to_vec(),
        delay: std::time::Duration::ZERO,
    }
}

/// 401 for a request with no credentials: asks the client to authenticate.
pub fn unauthorized() -> Resp {
    text(401, "Unauthorized\n")
        .with("www-authenticate", "Basic realm=\"Gitea\"".into())
        .with("cache-control", PRIVATE_CACHE.into())
}

/// 401 for a credential that does not verify (unknown, expired, or a password).
pub fn bad_credentials() -> Resp {
    text(401, "Verify\n").with("cache-control", PRIVATE_CACHE.into())
}

/// 403: authenticated, but the token's scope or the caller's permission is not enough.
pub fn forbidden() -> Resp {
    text(403, "Forbidden\n")
}

/// 404: no such repository, or none the caller may see (one answer).
pub fn repo_not_found() -> Resp {
    text(404, "Repository not found")
}

/// 404 for a path under a repository that is not on the whitelist.
pub fn not_found() -> Resp {
    text(404, "Not Found\n")
}

/// 405 for a method the sub-path does not accept.
pub fn method_not_allowed(allow: &str) -> Resp {
    text(405, "Method Not Allowed\n").with("allow", allow.into())
}

// ---- credentials ----

/// The token a git request presents, in any recorded form (`token`/`Bearer` header, Basic with
/// the token as the password under any username, or the token as the username with an empty
/// password). A Basic password that is not a token is simply a token that will not verify: git
/// transport never accepts a user password.
pub fn credential(cred: &Cred) -> Option<&str> {
    match cred {
        Cred::Anonymous => None,
        Cred::Header(t) => Some(t),
        Cred::Basic { user, pass } => Some(if pass.is_empty() { user } else { pass }),
    }
}

/// What a request is allowed to do, decided before any process exists.
pub struct Plan {
    pub user: User,
    pub access: Access,
    pub path: GitPath,
    pub service: Option<Service>,
    /// `REMOTE_USER` may be set (the write check passed): receive-pack only.
    pub may_write: bool,
}

/// Authenticate, check scope, resolve the repository and the caller's permission, in the one order
/// every git request follows: credentials (401), method (405), a valid smart service (404), scope
/// (403), repository and existence (404 for missing, not-live or invisible alike), permission (403).
pub fn authorize(app: &App, req: &Req, path: GitPath) -> Result<Plan, Resp> {
    let conn = crate::db::connect(&app.data_dir).map_err(|e| internal(app, &e))?;
    let cred = auth::parse(req);
    let Some(secret) = credential(&cred) else {
        return Err(unauthorized());
    };
    let (user, token) = match store::resolve_token(&conn, secret, crate::timefmt::now()) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(bad_credentials()),
        Err(e) => return Err(internal(app, &e)),
    };
    if req.method != path.sub.method() {
        return Err(method_not_allowed(path.sub.method()));
    }
    // After credentials and method, so the fixed error order holds for a malformed `service` too.
    let service = service_of(&path.sub, req.param("service")).map_err(|NotSmart| not_found())?;
    let (needs_write, perm) = match service {
        Some(Service::Receive) => (true, Perm::Write),
        _ => (false, Perm::Read),
    };
    let need = Need(
        Cat::Repository,
        if needs_write {
            Level::Write
        } else {
            Level::Read
        },
    );
    if scope::public_only(&token.scopes) || !scope::allows(&token.scopes, need) {
        return Err(forbidden());
    }
    let access = match repos::resolve(&conn, &user, &path.owner, &path.repo) {
        Ok(Some(a)) => a,
        Ok(None) => return Err(repo_not_found()),
        Err(e) => return Err(internal(app, &e)),
    };
    if access.perm < perm {
        return Err(forbidden());
    }
    Ok(Plan {
        user,
        access,
        path,
        service,
        may_write: needs_write,
    })
}

fn internal(app: &App, e: &dyn std::fmt::Display) -> Resp {
    eprintln!("sc-forge: internal error: {e}");
    let _ = app;
    text(500, "internal server error\n")
}

// ---- the CGI response ----

/// A parsed CGI response head.
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    /// Headers worth forwarding (whitelisted, validated).
    pub headers: Vec<(String, String)>,
}

/// Response headers forwarded from the CGI; everything else (hop-by-hop, `Status`, anything
/// unexpected) is dropped.
const FORWARD: [&str; 7] = [
    "content-type",
    "cache-control",
    "expires",
    "pragma",
    "last-modified",
    "etag",
    "content-encoding",
];

/// Parse a CGI header block (`Name: value` lines ended by a blank line, LF or CRLF). `Status:`
/// sets the status (default 200). Returns the head and the number of bytes consumed, or `None`
/// when the block is not complete yet. `Err` when it is malformed.
pub fn parse_head(buf: &[u8]) -> Result<Option<(Head, usize)>, &'static str> {
    let end = match buf
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|i| i + 2)
        .into_iter()
        .chain(buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4))
        .min()
    {
        Some(e) => e,
        None => {
            return if buf.len() > 16 * 1024 {
                Err("response header block too large")
            } else {
                Ok(None)
            }
        }
    };
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| "response headers are not UTF-8")?;
    let mut head = Head {
        status: 200,
        headers: Vec::new(),
    };
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (k, v) = line
            .split_once(':')
            .ok_or("malformed response header line")?;
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "status" {
            head.status = v
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .filter(|s| (100..600).contains(s))
                .ok_or("malformed Status")?;
        } else if FORWARD.contains(&k.as_str()) && !v.bytes().any(|b| b < 0x20 || b == 0x7f) {
            head.headers.push((k, v.to_string()));
        }
    }
    Ok(Some((head, end)))
}

// ---- the CGI environment ----

/// `Git-Protocol` is passed to git only in the form `version=N` with optional `:key=value` parts
/// of safe characters, at most 128 bytes.
pub fn protocol_header(v: Option<&str>) -> Option<String> {
    let v = v?;
    let rest = v.strip_prefix("version=")?;
    let (num, tail) = rest.split_once(':').map_or((rest, ""), |(n, t)| (n, t));
    let ok = v.len() <= 128
        && !num.is_empty()
        && num.bytes().all(|b| b.is_ascii_digit())
        && tail
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b':' | b'_' | b'.' | b'-'));
    ok.then(|| v.to_string())
}

/// A request `Content-Type` is passed through only as a short printable-ASCII value.
pub fn content_type(v: Option<&str>) -> Option<String> {
    let v = v?;
    (v.len() <= 128 && v.bytes().all(|b| (0x20..0x7f).contains(&b))).then(|| v.to_string())
}

/// Free bytes on the filesystem holding `path`.
pub fn free_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains NUL"))?;
    // SAFETY: statvfs fills the zeroed struct for a valid NUL-terminated path.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Accounting of disk promised to pushes in flight. A reservation is accounting, not
/// enforcement: a push can still write more than it reserved (bounded by `receive.maxInputSize`
/// and `RLIMIT_FSIZE`); a hard guarantee needs filesystem quotas.
#[derive(Default)]
pub struct Reserve {
    held: std::sync::Mutex<u64>,
}

/// Bytes held for one push; returned on drop.
pub struct Held {
    pool: std::sync::Arc<Reserve>,
    bytes: u64,
}

impl Reserve {
    /// Try to hold `need` more bytes given `free` bytes on disk and a `floor` that must stay free.
    fn try_hold(&self, free: u64, floor: u64, need: u64) -> bool {
        let mut h = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if free.saturating_sub(*h) < floor.saturating_add(need) {
            return false;
        }
        *h += need;
        true
    }

    /// Reserve `need` bytes for a push, or `None` when the disk cannot promise it (507).
    pub fn reserve(self: &std::sync::Arc<Self>, free: u64, floor: u64, need: u64) -> Option<Held> {
        // lazy `then`: a refused reservation must not build a guard whose drop returns bytes never held
        self.try_hold(free, floor, need).then(|| Held {
            pool: self.clone(),
            bytes: need,
        })
    }

    /// Total currently promised.
    pub fn held(&self) -> u64 {
        *self.held.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Held {
    /// Grow the reservation by `more` bytes as a push proceeds; `false` when the disk cannot
    /// promise it (the push is aborted).
    pub fn grow(&mut self, free: u64, floor: u64, more: u64) -> bool {
        if self.pool.try_hold(free, floor, more) {
            self.bytes += more;
            true
        } else {
            false
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut h = self.pool.held.lock().unwrap_or_else(|e| e.into_inner());
        *h = h.saturating_sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(path: &str) -> GitPath {
        match parse(path) {
            Route::Git(g) => g,
            other => panic!("{path}: {other:?}"),
        }
    }

    #[test]
    fn the_whitelist_accepts_exactly_the_recorded_shapes() {
        assert_eq!(git("/acme/alpha.git/info/refs").sub, Sub::InfoRefs);
        assert_eq!(git("/acme/alpha.git/git-upload-pack").sub, Sub::UploadPack);
        assert_eq!(
            git("/acme/alpha.git/git-receive-pack").sub,
            Sub::ReceivePack
        );
        assert_eq!(git("/acme/alpha.git/HEAD").sub, Sub::Head);
        assert_eq!(
            git("/acme/alpha.git/objects/info/packs").sub,
            Sub::InfoPacks
        );
        let loose = format!("objects/ab/{}", "c".repeat(38));
        assert_eq!(
            git(&format!("/acme/alpha.git/{loose}")).sub,
            Sub::Loose(loose.clone())
        );
        assert_eq!(
            git(&format!("/acme/alpha.git/{loose}")).sub.path_info(),
            format!("/{loose}")
        );
        let pack = format!("objects/pack/pack-{}.idx", "0".repeat(40));
        assert_eq!(git(&format!("/acme/alpha.git/{pack}")).sub, Sub::Pack(pack));
        let g = git("/Acme/Alpha-1.x.git/info/refs");
        assert_eq!((g.owner.as_str(), g.repo.as_str()), ("Acme", "Alpha-1.x"));
    }

    #[test]
    fn everything_else_under_a_git_path_is_unknown_and_never_reaches_the_cgi() {
        for bad in [
            "/acme/alpha.git/",
            "/acme/alpha.git",
            "/acme/alpha.git/config",
            "/acme/alpha.git/.git/config",
            "/acme/alpha.git/hooks/pre-receive",
            "/acme/alpha.git/info/refs/",
            "/acme/alpha.git/info/refs/x",
            "/acme/alpha.git//info/refs",
            "/acme/alpha.git/../beta.git/info/refs",
            "/acme/alpha.git/objects/info/alternates",
            "/acme/alpha.git/objects/ab/short",
            "/acme/alpha.git/objects/AB/cccccccccccccccccccccccccccccccccccccc",
            "/acme/alpha.git/objects/ab/gggggggggggggggggggggggggggggggggggggg",
            "/acme/alpha.git/objects/pack/pack-zz.pack",
            "/acme/alpha.git/objects/pack/other.pack",
            "/acme/alpha.git/refs/heads/main",
            "/acme/alpha.git/git-upload-pack%2f..%2f",
            "/acme/alpha.git/info%2Frefs",
            "/acme/alpha.git/HEAD/x",
            "/acme/alpha.git/git-receive-pack/",
        ] {
            assert_eq!(parse(bad), Route::Unknown, "{bad}");
        }
    }

    #[test]
    fn owner_and_repo_segments_cannot_smuggle_separators_or_traversal() {
        for bad in [
            "/%2e%2e/alpha.git/info/refs",
            "/acme/%2e%2e.git/info/refs",
            "/acme/al%2Fpha.git/info/refs",
            "/ac%00me/alpha.git/info/refs",
            "/acme/alpha%0d%0a.git/info/refs",
            "/a cme/alpha.git/info/refs",
            "//alpha.git/info/refs",
            "/acme/.git/info/refs",
            "/acme/%zz.git/info/refs",
        ] {
            assert!(
                matches!(parse(bad), Route::Unknown | Route::NotGit),
                "{bad}: {:?}",
                parse(bad)
            );
        }
        // dotted names are legal repository names, and the encoded form decodes to the same name
        assert_eq!(git("/acme/.hidden.git/info/refs").repo, ".hidden");
        assert_eq!(git("/acme/a%2Db.git/info/refs").repo, "a-b");
    }

    #[test]
    fn non_git_paths_fall_through_to_the_ordinary_router() {
        for p in [
            "/",
            "/api/v1/user",
            "/acme/alpha",
            "/acme",
            "/acme/alpha/info/refs",
            "healthz",
            "/api/healthz",
        ] {
            assert_eq!(parse(p), Route::NotGit, "{p}");
        }
    }

    #[test]
    fn info_refs_needs_a_smart_service() {
        assert_eq!(
            service_of(&Sub::InfoRefs, Some("git-upload-pack")),
            Ok(Some(Service::Upload))
        );
        assert_eq!(
            service_of(&Sub::InfoRefs, Some("git-receive-pack")),
            Ok(Some(Service::Receive))
        );
        assert_eq!(
            service_of(&Sub::InfoRefs, None),
            Err(NotSmart),
            "git's dumb listing ignores hideRefs"
        );
        assert_eq!(
            service_of(&Sub::InfoRefs, Some("git-upload-archive")),
            Err(NotSmart)
        );
        assert_eq!(
            service_of(&Sub::UploadPack, None),
            Ok(Some(Service::Upload))
        );
        assert_eq!(service_of(&Sub::Head, None), Ok(None));
    }

    #[test]
    fn methods_follow_the_sub_path() {
        assert_eq!(Sub::UploadPack.method(), "POST");
        assert_eq!(Sub::ReceivePack.method(), "POST");
        assert_eq!(Sub::InfoRefs.method(), "GET");
        assert_eq!(Sub::Head.method(), "GET");
    }

    #[test]
    fn every_token_form_is_extracted_and_a_password_is_just_a_token_that_will_not_verify() {
        assert_eq!(credential(&Cred::Header("t".into())), Some("t"));
        assert_eq!(
            credential(&Cred::Basic {
                user: "oauth2".into(),
                pass: "t".into()
            }),
            Some("t")
        );
        assert_eq!(
            credential(&Cred::Basic {
                user: "t".into(),
                pass: String::new()
            }),
            Some("t")
        );
        assert_eq!(credential(&Cred::Anonymous), None);
    }

    #[test]
    fn the_cgi_head_parser_reads_status_and_forwards_only_whitelisted_headers() {
        let raw = b"Status: 403 Forbidden\r\nContent-Type: text/plain\r\nX-Evil: 1\r\nSet-Cookie: a=b\r\nCache-Control: no-cache\r\n\r\nbody";
        let (h, n) = parse_head(raw).unwrap().unwrap();
        assert_eq!(h.status, 403);
        assert_eq!(
            h.headers,
            vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("cache-control".to_string(), "no-cache".to_string())
            ]
        );
        assert_eq!(&raw[n..], b"body");
        let (h, _) = parse_head(b"Content-Type: application/x-git-upload-pack-advertisement\nExpires: Fri, 01 Jan 1980 00:00:00 GMT\n\nx").unwrap().unwrap();
        assert_eq!(
            (h.status, h.headers.len()),
            (200, 2),
            "bare LF and a default status of 200"
        );
        assert_eq!(
            parse_head(b"Content-Type: a\r\n").unwrap(),
            None,
            "incomplete"
        );
        assert!(parse_head(b"no colon here\n\n").is_err());
        assert!(parse_head(b"Status: banana\n\n").is_err());
        assert!(parse_head(b"Status: 99\n\n").is_err());
        assert!(
            parse_head(&vec![b'a'; 20_000]).is_err(),
            "an unterminated header block is bounded"
        );
        let (h, _) = parse_head(b"Content-Type: x\x01y\n\n").unwrap().unwrap();
        assert!(
            h.headers.is_empty(),
            "a header value with control characters is dropped"
        );
    }

    #[test]
    fn the_protocol_header_is_filtered() {
        assert_eq!(protocol_header(Some("version=2")), Some("version=2".into()));
        assert_eq!(
            protocol_header(Some("version=2:object-format=sha1")),
            Some("version=2:object-format=sha1".into())
        );
        for bad in [
            "",
            "version=",
            "version=x",
            "version=2\r\nX: y",
            "foo",
            "version=2:a b",
            &format!("version=2:{}", "a".repeat(200)),
        ] {
            assert_eq!(protocol_header(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(protocol_header(None), None);
    }

    #[test]
    fn content_types_are_short_printable_ascii() {
        assert!(content_type(Some("application/x-git-upload-pack-request")).is_some());
        assert!(
            content_type(Some("a\r\nb")).is_none()
                && content_type(Some(&"a".repeat(200))).is_none()
                && content_type(None).is_none()
        );
    }

    #[test]
    fn the_reservation_never_overcommits_and_returns_on_drop() {
        let r = std::sync::Arc::new(Reserve::default());
        let a = r
            .reserve(1000, 100, 400)
            .expect("first fits: 1000 free, floor 100, need 400");
        assert_eq!(r.held(), 400);
        let b = r
            .reserve(1000, 100, 400)
            .expect("second fits: (1000-400) >= 100+400");
        assert!(
            r.reserve(1000, 100, 101).is_none(),
            "1000 - 800 < 100 + 101: refuse (507), do not overcommit"
        );
        assert!(
            r.reserve(1000, 100, 100).is_some(),
            "but exactly the remainder above the floor still fits"
        );
        drop(a);
        assert_eq!(r.held(), 400);
        let mut c = r.reserve(1000, 100, 100).unwrap();
        assert!(c.grow(1000, 100, 300), "(1000-500) >= 100+300");
        assert!(
            !c.grow(1000, 100, 300),
            "the next step does not fit: the push is aborted"
        );
        drop((b, c));
        assert_eq!(r.held(), 0, "everything is returned");
    }

    #[test]
    fn free_space_is_readable() {
        assert!(free_bytes(&std::env::temp_dir()).unwrap() > 0);
        assert!(free_bytes(std::path::Path::new("/definitely/not/here")).is_err());
    }
}
