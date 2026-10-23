//! Credential parsing and resolution. Two route classes exist (see the spec's
//! "Authentication"): token routes accept access tokens only, and the token
//! management routes accept the user's password only. A Basic password is never
//! tried as a token on a password route and never as a password on a token
//! route, so a stolen token cannot mint tokens and a password cannot be used
//! against ordinary APIs.

use crate::http::{error, signed_in_only, Req, Resp};
use crate::routes::App;
use crate::store::{self, User};
use rusqlite::Connection;
use scl_crypto::verify_password;

/// What the `Authorization` header carried.
pub enum Cred {
    Anonymous,
    /// `token X` or `Bearer X`.
    Header(String),
    /// `Basic user:pass`.
    Basic {
        user: String,
        pass: String,
    },
}

/// The authenticated caller.
pub struct Authed {
    pub user: User,
    /// Token scopes; `None` when the caller proved a password (full scope).
    pub scopes: Option<Vec<String>>,
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Parse the `Authorization` header. A malformed value is anonymous.
pub fn parse(req: &Req) -> Cred {
    let Some(h) = req.header("authorization") else {
        return Cred::Anonymous;
    };
    let Some((scheme, rest)) = h.split_once(' ') else {
        return Cred::Anonymous;
    };
    let rest = rest.trim();
    match scheme.to_ascii_lowercase().as_str() {
        "token" | "bearer" if !rest.is_empty() => Cred::Header(rest.to_string()),
        "basic" => {
            let Some(raw) = b64_decode(rest).and_then(|b| String::from_utf8(b).ok()) else {
                return Cred::Anonymous;
            };
            match raw.split_once(':') {
                Some((u, p)) => Cred::Basic {
                    user: u.to_string(),
                    pass: p.to_string(),
                },
                None => Cred::Basic {
                    user: raw,
                    pass: String::new(),
                },
            }
        }
        _ => Cred::Anonymous,
    }
}

/// The name echoed in a 401 is whatever the caller sent; cap it.
fn shown(name: &str) -> String {
    name.chars().take(80).collect()
}

fn unknown_user(app: &App, name: &str) -> Resp {
    error(
        &app.base,
        401,
        &format!("user does not exist [uid: 0, name: {}]", shown(name)),
    )
}

/// Resolve a token credential (`token`/`Bearer` header, a Basic password that
/// is a token under any username, or a token as the Basic username with an
/// empty password).
pub fn by_token(app: &App, conn: &Connection, cred: &Cred, now: i64) -> Result<Authed, Resp> {
    let (secret, shown_name) = match cred {
        Cred::Anonymous => return Err(signed_in_only()),
        Cred::Header(t) => (t.as_str(), ""),
        Cred::Basic { user, pass } if pass.is_empty() => (user.as_str(), user.as_str()),
        Cred::Basic { pass, user } => (pass.as_str(), user.as_str()),
    };
    match store::resolve_token(conn, secret, now) {
        Ok(Some((user, tok))) => Ok(Authed {
            user,
            scopes: Some(tok.scopes),
        }),
        Ok(None) => Err(match cred {
            // A Basic password that is not a token: say what this route takes.
            Cred::Basic { pass, .. } if !pass.is_empty() => error(
                &app.base,
                401,
                &format!(
                    "auth required: this route accepts access tokens only [uid: 0, name: {}]",
                    shown(shown_name)
                ),
            ),
            _ => unknown_user(app, shown_name),
        }),
        Err(e) => Err(app.internal(&e)),
    }
}

/// Resolve the user's password (`Basic login:password`). Every failure answers
/// the same text, runs one full Argon2 verification (against a dummy hash for
/// an unknown login), is counted for backoff, and is delayed.
pub fn by_password(app: &App, conn: &Connection, req: &Req, cred: &Cred) -> Result<Authed, Resp> {
    let Cred::Basic { user: login, pass } = cred else {
        return Err(error(
            &app.base,
            401,
            "Basic authentication with the user's password is required",
        )
        .with("www-authenticate", "Basic realm=\"sc-forge\"".into()));
    };
    if !app.backoff.begin(req.source) {
        return Err(error(
            &app.base,
            429,
            "too many failed password attempts from this address",
        )
        .with("retry-after", "60".into()));
    }
    let found = match store::find_by_login(conn, login) {
        Ok(u) => u.filter(|u| !u.is_org),
        Err(e) => {
            app.backoff.cancel(req.source);
            return Err(app.internal(&e));
        }
    };
    let ok = {
        let _slot = app.gate.acquire();
        verify_password(pass, found.as_ref().map(|u| u.password_hash.as_str()))
    };
    match (ok, found) {
        (true, Some(user)) => {
            app.backoff.success(login, req.source);
            if user.must_change_password {
                return Err(error(
                    &app.base,
                    403,
                    "You must change your password before using the API",
                ));
            }
            Ok(Authed { user, scopes: None })
        }
        _ => {
            let delay = app.backoff.failure(login, req.source);
            Err(error(&app.base, 401, "invalid username or password").delayed(delay))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_basic_credentials() {
        assert_eq!(b64_decode("YWxpY2U6cHc=").unwrap(), b"alice:pw");
        assert_eq!(b64_decode("YWxpY2U6").unwrap(), b"alice:");
        assert!(b64_decode("not base64!").is_none());
    }
}
