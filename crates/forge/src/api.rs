//! F1 handlers: version, current user, users, admin users, organizations,
//! access tokens. Authentication, scope and actor rules already passed in
//! `routes::dispatch`; handlers add only the per-resource rules.

use crate::http::{error, not_found, Resp};
use crate::names::{self, NameError};
use crate::routes::Ctx;
use crate::store::{self, NewAccount, StoreError, User, UserPatch};
use crate::timefmt::{now, rfc3339};
use scl_crypto::hash_password;
use serde_json::{json, Value};

/// The Gitea release whose behaviour `sc-forge` reproduces; clients may sniff it.
pub const GITEA_VERSION: &str = "1.22.6";

const DEFAULT_PAGE: i64 = 30;
const MAX_PAGE: i64 = 50;

pub(crate) fn user_json(base: &str, u: &User) -> Value {
    json!({
        "id": u.id,
        "login": u.login,
        "login_name": u.login_name,
        "source_id": 0,
        "full_name": u.full_name,
        "email": u.email,
        "avatar_url": format!("{base}/avatars/{}", u.login.to_lowercase()),
        "html_url": format!("{base}/{}", u.login),
        "language": "",
        "is_admin": u.is_admin,
        "last_login": rfc3339(u.created),
        "created": rfc3339(u.created),
        "restricted": false,
        "active": true,
        "prohibit_login": false,
        "location": u.location,
        "website": u.website,
        "description": u.description,
        "visibility": u.visibility,
        "followers_count": 0,
        "following_count": 0,
        "starred_repos_count": 0,
        "username": u.login,
    })
}

pub(crate) fn org_json(base: &str, o: &User) -> Value {
    json!({
        "id": o.id,
        "name": o.login,
        "full_name": o.full_name,
        "email": o.email,
        "avatar_url": format!("{base}/avatars/{}", o.login.to_lowercase()),
        "description": o.description,
        "website": o.website,
        "location": o.location,
        "visibility": o.visibility,
        "repo_admin_change_team_access": false,
        "username": o.login,
    })
}

pub(crate) fn no_such_user(ctx: &Ctx, name: &str) -> Resp {
    error(
        &ctx.app.base,
        404,
        &format!("user redirect does not exist [name: {name}]"),
    )
}

/// The recorded 404 for an organization that does not exist.
pub fn org_missing(app: &crate::routes::App, name: &str) -> Resp {
    not_found(
        &app.base,
        "GetOrgByName",
        Some(&format!("user redirect does not exist [name: {name}]")),
    )
}

pub(crate) fn no_such_org(ctx: &Ctx, name: &str) -> Resp {
    org_missing(ctx.app, name)
}

/// A JSON object body; an empty body is `{}`.
pub(crate) fn body(ctx: &Ctx) -> Result<Value, Resp> {
    if ctx.req.body.is_empty() {
        return Ok(json!({}));
    }
    match serde_json::from_slice::<Value>(&ctx.req.body) {
        Ok(v) if v.is_object() => Ok(v),
        _ => Err(error(&ctx.app.base, 400, "invalid JSON body")),
    }
}

pub(crate) fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(String::from)
}

pub(crate) fn page_params(ctx: &Ctx) -> (i64, i64) {
    let num = |k: &str| ctx.req.param(k).and_then(|v| v.parse::<i64>().ok());
    // Page is clamped so offset arithmetic cannot overflow.
    let page = num("page")
        .filter(|p| *p >= 1)
        .unwrap_or(1)
        .min(1_000_000_000);
    let limit = num("limit")
        .filter(|l| *l >= 1)
        .unwrap_or(DEFAULT_PAGE)
        .min(MAX_PAGE);
    (page, limit)
}

/// 200 with `X-Total-Count` and Gitea's `Link` header.
pub(crate) fn paged(
    ctx: &Ctx,
    path: &str,
    total: i64,
    page: i64,
    limit: i64,
    items: Vec<Value>,
) -> Resp {
    paged_with(ctx, path, total, page, limit, &[], items)
}

/// Percent-encode everything except the RFC 3986 unreserved characters, so a value can sit inside
/// a `<...>` link target without being able to close it or start another entry.
pub(crate) fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Like [`paged`], carrying `extra` query parameters (already strictly percent-encoded with [`pct_encode`], in the order
/// Gitea emits them: alphabetical after `limit` and `page`) into every `Link` URL, so following
/// a page link repeats the same query.
pub(crate) fn paged_with(
    ctx: &Ctx,
    path: &str,
    total: i64,
    page: i64,
    limit: i64,
    extra: &[(&str, String)],
    items: Vec<Value>,
) -> Resp {
    let mut r = Resp::json(200, &Value::Array(items)).with("x-total-count", total.to_string());
    if let Some(l) = link_header(ctx, path, total, page, limit, extra) {
        r = r.with("link", l);
    }
    r
}

/// Gitea's `Link` header value for page `page` of `total` rows, or `None` when there is one page.
pub(crate) fn link_header(
    ctx: &Ctx,
    path: &str,
    total: i64,
    page: i64,
    limit: i64,
    extra: &[(&str, String)],
) -> Option<String> {
    let tail: String = extra.iter().map(|(k, v)| format!("&{k}={v}")).collect();
    let last = ((total + limit - 1) / limit).max(1);
    let url = |p: i64, rel: &str| {
        format!(
            "<{}/api/v1{path}?limit={limit}&page={p}{tail}>; rel=\"{rel}\"",
            ctx.app.base
        )
    };
    let mut links = Vec::new();
    if page < last {
        links.push(url(page + 1, "next"));
        links.push(url(last, "last"));
    }
    if page > 1 {
        links.push(url(1, "first"));
        links.push(url(page - 1, "prev"));
    }
    (!links.is_empty()).then(|| links.join(","))
}

/// Like [`paged`], but a page link repeats *every* request parameter, alphabetically by name (what
/// Gitea does for the commits listing), with `limit` and `page` set to the link's own values.
pub(crate) fn paged_sorted(
    ctx: &Ctx,
    path: &str,
    total: i64,
    page: i64,
    limit: i64,
    items: Vec<Value>,
) -> Resp {
    let mut q: std::collections::BTreeMap<String, String> = ctx
        .req
        .query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), v.to_string())
        })
        .rev() // the request parser reads the first value of a repeated parameter; the last insert wins
        .collect();
    q.insert("limit".into(), limit.to_string());
    let last = ((total + limit - 1) / limit).max(1);
    // Gitea builds the links from the clamped page: asking past the end still points `prev` at the
    // page before the last.
    let page = page.min(last);
    let mut url = |p: i64, rel: &str| {
        q.insert("page".into(), p.to_string());
        let query: Vec<String> = q.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!(
            "<{}/api/v1{path}?{}>; rel=\"{rel}\"",
            ctx.app.base,
            query.join("&")
        )
    };
    let mut links = Vec::new();
    if page < last {
        links.push(url(page + 1, "next"));
        links.push(url(last, "last"));
    }
    if page > 1 {
        links.push(url(1, "first"));
        links.push(url(page - 1, "prev"));
    }
    let mut r = Resp::json(200, &Value::Array(items)).with("x-total-count", total.to_string());
    if !links.is_empty() {
        r = r.with("link", links.join(","));
    }
    r
}

/// `GET /version`: the Gitea release whose behaviour this server reproduces.
pub fn version(_: &mut Ctx) -> Resp {
    Resp::json(200, &json!({"version": GITEA_VERSION}))
}

/// Handler for routes whose policy is declared but whose slice has not landed: 501 after authentication, scope and actor checks.
pub fn not_implemented(ctx: &mut Ctx) -> Resp {
    error(&ctx.app.base, 501, "not implemented yet")
}

/// `GET /user`: the authenticated caller.
pub fn current_user(ctx: &mut Ctx) -> Resp {
    Resp::json(200, &user_json(&ctx.app.base, &ctx.who.user))
}

/// `GET /users/{u}`: a user (or organization) by login; private users are visible to themselves and site admins only.
pub fn get_user(ctx: &mut Ctx) -> Resp {
    let name = ctx.param("u").to_string();
    match store::find_by_login(ctx.conn, &name) {
        Ok(Some(u)) => {
            let me = &ctx.who.user;
            if u.visibility == "private" && u.id != me.id && !me.is_admin {
                return no_such_user(ctx, &name);
            }
            Resp::json(200, &user_json(&ctx.app.base, &u))
        }
        Ok(None) => no_such_user(ctx, &name),
        Err(e) => ctx.app.internal(&e),
    }
}

/// Visible to the caller: public and limited organizations to any signed-in
/// caller, private ones to owners and site admins.
pub(crate) fn org_visible(ctx: &Ctx, org: &User) -> rusqlite::Result<bool> {
    let me = &ctx.who.user;
    Ok(org.visibility != "private" || me.is_admin || store::is_org_owner(ctx.conn, org.id, me.id)?)
}

/// `GET /orgs/{o}`: an organization, subject to its visibility.
pub fn get_org(ctx: &mut Ctx) -> Resp {
    let name = ctx.param("o").to_string();
    let org = match store::find_by_login(ctx.conn, &name) {
        Ok(Some(o)) if o.is_org => o,
        Ok(_) => return no_such_org(ctx, &name),
        Err(e) => return ctx.app.internal(&e),
    };
    match org_visible(ctx, &org) {
        Ok(true) => Resp::json(200, &org_json(&ctx.app.base, &org)),
        Ok(false) => not_found(&ctx.app.base, "HasOrgOrUserVisible", None),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `GET /users/{u}/orgs/{o}/permissions`: what `{u}` may do in `{o}`; hides private organizations and users from callers who cannot see them.
pub fn org_permissions(ctx: &mut Ctx) -> Resp {
    let (uname, oname) = (ctx.param("u").to_string(), ctx.param("o").to_string());
    let subject = match store::find_by_login(ctx.conn, &uname) {
        Ok(Some(u)) if !u.is_org => u,
        Ok(_) => return no_such_user(ctx, &uname),
        Err(e) => return ctx.app.internal(&e),
    };
    // A hidden subject answers like a missing one, before the organization is
    // resolved, so the two cannot be told apart.
    let me = &ctx.who.user;
    if subject.visibility == "private" && subject.id != me.id && !me.is_admin {
        return no_such_user(ctx, &uname);
    }
    let org = match store::find_by_login(ctx.conn, &oname) {
        Ok(Some(o)) if o.is_org => o,
        Ok(_) => return no_such_org(ctx, &oname),
        Err(e) => return ctx.app.internal(&e),
    };
    // The caller must be able to see the organization at all (a private one is
    // hidden from outsiders, whoever the subject is), and a private subject is
    // hidden like on `GET /users/{u}`.
    match org_visible(ctx, &org) {
        Ok(true) => {}
        Ok(false) => return not_found(&ctx.app.base, "HasOrgOrUserVisible", None),
        Err(e) => return ctx.app.internal(&e),
    }
    let full = match store::is_org_owner(ctx.conn, org.id, subject.id) {
        Ok(owner) => owner || subject.is_admin,
        Err(e) => return ctx.app.internal(&e),
    };
    if !full && org.visibility == "private" {
        return not_found(&ctx.app.base, "HasOrgOrUserVisible", None);
    }
    Resp::json(
        200,
        &json!({"is_owner": full, "is_admin": full, "can_write": full, "can_read": full, "can_create_repository": full}),
    )
}

fn name_error(label: &str, name: &str, e: NameError) -> String {
    match e {
        NameError::Reserved => format!("name is reserved [name: {name}]"),
        NameError::Invalid => format!("[{label}]: invalid username"),
        NameError::TooLong => format!("[{label}]: MaxSize"),
    }
}

/// An email must be usable as a commit identity too (it reaches git through the environment):
/// no control characters and no angle brackets.
fn email_ok(e: &str) -> bool {
    e.contains('@') && !e.chars().any(|c| c.is_control() || matches!(c, '<' | '>'))
}

pub(crate) fn valid_visibility(v: &str) -> bool {
    matches!(v, "public" | "limited" | "private")
}

/// `POST /orgs`: create an organization owned by the caller.
pub fn create_org(ctx: &mut Ctx) -> Resp {
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let name = str_field(&b, "username").unwrap_or_default();
    if name.is_empty() {
        return error(&ctx.app.base, 422, "[UserName]: Required");
    }
    if let Err(e) = names::check(&name) {
        return error(&ctx.app.base, 422, &name_error("UserName", &name, e));
    }
    let visibility = str_field(&b, "visibility").unwrap_or_else(|| "public".into());
    if !valid_visibility(&visibility) {
        return error(&ctx.app.base, 422, "[Visibility]: invalid visibility");
    }
    let acct = NewAccount {
        login: name.clone(),
        is_org: true,
        full_name: str_field(&b, "full_name").unwrap_or_default(),
        email: str_field(&b, "email").unwrap_or_default(),
        description: str_field(&b, "description").unwrap_or_default(),
        website: str_field(&b, "website").unwrap_or_default(),
        location: str_field(&b, "location").unwrap_or_default(),
        visibility,
        ..Default::default()
    };
    let owner = ctx.who.user.id;
    match store::create_org(ctx.conn, &acct, owner, now()) {
        Ok(o) => Resp::json(201, &org_json(&ctx.app.base, &o)),
        Err(StoreError::Exists) => error(
            &ctx.app.base,
            422,
            &format!("user already exists [name: {name}]"),
        ),
        Err(e) => ctx.app.internal(&e),
    }
}

/// `GET /admin/users`: every user (not organizations), paged.
pub fn admin_list_users(ctx: &mut Ctx) -> Resp {
    let (page, limit) = page_params(ctx);
    match store::list_users(ctx.conn, page, limit) {
        Ok((users, total)) => {
            let items = users.iter().map(|u| user_json(&ctx.app.base, u)).collect();
            paged(ctx, "/admin/users", total, page, limit, items)
        }
        Err(e) => ctx.app.internal(&e),
    }
}

/// `POST /admin/users`: create a user; `must_change_password` defaults to true as in Gitea, and `admin` is ignored (set it with PATCH).
pub fn admin_create_user(ctx: &mut Ctx) -> Resp {
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let name = str_field(&b, "username").unwrap_or_default();
    let email = str_field(&b, "email").unwrap_or_default();
    let password = str_field(&b, "password").unwrap_or_default();
    let base = ctx.app.base.clone();
    if name.is_empty() {
        return error(&base, 422, "[Username]: Required");
    }
    if email.is_empty() {
        return error(&base, 422, "[Email]: Required");
    }
    if !email_ok(&email) {
        return error(&base, 422, "[Email]: Email");
    }
    if password.is_empty() {
        return error(&base, 422, "[Password]: Required");
    }
    if let Err(e) = names::check(&name) {
        return error(&base, 422, &name_error("Username", &name, e));
    }
    let visibility = str_field(&b, "visibility").unwrap_or_else(|| "public".into());
    if !valid_visibility(&visibility) {
        return error(&base, 422, "[Visibility]: invalid visibility");
    }
    let hash = {
        let _slot = ctx.app.gate.acquire();
        hash_password(&password)
    };
    let acct = NewAccount {
        login: name.clone(),
        login_name: str_field(&b, "login_name").unwrap_or_default(),
        full_name: str_field(&b, "full_name").unwrap_or_default(),
        email,
        password_hash: hash,
        must_change_password: b
            .get("must_change_password")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        visibility,
        ..Default::default()
    };
    match store::create_account(ctx.conn, &acct, now()) {
        Ok(u) => Resp::json(201, &user_json(&base, &u)),
        Err(StoreError::Exists) => {
            error(&base, 422, &format!("user already exists [name: {name}]"))
        }
        Err(e) => ctx.app.internal(&e),
    }
}

/// `PATCH /admin/users/{u}`: update only the supplied fields of a user.
pub fn admin_patch_user(ctx: &mut Ctx) -> Resp {
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let name = ctx.param("u").to_string();
    let target = match store::find_by_login(ctx.conn, &name) {
        Ok(Some(u)) if !u.is_org => u,
        Ok(_) => return no_such_user(ctx, &name),
        Err(e) => return ctx.app.internal(&e),
    };
    let base = ctx.app.base.clone();
    let visibility = str_field(&b, "visibility");
    if visibility.as_deref().is_some_and(|v| !valid_visibility(v)) {
        return error(&base, 422, "[Visibility]: invalid visibility");
    }
    let email = str_field(&b, "email");
    if email.as_deref().is_some_and(|e| !email_ok(e)) {
        return error(&base, 422, "[Email]: Email");
    }
    let password_hash = match str_field(&b, "password") {
        Some(p) if p.is_empty() => return error(&base, 422, "[Password]: Required"),
        Some(p) => {
            let _slot = ctx.app.gate.acquire();
            Some(hash_password(&p))
        }
        None => None,
    };
    let patch = UserPatch {
        login_name: str_field(&b, "login_name"),
        full_name: str_field(&b, "full_name"),
        email,
        password_hash,
        must_change_password: b.get("must_change_password").and_then(Value::as_bool),
        is_admin: b.get("admin").and_then(Value::as_bool),
        visibility,
        description: str_field(&b, "description"),
        website: str_field(&b, "website"),
        location: str_field(&b, "location"),
    };
    match store::update_user(ctx.conn, target.id, &patch) {
        Ok(u) => Resp::json(200, &user_json(&base, &u)),
        Err(e) => ctx.app.internal(&e),
    }
}

fn token_json(t: &store::Token, secret: Option<&str>) -> Value {
    json!({
        "id": t.id,
        "name": t.name,
        "sha1": secret.unwrap_or(""),
        "token_last_eight": t.last_eight,
        "scopes": t.scopes,
    })
}

/// The token's owner: the `{u}` of the path (already authorized as self or
/// site admin).
fn token_owner(ctx: &Ctx) -> Result<User, Resp> {
    let name = ctx.param("u");
    match store::find_by_login(ctx.conn, name) {
        Ok(Some(u)) if !u.is_org => Ok(u),
        Ok(_) => Err(no_such_user(ctx, name)),
        Err(e) => Err(ctx.app.internal(&e)),
    }
}

/// `GET /users/{u}/tokens`: the user's tokens, newest first, without their secrets.
pub fn list_tokens(ctx: &mut Ctx) -> Resp {
    let owner = match token_owner(ctx) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let (page, limit) = page_params(ctx);
    match store::list_tokens(ctx.conn, owner.id, page, limit) {
        Ok((toks, total)) => {
            let items = toks.iter().map(|t| token_json(t, None)).collect();
            let path = format!("/users/{}/tokens", owner.login);
            paged(ctx, &path, total, page, limit, items)
        }
        Err(e) => ctx.app.internal(&e),
    }
}

/// `POST /users/{u}/tokens`: mint a token; the secret is returned once, in `sha1`.
pub fn create_token(ctx: &mut Ctx) -> Resp {
    let owner = match token_owner(ctx) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let b = match body(ctx) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let base = ctx.app.base.clone();
    let name = str_field(&b, "name").unwrap_or_default();
    if name.is_empty() {
        return error(&base, 422, "[Name]: Required");
    }
    let requested: Vec<String> = b
        .get("scopes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if requested.is_empty() {
        return error(&base, 400, "access token must have a scope");
    }
    match store::mint(ctx.conn, owner.id, &name, &requested, now()) {
        Ok((t, secret)) => Resp::json(201, &token_json(&t, Some(&secret))),
        Err(store::MintError::BadScope(s)) => error(
            &base,
            400,
            &format!("invalid access token scope provided: invalid access token scope: {s}"),
        ),
        Err(store::MintError::Store(StoreError::Exists)) => {
            error(&base, 400, "access token name has been used already")
        }
        Err(store::MintError::Store(e)) => ctx.app.internal(&e),
    }
}

/// `DELETE /users/{u}/tokens/{id}`: delete one of the user's tokens by id or name.
pub fn delete_token(ctx: &mut Ctx) -> Resp {
    let owner = match token_owner(ctx) {
        Ok(o) => o,
        Err(r) => return r,
    };
    match store::delete_token(ctx.conn, owner.id, ctx.param("id")) {
        Ok(true) => Resp::no_content(),
        Ok(false) => error(&ctx.app.base, 404, "access token does not exist"),
        Err(e) => ctx.app.internal(&e),
    }
}
