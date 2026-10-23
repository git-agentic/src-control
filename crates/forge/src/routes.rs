//! The router table: every route declares its credential class, scope
//! requirement and actor rule in one place, and `dispatch` enforces them in a
//! fixed order (route match, authentication, scope, actor, handler) so no
//! handler can run unauthenticated or skip a scope check.

use crate::auth::{self, Authed};
use crate::http::{error, not_found, Req, Resp};
use crate::lifecycle::Lifecycle;
use crate::limits::{Backoff, Gate, Proxies};
use crate::repos::{self, Access, Perm};
use crate::scope::{self, Cat, Level, Need};
use crate::{api, db, repo_api, store};
use rusqlite::Connection;
use std::path::PathBuf;

/// Process-wide state shared by every request.
pub struct App {
    pub data_dir: PathBuf,
    /// `--public-url` without a trailing slash; the base of every URL in bodies.
    pub base: String,
    pub backoff: Backoff,
    pub gate: Gate,
    pub proxies: Proxies,
    /// Repository directories, the git runner and per-repository serialization.
    pub life: Lifecycle,
    /// Admission and limits of the git transport.
    pub transports: crate::cgi::Transports,
}

impl App {
    /// Build the shared state; also computes the dummy password hash so the first unknown login is not slower.
    pub fn new(
        data_dir: PathBuf,
        public_url: &str,
        proxies: Proxies,
        argon_slots: usize,
        life: Lifecycle,
    ) -> App {
        scl_crypto::warm_up();
        App {
            data_dir,
            base: public_url.trim_end_matches('/').to_string(),
            backoff: Backoff::default(),
            gate: Gate::new(argon_slots),
            proxies,
            life,
            transports: crate::cgi::Transports::new(crate::cgi::Cfg::default()),
        }
    }

    /// Log the detail, answer a bare 500: database errors never reach clients.
    pub fn internal(&self, e: &dyn std::fmt::Display) -> Resp {
        eprintln!("sc-forge: internal error: {e}");
        error(&self.base, 500, "internal server error")
    }
}

/// Which credential a route accepts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// Access token only (`token`, `Bearer`, Basic with the token).
    Token,
    /// The user's password only (`Basic login:password`).
    Password,
}

/// Who may call, beyond holding a valid credential.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Actor {
    Any,
    SiteAdmin,
    /// The caller must be the user named by this path parameter, or a site admin.
    SelfOrSiteAdmin(&'static str),
    /// The caller must own the organization named by this path parameter, or be a
    /// site admin; a missing organization is a 404.
    OrgOwnerOrSiteAdmin(&'static str),
    /// A repository route (`{o}`/`{r}`): the caller needs at least this permission. Resolved by
    /// `repos::resolve`, so a missing, not-live or invisible repository is one 404, and a token
    /// restricted to public repositories is refused before any existence is revealed.
    Repo(Perm),
    /// Like `Repo(Admin)`, but only the owning user, an owner of the owning organization or a
    /// site admin (not an admin collaborator): deleting the repository.
    RepoOwner,
}

/// What a handler receives; authentication and policy already passed.
pub struct Ctx<'a> {
    pub app: &'a App,
    pub req: &'a Req,
    pub conn: &'a mut Connection,
    pub who: &'a Authed,
    /// The caller's standing, set for `Actor::Repo` / `Actor::RepoOwner` routes.
    pub access: Option<Access>,
    params: Params,
}

impl Ctx<'_> {
    /// The captured path parameter `name` (percent-decoded), or empty if the route has none by that name.
    pub fn param(&self, name: &str) -> &str {
        self.params
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}

type Handler = fn(&mut Ctx) -> Resp;

/// One declared route. `pattern` is relative to `/api/v1`; `{x}` captures a
/// segment.
pub struct Route {
    pub method: &'static str,
    pub pattern: &'static str,
    pub class: Class,
    pub need: Option<Need>,
    pub actor: Actor,
    pub handler: Handler,
}

const fn r(
    method: &'static str,
    pattern: &'static str,
    class: Class,
    need: Option<Need>,
    actor: Actor,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern,
        class,
        need,
        actor,
        handler,
    }
}

const fn n(cat: Cat, level: Level) -> Option<Need> {
    Some(Need(cat, level))
}

use Actor::{Any, OrgOwnerOrSiteAdmin, Repo, RepoOwner, SelfOrSiteAdmin, SiteAdmin};
use Class::{Password, Token};

/// The route table. F2 onward append rows; a row cannot omit its class,
/// scope, or actor rule.
pub static ROUTES: &[Route] = &[
    r("GET", "/version", Token, None, Any, api::version),
    r(
        "GET",
        "/user",
        Token,
        n(Cat::User, Level::Read),
        Any,
        api::current_user,
    ),
    r(
        "GET",
        "/users/{u}",
        Token,
        n(Cat::User, Level::Read),
        Any,
        api::get_user,
    ),
    r(
        "GET",
        "/users/{u}/orgs/{o}/permissions",
        Token,
        n(Cat::Organization, Level::Read),
        Any,
        api::org_permissions,
    ),
    r(
        "GET",
        "/users/{u}/tokens",
        Password,
        None,
        SelfOrSiteAdmin("u"),
        api::list_tokens,
    ),
    r(
        "POST",
        "/users/{u}/tokens",
        Password,
        None,
        SelfOrSiteAdmin("u"),
        api::create_token,
    ),
    r(
        "DELETE",
        "/users/{u}/tokens/{id}",
        Password,
        None,
        SelfOrSiteAdmin("u"),
        api::delete_token,
    ),
    r(
        "GET",
        "/admin/users",
        Token,
        n(Cat::Admin, Level::Read),
        SiteAdmin,
        api::admin_list_users,
    ),
    r(
        "POST",
        "/admin/users",
        Token,
        n(Cat::Admin, Level::Write),
        SiteAdmin,
        api::admin_create_user,
    ),
    r(
        "PATCH",
        "/admin/users/{u}",
        Token,
        n(Cat::Admin, Level::Write),
        SiteAdmin,
        api::admin_patch_user,
    ),
    r(
        "POST",
        "/orgs",
        Token,
        n(Cat::Organization, Level::Write),
        Any,
        api::create_org,
    ),
    r(
        "GET",
        "/orgs/{o}",
        Token,
        n(Cat::Organization, Level::Read),
        Any,
        api::get_org,
    ),
    r(
        "GET",
        "/repos/search",
        Token,
        n(Cat::Repository, Level::Read),
        Any,
        repo_api::search,
    ),
    r(
        "GET",
        "/user/repos",
        Token,
        n(Cat::User, Level::Read),
        Any,
        repo_api::list_user_repos,
    ),
    r(
        "POST",
        "/user/repos",
        Token,
        n(Cat::User, Level::Write),
        Any,
        repo_api::create_user_repo,
    ),
    r(
        "GET",
        "/orgs/{o}/repos",
        Token,
        n(Cat::Organization, Level::Read),
        Any,
        repo_api::list_org_repos,
    ),
    r(
        "POST",
        "/orgs/{o}/repos",
        Token,
        n(Cat::Organization, Level::Write),
        OrgOwnerOrSiteAdmin("o"),
        repo_api::create_org_repo,
    ),
    r(
        "GET",
        "/repos/{o}/{r}",
        Token,
        n(Cat::Repository, Level::Read),
        Repo(Perm::Read),
        repo_api::get_repo,
    ),
    r(
        "PATCH",
        "/repos/{o}/{r}",
        Token,
        n(Cat::Repository, Level::Write),
        Repo(Perm::Admin),
        repo_api::patch_repo,
    ),
    r(
        "DELETE",
        "/repos/{o}/{r}",
        Token,
        n(Cat::Repository, Level::Write),
        RepoOwner,
        repo_api::delete_repo,
    ),
    r(
        "GET",
        "/repos/{o}/{r}/collaborators",
        Token,
        n(Cat::Repository, Level::Read),
        Repo(Perm::Admin),
        repo_api::list_collaborators,
    ),
    r(
        "GET",
        "/repos/{o}/{r}/collaborators/{u}/permission",
        Token,
        n(Cat::Repository, Level::Read),
        Repo(Perm::Admin),
        repo_api::collaborator_permission,
    ),
    r(
        "PUT",
        "/repos/{o}/{r}/collaborators/{u}",
        Token,
        n(Cat::Repository, Level::Write),
        Repo(Perm::Admin),
        repo_api::put_collaborator,
    ),
    r(
        "DELETE",
        "/repos/{o}/{r}/collaborators/{u}",
        Token,
        n(Cat::Repository, Level::Write),
        Repo(Perm::Admin),
        repo_api::delete_collaborator,
    ),
    r(
        "GET",
        "/repos/{o}/{r}/branches",
        Token,
        n(Cat::Repository, Level::Read),
        Repo(Perm::Read),
        repo_api::list_branches,
    ),
    r(
        "GET",
        "/repos/{o}/{r}/branches/{b..}",
        Token,
        n(Cat::Repository, Level::Read),
        Repo(Perm::Read),
        repo_api::get_branch,
    ),
    r(
        "DELETE",
        "/repos/{o}/{r}/branches/{b..}",
        Token,
        n(Cat::Repository, Level::Write),
        Repo(Perm::Write),
        repo_api::delete_branch,
    ),
];

/// Captured path parameters, in pattern order.
type Params = Vec<(&'static str, String)>;

/// Decode `%XX` escapes in a path segment; `None` when malformed or not UTF-8.
pub(crate) fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn match_pattern(pattern: &'static str, path: &str) -> Option<Params> {
    let (mut ps, mut xs) = (pattern.split('/'), path.split('/'));
    let mut caps = Vec::new();
    loop {
        match (ps.next(), xs.next()) {
            (None, None) => return Some(caps),
            (Some(p), Some(x)) => {
                if let Some(name) = p.strip_prefix('{').and_then(|s| s.strip_suffix("..}")) {
                    // Tail capture: the rest of the path, which may contain `/` (branch names).
                    let mut parts = vec![x];
                    parts.extend(xs.by_ref());
                    if ps.next().is_some() || parts.iter().any(|p| p.is_empty()) {
                        return None;
                    }
                    let decoded: Option<Vec<String>> =
                        parts.into_iter().map(percent_decode).collect();
                    caps.push((name, decoded?.join("/")));
                    return Some(caps);
                } else if let Some(name) = p.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    if x.is_empty() {
                        return None;
                    }
                    // Captures are percent-decoded (a token named `release bot` is
                    // addressed as `release%20bot`); undecodable input matches nothing.
                    caps.push((name, percent_decode(x)?));
                } else if p != x {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

/// Find the row for `method` and `path` (relative to `/api/v1`). `Err(true)`
/// means the path exists under another method.
pub fn resolve(method: &str, path: &str) -> Result<(&'static Route, Params), bool> {
    let mut path_known = false;
    for route in ROUTES {
        if let Some(caps) = match_pattern(route.pattern, path) {
            if route.method == method {
                return Ok((route, caps));
            }
            path_known = true;
        }
    }
    Err(path_known)
}

/// Ready only when the database file exists at this binary's schema version: a
/// deleted or replaced `forge.db` (which `connect` would recreate empty) is
/// reported as down rather than as a healthy server whose routes all fail.
fn database_ready(app: &App) -> bool {
    if !db::db_path(&app.data_dir).exists() {
        return false;
    }
    let Ok(conn) = db::connect(&app.data_dir) else {
        return false;
    };
    let version = conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0));
    // The version alone can be forged by a replacement file; the tables must answer too.
    version.is_ok_and(|v| v == db::SCHEMA_VERSION)
        && db::TABLES.iter().all(|t| {
            conn.query_row(&format!("SELECT 1 FROM {t} LIMIT 1"), [], |_| Ok(()))
                .map_or_else(
                    |e| matches!(e, rusqlite::Error::QueryReturnedNoRows),
                    |()| true,
                )
        })
}

fn healthz(app: &App) -> Resp {
    let ok = database_ready(app);
    let now = crate::timefmt::rfc3339(crate::timefmt::now());
    let mut r = Resp::json(
        if ok { 200 } else { 503 },
        &serde_json::json!({
            "status": if ok { "pass" } else { "fail" },
            "description": "sc-forge",
            "checks": {"database:ping": [{"status": if ok { "pass" } else { "fail" }, "time": now}]},
        }),
    );
    r.headers[0].1 = "application/json".into();
    r
}

/// Resolve the repository a route names and check the caller's standing, in the one order every
/// repository route follows: a token restricted to public repositories is refused (nothing is
/// revealed), a missing or invisible repository is the same 404, an insufficient permission is
/// a 403.
fn resolve_repo(
    app: &App,
    conn: &Connection,
    who: &Authed,
    owner: &str,
    name: &str,
    min: Perm,
    owner_only: bool,
) -> Result<Access, Resp> {
    if who.scopes.as_deref().is_some_and(scope::public_only) {
        return Err(error(
            &app.base,
            403,
            "token scope is limited to public repos",
        ));
    }
    match repos::resolve(conn, &who.user, owner, name) {
        Err(e) => Err(app.internal(&e)),
        Ok(None) => Err(not_found(&app.base, "The target couldn't be found.", None)),
        Ok(Some(a)) if a.perm < min || (owner_only && !a.is_owner) => Err(error(
            &app.base,
            403,
            "You do not have permission to perform this action",
        )),
        Ok(Some(a)) => Ok(a),
    }
}

/// Handle one request end to end. Blocking (SQLite, Argon2): the server runs it
/// on a blocking thread.
pub fn dispatch(app: &App, req: &Req) -> Resp {
    if req.method == "GET" && matches!(req.path.as_str(), "/api/healthz" | "/healthz") {
        return healthz(app);
    }
    let Some(path) = req.path.strip_prefix("/api/v1") else {
        return not_found(&app.base, "The target couldn't be found.", None);
    };
    let (route, params) = match resolve(&req.method, path) {
        Ok(x) => x,
        Err(path_known) => {
            // Authenticate before answering for a path with no row, so a
            // caller learns nothing about the API surface anonymously
            // (anonymous 403, bad token 401, as on declared routes).
            let unauth = db::connect(&app.data_dir)
                .map_err(|e| app.internal(&e))
                .and_then(|c| auth::by_token(app, &c, &auth::parse(req), crate::timefmt::now()));
            if let Err(resp) = unauth {
                return resp;
            }
            return if path_known {
                error(&app.base, 405, "method not allowed")
            } else {
                not_found(&app.base, "not found: no such API route", None)
            };
        }
    };
    let mut conn = match db::connect(&app.data_dir) {
        Ok(c) => c,
        Err(e) => return app.internal(&e),
    };
    let cred = auth::parse(req);
    let now = crate::timefmt::now();
    let who = match route.class {
        Class::Token => auth::by_token(app, &conn, &cred, now),
        Class::Password => auth::by_password(app, &conn, req, &cred),
    };
    let who = match who {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    if let (Some(need), Some(scopes)) = (route.need, &who.scopes) {
        if !scope::allows(scopes, need) {
            return error(
                &app.base,
                403,
                &format!(
                    "token does not have at least one of required scope(s): {}",
                    need.label()
                ),
            );
        }
    }
    let param = |p: &str| {
        params
            .iter()
            .find(|(k, _)| *k == p)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    let mut access: Option<Access> = None;
    let denied = match route.actor {
        Actor::Any => None,
        Actor::SiteAdmin => {
            (!who.user.is_admin).then_some("You must be a site admin to use this route")
        }
        Actor::SelfOrSiteAdmin(p) => (!who.user.is_admin
            && !who.user.login.eq_ignore_ascii_case(param(p)))
        .then_some("doer should be the site admin or be same as the contextUser"),
        Actor::Repo(_) | Actor::RepoOwner => {
            let (min, owner_only) = match route.actor {
                Actor::Repo(m) => (m, false),
                _ => (Perm::Admin, true),
            };
            match resolve_repo(app, &conn, &who, param("o"), param("r"), min, owner_only) {
                Ok(a) => {
                    access = Some(a);
                    None
                }
                Err(resp) => return resp,
            }
        }
        Actor::OrgOwnerOrSiteAdmin(p) => match store::find_by_login(&conn, param(p)) {
            Ok(Some(org)) if org.is_org => match store::is_org_owner(&conn, org.id, who.user.id) {
                Ok(true) => None,
                Ok(false) if who.user.is_admin => None,
                // A private organization is invisible to a non-owner: same answer as a missing one.
                Ok(false) if org.visibility == "private" => return api::org_missing(app, param(p)),
                Ok(false) => {
                    Some("Given user is not allowed to create repository in organization.")
                }
                Err(e) => return app.internal(&e),
            },
            Ok(_) => return api::org_missing(app, param(p)),
            Err(e) => return app.internal(&e),
        },
    };
    if let Some(msg) = denied {
        return error(&app.base, 403, msg);
    }
    (route.handler)(&mut Ctx {
        app,
        req,
        conn: &mut conn,
        who: &who,
        access,
        params,
    })
}
