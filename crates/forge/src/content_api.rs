//! F3a: the read half of the content API: refs, tags, commits, trees, contents and archives, in
//! the shapes recorded from Gitea. Every handler runs under the repository's shared lock
//! (`read_locked`), resolves client revisions with `gitobj::resolve` (never as git syntax) and
//! answers a busy runner 503.

use crate::api::{page_params, paged_sorted, paged_with, pct_encode, user_json};
use crate::b64;
use crate::gitobj::{self, Peel, RefKind, RefRow, Resolved, TreeEntry};
use crate::gitproc::GitError;
use crate::gitread;
use crate::http::{error, not_found, Resp};
use crate::repo_api::{acc, git_read_err, read_locked};
use crate::repos::Access;
use crate::routes::{percent_decode, Ctx};
use crate::store;
use crate::timefmt::rfc3339;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

fn dir(ctx: &Ctx, a: &Access) -> PathBuf {
    ctx.app.life.repo_dir(a.repo.id)
}

/// `{base}/api/v1/repos/{owner}/{repo}`.
fn api_base(ctx: &Ctx, a: &Access) -> String {
    format!(
        "{}/api/v1/repos/{}/{}",
        ctx.app.base, a.repo.owner, a.repo.name
    )
}

/// `{base}/{owner}/{repo}`: the web URLs Gitea puts in `html_url`.
fn web_base(ctx: &Ctx, a: &Access) -> String {
    format!("{}/{}/{}", ctx.app.base, a.repo.owner, a.repo.name)
}

/// A query parameter, percent-decoded.
fn param(ctx: &Ctx, k: &str) -> Option<String> {
    ctx.req.param(k).and_then(percent_decode)
}

fn flag(ctx: &Ctx, k: &str, default: bool) -> bool {
    match ctx.req.param(k) {
        Some("true" | "1") => true,
        Some("false" | "0") => false,
        _ => default,
    }
}

/// A git failure that is the request's doing, as opposed to the repository's.
fn read_err(ctx: &Ctx, a: &Access, e: GitError) -> Resp {
    match e {
        GitError::OutputTooLarge => error(&ctx.app.base, 413, "the result is too large to serve"),
        GitError::Timeout { .. } => error(&ctx.app.base, 504, "git timed out"),
        e => git_read_err(ctx.app, ctx.conn, a.repo.id, e),
    }
}

fn is_empty(ctx: &Ctx, a: &Access) -> Result<bool, Resp> {
    gitread::is_empty(&ctx.app.life.git, &dir(ctx, a)).map_err(|e| read_err(ctx, a, e))
}

/// No branch and no tag at all (a repository with only an unborn default is not this).
fn no_refs(ctx: &Ctx, a: &Access) -> Result<bool, Resp> {
    all_refs(ctx, a).map(|rows| rows.is_empty())
}

fn resolve(ctx: &Ctx, a: &Access, rev: &str, peel: Peel) -> Result<Option<Resolved>, Resp> {
    gitobj::resolve(
        &ctx.app.life.git,
        &dir(ctx, a),
        &a.repo.default_branch,
        rev,
        peel,
    )
    .map_err(|e| read_err(ctx, a, e))
}

fn git_err<T>(ctx: &Ctx, a: &Access, r: Result<T, GitError>) -> Result<T, Resp> {
    r.map_err(|e| read_err(ctx, a, e))
}

// ---- JSON pieces ----

/// Commit authors resolved to accounts by email, once per request.
struct Users<'a> {
    ctx: &'a Ctx<'a>,
    cache: HashMap<String, Value>,
}

impl<'a> Users<'a> {
    fn new(ctx: &'a Ctx<'a>) -> Self {
        Users {
            ctx,
            cache: HashMap::new(),
        }
    }

    /// The account owning `email`, or `null` (recorded: commits by unknown addresses).
    fn actor(&mut self, email: &str) -> Result<Value, Resp> {
        if let Some(v) = self.cache.get(&email.to_lowercase()) {
            return Ok(v.clone());
        }
        let ctx = self.ctx;
        let v = match store::login_by_email(ctx.conn, email).map_err(|e| ctx.app.internal(&e))? {
            Some(login) => {
                match store::find_by_login(ctx.conn, &login).map_err(|e| ctx.app.internal(&e))? {
                    Some(u) => user_json(&ctx.app.base, &u),
                    None => Value::Null,
                }
            }
            None => Value::Null,
        };
        self.cache.insert(email.to_lowercase(), v.clone());
        Ok(v)
    }
}

fn verification() -> Value {
    json!({"verified": false, "reason": "gpg.error.not_signed_commit", "signature": "", "signer": null, "payload": ""})
}

fn person_json(p: &gitread::Person) -> Value {
    json!({"name": p.name, "email": p.email, "date": rfc3339(p.when)})
}

fn commit_meta(ctx: &Ctx, a: &Access, sha: &str, when: i64) -> Value {
    json!({"url": format!("{}/git/commits/{sha}", api_base(ctx, a)), "sha": sha, "created": rfc3339(when)})
}

/// Files and line counts a commit response may carry (`None` for each the client did not ask for).
type Changes = (Option<Vec<gitobj::FileChange>>, Option<gitobj::Stats>);

/// The Gitea commit object. `changes` fills `files` and `stats` (`None` leaves them `null`).
fn commit_json(
    ctx: &Ctx,
    a: &Access,
    users: &mut Users,
    c: &gitobj::LogCommit,
    verified: bool,
    changes: Option<Changes>,
) -> Result<Value, Resp> {
    let (files, stats) = changes.unwrap_or((None, None));
    let api = api_base(ctx, a);
    Ok(json!({
        "url": format!("{api}/git/commits/{}", c.oid),
        "sha": c.oid,
        "created": rfc3339(c.committer.when),
        "html_url": format!("{}/commit/{}", web_base(ctx, a), c.oid),
        "commit": {
            "url": format!("{api}/git/commits/{}", c.oid),
            "author": person_json(&c.author),
            "committer": person_json(&c.committer),
            "message": c.message,
            // Recorded Gitea quirk: `tree` carries the *commit's* id, which `git/trees` accepts.
            "tree": {"url": format!("{api}/git/trees/{}", c.oid), "sha": c.oid, "created": rfc3339(c.committer.when)},
            "verification": if verified { verification() } else { Value::Null },
        },
        "author": users.actor(&c.author.email)?,
        "committer": users.actor(&c.committer.email)?,
        "parents": c.parents.iter().map(|p| commit_meta(ctx, a, p, c.committer.when)).collect::<Vec<_>>(),
        "files": files.map(|fs| fs.iter().map(|f| json!({"filename": f.name, "status": f.status})).collect::<Vec<_>>()),
        "stats": stats.map(|s| json!({"total": s.additions + s.deletions, "additions": s.additions, "deletions": s.deletions})),
    }))
}

fn load_changes(
    ctx: &Ctx,
    a: &Access,
    c: &gitobj::LogCommit,
    files: bool,
    stats: bool,
) -> Result<Option<Changes>, Resp> {
    if !files && !stats {
        return Ok(None);
    }
    let (f, s) = git_err(
        ctx,
        a,
        gitobj::changes(
            &ctx.app.life.git,
            &dir(ctx, a),
            c.parents.first().map(String::as_str),
            &c.oid,
        ),
    )?;
    Ok(Some((files.then_some(f), stats.then_some(s))))
}

fn ref_json(ctx: &Ctx, a: &Access, r: &RefRow) -> Value {
    let api = api_base(ctx, a);
    let tag = r.kind == "tag";
    json!({
        "ref": r.name,
        "url": format!("{api}/git/{}", r.name),
        "object": {
            "type": r.kind,
            "sha": r.oid,
            "url": format!("{api}/git/{}/{}", if tag { "tags" } else { "commits" }, r.oid),
        },
    })
}

// ---- refs and tags ----

fn all_refs(ctx: &Ctx, a: &Access) -> Result<Vec<RefRow>, Resp> {
    let (git, d) = (&ctx.app.life.git, dir(ctx, a));
    let mut rows = git_err(ctx, a, gitobj::list_refs(git, &d, "refs/heads"))?;
    rows.extend(git_err(ctx, a, gitobj::list_refs(git, &d, "refs/tags"))?);
    Ok(rows)
}

fn gone(ctx: &Ctx) -> Resp {
    not_found(&ctx.app.base, "The target couldn't be found.", None)
}

/// `GET /repos/{o}/{r}/git/refs`.
pub fn list_git_refs(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| match all_refs(ctx, &a) {
        Ok(rows) if rows.is_empty() => gone(ctx),
        Ok(rows) => Resp::json(
            200,
            &Value::Array(rows.iter().map(|r| ref_json(ctx, &a, r)).collect()),
        ),
        Err(r) => r,
    })
}

/// `GET /repos/{o}/{r}/git/refs/{ref..}`: the refs equal to `refs/<ref>` or below it.
pub fn get_git_refs(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let want = format!("refs/{}", ctx.param("ref").trim_end_matches('/'));
    read_locked(ctx, &a, |ctx| match all_refs(ctx, &a) {
        Ok(rows) => {
            let hit: Vec<Value> = rows
                .iter()
                .filter(|r| r.name == want || r.name.starts_with(&format!("{want}/")))
                .map(|r| ref_json(ctx, &a, r))
                .collect();
            if hit.is_empty() {
                gone(ctx)
            } else {
                Resp::json(200, &Value::Array(hit))
            }
        }
        Err(r) => r,
    })
}

/// `GET /repos/{o}/{r}/tags`, newest first.
pub fn list_tags(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| {
        let mut rows = match git_err(
            ctx,
            &a,
            gitobj::list_refs(&ctx.app.life.git, &dir(ctx, &a), "refs/tags"),
        ) {
            Ok(r) => r,
            Err(r) => return r,
        };
        // Newest first, as Gitea lists them; ties (a second's resolution) by name, descending.
        rows.sort_by(|x, y| (y.created, &y.name).cmp(&(x.created, &x.name)));
        let (page, limit) = page_params(ctx);
        let total = rows.len() as i64;
        let start = (((page - 1) * limit) as usize).min(rows.len());
        let end = (start + limit as usize).min(rows.len());
        let web = web_base(ctx, &a);
        let items = rows[start..end]
            .iter()
            .map(|r| {
                let name = r.name.strip_prefix("refs/tags/").unwrap_or(&r.name);
                let enc = name.split('/').map(pct_encode).collect::<Vec<_>>().join("/");
                json!({
                    "name": name,
                    "message": r.subject,
                    "id": r.oid,
                    // Recorded Gitea quirk: the url names the tag object, the sha the commit.
                    "commit": json!({"url": format!("{}/git/commits/{}", api_base(ctx, &a), r.oid), "sha": r.commit(), "created": rfc3339(r.commit_date)}),
                    "zipball_url": format!("{web}/archive/{enc}.zip"),
                    "tarball_url": format!("{web}/archive/{enc}.tar.gz"),
                })
            })
            .collect();
        paged_with(
            ctx,
            &format!("/repos/{}/{}/tags", a.repo.owner, a.repo.name),
            total,
            page,
            limit,
            &[],
            items,
        )
    })
}

// ---- commits ----

/// `GET /repos/{o}/{r}/commits`.
pub fn list_commits(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| list_commits_inner(ctx, &a))
}

fn list_commits_inner(ctx: &Ctx, a: &Access) -> Resp {
    if param(ctx, "not").is_some() {
        // Recorded Gitea filters by it; ignoring it would serve unfiltered history.
        return error(&ctx.app.base, 400, "the `not` parameter is not supported");
    }
    let named = param(ctx, "sha").filter(|v| !v.is_empty());
    let empty = || error(&ctx.app.base, 409, "Git Repository is empty.");
    if named.is_none() {
        match is_empty(ctx, a) {
            Ok(true) => return empty(),
            Ok(false) => {}
            Err(r) => return r,
        }
    }
    let rev = named.unwrap_or_else(|| a.repo.default_branch.clone());
    let path = param(ctx, "path").filter(|p| !p.is_empty());
    if let Some(p) = &path {
        if !gitobj::valid_path(p) {
            return error(&ctx.app.base, 422, "invalid path");
        }
    }
    let head = match resolve(ctx, a, &rev, Peel::Commit) {
        Ok(Some(h)) => h,
        // Gitea answers 500 here; a client error is a 404 (departure).
        Ok(None) => {
            return match no_refs(ctx, a) {
                Ok(true) => empty(),
                Ok(false) => error(&ctx.app.base, 404, &format!("ref not found [{rev}]")),
                Err(r) => r,
            }
        }
        Err(r) => return r,
    };
    let (page, limit) = page_params(ctx);
    let (git, d) = (&ctx.app.life.git, dir(ctx, a));
    let total = match git_err(ctx, a, gitobj::count(git, &d, &head.oid, path.as_deref())) {
        Ok(t) => t as i64,
        Err(r) => return r,
    };
    let commits = match git_err(
        ctx,
        a,
        gitobj::log(
            git,
            &d,
            &head.oid,
            path.as_deref(),
            ((page - 1) * limit) as usize,
            limit as usize,
        ),
    ) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (want_stat, want_files, want_verif) = (
        flag(ctx, "stat", true),
        flag(ctx, "files", true),
        flag(ctx, "verification", true),
    );
    let mut users = Users::new(ctx);
    let mut items = Vec::with_capacity(commits.len());
    for c in &commits {
        let changes = match load_changes(ctx, a, c, want_files, want_stat) {
            Ok(c) => c,
            Err(r) => return r,
        };
        match commit_json(ctx, a, &mut users, c, want_verif, changes) {
            Ok(v) => items.push(v),
            Err(r) => return r,
        }
    }
    paged_sorted(
        ctx,
        &format!("/repos/{}/{}/commits", a.repo.owner, a.repo.name),
        total,
        page,
        limit,
        items,
    )
}

/// `GET /repos/{o}/{r}/git/commits/{sha}` with the `.diff` and `.patch` forms.
pub fn get_git_commit(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| {
        let raw = ctx.param("sha").to_string();
        let (rev, form) = if let Some(r) = raw.strip_suffix(".diff") {
            (r.to_string(), Some("diff"))
        } else if let Some(r) = raw.strip_suffix(".patch") {
            (r.to_string(), Some("patch"))
        } else {
            (raw, None)
        };
        let oid = match resolve(ctx, &a, &rev, Peel::Commit) {
            Ok(Some(r)) => r.oid,
            Ok(None) => return not_found(&ctx.app.base, &rev, None),
            Err(r) => return r,
        };
        let (git, d) = (&ctx.app.life.git, dir(ctx, &a));
        let c = match git_err(ctx, &a, gitobj::commit(git, &d, &oid)) {
            Ok(Some(c)) => c,
            Ok(None) => return not_found(&ctx.app.base, &rev, None),
            Err(r) => return r,
        };
        let text = |bytes: Vec<u8>| Resp {
            status: 200,
            headers: vec![("content-type", "text/plain;charset=utf-8".into())],
            body: bytes,
            delay: std::time::Duration::ZERO,
            hold: None,
        };
        match form {
            Some("diff") => match git_err(
                ctx,
                &a,
                gitobj::diff_text(git, &d, c.parents.first().map(String::as_str), &c.oid),
            ) {
                Ok(b) => text(b),
                Err(r) => r,
            },
            Some(_) => match git_err(
                ctx,
                &a,
                gitobj::patch_text(git, &d, &c.oid, c.parents.len() > 1),
            ) {
                Ok(b) => text(b),
                Err(r) => r,
            },
            None => {
                let changes = match load_changes(ctx, &a, &c, true, true) {
                    Ok(c) => c,
                    Err(r) => return r,
                };
                let mut users = Users::new(ctx);
                match commit_json(ctx, &a, &mut users, &c, true, changes) {
                    Ok(v) => Resp::json(200, &v),
                    Err(r) => r,
                }
            }
        }
    })
}

// ---- trees ----

fn tree_entry_json(ctx: &Ctx, a: &Access, e: &TreeEntry) -> Value {
    let api = api_base(ctx, a);
    let url = match e.kind.as_str() {
        "tree" => format!("{api}/git/trees/{}", e.oid),
        "blob" => format!("{api}/git/blobs/{}", e.oid),
        _ => format!("{api}/git/commits/{}", e.oid),
    };
    json!({"path": e.path, "mode": e.mode, "type": e.kind, "size": e.size.unwrap_or(0), "sha": e.oid, "url": url})
}

/// `GET /repos/{o}/{r}/git/trees/{sha..}`.
pub fn get_git_tree(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| {
        let rev = ctx.param("sha").to_string();
        // The `sha` answered is the one the client named: a commit's id for a branch, tag or commit,
        // a tree's own id for a tree (recorded: the commit id, not its tree's).
        let (shown, tree) = match resolve(ctx, &a, &rev, Peel::Commit) {
            Ok(Some(c)) => match resolve(ctx, &a, &rev, Peel::Tree) {
                Ok(Some(t)) => (c.oid, t.oid),
                Ok(None) => return error(&ctx.app.base, 400, &format!("sha not found [{rev}]")),
                Err(r) => return r,
            },
            Ok(None) => match resolve(ctx, &a, &rev, Peel::Tree) {
                Ok(Some(t)) => (t.oid.clone(), t.oid),
                Ok(None) => return error(&ctx.app.base, 400, &format!("sha not found [{rev}]")),
                Err(r) => return r,
            },
            Err(r) => return r,
        };
        let recursive = flag(ctx, "recursive", false);
        let entries = match git_err(
            ctx,
            &a,
            gitobj::ls_tree(&ctx.app.life.git, &dir(ctx, &a), &tree, recursive),
        ) {
            Ok(e) => e,
            Err(r) => return r,
        };
        let num = |k: &str| {
            ctx.req
                .param(k)
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|n| *n >= 1)
        };
        let (page, per) = (
            num("page").unwrap_or(1),
            num("per_page").unwrap_or(1000).min(1000),
        );
        let total = entries.len();
        let start = ((page - 1).saturating_mul(per)).min(total);
        let end = (start + per).min(total);
        let body = json!({
            "sha": shown,
            "url": format!("{}/git/trees/{shown}", api_base(ctx, &a)),
            "tree": entries[start..end].iter().map(|e| tree_entry_json(ctx, &a, e)).collect::<Vec<_>>(),
            "truncated": end < total,
            "page": page,
            "total_count": total,
        });
        Resp::json(200, &body).with("x-total-count", total.to_string())
    })
}

// ---- contents ----

/// One contents object. `with_content` fills `content`/`encoding` of a file.
fn content_json(
    ctx: &Ctx,
    a: &Access,
    commit: &str,
    refname: &str,
    kind: RefKind,
    e: &TreeEntry,
    with_content: bool,
    exact_last: bool,
) -> Result<Value, Resp> {
    let (git, d) = (&ctx.app.life.git, dir(ctx, a));
    let api = api_base(ctx, a);
    let web = web_base(ctx, a);
    let enc_path = e
        .path
        .split('/')
        .map(pct_encode)
        .collect::<Vec<_>>()
        .join("/");
    let enc_ref = refname
        .split('/')
        .map(pct_encode)
        .collect::<Vec<_>>()
        .join("/");
    let query_ref = pct_encode(refname);
    let last = if exact_last {
        git_err(ctx, a, gitobj::last_commit(git, &d, commit, &e.path))?.unwrap_or_default()
    } else {
        commit.to_string()
    };
    let name = e.path.rsplit('/').next().unwrap_or(&e.path);
    let seg = kind.segment();
    let ty = match (e.kind.as_str(), e.mode.as_str()) {
        ("tree", _) => "dir",
        ("commit", _) => "submodule",
        (_, "120000") => "symlink",
        _ => "file",
    };
    let size = e.size.unwrap_or(0);
    let (mut encoding, mut content, mut target) = (Value::Null, Value::Null, Value::Null);
    // A link target is a path (PATH_MAX); a bigger blob is not read, and a listing reads at most
    // LAST_COMMIT_BUDGET of them, so one tree cannot make the server read thousands of blobs.
    if ty == "symlink" && size <= 4096 && (with_content || exact_last) {
        let b = git_err(ctx, a, gitobj::blob(git, &d, &e.oid))?;
        target = Value::String(String::from_utf8_lossy(&b).to_string());
    } else if ty == "file" && with_content && size <= gitobj::MAX_BLOB {
        let b = git_err(ctx, a, gitobj::blob(git, &d, &e.oid))?;
        encoding = json!("base64");
        content = Value::String(b64::encode(&b));
    }
    let self_url = format!("{api}/contents/{enc_path}?ref={query_ref}");
    // Recorded: directories point at `git/blobs/<tree id>` too.
    let git_url = format!("{api}/git/blobs/{}", e.oid);
    let html = format!("{web}/src/{seg}/{enc_ref}/{enc_path}");
    Ok(json!({
        "name": name,
        "path": e.path,
        "sha": e.oid,
        "last_commit_sha": last,
        "type": ty,
        "size": size,
        "encoding": encoding,
        "content": content,
        "target": target,
        "url": self_url,
        "html_url": html,
        "git_url": git_url,
        "download_url": if ty == "file" { json!(format!("{web}/raw/{seg}/{enc_ref}/{enc_path}")) } else { Value::Null },
        "submodule_git_url": null,
        "_links": {"self": self_url, "git": git_url, "html": html},
    }))
}

/// Entries of one listing whose `last_commit_sha` is computed exactly.
const LAST_COMMIT_BUDGET: usize = 100;

fn contents_not_found(ctx: &Ctx, id: &str, rel: &str) -> Resp {
    not_found(
        &ctx.app.base,
        "GetContentsOrList",
        Some(&format!(
            "object does not exist [id: {id}, rel_path: {rel}]"
        )),
    )
}

/// `GET /repos/{o}/{r}/contents` and `/contents/{path..}`.
pub fn get_contents(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| {
        // Recorded: an empty repository lists nothing and answers `[]` for any path. A named ref
        // that exists wins over an unborn default branch (a repository holding only `feat`).
        let named = param(ctx, "ref").filter(|v| !v.is_empty());
        if named.is_none() {
            match is_empty(ctx, &a) {
                Ok(true) => return Resp::json(200, &json!([])),
                Ok(false) => {}
                Err(r) => return r,
            }
        }
        let path = ctx.param("p").trim_matches('/').to_string();
        let refname = named.unwrap_or_else(|| a.repo.default_branch.clone());
        let head = match resolve(ctx, &a, &refname, Peel::Commit) {
            Ok(Some(h)) => h,
            Ok(None) => {
                return match no_refs(ctx, &a) {
                    Ok(true) => Resp::json(200, &json!([])),
                    Ok(false) => contents_not_found(ctx, &refname, ""),
                    Err(r) => r,
                }
            }
            Err(r) => return r,
        };
        let (git, d) = (&ctx.app.life.git, dir(ctx, &a));
        let entries: Vec<TreeEntry>;
        let single;
        if path.is_empty() {
            single = false;
            let tree = match git_err(
                ctx,
                &a,
                gitobj::ls_tree(git, &d, &format!("{}^{{tree}}", head.oid), false),
            ) {
                Ok(t) => t,
                Err(r) => return r,
            };
            entries = tree;
        } else {
            let Some(e) = (match git_err(ctx, &a, gitobj::tree_entry(git, &d, &head.oid, &path)) {
                Ok(e) => e,
                Err(r) => return r,
            }) else {
                return contents_not_found(ctx, "", &path);
            };
            if e.kind == "tree" {
                single = false;
                entries = match git_err(ctx, &a, gitobj::ls_tree(git, &d, &e.oid, false)) {
                    Ok(t) => t
                        .into_iter()
                        .map(|mut c| {
                            c.path = format!("{path}/{}", c.path);
                            c
                        })
                        .collect(),
                    Err(r) => return r,
                };
            } else {
                single = true;
                entries = vec![e];
            }
        }
        let mut items = Vec::with_capacity(entries.len());
        for (i, e) in entries.iter().enumerate() {
            // `last_commit_sha` costs one git process per entry: past LAST_COMMIT_BUDGET entries
            // a listing reports the commit it was read at instead (documented approximation).
            match content_json(
                ctx,
                &a,
                &head.oid,
                &refname,
                head.kind,
                e,
                single,
                i < LAST_COMMIT_BUDGET,
            ) {
                Ok(v) => items.push(v),
                Err(r) => return r,
            }
        }
        if single {
            Resp::json(200, &items[0])
        } else {
            Resp::json(200, &Value::Array(items))
        }
    })
}

// ---- archive ----

/// Archives in memory at once, server-wide: one is up to `MAX_ARCHIVE` of tar plus its gzip while it is
/// built, and up to `MAX_ARCHIVE` until the client has read it. The runner gate does not cover this
/// (its permit ends with the git process).
const MAX_ARCHIVES: usize = 4;
static ARCHIVES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One of the `MAX_ARCHIVES` slots; released when dropped, which `Resp::hold` defers to the end of
/// the response body.
struct ArchiveSlot;

impl ArchiveSlot {
    fn take() -> Option<ArchiveSlot> {
        let slot = ArchiveSlot;
        // Over the limit the slot drops again at once, which gives the count back.
        (ARCHIVES.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < MAX_ARCHIVES).then_some(slot)
    }
}

impl Drop for ArchiveSlot {
    fn drop(&mut self) {
        ARCHIVES.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// `GET /repos/{o}/{r}/archive/{ref..}.{zip,tar.gz}`.
pub fn get_archive(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    read_locked(ctx, &a, |ctx| {
        let raw = ctx.param("a").to_string();
        let (rev, zip) = if let Some(r) = raw.strip_suffix(".zip") {
            (r, true)
        } else if let Some(r) = raw.strip_suffix(".tar.gz") {
            (r, false)
        } else {
            return error(&ctx.app.base, 400, &format!("Unknown archive type: {raw}"));
        };
        let oid = match resolve(ctx, &a, rev, Peel::Commit) {
            Ok(Some(r)) => r.oid,
            Ok(None) => {
                return error(
                    &ctx.app.base,
                    404,
                    &format!("unrecognized repository reference: {rev}"),
                )
            }
            Err(r) => return r,
        };
        let Some(slot) = ArchiveSlot::take() else {
            return error(
                &ctx.app.base,
                503,
                "too many archives are being built, try again",
            );
        };
        let (git, d) = (&ctx.app.life.git, dir(ctx, &a));
        let tar = match git_err(ctx, &a, gitobj::archive(git, &d, &oid, &a.repo.name, zip)) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let body = if zip {
            tar
        } else {
            use std::io::Write;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            if gz.write_all(&tar).is_err() {
                return ctx.app.internal(&"gzip failed");
            }
            match gz.finish() {
                Ok(b) => b,
                Err(e) => return ctx.app.internal(&e),
            }
        };
        Resp {
            status: 200,
            headers: vec![
                ("content-type", "application/octet-stream".into()),
                (
                    "link",
                    format!(
                        "<{}/archive/{oid}.tar.gz?rev={oid}>; rel=\"immutable\"",
                        api_base(ctx, &a)
                    ),
                ),
            ],
            body,
            delay: std::time::Duration::ZERO,
            hold: Some(Box::new(slot)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_slots_are_limited_and_come_back_when_dropped() {
        let held: Vec<_> = (0..MAX_ARCHIVES)
            .map(|_| ArchiveSlot::take().unwrap())
            .collect();
        assert!(ArchiveSlot::take().is_none(), "over the limit");
        assert!(
            ArchiveSlot::take().is_none(),
            "a refusal does not leak a count"
        );
        drop(held);
        assert!(ArchiveSlot::take().is_some());
    }
}
