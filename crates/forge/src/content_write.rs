//! `POST`/`PUT`/`DELETE /repos/{o}/{r}/contents/{path..}` (F3b): one file changed by a server-made
//! commit. The commit is built from object ids with plumbing (`gitwrite`) and the ref moves last, by
//! compare-and-swap; the response is built before that, so nothing is read from git afterwards.
//! Plan: `docs/superpowers/plans/2026-10-24-p38-f3b-contents-writes.md`.

use crate::api::body;
use crate::b64;
use crate::content_api::{api_base, content_value, dir, read_err, verification, web_base};
use crate::gitobj::{RefKind, TreeEntry};
use crate::gitproc::Identity;
use crate::gitwrite::{self as gw, Op, Outcome, Refuse, WriteErr};
use crate::http::{error, not_found, Resp};
use crate::lifecycle::WriteRun;
use crate::policy;
use crate::refname;
use crate::repo_api::acc;
use crate::repos::{self, Access, Repo};
use crate::routes::Ctx;
use crate::timefmt::{now, rfc3339};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Publication attempts before the write answers 409.
const ATTEMPTS: usize = 3;
/// How long the whole operation may take, checked between attempts and between the walk, the rewrite and the commit.
const DEADLINE: Duration = Duration::from_secs(60);
/// How long a write waits for the repository's write gate.
const GATE_WAIT: Duration = Duration::from_secs(10);
/// Pause before rebuilding after a ref lock was held.
const BACKOFF: Duration = Duration::from_millis(50);
/// Disk promised beyond the content itself, up front; each attempt then reserves the tree bytes it read.
const RESERVE_SLACK: u64 = 8 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verb {
    Post,
    Put,
    Delete,
}

/// A validated request.
struct Write {
    verb: Verb,
    path: String,
    bytes: Vec<u8>,
    message: String,
    branch: Option<String>,
    new_branch: Option<String>,
    sha: Option<String>,
}

fn unprocessable(ctx: &Ctx, msg: &str) -> Resp {
    error(&ctx.app.base, 422, msg)
}

fn no_branch(ctx: &Ctx, name: &str) -> Resp {
    not_found(
        &ctx.app.base,
        "The target couldn't be found.",
        Some(&format!("branch does not exist [name: {name}]")),
    )
}

/// An optional string field: absent, `null` and `""` are all "not given".
fn opt_str(ctx: &Ctx, b: &Value, key: &str) -> Result<Option<String>, Resp> {
    match b.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(unprocessable(ctx, &format!("[{key}]: must be a string"))),
    }
}

fn parse(ctx: &Ctx, verb: Verb) -> Result<Write, Resp> {
    let b = body(ctx)?;
    let path = ctx.param("p").to_string();
    if opt_str(ctx, &b, "from_path")?.is_some_and(|f| f != path) {
        return Err(unprocessable(ctx, "from_path (rename) is not supported"));
    }
    if !gw::write_path_ok(&path) {
        return Err(unprocessable(
            ctx,
            &format!("invalid file path [path: {path}]"),
        ));
    }
    let sha = opt_str(ctx, &b, "sha")?;
    if verb != Verb::Post && sha.is_none() {
        return Err(unprocessable(ctx, "[SHA]: Required"));
    }
    let bytes = if verb == Verb::Delete {
        Vec::new()
    } else {
        let Some(c) = opt_str(ctx, &b, "content")? else {
            // an empty file is legal; a missing field is not
            return match b.get("content") {
                Some(Value::String(_)) => Ok(Write {
                    verb,
                    bytes: Vec::new(),
                    ..parse_rest(ctx, verb, &b, path, sha)?
                }),
                _ => Err(unprocessable(ctx, "[Content]: Required")),
            };
        };
        b64::decode(&c).ok_or_else(|| unprocessable(ctx, "invalid base64 content"))?
    };
    Ok(Write {
        bytes,
        ..parse_rest(ctx, verb, &b, path, sha)?
    })
}

/// Message and branch fields (the part of the request every verb shares).
fn parse_rest(
    ctx: &Ctx,
    verb: Verb,
    b: &Value,
    path: String,
    sha: Option<String>,
) -> Result<Write, Resp> {
    let verbword = match verb {
        Verb::Post => "Add",
        Verb::Put => "Update",
        Verb::Delete => "Delete",
    };
    let message = opt_str(ctx, b, "message")?.unwrap_or_else(|| format!("{verbword} {path}"));
    if message.contains('\0') {
        return Err(unprocessable(ctx, "[Message]: must not contain NUL"));
    }
    let message = format!("{}\n", message.trim_end());
    let name = |k: &str| -> Result<Option<String>, Resp> {
        match opt_str(ctx, b, k)? {
            Some(n) if !refname::valid_branch(&n) => {
                Err(unprocessable(ctx, &format!("[{k}]: invalid branch name")))
            }
            other => Ok(other),
        }
    };
    let branch = name("branch")?;
    let new_branch = name("new_branch")?.filter(|n| Some(n) != branch.as_ref());
    Ok(Write {
        verb,
        path,
        bytes: Vec::new(),
        message,
        branch,
        new_branch,
        sha,
    })
}

/// The `POST`, `PUT` and `DELETE` handler.
pub fn write_contents(ctx: &mut Ctx) -> Resp {
    let a = match acc(ctx) {
        Ok(a) => a.clone(),
        Err(r) => return r,
    };
    let verb = match ctx.req.method.as_str() {
        "POST" => Verb::Post,
        "PUT" => Verb::Put,
        "DELETE" => Verb::Delete,
        _ => return error(&ctx.app.base, 405, "method not allowed"),
    };
    let w = match parse(ctx, verb) {
        Ok(w) => w,
        Err(r) => return r,
    };
    if !gw::content_ok(&w.path, &w.bytes) {
        return unprocessable(ctx, "content is not allowed at this path");
    }
    let ctx: &Ctx = ctx;
    match ctx
        .app
        .life
        .with_write_row(ctx.conn, a.repo.id, GATE_WAIT, |row| run(ctx, &a, row, &w))
    {
        Ok(WriteRun::Ran(r)) => r,
        Ok(WriteRun::Busy) => error(
            &ctx.app.base,
            503,
            "this repository is being written to, try again",
        ),
        Ok(WriteRun::Gone) => not_found(&ctx.app.base, "The target couldn't be found.", None),
        Err(e) => ctx.app.internal(&e),
    }
}

/// The address git will record: surrounding blanks are stripped by git, so strip them here too and the
/// response matches the commit.
pub(crate) fn commit_email(user: &crate::store::User) -> String {
    let e = user.email.trim();
    if e.is_empty() {
        format!("{}@noreply.localhost", user.login)
    } else {
        e.to_string()
    }
}

fn refuse(ctx: &Ctx, path: &str, r: Refuse) -> Resp {
    match r {
        Refuse::AlreadyExists => unprocessable(
            ctx,
            &format!("repository file already exists [path: {path}]"),
        ),
        Refuse::Blocked(p) => {
            unprocessable(ctx, &format!("repository file already exists [path: {p}]"))
        }
        Refuse::NoFile => not_found(
            &ctx.app.base,
            "The target couldn't be found.",
            Some(&format!("repository file does not exist [path: {path}]")),
        ),
        Refuse::NotRegular => {
            unprocessable(ctx, &format!("path is not a regular file [path: {path}]"))
        }
        Refuse::ShaMismatch { given, expected } => unprocessable(
            ctx,
            &format!("sha does not match [given: {given}, expected: {expected}]"),
        ),
    }
}

fn denied(ctx: &Ctx) -> Resp {
    error(
        &ctx.app.base,
        403,
        &format!("user cannot commit to repo [user: {}]", ctx.who.user.login),
    )
}

/// A branch name that equals, contains or lies under an existing branch name.
fn collides(existing: &[String], new: &str) -> Option<bool> {
    for n in existing {
        if n == new {
            return Some(true);
        }
        if n.starts_with(&format!("{new}/")) || new.starts_with(&format!("{n}/")) {
            return Some(false);
        }
    }
    None
}

/// One write, under the gate and the shared lifecycle lock, against the fresh `row`.
fn run(ctx: &Ctx, a: &Access, row: &Repo, w: &Write) -> Resp {
    let started = Instant::now();
    let (git, d) = (&ctx.app.life.git, dir(ctx, a));
    let user = &ctx.who.user;
    let default = row.default_branch.clone();
    let base_name = w.branch.clone().unwrap_or_else(|| default.clone());
    let new_branch = w.new_branch.clone().filter(|n| *n != base_name);
    let target_name = new_branch.clone().unwrap_or_else(|| base_name.clone());
    // Gitea checks protection before it looks at the tree.
    // The rules are read here, under the write gate, so a rule change is ordered against this write.
    let rules = match crate::protection::load(ctx.conn, a.repo.id) {
        Ok(r) => r,
        Err(e) => return ctx.app.internal(&e),
    };
    if policy::check_contents_write(&rules, &target_name, new_branch.is_some()).is_err() {
        return denied(ctx);
    }
    let comps: Vec<&str> = w.path.split('/').collect();
    let op = match (w.verb, &w.sha) {
        (Verb::Post, _) => Op::Create,
        (Verb::Put, Some(s)) => Op::Update(s.clone()),
        (Verb::Delete, Some(s)) => Op::Delete(s.clone()),
        _ => return unprocessable(ctx, "[SHA]: Required"),
    };
    let email = commit_email(user);
    let when = now();
    let Some(identity) = Identity::new(&user.login, &email).map(|i| i.at(when)) else {
        return ctx.app.internal(&"unusable commit identity");
    };
    // Disk is promised only once the request has passed its preconditions (a refused one is 422, not 507).
    let mut held = None;
    // Written after the first successful precondition check, so a refused request stores nothing.
    let mut blob: Option<String> = None;
    let base_ref = refname::branch_ref(&base_name);
    let mut locked = false;
    for attempt in 0..ATTEMPTS {
        if started.elapsed() > DEADLINE {
            return error(&ctx.app.base, 503, "the write took too long, try again");
        }
        let old = match gw::read_ref(git, &d, &base_ref) {
            Ok(o) => o,
            Err(e) => return read_err(ctx, a, e),
        };
        // An unborn default branch is where a repository's first commit goes.
        let bootstrap =
            old.is_none() && w.verb == Verb::Post && new_branch.is_none() && base_name == default;
        if old.is_none() && !bootstrap {
            return no_branch(ctx, &base_name);
        }
        if let Some(n) = &new_branch {
            match gobj_branches(ctx, a) {
                Ok(rows) => match collides(&rows, n) {
                    Some(true) => {
                        return unprocessable(ctx, &format!("branch already exists [name: {n}]"))
                    }
                    Some(false) => {
                        return unprocessable(
                            ctx,
                            &format!("branch name conflicts with an existing branch [name: {n}]"),
                        )
                    }
                    None => {}
                },
                Err(r) => return r,
            }
        }
        let root = match &old {
            Some(o) => match gw::read_ref(git, &d, &format!("{o}^{{tree}}")) {
                Ok(Some(t)) => Some(t),
                Ok(None) => return ctx.app.internal(&"base commit has no tree"),
                Err(e) => return read_err(ctx, a, e),
            },
            None => None,
        };
        let mut budget = gw::Budget::new(started + DEADLINE);
        let walk = match gw::walk(git, &d, root.as_deref(), &comps, &mut budget) {
            Ok(w) => w,
            Err(e) => return write_err(ctx, a, e),
        };
        if started.elapsed() > DEADLINE {
            return error(&ctx.app.base, 503, "the write took too long, try again");
        }
        let prev_mode = match gw::check(&op, &comps, &walk) {
            Ok(m) => m,
            Err(r) => return refuse(ctx, &w.path, r),
        };
        // The content and slack once, and for this attempt the tree bytes the walk read (the rewrite
        // stores about as many).
        if held.is_none() {
            held = ctx
                .app
                .transports
                .reserve_disk(&ctx.app.data_dir, w.bytes.len() as u64 + RESERVE_SLACK);
            if held.is_none() {
                return error(&ctx.app.base, 507, "insufficient storage");
            }
        }
        let trees = (gw::TOTAL_LISTING - budget.listing) as u64 + (1 << 20);
        let _trees_held = match ctx.app.transports.reserve_disk(&ctx.app.data_dir, trees) {
            Some(h) => h,
            None => return error(&ctx.app.base, 507, "insufficient storage"),
        };
        if blob.is_none() && w.verb != Verb::Delete {
            match gw::hash_blob(git, &d, &w.bytes, started + DEADLINE) {
                Ok(b) => blob = Some(b),
                Err(e) => return read_err(ctx, a, e),
            }
        }
        let mode = prev_mode.unwrap_or_else(|| "100644".to_string());
        let file = blob.as_deref().map(|b| (mode.as_str(), b));
        let tree = match gw::rebuild(git, &d, &walk, &comps, file, started + DEADLINE) {
            Ok(t) => t,
            Err(e) => return write_err(ctx, a, e),
        };
        if started.elapsed() > DEADLINE {
            return error(&ctx.app.base, 503, "the write took too long, try again");
        }
        let commit = match gw::commit_tree(
            git,
            &d,
            &tree,
            old.as_deref(),
            &w.message,
            &identity,
            started + DEADLINE,
        ) {
            Ok(c) => c,
            Err(e) => return read_err(ctx, a, e),
        };
        let creating = new_branch.is_some() || bootstrap;
        let (full, expected) = if creating {
            (refname::branch_ref(&target_name), gw::ZERO.to_string())
        } else {
            (base_ref.clone(), old.clone().unwrap_or_default())
        };
        let resp = response(
            ctx,
            a,
            w,
            &target_name,
            &commit,
            &tree,
            old.as_deref(),
            blob.as_deref(),
            &mode,
            when,
        );
        if started.elapsed() > DEADLINE {
            return error(&ctx.app.base, 503, "the write took too long, try again");
        }
        // The linearization point of branch protection: just before the ref moves.
        let rules = match crate::protection::load(ctx.conn, a.repo.id) {
            Ok(r) => r,
            Err(e) => return ctx.app.internal(&e),
        };
        if policy::check_contents_write(&rules, &target_name, creating).is_err() {
            return denied(ctx);
        }
        let failure = match gw::update_ref(git, &d, &full, &commit, &expected) {
            Ok(None) => return published(ctx, a, resp),
            Ok(Some(stderr)) => stderr,
            Err(e) => return read_err(ctx, a, e),
        };
        let now_tip = match gw::read_ref(git, &d, &full) {
            Ok(t) => t,
            Err(e) => return read_err(ctx, a, e),
        };
        let expected_old = if creating { None } else { old.as_deref() };
        // A killed update-ref may have landed and been built on by a push before the re-read: our
        // commit is then an ancestor of the tip, and the write succeeded.
        let landed = match &now_tip {
            Some(t) if *t != commit => match gw::is_ancestor(git, &d, &commit, t) {
                Ok(b) => b,
                Err(e) => return read_err(ctx, a, e),
            },
            _ => false,
        };
        let seen = if landed {
            Some(commit.as_str())
        } else {
            now_tip.as_deref()
        };
        match gw::classify(expected_old, bootstrap, &commit, seen, &failure) {
            Outcome::Done => return published(ctx, a, resp),
            Outcome::Lost => locked = false,
            Outcome::LostAfterBackoff => {
                locked = true;
                std::thread::sleep(BACKOFF);
                continue;
            }
            Outcome::Gone => return no_branch(ctx, &base_name),
            Outcome::Exists => {
                return unprocessable(ctx, &format!("branch already exists [name: {target_name}]"))
            }
            Outcome::DfConflict => {
                return unprocessable(
                    ctx,
                    &format!("branch name conflicts with an existing branch [name: {target_name}]"),
                )
            }
            Outcome::Fatal => {
                eprintln!("sc-forge: update-ref {full} failed on attempt {attempt}: {failure}");
                return ctx.app.internal(&"could not update the branch");
            }
        }
        eprintln!("sc-forge: contents write to {full} lost round {attempt}: {failure}");
    }
    if locked {
        // Three rounds against a ref lock that never cleared: nothing changed the branch. A killed
        // git can leave `refs/heads/<branch>.lock` behind; it blocks pushes as well.
        eprintln!(
            "sc-forge: refs/heads/{target_name} of repository {} stayed locked; if no git process is running, remove its .lock file",
            a.repo.id
        );
        return error(&ctx.app.base, 503, "the branch is locked, try again later");
    }
    error(
        &ctx.app.base,
        409,
        "the branch was changed concurrently, try again",
    )
}

fn gobj_branches(ctx: &Ctx, a: &Access) -> Result<Vec<String>, Resp> {
    gw::branch_names(&ctx.app.life.git, &dir(ctx, a)).map_err(|e| read_err(ctx, a, e))
}

fn write_err(ctx: &Ctx, a: &Access, e: WriteErr) -> Resp {
    match e {
        WriteErr::Git(e) => read_err(ctx, a, e),
        WriteErr::Rewrite(m) => {
            eprintln!("sc-forge: contents write could not rewrite a directory: {m}");
            unprocessable(ctx, "a directory on the path cannot be rewritten")
        }
    }
}

/// The ref moved: stamp the repository (log-only, the write is already public) and answer.
fn published(ctx: &Ctx, a: &Access, resp: Resp) -> Resp {
    if let Err(e) = repos::touch(ctx.conn, a.repo.id, now()) {
        eprintln!(
            "sc-forge: could not stamp repository {} after a contents write: {e}",
            a.repo.id
        );
    }
    // The branch moved: PRs on it follow (the write gate is held).
    crate::pulls_api::sync_held(ctx, a);
    resp
}

/// The Gitea response for the commit just built.
#[allow(clippy::too_many_arguments)]
fn response(
    ctx: &Ctx,
    a: &Access,
    w: &Write,
    target: &str,
    commit: &str,
    tree: &str,
    parent: Option<&str>,
    blob: Option<&str>,
    mode: &str,
    when: i64,
) -> Resp {
    let (api, web) = (api_base(ctx, a), web_base(ctx, a));
    let user = &ctx.who.user;
    let email = commit_email(user);
    let person = json!({"name": user.login, "email": email, "date": rfc3339(when)});
    let content = match blob {
        Some(oid) => {
            let e = TreeEntry {
                mode: mode.to_string(),
                kind: "blob".into(),
                oid: oid.to_string(),
                size: Some(w.bytes.len() as u64),
                path: w.path.clone(),
            };
            content_value(
                ctx,
                a,
                target,
                RefKind::Branch,
                &e,
                commit,
                json!("base64"),
                Value::String(b64::encode(&w.bytes)),
                Value::Null,
            )
        }
        None => Value::Null,
    };
    let body = json!({
        "content": content,
        "commit": {
            "url": format!("{api}/git/commits/{commit}"),
            "sha": commit,
            "created": rfc3339(when),
            "html_url": format!("{web}/commit/{commit}"),
            "author": person,
            "committer": person,
            "parents": parent.map(|p| vec![json!({"url": format!("{api}/git/commits/{p}"), "sha": p, "created": rfc3339(when)})]).unwrap_or_default(),
            "message": w.message,
            "tree": {"url": format!("{api}/git/trees/{tree}"), "sha": tree, "created": rfc3339(when)},
        },
        "verification": verification(),
    });
    Resp::json(if w.verb == Verb::Post { 201 } else { 200 }, &body)
}
