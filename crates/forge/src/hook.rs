//! The `pre-receive` hook, run by `git receive-pack` as the symlink `<data>/hooks/pre-receive`
//! (argv[0] `pre-receive`) or as `sc-forge hook pre-receive`. It reads `<old> <new> <ref>` lines on
//! stdin, asks [`crate::policy`] about each, and exits non-zero (refusing the whole push) with one
//! `remote:` line per refusal. It fails closed: a missing environment, an unreadable database, a
//! repository that is not `live` all refuse the push.
//!
//! Trust boundary: the hook runs with the server's user and read access to the database; its code
//! cannot be replaced by repository content (`core.hooksPath` is pinned per spawn and repositories
//! are created without a hooks directory), and it trusts nothing from git but the three stdin fields.

use crate::gitproc::{Git, Spec};
use crate::policy::Rules;
use crate::{db, policy, protection, repos};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Read git's update lines from `r` as raw bytes. Any read error or any line that is not valid UTF-8
/// refuses the whole push: stopping at the first bad line would leave the rest unchecked (fail open).
pub fn read_updates(mut r: impl Read) -> Result<Vec<String>, String> {
    let mut raw = Vec::new();
    r.read_to_end(&mut raw)
        .map_err(|e| format!("cannot read the update lines: {e}"))?;
    raw.split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            String::from_utf8(l.to_vec())
                .map_err(|_| "an update line is not valid UTF-8".to_string())
        })
        .collect()
}

/// Decide a whole push. `lines` are git's `<old> <new> <ref>` records; returns every refusal text.
/// `is_ff(old, new)` answers whether `new` descends from `old`; it is asked only for an update of
/// an existing protected branch that allows pushes.
pub fn decide(
    lines: &[String],
    default_branch: &str,
    live: bool,
    rules: &Rules,
    is_ff: &dyn Fn(&str, &str) -> Result<bool, String>,
) -> Vec<String> {
    if !live {
        return vec!["refusing the push: the repository is not available".to_string()];
    }
    let mut out = Vec::new();
    for l in lines {
        let mut it = l.splitn(3, ' ');
        match (it.next(), it.next(), it.next()) {
            (Some(old), Some(new), Some(name)) if !name.is_empty() => {
                let verdict = policy::check_update(name, new, default_branch).and_then(|()| {
                    match name.strip_prefix("refs/heads/") {
                        Some(branch) => {
                            policy::check_protected_push(rules, branch, old, new, || {
                                is_ff(old, new)
                            })
                        }
                        None => Ok(()),
                    }
                });
                if let Err(e) = verdict {
                    out.push(e);
                }
            }
            _ => out.push(format!("refusing the push: malformed update line {l:?}")),
        }
    }
    out
}

/// What the hook needs to know about the repository.
pub struct RepoInfo {
    pub default_branch: String,
    pub live: bool,
    pub rules: Rules,
}

/// Look up the repository the hook runs for.
pub fn lookup(data_dir: &Path, repo_id: i64) -> Result<RepoInfo, String> {
    let conn = db::open_readonly(data_dir).map_err(|e| e.to_string())?;
    match repos::find_by_id(&conn, repo_id).map_err(|e| e.to_string())? {
        Some(r) => Ok(RepoInfo {
            rules: protection::load(&conn, r.id).map_err(|e| e.to_string())?,
            live: r.state == "live",
            default_branch: r.default_branch,
        }),
        None => Err(format!("repository {repo_id} does not exist")),
    }
}

fn full_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An object directory git handed the hook is acceptable only when it lies under the
/// repository's own `objects/` (receive-pack's quarantine does).
fn under(objects: &Path, p: &Path) -> bool {
    p.is_absolute()
        && !p.components().any(|c| matches!(c, Component::ParentDir))
        && p.starts_with(objects)
}

/// Is `new` a descendant of `old`? Runs `git merge-base --is-ancestor` with the sanitized runner
/// environment plus the quarantine's object directories (the pushed objects are only there until
/// the push is accepted). Anything unexpected refuses the update.
fn is_ff_in(
    data_dir: &Path,
    repo_id: i64,
    git_bin: &Path,
    old: &str,
    new: &str,
) -> Result<bool, String> {
    if !full_id(old) || !full_id(new) {
        return Err("malformed object id".into());
    }
    let git = Git::new(data_dir, git_bin.to_path_buf(), 1).map_err(|e| e.to_string())?;
    let repo: PathBuf = git.data_dir().join("repos").join(format!("{repo_id}.git"));
    let objects = repo.join("objects");
    let incoming = std::env::var("GIT_OBJECT_DIRECTORY").ok();
    let alternates = std::env::var("GIT_ALTERNATE_OBJECT_DIRECTORIES").ok();
    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(d) = incoming.as_deref() {
        if !under(&objects, Path::new(d)) {
            return Err("unexpected object directory".into());
        }
        extra.push(("GIT_OBJECT_DIRECTORY", d));
    }
    if let Some(a) = alternates.as_deref() {
        // A colon-separated list; every entry must be one of the repository's own.
        if !a.split(':').all(|d| under(&objects, Path::new(d))) {
            return Err("unexpected alternate object directory".into());
        }
        extra.push(("GIT_ALTERNATE_OBJECT_DIRECTORIES", a));
    }
    let out = git
        .run(&Spec {
            repo: Some(&repo),
            args: &["merge-base", "--is-ancestor", old, new],
            extra_env: &extra,
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
    }
}

/// Point `<data>/hooks/pre-receive` at `exe` (this binary): a symlink, so git runs the hook with no
/// shell and the path needs no quoting. Replaced atomically, at every start, because the binary's
/// path can change between runs.
pub fn install(data_dir: &Path, exe: &Path) -> std::io::Result<()> {
    let hooks = data_dir.join("hooks");
    std::fs::create_dir_all(&hooks)?;
    let tmp = hooks.join(".pre-receive.new");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(exe, &tmp)?;
    std::fs::rename(&tmp, hooks.join("pre-receive"))
}

/// Before a push deletes the head branch of an open pull request, record the branch's tip in the
/// PR's retention ref (`old` is the tip the push deletes). The spawn has no quarantine variables,
/// so git accepts the ref update; `old` already exists in the repository. A failure refuses the
/// push: deleting the branch would otherwise lose the only reference to that commit.
fn retain_deleted_heads(
    data_dir: &Path,
    repo_id: i64,
    git_bin: Option<&Path>,
    lines: &[String],
) -> Result<(), String> {
    let deletes: Vec<(&str, &str)> = lines
        .iter()
        .filter_map(|l| {
            let mut it = l.splitn(3, ' ');
            let (old, new, name) = (it.next()?, it.next()?, it.next()?);
            (policy::is_delete(new) && !policy::is_delete(old))
                .then(|| name.strip_prefix("refs/heads/").map(|b| (old, b)))
                .flatten()
        })
        .collect();
    if deletes.is_empty() {
        return Ok(());
    }
    let git_bin = git_bin.ok_or("FORGE_GIT_BIN is not set")?;
    let conn = db::open_readonly(data_dir).map_err(|e| e.to_string())?;
    let open = crate::pulls::open_pulls(&conn, repo_id).map_err(|e| e.to_string())?;
    let git = Git::new(data_dir, git_bin.to_path_buf(), 1).map_err(|e| e.to_string())?;
    let repo = git.data_dir().join("repos").join(format!("{repo_id}.git"));
    for (old, branch) in deletes {
        for p in open.iter().filter(|p| p.head_ref == branch) {
            if !full_id(old) {
                return Err("malformed object id".into());
            }
            crate::pulls::retain(&git, &repo, p.number, old).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Entry point: returns the process exit code.
pub fn run() -> i32 {
    let (Some(data), Some(id)) = (
        std::env::var_os("FORGE_DATA_DIR"),
        std::env::var("FORGE_REPO_ID")
            .ok()
            .and_then(|v| v.parse::<i64>().ok()),
    ) else {
        eprintln!(
            "sc-forge pre-receive: refusing the push: missing FORGE_DATA_DIR or FORGE_REPO_ID"
        );
        return 1;
    };
    let lines = match read_updates(std::io::stdin().lock()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sc-forge pre-receive: refusing the push: {e}");
            return 1;
        }
    };
    let info = match lookup(Path::new(&data), id) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("sc-forge pre-receive: refusing the push: {e}");
            return 1;
        }
    };
    let git_bin = std::env::var_os("FORGE_GIT_BIN").map(PathBuf::from);
    let is_ff = |old: &str, new: &str| match &git_bin {
        Some(b) => is_ff_in(Path::new(&data), id, b, old, new),
        None => Err("FORGE_GIT_BIN is not set".into()),
    };
    let refusals = decide(&lines, &info.default_branch, info.live, &info.rules, &is_ff);
    let refusals = if refusals.is_empty() {
        match retain_deleted_heads(Path::new(&data), id, git_bin.as_deref(), &lines) {
            Ok(()) => refusals,
            Err(e) => vec![format!(
                "refusing the push: cannot keep the head of a pull request ({e})"
            )],
        }
    } else {
        refusals
    };
    for r in &refusals {
        eprintln!("{r}");
    }
    // Tell the server that this push was let through, so it stamps the repository only for a push
    // that could change a ref (git exits 0 after reporting a rejection, too).
    if refusals.is_empty() && !lines.is_empty() {
        if let Some(m) = std::env::var_os("FORGE_ACCEPT_MARKER") {
            let _ = std::fs::write(m, b"");
        }
    }
    i32::from(!refusals.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const Z: &str = "0000000000000000000000000000000000000000";
    const A: &str = "1111111111111111111111111111111111111111";

    fn l(new: &str, r: &str) -> String {
        format!("{A} {new} {r}")
    }

    fn ff(v: bool) -> impl Fn(&str, &str) -> Result<bool, String> {
        move |_, _| Ok(v)
    }

    fn rules(push: bool) -> Rules {
        Rules(vec![policy::Rule {
            branch: "rel".into(),
            enable_push: push,
            enable_status_check: false,
            contexts: None,
        }])
    }

    #[test]
    fn protection_rules_decide_pushes_and_the_default_branch_text_comes_first() {
        let one =
            |rules: &Rules, line: String, f: bool| decide(&[line], "main", true, rules, &ff(f));
        assert_eq!(one(&rules(false), l(A, "refs/heads/rel"), true).len(), 1);
        assert_eq!(one(&rules(true), l(A, "refs/heads/rel"), true).len(), 0);
        assert_eq!(one(&rules(true), l(A, "refs/heads/rel"), false).len(), 1);
        assert_eq!(one(&rules(true), l(Z, "refs/heads/rel"), true).len(), 1);
        assert_eq!(one(&rules(true), l(A, "refs/heads/other"), false).len(), 0);
        assert_eq!(one(&rules(true), l(A, "refs/tags/rel"), false).len(), 0);
        let bad = decide(
            &[l(A, "refs/heads/rel")],
            "main",
            true,
            &rules(true),
            &|_, _| Err("boom".into()),
        );
        assert_eq!(bad.len(), 1, "a failed ancestry check refuses");
        let main = Rules(vec![policy::Rule {
            branch: "main".into(),
            enable_push: true,
            enable_status_check: false,
            contexts: None,
        }]);
        let out = one(&main, l(Z, "refs/heads/main"), true);
        assert!(out[0].contains("default branch"), "{out:?}");
    }

    #[test]
    fn a_clean_push_is_accepted() {
        assert!(decide(
            &[l(A, "refs/heads/feat"), l(A, "refs/tags/v1")],
            "main",
            true,
            &Rules::default(),
            &ff(true)
        )
        .is_empty());
    }

    #[test]
    fn one_bad_ref_refuses_the_whole_push_and_every_refusal_is_reported() {
        let out = decide(
            &[
                l(A, "refs/heads/ok"),
                l(A, "refs/replace/x"),
                l(Z, "refs/heads/MAIN"),
                l(A, "refs/pull/1/head"),
            ],
            "main",
            true,
            &Rules::default(),
            &ff(true),
        );
        assert_eq!(out.len(), 3, "{out:?}");
        assert!(
            out[0].contains("refs/replace/x")
                && out[1].contains("default branch")
                && out[2].contains("refs/pull/1/head")
        );
    }

    #[test]
    fn a_repository_that_is_not_live_refuses_everything() {
        assert_eq!(
            decide(
                &[l(A, "refs/heads/x")],
                "main",
                false,
                &Rules::default(),
                &ff(true)
            )
            .len(),
            1
        );
    }

    #[test]
    fn malformed_lines_fail_closed() {
        for bad in ["", "onlyone", "a b", "a b "] {
            assert_eq!(
                decide(
                    &[bad.to_string()],
                    "main",
                    true,
                    &Rules::default(),
                    &ff(true)
                )
                .len(),
                1,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn unreadable_or_non_utf8_update_lines_refuse_the_whole_push() {
        assert_eq!(
            read_updates(&b"a b refs/heads/x\nc d refs/tags/y\n"[..])
                .unwrap()
                .len(),
            2
        );
        assert!(
            read_updates(&b"a b refs/heads/ok\na b refs/replace/\xff\n"[..]).is_err(),
            "a bad line must not hide the lines after it"
        );
        assert!(read_updates(&b"\xff\na b refs/replace/x\n"[..]).is_err());
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        assert!(read_updates(Broken).is_err());
    }

    #[test]
    fn the_lookup_reports_live_state_and_the_default_branch() {
        let d = std::env::temp_dir().join(format!("scl-forge-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let conn = db::open_for_admin(&d).unwrap();
        let owner = crate::store::create_account(
            &conn,
            &crate::store::NewAccount {
                login: "o".into(),
                visibility: "public".into(),
                ..Default::default()
            },
            1,
        )
        .unwrap();
        let r = repos::insert_creating(&conn, owner.id, "r", "trunk", "", "", 1).unwrap();
        let i = lookup(&d, r.id).unwrap();
        assert_eq!(
            (i.default_branch.as_str(), i.live),
            ("trunk", false),
            "creating is not live"
        );
        repos::set_state(&conn, r.id, "creating", "live", 2).unwrap();
        let i = lookup(&d, r.id).unwrap();
        assert_eq!((i.default_branch.as_str(), i.live), ("trunk", true));
        assert!(i.rules.0.is_empty());
        assert!(lookup(&d, 999).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn object_directories_must_lie_under_the_repository_and_ids_must_be_full_hex() {
        let objects = Path::new("/data/repos/7.git/objects");
        for ok in [
            "/data/repos/7.git/objects",
            "/data/repos/7.git/objects/incoming-AbC123",
        ] {
            assert!(under(objects, Path::new(ok)), "{ok}");
        }
        for bad in [
            "/data/repos/7.git/objects/../../8.git/objects",
            "/data/repos/7.git/objects2",
            "/data/repos/8.git/objects",
            "/data/repos/7.git",
            "objects/incoming",
            "",
        ] {
            assert!(!under(objects, Path::new(bad)), "{bad:?}");
        }
        assert!(full_id(A) && full_id(&"a".repeat(64)));
        for bad in ["", "abc", &"g".repeat(40), &"a".repeat(41), "-q"] {
            assert!(!full_id(bad), "{bad:?}");
        }
    }
}
