//! The `pre-receive` hook, run by `git receive-pack` as the symlink `<data>/hooks/pre-receive`
//! (argv[0] `pre-receive`) or as `sc-forge hook pre-receive`. It reads `<old> <new> <ref>` lines on
//! stdin, asks [`crate::policy`] about each, and exits non-zero (refusing the whole push) with one
//! `remote:` line per refusal. It fails closed: a missing environment, an unreadable database, a
//! repository that is not `live` all refuse the push.
//!
//! Trust boundary: the hook runs with the server's user and read access to the database; its code
//! cannot be replaced by repository content (`core.hooksPath` is pinned per spawn and repositories
//! are created without a hooks directory), and it trusts nothing from git but the three stdin fields.

use crate::{db, policy, repos};
use std::io::Read;
use std::path::Path;

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
pub fn decide(lines: &[String], default_branch: &str, live: bool) -> Vec<String> {
    if !live {
        return vec!["refusing the push: the repository is not available".to_string()];
    }
    let mut out = Vec::new();
    for l in lines {
        let mut it = l.splitn(3, ' ');
        match (it.next(), it.next(), it.next()) {
            (Some(_old), Some(new), Some(name)) if !name.is_empty() => {
                if let Err(e) = policy::check_update(name, new, default_branch) {
                    out.push(e);
                }
            }
            _ => out.push(format!("refusing the push: malformed update line {l:?}")),
        }
    }
    out
}

/// Look up the repository the hook runs for: `(default_branch, live)`.
pub fn lookup(data_dir: &Path, repo_id: i64) -> Result<(String, bool), String> {
    let conn = db::open_readonly(data_dir).map_err(|e| e.to_string())?;
    match repos::find_by_id(&conn, repo_id).map_err(|e| e.to_string())? {
        Some(r) => Ok((r.default_branch, r.state == "live")),
        None => Err(format!("repository {repo_id} does not exist")),
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
    let (default_branch, live) = match lookup(Path::new(&data), id) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("sc-forge pre-receive: refusing the push: {e}");
            return 1;
        }
    };
    let refusals = decide(&lines, &default_branch, live);
    for r in &refusals {
        eprintln!("{r}");
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

    #[test]
    fn a_clean_push_is_accepted() {
        assert!(decide(
            &[l(A, "refs/heads/feat"), l(A, "refs/tags/v1")],
            "main",
            true
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
        assert_eq!(decide(&[l(A, "refs/heads/x")], "main", false).len(), 1);
    }

    #[test]
    fn malformed_lines_fail_closed() {
        for bad in ["", "onlyone", "a b", "a b "] {
            assert_eq!(decide(&[bad.to_string()], "main", true).len(), 1, "{bad:?}");
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
        assert_eq!(
            lookup(&d, r.id).unwrap(),
            ("trunk".to_string(), false),
            "creating is not live"
        );
        repos::set_state(&conn, r.id, "creating", "live", 2).unwrap();
        assert_eq!(lookup(&d, r.id).unwrap(), ("trunk".to_string(), true));
        assert!(lookup(&d, 999).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
