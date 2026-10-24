//! Read-only views of a bare repository, built on the [`Git`] runner. Branch names reach git
//! only as the full ref `refs/heads/<name>` after [`refname::valid_branch`]; commit data is
//! parsed from the raw commit object, so no format string or message content can confuse the
//! parser.

use crate::gitproc::{Git, GitError, Spec};
use crate::refname;
use std::path::Path;

/// A branch and the commit it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    pub name: String,
    pub oid: String,
}

/// One person line of a commit (`author`/`committer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub name: String,
    pub email: String,
    /// Seconds since the epoch.
    pub when: i64,
}

/// The parts of a commit the API shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub oid: String,
    /// The full message, as stored (it keeps its trailing newline).
    pub message: String,
    pub author: Person,
    pub committer: Person,
}

/// All branches, newest commit first, ties by name (recorded P#19-22: Gitea lists the branch that was
/// committed to last first).
pub fn list_branches(git: &Git, dir: &Path) -> Result<Vec<Branch>, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &[
            "for-each-ref",
            "--sort=refname",
            "--sort=-committerdate",
            "--format=%(refname)%00%(objectname)",
            "refs/heads",
        ],
        ..Default::default()
    })?;
    if !out.ok() {
        // A damaged or vanished repository is not an empty one.
        return Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (r, oid) = l.split_once('\0')?;
            Some(Branch {
                name: r.strip_prefix("refs/heads/")?.to_string(),
                oid: oid.to_string(),
            })
        })
        .collect())
}

/// Exit status 1 from `rev-parse --verify -q` means "no such ref"; anything else (128: not a
/// repository, corrupt) is a failure the caller must not read as absence.
fn found(out: &crate::gitproc::Out) -> Result<bool, GitError> {
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
    }
}

/// The commit a branch points at, or `None` when the branch does not exist (or the name is not
/// a valid branch name).
pub fn branch_oid(git: &Git, dir: &Path, name: &str) -> Result<Option<String>, GitError> {
    if !refname::valid_branch(name) {
        return Ok(None);
    }
    let full = refname::branch_ref(name);
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["rev-parse", "--verify", "-q", "--end-of-options", &full],
        ..Default::default()
    })?;
    Ok(found(&out)?.then(|| out.text()))
}

/// A repository is empty when `HEAD` does not resolve to a commit (computed live).
pub fn is_empty(git: &Git, dir: &Path) -> Result<bool, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["rev-parse", "--verify", "-q", "HEAD"],
        ..Default::default()
    })?;
    Ok(!found(&out)?)
}

fn person(line: &str) -> Option<Person> {
    // `Name <email> 1700000000 +0200`
    let (rest, _tz) = line.rsplit_once(' ')?;
    let (rest, when) = rest.rsplit_once(' ')?;
    let (name, email) = rest.rsplit_once(" <")?;
    Some(Person {
        name: name.to_string(),
        email: email.strip_suffix('>')?.to_string(),
        when: when.parse().ok()?,
    })
}

/// Parse the commit `oid` (a full object id from a prior git answer, never client text).
pub fn commit(git: &Git, dir: &Path, oid: &str) -> Result<Option<CommitInfo>, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["cat-file", "commit", oid],
        ..Default::default()
    })?;
    if !out.ok() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (head, message) = text.split_once("\n\n").unwrap_or((text.as_str(), ""));
    let (mut author, mut committer) = (None, None);
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("author ") {
            author = person(v);
        } else if let Some(v) = line.strip_prefix("committer ") {
            committer = person(v);
        }
    }
    Ok(match (author, committer) {
        (Some(author), Some(committer)) => Some(CommitInfo {
            oid: oid.to_string(),
            message: message.to_string(),
            author,
            committer,
        }),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitproc::{find_git, Identity};
    use std::path::PathBuf;

    fn repo(tag: &str) -> (Git, PathBuf, PathBuf) {
        let d =
            std::env::temp_dir().join(format!("scl-forge-gitread-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let g = Git::new(&d, find_git().expect("git"), 4).unwrap();
        let dir = d.join("1.git");
        assert!(g
            .run(&Spec {
                args: &[
                    "init",
                    "--bare",
                    "--quiet",
                    "--template=",
                    "--initial-branch=main",
                    dir.to_str().unwrap()
                ],
                ..Default::default()
            })
            .unwrap()
            .ok());
        (g, d, dir)
    }

    fn commit_on(g: &Git, dir: &Path, branch: &str, msg: &str) -> String {
        let id = Identity::new("Zoë Q", "zoe@example.invalid").unwrap();
        let tree = g
            .run(&Spec {
                repo: Some(dir),
                args: &["mktree"],
                stdin: Some(b""),
                ..Default::default()
            })
            .unwrap()
            .text();
        let oid = g
            .run(&Spec {
                repo: Some(dir),
                args: &["commit-tree", &tree],
                stdin: Some(msg.as_bytes()),
                identity: Some(&id),
                ..Default::default()
            })
            .unwrap()
            .text();
        assert!(g
            .run(&Spec {
                repo: Some(dir),
                args: &["update-ref", &refname::branch_ref(branch), &oid],
                ..Default::default()
            })
            .unwrap()
            .ok());
        oid
    }

    #[test]
    fn an_unborn_repo_is_empty_and_has_no_branches() {
        let (g, d, dir) = repo("unborn");
        assert!(is_empty(&g, &dir).unwrap());
        assert_eq!(list_branches(&g, &dir).unwrap(), vec![]);
        assert_eq!(branch_oid(&g, &dir, "main").unwrap(), None);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_damaged_repository_is_an_error_not_an_empty_one() {
        let (g, d, _dir) = repo("damaged");
        let broken = d.join("2.git"); // an empty directory: not a repository
        std::fs::create_dir_all(&broken).unwrap();
        assert!(matches!(is_empty(&g, &broken), Err(GitError::Failed(_))));
        assert!(matches!(
            list_branches(&g, &broken),
            Err(GitError::Failed(_))
        ));
        assert!(matches!(
            branch_oid(&g, &broken, "main"),
            Err(GitError::Failed(_))
        ));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn branches_sort_by_name_and_resolve_only_as_full_refs() {
        let (g, d, dir) = repo("branches");
        let a = commit_on(&g, &dir, "main", "first\n");
        let b = commit_on(&g, &dir, "feat/x", "feat two\n");
        assert!(!is_empty(&g, &dir).unwrap());
        assert_eq!(
            list_branches(&g, &dir).unwrap(),
            vec![
                Branch {
                    name: "feat/x".into(),
                    oid: b.clone()
                },
                Branch {
                    name: "main".into(),
                    oid: a.clone()
                }
            ]
        );
        assert_eq!(branch_oid(&g, &dir, "feat/x").unwrap(), Some(b));
        for not_a_branch in [
            "main~1",
            "main^",
            "HEAD",
            "refs/heads/main",
            "nope",
            "--all",
        ] {
            assert_eq!(
                branch_oid(&g, &dir, not_a_branch).unwrap(),
                None,
                "{not_a_branch}"
            );
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn commit_fields_come_from_the_raw_object() {
        let (g, d, dir) = repo("commit");
        let oid = commit_on(
            &g,
            &dir,
            "main",
            "subject line\n\nbody with <angle> and\nnewlines\n",
        );
        let c = commit(&g, &dir, &oid).unwrap().unwrap();
        assert_eq!(
            c.message,
            "subject line\n\nbody with <angle> and\nnewlines\n"
        );
        assert_eq!(
            (c.author.name.as_str(), c.author.email.as_str()),
            ("Zoë Q", "zoe@example.invalid")
        );
        assert_eq!(c.committer, c.author);
        assert!(c.author.when > 1_700_000_000);
        assert_eq!(
            commit(&g, &dir, "0000000000000000000000000000000000000001").unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn person_lines_parse_names_with_spaces_and_angle_brackets_in_the_email_only() {
        assert_eq!(
            person("A B C <a@x> 1700000000 +0200").unwrap(),
            Person {
                name: "A B C".into(),
                email: "a@x".into(),
                when: 1_700_000_000
            }
        );
        assert!(person("garbage").is_none());
    }
}
