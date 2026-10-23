//! Parsed views of a bare repository for the content API: refs, tags, history, trees, blobs, diffs
//! and archives. Everything here goes through the [`Git`] runner (own process group, scrubbed
//! environment, explicit `--git-dir`).
//!
//! **Argument hygiene.** A client string is never handed to git as a revision expression. A
//! revision is resolved by [`resolve`] to a full object id from a fixed set of shapes (`HEAD`,
//! `refs/heads/<valid name>`, `refs/tags/<valid name>`, a hex object id); only ids reach every other
//! command. Paths are literals (`--literal-pathspecs`, after `--`) and pass [`valid_path`] first.
//! Output is NUL-delimited where it carries names, and capped by the runner.

use crate::gitproc::{Git, GitError, Out, Spec};
use crate::gitread::Person;
use crate::refname;
use std::path::Path;
use std::time::Duration;

/// The empty tree: the base of a root commit's diff.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// Output cap of listings and diffs.
pub const BIG: usize = 64 << 20;

/// Output cap of a single blob read for the contents API (larger files answer without content).
pub const MAX_BLOB: u64 = 16 << 20;

/// Output cap of an archive (kept in memory; see the plan).
pub const MAX_ARCHIVE: usize = 128 << 20;

fn run(git: &Git, dir: &Path, args: &[&str], cap: Option<usize>) -> Result<Out, GitError> {
    git.run(&Spec {
        repo: Some(dir),
        args,
        max_output: cap,
        timeout: cap.map(|_| Duration::from_secs(120)),
        ..Default::default()
    })
}

/// stdout of a command that must succeed.
fn must(out: Out) -> Result<Vec<u8>, GitError> {
    if out.ok() {
        Ok(out.stdout)
    } else {
        Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

/// A 4 to 64 digit hexadecimal string (an object id, full or abbreviated).
pub fn is_hex(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A path inside a tree as a client may name it: relative, no empty, `.` or `..` component, no
/// NUL or other control character, not absurdly long.
pub fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 4096
        && !p.starts_with('/')
        && !p.chars().any(char::is_control)
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// How a revision was named; picks the `src/<kind>/` segment of the html URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    Branch,
    Tag,
    Commit,
}

impl RefKind {
    /// The path segment Gitea's html URLs use.
    pub fn segment(self) -> &'static str {
        match self {
            RefKind::Branch => "branch",
            RefKind::Tag => "tag",
            RefKind::Commit => "commit",
        }
    }
}

/// A resolved revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub oid: String,
    pub kind: RefKind,
}

/// What a revision is peeled to.
#[derive(Debug, Clone, Copy)]
pub enum Peel {
    Commit,
    Tree,
}

/// Resolve `rev` (a branch, a tag, `HEAD` or an object id) to an object id of kind `peel`. `None`
/// when it names nothing; a git failure that is not "not found" is an error.
pub fn resolve(
    git: &Git,
    dir: &Path,
    default_branch: &str,
    rev: &str,
    peel: Peel,
) -> Result<Option<Resolved>, GitError> {
    let suffix = match peel {
        Peel::Commit => "^{commit}",
        Peel::Tree => "^{tree}",
    };
    let mut candidates: Vec<(String, RefKind, bool)> = Vec::new();
    if rev == "HEAD" {
        candidates.push((refname::branch_ref(default_branch), RefKind::Branch, false));
    } else {
        if refname::valid_branch(rev) {
            candidates.push((refname::branch_ref(rev), RefKind::Branch, false));
            candidates.push((format!("refs/tags/{rev}"), RefKind::Tag, false));
        }
        if is_hex(rev) {
            candidates.push((rev.to_ascii_lowercase(), RefKind::Commit, true));
        }
    }
    for (spec, kind, lenient) in candidates {
        let full = format!("{spec}{suffix}");
        let out = run(
            git,
            dir,
            &["rev-parse", "--verify", "-q", "--end-of-options", &full],
            None,
        )?;
        match out.status.code() {
            Some(0) => {
                return Ok(Some(Resolved {
                    oid: out.text(),
                    kind,
                }))
            }
            Some(1) => {}
            // An abbreviation can be ambiguous or name an object of another kind: not found.
            _ if lenient => {}
            _ => {
                return Err(GitError::Failed(
                    String::from_utf8_lossy(&out.stderr).trim().to_string(),
                ))
            }
        }
    }
    Ok(None)
}

/// A branch or tag ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefRow {
    /// Full name, `refs/heads/x` or `refs/tags/x`.
    pub name: String,
    pub oid: String,
    /// `commit` or `tag` (an annotated tag object).
    pub kind: String,
    /// For an annotated tag, the commit it ends at.
    pub peeled: Option<String>,
    /// First line of the commit or tag message.
    pub subject: String,
    /// When the ref's own object was created (tagger date for an annotated tag).
    pub created: i64,
    /// Committer date of the commit the ref ends at.
    pub commit_date: i64,
}

impl RefRow {
    /// The commit the ref points at, through an annotated tag.
    pub fn commit(&self) -> &str {
        self.peeled.as_deref().unwrap_or(&self.oid)
    }
}

/// Branches and tags only (`refs/forge/`, `refs/pull/` and the rest are never listed), sorted by
/// name.
pub fn list_refs(git: &Git, dir: &Path, prefix: &str) -> Result<Vec<RefRow>, GitError> {
    debug_assert!(prefix == "refs/heads" || prefix == "refs/tags");
    let out = must(run(
        git,
        dir,
        &[
            "for-each-ref",
            "--sort=refname",
            "--format=%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)%00%(creatordate:unix)%00%(committerdate:unix)%00%(*committerdate:unix)%00%(contents:subject)",
            prefix,
        ],
        Some(BIG),
    )?)?;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| {
            let mut f = l.splitn(8, '\0');
            let (name, oid, kind, peeled, created, cdate, pdate, subject) = (
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
            );
            Some(RefRow {
                name: name.to_string(),
                oid: oid.to_string(),
                kind: kind.to_string(),
                peeled: (!peeled.is_empty()).then(|| peeled.to_string()),
                subject: subject.to_string(),
                created: created.parse().unwrap_or(0),
                commit_date: if peeled.is_empty() { cdate } else { pdate }
                    .parse()
                    .unwrap_or(0),
            })
        })
        .collect())
}

/// One commit as `log` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogCommit {
    pub oid: String,
    pub parents: Vec<String>,
    pub tree: String,
    pub author: Person,
    pub committer: Person,
    pub message: String,
}

const LOG_FORMAT: &str = "--format=%H%x00%P%x00%T%x00%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%B";

fn parse_log(raw: &[u8]) -> Vec<LogCommit> {
    let text = String::from_utf8_lossy(raw);
    let mut toks = text.split('\0');
    let mut out = Vec::new();
    loop {
        let mut f = [""; 10];
        for slot in f.iter_mut() {
            match toks.next() {
                Some(t) => *slot = t,
                None => return out,
            }
        }
        // `-z` puts a NUL after each record: the first token of the next one is the id.
        if f[0].is_empty() {
            return out;
        }
        out.push(LogCommit {
            oid: f[0].trim_start_matches('\n').to_string(),
            parents: f[1].split_whitespace().map(str::to_string).collect(),
            tree: f[2].to_string(),
            author: Person {
                name: f[3].to_string(),
                email: f[4].to_string(),
                when: f[5].parse().unwrap_or(0),
            },
            committer: Person {
                name: f[6].to_string(),
                email: f[7].to_string(),
                when: f[8].parse().unwrap_or(0),
            },
            message: f[9].to_string(),
        });
    }
}

/// `limit` commits of the history of `oid` after skipping `skip`, newest first; `path` restricts
/// to commits that touched it.
pub fn log(
    git: &Git,
    dir: &Path,
    oid: &str,
    path: Option<&str>,
    skip: usize,
    limit: usize,
) -> Result<Vec<LogCommit>, GitError> {
    let (skip, limit) = (format!("--skip={skip}"), format!("--max-count={limit}"));
    let mut args = vec![
        "--literal-pathspecs",
        "log",
        "-z",
        LOG_FORMAT,
        skip.as_str(),
        limit.as_str(),
        "--end-of-options",
        oid,
    ];
    if let Some(p) = path {
        args.extend(["--", p]);
    }
    Ok(parse_log(&must(run(git, dir, &args, Some(BIG))?)?))
}

/// One commit by full id, or `None` when it is not a commit.
pub fn commit(git: &Git, dir: &Path, oid: &str) -> Result<Option<LogCommit>, GitError> {
    Ok(log(git, dir, oid, None, 0, 1)?.into_iter().next())
}

/// How many commits are reachable from `oid` (through `path`, if given).
pub fn count(git: &Git, dir: &Path, oid: &str, path: Option<&str>) -> Result<u64, GitError> {
    let mut args = vec![
        "--literal-pathspecs",
        "rev-list",
        "--count",
        "--end-of-options",
        oid,
    ];
    if let Some(p) = path {
        args.extend(["--", p]);
    }
    let out = must(run(git, dir, &args, None)?)?;
    Ok(String::from_utf8_lossy(&out).trim().parse().unwrap_or(0))
}

/// A file a commit changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub name: String,
    /// `added`, `modified`, `removed` (Gitea's words).
    pub status: &'static str,
}

/// Lines added and removed across a commit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub additions: u64,
    pub deletions: u64,
}

/// Parse `diff-tree -r -z --raw --numstat` output.
fn parse_changes(raw: &[u8]) -> (Vec<FileChange>, Stats) {
    let text = String::from_utf8_lossy(raw);
    let mut toks = text.split('\0');
    let (mut files, mut stats) = (Vec::new(), Stats::default());
    while let Some(t) = toks.next() {
        if let Some(meta) = t.strip_prefix(':') {
            let status = meta.split_whitespace().last().unwrap_or("M");
            let Some(name) = toks.next() else { break };
            files.push(FileChange {
                name: name.to_string(),
                status: match status.chars().next() {
                    Some('A') => "added",
                    Some('D') => "removed",
                    _ => "modified",
                },
            });
        } else if let Some((a, rest)) = t.split_once('\t') {
            if let Some((d, _path)) = rest.split_once('\t') {
                // `-` for binary files
                stats.additions += a.parse::<u64>().unwrap_or(0);
                stats.deletions += d.parse::<u64>().unwrap_or(0);
            }
        }
    }
    (files, stats)
}

/// Files and line counts a commit changed against its first parent (the empty tree for a root).
pub fn changes(
    git: &Git,
    dir: &Path,
    parent: Option<&str>,
    oid: &str,
) -> Result<(Vec<FileChange>, Stats), GitError> {
    let base = parent.unwrap_or(EMPTY_TREE);
    let out = must(run(
        git,
        dir,
        &[
            "diff-tree",
            "-r",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--raw",
            "--numstat",
            "--end-of-options",
            base,
            oid,
        ],
        Some(BIG),
    )?)?;
    Ok(parse_changes(&out))
}

/// The unified diff of a commit against its first parent (`.diff`).
pub fn diff_text(
    git: &Git,
    dir: &Path,
    parent: Option<&str>,
    oid: &str,
) -> Result<Vec<u8>, GitError> {
    let base = parent.unwrap_or(EMPTY_TREE);
    must(run(
        git,
        dir,
        &[
            "diff-tree",
            "-p",
            "-r",
            "--no-color",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--end-of-options",
            base,
            oid,
        ],
        Some(BIG),
    )?)
}

/// A mailbox-format patch of one commit (`.patch`).
pub fn patch_text(git: &Git, dir: &Path, oid: &str) -> Result<Vec<u8>, GitError> {
    must(run(
        git,
        dir,
        &[
            "format-patch",
            "-1",
            "--root",
            "--stdout",
            "--no-signature",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--end-of-options",
            oid,
        ],
        Some(BIG),
    )?)
}

/// One entry of a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// Six digits, e.g. `100644`, `040000`, `120000`, `160000`.
    pub mode: String,
    /// `blob`, `tree` or `commit` (a submodule).
    pub kind: String,
    pub oid: String,
    /// Blob size; `None` for trees and submodules.
    pub size: Option<u64>,
    pub path: String,
}

fn parse_tree(raw: &[u8]) -> Vec<TreeEntry> {
    String::from_utf8_lossy(raw)
        .split('\0')
        .filter(|r| !r.is_empty())
        .filter_map(|r| {
            let (meta, path) = r.split_once('\t')?;
            let mut f = meta.split_whitespace();
            let (mode, kind, oid, size) = (f.next()?, f.next()?, f.next()?, f.next()?);
            Some(TreeEntry {
                mode: format!("{mode:0>6}"),
                kind: kind.to_string(),
                oid: oid.to_string(),
                size: size.parse().ok(),
                path: path.to_string(),
            })
        })
        .collect()
}

/// The entries of the tree `oid` (a tree id, from [`resolve`] with [`Peel::Tree`]); `recursive`
/// lists everything below, with the directories themselves, in path order.
pub fn ls_tree(
    git: &Git,
    dir: &Path,
    oid: &str,
    recursive: bool,
) -> Result<Vec<TreeEntry>, GitError> {
    let mut args = vec!["ls-tree", "-z", "-l"];
    if recursive {
        args.extend(["-r", "-t"]);
    }
    args.extend(["--end-of-options", oid]);
    Ok(parse_tree(&must(run(git, dir, &args, Some(BIG))?)?))
}

/// The entry at `path` in commit `commit`, or `None`.
pub fn tree_entry(
    git: &Git,
    dir: &Path,
    commit: &str,
    path: &str,
) -> Result<Option<TreeEntry>, GitError> {
    if !valid_path(path) {
        return Ok(None);
    }
    let out = must(run(
        git,
        dir,
        &[
            "--literal-pathspecs",
            "ls-tree",
            "-z",
            "-l",
            "--end-of-options",
            commit,
            "--",
            path,
        ],
        None,
    )?)?;
    Ok(parse_tree(&out).into_iter().find(|e| e.path == path))
}

/// The newest commit on `commit`'s history that touched `path`.
pub fn last_commit(
    git: &Git,
    dir: &Path,
    commit: &str,
    path: &str,
) -> Result<Option<String>, GitError> {
    let out = must(run(
        git,
        dir,
        &[
            "--literal-pathspecs",
            "log",
            "-n1",
            "--format=%H",
            "--end-of-options",
            commit,
            "--",
            path,
        ],
        None,
    )?)?;
    let t = String::from_utf8_lossy(&out).trim().to_string();
    Ok((!t.is_empty()).then_some(t))
}

/// The bytes of blob `oid`.
pub fn blob(git: &Git, dir: &Path, oid: &str) -> Result<Vec<u8>, GitError> {
    must(run(
        git,
        dir,
        &["cat-file", "blob", oid],
        Some(MAX_BLOB as usize + 1024),
    )?)
}

/// A tar or zip archive of commit `oid` with every path under `prefix/`.
pub fn archive(
    git: &Git,
    dir: &Path,
    oid: &str,
    prefix: &str,
    zip: bool,
) -> Result<Vec<u8>, GitError> {
    let fmt = if zip { "--format=zip" } else { "--format=tar" };
    let prefix = format!("--prefix={prefix}/");
    must(run(
        git,
        dir,
        &["archive", fmt, &prefix, "--end-of-options", oid],
        Some(MAX_ARCHIVE),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_literal_relative_and_clean() {
        for ok in ["a", "a/b.txt", "dir/with space/ü.rs", ".hidden", "a/.b"] {
            assert!(valid_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/a",
            "a//b",
            "a/",
            "./a",
            "a/./b",
            "../a",
            "a/..",
            "a/../b",
            "a\0b",
            "a\nb",
            &"x".repeat(5000),
        ] {
            assert!(!valid_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn hex_ids_are_four_to_sixty_four_digits() {
        assert!(is_hex("abcd") && is_hex(&"F".repeat(64)));
        assert!(!is_hex("abc") && !is_hex(&"a".repeat(65)) && !is_hex("abcg") && !is_hex(""));
    }

    #[test]
    fn log_records_split_on_their_fixed_field_count() {
        let rec =
            |h: &str, msg: &str| format!("{h}\0p1 p2\0t\0A B\0a@b.c\0100\0C\0c@d.e\0200\0{msg}\0");
        let raw = format!(
            "{}{}",
            rec("aaaa", "first\n\nbody\n"),
            rec("bbbb", "second\n")
        );
        let v = parse_log(raw.as_bytes());
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].oid, "aaaa");
        assert_eq!(v[0].parents, ["p1", "p2"]);
        assert_eq!(v[0].author.name, "A B");
        assert_eq!(v[0].committer.when, 200);
        assert_eq!(v[0].message, "first\n\nbody\n");
        assert_eq!(v[1].message, "second\n");
        assert!(parse_log(b"").is_empty());
        assert!(
            parse_log(b"aaaa\0only\0three").is_empty(),
            "a truncated record is dropped"
        );
    }

    #[test]
    fn changes_parse_raw_and_numstat_together() {
        let raw = b":100644 100644 aaa bbb M\0a.txt\0:000000 100644 000 ccc A\0n.txt\0:100644 000000 ddd 000 D\0d/b.txt\0\
                    1\t0\ta.txt\x001\t0\tn.txt\x000\t2\td/b.txt\0-\t-\tbin\0";
        let (files, stats) = parse_changes(raw);
        assert_eq!(
            files
                .iter()
                .map(|f| (f.name.as_str(), f.status))
                .collect::<Vec<_>>(),
            [
                ("a.txt", "modified"),
                ("n.txt", "added"),
                ("d/b.txt", "removed")
            ]
        );
        assert_eq!(
            stats,
            Stats {
                additions: 2,
                deletions: 2
            }
        );
    }

    #[test]
    fn tree_entries_parse_with_padded_sizes_and_odd_names() {
        let raw = [
            "100644 blob aaa      14\tREADME.md",
            "040000 tree bbb       -\tdocs",
            "100644 blob ccc       3\tdocs/a b\tc.md",
            "160000 commit ddd       -\tsub",
        ]
        .join("\0")
            + "\0";
        let v = parse_tree(raw.as_bytes());
        assert_eq!(v.len(), 4);
        assert_eq!((v[0].mode.as_str(), v[0].size), ("100644", Some(14)));
        assert_eq!((v[1].mode.as_str(), v[1].size), ("040000", None));
        assert_eq!(
            v[2].path, "docs/a b\tc.md",
            "a tab inside a name survives (only the first splits)"
        );
        assert_eq!(v[3].kind, "commit");
    }
}
