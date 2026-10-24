//! The git half of contents writes (F3b): path rules, and building a commit from an edited tree with
//! plumbing only. Nothing here moves a ref except [`update_ref`], which the caller runs last. Trees
//! are handled as raw bytes from `ls-tree -z` to `mktree -z`: a name is never decoded, so an entry
//! the request did not touch cannot be renamed by the rewrite.

use crate::gitproc::{Git, GitError, Identity, Spec};
use std::path::Path;
use std::time::{Duration, Instant};

/// Most path components a write may have (each level costs a few git processes).
pub const MAX_DEPTH: usize = 64;
/// Largest raw listing of one directory read for a write.
pub const MAX_LISTING: usize = 16 << 20;
/// Cumulative raw listings of one write attempt.
pub const TOTAL_LISTING: usize = 32 << 20;
/// The all-zero id: "the ref must not exist".
pub const ZERO: &str = "0000000000000000000000000000000000000000";
/// Longest line `fsck` accepts in a `.gitattributes`.
const ATTR_LINE: usize = 2048;

/// Code points HFS+ ignores when it compares names, so `.g\u{200c}it` is `.git` on a Mac.
fn hfs_ignorable(c: char) -> bool {
    matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}')
}

/// The names `fsck` treats as the special file `.<name>`: the dotted name, and on NTFS the 8.3 short
/// names `<first six>~1` to `~4` and `<hash prefix>~1` to `~9`. `hash` is NTFS's fall-back short-name
/// prefix for that file (`gi7eba` for `.gitmodules`).
fn special_names(name: &str, hash: Option<&str>) -> Vec<String> {
    let mut v = vec![format!(".{name}")];
    v.extend((1..=4).map(|n| format!("{}~{n}", &name[..6])));
    if let Some(h) = hash {
        v.extend((1..=9).map(|n| format!("{h}~{n}")));
    }
    v
}

/// Whether a path component is one of `names` on any filesystem git runs on.
fn is_alias(component: &str, names: &[String]) -> bool {
    let c: String = component.chars().filter(|c| !hfs_ignorable(*c)).collect();
    // NTFS ignores trailing dots and spaces and treats `name:stream` as the file `name`.
    let c = c.split(':').next().unwrap_or("");
    let c = c.trim_end_matches([' ', '.']).to_ascii_lowercase();
    names.contains(&c)
}

fn git_names() -> Vec<String> {
    vec![".git".into(), "git~1".into()]
}

fn modules_names() -> Vec<String> {
    special_names("gitmodules", Some("gi7eba"))
}

fn attributes_names() -> Vec<String> {
    special_names("gitattributes", Some("gi7d29"))
}

/// Whether a client may create or change `path` through the API. Stricter than the read rules: a path a
/// checkout on macOS or Windows would resolve into `.git`, and `.gitmodules` (whose content `fsck`
/// checks only on pushes), can never be written here.
pub fn write_path_ok(path: &str) -> bool {
    let (git, modules, attrs) = (git_names(), modules_names(), attributes_names());
    let comps: Vec<&str> = path.split('/').collect();
    crate::gitobj::valid_path(path)
        && !path.ends_with('/')
        && !path.contains('\\')
        && comps.len() <= MAX_DEPTH
        && comps.iter().enumerate().all(|(i, c)| {
            c.len() <= 255
                && !is_alias(c, &git)
                && !is_alias(c, &modules)
                // fsck requires `.gitattributes` to be a blob, so it cannot be a directory
                && (i + 1 == comps.len() || !is_alias(c, &attrs))
        })
}

/// Whether `content` may be stored at `path`: `fsck` rejects a `.gitattributes` (by any of its aliases)
/// with a line of 2048 bytes or more, so a server-made commit must not carry one either.
pub fn content_ok(path: &str, content: &[u8]) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    !is_alias(name, &attributes_names())
        || content.split(|b| *b == b'\n').all(|l| l.len() < ATTR_LINE)
}

/// One raw tree entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// As `ls-tree` prints it: `100644`, `100755`, `120000`, `160000` or `040000`.
    pub mode: String,
    /// `blob`, `tree` or `commit`.
    pub kind: String,
    pub oid: String,
    pub name: Vec<u8>,
}

/// Parse `ls-tree -z` output (no `-l`); `None` when a record is malformed.
pub fn parse_tree(raw: &[u8]) -> Option<Vec<Entry>> {
    let mut out = Vec::new();
    for rec in raw.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let tab = rec.iter().position(|b| *b == b'\t')?;
        let meta = std::str::from_utf8(&rec[..tab]).ok()?;
        let mut f = meta.split(' ');
        let (mode, kind, oid) = (f.next()?, f.next()?, f.next()?);
        if f.next().is_some() {
            return None;
        }
        out.push(Entry {
            mode: mode.to_string(),
            kind: kind.to_string(),
            oid: oid.to_string(),
            name: rec[tab + 1..].to_vec(),
        });
    }
    Some(out)
}

/// The `mktree -z` input for `entries`.
pub fn mktree_input(entries: &[Entry]) -> Vec<u8> {
    let mut b = Vec::new();
    for e in entries {
        b.extend_from_slice(format!("{} {} {}\t", e.mode, e.kind, e.oid).as_bytes());
        b.extend_from_slice(&e.name);
        b.push(0);
    }
    b
}

/// Why a write could not be built or published (the handler maps these to responses).
#[derive(Debug)]
pub enum WriteErr {
    Git(GitError),
    /// `mktree` or the parser refused a directory that already exists in the repository.
    Rewrite(String),
}

impl From<GitError> for WriteErr {
    fn from(e: GitError) -> WriteErr {
        WriteErr::Git(e)
    }
}

/// What one write attempt may still use: listing bytes and time. Every git command gets what is left
/// of the time (at most 60 s), so a deep path on slow storage cannot outlive the operation's deadline.
pub struct Budget {
    pub listing: usize,
    pub end: Instant,
}

impl Budget {
    pub fn new(end: Instant) -> Budget {
        Budget {
            listing: TOTAL_LISTING,
            end,
        }
    }
}

fn run(
    git: &Git,
    dir: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    id: Option<&Identity>,
    cap: usize,
    end: Instant,
) -> Result<Vec<u8>, GitError> {
    let left = end.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(GitError::Timeout { stdout: Vec::new() });
    }
    let out = git.run(&Spec {
        repo: Some(dir),
        args,
        stdin,
        identity: id,
        max_output: Some(cap),
        timeout: Some(left.min(Duration::from_secs(60))),
    })?;
    if out.ok() {
        Ok(out.stdout)
    } else {
        Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

fn read_tree(
    git: &Git,
    dir: &Path,
    oid: &str,
    budget: &mut Budget,
) -> Result<Vec<Entry>, WriteErr> {
    let cap = MAX_LISTING.min(budget.listing);
    let raw = run(
        git,
        dir,
        &["ls-tree", "-z", oid],
        None,
        None,
        cap,
        budget.end,
    )?;
    budget.listing -= raw.len().min(budget.listing);
    parse_tree(&raw).ok_or_else(|| WriteErr::Rewrite(format!("unreadable tree {oid}")))
}

/// What the directories along a path hold.
pub struct Walk {
    /// `levels[i]` lists the directory that should contain component `i`; it is as long as the path
    /// when every parent directory exists.
    pub levels: Vec<Vec<Entry>>,
    /// The first component that exists but is not a directory.
    pub blocker: Option<usize>,
}

impl Walk {
    /// The existing entry at the end of `comps`, if the parents exist.
    pub fn leaf(&self, comps: &[&str]) -> Option<&Entry> {
        if self.levels.len() < comps.len() || self.blocker.is_some() {
            return None;
        }
        let last = comps.last()?.as_bytes();
        self.levels[comps.len() - 1].iter().find(|e| e.name == last)
    }
}

/// Read the directories from `root` (`None`: an unborn branch, an empty root) down `comps`.
pub fn walk(
    git: &Git,
    dir: &Path,
    root: Option<&str>,
    comps: &[&str],
    budget: &mut Budget,
) -> Result<Walk, WriteErr> {
    let mut levels = vec![match root {
        Some(t) => read_tree(git, dir, t, budget)?,
        None => Vec::new(),
    }];
    let mut blocker = None;
    for (i, c) in comps[..comps.len() - 1].iter().enumerate() {
        match levels[i].iter().find(|e| e.name == c.as_bytes()) {
            None => break,
            Some(e) if e.kind == "tree" => {
                let next = read_tree(git, dir, &e.oid, budget)?;
                levels.push(next);
            }
            Some(_) => {
                blocker = Some(i);
                break;
            }
        }
    }
    Ok(Walk { levels, blocker })
}

/// What a write intends to do to the file.
pub enum Op {
    Create,
    /// Replace the blob with this id.
    Update(String),
    /// Remove the blob with this id.
    Delete(String),
}

/// Why the current tree does not allow the write.
#[derive(Debug, PartialEq, Eq)]
pub enum Refuse {
    AlreadyExists,
    /// A parent directory of the path is a file; carries the path up to it.
    Blocked(String),
    NoFile,
    /// Not a regular file (symlink, submodule, directory).
    NotRegular,
    ShaMismatch {
        given: String,
        expected: String,
    },
}

/// Check `op` against what `walk` found; on success the mode of the file being replaced.
pub fn check(op: &Op, comps: &[&str], walk: &Walk) -> Result<Option<String>, Refuse> {
    if let Some(i) = walk.blocker {
        return match op {
            Op::Create => Err(Refuse::Blocked(comps[..=i].join("/"))),
            _ => Err(Refuse::NoFile),
        };
    }
    let leaf = walk.leaf(comps);
    match (op, leaf) {
        (Op::Create, Some(_)) => Err(Refuse::AlreadyExists),
        (Op::Create, None) => Ok(None),
        (Op::Update(_) | Op::Delete(_), None) => Err(Refuse::NoFile),
        (Op::Update(given) | Op::Delete(given), Some(e)) => {
            if e.kind != "blob" || !matches!(e.mode.as_str(), "100644" | "100755") {
                return Err(Refuse::NotRegular);
            }
            if &e.oid != given {
                return Err(Refuse::ShaMismatch {
                    given: given.clone(),
                    expected: e.oid.clone(),
                });
            }
            Ok(Some(e.mode.clone()))
        }
    }
}

fn mktree(git: &Git, dir: &Path, entries: &[Entry], end: Instant) -> Result<String, WriteErr> {
    let input = mktree_input(entries);
    match run(git, dir, &["mktree", "-z"], Some(&input), None, 4096, end) {
        Ok(o) => Ok(String::from_utf8_lossy(&o).trim().to_string()),
        Err(GitError::Failed(m)) => Err(WriteErr::Rewrite(m)),
        Err(e) => Err(e.into()),
    }
}

/// Rebuild the trees along `comps` with the file replaced by `file` (`mode`, blob id) or removed
/// (`None`); returns the new root tree. An emptied directory is dropped from its parent.
pub fn rebuild(
    git: &Git,
    dir: &Path,
    walk: &Walk,
    comps: &[&str],
    file: Option<(&str, &str)>,
    end: Instant,
) -> Result<String, WriteErr> {
    let n = comps.len();
    let mut child: Option<Entry> = file.map(|(mode, oid)| Entry {
        mode: mode.to_string(),
        kind: "blob".into(),
        oid: oid.to_string(),
        name: comps[n - 1].as_bytes().to_vec(),
    });
    let mut root = String::new();
    for i in (0..n).rev() {
        let mut entries = walk.levels.get(i).cloned().unwrap_or_default();
        entries.retain(|e| e.name != comps[i].as_bytes());
        entries.extend(child.take());
        if entries.is_empty() && i > 0 {
            continue;
        }
        let oid = mktree(git, dir, &entries, end)?;
        if i == 0 {
            root = oid;
        } else {
            child = Some(Entry {
                mode: "040000".into(),
                kind: "tree".into(),
                oid,
                name: comps[i - 1].as_bytes().to_vec(),
            });
        }
    }
    Ok(root)
}

/// Store `bytes` as a blob.
pub fn hash_blob(git: &Git, dir: &Path, bytes: &[u8], end: Instant) -> Result<String, GitError> {
    let o = run(
        git,
        dir,
        &["hash-object", "-w", "--no-filters", "-t", "blob", "--stdin"],
        Some(bytes),
        None,
        4096,
        end,
    )?;
    Ok(String::from_utf8_lossy(&o).trim().to_string())
}

/// A commit of `tree` on top of `parent`, as `id` (dates included), with `message` verbatim.
pub fn commit_tree(
    git: &Git,
    dir: &Path,
    tree: &str,
    parent: Option<&str>,
    message: &str,
    id: &Identity,
    end: Instant,
) -> Result<String, GitError> {
    let mut args = vec!["commit-tree", tree];
    if let Some(p) = parent {
        args.extend(["-p", p]);
    }
    let o = run(
        git,
        dir,
        &args,
        Some(message.as_bytes()),
        Some(id),
        4096,
        end,
    )?;
    Ok(String::from_utf8_lossy(&o).trim().to_string())
}

/// Is commit `a` reachable from commit `b`? (A write that landed and was then built on by someone else.)
pub fn is_ancestor(git: &Git, dir: &Path, a: &str, b: &str) -> Result<bool, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["merge-base", "--is-ancestor", a, b],
        ..Default::default()
    })?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
    }
}

/// Every branch name (without `refs/heads/`), for the collision check of a new branch.
pub fn branch_names(git: &Git, dir: &Path) -> Result<Vec<String>, GitError> {
    let args = ["for-each-ref", "--format=%(refname:lstrip=2)", "refs/heads"];
    let raw = run(
        git,
        dir,
        &args,
        None,
        None,
        MAX_LISTING,
        Instant::now() + Duration::from_secs(60),
    )?;
    Ok(String::from_utf8_lossy(&raw)
        .lines()
        .map(String::from)
        .collect())
}

/// The commit `full` (a `refs/heads/...` name) points at, `None` when it does not exist.
pub fn read_ref(git: &Git, dir: &Path, full: &str) -> Result<Option<String>, GitError> {
    let out = git.run(&Spec {
        repo: Some(dir),
        args: &["rev-parse", "--verify", "-q", "--end-of-options", full],
        ..Default::default()
    })?;
    match out.status.code() {
        Some(0) => Ok(Some(out.text())),
        Some(1) => Ok(None),
        _ => Err(GitError::Failed(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
    }
}

/// Move `full` to `new` if it still is `expected` (`ZERO`: if it does not exist). `Ok(Some(stderr))` is a
/// refusal by git; the caller decides what it meant with [`classify`].
pub fn update_ref(
    git: &Git,
    dir: &Path,
    full: &str,
    new: &str,
    expected: &str,
) -> Result<Option<String>, GitError> {
    match git.run(&Spec {
        repo: Some(dir),
        args: &["update-ref", full, new, expected],
        ..Default::default()
    }) {
        Ok(o) if o.ok() => Ok(None),
        Ok(o) => Ok(Some(String::from_utf8_lossy(&o.stderr).trim().to_string())),
        // The process was killed: whether the ref moved is for the re-read to say.
        Err(GitError::Timeout { .. }) => Ok(Some("update-ref timed out".into())),
        Err(e) => Err(e),
    }
}

/// What a failed `update-ref` meant, judged from a re-read of the ref.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The ref already holds the new commit (a killed process whose update landed).
    Done,
    /// Somebody else moved or created the ref: rebuild on its tip.
    Lost,
    /// A ref lock was held: rebuild after a short pause.
    LostAfterBackoff,
    /// The branch disappeared under an advance.
    Gone,
    /// An explicit `new_branch` that exists now.
    Exists,
    /// The new name collides with another branch name in the ref tree.
    DfConflict,
    Fatal,
}

/// `expected_old` is the tip an advance started from, `None` for a creation; `bootstrap` marks the
/// creation of the default branch of an unborn repository (a lost race there is an advance, not a
/// duplicate `new_branch`).
pub fn classify(
    expected_old: Option<&str>,
    bootstrap: bool,
    new: &str,
    now: Option<&str>,
    stderr: &str,
) -> Outcome {
    if now == Some(new) {
        return Outcome::Done;
    }
    let locked = stderr.contains(".lock")
        && (stderr.contains("File exists") || stderr.contains("Unable to create"));
    match (expected_old, now) {
        (Some(_), None) => Outcome::Gone,
        (Some(old), Some(cur)) if cur != old => Outcome::Lost,
        (Some(_), Some(_)) | (None, None) if locked => Outcome::LostAfterBackoff,
        (None, Some(_)) if bootstrap => Outcome::Lost,
        (None, Some(_)) => Outcome::Exists,
        (None, None) if stderr.contains("cannot lock ref") && stderr.contains("exists") => {
            Outcome::DfConflict
        }
        _ => Outcome::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitproc::find_git;

    /// Removes its directory when dropped, and checks it is gone (also when a test fails).
    struct Tmp(std::path::PathBuf);

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
            if !std::thread::panicking() {
                assert!(!self.0.exists(), "test dir must be gone after teardown");
            }
        }
    }

    fn repo(tag: &str) -> (Git, Tmp, std::path::PathBuf) {
        let d =
            std::env::temp_dir().join(format!("scl-forge-gitwrite-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let g = Git::new(&d, find_git().expect("git"), 4).unwrap();
        let dir = d.join("1.git");
        let init = [
            "init",
            "--bare",
            "--quiet",
            "--template=",
            "--initial-branch=main",
            dir.to_str().unwrap(),
        ];
        assert!(g
            .run(&Spec {
                args: &init,
                ..Default::default()
            })
            .unwrap()
            .ok());
        (g, Tmp(d), dir)
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn entry(mode: &str, kind: &str, oid: &str, name: &[u8]) -> Entry {
        Entry {
            mode: mode.into(),
            kind: kind.into(),
            oid: oid.into(),
            name: name.to_vec(),
        }
    }

    #[test]
    fn ordinary_paths_pass() {
        for p in [
            "a",
            "dir/file.txt",
            "a/b/c.md",
            ".gitignore",
            ".github/workflows/ci.yml",
            "gitx",
            "x.git",
            "a.git/b",
            ".gitattributes",
        ] {
            assert!(write_path_ok(p), "{p}");
        }
    }

    #[test]
    fn git_aliases_and_separators_are_refused() {
        for p in [
            "",
            "/a",
            "a/",
            "a//b",
            "a/./b",
            "a/../b",
            ".git",
            ".GIT",
            "a/.git/hooks/x",
            ".git.",
            ".git ",
            ".git. .",
            "git~1/x",
            "GIT~1",
            ".g\u{200c}it/x",
            ".git\u{feff}",
            ".git::$INDEX_ALLOCATION",
            ".git:stream",
            "a\\b",
            "..\\x",
            "a\u{0}b",
            "a\nb",
            ".gitmodules",
            "x/.GITMODULES",
            ".gitmodules.",
            "gitmod~1",
            ".gitmodules::$DATA",
            ".gitm\u{200d}odules",
            "gitmod~2",
            "GITMOD~4",
            "gi7eba~1",
            "gi7eba~9",
            "d/gi7eba~5",
            ".gitattributes/x",
            "a/.GITATTRIBUTES/b",
            "gitatt~1/f",
            "gi7d29~3/f",
        ] {
            assert!(!write_path_ok(p), "{p:?}");
        }
        assert!(!write_path_ok(&"x".repeat(256)));
        assert!(write_path_ok(&"x".repeat(255)));
        assert!(write_path_ok(&vec!["d"; MAX_DEPTH].join("/")));
        assert!(!write_path_ok(&vec!["d"; MAX_DEPTH + 1].join("/")));
    }

    #[test]
    fn gitattributes_lines_are_bounded() {
        assert!(content_ok("a/.gitattributes", &[b'x'; ATTR_LINE - 1]));
        assert!(!content_ok("a/.gitattributes", &[b'x'; ATTR_LINE]));
        assert!(!content_ok("a/.gitattributes", &[b'x'; ATTR_LINE + 1]));
        for alias in [
            ".GITATTRIBUTES",
            ".gitattributes.",
            ".gitattributes ",
            "gitatt~1",
            "GITATT~4",
            "gi7d29~1",
            "gi7d29~9",
        ] {
            assert!(!content_ok(&format!("d/{alias}"), &[b'x'; 3000]), "{alias}");
            assert!(content_ok(&format!("d/{alias}"), b"ok\n"), "{alias}");
        }
        assert!(content_ok("d/gitatt~5", &[b'x'; 3000]), "not an alias");
        assert!(content_ok("a/readme", &[b'x'; 10_000]));
    }

    #[test]
    fn raw_trees_round_trip_with_odd_names() {
        let oid = "1".repeat(40);
        let es = vec![
            entry("100644", "blob", &oid, b"plain"),
            entry("100644", "blob", &oid, b"bad\xff\x01name"),
            entry("040000", "tree", &oid, b"tab\tnl\nname"),
        ];
        assert_eq!(parse_tree(&mktree_input(&es)).unwrap(), es);
        assert!(parse_tree(b"100644 blob\n").is_none());
    }

    #[test]
    fn what_the_tree_allows() {
        let oid = "a".repeat(40);
        let w = Walk {
            levels: vec![
                vec![
                    entry("040000", "tree", &oid, b"d"),
                    entry("100644", "blob", &oid, b"f"),
                    entry("120000", "blob", &oid, b"l"),
                ],
                vec![entry("100755", "blob", &oid, b"x")],
            ],
            blocker: None,
        };
        assert_eq!(check(&Op::Create, &["d", "new"], &w), Ok(None));
        assert_eq!(
            check(&Op::Create, &["d", "x"], &w),
            Err(Refuse::AlreadyExists)
        );
        assert_eq!(
            check(&Op::Update(oid.clone()), &["d", "x"], &w),
            Ok(Some("100755".into()))
        );
        assert_eq!(
            check(&Op::Update("b".repeat(40)), &["d", "x"], &w),
            Err(Refuse::ShaMismatch {
                given: "b".repeat(40),
                expected: oid.clone()
            })
        );
        assert_eq!(
            check(&Op::Delete(oid.clone()), &["d", "none"], &w),
            Err(Refuse::NoFile)
        );
        let top = Walk {
            levels: w.levels[..1].to_vec(),
            blocker: None,
        };
        assert_eq!(
            check(&Op::Update(oid.clone()), &["l"], &top),
            Err(Refuse::NotRegular)
        );
        assert_eq!(
            check(&Op::Update(oid.clone()), &["d"], &top),
            Err(Refuse::NotRegular)
        );
        let blocked = Walk {
            levels: w.levels[..1].to_vec(),
            blocker: Some(0),
        };
        assert_eq!(
            check(&Op::Create, &["f", "g"], &blocked),
            Err(Refuse::Blocked("f".into()))
        );
        assert_eq!(
            check(&Op::Delete(oid), &["f", "g"], &blocked),
            Err(Refuse::NoFile)
        );
    }

    #[test]
    fn a_failed_update_ref_is_judged_by_the_ref_afterwards() {
        let (old, new, other) = ("o".repeat(40), "n".repeat(40), "x".repeat(40));
        let c = |expected: Option<&str>, boot: bool, now: Option<&str>, err: &str| {
            classify(expected, boot, &new, now, err)
        };
        assert_eq!(c(Some(&old), false, Some(&new), "killed"), Outcome::Done);
        assert_eq!(c(Some(&old), false, None, "x"), Outcome::Gone);
        assert_eq!(
            c(Some(&old), false, Some(&other), "is at x but expected o"),
            Outcome::Lost
        );
        assert_eq!(
            c(
                Some(&old),
                false,
                Some(&old),
                "Unable to create 'refs/heads/m.lock': File exists."
            ),
            Outcome::LostAfterBackoff
        );
        assert_eq!(
            c(Some(&old), false, Some(&old), "disk on fire"),
            Outcome::Fatal
        );
        assert_eq!(
            c(None, false, Some(&other), "reference already exists"),
            Outcome::Exists
        );
        assert_eq!(
            c(None, true, Some(&other), "reference already exists"),
            Outcome::Lost
        );
        assert_eq!(
            c(
                None,
                false,
                None,
                "cannot lock ref 'refs/heads/a/b': 'refs/heads/a' exists; cannot create"
            ),
            Outcome::DfConflict
        );
        assert_eq!(
            c(
                None,
                false,
                None,
                "Unable to create 'refs/heads/a.lock': File exists."
            ),
            Outcome::LostAfterBackoff
        );
    }

    #[test]
    fn a_rewrite_keeps_every_untouched_entry_byte_for_byte() {
        let (g, d, dir) = repo("rewrite");
        let blob = hash_blob(&g, &dir, b"old\n", far()).unwrap();
        let other = hash_blob(&g, &dir, b"other\n", far()).unwrap();
        let odd: [&[u8]; 3] = [b"bad\xff\x01name", b"tab\tnl\nname", b"z"];
        let mut dir_entries = vec![entry("100644", "blob", &blob, b"edit.txt")];
        dir_entries.extend(odd.iter().map(|n| entry("100755", "blob", &other, n)));
        let sub = mktree(&g, &dir, &dir_entries, far()).unwrap();
        let root_entries = vec![
            entry("040000", "tree", &sub, b"d"),
            entry("100644", "blob", &other, b"top"),
        ];
        let root = mktree(&g, &dir, &root_entries, far()).unwrap();

        let mut budget = Budget::new(far());
        let comps = ["d", "edit.txt"];
        let w = walk(&g, &dir, Some(&root), &comps, &mut budget).unwrap();
        assert!(check(&Op::Update(blob.clone()), &comps, &w).is_ok());
        let new_blob = hash_blob(&g, &dir, b"new\n", far()).unwrap();
        let new_root = rebuild(&g, &dir, &w, &comps, Some(("100644", &new_blob)), far()).unwrap();
        let mut budget = Budget::new(far());
        let w2 = walk(&g, &dir, Some(&new_root), &comps, &mut budget).unwrap();
        let listing = &w2.levels[1];
        for n in odd {
            let e = listing
                .iter()
                .find(|e| e.name == n)
                .unwrap_or_else(|| panic!("{n:?} survived"));
            assert_eq!(
                (e.mode.as_str(), e.oid.as_str()),
                ("100755", other.as_str())
            );
        }
        assert_eq!(w2.leaf(&comps).unwrap().oid, new_blob);
        assert!(w2.levels[0].iter().any(|e| e.name == b"top"));

        // deleting the only file of a directory drops the directory
        let root2 = mktree(
            &g,
            &dir,
            &[
                entry(
                    "040000",
                    "tree",
                    &mktree(&g, &dir, &[entry("100644", "blob", &blob, b"only")], far()).unwrap(),
                    b"solo",
                ),
                entry("100644", "blob", &other, b"keep"),
            ],
            far(),
        )
        .unwrap();
        let comps = ["solo", "only"];
        let mut budget = Budget::new(far());
        let w = walk(&g, &dir, Some(&root2), &comps, &mut budget).unwrap();
        let after = rebuild(&g, &dir, &w, &comps, None, far()).unwrap();
        let top = parse_tree(
            &run(
                &g,
                &dir,
                &["ls-tree", "-z", &after],
                None,
                None,
                4096,
                far(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            top.iter().map(|e| e.name.clone()).collect::<Vec<_>>(),
            vec![b"keep".to_vec()]
        );
        // an unborn branch is an empty root; a new nested file builds its directories
        let comps = ["a", "b", "c.txt"];
        let mut budget = Budget::new(far());
        let w = walk(&g, &dir, None, &comps, &mut budget).unwrap();
        assert_eq!(check(&Op::Create, &comps, &w), Ok(None));
        let t = rebuild(&g, &dir, &w, &comps, Some(("100644", &blob)), far()).unwrap();
        let listed = run(
            &g,
            &dir,
            &["ls-tree", "-r", "-z", "--name-only", &t],
            None,
            None,
            4096,
            far(),
        )
        .unwrap();
        assert_eq!(listed, b"a/b/c.txt\0");
        drop(d);
    }

    #[test]
    fn refs_move_only_from_the_expected_tip() {
        let (g, d, dir) = repo("refs");
        let blob = hash_blob(&g, &dir, b"x", far()).unwrap();
        let tree = mktree(&g, &dir, &[entry("100644", "blob", &blob, b"f")], far()).unwrap();
        let id = Identity::new("u", "u@example.invalid")
            .unwrap()
            .at(1_700_000_000);
        let c1 = commit_tree(&g, &dir, &tree, None, "one\n", &id, far()).unwrap();
        let c2 = commit_tree(&g, &dir, &tree, Some(&c1), "two\n", &id, far()).unwrap();
        assert_eq!(read_ref(&g, &dir, "refs/heads/m").unwrap(), None);
        assert_eq!(
            update_ref(&g, &dir, "refs/heads/m", &c1, ZERO).unwrap(),
            None
        );
        assert!(
            update_ref(&g, &dir, "refs/heads/m", &c1, ZERO)
                .unwrap()
                .is_some(),
            "create twice"
        );
        assert!(
            update_ref(&g, &dir, "refs/heads/m", &c2, &c2)
                .unwrap()
                .is_some(),
            "wrong expected tip"
        );
        assert_eq!(
            update_ref(&g, &dir, "refs/heads/m", &c2, &c1).unwrap(),
            None
        );
        assert_eq!(
            read_ref(&g, &dir, "refs/heads/m").unwrap(),
            Some(c2.clone())
        );
        assert!(is_ancestor(&g, &dir, &c1, &c2).unwrap());
        assert!(!is_ancestor(&g, &dir, &c2, &c1).unwrap());
        let msg = run(
            &g,
            &dir,
            &["log", "-1", "--format=%an|%ae|%at|%cn|%ct|%s", &c2],
            None,
            None,
            4096,
            far(),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&msg).trim(),
            "u|u@example.invalid|1700000000|u|1700000000|two"
        );
        drop(d);
    }
}
