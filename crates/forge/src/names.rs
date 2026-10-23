//! User and organization name rules. They share the URL namespace with the
//! top-level routes, so they carry a reserved list (the union of Gitea's
//! 1.22.6 and 1.26.2 lists plus `api`, `admin`, `assets`, `user`, `login`).

/// Why a name was refused; `message` is the Gitea-shaped text (without the
/// trailing `[name: x]` detail for the pattern cases).
pub enum NameError {
    Reserved,
    Invalid,
    TooLong,
}

const MAX_LEN: usize = 40;

const RESERVED: &[&str] = &[
    ".",
    "..",
    ".well-known",
    "admin",
    "api",
    "assets",
    "attachments",
    "avatar",
    "avatars",
    "captcha",
    "commits",
    "debug",
    "devtools",
    "error",
    "explore",
    "favicon.ico",
    "ghost",
    "issues",
    "login",
    "manifest.json",
    "metrics",
    "milestones",
    "new",
    "notifications",
    "org",
    "pulls",
    "raw",
    "repo",
    "repo-avatars",
    "robots.txt",
    "search",
    "serviceworker.js",
    "ssh_info",
    "swagger.v1.json",
    "user",
    "v2",
    "healthz",
    "version",
    "-",
];

const RESERVED_SUFFIX: &[&str] = &[".keys", ".gpg", ".rss", ".atom"];

/// Validate a user or organization name. Matching is case-insensitive for the
/// reserved list; the character rule is Gitea's `^[0-9A-Za-z][-.\w]*$`.
pub fn check(name: &str) -> Result<(), NameError> {
    if name.chars().count() > MAX_LEN {
        return Err(NameError::TooLong);
    }
    let mut chars = name.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if !ok {
        return Err(NameError::Invalid);
    }
    let lower = name.to_ascii_lowercase();
    if RESERVED.contains(&lower.as_str()) || RESERVED_SUFFIX.iter().any(|s| lower.ends_with(s)) {
        return Err(NameError::Reserved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_recorded_rules() {
        // Recorded 201: `trail.git`, `org.git`; recorded 422: the rest.
        assert!(check("alice").is_ok());
        assert!(check("trail.git").is_ok());
        assert!(check("a_b-c.d").is_ok());
        assert!(matches!(check(".dot"), Err(NameError::Invalid)));
        assert!(matches!(check("-dash"), Err(NameError::Invalid)));
        assert!(matches!(check("has space"), Err(NameError::Invalid)));
        assert!(matches!(check(""), Err(NameError::Invalid)));
        assert!(matches!(check("API"), Err(NameError::Reserved)));
        assert!(matches!(check("admin"), Err(NameError::Reserved)));
        assert!(matches!(check("x.keys"), Err(NameError::Reserved)));
        assert!(matches!(check(&"x".repeat(41)), Err(NameError::TooLong)));
        assert!(check(&"x".repeat(40)).is_ok());
    }
}

/// Why a repository name was refused (Gitea's texts are built by the caller).
#[derive(Debug, PartialEq, Eq)]
pub enum RepoNameError {
    Empty,
    /// `.` or `..`.
    Reserved,
    /// A forbidden suffix such as `*.git`.
    Pattern(&'static str),
    /// A character outside `[A-Za-z0-9._-]`.
    BadChars,
    TooLong,
}

const REPO_MAX_LEN: usize = 100;
const REPO_SUFFIXES: [&str; 4] = [".git", ".wiki", ".rss", ".atom"];

/// Validate a repository name by the recorded Gitea rules: `[A-Za-z0-9._-]`, at most 100
/// characters, `.` and `..` reserved, and the suffixes `.git`, `.wiki`, `.rss`, `.atom` refused.
/// A leading `.` or `-`, `a..b` and words like `api` or `admin` are accepted (recorded 201):
/// repositories live on disk under their immutable id, never under their name.
pub fn check_repo(name: &str) -> Result<(), RepoNameError> {
    if name.is_empty() {
        return Err(RepoNameError::Empty);
    }
    if name.chars().count() > REPO_MAX_LEN {
        return Err(RepoNameError::TooLong);
    }
    if name == "." || name == ".." {
        return Err(RepoNameError::Reserved);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(RepoNameError::BadChars);
    }
    let lower = name.to_ascii_lowercase();
    for suffix in REPO_SUFFIXES {
        if lower.ends_with(suffix) {
            return Err(RepoNameError::Pattern(match suffix {
                ".git" => "*.git",
                ".wiki" => "*.wiki",
                ".rss" => "*.rss",
                _ => "*.atom",
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod repo_tests {
    use super::*;

    #[test]
    fn follows_the_recorded_repo_rules() {
        // Recorded 201 (scenario M): these names are accepted.
        for ok in [
            "Mixed",
            ".hidden",
            "-dash",
            "a..b",
            "api",
            "admin",
            "user",
            "assets",
            "ok_name-1.x",
        ] {
            assert_eq!(check_repo(ok), Ok(()), "{ok}");
        }
        assert_eq!(check_repo("."), Err(RepoNameError::Reserved));
        assert_eq!(check_repo(".."), Err(RepoNameError::Reserved));
        assert_eq!(
            check_repo("trail.git"),
            Err(RepoNameError::Pattern("*.git"))
        );
        assert_eq!(
            check_repo("wiki.wiki"),
            Err(RepoNameError::Pattern("*.wiki"))
        );
        assert_eq!(check_repo("feed.RSS"), Err(RepoNameError::Pattern("*.rss")));
        assert_eq!(
            check_repo("feed.atom"),
            Err(RepoNameError::Pattern("*.atom"))
        );
        assert_eq!(check_repo("a b"), Err(RepoNameError::BadChars));
        assert_eq!(check_repo("\u{fc}n\u{ef}"), Err(RepoNameError::BadChars));
        assert_eq!(check_repo(&"x".repeat(101)), Err(RepoNameError::TooLong));
        assert_eq!(check_repo(&"x".repeat(100)), Ok(()));
        assert_eq!(check_repo(""), Err(RepoNameError::Empty));
    }
}
