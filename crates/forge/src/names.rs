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
