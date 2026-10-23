//! Access-token scopes: parsing, normalization into Gitea's canonical order,
//! and the allow check. Accepted set: `all`, `read|write:{admin,issue,
//! organization,repository,user}` and `public-only`.

/// A scope category a route can require.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cat {
    Admin,
    Issue,
    Organization,
    Repository,
    User,
}

impl Cat {
    fn name(self) -> &'static str {
        match self {
            Cat::Admin => "admin",
            Cat::Issue => "issue",
            Cat::Organization => "organization",
            Cat::Repository => "repository",
            Cat::User => "user",
        }
    }
}

/// Read or write access within a category (`write` implies `read`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Read,
    Write,
}

/// A route's scope requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Need(pub Cat, pub Level);

impl Need {
    /// The text Gitea prints in the 403 body, e.g. `[write:user]`.
    pub fn label(self) -> String {
        let l = if self.1 == Level::Write {
            "write"
        } else {
            "read"
        };
        format!("[{l}:{}]", self.0.name())
    }
}

const CATS: [Cat; 5] = [
    Cat::Admin,
    Cat::Issue,
    Cat::Organization,
    Cat::Repository,
    Cat::User,
];

fn parse_one(s: &str) -> Option<(Cat, Level)> {
    let (level, cat) = s.split_once(':')?;
    let level = match level {
        "read" => Level::Read,
        "write" => Level::Write,
        _ => return None,
    };
    CATS.iter().find(|c| c.name() == cat).map(|c| (*c, level))
}

/// Normalize a requested scope list: validate, drop a `read` shadowed by a
/// `write` of the same category, collapse to `all` when present, and order as
/// Gitea does (`public-only`, then categories alphabetically). `Err` carries
/// the offending scope string.
pub fn normalize(requested: &[String]) -> Result<Vec<String>, String> {
    let mut public_only = false;
    let mut all = false;
    let mut by_cat: Vec<(Cat, Level)> = Vec::new();
    for s in requested {
        match s.as_str() {
            "public-only" => public_only = true,
            "all" => all = true,
            other => {
                let (cat, level) = parse_one(other).ok_or_else(|| other.to_string())?;
                match by_cat.iter_mut().find(|(c, _)| *c == cat) {
                    Some((_, l)) => *l = (*l).max_level(level),
                    None => by_cat.push((cat, level)),
                }
            }
        }
    }
    let mut out = Vec::new();
    if public_only {
        out.push("public-only".to_string());
    }
    if all {
        out.push("all".to_string());
        return Ok(out);
    }
    by_cat.sort_by_key(|(c, _)| c.name());
    for (c, l) in by_cat {
        let l = if l == Level::Write { "write" } else { "read" };
        out.push(format!("{l}:{}", c.name()));
    }
    Ok(out)
}

trait MaxLevel {
    fn max_level(self, other: Self) -> Self;
}
impl MaxLevel for Level {
    fn max_level(self, other: Self) -> Self {
        if self == Level::Write || other == Level::Write {
            Level::Write
        } else {
            Level::Read
        }
    }
}

/// Does a stored (normalized) scope list satisfy `need`?
pub fn allows(scopes: &[String], need: Need) -> bool {
    scopes.iter().any(|s| {
        if s == "all" {
            return true;
        }
        match parse_one(s) {
            Some((c, l)) => c == need.0 && (l == Level::Write || need.1 == Level::Read),
            None => false,
        }
    })
}

/// Is the token restricted to public repositories?
pub fn public_only(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "public-only")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn write_shadows_read_and_order_is_canonical() {
        // Recorded on Gitea 1.22.6 (scenario B).
        assert_eq!(
            normalize(&v(&["read:repository", "write:repository"])).unwrap(),
            v(&["write:repository"])
        );
        assert_eq!(
            normalize(&v(&["read:user", "read:organization", "write:repository"])).unwrap(),
            v(&["read:organization", "write:repository", "read:user"])
        );
        assert_eq!(
            normalize(&v(&["read:repository", "public-only"])).unwrap(),
            v(&["public-only", "read:repository"])
        );
    }

    #[test]
    fn all_collapses_and_unknown_is_rejected() {
        assert_eq!(normalize(&v(&["all", "read:user"])).unwrap(), v(&["all"]));
        assert_eq!(normalize(&v(&["nonsense"])).unwrap_err(), "nonsense");
        assert_eq!(
            normalize(&v(&["write:package"])).unwrap_err(),
            "write:package"
        );
    }

    #[test]
    fn allows_follows_write_implies_read() {
        let s = v(&["write:repository", "read:user"]);
        assert!(allows(&s, Need(Cat::Repository, Level::Read)));
        assert!(allows(&s, Need(Cat::Repository, Level::Write)));
        assert!(allows(&s, Need(Cat::User, Level::Read)));
        assert!(!allows(&s, Need(Cat::User, Level::Write)));
        assert!(!allows(&s, Need(Cat::Admin, Level::Read)));
        assert!(allows(&v(&["all"]), Need(Cat::Admin, Level::Write)));
        assert!(!allows(&v(&["public-only"]), Need(Cat::User, Level::Read)));
    }
}
