//! Branch-name validation, applied before a name ever reaches `git`. It follows
//! `git check-ref-format` for `refs/heads/<name>` and is stricter where git is
//! lenient in a way that matters here (`HEAD`, leading `-`). Names are always
//! addressed as the full ref `refs/heads/<name>`, never as a revision, so
//! `main~1` or `HEAD:path` can never be accepted as a branch.

const MAX_LEN: usize = 255;

/// Is `name` an acceptable branch name?
pub fn valid_branch(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_LEN || name == "@" || name == "HEAD" {
        return false;
    }
    if name.starts_with('-') || name.starts_with('/') || name.ends_with('/') || name.ends_with('.')
    {
        return false;
    }
    if name.contains("..") || name.contains("@{") || name.contains("//") {
        return false;
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return false;
    }
    name.split('/')
        .all(|c| !c.starts_with('.') && !c.ends_with(".lock"))
}

/// The full ref for a (validated) branch name.
pub fn branch_ref(name: &str) -> String {
    format!("refs/heads/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_and_slashed_names() {
        for ok in [
            "main",
            "dev",
            "feat/x",
            "docs/plan-01",
            "release-1.2",
            "a.b",
            "ünï",
            "x_y",
        ] {
            assert!(valid_branch(ok), "{ok}");
        }
    }

    #[test]
    fn rejects_revision_syntax_and_git_forbidden_forms() {
        for bad in [
            "",
            "-x",
            "--help",
            "/a",
            "a/",
            "a//b",
            "a..b",
            "main~1",
            "main^",
            "HEAD:path",
            "a b",
            "a\tb",
            "a\nb",
            "a\0b",
            "a?b",
            "a*b",
            "a[b",
            "a\\b",
            "a@{u}",
            "@",
            "HEAD",
            ".hidden",
            "a/.hidden",
            "x.lock",
            "a/x.lock",
            "a.",
        ] {
            assert!(!valid_branch(bad), "{bad:?}");
        }
        assert!(!valid_branch(&"x".repeat(256)));
        assert!(valid_branch(&"x".repeat(255)));
    }

    #[test]
    fn the_full_ref_is_what_reaches_git() {
        assert_eq!(branch_ref("feat/x"), "refs/heads/feat/x");
    }
}
