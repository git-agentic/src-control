//! The git half of contents writes (F3b): path rules, and building a commit from an edited tree with
//! plumbing only. Nothing here touches a ref; the caller moves it last.

/// Code points HFS+ ignores when it compares names, so `.g\u{200c}it` is `.git` on a Mac.
fn hfs_ignorable(c: char) -> bool {
    matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}')
}

/// Whether a path component is `.git` (or its 8.3 short name) on any filesystem git runs on.
fn is_git_alias(component: &str) -> bool {
    let c: String = component.chars().filter(|c| !hfs_ignorable(*c)).collect();
    // NTFS ignores trailing dots and spaces and treats `name:stream` as the file `name`.
    let c = c.split(':').next().unwrap_or("");
    let c = c.trim_end_matches([' ', '.']).to_ascii_lowercase();
    c == ".git" || c == "git~1"
}

/// Whether a client may create or change `path` through the API. Stricter than the read rules: a path a
/// checkout on macOS or Windows would resolve into `.git` can never be created here.
pub fn write_path_ok(path: &str) -> bool {
    crate::gitobj::valid_path(path)
        && !path.ends_with('/')
        && !path.contains('\\')
        && path.split('/').all(|c| c.len() <= 255 && !is_git_alias(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_paths_pass() {
        for p in ["a", "dir/file.txt", "a/b/c.md", ".gitignore", ".github/workflows/ci.yml", "gitx", "x.git", "a.git/b"] {
            assert!(write_path_ok(p), "{p}");
        }
    }

    #[test]
    fn git_aliases_and_separators_are_refused() {
        for p in [
            "", "/a", "a/", "a//b", "a/./b", "a/../b", ".git", ".GIT", "a/.git/hooks/x", ".git.", ".git ", ".git. .",
            "git~1/x", "GIT~1", ".g\u{200c}it/x", ".git\u{feff}", ".git::$INDEX_ALLOCATION", ".git:stream", "a\\b", "..\\x",
            "a\u{0}b", "a\nb",
        ] {
            assert!(!write_path_ok(p), "{p:?}");
        }
        assert!(!write_path_ok(&"x".repeat(256)));
        assert!(write_path_ok(&"x".repeat(255)));
    }
}
