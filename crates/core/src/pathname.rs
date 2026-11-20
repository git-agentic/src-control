//! The one rule for what a tree entry's path may be, before any code joins it
//! onto a checkout directory.
//!
//! A tree comes from a peer (native remote, Git bridge, pack), and tree decode
//! accepts any entry name. Left unchecked, a tree entry such as
//! `.sc/recipients.toml` would be written into the cloner's `.sc/` control
//! directory, and on Windows `..\..\x` or `C:\x` would leave the checkout. The
//! predicate is pure and platform-independent so each platform's rule can be
//! tested everywhere; callers pass `cfg!(windows)`.

use std::fmt;

/// Why [`check_tree_path`] refused a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRefusal {
    /// An empty, `.` or `..` component.
    Traversal,
    /// A NUL byte: some APIs truncate the name there.
    Nul,
    /// The control directory `.sc` (or an alias a checkout filesystem
    /// resolves to it) at any depth.
    ControlDir,
    /// A `\` or `:` in a component, which Windows treats as a separator or a
    /// drive/stream marker.
    WindowsSeparator,
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Traversal => "an empty, `.` or `..` component",
            Self::Nul => "a NUL byte",
            Self::ControlDir => "a component that names or aliases the `.sc` control directory",
            Self::WindowsSeparator => {
                "a `\\` or `:` in a component, which Windows would not treat as a name"
            }
        })
    }
}

/// Code points HFS+ ignores when it compares names, so `.s\u{200c}c` is `.sc`
/// on a Mac. Copied from `crates/forge/src/gitwrite.rs` (`hfs_ignorable`), which
/// applies the same alias rules to `.git`; `core` must not depend on the forge.
fn hfs_ignorable(c: char) -> bool {
    matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}')
}

/// Whether `component` is `.sc` on any filesystem a checkout may live on:
/// mirrors `is_alias` in `crates/forge/src/gitwrite.rs` (HFS-ignorable code
/// points dropped, an NTFS `:stream` suffix cut, trailing dots and spaces
/// trimmed) but folds case with Unicode uppercase, not ASCII: a case-insensitive
/// APFS volume resolves `.\u{17f}c` (LATIN SMALL LETTER LONG S) to `.sc`, and
/// `'\u{17f}'.to_uppercase()` is `S`. The folded name is then compared against
/// `.SC`, the first-six style 8.3 names `SC~1` to `SC~4`, and NTFS's checksum
/// short name `SC` + four hex digits + `~1` to `~9` (the base of `.sc` is only
/// two characters once the dot is stripped, so NTFS may use that form).
fn is_control_dir(component: &str) -> bool {
    let c: String = component.chars().filter(|c| !hfs_ignorable(*c)).collect();
    let c = c.split(':').next().unwrap_or("");
    let c: String = c
        .trim_end_matches([' ', '.'])
        .chars()
        .flat_map(char::to_uppercase)
        .collect();
    if c == ".SC" {
        return true;
    }
    let Some(tail) = c.strip_prefix("SC") else {
        return false;
    };
    match tail.split_once('~') {
        Some(("", n)) => matches!(n, "1" | "2" | "3" | "4"),
        Some((hex, n)) => {
            hex.len() == 4
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
                && matches!(n.as_bytes(), [b'1'..=b'9'])
        }
        None => false,
    }
}

/// Refuse a `/`-separated tree path that must never be written under a
/// checkout: an empty, `.` or `..` component, a NUL, the control directory
/// `.sc` (any alias, any depth), and with `windows` set any `\` or `:`. Callers
/// pass `cfg!(windows)`; the unix rule leaves `:` and `\` alone since they are
/// legal names there.
pub fn check_tree_path(rel: &str, windows: bool) -> Result<(), PathRefusal> {
    if rel.contains('\0') {
        return Err(PathRefusal::Nul);
    }
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(PathRefusal::Traversal);
        }
        if is_control_dir(comp) {
            return Err(PathRefusal::ControlDir);
        }
        if windows && comp.contains(['\\', ':']) {
            return Err(PathRefusal::WindowsSeparator);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_control_dir_under_every_alias_at_any_depth() {
        for p in [
            ".sc",
            ".SC",
            ".sc.",
            ".sc ",
            ".sc. .",
            ".s\u{200c}c",
            "\u{feff}.sc",
            "sc~1",
            "SC~1",
            "sc~4",
            "sc1a2B~1",
            "SCABCD~9",
            "a/sc0000~3",
            ".\u{17f}c",
            ".\u{17f}C",
            ".\u{17f}c.",
            "\u{17f}c~1",
            ".sc:x",
            ".sc/recipients.toml",
            "a/.Sc/b",
            "a/b/.sc",
        ] {
            for windows in [false, true] {
                assert_eq!(
                    check_tree_path(p, windows),
                    Err(PathRefusal::ControlDir),
                    "{p:?} windows={windows}"
                );
            }
        }
    }

    #[test]
    fn refuses_traversal_and_nul() {
        for p in ["", ".", "..", "a//b", "a/./b", "a/../b", "/a", "a/"] {
            assert_eq!(
                check_tree_path(p, false),
                Err(PathRefusal::Traversal),
                "{p:?}"
            );
        }
        assert_eq!(check_tree_path("a\0b", false), Err(PathRefusal::Nul));
        assert_eq!(check_tree_path("a\0/.sc", true), Err(PathRefusal::Nul));
    }

    #[test]
    fn windows_rule_refuses_separators_and_drives() {
        for p in ["a\\b", "C:", "C:\\x", "..\\..\\x", "a/b:c"] {
            assert!(check_tree_path(p, true).is_err(), "{p:?}");
        }
    }

    #[test]
    fn unix_rule_allows_colon_and_backslash() {
        for p in ["a:b", "a\\b", "dir/a:b", "..\\x"] {
            assert_eq!(check_tree_path(p, false), Ok(()), "{p:?}");
        }
    }

    #[test]
    fn ordinary_names_pass() {
        for p in [
            ".scignore",
            ".scx",
            "sc",
            "a/.sc_x/b",
            "src/main.rs",
            ".sc-keep",
            "sc~5",
            "sc123~1",
            "sc12345~1",
            "scxyzw~1",
            "sc1234~0",
            "sc1234~10",
            "\u{17f}x",
            "..a",
            "a..",
        ] {
            for windows in [false, true] {
                assert_eq!(
                    check_tree_path(p, windows),
                    Ok(()),
                    "{p:?} windows={windows}"
                );
            }
        }
    }
}
