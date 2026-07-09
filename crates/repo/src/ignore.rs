//! `.scignore` — commit-time ignore rules for the working tree.
//!
//! A plain-text file at the repo root, one pattern per line. Blank lines and
//! `#` comments are skipped. Semantics (a deliberate subset of gitignore):
//!
//! - A pattern **without `/`** matches any single path component anywhere in
//!   the tree (`target/` written as `target`, `.DS_Store`, `*.log`).
//! - A pattern **with `/`** is anchored at the repo root and matches the path
//!   whose leading components glob-match the pattern's components
//!   (`build/output`, `docs/tmp/`).
//! - A trailing `/` marks a directory pattern; it is equivalent to the same
//!   pattern without the slash (both files and directories match either way).
//! - `*` matches any run of characters **within one component** (never `/`).
//!
//! Ignore rules apply only to **untracked** paths: a path present in HEAD stays
//! tracked (diffed, committed) even if a pattern matches it — same model as
//! git. There is no negation (`!`) and no per-directory ignore file in the MVP.

use std::path::Path;

/// Parsed ignore rules for one repository.
#[derive(Debug, Default)]
pub struct Ignore {
    patterns: Vec<Pattern>,
}

#[derive(Debug)]
struct Pattern {
    /// Pattern components split on `/`; a single-element vec is unanchored.
    components: Vec<String>,
    anchored: bool,
}

impl Ignore {
    /// Load `<root>/.scignore`. A missing file yields the empty (match-nothing)
    /// rule set; an unreadable file is an error.
    pub fn load(root: &Path) -> std::io::Result<Ignore> {
        match std::fs::read_to_string(root.join(".scignore")) {
            Ok(text) => Ok(Ignore::parse(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ignore::default()),
            Err(e) => Err(e),
        }
    }

    /// Parse rules from text (one pattern per line).
    pub fn parse(text: &str) -> Ignore {
        let mut patterns = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_suffix('/').unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            let components: Vec<String> = line.split('/').map(str::to_string).collect();
            let anchored = components.len() > 1;
            patterns.push(Pattern {
                components,
                anchored,
            });
        }
        Ignore { patterns }
    }

    /// Does any rule match this repo-relative path (`/`-separated)? A match on
    /// any leading directory of the path matches the whole path, so `target`
    /// matches `target/debug/app`.
    pub fn matches(&self, rel: &str) -> bool {
        let parts: Vec<&str> = rel.split('/').collect();
        self.patterns.iter().any(|p| p.matches(&parts))
    }
}

impl Pattern {
    fn matches(&self, path: &[&str]) -> bool {
        if self.anchored {
            // The pattern's components must glob-match the path's leading
            // components (so a matched directory swallows everything under it).
            self.components.len() <= path.len()
                && self
                    .components
                    .iter()
                    .zip(path)
                    .all(|(pat, comp)| glob_component(pat, comp))
        } else {
            let pat = &self.components[0];
            path.iter().any(|comp| glob_component(pat, comp))
        }
    }
}

/// Match one pattern component against one path component. `*` matches any run
/// of characters (including empty) but the comparison never spans a `/` —
/// callers match component-by-component.
fn glob_component(pattern: &str, comp: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == comp;
    }
    let pieces: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (pieces[0], pieces[pieces.len() - 1]);
    if !comp.starts_with(first) || comp.len() < first.len() + last.len() || !comp.ends_with(last) {
        return false;
    }
    // Middle pieces must appear in order within the remaining span.
    let mut rest = &comp[first.len()..comp.len() - last.len()];
    for piece in &pieces[1..pieces.len() - 1] {
        match rest.find(piece) {
            Some(i) => rest = &rest[i + piece.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unanchored_pattern_matches_any_component() {
        let ig = Ignore::parse("target\n");
        assert!(ig.matches("target"));
        assert!(ig.matches("target/debug/app"));
        assert!(ig.matches("sub/target/x.o"));
        assert!(!ig.matches("src/main.rs"));
        assert!(!ig.matches("retarget/x")); // component must match exactly
    }

    #[test]
    fn trailing_slash_is_equivalent_to_bare_name() {
        let ig = Ignore::parse("node_modules/\n");
        assert!(ig.matches("node_modules/left-pad/index.js"));
        assert!(ig.matches("web/node_modules/x"));
        assert!(!ig.matches("node_modules_backup/x"));
    }

    #[test]
    fn star_glob_matches_within_a_component() {
        let ig = Ignore::parse("*.log\n");
        assert!(ig.matches("foo.log"));
        assert!(ig.matches("logs/deep/bar.log"));
        assert!(!ig.matches("foo.log.txt"));
        assert!(!ig.matches("foo/log")); // `*` never crosses `/`
    }

    #[test]
    fn anchored_pattern_matches_from_root_only() {
        let ig = Ignore::parse("build/output\ndocs/tmp/\n");
        assert!(ig.matches("build/output"));
        assert!(ig.matches("build/output/a.bin"));
        assert!(ig.matches("docs/tmp/scratch.md"));
        assert!(!ig.matches("sub/build/output/a.bin")); // anchored at root
        assert!(!ig.matches("build/outputs/a.bin"));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let ig = Ignore::parse("# comment\n\n  \ntarget\n");
        assert!(ig.matches("target/x"));
        assert!(!ig.matches("# comment"));
    }

    #[test]
    fn load_missing_file_is_empty() {
        let dir = std::env::temp_dir().join(format!("scl-ignore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ig = Ignore::load(&dir).unwrap();
        assert!(!ig.matches("anything"));
        std::fs::write(dir.join(".scignore"), "*.tmp\n").unwrap();
        let ig = Ignore::load(&dir).unwrap();
        assert!(ig.matches("a/b.tmp"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
