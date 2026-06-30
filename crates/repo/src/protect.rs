//! Encrypted-path policy helpers.

use scl_core::{ProtectPrefix, Protection};

/// The protecting prefix rule for `path`, if any (longest-prefix wins).
pub fn matching_prefix<'a>(protection: &'a Protection, path: &str) -> Option<&'a ProtectPrefix> {
    protection
        .prefixes
        .iter()
        .filter(|p| {
            // Match only at a path boundary: a path is governed by a prefix iff it
            // equals the prefix's bare form or lies under it at a `/` boundary.
            // `starts_with` alone would over-match (e.g. `secret` -> `secretstuff`).
            let bare = p.prefix.trim_end_matches('/');
            path == bare || path.starts_with(&format!("{bare}/"))
        })
        .max_by_key(|p| p.prefix.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prot(prefixes: &[&str]) -> Protection {
        Protection {
            prefixes: prefixes
                .iter()
                .map(|p| ProtectPrefix { prefix: p.to_string(), recipients: vec![] })
                .collect(),
            wrapped: Default::default(),
        }
    }

    #[test]
    fn matches_under_prefix_longest_wins() {
        let p = prot(&["secrets/", "secrets/prod/"]);
        assert_eq!(
            matching_prefix(&p, "secrets/prod/db").unwrap().prefix,
            "secrets/prod/"
        );
        assert_eq!(matching_prefix(&p, "secrets/x").unwrap().prefix, "secrets/");
        assert!(matching_prefix(&p, "src/main.rs").is_none());
    }

    #[test]
    fn prefix_matches_only_at_path_boundary() {
        // A prefix without a trailing slash must match only the bare path or a
        // child under a `/` boundary — never a sibling sharing a textual prefix.
        let p = prot(&["secret"]);
        assert!(matching_prefix(&p, "secret/db").is_some());
        assert!(matching_prefix(&p, "secret").is_some());
        assert!(matching_prefix(&p, "secretstuff.txt").is_none());
        assert!(matching_prefix(&p, "secret-evil/x").is_none());
    }
}
