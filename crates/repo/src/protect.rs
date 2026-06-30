//! Encrypted-path policy helpers.

use scl_core::{ProtectPrefix, Protection};

/// The protecting prefix rule for `path`, if any (longest-prefix wins).
pub fn matching_prefix<'a>(protection: &'a Protection, path: &str) -> Option<&'a ProtectPrefix> {
    protection
        .prefixes
        .iter()
        .filter(|p| path == p.prefix.trim_end_matches('/') || path.starts_with(&p.prefix))
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
}
