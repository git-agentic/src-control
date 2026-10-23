//! The ref-update policy every mutation path shares. F2b enforces it in the `pre-receive` hook;
//! F3's contents writes and F4's merges call the same function, and branch protection rules (F4)
//! extend it here, so there is one place that decides whether a ref may move.

/// Why an update is refused (the text git shows to the pusher as `remote: <text>`).
pub type Refusal = String;

/// Is `new` the all-zero id (a deletion)? Any length: sha1 and sha256 repositories alike.
pub fn is_delete(new: &str) -> bool {
    !new.is_empty() && new.bytes().all(|b| b == b'0')
}

/// Do two branch names name the same branch on a case-insensitive filesystem? Compared by Unicode
/// lowercase (there, `MAIN` and `Ünï` alias their lowercase forms).
/// shortcut: Unicode normalization (NFC vs NFD) aliasing on APFS/HFS+ is not handled; production is
/// Linux (case- and normalization-sensitive), macOS is development only.
pub fn same_branch_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// May a client push `name` (`old` -> `new`) to a repository whose default branch is
/// `default_branch`? Only `refs/heads/*` and `refs/tags/*` are writable; `refs/replace/*`,
/// `refs/forge/*`, `refs/pull/*`, `refs/notes/*` and anything else is refused. The default branch
/// cannot be deleted, compared case-insensitively (on a case-insensitive filesystem `MAIN` aliases
/// the loose ref `main`).
pub fn check_update(name: &str, new: &str, default_branch: &str) -> Result<(), Refusal> {
    if let Some(branch) = name.strip_prefix("refs/heads/") {
        if is_delete(new) && same_branch_name(branch, default_branch) {
            return Err(format!("refusing to delete the default branch {branch}"));
        }
        return Ok(());
    }
    if name.starts_with("refs/tags/") {
        return Ok(());
    }
    Err(format!(
        "refusing to update {name}: only refs/heads/* and refs/tags/* are writable"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const Z: &str = "0000000000000000000000000000000000000000";
    const A: &str = "1111111111111111111111111111111111111111";

    #[test]
    fn branches_and_tags_are_writable() {
        for r in [
            "refs/heads/main",
            "refs/heads/feat/x",
            "refs/tags/v1",
            "refs/heads/MAIN-2",
        ] {
            assert!(check_update(r, A, "main").is_ok(), "{r}");
            assert!(
                check_update(r, Z, "dev").is_ok() || r.ends_with("dev"),
                "{r}: deleting a non-default is allowed"
            );
        }
    }

    #[test]
    fn every_other_namespace_is_refused_with_the_recorded_text() {
        for r in [
            "refs/replace/1111111111111111111111111111111111111111",
            "refs/forge/pull/1/head",
            "refs/pull/1/head",
            "refs/notes/commits",
            "refs/changes/01/1/1",
            "refs/for/main",
            "refs/keep-around/abc",
            "HEAD",
            "refs/heads",
            "refs/headsx/main",
            "refs/tag/v1",
            "FETCH_HEAD",
            "",
        ] {
            let e = check_update(r, A, "main").unwrap_err();
            assert_eq!(
                e,
                format!("refusing to update {r}: only refs/heads/* and refs/tags/* are writable"),
                "{r:?}"
            );
        }
        // a name that merely contains `..` after the allowed prefix is git's to reject (check-ref-format); the policy
        // only decides the namespace, and `refs/heads/x/../../replace/y` is not under another prefix as a ref name
        assert!(
            check_update("refs/heads/../replace/y", A, "main").is_ok(),
            "namespace check is a prefix check; git refuses the name itself"
        );
    }

    #[test]
    fn the_default_branch_cannot_be_deleted_even_by_a_case_alias() {
        for r in ["refs/heads/main", "refs/heads/MAIN", "refs/heads/Main"] {
            assert!(check_update(r, Z, "main").is_err(), "{r}");
        }
        assert!(
            check_update("refs/heads/main", A, "main").is_ok(),
            "updating it is fine"
        );
        assert!(
            check_update("refs/heads/main", "0".repeat(64).as_str(), "main").is_err(),
            "sha256 all-zero id is a delete too"
        );
        assert!(check_update("refs/heads/mainx", Z, "main").is_ok());
        assert!(
            check_update("refs/tags/main", Z, "main").is_ok(),
            "a tag named like the default branch is not the branch"
        );
    }

    #[test]
    fn deletion_means_an_all_zero_id_of_any_length() {
        assert!(is_delete(Z) && is_delete("0") && is_delete(&"0".repeat(64)));
        assert!(
            !is_delete("")
                && !is_delete(A)
                && !is_delete("0000000000000000000000000000000000000001")
        );
    }
}
