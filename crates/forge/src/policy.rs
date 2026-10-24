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

/// One branch protection rule: exact branch name (compared like [`same_branch_name`]), whether
/// direct updates are allowed at all (`enable_push`), and the status contexts a merge needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub branch: String,
    pub enable_push: bool,
    pub enable_status_check: bool,
    /// `None` when the request gave none (recorded: the API then reports `null`).
    pub contexts: Option<Vec<String>>,
}

/// The protection rules of one repository.
#[derive(Clone, Debug, Default)]
pub struct Rules(pub Vec<Rule>);

impl Rules {
    /// The rule that protects `name`, if any.
    pub fn for_branch(&self, name: &str) -> Option<&Rule> {
        self.0.iter().find(|r| same_branch_name(&r.branch, name))
    }
}

/// May a client push `old` -> `new` to `refs/heads/<branch>` under `rules`? Applied after
/// [`check_update`]. A rule with `enable_push` off refuses every update (the branch can only move
/// through a merge), administrators included; with it on, a fast-forward is fine and a deletion
/// or a non-fast-forward update is refused for everyone. `is_ff` runs only when it matters
/// (an update of an existing branch under a rule that allows pushes) and any failure to decide
/// refuses the update.
pub fn check_protected_push(
    rules: &Rules,
    branch: &str,
    old: &str,
    new: &str,
    is_ff: impl FnOnce() -> Result<bool, String>,
) -> Result<(), Refusal> {
    let Some(rule) = rules.for_branch(branch) else {
        return Ok(());
    };
    if !rule.enable_push {
        return Err(format!(
            "refusing to update protected branch {branch}: direct pushes are not allowed"
        ));
    }
    if is_delete(new) {
        return Err(format!("refusing to delete protected branch {branch}"));
    }
    if is_delete(old) {
        return Ok(());
    }
    match is_ff() {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("refusing to force-push protected branch {branch}")),
        Err(e) => Err(format!(
            "refusing to update protected branch {branch}: cannot tell whether it is a fast-forward ({e})"
        )),
    }
}

/// May a contents write put a commit on branch `target`? `creating` is true when the write creates
/// the branch (`new_branch`, or the first commit of an unborn default). Called before the objects
/// are built and again immediately before the ref update, on every attempt, with the rules read
/// under the repository's write gate, so a rule change is ordered against the write (the spec's
/// linearization point). Rules refuse when `enable_push` is off, whether or not the branch
/// exists yet: a rule reserves its name (stricter than Gitea, which checks only an existing
/// branch).
pub fn check_contents_write(rules: &Rules, target: &str, _creating: bool) -> Result<(), Refusal> {
    match rules.for_branch(target) {
        Some(r) if !r.enable_push => Err(format!("branch {target} is protected")),
        _ => Ok(()),
    }
}

/// May the API delete branch `name`? A protected branch is never deleted by the API (the default
/// branch is refused before this is asked).
pub fn check_branch_delete(rules: &Rules, name: &str) -> Result<(), Refusal> {
    match rules.for_branch(name) {
        Some(_) => Err(format!("branch {name} is protected and cannot be deleted")),
        None => Ok(()),
    }
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

    fn rules(push: bool) -> Rules {
        Rules(vec![Rule {
            branch: "Release".into(),
            enable_push: push,
            enable_status_check: false,
            contexts: None,
        }])
    }

    #[test]
    fn a_rule_with_pushes_off_refuses_every_update_including_creation() {
        let r = rules(false);
        for (old, new) in [(A, A), (Z, A), (A, Z)] {
            assert!(
                check_protected_push(&r, "release", old, new, || Ok(true)).is_err(),
                "{old} {new}"
            );
        }
        assert!(check_contents_write(&r, "RELEASE", true).is_err());
        assert!(check_contents_write(&r, "other", true).is_ok());
    }

    #[test]
    fn a_rule_with_pushes_on_allows_fast_forwards_only() {
        let r = rules(true);
        assert!(check_protected_push(&r, "release", A, A, || Ok(true)).is_ok());
        assert!(
            check_protected_push(&r, "release", Z, A, || panic!("creation needs no ancestry"))
                .is_ok()
        );
        let e = check_protected_push(&r, "release", A, A, || Ok(false)).unwrap_err();
        assert!(e.contains("force-push"), "{e}");
        let e = check_protected_push(&r, "release", A, Z, || panic!("deletion needs no ancestry"))
            .unwrap_err();
        assert!(e.contains("delete"), "{e}");
        assert!(
            check_protected_push(&r, "release", A, A, || Err("boom".into())).is_err(),
            "a failure to decide refuses"
        );
        assert!(check_contents_write(&r, "release", false).is_ok());
    }

    #[test]
    fn unruled_branches_and_branch_delete() {
        let r = rules(true);
        assert!(check_protected_push(&r, "dev", A, Z, || Ok(false)).is_ok());
        assert!(check_branch_delete(&r, "RELEASE").is_err());
        assert!(check_branch_delete(&r, "dev").is_ok());
        assert!(check_branch_delete(&Rules::default(), "release").is_ok());
    }
}
