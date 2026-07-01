//! Git *history* import — the full-DAG read half of the interop boundary
//! (single-HEAD import lives in `lib.rs::import_head`). Deterministic: a given
//! git commit always maps to the same sc snapshot id, so two repos importing the
//! same git repo agree on ids. `known` short-circuits commits already imported.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use scl_core::{Object, ObjectId, Snapshot, Store};

use crate::import_tree;

/// Result of a history import.
#[derive(Debug)]
pub struct ImportReport {
    /// sc snapshot id of the imported branch tip.
    pub tip: ObjectId,
    /// Freshly-imported commits as `(git_oid_hex, sc_id)`; excludes any commit
    /// found in `known`.
    pub new_marks: Vec<(String, ObjectId)>,
}

/// Import the full history of `branch` from the git repo at `repo_path` into
/// `store`. Post-order DAG walk (parents before children) using an explicit
/// stack so deep history can't overflow. Commits found in `known`
/// (`git_oid_hex → sc_id`) are reused, not re-imported, and their subgraphs are
/// not descended.
///
/// Each git commit maps to a snapshot that is a pure function of the commit —
/// the field-level inverse of export's `synth_sig`: `author = "{name} <{email}>"`
/// (name-only when the email is empty), `timestamp` = the git author time in
/// seconds, `message` = the git commit message with the single trailing newline
/// git appends stripped, `root` = the imported tree, `parents` = the mapped
/// parent sc ids in git parent order, no secrets, and default protection. So an
/// sc-native commit exported to git and re-imported yields the same sc id.
pub fn import_history(
    store: &mut Store,
    repo_path: &Path,
    branch: &str,
    known: &HashMap<String, ObjectId>,
) -> Result<ImportReport> {
    let repo = gix::open(repo_path)
        .with_context(|| format!("opening git repo at {}", repo_path.display()))?;
    let mut reference = repo
        .find_reference(&format!("refs/heads/{branch}"))
        .with_context(|| format!("resolving branch {branch}"))?;
    let tip_oid = reference.peel_to_id().context("peeling branch to commit")?.detach();

    // sc id for every git commit we resolve this call (seed with `known`).
    let mut mapped: HashMap<gix::ObjectId, ObjectId> = HashMap::new();
    for (hex, sc) in known {
        if !store.contains(sc) {
            // Stale mark: the snapshot was pruned (e.g. remote rewind + gc). Skip it so
            // this commit is re-imported deterministically (import is a pure function of
            // the git commit → same sc id) and re-rooted, rather than trusting a dangling
            // id. Keeps marks a recoverable cache, never corrupting (ADR-0018).
            continue;
        }
        if let Ok(oid) = gix::ObjectId::from_hex(hex.as_bytes()) {
            mapped.insert(oid, *sc);
        }
    }
    let mut new_marks: Vec<(String, ObjectId)> = Vec::new();

    // Post-order: (oid, ready). ready=false => push children first; ready=true => build.
    let mut stack: Vec<(gix::ObjectId, bool)> = vec![(tip_oid, false)];
    while let Some((oid, ready)) = stack.pop() {
        if mapped.contains_key(&oid) {
            continue;
        }
        let commit = repo.find_object(oid).context("finding commit")?.into_commit();
        let decoded = commit.decode().context("decoding commit")?;
        // Raw hex-hash parents in git parent order (gix validated them on parse).
        let parents: Vec<gix::ObjectId> = decoded.parents().collect();

        if ready {
            // All parents are mapped now.
            let parent_sc: Vec<ObjectId> = parents.iter().map(|p| mapped[p]).collect();
            let tree_obj = commit.tree().context("reading commit tree")?;
            let root = import_tree(store, &repo, &tree_obj)?;

            // `author()` (not the raw `.author` field) returns a parsed,
            // whitespace-trimmed SignatureRef.
            let sig = decoded.author().context("parsing commit author")?;
            let name = sig.name.to_string();
            let email = sig.email.to_string();
            let author = if email.is_empty() { name } else { format!("{name} <{email}>") };
            // Author time in seconds (timezone-independent; 0 if unparseable).
            let timestamp = sig.seconds();
            // Git normalizes `-m` messages to end in exactly one newline; strip
            // it so the message is the field-level inverse of what export wrote
            // (gix writes our message verbatim, adding no trailing newline).
            let raw = decoded.message.to_string();
            let message = raw.strip_suffix('\n').unwrap_or(&raw).to_string();

            let snap = Object::Snapshot(Snapshot {
                root,
                parents: parent_sc,
                author,
                timestamp,
                message,
                secrets: std::collections::BTreeMap::new(),
                protection: Default::default(),
            });
            let sc_id = store.put(snap).context("storing imported snapshot")?;
            mapped.insert(oid, sc_id);
            new_marks.push((oid.to_hex().to_string(), sc_id));
        } else {
            stack.push((oid, true));
            for p in parents {
                if !mapped.contains_key(&p) {
                    stack.push((p, false));
                }
            }
        }
    }

    Ok(ImportReport { tip: mapped[&tip_oid], new_marks })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::StoreConfig;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "Ada").env("GIT_AUTHOR_EMAIL", "ada@x")
            .env("GIT_COMMITTER_NAME", "Ada").env("GIT_COMMITTER_EMAIL", "ada@x")
            .output()
            .expect("git runs")
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("scl-imph-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn imports_full_history_with_parent_edges() {
        let dir = tmp("hist");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "c1"]);
        std::fs::write(dir.join("a.txt"), b"two").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "c2"]);

        let mut store = Store::new(StoreConfig::default());
        let known = HashMap::new();
        let rep = import_history(&mut store, &dir, "main", &known).unwrap();

        // Tip snapshot has one parent (c1); c1 has none.
        let tip = store.get_snapshot(&rep.tip).unwrap();
        assert_eq!(tip.message, "c2");
        assert_eq!(tip.parents.len(), 1);
        let parent = store.get_snapshot(&tip.parents[0]).unwrap();
        assert_eq!(parent.message, "c1");
        assert_eq!(parent.parents.len(), 0);
        // Author round-trips as "Name <email>".
        assert_eq!(tip.author, "Ada <ada@x>");
        // Two commits imported, both recorded as new marks.
        assert_eq!(rep.new_marks.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_is_deterministic_across_runs() {
        let dir = tmp("det");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("f"), b"x").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "only"]);

        let mut s1 = Store::new(StoreConfig::default());
        let mut s2 = Store::new(StoreConfig::default());
        let k = HashMap::new();
        let r1 = import_history(&mut s1, &dir, "main", &k).unwrap();
        let r2 = import_history(&mut s2, &dir, "main", &k).unwrap();
        assert_eq!(r1.tip, r2.tip); // pure function of git commit
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn known_commits_are_not_reimported() {
        let dir = tmp("known");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("f"), b"x").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "c1"]);

        let mut store = Store::new(StoreConfig::default());
        // First import learns the mark.
        let r1 = import_history(&mut store, &dir, "main", &HashMap::new()).unwrap();
        let (git_oid, sc_id) = r1.new_marks[0].clone();
        // Re-import with that mark known: nothing new, same tip.
        let mut known = HashMap::new();
        known.insert(git_oid, sc_id);
        let r2 = import_history(&mut store, &dir, "main", &known).unwrap();
        assert_eq!(r2.tip, r1.tip);
        assert!(r2.new_marks.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stale_mark_is_skipped_so_pruned_parent_is_reimported() {
        // Real scenario: fetch A,B → gc prunes B after a remote rewind → remote
        // re-advances to C (child of B) → re-fetch with a stale mark for B. The
        // stale mark must be skipped so B (and thus C's parent) re-imports instead
        // of dangling. Under the pre-fix code C's parent sB is missing.
        let dir = tmp("stale");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("f"), b"a").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "A"]);
        std::fs::write(dir.join("f"), b"b").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "B"]);

        let mut store = Store::new(StoreConfig::default());
        let r1 = import_history(&mut store, &dir, "main", &HashMap::new()).unwrap();
        // Recover marks for A and B by message.
        let mut ga_hex = None;
        let mut gb_hex = None;
        let sb = r1.tip; // tip is B
        for (hex, sc) in &r1.new_marks {
            let snap = store.get_snapshot(sc).unwrap();
            match snap.message.as_str() {
                "A" => ga_hex = Some(hex.clone()),
                "B" => gb_hex = Some(hex.clone()),
                _ => {}
            }
        }
        let ga_hex = ga_hex.expect("A mark");
        let gb_hex = gb_hex.expect("B mark");
        let sa = {
            // sc id for A = the recorded mark for A.
            r1.new_marks.iter().find(|(h, _)| *h == ga_hex).unwrap().1
        };

        // Simulate rewind + gc: B's snapshot is now unreachable and pruned.
        store.delete(&sb).unwrap();
        assert!(!store.contains(&sb), "sB must be absent after delete");

        // Remote re-advances: add C (child of B).
        std::fs::write(dir.join("f"), b"c").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "C"]);

        // Re-fetch carrying the stale marks (gA:sA, gB:sB — sB is gone).
        let mut known = HashMap::new();
        known.insert(ga_hex, sa);
        known.insert(gb_hex, sb);
        let r2 = import_history(&mut store, &dir, "main", &known).unwrap();

        // The entire ancestry of the new tip must be resident in the store.
        let mut stack = vec![r2.tip];
        let mut saw_b = false;
        while let Some(id) = stack.pop() {
            assert!(store.contains(&id), "ancestor {id:?} must exist in store");
            let snap = store.get_snapshot(&id).unwrap();
            if snap.message == "B" {
                saw_b = true;
            }
            for p in snap.parents {
                stack.push(p);
            }
        }
        // B was re-created with its same deterministic id.
        assert!(store.contains(&sb), "sB must be re-imported (deterministic id)");
        assert!(saw_b, "B must appear in the re-rooted ancestry");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn imports_a_merge_commit_with_two_parents() {
        let dir = tmp("merge");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("base"), b"b").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "base"]);
        git(&dir, &["checkout", "-q", "-b", "side"]);
        std::fs::write(dir.join("side.txt"), b"s").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "side"]);
        git(&dir, &["checkout", "-q", "main"]);
        std::fs::write(dir.join("main.txt"), b"m").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "mainwork"]);
        git(&dir, &["merge", "-q", "--no-ff", "side", "-m", "merge"]);

        let mut store = Store::new(StoreConfig::default());
        let rep = import_history(&mut store, &dir, "main", &HashMap::new()).unwrap();
        let tip = store.get_snapshot(&rep.tip).unwrap();
        assert_eq!(tip.message, "merge");
        assert_eq!(tip.parents.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
