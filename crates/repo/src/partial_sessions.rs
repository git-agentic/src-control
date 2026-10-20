//! Tests for agent sessions on a partial clone (ADR-0050): `sc ws` and
//! `sc work` workspaces see the host's view, and harvest lands through the
//! same tree-recursive merge as `sc merge` (ADR-0049).
//!
//! They reuse the merge fixture: an origin with `src/`, `docs/`, `docs/api/`
//! and `lib/`, and a `--filter src/` clone.

use crate::partial_merge::{dir_id, has, Fx, SRC_A};
use crate::refs;
use crate::workspace::WorkOptions;
use crate::ws::WsHarvestOutcome;

const SRC_FIRST: &[u8] = b"ONE\ntwo\nthree\n";
const SRC_LAST: &[u8] = b"one\ntwo\nTHREE\n";

/// `sc ws fork` lays out the view and nothing else.
#[test]
fn fork_materializes_only_the_view() {
    let fx = Fx::origin("ws-view", |_| {});
    let clone = fx.clone(false);
    let session = clone.ws_fork(None, 2, "t", None).unwrap();
    assert_eq!(session.workspaces.len(), 2);
    for ws in &session.workspaces {
        assert_eq!(std::fs::read(ws.dir.join("src/a.txt")).unwrap(), SRC_A);
        assert!(!ws.dir.join("docs").exists(), "docs is outside the view");
        assert!(!ws.dir.join("lib").exists());
    }
    clone.ws_abandon(None, None).unwrap();
    assert!(clone.ws_session(None).unwrap().is_none());
    drop(clone);
    fx.cleanup();
}

/// A workspace edit and a host edit to different lines of the same file merge
/// cleanly, and the out-of-view subtrees are carried by id, never read.
#[test]
fn harvest_lands_a_clean_merge_and_carries_the_out_of_view_subtrees() {
    let fx = Fx::origin("ws-land", |_| {});
    let clone = fx.clone(false);
    let base = refs::read_branch_tip(clone.layout(), "main")
        .unwrap()
        .unwrap();
    let docs = dir_id(&clone, &base, "docs");
    let session = clone.ws_fork(None, 1, "t", None).unwrap();
    std::fs::write(session.workspaces[0].dir.join("src/a.txt"), SRC_FIRST).unwrap();

    // The host moves on in the same file, on another line.
    std::fs::write(fx.clone_root.join("src/a.txt"), SRC_LAST).unwrap();
    let host_tip = clone.commit("t", "host edit").unwrap();

    let outcomes = clone.ws_harvest(None, None, "t", None).unwrap();
    let merged = match outcomes.as_slice() {
        [WsHarvestOutcome::Landed { merged_tip, .. }] => *merged_tip,
        other => panic!("expected a clean landing, got {other:?}"),
    };
    let snap = clone.snapshot(&merged).unwrap();
    assert_eq!(snap.parents.len(), 2);
    assert_eq!(snap.parents[0], host_tip);
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        b"ONE\ntwo\nTHREE\n"
    );
    assert_eq!(dir_id(&clone, &merged, "docs"), docs, "docs is unchanged");
    assert!(!has(&clone, &docs), "and was never read or fetched");
    assert!(!fx.clone_root.join("docs").exists());
    assert!(
        clone.ws_session(None).unwrap().is_none(),
        "the session ended"
    );
    drop(clone);
    fx.cleanup();
}

/// Both sides edit the same line: the workspace falls back to a branch and
/// the landing branch is untouched.
#[test]
fn harvest_conflict_falls_back_to_a_branch() {
    let fx = Fx::origin("ws-conflict", |_| {});
    let clone = fx.clone(false);
    let session = clone.ws_fork(None, 1, "t", None).unwrap();
    std::fs::write(session.workspaces[0].dir.join("src/a.txt"), SRC_FIRST).unwrap();
    std::fs::write(fx.clone_root.join("src/a.txt"), b"uno\ntwo\nthree\n").unwrap();
    let host_tip = clone.commit("t", "host edit").unwrap();

    let outcomes = clone.ws_harvest(None, None, "t", None).unwrap();
    match outcomes.as_slice() {
        [WsHarvestOutcome::FallbackBranch { branch, .. }] => {
            assert_eq!(branch, "work-1");
        }
        other => panic!("expected a fallback branch, got {other:?}"),
    }
    assert!(refs::read_branch_tip(clone.layout(), "work-1")
        .unwrap()
        .is_some());
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        Some(host_tip),
        "main did not move"
    );
    assert!(!clone.merge_in_progress());
    drop(clone);
    fx.cleanup();
}

/// Two named sessions on one partial clone (ADR-0056): each is forked under the
/// host's view, they edit different lines of one file, and they land one after
/// the other. The second is a real merge over the first, and `docs/` is carried
/// by id the whole time, never read.
#[test]
fn two_named_sessions_land_independently_under_the_view() {
    let fx = Fx::origin("ws-named", |_| {});
    let clone = fx.clone(false);
    let base = refs::read_branch_tip(clone.layout(), "main")
        .unwrap()
        .unwrap();
    let docs = dir_id(&clone, &base, "docs");

    let a = clone.ws_fork(Some("a"), 1, "t", None).unwrap();
    let b = clone.ws_fork(Some("b"), 1, "t", None).unwrap();
    for ws in a.workspaces.iter().chain(&b.workspaces) {
        assert_eq!(std::fs::read(ws.dir.join("src/a.txt")).unwrap(), SRC_A);
        assert!(!ws.dir.join("docs").exists(), "docs is outside the view");
    }
    std::fs::write(a.workspaces[0].dir.join("src/a.txt"), SRC_FIRST).unwrap();
    std::fs::write(b.workspaces[0].dir.join("src/a.txt"), SRC_LAST).unwrap();

    let first = match clone
        .ws_harvest(Some("a"), None, "t", None)
        .unwrap()
        .as_slice()
    {
        [WsHarvestOutcome::Landed { merged_tip, .. }] => *merged_tip,
        other => panic!("expected a landing, got {other:?}"),
    };
    assert!(
        clone.ws_session(Some("b")).unwrap().is_some(),
        "b is still open"
    );
    let merged = match clone
        .ws_harvest(Some("b"), None, "t", None)
        .unwrap()
        .as_slice()
    {
        [WsHarvestOutcome::Landed { merged_tip, .. }] => *merged_tip,
        other => panic!("expected a landing, got {other:?}"),
    };
    assert_eq!(clone.snapshot(&merged).unwrap().parents[0], first);
    assert_eq!(
        std::fs::read(fx.clone_root.join("src/a.txt")).unwrap(),
        b"ONE\ntwo\nTHREE\n"
    );
    assert_eq!(dir_id(&clone, &merged, "docs"), docs, "docs is unchanged");
    assert!(!has(&clone, &docs), "and was never read or fetched");
    assert!(clone.ws_sessions().unwrap().is_empty());
    drop(clone);
    fx.cleanup();
}

/// An untouched workspace harvests as unchanged, with no branch minted.
#[test]
fn harvest_of_an_untouched_workspace_is_unchanged() {
    let fx = Fx::origin("ws-unchanged", |_| {});
    let clone = fx.clone(false);
    clone.ws_fork(None, 1, "t", None).unwrap();
    let outcomes = clone.ws_harvest(None, None, "t", None).unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [WsHarvestOutcome::Unchanged { .. }]
    ));
    assert!(refs::read_branch_tip(clone.layout(), "work-1")
        .unwrap()
        .is_none());
    drop(clone);
    fx.cleanup();
}

fn work_opts(cmd: &[&str], scratch: &std::path::Path) -> WorkOptions {
    WorkOptions {
        agents: 1,
        base_name: "agent".into(),
        cmd: cmd.iter().map(|s| s.to_string()).collect(),
        author: "t".into(),
        message: None,
        identity: None,
        with_secrets: false,
        session_root: Some(scratch.join("session")),
    }
}

/// `sc work` agents see the view only, and what they commit is grafted onto
/// the base's out-of-view subtrees without reading them.
#[test]
fn work_agents_see_the_view_and_harvest_without_reading_the_rest() {
    let fx = Fx::origin("work-partial", |_| {});
    let clone = fx.clone(false);
    let base = refs::read_branch_tip(clone.layout(), "main")
        .unwrap()
        .unwrap();
    let docs = dir_id(&clone, &base, "docs");
    let scratch = std::env::temp_dir().join(format!("scl-work-partial-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();

    // The agent proves it cannot see docs/ and edits a file in the view.
    let outcomes = clone
        .work(work_opts(
            &["sh", "-c", "test ! -e docs && echo agent >> src/a.txt"],
            &scratch,
        ))
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].agent_exit, Some(0));
    let tip = match &outcomes[0].harvest {
        Ok(crate::workspace::HarvestResult::Committed(id)) => *id,
        other => panic!("expected a committed harvest, got {other:?}"),
    };
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "agent-1").unwrap(),
        Some(tip)
    );
    assert_eq!(dir_id(&clone, &tip, "docs"), docs, "docs is carried");
    assert!(!has(&clone, &docs), "and was never read or fetched");
    assert!(!scratch.join("session").exists(), "no session residue");
    std::fs::remove_dir_all(&scratch).unwrap();
    drop(clone);
    fx.cleanup();
}

/// A non-lazy clone whose HEAD view holds a gap: fork and `sc work` fail with
/// the gap error before any session state or checkout exists.
#[test]
fn fork_and_work_refuse_a_view_gap_before_writing_anything() {
    let fx = Fx::origin("ws-gap", |_| {});
    let clone = fx.clone(false);
    // The origin adds src/copy.md with the bytes of docs/a.md. The clone never
    // fetched that blob (docs/ is outside its filter), so after a fetch an
    // in-filter object is absent. Its main is pointed at the new tip.
    std::fs::write(fx.origin_root.join("src/copy.md"), b"a\n").unwrap();
    fx.origin
        .commit("t", "adds a src file sharing a docs blob")
        .unwrap();
    clone.fetch("origin").unwrap();
    let tip = refs::resolve_tip(clone.layout(), "origin/main")
        .unwrap()
        .unwrap();
    refs::write_branch_tip(clone.layout(), "main", &tip).unwrap();
    assert!(
        !has(&clone, &crate::partial_merge::blob_id(b"a\n")),
        "premise: a gap"
    );

    let err = clone.ws_fork(None, 1, "t", None).unwrap_err();
    assert!(
        matches!(err, crate::error::Error::GapInView { .. }),
        "got {err:?}"
    );
    assert!(clone.ws_session(None).unwrap().is_none());
    assert!(!clone.layout().dot_sc.join("ws").exists(), "no session dir");

    let scratch = std::env::temp_dir().join(format!("scl-work-gap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let err = clone.work(work_opts(&["true"], &scratch)).unwrap_err();
    assert!(
        matches!(err, crate::error::Error::GapInView { .. }),
        "got {err:?}"
    );
    assert!(!scratch.join("session").exists(), "no session residue");
    std::fs::remove_dir_all(&scratch).unwrap();
    drop(clone);
    fx.cleanup();
}

/// A probe that cannot be answered (the host moved a protected region the
/// clone does not hold) fails the harvest, and must not leave a candidate
/// `work-<i>` branch behind: a retry would mint another one.
#[test]
fn a_failing_probe_leaves_no_candidate_branch() {
    let (_sk, pk) = scl_crypto::generate_keypair();
    let fx = crate::partial_merge::protected_origin("ws-probe", &pk);
    let b1 = fx.origin_branch("b1", &[("vault/s.txt", b"L1\nl2\nl3\n")]);
    let clone = fx.clone(false);
    let session = clone.ws_fork(None, 1, "t", None).unwrap();
    std::fs::write(session.workspaces[0].dir.join("src/a.txt"), SRC_FIRST).unwrap();
    // The host fast-forwards to a commit that changed the protected vault/,
    // which the clone does not hold and cannot fetch.
    clone.merge("origin/b1", "t").unwrap();
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        Some(b1)
    );

    let err = clone.ws_harvest(None, None, "t", None).unwrap_err();
    eprintln!("probe error: {err:?}");
    assert!(
        refs::read_branch_tip(clone.layout(), "work-1")
            .unwrap()
            .is_none(),
        "no candidate branch may survive a failed harvest ({err:?})"
    );
    assert!(
        clone.ws_session(None).unwrap().is_some(),
        "the workspace stays live"
    );
    assert_eq!(
        refs::read_branch_tip(clone.layout(), "main").unwrap(),
        Some(b1)
    );
    clone.ws_abandon(None, None).unwrap();
    drop(clone);
    fx.cleanup();
}
