# ADR-0033: Merge ergonomics — conflict UX beyond markers

- **Status:** Accepted
- **Date:** 2026-07-08
- **Phase:** 23
- **Builds on:** ADR-0012 (three-way merge), ADR-0025 (protected conflicts), ADR-0029 (in-progress states)

## Context

P4 chose detection/representation (markers + sidecars) and deferred
resolution UX. Every phase since has widened the surfaces that produce
conflicts (merge, pick, stopped rebase, ws fallback branches) while the
resolution story remained "edit the markers by hand."

## Decision

Presentation and resolution tooling only; merge semantics unchanged.
Spec: `docs/superpowers/specs/2026-07-08-p23-merge-ergonomics-design.md`.

One `conflict_versions(path) -> {base, ours, theirs}` abstraction
re-derives the three versions from the DAG (authoritative, not parsed
from lossy markers), dispatching on the active op: merge (ours=tip,
theirs=`MERGE_HEAD`, base=merge-base), cherry-pick (theirs=`PICK_HEAD`,
base=picked parent), rebase-stop (ours=`REBASE_STATE.acc_tip`,
theirs=the conflicted commit, base=its parent).

- `sc conflicts [<path>] [--identity]` — no path lists conflicted paths
  with a kind tag (text/binary/protected); with a path shows base/ours/
  theirs (plaintext for protected under `--identity`).
- `sc resolve --ours|--theirs <path…> [--identity]` — writes the chosen
  side's clean content to the working file, drops sidecars, drops the
  path from the active `<STATE>_CONFLICTS` record. Text/binary need no
  key; protected paths need `--identity` to DECRYPT the chosen side
  (resolve never re-encrypts — completion's commit path does, so
  plaintext never enters the CAS at resolve time). Completion is the
  unchanged `sc commit` / `sc rebase --continue`.
- `sc status` gains per-path conflict detail with the protected
  identity-required note, replacing the bare count.

Uniform coverage of all conflict kinds including protected paths was the
brainstorm's decided scope (identity gate reuses P15's
`ProtectedMergeNeedsIdentity`). Whole-file-per-side only — no hunk-level
or `--union`/`--base` modes in the MVP.

## Consequences

- A conflicted merge/pick/stopped rebase becomes resolvable end-to-end
  without hand-editing markers; the demo proves it.
- Works uniformly across merge, pick, and rebase-stop conflicts because
  all three share the P4 conflict representation (and, after P21's
  extraction, one materialization helper).

## Alternatives considered

- **Interactive/TUI resolver:** far larger surface; deferred.
- **Changing conflict representation:** P4's markers+sidecars are shared
  by every downstream feature; UX layers on top instead.

## Refinements discovered during the build

- **`conflict_versions` landed exactly where the Decision said, one layer
  down.** `crates/repo/src/conflicts.rs` re-derives base/ours/theirs from
  the DAG per active op (`ActiveOp::Merge`/`Pick`/`Rebase`, precedence
  merge → pick → rebase). Each side is decrypted against **its own**
  snapshot's protection registry (`side_for` reads `snap.protection` off
  the snapshot the id belongs to, not a shared one), so a path protected on
  one side and plain on the other still resolves correctly per side.
  `conflict_kind` classifies text/binary/protected from tree-entry
  `PROTECTED` perms alone, with no decryption — an unauthorized caller can
  still see *that* a path is protected without a key.
- **A review-caught carry-in from Task 1: cherry-pick's base ignored
  `--mainline`.** `op_triple`'s `ActiveOp::Pick` arm originally derived
  `base` from `parents[0]` unconditionally. A conflicted `--mainline` pick
  (P19, ADR-0029) persists its chosen parent in `PICK_MAINLINE_BASE`, and a
  base re-derivation that ignored it would show the wrong base for anything
  but mainline 1. Fixed in Task 2: `op_triple` now checks
  `pick_state::read_mainline_base` first and only falls back to
  `parents[0]` when it's absent.
- **A review-caught CRITICAL in `resolve_path`: sidecar cleanup was a blind
  unlink of a three-name set.** The brief's "drop sidecars" language was
  read as removing `{path}.base`/`{path}.ours`/`{path}.theirs`
  unconditionally — a data-loss bug, since a repo can legitimately track a
  real file that happens to be named `foo.txt.theirs`. The system never
  writes `.base`/`.ours` sidecars at all (only `.theirs`, for a binary
  conflict), so those two names were dead code with a footgun attached.
  Fixed: `resolve_path` removes only the `.theirs` sidecar, and only when
  `{path}.theirs` is **not** itself a tracked path (checked against
  `tracked_paths()` before unlinking) — a genuine sidecar is untracked
  scratch by construction, so a tracked `{path}.theirs` is left alone as a
  user's real file.
- **`resolve_path` decrypts, never re-encrypts.** For a protected path,
  `conflict_versions`/`side_for` decrypt the chosen side with the supplied
  identity and write plaintext straight to the working file. No plaintext
  is written to the CAS at resolve time — the object store is untouched
  until the eventual `sc commit`, whose existing pipeline re-encrypts
  through the same `encrypt_protected`/`reuse_prior_wraps` helpers it
  already used before P23. That split is why `sc commit` after
  `sc resolve --theirs <protected-path> --identity <key>` needs no
  `--identity` of its own: sealing only needs recipient public keys.
- **Absent-side handling is uniform across display and resolution.**
  `side_for` returns `Side::Absent` whenever a path isn't in a given
  snapshot's tree (add/delete conflicts, or a root-commit pick/rebase with
  no base at all — `op_triple`'s `base: Option<ObjectId>` is `None` there,
  and `conflict_versions` maps that straight to `Side::Absent` without
  touching the store). Display renders it as the literal `(absent)` line;
  `resolve_path` resolving to an absent side deletes the working file
  (tolerating `NotFound` — resolving an already-absent path twice is not an
  error).
- **A pre-existing empty-list serialization bug, fixed incidentally.** The
  conflict-record writers used by `resolve_path` (`merge_state::
  set_conflicts`, `pick_state::set_conflicts`, `rebase_state::
  write_conflicts`) previously round-tripped an empty conflict list as
  `"\n".lines()`, which yields `vec![""]` (one empty-string entry) rather
  than `vec![]` — so resolving a merge/pick/rebase's last conflicted path
  would leave one phantom empty-path entry in the record. The new
  `set_conflicts` helpers fixed this at the same time Task 2 needed a
  writer that could shrink the list, since none of the three pre-P23
  writers had ever needed to write an empty list before.
- **`sc status --json`'s `"conflicts"` key changed shape, with no breaking
  consumer.** It carried `Vec<String>` (from the merge-only
  `merge_conflicts()`) before P23 and now carries `[{path, kind}]` (from
  the op-aware `active_conflicts()`/`conflict_kind()`, covering pick and
  rebase-stop conflicts too, which the old shape never did). A repo-wide
  grep for `"conflicts"` found no caller outside this file depending on the
  old shape — a strict superset, not a wire break. `sc conflicts` and
  `sc resolve` share the same `print_conflict_detail_line`/`conflicts_json`
  render helpers `sc status` already used, rather than each command owning
  its own formatting.
- **Whole-file resolution only, as scoped.** `sc resolve --ours|--theirs`
  writes an entire side; there is no hunk-level or `--union`/`--base` mode,
  matching the Decision's stated MVP scope. One thing checked and *not*
  found: `commit` has no gate that refuses literal `<<<<<<<` marker text
  left on disk — it commits whatever bytes are in the working tree
  verbatim, unresolved or not (`conflict_marks_tree_and_finalizes_on_commit`
  in `crates/repo/src/repo.rs` exercises this directly). `sc resolve` is a
  usability improvement over hand-editing markers, not a safety gate that
  was added or that markers depend on — that discipline is unchanged by
  this phase and remains entirely on the user.
