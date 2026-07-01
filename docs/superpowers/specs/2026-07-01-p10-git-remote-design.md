# P10 — Git as a remote (bidirectional sync): design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-07-01
- **Phase:** 10
- **Refines:** ADR-0018 (new; firm to Accepted at build time)
- **Builds on:** ADR-0007 (Git interop via `gix`, import side), ADR-0016 / P9
  (`sc export` — deterministic sc→git translation), ADR-0013 / P6 (remotes:
  named remotes, remote-tracking refs, fetch→merge loop), ADR-0012 / P4 (merge),
  ADR-0015 / P8 (packfiles + GC reachability)

## Goal

Make a Git repository a **first-class remote** that a src-control repo can
`fetch` from and `push` to, closing the interop loop. P1 import reads a Git
`HEAD` tree one-way; P9 `sc export` writes sc history to Git one-way. Neither
round-trips: import mints fresh snapshot ids each run and covers only HEAD, so
it is not the inverse of export. This phase adds a **stable, repeatable
bijection** between sc's snapshot DAG and Git's commit DAG so the collaborative
loop — `sc fetch <git-remote>` → `sc merge` → `sc push <git-remote>` — works
against a Git repo without duplicating or diverging history.

**Scope: local Git repos on disk** (a bare `.git` path), matching how P6 scoped
itself (ADR-0013: local transport first; network deferred). The hard part — the
DAG bijection and the identity map — is identical whether the Git repo is on
disk or across the network, so local-first proves the model without taking on
Git's wire protocol, auth, or TLS. Network Git (GitHub over https/ssh) is a
later transport swap.

The translation stays **quarantined in `gitio`** — the only crate that links
`gix` (ADR-0007). The content-addressing invariant (CLAUDE.md) is preserved by
construction: the sc object model is not changed.

## Decisions (locked in brainstorm)

### 1. Identity via a persisted correspondence map ("marks"), not a fatter object model

Bidirectional sync needs a stable bijection between the two DAGs. Three
mechanisms were weighed:

- **(A) Persisted marks map — chosen.** A per-git-remote table
  `git_oid ↔ sc_snapshot_id` stored in `.sc/`. Identity is carried by the map,
  not by byte-fidelity. Proven pattern (git-fast-import marks, git-remote-hg,
  git-cinnabar).
- **(B) Fat snapshots (round-trip-faithful encoding) — rejected.** Growing the
  `Snapshot` object to carry Git's committer/timezone/gpgsig/encoding would make
  import→export byte-exact, but it **changes the canonical snapshot encoding,
  which changes every sc object id** — a format break of the content-addressing
  invariant (CLAUDE.md), not a tradeoff. It also pollutes the core model with
  Git baggage and still cannot help sc-native commits that have no Git metadata.
  The invariant decides this; (B) is not a live contender.
- **(C) Stateless deterministic bijection — rejected.** Relying on import and
  export being pure inverses fails because Git commits carry committer/tz/gpgsig
  the sc model does not hold, so fetch-then-push would not reproduce the original
  Git oid and would fork the remote's history.

**Import stays a deterministic pure function of the Git commit** (so two sc
repos fetching the same Git repo derive identical sc ids and can then sync
sc-to-sc), but the **marks map — not byte-fidelity — is the source of truth for
round-trip identity.** Import is not contorted to be a byte-exact inverse of
export.

### 2. Crate boundaries (dependency rule: `repo ↛ gitio`; `cli` links both)

- **`gitio`** (only crate linking `gix`) grows the translation core:
  - `import_history(store, git_repo_path, branch) -> Vec<(git_oid_hex, sc_id)>`
    — full-history post-order walk (the inverse shape of `export_branch`),
    deterministic, returns commit-level id pairs.
  - `export_branch` is refactored to consult/emit a **caller-supplied marks
    lookup** instead of its per-run in-memory memo, so already-mapped snapshots
    reuse their Git oid rather than being rewritten.
  - Public surface deals in **opaque hex `git_oid` strings**; no `gix` types leak.
- **`repo`** stays Git-agnostic. It gains:
  - A generic **per-remote opaque metadata store** — a `(key, value)` table
    under `.sc/git-remotes/<name>/` that persists bytes/strings without knowing
    they mean "git oid ↔ sc id".
  - Git-remote registration in `.sc/config` (a remote *kind*: sc-backed vs
    git-backed).
  - Reuses the existing `refs/remotes/<name>/<branch>` remote-tracking machinery.
- **`cli`** owns orchestration: opens the Git repo via `gitio`, threads the marks
  map in/out of `repo`'s metadata store, writes remote-tracking refs, and applies
  the confidentiality gate.

The git-remote path sits **above** the object-level `Transport` trait and does
**not** implement it — that trait exchanges content-addressed sc objects by
BLAKE3 id and cannot describe a Git remote (different id space and encoding).
`sc fetch/push <name>` **dispatches on remote kind**: sc-backed → existing P6
`Transport` path; git-backed → new translation path.

### 3. The marks map: commit-only, append-only, cache-not-truth

- **Location/format:** `.sc/git-remotes/<name>/marks`, append-only text lines
  `<git_oid_hex> <sc_id_hex>`, loaded into a bidirectional `HashMap` on use.
  `repo` owns the file as opaque bytes; Git meaning lives in `cli`/`gitio`.
- **Commit↔snapshot pairs only.** Trees and blobs are re-derived deterministically
  each translation (cheap, content-addressed, idempotent), so persisting them
  buys nothing. Commits are irreducible: a Git commit carries committer/tz/gpgsig
  the sc snapshot cannot reconstruct, so we must *remember* the origin Git oid.
- **Recoverable cache, not content ground-truth.** Content is content-addressed
  and re-derivable. Deleting the map → a re-fetch re-imports deterministically
  (same sc ids, import is pure) and a later push re-synthesizes Git commits
  (deterministic export → identical Git oids → idempotent on the remote). Loss is
  recoverable, never corrupting.

### 4. Deterministic import & the signature round-trip

Export and import must agree on the fields sc models, or an sc-native commit
pushed to Git and re-fetched by a peer would land on a *different* sc id and fork
the DAG. This is a **consistent inverse on sc's fields**, not byte-exactness.

- **Export (`synth_sig`, from P9), pinned rule:** committer = author, timezone =
  UTC (`+0000`), no gpgsig, Git author-time = `snap.timestamp`.
- **Import (new), the inverse on those fields:** `snap.author` = Git author
  name/email, `snap.timestamp` = Git author-time, `snap.message` = Git message,
  `snap.root` = imported tree, `snap.parents` = mapped parent sc ids,
  `secrets = {}`, `protection = default`. A real Git commit's committer, timezone
  offset, and gpgsig are **dropped** (sc does not model them) — which is exactly
  why the marks map exists to carry identity for Git-origin commits.

Resulting guarantees, stated honestly:

- **sc-native round-trip is lossless.** Author in sc → push (synthesize Git) →
  peer fetch → deterministic import reproduces the *same* sc id.
- **Git-origin commits are stable but not byte-reversible.** Fetch a real Git
  commit → the snapshot drops committer/tz/gpgsig; a later push reuses the
  mapped Git oid (map hit), so the original Git commit is never rewritten.
- **Known MVP limitation (documented, not solved): fetch-from-A / push-to-B
  divergence.** Fetching from Git repo A then pushing a Git-origin commit to a
  *different* Git repo B (no mark for B) forces re-synthesis → B gets a commit
  with dropped committer/tz/gpgsig, a different Git oid than A had. The common
  case — fetch and push against the *same* remote — is clean. Called out in the
  spec and ADR as an accepted boundary.

### 5. Confidentiality: reuse the export fail-closed gate

Pushing to a Git remote is the same boundary crossing as `sc export`, and Git has
no envelope-encryption model. Push **reuses P9's behavior verbatim**: if any
snapshot in the pushed history carries `PROTECTED` tree entries or registry
secrets, **refuse unless `--include-encrypted`**. With the flag, protected files
go out as ciphertext blobs and secrets are dropped (counted in the report) — no
new policy. *Fetch* is safe by construction: Git content is plaintext, imported
as ordinary sc blobs; nothing decrypts and no secrets are minted.

### 6. Push semantics: fast-forward-only (matches P6)

- Read the current Git ref tip; if non-empty and not an ancestor of what we're
  pushing (not a fast-forward), refuse clearly — no force this round.
- Creating an absent Git branch is allowed (mirrors P6's "push creates a new
  remote branch").
- The Git ref is updated only **after** all objects are written and verified —
  never leave a ref pointing at a missing commit.

### 7. Fetch → merge integration (matches P6)

Fetch never touches the working tree or local branches; it writes
`refs/remotes/<gitremote>/<branch>` and updates the marks map. Integration is the
existing `sc merge <gitremote>/<branch>` (P4), keeping the git-remote loop
identical to the sc-remote loop the user already knows.

## Data flow

**fetch:** `cli` opens the Git repo via `gitio` → `gitio` walks Git history,
importing commits→snapshots deterministically, returning `(git_oid, sc_id)`
pairs, stopping descent at any oid already in the marks map → `cli` persists new
pairs and writes `refs/remotes/<gitremote>/<branch>` to the tip sc id → user runs
`sc merge <gitremote>/<branch>`.

**push:** `cli` walks local snapshots from the branch tip → for each, map hit ⇒
reuse Git oid (already on remote, don't rewrite); map miss ⇒ `gitio` synthesizes
+ writes a Git commit via the deterministic export path, record the new pair →
after the whole DAG is written, fast-forward-update the Git ref.

## GC safety (the one real hazard)

`sc gc` prunes by reachability. Snapshots that exist only because they were
fetched from Git must stay reachable. This is already solved for sc remotes: fetch
writes `refs/remotes/<gitremote>/<branch>`, whose tip and full DAG are GC roots.
Confirm the remote-tracking ref is treated as a GC root and add a test that `gc`
after a git-fetch (with no local merge) retains the fetched snapshots. The marks
file is not a GC root and does not need to be — it only maps ids kept alive
independently by the ref.

## Failure atomicity

- **Fetch** dying mid-walk leaves already-written sc objects (harmless,
  unreferenced, gc-collectible) but does **not** advance the remote-tracking ref
  or append partial marks — ref and marks are written last, together, after the
  walk succeeds (same discipline as `put_pack`'s "don't update refs on failure").
- **Push** failing before the Git ref update leaves synthesized Git objects
  orphaned in the Git repo (reclaimable by `git gc`) but never advances the Git
  ref.

Errors: per-crate `thiserror` in `repo`/`gitio`, `anyhow` in `cli`.

## CLI surface

- `sc remote add <name> <git-path> --git` — register a git-backed remote.
- `sc fetch <git-remote>` — import full history, write remote-tracking ref +
  marks. Dispatches to the git path on remote kind.
- `sc push <git-remote> [--include-encrypted]` — synthesize/reuse Git commits for
  the current branch, ff-only update the Git ref.
- `sc remote list` shows kind (sc/git) per remote.

## Testing & demo

**Unit / integration** (in-crate `#[cfg(test)]`, temp dirs cleaned up and
teardown asserted, per CLAUDE.md):

- *gitio:* `import_history` reconstructs a multi-commit Git DAG (not just HEAD)
  with correct parent edges; import is deterministic (same repo → same sc ids
  across runs); merge commits (two parents) import correctly.
- *Round-trip identity:* author sc commits → push to a local bare Git repo →
  fresh sc repo fetches → **identical sc snapshot ids**; `git log` on the target
  reads back the expected commits (P9 verification style).
- *Marks map:* fetch then push against the same remote does **no commit rewrite**
  (map hits, Git oids unchanged); deleting the marks file and re-fetching yields
  the same sc ids (recoverable-cache property).
- *Confidentiality:* pushing history with a protected path or a secret **refuses**
  without `--include-encrypted` and succeeds (ciphertext, secrets dropped,
  counted) with it — mirrors the P9 refusal test.
- *Push semantics:* ff push advances the Git ref; non-ff push is rejected;
  pushing to an absent branch creates it.
- *GC safety:* `sc gc` after a git-fetch (no local merge) retains the fetched
  snapshots.

**End-to-end demo:** `demo/run_git_remote_demo.sh` in the style of the existing
scripts — `sc init` + commit, `git init --bare` target, `sc remote add --git`,
`sc push`, verify with real `git log`; then a second sc repo `sc fetch`es the
bare Git repo, `sc merge`s it, and shows the content arrived. An independent,
scriptable proof of the round-trip; the phase's demoable outcome.

## Docs to update at build time

- New **ADR-0018** (git-as-a-remote bidirectional sync), Proposed→Accepted with
  refinements discovered during the build; add to the ADR index (Phase 10).
- **ROADMAP.md** P10 entry (Done + table) and dependency notes.
- **CLAUDE.md** command list, a "Phase 10 is built" note, and drop
  "git-as-a-remote bidirectional sync" from the remaining follow-ons.

## Non-goals (this phase)

- Network Git (GitHub over https/ssh) — later transport swap.
- Byte-faithful preservation of Git committer/timezone/gpgsig — carried by the
  marks map for same-remote round-trips; the fetch-A/push-B divergence is an
  accepted MVP boundary.
- Multi-branch / all-refs mirror in one command — current branch per push,
  matching P6/P9.
- Force push / non-ff push.
- Submodule content (skipped today by import, unchanged here).
