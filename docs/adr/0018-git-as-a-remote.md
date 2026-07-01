# ADR-0018: Git as a remote (bidirectional sync)

- **Status:** Accepted
- **Date:** 2026-07-01
- **Phase:** 10

## Context

P1 import (ADR-0007) reads a Git `HEAD` tree into the store one-way, minting
fresh snapshot ids on every run. P9 export (ADR-0016) writes sc history to Git
one-way, deterministically. Neither is the inverse of the other: import does
not reproduce prior ids on re-run against the same commits, and export is not
consulted by import. That means a Git repository could not act as a genuine
**remote** in the P6 sense (ADR-0013) — something a src-control repo can
`fetch` from and `push` to in a loop without duplicating or diverging history.

This phase closes that loop: `sc fetch <git-remote>` → `sc merge` →
`sc push <git-remote>` against a Git repo, reusing the collaborative workflow
users already have from P6 sc-to-sc remotes.

**Scope: local Git repos on disk** (a bare `.git` path), matching how P6 scoped
itself — local transport first, network deferred. The hard part is the DAG
bijection and identity map, which is identical whether the Git repo is local or
remote; local-first proves the model without taking on Git's wire protocol,
auth, or TLS.

## Decision

### Identity via a persisted marks map, not a fatter object model

Bidirectional sync needs a stable bijection between the sc snapshot DAG and
Git's commit DAG. Three mechanisms were weighed:

- **Persisted marks map (chosen).** A per-git-remote table
  `git_oid ↔ sc_snapshot_id`, stored under `.sc/git-remotes/<name>/marks` as
  append-only text lines `<git_oid_hex> <sc_id_hex>`. Identity is carried by the
  map, not by byte-fidelity — the same pattern as `git-fast-import` marks,
  `git-remote-hg`, and `git-cinnabar`.
- **Fat snapshots (rejected).** Growing the `Snapshot` object to carry Git's
  committer, timezone, and gpgsig fields would make import→export byte-exact,
  but it **changes the canonical snapshot encoding, which changes every sc
  object id** — a format break of the content-addressing invariant (CLAUDE.md),
  not a tradeoff. It also pollutes the core model with Git-specific baggage and
  still cannot help sc-native commits that carry no Git metadata to begin with.
  The content-addressing invariant decides this outright; it was never a live
  contender.
- **Stateless deterministic bijection (rejected).** Relying on import and
  export being pure inverses fails because real Git commits carry
  committer/timezone/gpgsig that the sc model does not hold, so fetch-then-push
  would not reproduce the original Git oid and would fork the remote's history.

Import stays a **deterministic pure function of the Git commit** — so two sc
repos fetching the same Git repo derive identical sc ids and can then sync
sc-to-sc directly — but the marks map, not byte-fidelity, is the source of
truth for round-trip identity. Import is not contorted into a byte-exact
inverse of export.

The map is commit-only (trees/blobs are cheap to re-derive deterministically
each time, so persisting them buys nothing) and a **recoverable cache, not
ground truth**: deleting it and re-fetching reproduces the same sc ids (import
is pure), and a later push re-synthesizes Git commits deterministically
(identical Git oids, idempotent on the remote). Loss is recoverable, never
corrupting.

### Deterministic import & the signature round-trip

Export (`synth_sig`, from P9) is pinned: committer = author, timezone = UTC
(`+0000`), no gpgsig, Git author-time = `snap.timestamp`. Import is the inverse
on those same fields: `snap.author` = Git author name/email, `snap.timestamp` =
Git author-time, `snap.message` = Git message, `snap.root` = imported tree,
`snap.parents` = mapped parent sc ids, `secrets = {}`, `protection = default`.
A real Git commit's committer, timezone offset, and gpgsig are dropped — sc
does not model them — which is exactly why the marks map exists to carry
identity for Git-origin commits.

This is a consistent inverse on sc's fields, not byte-exactness:

- **sc-native round-trip is lossless.** Author in sc → push (synthesize Git) →
  peer fetch → deterministic import reproduces the same sc id.
- **Git-origin commits are stable but not byte-reversible.** Fetching a real
  Git commit drops committer/tz/gpgsig from the snapshot; a later push reuses
  the mapped Git oid (map hit), so the original Git commit is never rewritten.
- **Accepted MVP limitation: fetch-from-A / push-to-B divergence.** Fetching
  from Git repo A, then pushing a Git-origin commit to a *different* Git repo B
  with no mark for B, forces re-synthesis — B gets a commit with dropped
  committer/tz/gpgsig and a different Git oid than A had. The common case —
  fetch and push against the same remote — is clean. This is documented, not
  solved, in this phase.

### Confidentiality: reuse the export fail-closed gate

Pushing to a Git remote is the same boundary crossing as `sc export`, and Git
has no envelope-encryption model. Push reuses P9's behavior verbatim: if any
pushed snapshot carries `PROTECTED` tree entries or registry secrets, refuse
unless `--include-encrypted`. With the flag, protected files go out as
ciphertext blobs and secrets are dropped (counted in the report) — no new
policy is introduced. Fetch is safe by construction: Git content is plaintext,
imported as ordinary sc blobs; nothing decrypts and no secrets are minted.

### Push semantics: fast-forward-only

Matches P6 (ADR-0013): read the current Git ref tip; if non-empty and not an
ancestor of what is being pushed, refuse — no force push this round. Creating
an absent Git branch is allowed (mirrors P6's "push creates a new remote
branch"). The Git ref is updated only after all objects are written and
verified, so a failed push never leaves a ref pointing at a missing commit.

### Crate boundaries and dispatch above `Transport`

The git-remote path sits **above** the object-level `Transport` trait (P6) and
does not implement it — `Transport` exchanges content-addressed sc objects by
BLAKE3 id and cannot describe a Git remote, which has a different id space and
encoding entirely. `sc fetch`/`sc push` **dispatch on remote kind**: sc-backed
remotes use the existing P6 `Transport` path; git-backed remotes use the new
translation path.

- **`gitio`** (the only crate linking `gix`, per ADR-0007) grows the
  translation core: `import_history` does a full-history post-order walk (the
  inverse shape of `export_branch`), deterministic, returning
  `(git_oid_hex, sc_id)` pairs. `export_branch` consults/emits a
  caller-supplied marks lookup instead of a per-run in-memory memo, so
  already-mapped snapshots reuse their Git oid rather than being rewritten.
  Its public surface deals only in opaque hex `git_oid` strings; no `gix` type
  leaks out.
- **`repo`** stays Git-agnostic. It gains a generic per-remote opaque metadata
  store — a `(key, value)` table under `.sc/git-remotes/<name>/` that persists
  bytes/strings without knowing they mean "git oid ↔ sc id" — plus a remote
  *kind* (sc-backed vs. git-backed) recorded in `.sc/config`, and reuses the
  existing `refs/remotes/<name>/<branch>` remote-tracking machinery.
- **`cli`** owns orchestration: opens the Git repo via `gitio`, threads the
  marks map in/out of `repo`'s metadata store, writes remote-tracking refs, and
  applies the confidentiality gate.

## Consequences

- A Git repository is now a first-class remote: `sc remote add <name>
  <git-path> --git`, `sc fetch <git-remote>`, `sc push <git-remote>
  [--include-encrypted]`, integrated through the existing `sc merge
  <git-remote>/<branch>`.
- `gix` stays quarantined in `gitio`; `repo` never depends on it. The
  content-addressing invariant is untouched — the sc object model was not
  changed to accommodate Git metadata.
- GC safety is inherited for free: fetch writes
  `refs/remotes/<gitremote>/<branch>`, which is already a GC root, so snapshots
  that exist only because they were fetched from Git stay reachable without new
  machinery.
- **Side-fix discovered during the build:** `sc merge <ref>` previously assumed
  the local branch already had a tip. The demo's second repo (`sc init` then
  `sc fetch hub` then `sc merge hub/main`) merges into a freshly initialized,
  unborn branch — there is no local tip yet to three-way-merge against. `Repo::merge`
  (`crates/repo/src/repo.rs`) was extended to detect the unborn case and adopt
  the incoming snapshot wholesale (fast-forward-from-empty, the same behavior
  Git uses when merging into an unborn branch), rather than erroring. This is a
  necessary generalization of P4's merge, not a git-remote-specific special
  case — it also benefits the sc-to-sc P6 loop (`sc init` a fresh repo, add an
  sc-backed remote, `fetch`, then `merge` into the still-unborn local branch,
  without an intervening `sc clone`).
- The fetch-A/push-B divergence (see Decision) is a known, accepted boundary:
  Git-origin history pushed to a remote other than the one it was fetched from
  will re-synthesize with a different Git oid. Same-remote fetch/push stays
  clean.
- Network Git (GitHub over https/ssh) remains a later transport swap; this
  phase only proves the model against local bare repos.

## Alternatives considered

- **Fat snapshots carrying full Git metadata.** Rejected — breaks the
  content-addressing invariant by changing the canonical encoding, and does
  not help sc-native commits that never had Git metadata. See Decision.
- **Stateless deterministic bijection with no persisted state.** Rejected —
  cannot round-trip real Git commits, since sc drops committer/timezone/gpgsig;
  fetch-then-push would silently fork the remote's history. See Decision.
- **Implementing git-backed remotes under the existing `Transport` trait.**
  Rejected — `Transport` is defined over content-addressed sc object ids;
  forcing a different id space and encoding through it would corrupt the
  abstraction. Dispatch on remote kind above `Transport` keeps both paths
  honest.
- **Force push / non-fast-forward push in this phase.** Rejected — deferred to
  match P6's no-force stance; a git-backed remote should not behave more
  permissively than an sc-backed one.
- **Byte-faithful preservation of Git committer/timezone/gpgsig for every
  commit.** Would require the fat-snapshot approach above; rejected for the
  same reason. The marks map already gives lossless identity for the common
  same-remote case, which is deemed sufficient for this phase.
