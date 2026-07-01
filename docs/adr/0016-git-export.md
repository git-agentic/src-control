# ADR-0016: Git export for round-trip interop

- **Status:** Accepted
- **Date:** 2026-06-25
- **Phase:** 9

## Context

`gitio` originally imported a Git repository's HEAD into our store (ADR-0007)
but had no write-back path. The thesis is to interoperate with Git, not replace
it; teams need to push src-control history into a Git repo for coexistence,
migration, and existing tooling (`git log`, hosting, CI).

## Decision

Add **`sc export --to <git-repo>`** that maps src-control objects to Git objects,
keeping the translation **quarantined in `gitio`** (the only crate linking `gix`,
per ADR-0007):

- **Blob → Git blob**, **Tree → Git tree** (translating our sorted, mode-bearing
  entries to Git's tree format), **Snapshot → Git commit** (root tree + parents +
  author/message; our `i64` timestamp maps to Git's commit time).
- Export walks the current branch's full history and writes the equivalent Git
  object graph, then updates a Git ref to the exported commit. Re-export is
  idempotent: identical history maps to identical Git objects via deterministic
  signature synthesis (parse `Name <email>` else name-only + empty email;
  committer = author; timezone +0000).
- **Encrypted-path objects (protected files):** export is **fail-closed** — if the
  history contains protected paths or registry secrets the command refuses unless
  `--include-encrypted` is passed. With `--include-encrypted`, protected files
  export as their **ciphertext blobs** (nothing plaintext leaks); registry secrets
  are **dropped and reported** rather than materialized as sidecar files, because
  Git has no equivalent of our secrets registry.
- **Target ref is overwritten** (mirror semantics). If the `--to` path does not
  exist it is created with `git init --bare`; `HEAD` is pointed at the exported ref
  on a newly-created repo. Pre-existing repos have their ref force-updated but
  HEAD is left alone.

Import (ADR-0007) plus export gives round-trip interop; full bidirectional sync
(treating Git as a remote via the P6 `Transport`) is a later extension.

## Consequences

- src-control history becomes visible to and migratable into the Git ecosystem.
- The `gix` dependency stays in `gitio`; export is the symmetric peer of import,
  so the boundary and invariant are unchanged.
- Mapping is mostly mechanical because both models are content-addressed DAGs of
  blobs/trees/commits; the lossy points are our extra metadata (secrets registry,
  protection policy, per-entry `perms`) which Git trees cannot carry and which the
  export must handle explicitly rather than silently drop.
- The fail-closed scan keys on the per-entry `PROTECTED` bit, so content that was
  committed as plaintext *before* a path was protected remains plaintext in history
  and is neither flagged nor refused by `--include-encrypted`. This is the same
  forward-looking model as git-crypt; a reader must not treat export refusal as a
  blanket "no plaintext anywhere in history" guarantee.

## As built (P9)

The implementation shipped with the stricter export policy captured above:

- `scl-gitio` owns the full Git-write path in `export.rs` and exports only
  project-native types (`ExportOptions`, `ExportReport`, `export_branch`) so no
  `gix` type leaks into `cli` or `repo`.
- Export walks the snapshot DAG from the current branch tip, writes parents
  before children, emits canonical Git tree order, synthesizes deterministic
  author/committer signatures, and force-updates the requested ref.
- Absent targets are initialized as bare Git repos and have `HEAD` pointed at the
  exported ref; existing Git repos keep their existing `HEAD`.
- `sc export --to <path> [--ref <name>] [--include-encrypted]` resolves the
  current branch tip in `cli`, calls `gitio::export_branch`, and reports commit
  count plus any protected ciphertext / dropped-secret counts.
- Tests cover canonical tree ordering against `git`, multi-commit history,
  idempotent re-export, import→export→re-import round-trip, fail-closed encrypted
  content, and `--include-encrypted` behavior.

## Alternatives considered

- **Git as the on-disk format (no native store).** Abandons the thesis of owning
  the object format and the features that depend on it (committed secrets,
  encrypted paths, in-RAM clones); rejected from the start.
- **One-way migration dump only (no idempotent re-export).** Simpler but breaks
  ongoing coexistence; we want repeatable export so a src-control repo can
  continuously mirror to Git.
- **Exporting decrypted content for Git compatibility.** Would leak protected
  content into an unprotected store; rejected — export preserves ciphertext.
