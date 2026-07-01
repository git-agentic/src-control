# P9 — Git export (round-trip interop): design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-07-01
- **Phase:** 9
- **Refines:** ADR-0016 (firm to Accepted at build time)
- **Builds on:** ADR-0007 (Git interop via `gix`, import side), P7 encrypted paths
  (ADR-0014), P8 packfiles/GC (ADR-0015)

## Goal

Let a src-control repo write its history back into Git, so teams can coexist
with, migrate to, and use existing Git tooling (`git log`, hosting, CI). Import
(ADR-0007) already reads a Git `HEAD` tree into our store; this phase adds the
symmetric peer: **`sc export --to <git-repo>`** maps our objects to Git objects
and updates a Git ref. Import + export gives round-trip interop; treating Git as
a P6 remote for full bidirectional sync is a later extension.

The translation stays **quarantined in `gitio`** — the only crate that links
`gix` (ADR-0007). Content-addressing is preserved by construction: both models
are content-addressed DAGs of blobs/trees/commits, so the mapping is
deterministic and re-export is idempotent.

## Decisions (locked: brainstorm + ADR-0016)

1. **Scope: current branch, full history.** Export walks the current branch tip
   through all parents and writes the whole commit DAG to one Git ref. All-branches
   export is a later extension. (HEAD-only was rejected — it isn't a real mirror.)
2. **Fail-closed on encrypted content.** If any reachable tree entry carries the
   `PROTECTED` perms bit, **or** any exported snapshot's `secrets` registry is
   non-empty, export **refuses** unless `--include-encrypted` is passed — matching
   the project's `MergeProtected` / "fail loudly, never silently drop" precedent.
   A warning alone is too easy to lose in automation (the real risk is pushing an
   exported mirror to a public host without realizing ciphertext rode along).
3. **Protected blobs export as ciphertext; secrets are dropped.** With
   `--include-encrypted`:
   - Protected-path files are **already ciphertext in the tree**, so they export
     as ordinary Git blobs with no special handling. Only the `protection` policy
     (wrapped DEKs, prefixes) and the `PROTECTED` perms bit are lost — the Git side
     gets opaque, undecryptable files.
   - Secrets live in the snapshot's `secrets` **registry**, not the tree, so Git
     has no slot for them; they are **dropped** (not materialized as sidecar
     files — that would add files that were never in the tree). A summary warning
     lists what exported as ciphertext and what was dropped.
4. **Target repo: auto-init a bare mirror.** `--to <path>`: an existing Git repo
   is used as-is; an absent path is created with `git init --bare`; a path that
   exists but is not a Git repo is an error.
5. **Ref: overwrite (mirror semantics).** Default target ref is
   `refs/heads/<current-branch>`, overridable with `--ref <name>`. Export **sets**
   (overwrites) the ref to the exported tip. (Fast-forward-only is a documented
   future option.)
6. **Deterministic signature synthesis.** Git commits need author *and* committer
   as `NAME <EMAIL> TIME TZ`; we have one freeform `author: String` and an
   `i64` timestamp. Synthesis: if `author` matches `Name <email>`, split it; else
   name = `author`, empty email (`<>`). committer = author; time = `timestamp`;
   timezone `+0000`. Deterministic input → identical commit bytes → identical Git
   oid → idempotent re-export.

## Out of scope (this round)

- **All-branches / tag export.** Single current branch only.
- **Git-as-a-remote bidirectional sync** (push/fetch against Git via the P6
  `Transport`). Export is one-directional history mirroring.
- **Fast-forward-only ref updates / divergence protection.** MVP overwrites.
- **Round-tripping our extra metadata** (secrets registry, protection policy,
  per-entry `perms`) *back* out of Git — Git trees can't carry it, so it is lost
  on export by design.
- **Submodule / commit-in-tree entries** (import already skips these).

## Architecture

Strict dependency direction preserved: `cli → repo → {vfs, gitio, crypto} → core`;
`repo` never depends on `gitio`.

### `gitio` — the Git write boundary (quarantined `gix`)

New public entry point, the symmetric peer of `import_head`:

```rust
/// Options controlling an export.
pub struct ExportOptions<'a> {
    /// Target Git repo path (existing repo, or created bare if absent).
    pub to: &'a Path,
    /// Ref to update, e.g. "refs/heads/main".
    pub ref_name: &'a str,
    /// Allow exporting protected ciphertext + dropping secrets.
    pub include_encrypted: bool,
}

/// Result summary: the Git commit id written and what was elided. The commit id
/// is a hex string (not a `gix` type) so `cli` never needs `gix` in scope.
pub struct ExportReport {
    pub git_commit: String,
    pub commits_written: usize,
    pub protected_blobs_as_ciphertext: usize,
    pub secrets_dropped: usize,
}

/// Export the snapshot DAG rooted at `tip` (a src-control snapshot id) into the
/// Git repo named by `opts`, updating `opts.ref_name` to the exported commit.
pub fn export_branch(store: &mut Store, tip: ObjectId, opts: &ExportOptions) -> Result<ExportReport>;
```

Internals (all inside `gitio`):

- **Pre-flight encrypted scan.** Walk the reachable set from `tip` (snapshots →
  trees → blobs, plus each snapshot's `secrets` registry). Count protected entries
  (`perms & PROTECTED`) and registry secrets. If either is non-zero and
  `!include_encrypted` → return an error naming offending paths/secret names.
- **DAG walk (post-order).** Reverse-topological walk so a commit is written only
  after its parents have Git oids. Explicit stack (not recursion) so deep history
  can't overflow — mirrors `reachable.rs`. A memo map `ObjectId → gix::ObjectId`
  ensures each object maps once and shared ancestors are reused.
- **Object writers:**
  - `blob`: `repo.write_blob(bytes)`.
  - `tree`: translate `TreeEntry`s to `gix` tree entries with Git modes
    (`FILE→100644`, `EXEC→100755`, symlink→`120000`, `Tree→40000`), **emitted in
    Git's canonical entry order** (see Correctness below), then write.
  - `commit`: root tree oid + parent commit oids + synthesized author/committer +
    message; write.
- **Ref update.** After the tip commit is written, set `opts.ref_name` to it
  (overwrite).

### `cli` — command + wiring

`sc export --to <path> [--ref <name>] [--include-encrypted]`:

1. `Repo::open(".")`; resolve `branch = refs::current_branch`, `tip = head_tip`
   (error `Unborn` if no commits).
2. Default `ref_name = "refs/heads/<branch>"` unless `--ref` given.
3. Lock the store, call `gitio::export_branch(&mut store, tip, &opts)`.
4. Print the report (commit id, count, and any ciphertext/dropped-secret summary).

`repo` is untouched — `cli` links both `repo` and `gitio` and passes the resolved
tip + store down, exactly as `run_import` calls `gitio::import_head`.

## Correctness: canonical Git tree encoding

Git orders tree entries as if a directory entry's name carries a trailing `/`
(so a file `lib` and a directory `lib` sort differently than a plain byte
compare, and `a` sorts before `a.txt` only under the file-vs-file rule). Our
`Tree::new` sorts by plain `name.cmp`. Emitting entries in the wrong order
produces a tree Git considers malformed and/or one whose oid differs from
canonical Git — silently breaking **both** idempotency and interop.

This is verified before anything builds on it (see Testing, Task 1): write a tree
with adversarial names via `gix` and assert its oid equals what the real `git`
binary produces. The implementation either sorts entries per Git's rule before
handing them to `gix`, or relies on `gix`'s tree encoder to canonicalize —
whichever the verification shows is correct for `gix` 0.85.

## Data flow

- **export:** `cli` resolves tip + branch → `gitio::export_branch` → pre-flight
  encrypted scan (refuse or proceed) → post-order DAG walk writing
  blobs/trees/commits into the Git object DB (memoized) → update the target ref →
  `ExportReport` back to `cli` for display.
- **idempotency:** deterministic object + signature mapping → identical Git oids
  on re-export; Git's content-addressed DB makes re-writing a no-op.

## Error handling

- **Refuse-on-encrypted** is a distinct, named error listing the protected paths
  / secret names, so the user knows exactly what `--include-encrypted` would
  expose. No partial Git write happens before the pre-flight scan passes.
- Target path exists but is not a Git repo → clear error (never clobber a
  non-repo directory).
- `gix` write / open failures propagate with context (`anyhow`, as `import_head`
  does); the refuse-on-encrypted case is a typed error so `cli` can message it.

## Testing

- **Task 1 (first, gating):** `gix` 0.85 write ergonomics + **canonical tree
  encoding**. Write blob/tree/commit and update a ref via `gix`; feed adversarial
  names (`lib` file beside `lib/` dir, `a` vs `a.txt`, `a.txt` vs `a`) and assert
  the emitted tree oid **equals** what the real `git` binary produces (tests may
  shell to `git`, as the import test already does). Nail the sort-order rule here.
- **Object mapping:** blob/tree/commit round-trip — build a small snapshot in our
  store, export, then `git` (or `gix`) reads back the same file contents + modes.
- **Multi-commit history:** a 3-commit chain exports to a DAG whose `git log`
  shows three commits with correct parent links and messages.
- **Idempotency:** exporting the same branch twice yields identical Git oids and
  the second run writes no new objects.
- **Round-trip:** `git` repo → `import_head` → `export_branch` to a fresh bare
  repo → re-`import_head` → the re-imported tree matches the original.
- **Encrypted policy:** a snapshot with a protected path and/or a registry secret
  → export **without** `--include-encrypted` errors (naming the content); **with**
  the flag, protected blobs appear as ciphertext, secrets are absent, and the
  report counts both.
- **Target handling:** absent `--to` path is created bare and gets the ref; an
  existing non-Git directory errors.
- **CLI:** `sc export` on an unborn branch errors; a normal export prints the
  commit id and summary. Extend `demo/run_repo_demo.sh` (or a dedicated check) to
  export a small repo and show `git log` reading it back.
