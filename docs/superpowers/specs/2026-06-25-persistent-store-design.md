# Persistent store + native repo: design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-06-25
- **Builds on:** Phase 1 (in-memory worktrees) and Phase 2 (committed secrets)

## Goal

Give src-control a durable on-disk repository so work survives across separate
`sc` invocations. A `.sc/` directory at a repo root holds content-addressed
objects, named branches, and HEAD; the files beside it are a git-like working
tree. This delivers the deferred Phase 2 follow-on — `sc secret add` in one
invocation and `sc run` in a later one — and generalizes it into a usable native
VCS: `init`, `commit`, `status`, `log`, `branch`, `switch`, plus the secrets
workflow.

The headline property to prove: **state persists across a full process boundary
— commit/secret-add in one process, reopen in another, and the objects, refs,
and secrets are all there.**

## Decisions (locked during brainstorming)

1. **Scope:** persistent repo with **named branches**. Commands: `init`,
   `commit`, `status`, `log`, `branch`, `switch`, and the secrets workflow
   (`secret add/grant/revoke/list`, `run`). **Merge is out of scope** this round.
2. **Object format:** loose content-addressed files at `.sc/objects/<hex>`, whose
   contents are exactly the canonical `Object::encode()` bytes (so
   `BLAKE3(contents) == filename`). Reuses the existing encoding and `ObjectId`.
3. **Durability:** **write-through on every `Store::put`** in persistent mode;
   refs are updated atomically at commit boundaries.
4. **Working tree:** git-like. `.sc/` sits at a repo root; the files beside it are
   the working tree. `commit` snapshots the working tree; `switch`/`checkout`
   materializes a branch tip into it; `status` diffs the working tree vs HEAD.

## Out of scope (this round)

- **Merge / rebase / conflict resolution.** Branches can be created, switched,
  committed onto, and listed, but not merged.
- **fsync/durability tuning** beyond atomic renames (noted as a follow-on).
- **Remotes / push / fetch / clone over a network.** Local repo only.
- **Packfiles / compaction.** Loose objects only; packing is a later optimization.
- **Multi-writer concurrency** beyond a single-writer lock file.

## Architecture

### Crate structure

A new crate **`scl-repo`** owns the on-disk repository: directory layout,
refs/HEAD/branches, working-tree snapshot & materialize, and command
orchestration. Object byte-IO stays in `core` (which already performs spill IO).
The dependency direction extends to:

```
cli → repo → {vfs, gitio, crypto} → core
```

`scl-repo` depends on `core` (objects/store), `vfs` (tree building, checkout
machinery), and `crypto` (secrets). `core` still depends on nothing of ours;
`gix` stays in `gitio`; RustCrypto stays in `crypto`.

### `.sc/` directory layout

```
.sc/
  objects/<64-hex>      # = Object::encode() bytes; BLAKE3(contents) == filename
  refs/heads/<branch>   # text file: 64-hex snapshot id
  HEAD                  # text file: "ref: refs/heads/<branch>" (symbolic)
  lock                  # presence = a writer holds the repo (single-writer)
```

Legible and git-like on purpose. A snapshot id in a ref is the durable entry
point; objects are reachable from it by content address.

## Components

### 1. `core::Store` — two backend modes

`Store` gains a durable backend alongside the existing ephemeral one. Model it as
a `Backend` on `StoreConfig`:

```rust
enum Backend {
    /// Phase 1 behavior: RAM + optional ephemeral spill, removed on Drop.
    Ephemeral(SpillPolicy),
    /// Durable: RAM + write-through to a `.sc/objects/` directory.
    Persistent(PathBuf),
}
```

- **Ephemeral** (unchanged): RAM + optional `SpillTo(session_tmp)`; `Drop` removes
  the spill dir; zero-residue. Used by `sc demo` and parallel agents.
- **Persistent:**
  - `put(obj)` writes through: serialize `obj.encode()` to
    `objects/<hex>.tmp` then `rename` to `objects/<hex>` (idempotent; skip if the
    final path already exists). Applies to **all** object kinds — trees,
    snapshots, and secrets must survive restart, not just blobs.
  - A read-miss loads from `objects/<hex>`: read bytes, **verify
    `ObjectId::of(bytes) == id`** (else `CorruptObject`), `Object::decode`, admit
    to RAM (subject to the budget).
  - Blob **eviction drops the RAM copy only**; the durable file is authoritative,
    so eviction never loses data and never needs ephemeral spill in this mode.
  - `Drop` does **not** delete `objects/`.

The budget/eviction machinery is reused unchanged; only the miss/evict/drop edges
differ between backends.

### 2. `scl-repo` — refs, HEAD, working tree, commands

**Refs & HEAD.** `HEAD` is symbolic, naming a branch under `refs/heads/`; the
branch file holds the tip snapshot id. Ref writes are atomic (write `*.tmp` +
`rename`). A `.sc/lock` file is created when a repo is opened for writing and
removed on drop; a present lock yields `Error::Locked` with guidance to remove a
stale lock.

**Working tree.** The repo root is the directory containing `.sc/`.
- `snapshot_worktree() -> ObjectId` walks the working-tree files (skipping `.sc/`
  itself), builds blobs/trees via the existing `vfs` tree-builder, and returns the
  root tree id.
- `materialize(snapshot)` writes a snapshot's file tree into the working dir,
  reusing `Worktree::checkout` semantics. This is a deliberate persistent write,
  distinct from the ephemeral agent checkout.

**Command operations** (the CLI is a thin shell over these):
- `init` — create `.sc/objects`, `.sc/refs/heads`, write `HEAD` →
  `refs/heads/main`; `main` starts unborn (no ref file until first commit).
- `commit(message)` — `snapshot_worktree()` → build a `Snapshot { root, parents:
  [current tip], secrets: <carried from current tip>, author, message }` →
  `put` (write-through) → atomically update the current branch ref to the new id.
- `status()` — diff the working-tree tree against the HEAD tip's root tree;
  report added / modified / deleted paths.
- `log()` — walk `parents` from the HEAD tip, printing id/author/message.
- `branch(name)` — create `refs/heads/<name>` pointing at the current tip.
- `switch(name)` — repoint `HEAD` to `refs/heads/<name>` and `materialize` that
  tip into the working dir.
- `secret add/grant/revoke/list` — read the HEAD tip snapshot, modify its
  `secrets` `BTreeMap` registry (seal/rewrap/remove via `scl-crypto`), produce a
  new snapshot onto the branch (so secret changes are versioned commits), update
  the ref.
- `run(cmd, identity)` — read HEAD's registry; for each secret, attempt
  `scl-crypto::open` with the resolved identity. Secrets the identity **can**
  decrypt are injected into the child process environment; secrets it **cannot**
  (it is not a recipient) are **skipped with a stderr warning**, not a hard error
  — a repo may hold secrets wrapped for several recipients and a given runner only
  needs its own. (A `CorruptObject`/tamper error, by contrast, does fail.) Then
  spawn `cmd`. Plaintext stays in memory only, never written to disk.

Secrets reuse the Phase 2 `scl-crypto` primitives and the `BTreeMap<String,
ObjectId>` registry already on `Snapshot`. Identity/recipients resolution reuses
the Phase 2 CLI helpers (`resolve_identity_path`, `load_recipients`) — which were
built as scaffolding for exactly this.

### 3. CLI surface (`scl-cli`)

New subcommands wire to `scl-repo`: `sc init`, `sc commit -m`, `sc status`,
`sc log`, `sc branch <name>`, `sc switch <name>`, `sc secret add <name> --to ...`,
`sc secret grant <name> --to ...`, `sc secret revoke <name> --from ...`,
`sc secret list`, `sc run -- <cmd>`. The Phase 1 `sc demo` and Phase 2
`sc secret-demo` (ephemeral, RAM-only) are unchanged.

## Invariant revision (CLAUDE.md)

The current invariant "disk is touched only by `Worktree::checkout` / ephemeral
spill" becomes **mode-scoped**:

- **Ephemeral mode** (agents, `sc demo`, `sc secret-demo`): unchanged. Disk is
  touched only by an explicit `checkout` and the optional session-temp spill,
  which is removed on teardown — the **zero-residue guarantee holds and is still
  proven by `sc demo`**.
- **Persistent mode** (`sc init` repos): the durable backend writes objects to
  `.sc/objects/` on every `put` by design, and the working-tree commands read and
  write the working directory. The `.sc/` directory is **user-owned durable
  state** (like `.git`), explicitly outside the zero-residue claim.

Both modes are stated plainly so the guarantees do not blur.

## Crash-safety (MVP-pragmatic)

- Object files are content-addressed and idempotent: write `objects/<hex>.tmp`
  then `rename` (atomic on the same filesystem); skip if the final path exists. A
  half-written `.tmp` is never named as a valid object, and any corruption is
  caught by the read-time `BLAKE3` verify (`CorruptObject`).
- Ref updates are temp-write + `rename`.
- **Objects are written before the ref that points at them**, so a crash leaves
  unreferenced objects (harmless, garbage-collectable later) rather than a
  dangling ref.
- `.sc/lock` enforces single-writer per invocation.
- No fsync tuning this round (follow-on).

## Error handling

New `scl-repo::Error` (thiserror): `NotARepo`, `RepoExists`, `Locked`,
`CorruptObject { id }`, `BadRef`, plus `#[from]` conversions for
`scl_core::Error`, `scl_vfs::Error`, `scl_crypto::Error`, and `std::io::Error`.
The CLI absorbs these via `anyhow`/`?`.

## Testing

- **`core` persistent backend:** put in persistent mode → drop the `Store` →
  reopen on the same dir → `get` returns the object (all kinds: blob, tree,
  snapshot, secret). Corrupt an object file on disk → read returns
  `CorruptObject`. Eviction drops RAM but a later `get` rehydrates from disk.
- **`scl-repo` refs/working-tree:** `init` then `commit` then reopen → `log`
  shows the snapshot; `branch` + `switch` repoints HEAD and materializes files;
  `status` detects add / modify / delete against HEAD; the lock blocks a second
  concurrent writer.
- **Headline cross-invocation proof:** `secret add` in one `Store`/repo instance,
  drop it, reopen on the same `.sc/`, and `run`/decrypt succeeds with the
  authorized identity — proving secrets persist across a process boundary.
- **End-to-end CLI script** (à la `demo/run_demo.sh`): `init` → write files →
  `commit` → `branch` → `switch` → `secret add` → `run`, asserting expected
  output and that `.sc/` contains the expected objects/refs.

Every new behavior ships with a test, per project convention.

## Documentation updates

- Add **ADR-0011**: persistent loose-object store + git-like working tree
  (records the loose-objects format choice, write-through durability, the
  ephemeral-vs-persistent `Store` backend split, and the mode-scoped invariant).
- Update `ARCHITECTURE.md` (new persistent mode, `.sc/` layout, `scl-repo` crate,
  working-tree model) and `CLAUDE.md` (crate list + dependency rule with `repo`;
  the mode-scoped disk invariant; new commands).

## Open follow-ons (not this round)

- Merge / rebase / conflict resolution across branches.
- Packfiles + `gc` for loose-object compaction.
- fsync durability tuning and crash-recovery hardening.
- Remotes (push/fetch/clone) and Git export.
- `.scignore` beyond the implicit `.sc/` skip.
