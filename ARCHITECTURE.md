# src-control — Architecture

A next-generation version control system built around a snapshot-and-tag model
(Jujutsu-inspired) with per-file permissions, native committed secrets, and
in-memory clones. This document covers the MVP architecture and the two wedges
we are proving first. The rationale behind each major decision is recorded as an
ADR in [`docs/adr/`](docs/adr/).

## Thesis and MVP scope

The long-term bet is that Git's two structural limitations — an all-or-nothing
access model and a disk-bound working copy — are increasingly expensive in a
world of autonomous coding agents. Agents want to fork many short-lived working
copies cheaply, and teams want to commit secrets into repo state without bolting
on an external vault. Git makes both painful.

The MVP does not try to replace Git. It proves two wedges that have the clearest
near-term value and builds on / interoperates with Git wherever that saves time:

- **Phase 1 — In-memory virtual worktrees (the agent wedge).** A library + CLI
  that lets an autonomous agent fork *N* parallel worktrees of a repo entirely
  in RAM, run and checkout against each, and tear them down cleanly leaving zero
  local artifacts. Includes a bounded memory budget with eviction and optional
  spill so large repos don't exhaust the heap.
- **Phase 2 — Native committed secrets.** Env vars / keys committed directly
  into repo state, encrypted at rest and in transit, decrypted only inside an
  authorized execution context through integrated key management.

Everything in Phase 1 is designed so Phase 2 drops in without re-architecting:
secrets are just a special object kind in the same content-addressed store.

## Why Rust

This is systems work with three demands that Rust serves better than the
alternatives. First, a strict **memory budget with deterministic eviction** is a
core requirement; Rust's lack of a tracing GC means the heap budget we enforce is
the heap we actually use, with no hidden retention or GC pauses skewing the
numbers. Second, the **content-addressed store** benefits from zero-copy hashing
and slicing over `Bytes`/`Arc<[u8]>` without defensive copies. Third, the
**crypto** for Phase 2 wants mature, audited primitives — the RustCrypto
ecosystem and `ring` provide AEAD (XChaCha20-Poly1305), X25519, and Argon2 with
good ergonomics. Git interop is in-process via **`gix`** (pure-Rust Git), so
there is no subprocess boundary or dependency on a system `git` binary.

Go was the main alternative and would scaffold faster with excellent concurrency,
but its GC makes a *precise* heap budget and eviction strategy materially harder
to reason about — which is exactly the property Phase 1 is meant to demonstrate.

## System overview

The codebase is a Cargo workspace of four crates with a strict dependency
direction (`cli → {vfs, gitio} → core`):

```
src-control/
├── crates/
│   ├── core/     content-addressed store, snapshot model, memory budget + eviction
│   ├── vfs/      in-memory virtual worktree engine (fork / edit / checkout / teardown)
│   ├── gitio/    Git interop boundary (import a Git repo's tree into the store via gix)
│   └── cli/      `sc` binary: import, fork agents, run, checkout, status, teardown
└── ARCHITECTURE.md
```

`core` knows nothing about Git or worktrees. `gitio` is the only crate that
links `gix`, keeping the Git dependency quarantined behind one boundary. This
matters because the long-term plan is to own the object format outright; Git is
an import/export peer, not a foundation.

## Content-addressed snapshot model

Every piece of repo state is an immutable object identified by the BLAKE3 hash of
its serialized bytes — the `ObjectId`. BLAKE3 (not SHA-1/SHA-256) because it is
fast, parallel, and tree-structured, which lines up with verified streaming and
future incremental hashing. Identical content anywhere in history is stored once.

There are four object kinds:

- **Blob** — raw file contents.
- **Tree** — a sorted directory listing mapping a name to `(kind, ObjectId,
  mode, permissions)`. The per-entry `permissions` field is unused in the MVP but
  is where the long-term per-file permission model lands, so the on-disk format
  doesn't have to change later.
- **Snapshot** — the Jujutsu-inspired analogue of a commit: a root tree id plus
  metadata (parent snapshot ids, author, timestamp, message). The distinction
  from Git is that snapshots are cheap and implicit — the working copy *is* a
  snapshot that gets amended, rather than a staging area that must be explicitly
  committed.
- **Secret** (Phase 2) — an envelope-encrypted object: ciphertext + AEAD nonce +
  wrapped data-encryption key + recipient key ids. Stored and addressed exactly
  like any other object, so it flows through fork/checkout/clone untouched and
  stays ciphertext until an authorized context decrypts it.

Objects are serialized canonically (length-prefixed, sorted tree entries) so the
hash is stable across machines.

## In-memory VFS layer

A **worktree** is a mutable view over an immutable base snapshot. Forking a
worktree allocates only a small overlay — it does not copy file content. Reads
fall through the overlay to the base tree in the store; writes land in the
overlay as copy-on-write entries. Because the base objects are shared via
`Arc`, forking *N* agents off the same snapshot is O(N) in overlay size, not in
repo size, and the heavy blob bytes are never duplicated.

Agents interact with worktrees exclusively through the library API and CLI
(`read`, `write`, `remove`, `list`, `checkout`). Content lives only in RAM and is
materialized to a real filesystem path **only** on an explicit `checkout` to a
caller-chosen directory — which the agent then owns and cleans up. There is no
FUSE mount and no kernel extension: nothing touches disk unless the caller asks
for it, which is what makes "zero residual artifacts" provable rather than
aspirational. (FUSE was considered and rejected: on macOS it needs the macFUSE
kernel extension, is fragile, and makes the zero-residue guarantee harder to
prove than a pure in-RAM model.)

Teardown drops the overlay and releases the `Arc` references; base objects
survive only as long as some live worktree or the session store references them.

## Memory budget and eviction

The store enforces a **bounded byte budget** (configurable, e.g. 512 MiB) over
blob content so a large repo or many agents cannot exhaust the heap. Accounting
is the sum of resident blob sizes; trees, snapshots, and overlay metadata are
small and tracked but rarely dominate.

Eviction is **LRU over clean, reconstructible blobs**. A blob is evictable only
if it is content-addressed (so it can be re-derived) and not pinned by a live
worktree overlay write. On a read miss for an evicted blob, the store
rehydrates it from the **spill backend**:

- **Default (no spill):** eviction is disallowed for objects with no other
  source and the store returns a typed `BudgetExceeded` error, so the caller
  fails loudly instead of silently thrashing.
- **Optional spill:** evicted blobs are written to a temporary, content-addressed
  spill directory (keyed by `ObjectId`, so writes are idempotent and verifiable
  on read-back) and dropped from RAM. This trades RAM for disk on demand. The
  spill directory is created lazily, lives under a session-scoped temp root, and
  is removed entirely on session teardown — so even *with* spill enabled the
  zero-residue guarantee holds after the session ends.

The budget is enforced at insert time: inserting a blob that would exceed the
budget triggers eviction of the coldest evictable blobs until it fits, or errors
if nothing can be freed. Dirty overlay writes are never evicted because they are
not yet reconstructible.

## Git interop boundary

`gitio` imports an existing Git repository in-process via `gix`. It walks the
commit's root tree, reads blobs and subtrees directly from the Git object
database, and inserts equivalent `Blob`/`Tree`/`Snapshot` objects into our store,
returning the root `Snapshot` id. Agents then fork in-memory worktrees off that
snapshot. No subprocess, no dependency on an installed `git`, and the boundary is
a single crate so the rest of the system stays Git-agnostic. Export (writing a
snapshot back out as a Git commit) is the symmetric operation and is left as a
post-MVP extension; import is what the agent wedge needs first.

## Key management design (Phase 2 preview)

Committed secrets use **envelope encryption**. Each secret object carries
ciphertext encrypted under a fresh per-secret data-encryption key (DEK) using
XChaCha20-Poly1305 (AEAD, large random nonce, authenticated). The DEK is then
*wrapped* (encrypted) once per authorized recipient public key (X25519). The
secret object stores the ciphertext, the AEAD nonce, and the set of wrapped DEKs
keyed by recipient key id.

The consequence is that a clone in an **unauthorized** context — one whose
private key is not among the recipients — receives the secret object intact but
cannot unwrap any DEK, so the value stays ciphertext: confidential at rest and in
transit by construction, with no separate vault. In an **authorized** context,
the runtime unwraps the DEK with its private key, decrypts the value, and injects
it into the execution environment transparently. Authorization is therefore "do
you hold a private key listed as a recipient," and granting/revoking access is
re-wrapping the DEK for a changed recipient set — a cheap metadata operation that
does not require rotating the secret itself. This is the same envelope model used
by age and cloud KMS, chosen because it is well-understood and auditable.

This is documented now because Phase 1's object store and clone path are built to
carry `Secret` objects unmodified, so Phase 2 is additive rather than a rewrite.

## Phase 1 deliverable and proof

The Phase 1 demo imports a sample repo, forks several agent worktrees in
parallel, has each agent independently edit and checkout files, runs the bounded
budget under load, then tears everything down. A filesystem snapshot taken before
and after the run is diffed to prove **zero residual files** remain on disk once
the session ends. That diff is the headline evidence for the agent wedge.
