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
- **Phase 2 — Native committed secrets (built).** Env vars / keys committed
  directly into repo state, encrypted at rest and in transit, decrypted only
  inside an authorized execution context through integrated key management.

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

The codebase is a Cargo workspace of six crates with a strict dependency
direction (`cli → repo → {vfs, gitio, crypto} → core`):

```
src-control/
├── crates/
│   ├── core/     content-addressed store, snapshot model, memory budget + eviction
│   ├── vfs/      in-memory virtual worktree engine (fork / edit / checkout / teardown)
│   ├── gitio/    Git interop boundary (import a Git repo's tree into the store via gix)
│   ├── crypto/   envelope encryption for committed secrets (scl-crypto; depends on core)
│   ├── repo/     durable on-disk repo: .sc/ layout, refs, branches, working tree
│   └── cli/      `sc` binary: the full command surface — demo/import, init/commit/status/log,
│                 branch/switch/merge, secret/run/scan, protect/grant/revoke, clone/remote/
│                 fetch/push, gc, export, escrow
└── ARCHITECTURE.md
```

`core` knows nothing about Git, worktrees, or cryptography. `gitio` is the only
crate that links `gix`, keeping the Git dependency quarantined behind one
boundary. `crypto` is the only crate that links the RustCrypto stack, keeping
the cryptographic dependency quarantined behind another. `repo` owns the
`.sc/` on-disk layout and the `init`/`commit`/`switch`/`secret` orchestration;
`cli` depends on `repo` and links `gitio` directly only for the `import`
command. This matters because the long-term plan is to own the object format
outright; Git is an import/export peer, not a foundation.

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
snapshot back out as a Git commit) is the symmetric operation, built in Phase 9;
Phase 10 composes the two into bidirectional sync with a Git repo as a
first-class remote. Both keep `gix` quarantined in `gitio`.

## Key management design (Phase 2)

Committed secrets use **envelope encryption**. Each secret object carries
ciphertext encrypted under a fresh per-secret data-encryption key (DEK) using
XChaCha20-Poly1305 (AEAD, large random nonce, authenticated). The DEK is then
*wrapped* (encrypted) once per authorized recipient public key (X25519). The
secret object stores the ciphertext, the AEAD nonce, and the set of wrapped DEKs
keyed by recipient key id.

Secrets are referenced by a side registry on each snapshot (`name -> Secret id`,
a `BTreeMap` so canonical encoding is insertion-order-independent), kept separate
from the file tree so `checkout` never materializes them. An authorized context
decrypts in memory and injects the value into a child process environment; `sc
secret-demo` proves the authorize/deny/grant flow end-to-end with the same
zero-residue teardown as Phase 1. See ADR-0010.

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

## Persistence

The third wedge adds a durable on-disk store so commits and committed secrets
survive between `sc` invocations. See ADR-0011.

### Persistent Store backend

`core::Store` gains a `Backend::Persistent(PathBuf)` variant alongside the
existing `Backend::Ephemeral`. In persistent mode every `put` writes the
canonical `Object::encode()` bytes to `.sc/objects/<hex>` (idempotent
tmp+rename) before returning, so disk is always at least as fresh as RAM. A
read-miss loads the file, verifies `BLAKE3(bytes) == id`, and decodes; a
tampered file returns `Error::Malformed`. Blob eviction drops only the RAM copy
— the durable file remains authoritative — so the existing LRU eviction logic
extends naturally.

### `.sc/` layout and `scl-repo`

The `scl-repo` crate owns everything `.sc/`-related:

- `objects/` — loose content-addressed object files (one per `ObjectId`).
- `refs/heads/<branch>` — one hex-id-per-line branch tip file, updated
  atomically.
- `HEAD` — symbolic ref (`ref: refs/heads/<branch>`), updated atomically.
- `lock` — exclusive lock file; acquired on `Repo::open`/`init`, removed on
  drop. Enforces the single-writer invariant.
- `recipients.toml` — `[recipients]` table mapping a name to its
  `scl-pk-<hex>` public key; read by `sc secret add/grant`.

### Git-like working tree

The directory beside `.sc/` is the working tree. `commit` reads every file
(skipping `.sc/`), builds a content-addressed tree, and advances the current
branch ref. `switch` materializes the target branch tip into the working tree,
removing tracked files that are absent from the target, and refuses the
operation if tracked files are modified or deleted (to prevent data loss). New,
untracked files are left in place. `status` diffs the working tree against HEAD.

### Mode-scoped disk invariant

**Ephemeral mode** (Phase 1 agents, `sc demo`, `sc secret-demo`) keeps the
zero-residue guarantee unchanged: nothing touches disk except `Worktree::checkout`
and the optional spill backend, both of which are removed after the session.

**Persistent mode** (`sc init` repos) writes to `.sc/` by design. `.sc/` is
user-owned durable state — the same relationship Git has with `.git/`. The
two modes are mutually exclusive: a session is either ephemeral or persistent,
never a mix.

### Durability & concurrency (hardened)

Every ref, loose-object, and pack write goes through one durable atomic-write
helper (`scl_core::fsutil`): write a per-process temp sibling, fsync it,
rename, fsync the parent directory — Git's crash-durability discipline.
Remote ref updates are compare-and-swap: `Transport::update_ref` revalidates
the expected old tip under the remote's own lock, so two racing pushes cannot
silently clobber each other. The single-writer lock file records the holder's
PID and is broken automatically when that process is provably dead, so a
SIGKILLed `sc` doesn't brick the repo. See ADR-0021.

## Phase 1 deliverable and proof

The Phase 1 demo imports a sample repo, forks several agent worktrees in
parallel, has each agent independently edit and checkout files, runs the bounded
budget under load, then tears everything down. A filesystem snapshot taken before
and after the run is diffed to prove **zero residual files** remain on disk once
the session ends. That diff is the headline evidence for the agent wedge.

## Phase 8 — packfiles, GC, and bulk-pack transfer (built)

Phase 8 adds three tightly coupled capabilities to the persistent store:

- **Sharded + zstd loose objects.** Loose objects moved from `objects/<hex>` to
  `objects/<aa>/<rest>` (first two hex chars as a shard prefix) and their payloads
  are zstd-compressed on disk. The canonical bytes are decompressed and
  BLAKE3-verified on every read, so the content-addressing invariant is unchanged.
  Legacy flat/uncompressed objects are still read (read-both, write-new).
- **Packfile format.** `objects/pack/<hash>.pack` + `.idx` bundle many objects
  into a single file. Each pack record is `[id:32][compressed_len:4][zstd(canonical)]`;
  the `.idx` maps `ObjectId → (offset, length)`. The store gains a pack-aware read
  path: loose objects are checked first, then pack indexes. Writing is always loose;
  packing is a batch GC operation.
- **`sc gc`.** Computes the reachable object set by walking from all refs (branch
  tips, HEAD, all `refs/remotes/*` remote-tracking refs, and `MERGE_HEAD` when a
  merge is in progress) through snapshots → trees → blobs/secrets/protected objects.
  Reachable objects are written into a new packfile; unreachable loose objects older
  than the grace window (default 24 h, `--prune-expire <dur>`) are deleted. Packed
  unreachable objects are dropped immediately (they survived a prior GC cycle).
  Deletions happen only after the new pack is durably written. GC is persistent-only
  and runs under the single-writer repo lock.
- **Bulk-pack transfer.** `push` builds a single pack of objects the remote lacks
  and ships it via `put_pack`; `clone`/`fetch` use `get_pack(wants, haves)`. The
  transport read path resolves packed, sharded, and compressed objects from the
  remote store. This replaces the prior object-at-a-time transfer.

Remaining follow-ons: network Git remotes, HTTP transport, streaming (>4 GiB)
frames, bulk re-wrap, and multiple escrow keys (merge shipped as Phase 4;
break-glass escrow shipped as Phase 11; ssh-native network transport shipped
as Phase 12).

## Phase 9 — Git export (built)

`sc export --to <git-repo> [--ref <name>] [--include-encrypted]` is the symmetric
peer of the Phase 1 Git import: it maps src-control objects to Git objects and
writes them into a target Git repository via `gix`, keeping all Git logic
quarantined in `gitio`.

### Object mapping

| src-control | Git |
|---|---|
| `Blob` | Git blob |
| `Tree` | Git tree (entries sorted in Git's byte order) |
| `Snapshot` | Git commit (root tree + parents + author/message) |

The full history of the current branch is walked and written. Identical content
maps to identical Git objects, so re-export is **idempotent**.

### Deterministic signature synthesis

`Snapshot` author strings are parsed as `Name <email>` (with fallback to name-only
+ empty email). The committer is set equal to the author. The timezone is always
`+0000`. This makes the Git commit hash stable across re-exports of the same
src-control history.

### Encrypted-content policy (fail-closed)

Export **refuses** if the history contains protected paths or registry secrets
unless `--include-encrypted` is passed:

- **Protected files** export as their **ciphertext blobs** — nothing plaintext
  escapes into the Git repo.
- **Registry secrets** are **dropped** — Git has no secrets-registry equivalent,
  so there is no safe representation; silently omitting them is the least-surprise
  behaviour.

### Target ref and HEAD

The target ref is **overwritten** (mirror semantics). If `--to` does not exist,
it is created with `git init --bare`. On a newly-created repo, `HEAD` is pointed
at the exported ref so tools that resolve `HEAD` (including `git log`) work
without additional configuration. Pre-existing repos have their ref force-updated;
`HEAD` is not touched.

### Lossy points

Git trees cannot carry the following src-control metadata; it is dropped on export:

- The **secrets registry** (`BTreeMap<String, ObjectId>` on each snapshot).
- The **protection policy** (wrapped DEKs for encrypted paths).
- The **per-entry `perms` byte** on tree entries.

These are the documented lossy points (see ADR-0016). Phase 10's bidirectional
sync inherits them: the Git side of a git-backed remote never carries the
secrets registry, protection policy, or perms byte — a sidecar or
extended-attribute convention to preserve them remains out of scope.

Note: the fail-closed scan keys on the per-entry `PROTECTED` bit, so content
committed as plaintext *before* a path was protected remains plaintext in history
and is neither flagged nor refused by `--include-encrypted`. This is the same
forward-looking model as git-crypt; export refusal is not a blanket guarantee of
"no plaintext anywhere in history".

## Phase 10 — Git as a remote (built)

A local Git repository is a first-class remote. `sc remote add <name>
<git-path> --git` registers it; `sc fetch <git-remote>` imports the full Git
history deterministically and writes a `refs/remotes/<name>/<branch>`
remote-tracking ref; `sc push <git-remote> [--include-encrypted]`
synthesizes (or reuses) Git commits for the current branch and
fast-forward-updates the Git ref, reusing Phase 9's export machinery and
confidentiality gate verbatim.

Identity across the two DAGs is carried by a persisted `git_oid ↔ sc_id`
**marks map** (`.sc/git-remotes/<name>/marks`), not by a fatter object model —
the content-addressing invariant is unchanged. The git-remote path dispatches
in `cli` *above* the Phase 6 `Transport` trait rather than implementing it: a
Git remote has a different id space and encoding than `Transport` assumes, and
routing through `cli` keeps `repo` free of any `gitio` dependency.

Scope is local `.git` paths on disk; network Git is a later transport swap
onto the same translation core. One accepted MVP limitation: fetching from Git
repo A and pushing a Git-origin commit to a *different* Git repo B
re-synthesizes with dropped committer/timezone/gpgsig and a different Git oid
than A had — same-remote fetch/push stays clean. See ADR-0018.

## Phase 11 — secret/permission lifecycle: rotation + escrow (built)

`sc secret rotate <name> [--value <new>] [--to <names>] [--identity <key>]`
re-seals a secret's value under a **fresh DEK**, composed entirely from the
existing `seal`/`open` primitives (`crates/crypto` is unchanged). With
`--value`, the new plaintext is sealed directly; without it, the current value
is recovered via `--identity` and re-sealed. Recipients default to the
secret's current set (reverse `recipient_id` lookup against
`.sc/recipients.toml`), overridable with `--to`.

Rotation is **secrets-only**: protected paths use convergent encryption
(`DEK = HKDF(BLAKE3(plaintext))`), so a recipient who checked the file out can
re-derive the key — "rotating" a path's DEK is either dedup-breaking or
security-meaningless. Path lifecycle stays on recipient re-wrap
(`grant`/`revoke`). `sc secret revoke` remains metadata-only and now hints to
run `rotate` for the actual cryptographic cutover.

`sc escrow set <pubkey-or-name>` / `sc escrow show` configure a single
break-glass recipient key (`[escrow]` in `.sc/recipients.toml`) that is
auto-appended (deduped) whenever `secret add`, `secret rotate`, or `protect`
seals or wraps — forward-only (existing secrets/paths gain escrow when next
rotated/re-wrapped) and policy, not enforcement.

**Rotation ≠ erasure:** content-addressed history keeps the old ciphertext
object reachable, and anyone who kept the old DEK can still decrypt it.
Rotation cuts off *future* reads through the current registry; real security
requires rotating the underlying external credential too. See ADR-0019.

## Phase 12 — Network transport over SSH (built)

`sc clone / fetch / push` work against `ssh://[user@]host[:port]/path`
remotes. The wire protocol mirrors the 8 `Transport` verbs over length-
prefixed frames with a version handshake; the server (`sc serve --stdio`) is
a dispatch loop around `LocalTransport`, so CAS ref updates and pack
verification apply verbatim server-side. The client spawns the user's `ssh`
(overridable via `SC_SSH`, Git's `GIT_SSH` pattern — the demo and tests drive
the full ssh:// path through a local shim, no sshd needed). Typed errors
(`NonFastForward`, `NotARepo`) survive the wire; an interrupted push leaves
at worst unreachable objects, never a torn ref. Confidentiality is unchanged
by construction: objects travel as canonical bytes, ciphertext stays
ciphertext. See ADR-0022.
