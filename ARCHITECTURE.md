# src-control — Architecture

A next-generation version control system built around a snapshot-and-tag model
(Jujutsu-inspired) with per-file permissions, native committed secrets, and
in-memory clones. This document covers the architecture as built — the two
founding wedges and the full collaborative VCS grown around them across 30
vertical-slice phases. The rationale behind each major decision is recorded as an
ADR in [`docs/adr/`](docs/adr/), and a compact per-phase appendix closes this doc.

## Thesis and MVP scope

The long-term bet is that Git's two structural limitations — an all-or-nothing
access model and a disk-bound working copy — are increasingly expensive in a
world of autonomous coding agents. Agents want to fork many short-lived working
copies cheaply, and teams want to commit secrets into repo state without bolting
on an external vault. Git makes both painful.

The project does not try to replace Git. It began by proving two wedges with the
clearest near-term value, and has since grown — one vertical-slice phase at a
time — into a full persistent, branchable, content-addressed VCS that builds on
and interoperates with Git wherever that saves time. The two founding wedges:

- **Phase 1 — In-memory virtual worktrees (the agent wedge).** A library + CLI
  that lets an autonomous agent fork *N* parallel worktrees of a repo entirely
  in RAM, run and checkout against each, and tear them down cleanly leaving zero
  local artifacts. Includes a bounded memory budget with eviction and optional
  spill so large repos don't exhaust the heap.
- **Phase 2 — Native committed secrets.** Env vars / keys committed directly into
  repo state, encrypted at rest and in transit, decrypted only inside an
  authorized execution context through integrated key management.

Everything in Phase 1 was designed so Phase 2 dropped in without re-architecting:
secrets are just a special object kind in the same content-addressed store. That
composability held across every phase since. **All three long-term-thesis pillars
now ship** — in-RAM worktrees (P1), committed secrets (P2), and per-file
permissions (P7, encrypted paths) — atop a full collaborative VCS: three-way
merge and history editing, packfiles + GC, ssh:// / sc+http:// / Git network
transports, sparse and partial clone, signed commits, and intent-deep provenance
via sealed agent-session transcripts. The phase-by-phase build log is in
[`ROADMAP.md`](ROADMAP.md) and [`CLAUDE.md`](CLAUDE.md); the sections below cover
the architecture, with a compact per-phase appendix at the end.

## Why Rust

This is systems work with three demands that Rust serves better than the
alternatives. First, a strict **memory budget with deterministic eviction** is a
core requirement; Rust's lack of a tracing GC means the heap budget we enforce is
the heap we actually use, with no hidden retention or GC pauses skewing the
numbers. Second, the **content-addressed store** benefits from zero-copy hashing
and slicing over `Bytes`/`Arc<[u8]>` without defensive copies. Third, the
**crypto** wants mature, audited primitives — the RustCrypto ecosystem provides
AEAD (XChaCha20-Poly1305), X25519 ECDH, HKDF-SHA256, and Ed25519 with good
ergonomics, all pure-Rust. Git interop is in-process via **`gix`** (pure-Rust
Git), so there is no subprocess boundary or dependency on a system `git` binary
(the P18 hosted-Git bridge is the one exception, spawning system `git` only
because `gix` cannot push).

Go was the main alternative and would scaffold faster with excellent concurrency,
but its GC makes a *precise* heap budget and eviction strategy materially harder
to reason about — which is exactly the property Phase 1 is meant to demonstrate.

## System overview

The codebase is a Cargo workspace of six crates with a strict dependency
direction (`cli → repo → {vfs, gitio, crypto} → core`):

```
src-control/
├── crates/
│   ├── core/     content-addressed store (loose + packfiles), object model, memory
│   │             budget + eviction, streaming pack build/parse
│   ├── vfs/      in-memory copy-on-write worktree engine (fork / edit / checkout / teardown)
│   ├── gitio/    Git interop: import a repo's HEAD + export history back to Git via gix,
│   │             plus a system-git mirror bridge for hosted Git (the only crate linking gix)
│   ├── crypto/   envelope encryption (secrets + protected paths) AND Ed25519 signing +
│   │             v2 dual-key identities (scl-crypto; the only crate linking RustCrypto)
│   ├── repo/     durable .sc/ repo: refs/branches/working tree, three-way merge, history
│   │             editing (cherry-pick/rebase/amend/undo), remotes + wire transport (ssh://,
│   │             sc+http://), protection + secret lifecycle, GC, sparse & partial clone,
│   │             signatures & session transcripts, agent workspaces
│   └── cli/      `sc` binary — the full ~42-command surface (see CLAUDE.md)
└── ARCHITECTURE.md
```

`core` knows nothing about Git, worktrees, or cryptography. `gitio` is the only
crate that links `gix`, keeping the Git dependency quarantined behind one
boundary. `crypto` is the only crate that links the RustCrypto stack, keeping
the cryptographic dependency quarantined behind another. `repo` owns the `.sc/`
on-disk layout and all repo orchestration; it is deliberately **Git-agnostic**
(it never links `gitio`) — `cli` links both `repo` and `gitio` and passes
imported snapshots down. This matters because the long-term plan is to own the
object format outright; Git is an import/export peer, not a foundation.

## Content-addressed snapshot model

Every piece of repo state is an immutable object identified by the BLAKE3 hash of
its serialized bytes — the `ObjectId`. BLAKE3 (not SHA-1/SHA-256) because it is
fast, parallel, and tree-structured, which lines up with verified streaming and
future incremental hashing. Identical content anywhere in history is stored once.

There are six object kinds (the leading byte of the canonical encoding tags the
kind: blob 0, tree 1, secret 3, snapshot 4, signature 5, transcript 6; tag 2 is
a retired pre-P16 snapshot encoding, refused with a clear error):

- **Blob** — raw file contents.
- **Tree** — a sorted directory listing mapping a name to `(kind, ObjectId,
  mode, permissions)`. The per-entry `permissions` byte carries the `PROTECTED`
  bit (P7): a protected entry's blob is encrypted ciphertext — convergent for
  pre-P33 seals, randomized (a companion `RANDOMIZED` bit, P33/ADR-0043) for
  new ones — and the bit is what makes "protected" and "ciphertext" synonymous
  in every tree.
- **Snapshot** — the Jujutsu-inspired analogue of a commit: a root tree id plus
  metadata (parent snapshot ids, author, timestamp, message), a `secrets`
  side-registry (name → secret-object id, so secrets are env vars, not files),
  and a `protection` registry (per-prefix recipient rules as last-writer-wins
  epoch registers, plus the per-blob wrapped-DEK map). The distinction from Git
  is that snapshots are cheap and implicit — the working copy *is* a snapshot
  that gets amended, rather than a staging area that must be explicitly committed.
- **Secret** — an envelope-encrypted object: ciphertext + AEAD nonce + wrapped
  data-encryption key + recipient ids. Stored and addressed exactly like any
  other object, so it flows through fork/checkout/clone untouched and stays
  ciphertext until an authorized context decrypts it.
- **Signature** (P22) — a bytes-only object over a domain-separated snapshot id
  (`Ed25519`), indexed on the side (`.sc/signatures`); the crypto stays
  quarantined in `crates/crypto`, so `core` sees only opaque bytes.
- **Transcript** (P30) — a sealed agent-session record attached to the snapshot
  it motivated: the same envelope shape as a `Secret` (fresh DEK wrapped per
  recipient) plus `{snapshot, agent, session}` metadata, so the plaintext session
  never enters the store. Indexed on the side (`.sc/transcripts`), optionally
  signed under its own domain.

Objects are serialized canonically (length-prefixed, sorted tree entries) so the
hash is stable across machines. Every decode length prefix is bounded by a
`MAX_OBJECT_SIZE` / remaining-bytes guard (P28) so a hostile object can't drive
an unbounded allocation.

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
Phase 10 composes the two into bidirectional sync with a *local* Git repo as a
first-class remote, and Phase 18 reaches *hosted* Git (GitHub over https/ssh)
through a spawned-system-`git` mirror bridge (`gix` can fetch but not push, so a
lazily-built bare `mirror.git` beside the marks map is the transport). All of it
keeps `gix` quarantined in `gitio`. This is distinct from sc's **own** network
transport: `repo` speaks a framed wire protocol over ssh:// (P12) and sc+http://
(P26) that mirrors its `Transport` trait — no `gix` involved (see the appendix).

## Cryptography and key management

All cryptography is quarantined in `crates/crypto`; `core` and `repo` see only
opaque bytes. The crate owns three surfaces, all built on the RustCrypto stack:
**envelope encryption** (secrets, below), **encryption for protected paths**
(randomized DEK/nonce for new content since P33, convergent dual-read for
pre-P33 history — see below), and **Ed25519 signing** for provenance.

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

**Protected paths (P7)** encrypt designated file *content* rather than named
env-var secrets. As of **P33 (ADR-0043)** all new protected content is sealed
under a **fresh random DEK + random nonce** (`RANDOMIZED` perms bit alongside
`PROTECTED`), so two seals of the same plaintext yield different ciphertext ids
— closing the convergent equality-confirmation oracle for everything sealed
from P33 on. The store is **dual-read, randomized-write**: pre-P33 *convergent*
ciphertext (DEK/nonce derived from `BLAKE3(plaintext)`) still decrypts through
the unchanged `decrypt_path`, so no snapshot-tag bump and no forced migration —
a pre-P33 store reads byte-for-byte identically. Commit's per-path rule is
**format-dispatched** on the prior tip entry (convergent → re-encrypt-and-
compare, carry-if-unchanged; randomized → keyed-PRF stat cache under a never-
committed `.sc/local-key`; new → seal randomized), so unchanged convergent
content stays convergent until an edit or an explicit `sc rewrap` upgrades it.
An unauthorized clone still gets ciphertext it cannot read; the `sc protect` CLI
still nudges genuine low-entropy secrets toward `sc secret` (P28). Per-prefix
recipient rules are last-writer-wins epoch registers so a revoke is durable
across merges (P16). `sc grant`/`revoke` manage the recipient set without
touching ciphertext; **`sc rewrap` now eagerly re-seals still-convergent blobs
randomized** as it re-wraps the tip — so a rewrap that upgrades content is no
longer tree-identical (a convergent→randomized reseal changes the blob id),
though a second rewrap over an all-randomized tip converges back to policy-only.
See ADR-0014/0026/0043.

**Lifecycle (P11/P17):** `sc secret rotate` re-seals a secret under a fresh DEK
(the real cryptographic cutover, distinct from metadata-only revoke); `sc escrow`
maintains break-glass recovery keys auto-included at seal time; `sc rewrap` is a
one-commit bulk cutover of every secret and protected blob to the current
recipient/escrow set. See ADR-0019/0027.

**Provenance (P22):** `sc keygen` emits a **v2 identity** — one random seed,
HKDF-derived into *both* an X25519 encryption key and an Ed25519 signing key,
written as a single `scl-id-<hex>` file (a pre-P22 v1 `scl-sk-` identity still
parses and encrypts but cannot sign). Signatures are bytes-only CAS objects over
a domain-separated snapshot id, indexed in `.sc/signatures`; `sc verify` walks
history and reports a four-state status (trusted ✓ / untrusted ? / invalid ✗ /
unsigned). Session transcripts (P30) reuse the same signing machinery under a
distinct domain. Signing binds identity to a *snapshot id*, detecting history
rewrites in clones and remotes. See ADR-0032.

## Persistence

Persistence (Phase 3) adds a durable on-disk store so commits and committed
secrets survive between `sc` invocations — the foundation every collaborative
phase after it builds on. See ADR-0011.

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

The `scl-repo` crate owns everything `.sc/`-related. The layout grew with the
phases but the shape is stable:

- `objects/` — content-addressed object storage: sharded/zstd loose files
  (`<aa>/<rest>`) plus `objects/pack/<hash>.pack` + `.idx` packfiles (P8).
- `refs/heads/<branch>` — one hex-id-per-line branch tip, updated atomically.
  `refs/remotes/<remote>/<branch>` — remote-tracking refs (P6).
- `HEAD` — symbolic ref (`ref: refs/heads/<branch>`), updated atomically.
- `lock` — exclusive lock file; acquired on `Repo::open`/`init`, removed on
  drop. Enforces the single-writer invariant.
- `config` — remote definitions (`sc remote add`), TOML.
- `recipients.toml` — `[recipients]` (name → `scl-pk-<hex>` encryption key),
  `[escrow]` break-glass keys (P11/P17), and `[signing]`/`[signers]` (P22).
- `scanner-allowlist.toml` — hash-scoped allowlist for the commit-time secret
  scanner (P5).
- `oplog` — append-only operation log; every ref-moving op records before/after
  so `sc undo`/redo can invert it (P14). Local-only, like a reflog.
- `signatures` — snapshot→signature-object index (P22); `transcripts` —
  snapshot→transcript-object index, one-to-many (P30). Both gc-rooted, local-only.
- `sparse` — the local, uncommitted sparse-checkout prefix spec (P24);
  `promisor` — a partial clone's fetch-filter + origin (P27).
- `serve-tokens.toml` — bearer-token access control for `sc serve --http` (P29).
- `tmp/` — guard-cleaned scratch for streaming pack transfer (P25).
- `ws/` — durable agent-session workspaces: `session.toml` manifest + per-agent
  checkouts (P20). `git-remotes/<name>/` — the `git_oid ↔ sc_id` marks map and a
  lazily-built bare `mirror.git` for network Git (P10/P18).
- Transient in-progress state (removed on completion/abort): `MERGE_HEAD`,
  `PICK_HEAD`, `REBASE_STATE`, and their `*_DECIDED_ROOT` records — an
  interrupted merge/pick/rebase resumes or aborts cleanly from these.

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
user-owned durable state — the same relationship Git has with `.git/`. The two
modes compose in exactly one way: a `sc work`/`sc ws` agent session (P13/P20) is
a bounded ephemeral session *hosted by* a persistent repo — temp checkouts are
removed on teardown and the only durable writes go through the same commit path
persistent mode already owns. Otherwise a session is either ephemeral or
persistent, never a mix.

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
frames, bulk re-wrap, multiple escrow keys, interactive workspace sessions
and auto-merge of clean workspace results (merge shipped as Phase 4;
break-glass escrow shipped as Phase 11; ssh-native network transport shipped
as Phase 12; agent workspaces shipped as Phase 13).

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

Rotation is **secrets-only**: pre-P33 protected paths used convergent
encryption (`DEK = HKDF(BLAKE3(plaintext))`), so a recipient who checked the
file out could re-derive the key — "rotating" a convergent path's DEK is either
dedup-breaking or security-meaningless. Path lifecycle stays on recipient
re-wrap (`grant`/`revoke`). `sc secret revoke` remains metadata-only and now
hints to run `rotate` for the actual cryptographic cutover. (**P33/ADR-0043:**
the security-meaningless objection dissolves for **randomized** content — a
random DEK is independent of the plaintext — so a genuine rotate-for-paths
cutover is now coherent and recorded as an unlocked follow-on, not yet built.)

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

## Phase 13 — agent workspaces (built)

`sc work` is the fusion of Phase 1 and Phase 3: the session engine
(`crates/repo/src/workspace.rs`) forks N vfs worktrees from HEAD *inside the
repo's own budget-bounded persistent store*, so all forks share one Arc'd
blob cache and eviction never needs a spill backend — `.sc/objects` is the
reconstruction source. Checkout reuses the P7-aware `materialize`; harvest
reuses the commit pipeline (`snapshot_files`, extracted from `commit`), so
the P5 scanner and `.scignore` gate agent output exactly like a human
commit. Each changed workspace becomes a flat `work-<i>` branch (the ref
grammar reserves `/` for remote-tracking refs); merge is the ordinary P4
path. The session holds the single-writer lock end to end, and teardown is
Drop-guarded: zero residue outside `.sc/` on success, error, or panic.

## Phase 14 — history editing (built)

Replay is merge: cherry-picking commit C onto tip T, or replaying a branch
commit-by-commit during rebase, is diff3(base = the commit's first parent,
ours = the current tip, theirs = the commit), computed by P4's existing
`three_way_files` (extracted from `three_way`) — no second merge engine, no
object mutation, and protected content is refused up front, inheriting P4's
fail-closed guard verbatim → lifted in P15 (ADR-0025). `sc cherry-pick` resolves like `merge`: a clean
replay advances the branch with a single-parent snapshot; a conflict writes
P4-style markers plus `.sc/PICK_HEAD`, and the next `sc commit` completes it.
`sc rebase` is atomic instead: a merge commit anywhere in the replayed range
refuses the whole operation before a single commit replays, and the first
conflict aborts wholesale with refs and the working tree untouched — unlike
cherry-pick's per-commit resolve flow. Both follow the same crash discipline
as `merge`: build the snapshot in the CAS, materialize the working tree,
*then* move the branch ref — the ref update is the atomic commit point, so a
crash in that window leaves a post-operation working tree paired with a
pre-operation tip (status reads dirty; no ref damage), not a consistently
pre-operation state.

A single append-only `.sc/oplog` gives every ref-moving operation (commits,
merges, cherry-picks, rebases, switches, secret/protect ops, `sc work`
sessions) an undo record: HEAD and every touched ref's before/after value.
`sc undo` restores the last record's before-state and appends its own
inverse record — refs are written first, the oplog record last, so a crash
between the two loses an undo entry but never fabricates one, and a torn
tail from a prior crash is healed (truncated) before the next append. Undo
of undo is redo. `sc gc` treats oplog-referenced snapshot ids as reachability
roots and trims records past the prune-expire window, always keeping the
newest, so the root set stays bounded. Undoing the repo's initial commit is
refused (there is no working tree to materialize back to) — a deliberate
scope cut rather than a half-built rewind. The oplog is local-only, like a
reflog: it is never copied by clone and never travels over a transport. See
ADR-0024.

## Phase 15 — protected merge & replay (built)

Every merge/rebase/cherry-pick used to fail closed on protected content —
**lifted in P15 (ADR-0025)**. The key observation is that P7's path encryption is
**convergent** (equal plaintext ⇒ equal ciphertext blob id), so most
three-way cases resolve on ciphertext ids alone: unchanged, one-side-changed,
and clean-delete protected paths merge with no identity at all, carrying
ciphertext blobs plus a union of wrapped DEKs. Only a **content-divergent**
protected path — both sides edited the plaintext — needs an authorized
`--identity` (**→ P33/ADR-0043 adjustment:** under randomized sealing, both
sides editing to even *identical* plaintext no longer id-match, so that case
now also conflicts and needs an identity — accepted cost 4a): the two
plaintexts are decrypted, diff3-merged, and the result
is re-encrypted through the same `encrypt_protected`/`reuse_prior_wraps`
helpers `commit` already used (extracted, single-sourced), so plaintext is
never written to the CAS — conflict markers and sidecars for protected paths
go straight to the identity-holder's working tree instead. Missing identity
raises `Error::ProtectedMergeNeedsIdentity`; a supplied identity that can't
unwrap raises `Error::NotAuthorized`; `decrypt_with` distinguishes ciphertext
corruption from either, so a truncated object never misreports as an
authorization failure. Protection rules merge by **union**
(`union_prefixes`/`union_wraps`, both deterministically sorted for encoding
stability) — narrowing protection is not something a merge can do silently.
This closes an internal-consistency case (I2): a file carried forward as
PLAIN that matches a rule landing at the merge is re-encrypted at
completion, so a path's protection bit and its ciphertext-or-plaintext state
never drift apart in any snapshot.

Conflicted protected merges and picks persist the merge/pick's **decided
tree** — `.sc/MERGE_DECIDED_ROOT` / `.sc/PICK_DECIDED_ROOT`, written
alongside the operation's HEAD marker and cleared with it, gc-rooted only
while that HEAD file exists so crash residue from an abandoned operation
can't be read back and hijack a later, unrelated completion. Completion
unions both parents' (or tip-and-picked) protection rules and wraps, and
carries any protected file *absent from the working tree* forward from the
decided tree rather than arbitrating by parent order — plain ours-first
carry-forward was found during the build to silently revert content the
other side had already updated.

The secret registry now **replays** through `sc rebase`/`sc cherry-pick`
via the existing `merge_secrets` helper, with each replayed commit's own
parent as the merge base; a registry conflict aborts the operation
atomically, same as a tree conflict. Replay's `Empty` check was redefined
to mean the tree delta **and** the registry delta **and** the
protection-prefix delta are all empty, so a rules-only or secrets-only
commit now replays instead of being silently dropped (P14's `Empty` checked
the tree only). A conflicted cherry-pick's completion also merges the
picked commit's registry change, closing a hole where a combined
conflict+registry-change commit lost the registry side. `MergeProtected`
and `ReplayProtected` — the P4/P14 fail-closed guards — are retired now that
every path they blocked has a decrypt-on-demand or ciphertext-id
resolution. `demo/run_protected_merge_demo.sh` proves the keyless disjoint
case, the identity-gated content-divergent case, and registry replay
end-to-end. See ADR-0025.

## Phase 16 — revocation tombstones (built)

Protection rules moved from a bare recipient-key list to a per-recipient
**last-writer-wins register**: `RecipientEntry { key, epoch, state: Granted |
Revoked }`. `grant`/`revoke` mint a fresh `epoch = max(current) + 1`;
`merge_prefixes` keeps the higher-epoch entry per recipient and resolves an
epoch tie with disagreeing states as **Revoked** (fail-closed). Commit-time
sealing reads only `granted_keys()` — Granted entries — so a tombstoned
recipient never seals a fresh DEK again, even when a pre-revoke branch merges
in later. This is the closure of the P15 boundary note: P15's union merge
made revoke non-durable against a merge of a pre-revoke branch, because the
old key-list union simply re-added the revoked recipient.

`grant`'s authorization and `decrypt_with` are unchanged (they key off wrap
*presence*, not standing), so a revoked recipient can still read ciphertext
sealed before the revoke — revoke is a standing cutover, not a
cryptographic one; rotation remains the only way to cut off a key that
already saw plaintext. The rules-format tag bumped `2 → 4`
(`TAG_SNAPSHOT_LEGACY = 2`), so a pre-P16 store fails to decode with an
explicit error rather than silently misparsing the new layout. See ADR-0026.

## Phase 17 — bulk re-wrap + multiple escrow keys (built)

`sc rewrap [--identity <key>] [--dry-run]` is a one-commit, one-oplog-record
sweep that recovers every secret and unwraps every protected blob's DEK by
wrap presence, then re-seals to exactly the governing rule's current
`granted_keys() + escrow` — the practical answer to the P16 corollary that a
merged-in pre-revoke branch can re-attach a revoked recipient's old wraps to
the live tip. Convergent DEKs keep ciphertext ids unchanged, so the commit is
policy-only (root tree byte-identical to the parent). Entries the identity
can't open are **skipped and named**, not silently dropped; the sweep commits
what it could and exits non-zero when anything was skipped.

Escrow grew from a single key to a managed list: `sc escrow add/remove/show`
join `set` (kept as replace-with-one sugar), and `.sc/recipients.toml
[escrow]` grows from `key = "…"` to `keys = […]` (old singular form still
read on load). Same honesty caveat as rotation: rewrap cuts the *live tip*
only — old snapshots in history keep their old wraps via content addressing.
See ADR-0027.

## Phase 18 — network Git remotes (built)

Hosted Git (GitHub over https/ssh) becomes reachable because upstream `gix`
can fetch/clone but not push, so a pure in-process path is impossible today.
Each git-backed network remote gets a lazily-created bare mirror at
`.sc/git-remotes/<name>/mirror.git`, alongside (not replacing) P10's `marks`
file — deleting `mirror.git` is always safe (self-reconstructs), deleting
`marks` is not (it carries `git_oid ↔ sc_id` identity). The spawned system
`git` binary (quarantined to `crates/gitio`) is transport-only: `fetch` runs
`git fetch --prune` into the mirror then P10's unchanged import; `push` runs
P10's unchanged export into the mirror then `git push`, reusing the P9/P10
confidentiality gate verbatim. Auth is fully delegated to the spawned `git`
(ssh-agent, credential helpers, tokens) — `sc` has no credential surface of
its own.

Clone routing auto-detects unambiguous git URL forms (`https://`, `http://`,
scp-style, `file://`); bare `ssh://` stays sc-native unless `--git` forces
the bridge. `SC_GIT` overrides the spawned binary, mirroring P12's `SC_SSH`.
See ADR-0028.

## Phase 19 — history-editing polish (built)

Riding the same P14/P15 replay core with no second merge implementation.
`sc amend [-m <msg>]` rebuilds the tip from the working tree with the tip's
own parents kept, via a `parents_override` parameter on the existing
`snapshot_files` pipeline. **Resumable rebase is now the default**, revising
P14's atomic-abort: a conflict stops with P4 markers and a persisted
`.sc/REBASE_STATE` instead of aborting; `sc rebase --continue` completes the
conflicted commit and resumes the fold, and any number of stops still
collapses into ONE oplog record because the branch ref only moves at final
completion. `sc cherry-pick --abort` restores the untouched tip with no
oplog record at all — no ref ever moved, so abort is its own inverse. `sc
cherry-pick <ref> --mainline <N>` replays a merge commit relative to its Nth
parent; rebase over a merge-containing range stays refused (a rebase replays
a whole range, so there's no single relative parent a flag could resolve).

A review Critical closed a resumability bug: `--continue` used to clear
`REBASE_STATE` before running the resumed fold, so a typed error mid-fold
destroyed retry/abort; state now clears only on the fold's own completion,
and a `resolved` flag makes a retried `--continue` idempotent. See ADR-0029.

## Phase 20 — agent sessions + auto-merge (built)

Agent sessions now outlive a single process. `sc ws fork --agents N`
materializes N checkouts under `.sc/ws/<i>/` and atomically writes
`.sc/ws/session.toml` (base snapshot, base branch, workspace dirs + status,
author) — the checkout directories plus this manifest **are** the durable
state, so `sc ws list/run/harvest/abandon` work across any number of later
invocations, even a different day. `sc ws harvest` runs each live workspace
through P13's harvest pipeline, then auto-merges the candidate onto the
landing branch through a read-only conflict probe (`would_merge_cleanly`,
composing P4's `three_way` + `merge_secrets`) that guarantees no conflict
markers land unattended: clean merges land immediately and cumulatively (one
oplog record each), anything conflicted falls back to a `work-<i>` branch
exactly as P13 did. Harvest joins the P19 merge/pick/rebase-in-progress
guard family as a ref-mover.

`resolve_and_teardown` writes the manifest before removing the workspace
directory, so a crash between the two never strands a `live = true` entry
pointing at a directory that no longer exists. See ADR-0030.

## Phase 21 — hardening & consolidation sweep (built)

No new capability axis — a sweep closing the P16–P20 review tail. Every
commit-creating policy op (`protect`/`grant`/`revoke`,
`secret add/rotate/grant/revoke`) now opens with the same
merge/pick/rebase-in-progress guard the ref-movers already used, closing a
hazard where an unguarded policy op mid-stopped-rebase had its commit
silently discarded by completion. Git marks staleness self-heals at the one
dangerous point of use: `GitTarget::has_object` verifies a mark-reused git
commit still exists in the target before reuse, re-synthesizing instead of
writing a broken parent chain when `git gc` pruned it upstream. The three
verbatim conflict-materialization copies (merge, cherry-pick, rebase fold)
collapse into one `Repo::materialize_conflict_state` helper. `sc ws list`
gains a `landed_tip` field so a workspace whose merge actually landed
reports `"landed"` (or `"landed (undone by sc undo)"`) instead of the
generic `"abandoned"` a manual `ws abandon` still shows. See ADR-0031.

## Phase 22 — signed commits & provenance (built)

Signatures are ordinary CAS objects (`TAG_SIGNATURE`, bytes-only in
`crates/core` — no crypto crosses the quarantine) over the domain-separated
snapshot id; a local `.sc/signatures` index maps snapshot → signature ids,
gc-rooted and pruned alongside dead snapshots. `sc keygen` now emits a **v2
identity**: one random seed, HKDF-derived into *both* an X25519 encryption
key and an Ed25519 signing key in a single `scl-id-<hex>` file (a v1
`scl-sk-` identity still parses and encrypts, but can't sign). Verification
(`sig_status`) is strict four-state — `Invalid` beats `Trusted` beats
`Untrusted` beats `Unsigned` — and `sc verify [<ref>] [--require]` walks
every parent, not just the mainline.

Transfer needed zero wire changes: signatures ride the existing pack as
ordinary objects, reindexed by id on receipt. `recipients.toml` gains
`[signing]` (name → key) and `[signers] trusted = […]`, mirroring
`[recipients]`'s shape. Stated plainly: signing defends against history
rewriting and attribution disputes, not against a trusted signer acting
maliciously — and `amend`/`rebase`/`merge` results start unsigned by design,
since a new snapshot id is a new claim. See ADR-0032.

## Phase 23 — merge ergonomics (built)

One new abstraction, `conflict_versions(path) -> {base, ours, theirs}`
(`crates/repo/src/conflicts.rs`), re-derives all three sides of a conflict
from the DAG for whichever op is active (merge/pick/stopped-rebase) instead
of parsing marker text off disk. `sc conflicts [<path>] [--identity]` lists
conflicted paths and kinds, or renders a path's base/ours/theirs sections
(protected paths decrypted per-side against *that side's own* protection
registry, gated on `--identity`); `sc resolve --ours|--theirs <path…>`
writes the chosen side and clears the path from the active conflict record.
Resolution only decrypts — it never re-encrypts, so plaintext still never
enters the CAS before the unchanged `sc commit`/`sc rebase --continue`
completion re-encrypts through the same helpers `commit` always used.

`sc status --json`'s `"conflicts"` field grew from a bare path list to
`[{path, kind}]` — a strict superset, no existing consumer broke. Whole-file
resolution only; no hunk-level modes. See ADR-0033.

## Phase 24 — sparse checkouts (built)

`.sc/sparse` is a local, uncommitted prefix spec (`sc sparse set/show/
disable`; empty/absent = full materialization). The whole feature is one
generalized carry predicate: `commit`'s existing absent-path carry (the
P15/ADR-0025 discipline) widens from "absent AND still-protected-and-not-a-
recipient" to "absent AND (that OR outside the sparse set)", so a commit
made while narrowed carries the untouched out-of-sparse subtree forward
byte-identical, while an in-sparse absence stays a genuine deletion.
`materialize` filters its write and old-root-removal loops by the same spec;
`sc ws` workspaces inherit the host's sparse view, persisted at fork time in
`session.toml` so a later `sparse set` on the host can't reinterpret a
workspace's never-materialized paths as deletions.

A clean merge/pick/rebase change to an out-of-sparse path lands in the CAS
without materializing; a CONFLICT there refuses up front with a "run `sc
sparse set` to include it" hint. Sparse is CHECKOUT-only — every object
stays in the CAS regardless of the spec, so `sc gc`'s reachability walk is
unaffected; not fetching out-of-prefix objects at all is deferred to P27.
See ADR-0034.

## Phase 25 — streaming pack transfer (built)

`push`/`fetch`/`clone` no longer hold a whole pack in RAM on either side.
`crates/core/src/pack.rs` gained an incremental `PackWriter` (appends
objects one at a time to any `Write`) and a streaming `parse_pack_reader`
(verifies each record's hash off a `Read` without holding the whole body).
`crates/repo/src/wire.rs` frames a pack as `ST_PACK_CHUNK`/`ST_PACK_END`
opcodes under the unchanged `u32` frame header, `CHUNK_SIZE` defaulting to 1
MiB (`SC_PACK_CHUNK` overrides it). **`PROTOCOL_VERSION` bumped 1 → 2**, v1
dropped outright — one pack encoding, always chunked, rejected cleanly at
handshake on mismatch. The receiver does a two-pass atomic-after-verify
ingest into a guarded temp file (`.sc/tmp/`, `TempPackGuard`) so a corrupt or
truncated pack never partially lands.

A final-review fix closed the client side too: `fetch`/`clone`'s incoming
pack and `push`'s outgoing pack both now spill through the same guarded
temp-file path instead of destreaming into a `Vec`, so peak RAM is one
object end to end, not just on the wire and server. See ADR-0035.

## Phase 26 — sc-native HTTP transport (built)

A second sc-native transport alongside P12's ssh://: `sc+http://
host[:port]/repo` (default port 8730). The opening codec is four small pure
`Read`/`Write` functions routed through one `read_bounded_opening` helper
that errors out past `MAX_OPENING_BYTES` (8 KiB) rather than allocating
unbounded on a hostile/unterminated opening. The client reads and maps an
HTTP-style status line (`200`/`404`/other) *before* the `WireClient`
handshake begins, so a non-repo server is never mistaken for a HELLO
failure. The server (`sc serve --http <addr> <path>`) is a
`TcpListener`, thread-per-connection, each thread opening `LocalTransport`
fresh — no store or lock shared across threads. Concurrency safety layers
the pre-existing single-writer `RepoLock` (ref updates) with lock-free
content-addressed object writes, tightened with thread-unique temp sibling
names now that thread-per-connection puts multiple writers in one process
for the first time.

After the `200` status, the raw `TcpStream` goes straight to `wire::serve` —
no HTTP framing wraps the P25 chunk stream. Zero new dependencies
(`std::net`/`std::io` only). Standing boundaries stated plainly: plaintext
only (no TLS), unauthenticated (closed in P29), not proxy/CDN-safe. See
ADR-0036.

## Phase 27 — partial clone (built)

`.sc/promisor` (local, uncommitted) records a partial clone's fetch-filter
prefixes plus the promisor origin URL; its presence makes a gap expected.
One path-aware walk, `reachable_objects_filtered` → `Reachable { included,
gaps }`, serves both the server's `get_pack` filter (`GetPack.filter`,
**`PROTOCOL_VERSION` 2 → 3**) and the client's own gc/`sc verify`: an
out-of-filter child's id lands in `gaps` and is never fetched — which is why
absent out-of-filter objects never surface as errors. `sc clone --filter
<prefix…>` writes both `.sc/promisor` and `.sc/sparse` to the same prefixes
(partial ⊇ sparse, one filter); `sc backfill <prefix…>` widens both,
explicitly and offline — no lazy-fetch from inside a read path.

Building a *new* commit on a partial clone needed real machinery beyond
carry-by-id: `worktree::graft_out_of_sparse` splices the tip's untouched
out-of-filter subtrees back into a freshly built root by id, never reading
their content, so push's filtered reachability walk still sends only the
client's new in-filter objects. `commit` refuses (`Error::GappedPathContent`)
rather than silently drop content under an unfetched subtree. `sc backfill
--all` is the genuine full-clone escape hatch: fetch everything, verify the
closure, then remove `.sc/promisor`. Merge, replay, `sc ws fork/harvest`, and
`sc work` are all refused outright on a partial clone as a deliberate MVP
coarsening rather than per-case gap tolerance. See ADR-0037.

## Phase 28 — security hardening sweep (built)

A dedicated security pass closing exposure introduced by opening the store
to untrusted network peers (P26/P27). One `MAX_OBJECT_SIZE` cap bounds any
single object's decompressed/decoded size at every read/write boundary that
takes attacker-controlled bytes, closing a decompression-bomb / unbounded-
allocation class that P25's `read_frame_inner` had already named as a known
gap. Ref names are validated at the write boundary (rejecting path traversal
and control characters) before ever touching `.sc/refs/` on disk, since a
ref name had until now been trusted as an internal identifier rather than
treated as attacker-reachable input once a network write path existed. See
ADR-0039.

## Phase 29 — sc+http access control (built)

`sc serve --http` gains three composed access-control gates at the
connection opening, closing P26's stated "unauthenticated" boundary: a
read-only mode that rejects any write-shaped request before it reaches
`wire::serve`, a fail-closed bind check, and bearer-token authentication
against a `.sc/serve-tokens.toml` allowlist. `EC_READONLY` (or equivalent
server flag) forces the read-only gate independent of tokens, so a
public-read mirror needs no token management at all. Each gate runs before
the P25/P26 wire handshake begins, matching P26's own status-line-before-
handshake discipline, so a rejected connection never reaches
`LocalTransport`. See ADR-0040.

## Phase 30 — agent session transcripts (built)

A sealed provenance record can now attach to a commit. `Transcript {
snapshot, agent, session, nonce, ciphertext, wrapped_keys }` is a bytes-only
`TAG_TRANSCRIPT` object in `crates/core` (the crypto quarantine holds) whose
body is *always* sealed via `scl_crypto::seal` before it reaches the CAS —
a keyless clone gets ciphertext only. A one-to-many `.sc/transcripts` index
(snapshot → transcript ids) means history-editing ops start each fresh
snapshot with none attached, so there is no stale-provenance carry-forward
to reason about. Signing is opt-in and reuses P22's machinery outright —
same `SignatureObj` type, same `.sc/signatures` index, no second index —
under a distinct signature domain string.

Because transcripts are ordinary content-addressed CAS objects, transfer
needed zero wire changes: the sender over-sends every indexed transcript
(and its signature, folded into the same over-send query as P22's) covering
a transfer-relevant snapshot, and the receiver reindexes idempotently. `sc
gc` roots live transcript ids into reachability before signature pruning
runs, so a signed transcript survives exactly as long as the transcript
itself does. `sc export --to <git-repo>` drops transcripts (no Git-native
form exists) and reports a count. See ADR-0038.
