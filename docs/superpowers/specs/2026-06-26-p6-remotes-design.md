# P6 — Remotes (clone / push / fetch): design

- **Status:** Approved (brainstorm); pending implementation plan
- **Date:** 2026-06-26
- **Phase:** 6
- **Refines:** ADR-0013 (firm to Accepted at build time)

## Goal

Synchronize a persistent repo between locations: `sc clone` an existing `.sc/`
repo, `sc fetch` new objects + refs from a remote, and `sc push` local commits to
a remote. This is the "in-memory clones" thesis pillar made concrete, and it
completes the Phase-2/P7 confidentiality story end to end: an **unauthorized
clone receives secret/encrypted objects as ciphertext it cannot decrypt**.

## Decisions (locked: brainstorm + ADR-0013)

1. **Named remotes** in a `.sc/config` (TOML `[remote.<name>] url = …`); `clone`
   seeds `origin`; `fetch`/`push` default to `origin`; `sc remote add <name> <url>`.
2. **Pluggable `Transport` trait**, with a **local-filesystem** implementation
   (`LocalTransport`) the only one this round. The trait is the seam for SSH/HTTP
   transports later; sync only (no async this round).
3. **clone** copies all branches + HEAD, transfers reachable objects, records
   `origin`, and **materializes HEAD into the destination working tree**.
4. **fetch** transfers missing objects and updates **remote-tracking refs**
   (`refs/remotes/<remote>/<branch>`); it does NOT modify local branches.
   Integration is via `sc merge <remote>/<branch>`.
5. **push** pushes the **current branch**, **fast-forward-only**, creating the
   remote branch if absent; non-ff is rejected.
6. **Confidentiality:** objects transfer verbatim (raw `encode()` bytes,
   BLAKE3-verified on receive); ciphertext stays ciphertext — no transport
   special-casing.

## Out of scope (this round)

- Network transports (SSH/HTTP) — `Transport` trait only; local-path impl.
- `push --all`, force push, non-fast-forward push, delete-on-push.
- `sc pull` (fetch+merge in one) — use `fetch` then `merge`.
- Packfile / bulk transfer (object-at-a-time; P8 packfiles accelerate later).
- Async transport (sync this round).

## Architecture

All work is in `scl-repo` (plus a CLI surface and merge ref-resolution). No
`core` change: verified receive reuses `Object::decode` + `Store::put`
(`put` recomputes the id and write-throughs in persistent mode); negotiation uses
`Store::contains`.

### `transport.rs` — the seam

```rust
pub trait Transport {
    /// Branch name -> tip snapshot id for every `refs/heads/*` on the remote.
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>>;
    /// The branch the remote's HEAD points at.
    fn head_branch(&self) -> Result<String>;
    fn has_object(&self, id: &ObjectId) -> Result<bool>;
    /// Raw canonical `encode()` bytes for an object.
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>>;
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()>;
    /// Set `refs/heads/<branch>` on the remote to `id` (atomic).
    fn update_ref(&self, branch: &str, id: &ObjectId) -> Result<()>;
}
```

`LocalTransport { layout: Layout }` implements it over a remote `.sc/` directory:
- `list_refs` / `head_branch` read the remote `refs/heads/*` and `HEAD`.
- `has_object` = remote `objects/<hex>` exists; `get_object` reads those bytes;
  `put_object` verifies `ObjectId::of(bytes) == id` then writes
  `objects/<hex>` (tmp+rename, idempotent).
- `update_ref` acquires the remote's `.sc/lock` for the duration, writes the ref
  atomically, releases.

### Reachability walker (`remote.rs` or a small `reachable.rs`)

The walker must run over **either** side's object graph — the local `Store` (for
push) or the remote (for clone/fetch) — so it is parameterized by an object
source rather than tied to a concrete `Store`. The source is a small trait the
walker calls to fetch a decoded object by id:

```rust
/// Minimal read access the reachability walk needs.
pub trait ObjectSource {
    fn get(&mut self, id: &ObjectId) -> Result<Object>;
}

/// All object ids reachable from `tips`: each snapshot, its parents, its root
/// tree (recursively into subtrees + blobs), and its `secrets` registry objects.
pub fn reachable_objects(src: &mut impl ObjectSource, tips: &[ObjectId]) -> Result<BTreeSet<ObjectId>>
```

`Store` implements `ObjectSource` (delegating to `Store::get`); a thin
`TransportSource` wraps a `&Transport` (`get` = `get_object` + `Object::decode`),
so the same walk drives push (local `Store`) and clone/fetch (remote
`Transport`). BFS over the snapshot DAG: for each snapshot collect its id, push
its `parents`, walk its `root` tree (blobs by id, subtrees recursed), and add
every `ObjectId` in its `secrets` map. (P8 gc reuses this over the local `Store`.)

### `remote.rs` — config + orchestration

- **`.sc/config`** TOML: `RemoteConfig { remotes: BTreeMap<String, Remote { url: String }> }`. Load/save helpers; missing file → empty. Parse errors → `Error::BadConfig`.
- **`Repo::remote_add(name, url)`** — error `RemoteExists` if present; writes config.
- **`Repo::clone_to(src, dst)`** (associated fn): `Repo::init`-equivalent at `dst`;
  open `src` via `LocalTransport`; `reachable_objects` from src's branch tips
  (walking a read-only `Store` opened on src's objects dir); transfer each missing
  object (decode+put) into dst; copy each `refs/heads/<branch>`; set `HEAD` to
  src's branch; write `origin = src` to `dst/.sc/config`; materialize HEAD into
  the dst working tree.
- **`Repo::fetch(remote)`** — resolve remote url from config (`NoSuchRemote` if
  absent); open `LocalTransport`; for each remote branch, `reachable_objects` from
  its tip on the remote, transfer missing into the local store, then write
  `refs/remotes/<remote>/<branch>` = tip locally. Local `refs/heads/*` untouched.
- **`Repo::push(remote)`** — current branch + its local tip; open transport;
  read the remote branch tip (if any). If present and **not** an ancestor of the
  local tip → `Error::NonFastForward`. Otherwise transfer objects reachable from
  the local tip that the remote lacks, then `update_ref(branch, local_tip)` on the
  remote. Absent remote branch = create it (push a new branch).

### Merge integration: remote-tracking refs

Extend ref resolution so a name of the form `<remote>/<branch>` resolves to
`refs/remotes/<remote>/<branch>`. `sc merge origin/main` then merges the
fetched remote tip into the current branch using the existing P4 three-way merge.
Local branch names (no `/`) resolve under `refs/heads/` as today; a name
containing `/` is tried as a remote-tracking ref. (Branch-name validation already
rejects `/` in local branch *creation*, so there is no collision.)

## CLI

- `sc clone <src> <dst>` — clone a local repo; sets `origin`; materializes the tree.
- `sc remote add <name> <url>` ; `sc remote` (list) — manage remotes.
- `sc fetch [remote]` (default `origin`) — update remote-tracking refs.
- `sc push [remote]` (default `origin`) — push current branch, ff-only.
- `sc merge <remote>/<branch>` — integrate fetched work (P4 merge, extended ref
  resolution).

## Confidentiality

Transfer is byte-verbatim and content-addressed: `get_object` returns the stored
`encode()` bytes, `put_object` verifies `BLAKE3(bytes) == id` before writing.
`Secret` objects (Phase 2) and future P7 encrypted-path blobs move as ciphertext;
a clone whose holder lacks a recipient key receives them but cannot decrypt — the
headline property, with zero transport-level special-casing.

## Error handling

New `scl-repo::Error` variants (thiserror): `NonFastForward`,
`NoSuchRemote(String)`, `RemoteExists(String)`. `.sc/config` parse failures reuse
`BadConfig`. A received object whose bytes don't hash to the requested id →
`CorruptObject`. The CLI absorbs via `anyhow`; `NonFastForward` prints actionable
guidance (fetch + merge first).

## Testing

- **reachability:** a repo with branches/merge history + a committed secret →
  `reachable_objects` returns exactly the snapshots, trees, blobs, and Secret
  objects reachable from the tips (and nothing unreachable).
- **clone (local round-trip):** clone repo A → B; B's `objects/` contains every
  object reachable from A's branches; B's `refs/heads/*` + `HEAD` match A; B's
  working tree is materialized; `B` records `origin = A`.
- **fetch:** commit on A after clone; `B` `fetch` transfers the new objects and
  sets `refs/remotes/origin/<branch>` to A's new tip without moving B's local
  branch; `sc merge origin/<branch>` then integrates it.
- **push:** B commits and pushes to A (ff) → A's branch advances and A has the
  objects; a non-ff push (A diverged) → `Error::NonFastForward`, A unchanged;
  pushing a brand-new branch creates it on A.
- **confidentiality:** A has a secret wrapped to alice only; clone to B (no key);
  B's store contains the Secret object (ciphertext) but `run` as a non-recipient
  cannot decrypt it; with alice's key it can.
- **end-to-end** `demo/run_remote_demo.sh`: init A, commit, clone to B, commit on
  A, fetch+merge on B, commit on B, push to A — asserting the expected tips and
  contents at each step, plus the unauthorized-clone ciphertext property.

Every new behavior ships with a test (project convention).

## ADR

Firm **ADR-0013** Proposed → Accepted at build time, recording the as-built
specifics: `.sc/config` named remotes, the `Transport` trait + `LocalTransport`,
reachability-based object-at-a-time transfer, remote-tracking refs + merge
ref-resolution, fast-forward-only current-branch push.

## Open follow-ons (not this round)

- Network transports (SSH/HTTP) behind the `Transport` trait.
- Packfile bulk transfer (after P8) and smarter negotiation.
- `sc pull`, `push --all`, force/non-ff push, delete refs on push.
- Pruning stale remote-tracking refs.
