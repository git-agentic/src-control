# ADR-0055: Blob-size clone filter (`--filter blob:limit=<size>`)

- **Status:** Proposed. Needs an owner decision: it requires a wire change (`PROTOCOL_VERSION` 5 to 6). Nothing is implemented.
- **Date:** 2026-10-20
- **Phase:** 27 follow-on (issue #217)
- **Builds on:** ADR-0037 (partial clone), ADR-0047 (want-by-id fetch), ADR-0048 (presence-based walks), ADR-0049/0050 (merge and sessions on partial clones), ADR-0044 (private branches), ADR-0014 (protected paths)

## Context

`sc clone --filter` takes path prefixes only. Issue #217 asks for git's
`blob:limit` axis (skip blobs above a size) and an object-count limit.

ADR-0048 already made a partial clone a store plus one promise: every id a
present object references and the store lacks is held by the origin. The
filter records what a clone *asked for*; presence decides what exists. A blob
left out by size is the same kind of gap as a blob left out by path, so the
client side needs almost nothing new. The open questions are who learns the
size, and what a checkout does with a gapped file.

## Findings that shape the design

1. **Only the server can know a blob's size before receiving it.** A
   `TreeEntry` is `{name, kind, id, mode, perms}` (`core/src/object.rs:119`);
   there is no size. The wire has no size query: `HasObject` returns a bool,
   `GetObject`/`GetObjects` return the object itself (`wire.rs:118`). The
   by-id reply caps (ADR-0048 decision 5) refuse an over-cap *batch*, they do
   not report sizes.
2. **The prefix filter cannot carry it.** `GetPack` ships `filter:
   Vec<String>` of path prefixes (`wire.rs:138`, `put_strs`). A reserved
   entry such as `blob:limit=1048576` in that list would be read by a v5
   server as a path prefix and silently send almost nothing, a fail-unsafe
   misparse. ADR-0047 rejected the same trick for the lazy flag.
3. **The walk that cuts a transfer never reads blobs.**
   `walk_tree_filtered` decides blob inclusion from the path alone
   (`reachable.rs:347`). A size rule means the server reads (or at least
   sizes) each candidate blob once during the walk.
4. **Git has no object-count filter.** Its filters are `blob:none`,
   `blob:limit`, `tree:<depth>`, `object:type`, `sparse:oid`, `combine`. A
   count limit would also be undefined here: `reachable_objects_filtered`
   collects into a `BTreeSet` ordered by id, so "the first N objects" would
   be an arbitrary, server-dependent set, and a client could not tell a
   cut-off object from a missing one by any rule.

## Decisions

### 1. User-facing form

`sc clone --filter blob:limit=<size> <src> <dst>`, with `<size>` parsed by
`scl_core::parse_byte_size` (`1048576`, `1MiB`, `512KiB`). It combines with
prefix filters in the same repeatable flag: `--filter src/ --filter
blob:limit=1MiB` means "only `src/`, and within it no blob above 1 MiB except
as decision 4 says". `blob:limit=0` is legal and means no blobs beyond the
tips.

`--filter` values starting with `blob:` become a reserved grammar. An unknown
`blob:` form (`blob:none`, a misspelling) is an error, not a prefix. Cost: a
path prefix that literally begins with `blob:` can no longer be named in
`--filter`. Alternative: a separate `--blob-limit` flag, which has no
collision. This ADR recommends the issue's form; it is an owner choice.

### 2. Object-count limit: deferred, not built

No stable definition (finding 4), no git precedent, no stated use case.
`ROADMAP.md` keeps a one-line deferred entry for it; the blob-size part
leaves the deferred list when this lands.

### 3. The server evaluates the filter: wire change, `PROTOCOL_VERSION` 6

Findings 1 and 2 leave no client-side design that saves transfer.

- `Request::GetPack` gains a trailing optional `blob_limit` (a tag byte, then
  a `u64` when present; absent means no limit, so `blob:limit=0` stays
  representable). `PROTOCOL_VERSION` 5 to 6; a v5 peer is rejected at the
  handshake, as at P25, P27, P34 and P37.
- `Transport::get_pack` gains the same parameter. Every implementation
  (`LocalTransport`, `WireClient`, stdio, http) forwards it; the two wrappers
  forward by hand as in ADR-0047.
- `build_pack_tempfile` passes it to `reachable_objects_filtered`, which
  drops a blob over the limit into `gaps` (never `included`). The `haves`
  side stays unfiltered, as ADR-0037 requires.
- Bucket remotes already refuse partial clone (ADR-0046) and refuse this.

Alternatives considered and rejected:

- **Client-side drop on ingest, no bump.** The client downloads every blob and
  discards the large ones. It saves disk and gives the same gap model, but
  not one byte of transfer, which is the point of the feature. It would also
  hide the missing wire support behind a flag that does not do what git users
  expect.
- **A size-query verb (`ObjectSizes`) plus client-chosen fetches.** Also a
  new verb and a bump. The client would walk all history level by level over
  `GetObjects` to learn blob ids first, then ask sizes, then fetch: many
  round trips for something the server does in one walk.
- **Sentinel in the prefix list.** Finding 2.

Server cost: each candidate blob is read once to measure it, then read again
when written to the pack if kept. This is O(blobs under the filter) per
clone and backfill, never per fetch. A size index is a later optimization.

### 4. Tips are complete; the limit applies to history

The server exempts blobs reachable from the root tree of each *want* (every
ref tip the client asked for) that match the prefix filter. The limit applies
to blobs reachable only through parent snapshots.

Reason: checkout, `sc switch` between branches, and every operation that
materializes a tip need those blobs, and the clone's own initial checkout
runs before any lazy marker can exist (`sync.rs`, the
`ensure-view-exempt: clone` note). A strict limit would make a non-lazy
clone fail at its own checkout with `GapInView`, and a lazy one would fetch
the same large files in a second round trip right after clone. The
alternative that skips large tracked files at checkout would need a third
"tracked but absent" state in status, diff, commit graft, materialize and the
merge engine (the sparse machinery covers paths, not sizes) and is not a small
change.

What this saves: old revisions of large files, and large files only reachable
from history. That is where git's `blob:limit` pays off for binary assets
too. What it does not do: skip a large file at HEAD. The issue's phrase
"reports or lazily fills large ones" is therefore met by the history case:
operations reaching an old gapped blob fill it by id on a lazy clone and fail
with the gap error on a non-lazy one (decision 5).

### 5. Gap record, presentation and repair

- **No new gap record.** Absence is the gap (ADR-0048). Push, verify and gc
  already walk presence (`reachable_objects_partial`) and need no change; the
  tests for them are new, the code is not.
- **Marker:** `.sc/promisor-blob-limit`, local and uncommitted, one decimal
  byte count. Not a field in `.sc/promisor`, for the ADR-0047 reason (that
  file is `origin` plus one path prefix per line). `Repo::promisor()` returns
  a clone with the limit marker as partial even when the prefix list is empty;
  an empty prefix list together with the marker means the whole tree is in
  scope. `Promisor::matches`/`should_descend` and its consumers
  (`graft_out_of_sparse`, the materialize old-view bound, push and verify
  messages) need that case checked one by one; it is the main implementation
  risk.
- **Presentation:** `sc verify` keeps `partial: N object(s) outside filter
  [...]`, with `blob:limit=<size>` printed in the bracket beside any
  prefixes. `sc clone` prints one line naming the limit and the gap count.
- **Repair, lazy and online:** nothing to do. `ensure_view`, `sc cat` and the
  ADR-0049 merge fill by id.
- **Repair, otherwise:** the gap error already names `sc backfill <prefix>`.
  For a size gap the prefix is the gapped file's own path, which
  `Promisor::matches` accepts as an exact boundary. `sc backfill <path>` sends
  every version of that path without applying the limit (backfill passes no
  `blob_limit`). `sc backfill --all` removes the markers and converts to a full
  clone, as before (`promisor::remove` must also delete the limit marker).
  Error text gains one clause when the limit marker exists: "(blob:limit=1MiB
  left this out of the clone)". No `--min-size` form: it would be a second
  size parser on the repair side with no use that `<path>` does not cover.
- **`sc fetch` is unchanged:** it stays unfiltered (ADR-0048 Context), so new
  large blobs from new commits arrive in full. A limit-aware fetch needs the
  exemption list for backfilled paths in the request, which is a larger design.
  Deferred; the clone's limit therefore bounds the initial transfer, not later
  growth.

### 6. Interactions

- **Protected content.** The size is the stored object's payload length. A
  protected file's blob is ciphertext, so its size is the plaintext size plus
  the sealing overhead; the server cannot see plaintext. A file near the
  limit may flip sides from its plaintext size by that overhead. Protected
  and plain blobs are treated by the same rule. No new information leaks:
  ciphertext length is already visible to anyone who can fetch the object.
- **Private branches.** Unchanged: a filtered transfer already excludes them
  (ADR-0044).
- **Sealed objects, signatures, transcripts.** Never subject to the limit;
  they are not path-reached blobs.
- **Sparse and prefix filters.** The prefix decides scope first, the limit
  prunes inside it. `.sc/sparse` is still set to the prefixes (none for a
  size-only clone, meaning a full view).
- **Push, verify, gc.** Presence-based already (ADR-0048); a size gap is
  checked against the push destination like any other gap.
- **Merge, pick, rebase, ws, work** (ADR-0049/0050). A merge base or an old
  version that is a size gap is "asked for" by the engine and filled by id on
  a lazy, online clone, or fails with the gap error. No new engine code.
- **Wire caps.** A gapped blob over the by-id reply cap behaves as in
  ADR-0048 decision 5.

## Implementation outline (once accepted)

1. Wire v6: `GetPack.blob_limit`, `Transport::get_pack`, all transports, a
   version test, the wire doc comments.
2. Server walk: size-aware, tip-exempt `reachable_objects_filtered`; tests
   that a filtered pack omits a large history blob and keeps a large tip
   blob; a differential test against the unlimited walk.
3. `Repo`: clone option, `.sc/promisor-blob-limit`, whole-tree scope case in
   `Promisor`, `promisor::remove`, backfill passing no limit.
4. CLI: parse `blob:limit=<size>` in `run_clone`, reject unknown `blob:`
   forms, report line, `sc verify` text.
5. Tests: push, verify and gc on a size-limited clone; the gap error text;
   prefix plus size; `sc backfill <path>` repair; lazy fill by id; partial
   clone refusals unchanged.
6. Docs: ADR-0037 and ADR-0048 pointers, CLAUDE.md capability row and bullets,
   ROADMAP, ARCHITECTURE, THREAT-MODEL (one line on sizes), the
   `sc-cli-reference` skill, a demo script.

## Open questions for the owner

1. Accept the `PROTOCOL_VERSION` 6 bump? (Recommended: yes; no useful design
   avoids it.)
2. Tips complete, limit on history only (decision 4), versus a strict limit?
   (Recommended: tips complete.)
3. `--filter blob:limit=...` with `blob:` reserved, or a separate
   `--blob-limit` flag? (Recommended: the issue's form.)
4. Object-count limit deferred, and `sc fetch` not limit-aware in the first
   version. (Recommended: both deferred; PR says `Refs #217`.)
