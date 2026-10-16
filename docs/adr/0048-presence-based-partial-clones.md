# ADR-0048: Presence-based walks for partial clones (P37b)

- **Status:** Proposed
- **Date:** 2026-10-16
- **Phase:** 37b
- **Builds on:** ADR-0047 (want-by-id fetch, 37a), ADR-0037 (partial clone), ADR-0034 (sparse), ADR-0035 (streaming transfer), ADR-0039/0041 (size limits)

## Context

37a gave a lazy partial clone one read entry point (`sc cat`) and a network
seam (`Filler`). A fill leaves objects in the store that lie outside the
promisor filter, and 37a stopped there: it does not widen the sparse view,
because several walks still read "outside the filter" as "not here".

Reviewing the code for this phase found that the premise behind those walks is
already wrong on main, with or without lazy fills.

**`sc fetch` on a partial clone is not filtered.** It passes no filter
(`sync.rs:361`) and advertises local tips as `haves`, and the origin subtracts
each have's *full* closure (`transport.rs:242`). An object that is new at an
in-filter path but equal to an out-of-filter object reachable from a have is
therefore left out of the reply, and stays absent. Reproduced on main: the
origin adds `docs/readme.txt`, the clone is made with `--filter src/`, the
origin then adds an identical `src/readme.txt`, the clone fetches. `sc gc` and
a fast-forward `sc merge` then fail with `object … not found`, while `sc
verify` exits successfully and reports only the expected `docs/` gap. The cause is that the filtered walk
never reads blobs (`reachable.rs:347`), so a missing in-filter blob is only
found later, by `write_pack`.

So "in the filter" has never meant "present". The filter records what a clone
and a backfill *asked for*. This ADR makes every walk that decides what to
send, keep or report ask the store instead.

Who reads the filter today:

| Consumer | Where | Use |
|---|---|---|
| clone, backfill | `sync.rs` (`get_pack` filter) | transfer scope. Correct, stays. |
| server pack construction | `transport.rs:222` | builds a `Promisor` and cuts a filtered transfer. Stays. |
| push | `sync.rs:436` | walks with the filter, sends only in-filter objects |
| gc | `gc.rs:110` | strict in-filter, plus a present-only walk of gap ids that are held |
| verify | `Repo::partial_gap_count` | gaps are filter-derived |
| commit graft | `worktree::graft_out_of_sparse` | filter decides "was this ever fetched" (`GappedPathContent`) |
| materialize | `worktree.rs:625` | filter prefixes bound the old view when removing files |
| sparse set / disable | `sparse.rs:162`, `:229` | refuse a prefix outside the filter; refuse disable |
| tracked paths, status, diff | `repo.rs:173`, `:1079` | pick a sparse walker when partial |
| merge, pick, rebase | `repo.rs:398`, `:1349`, `replay.rs:176`, `private.rs:1188` | refuse |
| `Filler` | `fill.rs:194` | origin, lazy marker, partial state |

## The model

A partial clone is a store plus one promise.

> **Promise P.** Every object id referenced by an object reachable from a
> local root that the store lacks is held by the origin.

P holds after clone, after a fetch **from the origin** (it built the reply from
its own graph), after a fill, and after any local write that only carries ids read
from an existing tree entry (commit graft). Hash verification at ingest proves
identity, not that the sender has a complete closure, so P is a statement about
the origin, not something the client can prove locally. P is about the
promisor origin only. A fetch from any other remote can leave a gap that the
origin does not hold (that remote subtracted the closure of a have it holds and
the origin may not), and `Filler` only ever dials the origin. So **a partial
clone fetches from its promisor origin only**: `sc fetch <other>` is refused on
a partial clone in 37b-i, with a hint to fetch from the origin or `sc backfill
--all` to convert to a full clone first. This is a behavior change and needs a
test. P can be broken by the
origin pruning history a clone still points at; that hazard is the same as in
git partial clones and is out of scope.

Consequences:

- The filter is **request scope** for clone and backfill. It is not a statement
  about what is present and it changes only through `sc backfill`.
- A walk must treat any absent object referenced by a present tree as a **gap**,
  not an error. Gaps are legitimate because of P.
- What the filter used to catch as corruption (a missing in-filter tree) is now
  caught by an origin-backed check, below.

## Decisions

### 1. One presence-based walk for client operations

Add `reachable::reachable_objects_partial(store, tips)`. It descends every
present tree and records an absent child as a gap with the tree that references
it. It takes no filter. A snapshot's **root tree** can be absent too (a new
commit that moves an old out-of-filter subtree to the root is omitted by the
`haves` subtraction), so an absent root is a gap, not an error. Snapshots,
parents, secrets and transcripts stay strict: those are never gaps. A private branch's manifest keeps the handling
the filtered walk already gives it (the closure list, public base, anchors and
superseded-manifest chain are walked, sealed ids are opaque leaves). Verdicts do not depend on path, so the ordinary
bare-id expansion dedup applies (the path-keyed dedup of the filtered walk is
not needed and must not be copied over).

`gc`, push and verify use it. gc's hand-written "walk present gap ids in" block
disappears into it.

**`reachable_objects_filtered` keeps its meaning.** The origin runs it over a
full store to *cut* a filtered transfer. If it gained presence semantics every
filtered clone would receive the whole repo. The new function is a separate
entry point and a test pins that a filtered `get_pack` against a full origin
still omits out-of-filter objects.

`sc gc` also strictly walks the merge, pick and rebase decided roots
(`gc.rs:162`); those switch to the same walk when the repo is partial, so a
stopped operation cannot brick gc once the later phases let one exist.

### 2. Push checks every gap edge against the push destination

Push sends every object in the presence walk that the destination lacks, then
advances the ref. The destination is whatever `push(remote)` resolves, which
need not be the promisor origin, so P gives no guarantee about it. Before any
`put_pack`:

> Every gap id the walk found must exist on the push destination. Otherwise
> refuse, naming the id and the tree that references it, and leave the remote
> untouched.

This catches a locally created object that was lost (the new tree references
it, it is absent, the destination lacks it), an interrupted earlier push that
left a tree without its child, and a push to a second remote that is not a
mirror of the origin. It replaces the corruption signal the filter gave for
trees.

This is best effort, not a proof of destination closure. `has_object` shows an
id is stored, and ingest's write pass is not all-or-nothing, so a tree left
behind by an interrupted earlier push could be present without its children.
The ref only advances after a push completes, so such residue is never
reachable from a ref, and a gap normally arrives from an origin tree entry. The
remaining hole needs two faults: an interrupted push of that tree, then loss of
the local copy before the next push. A server that validates the closure of the
new tip before it moves a ref (cost proportional to the new objects) would
close it and is open question 1.

Scope: native remotes only (local path, ssh, http, bucket; a bucket supports
the check through its committed object index). Git remotes are refused up
front for a partial clone (decision 6).

Cost: one `has_object` per distinct gap id. The gap set is the cut of the
present region (siblings along the paths to present prefixes), not the repo,
and it grows with fills. Push already does one `has_object` per reachable id.
A batched `HasObjects` verb would cut the round trips and is deferred (open
question 2).

Push does not stop descending at ids the destination has. Ingest's write pass
is not all-or-nothing, so a stored tree does not prove a stored closure.

### 3. Verify and gc

- `sc verify` on a partial clone reports `partial: N gaps` from the presence
  walk. N is the size of the gap frontier: it can rise when a fill replaces one
  missing tree with several missing children, and it is not a measure of
  progress. An optional origin check over the gap set is a follow-on.
- `sc gc` keeps what the walk reaches. Filled objects that stay reachable
  survive. Evicting fills needs proof that the origin holds them and is a
  follow-on (open question 4). Disk use is whatever the live graph costs; gc
  still drops unreachable loose objects, old packs and trimmed oplog roots.

### 4. The sparse view and its closure obligation

For a lazy, online clone, `sc sparse set <prefix>` stops refusing a prefix
outside the filter. It resolves the prefix's subtree at the HEAD tip and calls
`fill_closure`, then continues down the existing path.

`fill_closure(root)` goes level by level. At each level it reads every tree
that is present or just arrived, collects absent children, and requests them
in `GetObjects` batches of at most 1024 ids (`MAX_GET_OBJECTS_IDS`, a hard
limit, so a wider level is chunked by count before anything is split by size).
It must read present trees too, since a tree can
land before its children. Duplicate subtrees are visited once by id. Progress
is by presence, so an interrupted fill resumes where it stopped.

**The view closure obligation.** The sparse view promises that the closure
under its prefixes at the current tip is present. That is true after a clone
and false after any fetch that leaves a gap at a view path (the issue in the
Context). So every operation that materializes a root first runs
`Filler::ensure_view(root)`, which fills the view's closure on a lazy, online
clone and fails with the existing gap hint on a non-lazy or offline one
(non-lazy clones skip the fill and keep today's behavior). This also heals the
in-filter gap case above for lazy clones; non-lazy clones keep the explicit
`sc backfill` answer.

`ensure_view` has two halves, and they ship separately. The **preflight**
(check that the view's closure at the target root is present, otherwise fail
with the gap hint, before any mutation) needs no network and lands in 37b-i, so
a fast-forward or switch after an ordinary fetch fails cleanly with an
actionable message instead of a raw `NotFound`. The **fill** half lands in
37b-ii and is what makes a lazy clone heal it.

Placement matters. `ensure_view` runs **before any ref, spec or working-tree
mutation**, so an offline failure leaves nothing half-done. The call sites are
every caller of the materializer, pinned by a test that greps for them and by
behavioral tests for ordering and for failure while offline:

- clone, `switch`, adopt and fast-forward merge, fast-forward rebase
- merge, pick and rebase conflict materialization and their aborts
- **`sc undo`/redo**, which restores refs and HEAD before it materializes
  (`oplog.rs:418`), so the call goes ahead of that
- `sparse set`, which checks against the *proposed* spec before `sparse.rs:178`
  stores it, and passes the *previous* spec to the materializer: today the new
  spec is stored first, so the old view cannot be recovered when files must be
  removed

Per-site notes from review: undo preflights the snapshot it will restore to
(`will_be_tip`), not the ambient HEAD read afterwards; the fast-forward rebase
releases the store mutex around the call because `Filler` takes it
(`fill.rs:210`); `switch` preflights before it removes stale files
(`repo.rs:1826`).

`tracked_paths_at`, status and diff rely on the obligation holding at the
tip; they are not independent sites.

The filter is not widened by a fill or a sparse set. Widening would not remove
the obligation, because of the `haves` effect in the Context.

Consumers that used the filter as "was this ever fetched" take the broader
truth:

- **Commit graft.** `graft_out_of_sparse` has two checks. The check for a
  built-side name that the parent has no entry for (a brand-new directory)
  moves from the filter to the union of the filter and the sparse view, so a
  path is refused only if it lies outside both; the filter was the larger set,
  so nothing is newly refused, and a widened view stops being refused. The
  other check, a built-side entry where the parent subtree is carried by id
  (`worktree.rs:288`), stays on the sparse view: relaxing it would silently
  discard an edit under a carried subtree.
- **Materialize.** The old-view bound comes from the spec that was in effect,
  passed in, not from the filter prefixes.

`sc sparse disable` stays refused on a partial clone; whole history and a full
tree stay `sc backfill --all`. A `sc sparse set` with no prefixes means a full
checkout (it equals disable), so it is refused on a partial clone too, in
37b-i; otherwise `ensure_view` would fill the whole tip and persist a full
spec, bypassing the refusal.

### 5. Reply size limits

37a left a mismatch: the client reads at most 1 GiB per by-id reply while the
server default `--max-pack-size` is larger, and the server sums canonical
object sizes while the client counts pack bytes (36-byte record headers plus
zstd framing). Decisions:

- The server caps a `GetObjects` reply, measured in canonical size, at
  `min(--max-pack-size, 512 MiB)` where a `--max-pack-size` of 0 means
  unlimited. Headroom to the client's 1 GiB read cap covers framing and
  incompressible data.
- The cap applies to `LocalTransport::get_objects` as well, which today builds
  with no limit (`build_objects_tempfile(ids, 0)`). A lazy clone whose promisor
  is a local path would otherwise spool up to 1024 large blobs in one request.
- The over-cap refusal happens before any pack byte is written, so the
  connection stays in sync. The client splits the batch in half and retries.
  A batch of one that is still refused is final and is returned as an error;
  splitting never loops. (An object above `MAX_OBJECT_SIZE`, or above a small
  `--max-pack-size`, can exist on an origin.)
- The 37a handling for a stream abandoned mid-reply (kill the ssh child, drop
  the connection) stays as the backstop.

### 6. Lifting the P27 refusals: directions, not designs

The first version of this ADR proposed a recursive tree merge by id. Review
showed the proposal was not safe as written, so merge, replay and sessions are
not specified here. Each needs its own design record after a spike. What
review established, as constraints on that work:

- Carrying a subtree by id when `base == theirs` or `ours == theirs` is wrong
  when the **union of protection rules** newly covers paths under it: current
  merge encrypts carried plain files under a union rule (`repo.rs:1395`), and
  replay does the same (`replay.rs:210`). The shortcut is valid only for a
  subtree no rule newly covers, relative to the side being carried.
- Protected wraps are gathered per blob (`merge.rs:327`) and pruned by fully
  flattening the merged tree (`repo.rs:1486`, `replay.rs:256`). A carried
  subtree is never enumerated, so its wraps would be dropped, which is the same
  class as the commit-graft wrap bug. A subtree that cannot be enumerated must
  keep the union of its input wraps.
- Conflict completion refuses today (`repo.rs:398`) and its graft preserves one
  parent only (`repo.rs:667`). Permitting it needs a graft from the decided
  root, a partial-aware decided-root walk in gc (decision 1), and the same for
  `sc conflicts`/`sc resolve` (`conflicts.rs:147`, `:263`).
- Acceptance for any merge rewrite: a differential test over random trees
  between the old and new implementations on full clones, and between a partial
  and a full clone doing the same merge. It compares decrypted semantics for
  freshly sealed output (sealing is randomized) and bytes for carried objects.
  A full-clone-only test cannot catch the snapshot-id divergence that skipping
  the wrap prune would cause.
- `sc export` stays refused permanently: it needs the whole history and every
  blob, and `sc backfill --all` is the answer. `ws`/`work` are undecided.
- Several commands flatten whole trees and fail with a raw `NotFound` on a
  partial clone instead of an explicit refusal (`rewrap.rs:166`,
  `protect_ops.rs:118`, switching away from a private branch at `repo.rs:1825`).
  They get the explicit refusal in 37b-i; lifting them is not planned.
- `sc push` to a **git** remote bypasses `Repo::push` and `export` and reaches
  `export_branch` without the partial-clone guard, so it would fail partway
  through the export walk at the first absent object. 37b-i adds the same
  up-front refusal that `sc export` has.

## Phasing

- **37b-i, engine.** `reachable_objects_partial`; gc, push and verify on it;
  the push gap-edge check; graft authority for new names as the union;
  materialize takes the old spec; the `ensure_view` preflight at every
  materializer site; refusals for the commands above, for `sc push` to a git
  remote, for `sc fetch` from a non-origin remote, and for a zero-prefix
  `sc sparse set`. Regression tests: the
  fetch-then-gc repro from the Context, the filtered-`get_pack`-still-cuts
  test, a lost-local-object push that must refuse, a push to a non-mirror
  remote. Existing partial-clone demos stay green unchanged.
- **37b-ii, widen.** `fill_closure`, `ensure_view` at every materializer call
  site with the ordering tests, reply-cap alignment with batch splitting,
  `sparse set` outside the filter. Demo: widen, commit, push, a second clone
  sees it; gc and verify after; undo after a widen while offline.
- **37b-iii onward.** Merge design record after a spike, then replay, then a
  decision on sessions.

## Consequences

- The filter becomes a plain statement of request scope and a reader no longer
  has to know which call site interprets it differently.
- A latent bug on main is fixed by 37b-i without waiting for the lazy features:
  gc works after an ordinary fetch, and a fast-forward or switch fails before
  mutating anything, with the `sc backfill` hint. Lazy clones heal the same
  case in 37b-ii.
- Push on a partial clone does extra `has_object` calls and refuses more often,
  correctly. A push to a remote that is not a mirror of the origin now fails
  safe instead of writing a snapshot with dangling references.
- Materializing operations on a lazy clone can do network I/O, only at the
  allow-listed sites and only where the user opted in. `Store::get` stays
  network-free.
- No wire change except the server's reply cap. `PROTOCOL_VERSION` stays 5.

## Open questions

1. **Server-side closure validation at ref update.** Check that the new tip's
   not-previously-held closure is complete before the ref moves. Closes the
   two-fault hole in decision 2.
2. **Batched `HasObjects`.** Worth a verb (and a protocol bump) only if the
   push check's round trips show up in measurement.
3. **Have-pruning in push** (stop at ids the destination has). Needs an answer
   to the non-atomic ingest write pass first.
4. **Evicting fills.** Requires proof the origin holds the object.
5. **A filtered `haves`.** Having fetch send the filter and the origin compute
   the have-set under it would remove the original source of in-filter gaps.
   Presence-based walks and `ensure_view` make it unnecessary for correctness;
   it would only reduce gaps, and it changes fetch semantics.
6. **Re-reading present trees** in `fill_closure`. A local "known complete"
   marker would skip them; not needed until it is slow.
7. **Merge, replay, sessions.** Constraints are in decision 6.
8. **Possible id divergence (unverified).** `graft_out_of_sparse` can insert
   an empty subtree entry (`worktree.rs:312`), so a partial-clone commit might
   differ by id from the same commit on a full clone. A spike should check.
9. **Crash between storing the sparse spec and materializing** (`sparse.rs:178`
   and `:186`) leaves in-view files reading as deleted at the next commit.
   Pre-existing; the old-spec parameter in decision 4 is a natural place to
   close it.

## Alternatives considered

- **Keep the filter as a strict invariant and add a filtered `haves`.** This
  fixes one cause of in-filter gaps but not interrupted ingest or a lost
  object, and it changes fetch semantics. Kept as an optimization (open
  question 5), not the model.
- **Widen the filter on a fill.** Does not remove the closure obligation and
  makes the filter mean two things.
- **Track an "origin-known" set on disk.** More state, a crash window between
  the fetch and the record, and nothing it proves that the push-time check does
  not.
- **Make `reachable_objects_filtered` presence-aware for everyone.** The origin
  uses it to cut transfers.
- **A tree-recursive merge by id in this ADR.** Withdrawn; see decision 6.
- **Server-side merge and history operations.** Still deferred (ROADMAP).
