# ADR-0037: Partial clone (promisor store + prefix-scoped fetch)

- **Status:** Accepted
- **Date:** 2026-07-09
- **Phase:** 27
- **Builds on:** ADR-0034 (sparse checkout — the materialize half), ADR-0035 (streaming pack transfer), ADR-0015 (packfiles + reachability gc), ADR-0022/0036 (transports)

## Context

Sparse checkout (ADR-0034) stopped *materializing* out-of-prefix subtrees,
but a clone still *fetches and stores* every object. P27 — the scale-&-
reach horizon's capstone — stops fetching them: a `--filter <prefix>`
clone downloads only in-prefix reachable objects. The object store must
tolerate MISSING objects (promisor gaps), and every graph-walking reader
(gc, verify, get_pack) must handle a gap without erroring or treating it
as corruption.

## Decision

Spec: `docs/superpowers/specs/2026-07-09-p27-partial-clone-design.md`.

**Explicit `sc backfill`, no network in read paths** (chosen over
transparent lazy-fetch) and **one-slice: `--filter` sets both the durable
fetch-filter and the sparse view, partial ⊇ sparse** (chosen over
independent filters).

- **`.sc/promisor`** (local, uncommitted) records the fetch-filter (prefix
  set, P24 `matching_prefix` boundary rules) + the promisor remote URL.
  Its presence makes a gap expected; absent = full clone, unchanged.
- **`sc clone --filter <prefix…>`** fetches only in-prefix reachable
  objects (prefix-scoped `get_pack`), writes `.sc/promisor`, and sets
  `.sc/sparse` to the same prefix.
- **Prefix-scoped `get_pack`**: a path-aware reachability walk that
  includes a parent tree object (structure + child ids) but does NOT
  recurse into an out-of-prefix child subtree/blob. The filter rides a new
  `GetPack` field; `PROTOCOL_VERSION` bumps 2→3 (both ends v3).
- **Gap-tolerant `reachable_objects`/`walk_tree`**: gc stops at absent
  referenced objects (never prunes/errors on a gap); verify reports
  `partial: N gaps` (expected) vs corruption (an in-filter absent object).
- **The gap error**: any access genuinely outside the filter →
  `Error::NotFound` → "run `sc backfill <prefix>`." No silent network.
- **`sc backfill <prefix…>`**: prefix-scoped fetch from the promisor
  remote, then widens `.sc/promisor`. The manual form of lazy-fetch.

## Consequences

- A `--filter src/` clone of a monorepo pulls only `src/`; the rest is
  never fetched or stored. `sc backfill` widens on demand, offline-safe,
  network-free everywhere else.
- **Push composes for free**: a partial clone's new commits carry the
  unchanged out-of-filter subtree ids forward (P24/P15 carry-by-id, which
  needs the tip tree object — present — not the gapped child), so a push
  pack is only the client's new in-filter objects; the server has the rest.
- partial ⊇ sparse: `sc sparse set` narrower is free; sparse-wider or
  `sparse disable` beyond the filter hits the gap error → backfill first.
- **`sc export` refuses on a partial clone** (Git needs full trees).
- Transparent lazy-fetch is a clean deferred follow-on — identical infra,
  only the on-gap action differs.
- `PROTOCOL_VERSION` 2→3; a v2 peer is rejected at handshake (as with the
  P25 v1 drop). No new dependencies.

## Alternatives considered

- **Transparent lazy-fetch** (git's promisor default): the store dials the
  remote on any gap. The full monorepo UX, but threads network I/O into
  the deepest read path (`store.get`) that gc/verify/materialize/merge/
  export all invoke — huge scope/risk (offline breakage, surprise latency,
  fetch-during-gc), against the fail-loudly/predictable grain. Deferred.
- **Independent partial + sparse filters**: more flexible but a footgun
  (sparse-view into un-fetched gaps with no "one slice" mental model).
- **Blob-size / object-count filters** (git's `--filter=blob:limit`):
  prefix-only matches sparse and the path-boundary machinery already
  built; size filters are a separate axis, deferred.

## Refinements discovered during the build

The design above held up structurally, but two of its claims needed real
work to become true, and one ("push composes for free") was flatly wrong as
originally stated. Documented honestly, with exact call sites.

### The ancestor descent rule (`crates/repo/src/promisor.rs`)

`Promisor` exposes two predicates, not one: `matches(path)` ("is this path
itself in-filter") and `should_descend(path)` ("should a tree walk step
into this directory at all"). A filter of `["src/app/"]` must still descend
through `src` to reach `src/app/`, even though `src` itself does not match
— `should_descend` (`promisor.rs:66-73`) is the load-bearing predicate a
naive single-predicate design would have missed, since `matches` alone
would prune `src` (and therefore everything under it) at the root.
`should_descend("")` is unconditionally `true` — every prefix lies under
the empty root path.

### The filtered reachability walk (`crates/repo/src/reachable.rs`)

`reachable_objects_filtered` (`reachable.rs:106-139`) is one path-aware
walk that serves both the server side (`get_pack`'s want-set, via
`Transport::get_pack`'s `filter` parameter, `transport.rs:106-155`) and the
client side (gc, `sc verify`'s gap count). It returns `Reachable {
included, gaps }`: a parent tree is always included (its structure + child
ids), but an out-of-filter child's id is recorded in `gaps` and never
`get()`'d — this is *why* a partial-clone source that's genuinely missing
an out-of-filter object never errors (`gap_object_is_never_fetched`,
`reachable.rs:524-538`), and why the client's own gap-tolerant reads follow
the identical rule. `reachable_objects` (the pre-P27 unfiltered entry
point) is now literally `reachable_objects_filtered(..., filter: None)`
with `included` returned and `gaps` discarded (`reachable.rs:42-44`) — one
walk, not two parallel implementations.

**A review-caught CRITICAL**, fixed in the same task before merge
(`walk_tree_filtered`, `reachable.rs:169-230`, doc comment at
`156-168`): the original expansion-dedup gate keyed subtree descent on the
bare object id, which is correct with no filter (a verdict doesn't depend
on path) but wrong under one — content addressing can dedup a
byte-identical subtree to a single id reachable at two different paths with
two different filter verdicts (e.g. filter `["a/x/", "b/y/"]` where trees
`a` and `b` hash identically: only `x` is in-filter under `a`, only `y`
under `b`). Gating on bare id expanded the shared subtree only at whichever
path the stack popped first, silently dropping in-filter content only
reachable via the second path. The fix gates expansion on the `(id, path)`
pair instead, while `included` still dedups by bare id for the *result* —
pinned by `deduped_tree_included_under_each_path`
(`reachable.rs:443-519`), the reviewer's exact repro. `Reachable`'s two
sets are disjoint by construction (`gaps.retain(|id| !included.contains(id))`,
`reachable.rs:137`) — an id in-filter anywhere always wins.

### Prefix-scoped `get_pack` and the protocol bump

`GetPack` gained a `filter: Option<&[String]>` field (`transport.rs:106-155`);
with a filter, the sender's *want*-side walk runs through
`reachable_objects_filtered` and its `.included` set becomes the pack's
object set, while the *have*-side walk (what the receiver already holds)
stays fully unfiltered — a filter only narrows what's sent, never widens
what's assumed already held. `PROTOCOL_VERSION` bumped 2→3
(`wire.rs:25`); a v2 peer is rejected at handshake, same discipline as the
P25 v1 drop. `reachable_objects` being the `filter = None` case of the
same function means full transfer's code path is structurally unchanged,
not just behaviorally compatible.

### "Push composes for free" was FALSE as originally stated

The Context/Consequences sections above claim push composes for free
"via carry-by-id" — that undersells (misstates, really) what building a new
commit on a partial clone actually required. **The commit path itself
needed new machinery.** `snapshot_files`'s existing per-blob byte-carry
(the P24/P15 mechanism the original ADR text pointed to) only carries
*individual absent blobs*; it does nothing for an entire out-of-filter
*subtree* that the working-tree enumeration never even walks (a partial
clone never fetched it, so there is nothing on disk to enumerate under
`docs/` at all). Left alone, building the new root tree purely from
in-filter content would silently **drop every out-of-filter subtree from
the new snapshot** — not carry it forward.

The fix is `worktree::graft_out_of_sparse` (`worktree.rs:202-298`,
called from `repo.rs:511-519` inside `snapshot_files`, guarded to a
plain single-tip commit only — `decided_root.is_none() &&
merge_head.is_none()`, `repo.rs:427-431`, `T5-I4`): after the working
tree is flattened and written from in-filter content, this walks the
*tip's own parent tree* and splices its out-of-filter entries back into the
freshly built root **by id, without ever reading their content** — a whole
out-of-sparse subtree carried forward as one structural-sharing id copy,
the tree-level analogue of the blob-level carry. An ancestor directory that
must be descended through to reach a deeper in-filter prefix recurses
instead of being grafted whole (`worktree.rs:270-283`), so genuinely
in-filter content underneath it still comes from the built side.

Once the graft exists, `push`'s reachability walk (`sync.rs:301-321`) *is*
filter-aware and *does* send only the client's new in-filter objects — that
part of the original claim holds, and is the reason a full re-clone of the
origin after a partial-clone push sees the edit AND intact
docs/lib byte-identical (proven end to end by
`demo/run_partial_clone_demo.sh` step 5). But "for free" implied zero new
work; the accurate framing is: **commit on a partial clone required a new
gap-tolerant tree flattener + an id-only graft step, after which push
composes cleanly on top of it.**

Two review-caught Criticals landed on top of the graft before it was safe:

- **C1 (crypto access loss):** the graft splices out-of-filter subtrees
  back in purely by id, so any PROTECTED blob living only under a grafted
  subtree never passes through the encrypt-or-carry loops that populate
  `fresh_wrapped` — left alone, `reuse_prior_wraps` (which only *refreshes*
  ids already present in `fresh_wrapped`, never adds new ones) would
  silently drop those blobs' wrapped DEKs from the new snapshot, and
  because that snapshot becomes the new tip, the loss is **permanent**:
  every later push/merge/clone builds on top of a `protection.wrapped` that
  can no longer open that ciphertext for anyone. Fixed at `repo.rs:520-542`
  by unioning in every entry from the tip's own `protection.wrapped` that
  `fresh_wrapped` doesn't already have — convergent encryption keeps a
  blob's id stable regardless of who grafted it, so reusing the prior wrap
  bytes verbatim is correct, not just convenient. **Note the fix is a
  blanket carry-forward of every tip wrap**, not scoped to only the grafted
  paths — harmless (a revoked recipient's already-superseded wrap sticking
  around one extra generation is the same accumulation `sc rewrap`
  addresses elsewhere, ADR-0027) but deterministic, not zero-cost. Verified
  end to end: a full clone decrypts `docs/*` under the recipient key after
  a partial-clone-originated commit touching a protected sibling path.
- **Data-safety CRITICAL:** `graft_out_of_sparse` refuses (rather than
  silently discarding) any content the working tree has under a path this
  clone never fetched. Two sites: a built-side entry with **no same-name
  parent entry at all** — e.g. a brand-new top-level directory the
  promisor filter never knew about — is checked up front against the
  promisor filter itself (not `sparse`, which can be narrower than the
  fetch filter but never wider; `worktree.rs:219-241`); a built-side entry
  that collides with a parent entry the graft would otherwise overwrite
  wholesale by id is checked in the per-entry loop
  (`worktree.rs:262-266`). Both return `Error::GappedPathContent(path)`,
  surfaced with a `sc backfill` hint. Net effect: **you cannot commit under
  an unfetched subtree on a partial clone** — a stray out-of-filter file on
  disk (however it got there) blocks even an otherwise-clean in-filter
  commit until removed, fail-closed rather than fail-silent.

### Gap-vs-corruption is a path check, not a blanket "any missing object is fine"

`reachable_objects_filtered`'s walk only ever `get()`s an id it has decided
is in-filter; an id it decides is out-of-filter is recorded in `gaps`
straight from the parent tree's entry and never fetched at all
(`reachable.rs:150-154`). So a missing **out-of-filter** object is
structurally incapable of erroring (there's no `get()` call that could
fail), while a missing **in-filter** object still hits `src.get()` and
surfaces as a genuine `Error::Core(NotFound)` — real corruption, not an
expected gap. Both are proven by name: `gap_object_is_never_fetched` vs
`in_filter_absent_is_an_error` (`reachable.rs:524-563`). `sc verify`
renders the distinction as `partial: N object(s) outside filter [...]`
(`main.rs:1940-1949`, `partial_gap_count` at `promisor.rs:158-174`) — a
count printed alongside the ordinary signature-trust summary, never
folded into it, and exit code 0 even under `--require` for a healthy
partial clone.

### The gap-error sites, enumerated

Every place a partial clone can hit "this needs content I don't have"
resolves to one of two errors, both defined in `promisor.rs`:

- **`Error::GapOutsideFilter(path)`** (`promisor.rs:95-97`) — a *narrow*,
  path-scoped gap `sc backfill <path>` can act on directly: sparse-widen
  preflight (`sparse.rs:155-165`, checked before any disk write) and
  `sparse disable` on a partial clone (`sparse.rs:217-227`, refused
  outright — nothing short of a full backfill covers a full
  materialization).
- **`Error::PartialCloneUnsupported(op)`** (`promisor.rs:99-109`) — a
  *whole-operation* refusal for anything that needs the FULL tree of
  whatever it touches, where there is no single path to name: `merge`
  (`repo.rs:1062-1063`), cherry-pick/rebase replay
  (`replay.rs:178-182`, one choke point shared by both since they both
  fold through the same function), `sc ws harvest` (`ws.rs:456`, `551`),
  and `sc work` (`workspace.rs:196`). This is a deliberate MVP coarsening,
  not a per-case limitation worth threading gap-tolerance through
  individually: **merge/pick/rebase/ws-harvest/sc-work are refused
  entirely on a partial clone** — `sc backfill` to a full clone first.
- **`Error::GappedPathContent(path)`** (distinct from the two above,
  defined in `error.rs`) is `graft_out_of_sparse`'s commit-time refusal,
  covered in the "push composes" section.

`sc export` refuses unconditionally on a partial clone (`main.rs:2803-2809`)
— Git needs full trees to synthesize objects, and there is no partial Git
export to fall back to.

### gc: defense-in-depth, not just "gaps aren't errors"

Beyond simply not erroring on a gap, `gc::run` (`gc.rs:100-131`) walks
every gap id that happens to be **present locally for any reason** back
into the reachable set, unfiltered (`gc.rs:118-130`) — "walk what you
have." This is a deliberate backstop, reviewer-requested alongside the
Task 4 commit-side `GappedPathContent` refusal: that refusal closes the one
known way a reachable-but-out-of-filter object could land in the store, but
"walk what you have" makes gc *structurally* incapable of pruning a
present, reachable object regardless of how it got there, rather than
relying on every future write path remembering to guard itself. Proven by
`gc_never_prunes_present_reachable_out_of_filter_object` and
`gc_on_partial_clone_preserves_and_doesnt_error` (`gc.rs:610-653` and
neighboring).

### status/diff needed no new code

`sc clone --filter` writes `.sc/sparse` to the same prefixes as
`.sc/promisor` (`sync.rs:128-137`) — the "one-slice, partial ⊇ sparse"
decision made this free: `diff_worktree`/`diff_unified` already treat an
absent out-of-sparse path as expected-not-a-deletion (the P24/ADR-0034
mechanism), and a partial clone's out-of-filter paths are always a subset
of (or equal to) its out-of-sparse paths, so the existing sparse-diff
tolerance covers the partial-clone case structurally, with zero new
branches in `status`/`diff`.
