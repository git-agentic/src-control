# P27 — Partial clone: design

**Date:** 2026-07-09
**Status:** Approved
**ADR:** 0037 (Proposed → Accepted when built)
**Horizon:** Scale & reach (P25 streaming → P26 HTTP transport → **P27 partial clone**, capstone)

## Problem

Sparse checkout (P24) stopped *materializing* out-of-prefix subtrees, but
the objects are still fetched and stored — a monorepo clone still pulls
everything. P27 stops *fetching* them: a `--filter <prefix>` clone
downloads and stores only in-prefix reachable objects. This is P24's
deferred other half and the horizon's monorepo payoff, built on the proven
streaming wire (P25) and transports (P12 ssh, P26 sc+http).

The hard part: the object store must tolerate MISSING objects (promisor
gaps), and every reader that walks the graph (gc, verify, get_pack) must
handle a gap without treating it as corruption or erroring mid-walk.

## Decided design

**Explicit `sc backfill`, no network in read paths** (user-decided over
transparent lazy-fetch) and **one-slice model: `--filter` sets both the
durable fetch-filter and the sparse view; partial bounds sparse**
(user-decided over independent filters).

### The promisor marker (`.sc/promisor`)

A partial clone records `.sc/promisor`: the fetch-filter (a prefix set,
matching P24/P7 `matching_prefix` boundary rules) + the promisor remote
(the origin URL). Local, uncommitted, like `.sc/sparse`. Its **presence is
what makes a gap expected**; absent = a full clone, everything unchanged.

### Clone

`sc clone --filter <prefix…> <url> <dst>`:
- fetches only in-prefix reachable objects (prefix-scoped `get_pack`);
- writes `.sc/promisor` (filter + origin URL);
- initializes `.sc/sparse` to the same prefix (one slice).

A plain `sc clone` (no `--filter`) is unchanged — a full clone, no
`.sc/promisor`.

### Prefix-scoped `get_pack` (the transport core)

`get_pack` gains an optional filter. The reachability walk becomes
**path-aware**: descending from a snapshot root, when a tree entry's
accumulated path falls OUTSIDE the filter, the walk includes the PARENT
tree object (so the client has full tree structure and the child's id) but
does NOT recurse into or include the out-of-prefix child subtree/blobs.

Client result: every snapshot, every tree on/above in-prefix paths, all
in-prefix blobs are present; out-of-prefix subtree-roots are
referenced-but-absent — the promisor gaps.

**Wire:** the filter rides as a new `GetPack` field; `PROTOCOL_VERSION`
bumps 2→3 (both ends v3, the handshake rejects a mismatch, as with the P25
v1 drop). A full (unfiltered) `get_pack` is the filter-absent case,
byte-behaviorally identical to today.

### Gap-tolerant readers (the load-bearing change)

`reachable_objects`/`walk_tree` (`crates/repo/src/reachable.rs`, used by
gc, verify, get_pack) gain a gap-tolerant mode:

- **gc**: the walk STOPS at an absent referenced object (a gap is a leaf
  of the local graph — nothing behind it to prune) instead of erroring;
  prunes only genuinely-unreachable PRESENT objects; never treats a gap as
  garbage. No network.
- **verify**: reports `partial: N promisor gaps (filter=<prefix>)` —
  expected, NOT corrupt. An absent object whose path is IN-filter IS
  corruption — a real gap-vs-corruption distinction, path-checked against
  the promisor filter.
- **materialize / diff / status**: already skip out-of-sparse paths (P24),
  and sparse ⊆ partial, so in-view operations never touch gaps.

### The gap error

Any path that genuinely reaches OUTSIDE the partial filter — a merge whose
content-merge touches an out-of-prefix path, `sc export` walking the full
tree, or a sparse-widen beyond partial — hits `store.get(gap)` →
`Error::NotFound` mapped to a clear message: *"`<path>` is outside your
partial clone; run `sc backfill <prefix>`."* No silent network, offline-safe.

### `sc backfill <prefix…>`

A prefix-scoped fetch from the recorded promisor remote that fills in the
now-wanted in-`<prefix>` reachable objects (the server has them; the have-
set excludes what the client already holds), then WIDENS the
`.sc/promisor` filter to include `<prefix>` (those objects stop being
expected gaps). It is the manual, explicit form of lazy-fetch.

### Push composes for free

A partial clone edits only in-filter content; its new commits carry the
UNCHANGED out-of-filter subtree IDS forward via P24/P15's carry-by-id
(which needs the tip's tree object — present — not the child subtree
object — a gap). So a push pack contains only the client's new in-filter
objects; the server already has everything out-of-filter. No special push
logic — the existing have-set + carry-forward suffice.

## Composition & boundaries

- partial (durable, fetched) ⊇ sparse (mutable, materialized). `sc clone
  --filter` sets both to the same prefix. `sc sparse set` NARROWER is fine
  (materialize less of what you have); `sc sparse disable` or setting
  sparse WIDER than partial makes materialize touch gaps → the gap error →
  `sc backfill` first. `sc status` / `sc sparse show` surface both the
  sparse view and the partial filter.
- **`sc export` refuses on a partial clone** with a gap (Git needs full
  trees) → backfill-to-full or use a full clone. Explicit boundary.
- `sc gc` and everything in-view stay network-free.

## Testing & demo

- Unit: the path-aware filtered walk (out-of-prefix subtrees pruned,
  structure + child ids kept in the parent tree); gap-tolerant gc (no
  prune, no error on gaps — a gap-referencing tree survives, the gap isn't
  pruned-as-garbage); verify partial-not-corrupt AND in-filter-absent =
  corrupt; the gap→backfill error message; backfill widens `.sc/promisor`.
- Integration (local path AND sc+http):
  - `sc clone --filter src/` fetches only in-src objects — an out-of-src
    blob is genuinely ABSENT from the CAS (`store.contains` false /
    `store.get` NotFound), not merely unmaterialized;
  - an in-src commit + `sc push` round-trips (push pack carries only new
    in-src objects; server has the rest);
  - an out-of-src access (e.g. `sc sparse disable`) errors with the
    backfill hint; `sc backfill docs/` makes those objects present and the
    access now works;
  - `sc gc` on the partial clone prunes nothing it shouldn't and doesn't
    error on gaps; `sc verify` reports the gaps as expected;
  - a signed commit (P22) verifies clean in the partial clone (signatures
    are in-registry, not gapped).
- `demo/run_partial_clone_demo.sh`: a multi-subtree repo (src/ docs/ lib/);
  `sc clone --filter src/` over a transport; prove docs//lib/ objects are
  UNFETCHED (grep/inspect the object store, not just the working tree);
  edit + commit + push in src/; `sc backfill docs/` and prove docs/ objects
  are now present; zero residue. Run twice.

## Out of scope

Transparent lazy-fetch (deferred — identical infra, only the on-gap action
differs); partial clone over the git-bridge (P18) remotes; blob-size /
object-count filters (prefix-only, matching sparse); `sc export` from a
partial clone; automatically narrowing `.sc/promisor` (backfill only
widens; a shrink-and-gc-the-now-out-of-filter-objects op is a follow-on).
