# ADR-0037: Partial clone (promisor store + prefix-scoped fetch)

- **Status:** Proposed
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
