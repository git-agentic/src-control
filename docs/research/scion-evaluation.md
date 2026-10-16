# Scion evaluation — what should src-control take from Anthropic's source-control redesign?

Research date: 2026-10-16
Source: <https://www.anthropic.com/engineering/redesigning-source-control>

## Recommendation (summary)

Scion is Anthropic's server-side source control for an internal monorepo
(30k+ merges/day, ~100 GB history, ~25M CI checkouts/day). It is **not** a
git replacement and, by its authors' own account, is too bespoke to package.
It is useful to us as a **design source only**, in the same way walgit was
(`docs/research/walgit-evaluation.md`).

- **Take: want-by-id fetch (the `scn` negotiation).** The client names the
  trees/blobs it wants and never describes what it has; requests target
  immutable objects, so any cache can answer and transfers resume. This is the
  mechanism that retires our "transparent lazy-fetch" Deferred item and the
  P27 refusals on partial clones. → ADR-0047 (Proposed).
- **Take later: derived data.** Blame, path history, commit-graph skip lists
  and copy-detection built by one generic recursive mechanism over changesets,
  stored separately and rebuildable. We have none of these. Needs its own ADR
  after ADR-0047; recorded in ROADMAP → Deferred.
- **Take later: server-side ops as an API + ref-CAS commits.** Query
  history/diff/blame/merge on the server so agents and CI need no local repo;
  commit by compare-and-swapping a ref rather than pushing. Recorded in
  ROADMAP → Deferred.
- **Skip: changeset data model.** A changeset lists files changed relative to
  its first parent. Adopting it changes every object id — a format break
  against the content-addressing invariant for no benefit at our scale.
- **Skip: tiered daemon/cache/server and the no-merge-queue workflow.** These
  matter at monorepo scale; our wedge is parallel agents and secrets.

## Where we already line up

| Scion | src-control today |
|---|---|
| Immutable content-addressed objects, no packfile maintenance | Content-addressed (BLAKE3); packs exist (P8) but P36 bucket remotes use immutable packs + CAS'd manifest |
| Sparse/virtual checkouts | P1 in-RAM worktrees, P24 sparse — but bolted on, not protocol-native |
| Refs as compare-and-swap | P36 manifest CAS; `UpdateRef { expected_old }` on the wire |
| Per-directory permissions | P7/P34 — ours are cryptographic, Scion's are IAM |
| Disposable server instances over shared storage | P36 `sc serve --store` |

## Why partial clone is the right first target

Scion's article names the failure we hit in P27: "history-dependent operations
like diff and blame became fragile on partial clones." ADR-0037 refuses merge,
cherry-pick/rebase, `ws fork`/`harvest`, `work`, `export` and `sparse disable`
on a partial clone, and rejected transparent lazy-fetch because it "threads
network I/O into the deepest read path (`store.get`)". Scion's answer is not
to hide the network in `get`; it is to make *what to fetch* a cheap, explicit,
by-id request the client plans in advance. That keeps ADR-0037's
fail-loudly grain while removing the refusals.

## Caveats worth carrying into the design

- Scion trusts an IAM layer to authorize by-id reads. We have no such layer;
  see ADR-0047 "Authorization of by-id reads".
- Round trips: a recursive tree walk is one request per depth level, not per
  object. Scion hides this behind a >99% hit-rate cache tier; we have none, so
  ADR-0047 batches per level and measures.
- The article reports that Claude-written code sometimes violated core
  constraints (scanning the log instead of using the designated API). The same
  discipline applies to us: the seam in ADR-0047 is the *only* place the
  network may be entered, and a test pins that `Store::get` stays
  network-free.
