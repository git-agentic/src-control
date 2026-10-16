# ADR-0047: Want-by-id fetch and explicit gap fill for partial clones

- **Status:** Proposed
- **Date:** 2026-10-16
- **Phase:** 37
- **Builds on:** ADR-0037 (partial clone), ADR-0035 (streaming transfer), ADR-0039/0041 (size and listener limits), ADR-0040 (HTTP access control), ADR-0044 (private branches)
- **Research:** `docs/research/scion-evaluation.md`

## Context

A partial clone (ADR-0037) fetches only in-filter objects and then refuses
every operation that needs the rest: merge, cherry-pick/rebase, `ws
fork`/`harvest`, `work`, `export`, and `sparse disable`. ADR-0037 rejected
*transparent* lazy-fetch because it would put network I/O inside `Store::get`,
which gc, verify, materialize, merge and export all call — offline breakage,
surprise latency, fetch-during-gc. It left `sc backfill <prefix…>` as the
manual escape hatch and recorded lazy-fetch as a deferred follow-on.

Anthropic's Scion write-up (see the research note) names the same failure on
git partial clones and fixes it differently: the client never describes what
it *has*. It asks for specific immutable trees and blobs *by id*, starting at
the root tree and descending, and any cache can answer because the objects are
immutable. The network is not hidden in a read path; "what do I need next" is
an explicit, cheap, batchable request.

We already have the pieces: `Request::GetObject(id)` exists on the wire,
objects are self-authenticating (BLAKE3 of canonical encoding), the P25 chunk
stream bounds RAM, and P27 gives us a gap-tolerant store plus a durable
`.sc/promisor` marker.

## Decision

Add a **batched by-id object request** and an **explicit gap-fill seam** at
operation entry points. `Store::get` stays network-free, permanently.

1. **Wire: `Request::GetObjects { ids: Vec<ObjectId> }`.** The reply is the
   requested objects as a normal P25 pack stream (`ST_PACK_CHUNK`/
   `ST_PACK_END`). No `haves`, no reachability walk: server cost is
   O(requested objects), independent of history size. Ids the server lacks are
   reported in a trailing missing-id list rather than failing the whole batch.
   `PROTOCOL_VERSION` 4 → 5 (additive verb; a v4 peer is rejected at
   handshake, same discipline as P25/P27/P34).
2. **Transport: `Transport::get_objects(&self, ids, out)`** with a default
   implementation that loops `get_object`, so local-path, ssh, http(s) and
   test transports compose immediately; stdio/http override it to use the one
   round trip. Bucket remotes keep refusing partial clone (ADR-0046) and are
   out of scope.
3. **Client seam: `Repo::fill_gaps(plan)`**, the only code path allowed to
   dial the promisor remote after clone. An operation that needs more than the
   filter *plans first*: it walks the trees it already holds, collects the
   absent child ids (the "frontier"), batches them into one `GetObjects`,
   verifies every returned object against the requested id and
   `MAX_OBJECT_SIZE`, ingests atomically (the P25 two-pass
   verify-then-commit), and repeats per tree depth until the plan is
   satisfied. The operation then runs unchanged against a store that now has
   what it needs. Cost: one round trip per directory depth, not per object.
4. **Opt-in, not default.** `.sc/promisor` gains `lazy = true`, set by `sc
   clone --filter <prefix…> --lazy` or `sc backfill --lazy`. Without it the
   P27 behavior is byte-identical: the gap error with the `sc backfill` hint.
   With it, the entry points below call `fill_gaps` before proceeding.
   `SC_OFFLINE=1` (and `--offline`) force the gap error even when `lazy` is
   set, so offline use stays predictable.
5. **Entry points that may call `fill_gaps`** (an exhaustive allow-list,
   pinned by a test that greps for the call): `diff`/`log -p`/`show` of
   out-of-filter paths, `sparse set`/`disable` widening, `switch`/materialize
   of a wider sparse view, and — in phase 37b — merge, cherry-pick/rebase,
   `ws fork`/`harvest`, `work` and `export`. Everything else, including gc,
   verify and the desktop read model (ADR-0045), never touches the network.
6. **Gap semantics change from "out of filter" to "absent".** `sc verify`
   currently counts gaps by filter membership. Once fill-gap can fetch
   out-of-filter objects, a fetched object is simply present and the filter
   remains only the *initial* fetch scope. `reachable_objects_filtered`'s
   `gaps` set continues to be computed against presence, and gc must keep
   everything reachable regardless of how it arrived.

### Authorization of by-id reads

A hash is not a capability, and Scion delegates this to an IAM layer we don't
have. Rules for `GetObjects`, in order of preference:

- It is **read-scope**: a `--read-only` token (ADR-0040) may call it; no
  write verb is implied.
- It **never returns private-branch objects** (ADR-0044) to a caller who could
  not receive them through a filtered `GetPack` today — the same
  `filter_manifest_wants` exclusion applies, so a sealed-branch manifest or
  member id is reported "missing", indistinguishable from absent.
- Protected-path ciphertext is returned as-is, exactly as it already is in
  every pack: confidentiality rests on encryption, not on withholding.
- Caps: ids per request, aggregate bytes per request (reusing
  `--max-pack-size`), and the existing per-object `MAX_OBJECT_SIZE`.
  Over-limit requests fail with `EC_TOO_LARGE`; the client splits and retries.

Whether to additionally require that a requested id be *reachable from a
visible ref* (a walk, so not O(request)) is an open question — see below.

## Consequences

- Partial clones of a large repo become usable for the whole day-to-day
  workflow, not just read-and-commit within the filter; phase 37b retires the
  P27 refusals one operation at a time, each with a test that the old
  `PartialCloneUnsupported` is gone.
- The network is entered at a handful of named call sites, which keeps
  ADR-0037's "fail loudly, no surprise latency" grain while delivering the
  lazy-fetch UX where the user opted in.
- Every received object is verified against its requested id before ingest, so
  a malicious or buggy remote can at worst return `missing`, never wrong
  content. No new dependency. Core invariants (content addressing, `Arc<[u8]>`
  blobs, mode-scoped disk invariant) are untouched; `core` learns nothing.
- Fetch granularity is per tree level; a pathological deep path costs one
  round trip per level. Mitigation is batching and, later, a server-side
  "subtree closure to depth N" hint — only if measurement shows it matters.
- `PROTOCOL_VERSION` 5. THREAT-MODEL.md gets a by-id-read section.

## Open questions

1. **Reachability check on by-id reads.** O(request) is the point of the verb;
   a reachability check undoes it. Candidate: cache a per-connection
   "visible set" from `ListRefs` tips and check membership lazily via the
   tree the id was named in. Decide with a threat-model pass before 37a lands.
2. **Does `fill_gaps` widen `.sc/promisor`'s filter?** Leaning no — the filter
   stays the *initial* scope, and presence is tracked by the store — but this
   interacts with `sc verify`'s `partial: N gaps` line and `sc backfill
   --all`'s "convert to full clone" semantics.
3. **Merge on a partial clone** needs base/ours/theirs trees for only the
   *conflicting* paths. Whether the plan can be computed from tree ids alone
   (identical ids ⇒ no fetch) or needs a server-assisted diff is a 37b spike.
4. **Bucket remotes.** `sc+wal://` stores objects inside packs; by-id reads need
   an object→pack index. Out of scope; partial clone from buckets stays refused.

## Alternatives considered

- **Transparent lazy-fetch inside `Store::get`** (git's promisor default).
  Rejected again for the ADR-0037 reasons; the seam in decision 3 delivers the
  same UX without the blast radius.
- **Keep `sc backfill` only.** Safe, but leaves merge/rebase/ws/work/export
  unusable on partial clones, which is exactly where agents and CI want them.
- **Server-side history ops (Scion's blame/merge RPCs) first.** More powerful
  — a client with no history at all — but a much larger surface (new wire
  verbs per op, server CPU, authorization per query). Better built on top of
  by-id fetch than instead of it; tracked in ROADMAP → Deferred.
- **Adopt Scion's changeset model.** Changes every object id; breaks the
  content-addressing invariant for no gain at our scale.

## Phasing

- **37a** — `GetObjects` verb, `Transport::get_objects`, `Repo::fill_gaps`,
  `--lazy`/`SC_OFFLINE`, read-only entry points (diff/show/sparse-widen/
  switch). Demo: `demo/run_lazy_fetch_demo.sh` counts objects fetched and
  proves `Store::get` stays offline.
- **37b** — lift the P27 refusals (merge, replay, ws, work, export), one
  operation per task.
