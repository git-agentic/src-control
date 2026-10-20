# ADR-0047: Want-by-id fetch and explicit gap fill for partial clones

- **Status:** Accepted for 37a (built); 37b Proposed
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

1. **Wire: `Request::GetObjects { ids: Vec<ObjectId> }`.** The reply is an OK
   frame whose body lists the ids the server will not send, followed by the
   found objects as a normal P25 pack stream (`ST_PACK_CHUNK`/`ST_PACK_END`).
   No `haves`, no reachability walk: server cost is O(requested objects),
   independent of history size. A missing id does not fail the batch.
   `PROTOCOL_VERSION` 4 to 5 (additive verb; a v4 peer is rejected at the
   handshake, same discipline as P25/P27/P34).
2. **Transport: `Transport::get_objects(&self, ids, out) -> not_sent`.** The
   trait default refuses. `LocalTransport` (local paths and every wire
   server), `WireClient`, `StdioTransport` (ssh) and `HttpTransport`
   implement it; the two wrappers forward explicitly, because a default that
   looped `get_object` would cost one round trip per object. Bucket remotes
   refuse (ADR-0046 already refuses partial clone there).
3. **Client seam.** `Repo::fetch_by_id_from(transport, ids)` is the only
   function that dials the promisor remote after clone, called through the
   `Filler` in `crates/repo/src/fill.rs`. It fetches one batch, hash-verifies
   every record, then checks the reply partitions the request exactly: no
   unrequested object, nothing both sent and refused, nothing silently
   omitted. Only then does it write. This is verify-before-write, not a
   transaction: objects are immutable and content-addressed, so objects that
   landed before a later failure are kept, and a retry recomputes what is
   missing from current presence. An id the server refuses is terminal
   (`NotFound`). `Repo` already holds the repo lock for its lifetime, so a
   fill cannot interleave with `sc gc`; the seam takes no second lock.
4. **Opt-in, not default.** Laziness is a separate marker file,
   `.sc/promisor-lazy` (local, uncommitted), set by `sc clone --filter
   <prefix...> --lazy` or `sc backfill --lazy`. It is not a field in
   `.sc/promisor`: that file is `origin <url>` followed by one path prefix per
   line, and a prefix such as `lazy = true` is a legal path, so a new field
   would silently reinterpret a legacy clone's filter. Without the marker the
   P27 behavior is unchanged: the gap error with the `sc backfill` hint.
   `SC_OFFLINE=1` forces the gap error even when the marker is present. (A
   `--offline` flag is deferred; the environment variable covers scripts and
   CI.)
5. **Entry points.** 37a has exactly one: the new `sc cat <ref>:<path>`, which
   walks from the ref's root tree and fetches each absent tree and the final
   blob, one round trip per level. It refuses protected paths and private
   branches. Today's `sc diff` compares the working tree to HEAD only and `sc
   log` has no patch output, so neither is an entry point until they gain
   revision and path arguments. Everything else, including gc, verify and the
   desktop read model (ADR-0045), never touches the network.
6. **A fill never widens the promisor filter, and 37a keeps it that way on
   purpose.** The filter decides what `push`, `gc` and `sc verify` walk.
   Extra present objects outside it are harmless to all three (gc keeps them,
   push ignores them, verify counts filter-derived gaps as before). Widening
   the sparse view over a filled path is different: a commit there would
   create objects `push` never sends, leaving the origin with a snapshot that
   points at objects it does not have. That needs presence-based push, verify
   and gc, which is 37b's design work, so `sc sparse set` beyond the filter
   keeps its gap error in 37a.

### Authorization of by-id reads

A hash is not a capability, and Scion delegates this to an IAM layer we do
not have. The rules for `GetObjects`:

- It is a read verb: a `--read-only` session (ADR-0040) serves it.
- It never serves a sealed-branch manifest or a sealed member object
  (`Object::Manifest`, `Object::Sealed`). The server answers "not sent",
  the same reply as an absent id. This matches filtered `GetPack`, which
  already excludes private branches, and a partial-clone client never needs
  those kinds. It is a consistency rule, not a confidentiality boundary:
  sealed objects are ciphertext, an unfiltered `GetPack` still serves them,
  and `HasObject` still reveals whether an id exists, so "indistinguishable
  from absent" holds for this verb only.
- It cannot enforce private-branch membership by kind alone. A private
  branch keeps its fork-point snapshot and carried public trees and blobs
  unsealed, but those are public content by construction.
- The existing single-object `GetObject` is unchanged in 37a. It already
  returns any stored object by id; this ADR does not widen that exposure and
  does not close it. Closing it needs a decision about unfiltered private
  transfers and is tracked as a follow-on.
- Protected-path ciphertext is returned as-is, as in every pack:
  confidentiality rests on encryption, not on withholding.
- Caps: 1024 ids per request (`MAX_GET_OBJECTS_IDS`, checked while decoding),
  the server's `--max-pack-size` over the summed canonical encoded size of a reply and
  `MAX_OBJECT_SIZE` per object (both `PackTooLarge`, before any pack byte is
  written), and a 1 GiB cap on the stream a client will read back (since #213 a 4 GiB
  constant independent of the object cap; see ADR-0048 and the ADR-0039
  addendum). A client
  also stops reading a pack as soon as it holds more records than it
  requested, so repeating one large object cannot multiply the receiver's
  decompress-and-hash work.

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

1. **Presence-based walks (gates 37b).** Push, verify and gc currently ask
   "is this path inside the filter?". Widening the sparse view, and any
   operation that commits outside the filter (merge, rebase), needs them to
   ask "is this object present?" instead, with the filter recording only the
   initial fetch scope. Push must then send every reachable present object
   the origin lacks.
2. **Frontier closure and ancestors.** `fill_closure` over a whole subtree
   must traverse present trees too (a tree can land before its children, so a
   retry cannot trust a present root), and the ancestors of an arbitrary
   prefix may be absent: only the root and the ancestors of the original
   filter are guaranteed.
3. **Merge on a partial clone** needs base, ours and theirs trees for only the
   conflicting paths. Whether tree ids alone suffice (identical ids need no
   fetch) or a server-assisted diff is needed is a 37b spike.
4. **Reply size caps and batching.** (Superseded: since #213 the client read cap
   is a 4 GiB constant and the server reply ceiling 2 GiB; ADR-0048, ADR-0039.)
   The client reads at most 1 GiB per reply
   while the server's default `--max-pack-size` is larger, so a batch that
   crosses 1 GiB fails mid-stream and leaves that connection out of sync. 37a
   sends one id per call so it cannot happen; 37b must split batches by size
   or close the transport on that error.
5. **`GetObject` and unfiltered private transfers.** See the authorization
   section.
6. **Bucket remotes.** `sc+wal://` stores objects inside packs; by-id reads need
   an object-to-pack index. Out of scope; partial clone from buckets stays
   refused.

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

## Refinements from the 37a plan review

Two independent reviews of the 37a plan (an Opus review and a Sol review)
found problems that changed the scope. Recorded so the next phase starts from
them.

- The plan widened the sparse view after a fill and kept the promisor filter
  as is. Both reviews showed `push` walks with the filter (`sync.rs`), so an
  edit under a filled prefix would never reach the origin. 37a was cut back to
  the read-only entry point (`sc cat`); the sparse widen moved to 37b.
- "Ancestors are present" was wrong for any prefix outside the original
  filter, and the frontier loop could not resume after a partial fill. Both
  are open question 2; `sc cat` avoids them by walking one path and checking
  presence at each level.
- Reusing `filter_manifest_wants` would not have protected sealed members. The
  server now refuses by kind in one helper shared by every transport.
- Ssh and http transports forward every method by hand, so the default would
  have silently degraded to one round trip per object. They forward
  `get_objects` explicitly.
- Reply validation needed a hook between the ingest passes
  (`ingest_pack_file_checked`) so unrequested objects are rejected before any
  is written.

## Phasing

- **37a (built).** `GetObjects` verb and protocol v5, `Transport::get_objects`,
  `Repo::fetch_by_id_from`, `.sc/promisor-lazy` and `SC_OFFLINE`, `sc clone
  --lazy`, `sc backfill --lazy`, `sc cat <ref>:<path>`. Proof:
  `demo/run_lazy_fetch_demo.sh` (a path-only fetch of exactly three objects,
  sibling untouched, offline and non-lazy gap errors, a read-only `sc+http`
  server).
- **37b (proposed).** [ADR-0048](0048-presence-based-partial-clones.md) designs
  presence-based push, verify and gc (37b-i) and sparse widen over a filled
  prefix (37b-ii). Merge, replay and sessions on partial clones are directions
  with constraints there, not designed work. Export and `sparse disable` stay
  refused.
