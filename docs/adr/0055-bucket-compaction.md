# ADR-0055: Bucket remote compaction and gc

- **Status:** Accepted
- **Date:** 2026-10-20
- **Phase:** 36 follow-on (#216)

## Context

ADR-0046's bucket remote only ever adds objects. `log/<seq>` entries,
`checkpoints/<seq>` objects and `packs/<hash>.{pack,idx}` pairs accumulate
without bound. Two costs follow:

- Storage and listing cost grow with every push. A cold start already stops at
  the latest checkpoint (P36b), but it still fetches one `.idx` per on-chain
  pack, so the pack count is the cold-start cost.
- `walfmt::MAX_LIST` (65536) caps a checkpoint's `refs` and `packs`. A fold
  that would exceed it is skipped (`maybe_fold_checkpoint`), so a remote with
  more than 65536 packs loses folding for good and every reader walks an
  ever-longer tail.

The hard part is the cutoff: nothing may be removed that a reader or writer
can still need, with disposable `sc serve --store` instances, concurrent
writers, and no lease primitive (ROADMAP "Leases", unbuilt).

## Decision

### No format change

`Manifest` decodes strictly: `header()` refuses any version other than 1 and
`done()` refuses trailing bytes. A new `compacted_through` field would
therefore make every deployed reader fail closed, which is a format break. It
is also unnecessary: `Manifest.checkpoint_seq` already says where a cold start
stops. Compaction adds no field, no object kind and no `PROTOCOL_VERSION`
bump. Everything it writes is an ordinary record an old client decodes: a log
entry with `updates = []`, and a checkpoint whose `packs` list is a set that
covers the chain instead of a literal accumulation.

### What compaction does

`BucketTransport::compact(&CompactOptions)` runs two phases. Each is
independently safe and either may be a no-op.

**Phase 1, consolidate (additive, fenced by the manifest CAS).** The live pack
set is `view.packs`, deduplicated. Packs smaller than `small_pack_bytes`
(default 16 MiB, sizes from `list_meta`) are grouped greedily, smallest first,
into groups of at most `group_bytes` (default 64 MiB); a group needs at least
two members. Each group is read, its objects are deduplicated by id, and one
new content-addressed pack plus idx is uploaded. This bounds peak RAM to a few
times `group_bytes`, and packs above the threshold are never rewritten.

The result is committed with one CAS, which is both the fence and the fold:

1. `refresh`, then recompute the plan if the members are no longer all live.
2. Claim `log/<s>` (`s > head_seq`, same claim loop as `update_ref`) with
   `LogEntry { parent_seq: head_seq, packs: [new packs], updates: [] }`.
3. `put_new` `checkpoints/<s>` with `refs = view.refs` and
   `packs = dedup(view.packs) - replaced + new`. If this exceeds `MAX_LIST`
   the run stops before writing it.
4. CAS the manifest from the tag of the view in step 1 to
   `{head_seq: s, checkpoint_seq: s}`.

The CAS validates that the manifest has not moved since step 1, so the
checkpoint is exactly the state through `s`. A lost CAS leaves an off-chain
entry and checkpoint (ordinary debris) and the run re-plans, bounded retries.
Because the manifest tag changes, every writer holding an older tag loses its
CAS and must refresh.

Old packs stay in place. After the CAS the superseded packs are named by no
chain a new reader walks, but older checkpoints and log entries still name
them. They are removed by phase 2, a grace period later.

**Phase 2, sweep (deletes, behind a cutoff).** All deletions are of objects
that the current manifest chain does not reference (and, outside the residual
limit below, no later chain will); the manifest itself is never deleted.

- **Cutoff K.** Let `K` be the highest `checkpoints/<seq>` object with
  `seq <= manifest.checkpoint_seq` whose last-modified time is at least
  `grace` ago. No `K` means nothing is eligible by seq (orphan packs may still
  be, below).
- **Removed:** `log/<seq>` for `seq <= K` (including off-chain debris),
  `checkpoints/<seq>` for `seq < K`, and pack objects named by nothing
  retained and at least `grace` old.
- **Retained set** for packs: the current chain (`view.packs`), every kept
  checkpoint (`seq >= K`) and every kept log entry (`seq > K`, on-chain or
  not). A pack named by an old checkpoint or a straggler's in-flight entry is
  therefore kept. If a retained object cannot be decoded the sweep stops
  without deleting packs (fail closed).
- **Order:** log entries, then older checkpoints, then (for each pack) idx,
  then pack. Every prefix of this order leaves a bucket a cold start reads,
  because none of these are reachable from the manifest being deleted against.
  Log entries and checkpoints behind the cutoff are safe whatever the manifest
  does meanwhile (the cutoff only grows). Pack deletion alone is gated on the
  manifest being unchanged since the pack set was computed; if it moved, the
  pack set is replanned (bounded), and otherwise the run keeps the packs and
  says so.
- `K` rather than "the current checkpoint" matters on a busy remote: folds
  happen every 64 pushes, so the newest checkpoint is rarely `grace` old,
  while an older one is.

`K = 0` is a valid answer on a young remote. A run on a bucket whose newest
checkpoint is younger than `grace` consolidates (if worthwhile) and deletes
nothing; the next run after `grace` deletes. This is deliberate: it is the
two-phase "supersede, then delete after T" scheme without a tombstone object,
using the checkpoint's own creation time as the supersession clock.

### Reader protocol

Readers never take a lock and never need compaction to be quiet. The rule:

> When a key the current view names is absent (checkpoint, log entry, idx, or
> pack body), re-read the manifest unconditionally. If its tag differs from
> the view's, discard the view and restart from the new manifest (bounded
> retries, 8). If it is unchanged, the absence is real corruption and the
> operation fails closed exactly as before.

This is sound because deletion only follows a manifest CAS that moved the
tag: the sweep deletes only objects unreferenced by the manifest it read, and
manifest tags never repeat (every successful CAS strictly increases
`(head_seq, checkpoint_seq)`, so the content cannot return to an earlier value,
and an S3 ETag changes with the content, whether it is an MD5 or an opaque
SSE value). A reader that lost an object therefore
always finds a newer manifest on re-read. Object ids stay valid across the
restart because consolidation preserves every object, only moving it to a new
pack, so `get_pack`'s id lists computed before a restart remain valid.
Restart is at the object-fetch level (`object_bytes`, the signature/transcript
scan, `refresh`), never in the middle of the bytes `get_pack` has already
written.

`grace` is therefore not what makes readers correct; it only makes restarts
rare. A reader older than `grace` is the only one that can be restarted.

### Writer protocol

A push uploads packs, claims a log slot, then CASes the manifest. An
uploaded-but-unreferenced pack is indistinguishable from debris, and an object
store offers no atomic "delete if the manifest is unchanged". Two defenses:

1. **Age.** The sweep removes an unreferenced pack only if its last-modified
   time is at least `grace` old (default 24 h). A writer's gap between upload
   and CAS is milliseconds to minutes.
2. **Verify before commit.** `update_ref` checks (`exists`, a HEAD) that each
   pending pack and idx still exist immediately before every manifest CAS
   (after the log slot is claimed), so pushers need no list rights;
   consolidation does the same for the packs it created, and fails with a clear
   retry-the-push error if not, instead of committing an entry that names a
   deleted pack. The window left is one bucket round trip.

**Residual limit (documented, not closed).** A writer that stalls longer than
`grace` between uploading a pack and its CAS, or re-pushes byte-identical
content to an old orphan in the same instant a sweep selects it, can still
commit an entry naming a deleted pack. Closing that needs a lease or a
conditional delete, which the `Bucket` trait lacks (ROADMAP "Leases"). The
same staleness has a second, milder form: a writer paused longer than `grace`
between reading the manifest and claiming a log slot can claim a slot the
sweep freed behind the cutoff. Its manifest CAS fails, but a reader equally
stale (older than `grace`, still walking the chain it read) could read that
phantom entry instead of seeing the slot absent. Both need a participant stalled
past the window; neither affects anyone who read the manifest within it. Run
compaction with a `grace` well above any plausible writer stall; the 24 h
default matches `sc gc --prune-expire`.

### MAX_LIST

Folding is skipped only when the cumulative `packs` (or `refs`) of a fold
exceed 65536. Phase 1 shrinks the pack axis: after consolidation the
checkpoint holds `non-replaced + new` packs, so later folds fit again and the
tail stops growing. The ref axis cannot be relieved: refs are live state, not
history. A remote with more than 65536 live branches stays unfoldable; raising
the cap is a format question and out of scope. Compaction refuses (no writes
beyond debris) if even the consolidated list would exceed the cap.

Dropping on-chain packs whose objects are unreachable from every ref is
**out of scope**. It changes what `has_object` reports, so a pusher that
skipped re-uploading an object could reference a dropped pack; it also needs a
reachability walk of the whole bucket. A pack is "live" here if the chain names
it.

### Signatures, transcripts and tombstones (#229, #254)

The bucket's sender seam finds signatures, transcripts and signed drop
tombstones by decoding every on-chain pack (`pack_leaves`). Compaction keeps
that sound three ways: an on-chain pack is never dropped, only merged;
consolidation decodes and re-encodes every object of a merged pack, whatever its
kind, so the merged pack holds the same leaves; and `pack_leaves` runs against
the post-compaction pack list (the leaf cache is keyed by pack hash and trimmed
to live packs on refresh). `a_clone_after_compaction_still_gets_signatures_transcripts_and_tombstones`
covers a clone and a fetch across two compactions with a signed drop in between.

### Command surface

`sc remote compact <name> [--dry-run] [--prune-expire <dur>]` (default
`24h`, same flag and default as `sc gc`; a value under 1h is refused unless
`--allow-short-grace` is given, because a short grace turns the residual limit
below into an ordinary race). It is the smallest surface: it needs
only the configured remote's URL, adds no wire verb, and is not reachable
through `sc serve`, so a served bucket's clients can never trigger a delete.
`--dry-run` plans phase 1 and phase 2 against the live bucket and prints what
would be consolidated and deleted (counts, bytes, and how many objects are
held back by the grace window), writing nothing.

It refuses a non-bucket remote. Rejected alternatives: `sc gc --remote`
(couples two unrelated reachability models), and a `--compact` flag on
`sc serve --store` (servers are disposable and many; a delete should be an
operator action, not a side effect of an instance starting).

### objio

The `Bucket` trait gains two methods, implemented by `DirBucket` and
`S3Bucket`:

- `list_meta(prefix)`: keys with size and last-modified time, raw string
  prefix, sorted. S3 uses `ListObjectsV2`.
- `exists(key)`: a HEAD, read rights only. Used by the writer-side check.
- `delete(key)`: idempotent; an absent key is success. On a versioned S3 bucket
  a delete only adds a delete marker, so space comes back only with a
  lifecycle rule that expires noncurrent versions.

## Consequences

- On a non-versioned bucket, storage and cold-start cost are bounded by the
  live data plus one grace window (a versioned bucket keeps delete-marked
  versions until a lifecycle rule expires them). A bucket past `MAX_LIST` on the pack axis regains folding after one run if
  its small packs merge to a list under the cap; packs above the merge
  threshold are never rewritten, and the ref axis is not relieved.
- Compaction needs bucket `list` and `delete` rights, which an ordinary
  pusher or reader does not. See the THREAT-MODEL bucket section.
- Only one compaction is useful at a time. Concurrent runs are safe (each
  recomputes from the manifest it read, the loser's CAS fails) but waste work.
- Consolidation rewrites small packs once. Large packs are never touched, so
  there is no write amplification on big pushes.
- Old clients keep working against a compacted bucket. A very old reader may
  see one "retry" error if it straddles the sweep, and a re-run succeeds.

## Alternatives considered

- **`compacted_through` in the manifest.** Rejected: version-gated field breaks
  every deployed reader (strict decode) and is redundant with
  `checkpoint_seq`.
- **Tombstone objects (`gc/<id>` listing keys to delete after T).** Needs a
  new object kind and a second pass; using the checkpoint's creation time as
  the supersession clock gives the same ordering with nothing new in the
  bucket. The checkpoint clock can be wrong (a folder stalled between
  `put_new` and CAS), but that only costs a reader a restart, not safety.
- **Delete immediately after consolidation.** Simple, correct for readers
  (they restart), but makes the writer-stall window as wide as one object's
  age and restarts every in-flight clone. The grace window costs one extra run.
- **Repack everything into one pack.** Unbounded RAM and write amplification.

## As built

`crates/objio` (`ObjectMeta`, `Bucket::list_meta`/`delete`, contract suite);
`crates/repo/src/bucket_transport/compact.rs` (`compact`, `CompactOptions`,
`CompactReport`); reader restart and the pre-commit pack check in
`bucket_transport.rs`; `sc remote compact` in `crates/cli`.
