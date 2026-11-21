# ADR-0057: Bucket remote compaction and gc

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
A group's decoded bytes are also bounded: past `4 x group_bytes` the objects read
so far are uploaded as a pack and reading continues. A part built from fewer
than two source packs is dropped, not uploaded, and its source stays where it
is (#263): rewriting one pack into one reduces nothing, and without this two
highly compressible packs that each decode past the limit cost one upload per
source. A run where no part reaches two sources merges nothing and writes no log
entry or checkpoint. `bytes_deleted` counts only objects the sweep actually
removed: packs kept because the manifest moved mid-sweep are subtracted.

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
them. They are removed by phase 2 once the checkpoint that dropped them has
aged past `grace`, normally a later run. (A leftover checkpoint from a lost
CAS can set that cutoff earlier than the real one, which only costs a reader
that read the manifest moments before a restart; see the reader protocol.)

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
rare; a reader straddling a sweep can be restarted.

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
content to an old orphan while a sweep that already selected it is still
deleting (the manifest is looked at again every 16 packs), can still
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

### Rollout and permissions

Upgrade pushers and `sc serve --store` instances before the first `sc remote
compact`: a client without the pre-commit pack check can still lose a pack to
the residual limit above. Pushers and readers need only get, put and head on
objects, but the "absent object" cases (restart on a swept object, the pre-commit
check) rely on a missing key answering 404. S3 answers 403 instead when the
caller lacks `s3:ListBucket`, so grant pushers and readers list as well if you
want the retry messages; without it they fail closed, with an opaque error.

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

The `Bucket` trait gains three methods, implemented by `DirBucket` and
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

## Addendum: compaction on an `sc+git::` remote (P39 follow-on, ADR-0060)

ADR-0060 shipped the Git carrier with compaction refused: a Git host reports
no trustworthy age for a stored object. The only time it has is a commit's
committer date, which the writer chooses and which predates publication, so it
cannot say how long an unreferenced pack has been sitting there. Without
compaction `refs/sc/*` grows by at least three refs per push, every `ls-remote`
and push downloads the whole advertisement, and a cold read fetches every
`log/` and `checkpoints/` entry. This addendum lifts the refusal. The
algorithm above is unchanged; only the age source, the sizing, and the delete
primitive differ on a carrier, and the deletion rules around them get stricter.

**Age source: first sightings.** On a carrier the compactor keeps its own
clock. Bucket key `compact/sightings` (`refs/sc/compact/sightings`) holds one
line per tracked key, `<first_seen_unix_secs> <oid> <key>\n`, sorted by key,
where `oid` is the value's tag when the compactor first listed it and
`first_seen` is the compactor's own clock then. Only `packs/` and
`checkpoints/` keys are tracked: log entries are deleted by sequence behind the
cutoff, never by age. An object's age is `now - first_seen`, so the first run
after an object appears never deletes it (with a zero grace a first sighting is
immediately old), and a later run at least `--prune-expire` after the first
sighting may. A listed key whose oid differs from the recorded one is a new
generation (a key that was deleted and uploaded again; every write is a new
commit, so the oid always differs) and starts its age over.

The record supplies ages and nothing else. Deletion candidates still come from
the listing minus everything the live chain and the retained checkpoints and log
entries name, so a record that calls a live pack ancient deletes nothing live.
It decodes strictly: plain decimal seconds, a 40-digit lowercase oid, a
`packs/` or `checkpoints/` key the carrier accepts, keys sorted and unique, no
other bytes. Anything else is an error that blocks the run before phase 1
writes anything, and the message names the fix (delete
`refs/sc/compact/sightings`; every object's age then starts over); a record is
never read as "everything is old". A first-seen time more than five minutes
after the compactor's own clock is refused ("compactor clocks disagree"). The
read cap is the 256 MiB value cap; a write that would pass it is an error, never
a truncation. The record is written with a compare-and-swap, only when it
changed, before any delete decision uses it (a lost CAS replans, so two
compactors converge). A dry run never writes it and reports ages as a lower
bound.

**Sizes without downloads.** `list_meta` downloads every value on a carrier, so
the compactor never calls it there. A live pack's size for the merge plan is the
end of its furthest record in its idx (`offset + 4 + length`, saturating), taken
while the view parses each live idx. The idx is writer-controlled, so after a
member body is downloaded a pack far over `small_pack_bytes` (twice it) is left
unmerged and reported; the body is already in RAM by then (up to the 2 GiB value
cap), so an understating idx costs the compactor a download. Report byte counts
on a carrier are those idx sizes, summed with saturation (log entries,
checkpoints, idx files and a pack with no readable idx count as 0, and the
report says so whenever the run deletes anything). Deletion counts are what the
run attempted: a key that survives its lease, or that another compactor already
removed, is still counted.

**Clock and retained records.** The clock is read per sweep attempt, so a key
first listed after a replan is stamped with that attempt's time, not the time the
sweep began. A retained log entry or checkpoint is compared, by tag, with the
tag its own listing showed: a carrier serves a create-only key it has already
read from its cache, so a mismatch (a writer deleted and re-created the entry)
means the bytes read are not the value the listing shows, and every candidate
pack is kept for that run (a rerun, in a new process, reads it afresh).

**Leased deletes.** `Bucket` gains `list_tags` (keys with their tags, one
listing) and `delete_leased` (delete each `(key, tag)` only if the key still
holds that tag; the default has no lease and deletes unconditionally). The Git
carrier pushes the deletions with one `--force-with-lease=refs/sc/K:<oid>` and
one `:refs/sc/K` refspec per key (never `+`, never `--atomic`, at most 128 refs
and about 24 KiB of arguments per push). A key that was re-created since the
listing is at another oid and survives; a key still at its lease after a refusal
(a hook) is an error. The sweep deletes each key leased to the oid of the one
listing whose age it judged; nothing lists twice.

**Authoritative manifest check.** Before every destructive batch (the log and
checkpoint deletes, and each batch of packs: idx files first, then bodies) the
compactor reads the manifest with `get("manifest", None)` and compares the tag.
A conditional read with the cached tag is not enough: the Git carrier answers
one from its 2 s freshness window with no network call, and a stale view is the
one thing the pack deletes cannot tolerate. This applies to every backend, and
to the log and checkpoint deletes too, which the cutoff alone would have made
safe: nothing is deleted on a picture the manifest has moved past, so a remote
that is pushed to continuously can defer cleanup to a rerun (the report says so).
If the manifest moved before the first batch the plan is stale and is redone;
later, the rest is kept. Order per batch: age record write (if changed),
manifest check, deletes.

**What remains.** The race named under "Residual limit" is narrowed, not closed.
A pusher that finds an aged orphan pack already present (`put_new` returns
false and leaves the oid unchanged, because the bytes are identical) and commits
its manifest after the compactor's check but before the delete lands can still
lose the pack: no lease on the manifest exists to close that. A push also keeps
its pack only if it commits within the grace window of the compactor first
seeing the pack. Both are the contract this ADR already states for every
backend. A crash between the age record write and the deletes leaves every key
in place with its age recorded, so the next run decides again and finishes the
job; a crash between an idx delete and its pack delete leaves a lone `.pack`,
which ages out on its own.

**Operating it.** Run compaction from one host: runs that share the record need
clocks within far less than the grace window. On a Git host every pusher holds
delete (a push to `refs/sc/*` is a push), unlike the advice above to keep delete
rights away from pushers; branch protection does not cover `refs/sc/*`.
Deleting a ref is not erasure: the host may keep the objects fetchable by id,
and forks and mirrors keep their own copies; sealed content stays ciphertext, so
rotation (`sc rewrap --rotate`) is the cutover. Tested over a bare repository
and sc-forge; not tested against GitHub.

As built: `compact/sightings.rs` (the record), `compact.rs` (`list_for_sweep`,
`delete_keys`, `manifest_unmoved`), `WalView.pack_sizes`, `Bucket::list_tags`
and `delete_leased` (`GitBucket` overrides both). Tests:
`compact/tests/git.rs`, `crates/objio/src/git.rs`, `crates/cli/tests/git_bucket.rs`;
proof: `demo/run_git_carrier_demo.sh`.
