# ADR-0055: Blob-size clone filter (`--filter blob:limit=<size>`)

- **Status:** Accepted (built). Accepted after an independent Opus plan review and a Sol review; their blockers are decisions 3, 5, 7 and 8 below. A limit-aware `sc fetch` was added afterwards (decision 9, #217); the object-count limit is rejected (decision 10).
- **Date:** 2026-10-20
- **Phase:** 27 follow-on (issue #217)
- **Builds on:** ADR-0037 (partial clone), ADR-0047 (want-by-id fetch), ADR-0048 (presence-based walks), ADR-0049/0050 (merge and sessions on partial clones), ADR-0044 (private branches), ADR-0014 (protected paths), ADR-0046 (bucket remotes)

## Context

`sc clone --filter` took path prefixes only. Issue #217 asks for git's
`blob:limit` axis (leave out blobs above a size) and an object-count limit.

ADR-0048 already made a partial clone a store plus one promise: every id a
present object references and the store lacks is held by the origin. The
filter records what a clone *asked for*; presence decides what exists. A blob
left out by size is the same kind of gap as one left out by path, so the client
side needs almost nothing new. The open questions were who learns the size, and
what a checkout does with a gapped file.

## Findings that shape the design

1. **Only the server can know a blob's size before receiving it.** A
   `TreeEntry` is `{name, kind, id, mode, perms}` (`core/src/object.rs`); there
   is no size. The wire has no size query: `HasObject` returns a bool,
   `GetObject`/`GetObjects` return the object itself. The by-id reply caps
   (ADR-0048 decision 5) refuse an over-cap *batch*; they do not report sizes.
2. **The prefix filter cannot carry it.** `GetPack` shipped `filter:
   Vec<String>` of path prefixes. A reserved entry such as `blob:limit=1048576`
   in that list would be read by a v5 server as a path prefix and silently send
   almost nothing, a fail-unsafe misparse. ADR-0047 rejected the same trick for
   the lazy flag.
3. **The walk that cuts a transfer never read blobs.** `walk_tree_filtered`
   decided blob inclusion from the path alone. A size rule makes the server
   measure each candidate blob once per request.
4. **Git has no object-count filter** (`blob:none`, `blob:limit`, `tree:<depth>`,
   `object:type`, `sparse:oid`, `combine`). A count limit is also undefined
   here: `reachable_objects_filtered` collects into a `BTreeSet` ordered by id,
   so "the first N objects" would be an arbitrary, server-dependent set, and a
   client could not tell a cut-off object from a missing one by any rule.

## Decisions

### 1. User-facing form

`sc clone --filter blob:limit=<size> <src> <dst>`, with `<size>` parsed by
`scl_core::parse_byte_size` (`1048576`, `1MiB`, `512KiB`). It combines with
prefix filters in the same repeatable flag: `--filter src/ --filter
blob:limit=1MiB` means "only `src/`, and within it no blob of 1 MiB or more
unless decision 4 keeps it".

**Boundary:** a blob of size >= the limit is left out (like git; `blob:limit=1`
leaves out every non-empty blob outside the tips). `blob:limit=0` leaves out
every blob no ref tip reaches. Size is the stored object's payload length.

**Grammar.** `blob:` is reserved in `--filter`, matched after trimming and
lower-casing (so `Blob:limit=1KiB` is the filter, never a path prefix that
matches nothing): only `blob:limit=<size>` is
accepted, once. A second `blob:limit` is an error. `blob:none` is an error that
points at `blob:limit=0`. Any other `blob:` form is an error naming the one
supported form. Cost: a path prefix that literally begins with `blob:` can no
longer be named in `--filter`. `sc clone --help` documents this. `--lazy`
requires `--filter`, which a lone `blob:limit=` satisfies, and works with it.
A limit above the largest transferable object (1 GiB, `MAX_MAX_OBJECT_SIZE`)
filters nothing and is an error. Rejected: a separate `--blob-limit` flag, which has no collision but diverges
from the issue and from git.

### 2. Deferred at first, both closed later

- **Object-count limit.** Rejected, decision 10.
- **A limit-aware `sc fetch`.** Built, decision 9. The first version of this ADR
  kept fetch unfiltered and thought it needed the paths a user backfilled to ride
  in the request as exemptions; decision 9 shows it does not.

### 3. The server evaluates the filter: wire change, `PROTOCOL_VERSION` 5 to 6

Findings 1 and 2 leave no client-side design that saves transfer.

- `Request::GetPack` gains a trailing optional `blob_limit` (a tag byte, then a
  big-endian `u64` when present; absent means no limit, so `blob:limit=0` stays
  representable). `PROTOCOL_VERSION` 5 to 6, in the same style as P25, P27, P34
  and P37.
- `Transport::get_pack` takes a `PackFilter` instead of a prefix slice; every
  implementation (`LocalTransport`, `WireClient`, stdio, http, bucket) carries
  it, and the two wrappers forward by hand as in ADR-0047.
- The sender's walk (`reachable_objects_limited`) moves a blob at or over the
  limit from `included` to `gaps`, unless decision 4 exempts it. The `haves` side
  stays unfiltered, as ADR-0037 requires.

**Alternatives that avoid a bump, and why they lose.**

- *A capability-probed new verb* (say `GetPackSized`): a v5 server answers an
  unknown opcode with a protocol error mid-session, so the client needs a probe
  round trip first, and `Hello` carries only a version, so the probe is itself a
  new verb. It buys mixed-version operation only for the size filter and leaves
  every other verb at v5, two code paths to keep forever.
- *A trailing optional field on `GetPack` without a bump:* a v5 decoder ends with
  `done()` and rejects trailing bytes as `trailing bytes in frame`, a mid-session
  error the client cannot distinguish from corruption, with no way to fall back.
- *A size manifest plus `GetObjects`:* the client would walk all history level by
  level to learn blob ids, ask for sizes through a new verb (a bump anyway), then
  fetch: many round trips for what the server does in one walk.
- *Client-side drop on ingest:* the client downloads every blob and discards the
  large ones. It saves disk and gives the same gap model, but not one byte of
  transfer, which is the point of the feature.
- *A sentinel in the prefix list:* finding 2.

**Cost of the bump.** The server and its clients upgrade together. Every mixed
pair fails closed at the handshake, before any repository access, in both
directions, for `sc+http(s)://` and for ssh remotes alike (an `ssh://` remote
runs the remote host's own `sc serve --stdio` binary, so its version is whatever
that host has installed). The messages are the server's own:

- v6 client, v5 server: `wire protocol error: unsupported protocol version 6
  (server speaks 5)`.
- v5 client, v6 server: `unsupported protocol version 5 (server speaks 6)`, which
  the v5 client prints as `wire protocol error: unsupported protocol version 5
  (server speaks 6)`.

Pinned by `a_v6_client_reports_a_v5_servers_refusal`,
`serve_rejects_a_v5_client_naming_both_versions` and `handshake_rejects_v5_peer`
(the retargeted successor of `handshake_rejects_v4_peer`), plus encode and decode
round trips of `GetPack` with and without a limit and strict rejection of a bad
tag or a v5-length frame.

### 4. Every ref tip is complete; the limit applies to history

The walk exempts blobs reachable from the root tree of each *want* (every ref tip
the client asked for) that match the prefix filter. The limit applies to blobs
reachable only through parent snapshots.

Reason: checkout, `sc switch` between branches and every operation that
materializes a tip need those blobs, and the clone's own initial checkout runs
before any lazy marker exists. A strict limit would make a non-lazy clone fail at
its own checkout with `GapInView`, and a lazy one would fetch the same large
files in a second round trip right after the clone. Skipping large tracked files
at checkout would need a third "tracked but absent" state in status, diff, commit
graft, materialize and the merge engine (the sparse machinery covers paths, not
sizes).

**Trade-off.** The filter saves old revisions of large files and large files only
reachable from history, which is where git's `blob:limit` pays off for binary
assets. It does not skip a large file at HEAD or at any other branch tip, so a
clone with many branches carries each tip's large files. "Reports or lazily fills
large ones" from the issue is therefore met for the history case: an operation
that reaches an old gapped blob fills it by id on a lazy clone and fails with the
gap error otherwise.

**Tips are complete at clone time only (D2).** A later `sc fetch` is limit-aware
(decision 9) but still subtracts the closure of the local tips, so a new tip that
points at an old, gapped blob (a revert) arrives without it. A lazy clone heals that on the
fast-forward or switch (decision 7); a non-lazy one gets the gap error with the
limit clause (decision 6) and `sc backfill <file>` repairs it.

**Ordering (D7).** `walk_snapshots` queues every tip before any parent, so a
tip's exempt walk always runs before a non-tip snapshot's limited one, even when
one tip is an ancestor of another. The `(id, path)` expansion gate then only ever
lets a limited walk skip work an exempt walk already did, never the reverse, and
a blob already `included` is kept without measuring. A tip root tree that equals
an older subtree is expanded at its own `(root, "")` key. Tests: an ancestor tip,
a tip root equal to a subtree of a non-tip, and the walk with the wants in both
orders.

### 5. Scope is explicit; `filter active` has one definition (B1, B2)

- **`Promisor`** holds `Scope` (`AllPaths` or `Prefixes(list)`), `blob_limit:
  Option<u64>` and the origin. `AllPaths` is a clone with a limit and no prefix;
  an empty prefix list means "matches nothing" and cannot say it. Every consumer
  of `matches`/`should_descend`/`prefixes` handles the case (graft, materialize
  bound, sparse refusals, gap hints, verify text, widen), and `widen` on
  `AllPaths` is a no-op, so `backfill <path>` cannot narrow the scope.
- **Persistence.** `.sc/promisor` is unchanged (`origin <url>` then one prefix per
  line). `.sc/promisor-blob-limit` (local, uncommitted) holds `limit <bytes>` and
  `scope all-paths|prefixes`, written before `.sc/promisor` and removed with it
  (`promisor::remove`, so `backfill --all` leaves neither). It is a separate file
  for the ADR-0047 reason: any text is a legal path. A malformed file is an error,
  not an unlimited clone. A limit file with no `.sc/promisor` is leftover state
  and reads as a full clone.
- **An older binary** cannot talk to a v6 server, and locally it reads
  `.sc/promisor` only: a size-only clone has an empty prefix list there, which it
  treats as a degenerate partial clone that matches nothing (gaps everywhere,
  never wrong content), and it ignores the limit file. If it ran `backfill
  <prefix>`, that would add a prefix to `.sc/promisor`; the current binary still
  reads `scope all-paths` from the limit file and keeps the whole-tree scope. If
  it ran `backfill --all`, it would remove `.sc/promisor` and leave the limit file,
  which the current binary ignores.
- **`PackFilter`** is the one definition of "filter active": it exists only when
  `!prefixes.is_empty() || blob_limit.is_some()`. Every `Some(&PackFilter)`
  therefore means a partial transfer, in all of these places, each with a test:
  the server walk and its private-branch handling (`filter_manifest_wants` drops
  manifest wants), the bucket refusal (`BucketTransport::get_pack`, a served
  `--store` over the wire, and a direct `sc+wal://` clone through the CLI), and
  the client's clone, which skips refs whose tip did not arrive.

### 6. Gap record, presentation and repair

- **No new gap record.** Absence is the gap (ADR-0048). Push, verify and gc
  already walk presence (`reachable_objects_partial`) and need no code change;
  tests pin them on a size-limited clone, including the push gap-edge check
  against a destination that lacks the history.
- **Presentation.** `sc clone` prints `partial: blob:limit=<bytes>` (prefixes
  first when both). `sc verify` keeps `partial: N object(s) outside filter
  [...]` with the same bracket text. `GapInView` gains the limit: its message
  names `blob:limit=<bytes>` as a cause beside "an earlier fetch left a gap", and
  `prefix` is the file's own path, not a covering prefix. Gaps found by a merge,
  pick, rebase, session or `sc cat` on a clone with a limit are
  `GapBySize { path, limit }`: "`<path>` was left out of this partial clone
  (blob:limit=<n>); run `sc backfill <path>` to fetch it first". A prefix-only
  clone keeps every old message byte for byte. The limit is named only for a
  missing file in scope; a missing directory (a fetch left it out) is named by its
  path, and a missing root tree points at `sc backfill --all` (merge needs carry
  a tree/blob flag for this).
- **Repair, lazy and online:** nothing to do. `ensure_view`, `sc cat` and the
  ADR-0049 merge fill by id.
- **Repair, otherwise:** `sc backfill <path>` fetches every version of that path
  (backfill sends no limit), and `sc backfill --all` converts to a full clone. No
  `--min-size` form: it would be a second size parser on the repair side with no
  use that `<path>` does not cover.

### 7. A full view must still fill (B3)

`Repo::ensure_view` returned without filling when the sparse view was full, so a
lazy size-only clone, whose view is always full, would have failed on switch,
undo, merge, replay and sessions to a revision with a gapped blob. The guard now
skips only when the clone is not `AllPaths`. For an `AllPaths` clone the fill is
bounded by the one revision being laid out. Tests: switch and undo to a gapped
revision (refused, then filled when lazy), merge, cherry-pick and rebase with a
gapped merge base (the engine fills it by id, or refuses before any write with
the file's own path), and a workspace session on a size-limited clone.

### 8. Interactions

- **Protected content (D6).** The size is the stored object's payload length. A
  protected file's blob is ciphertext, so its size is the plaintext size plus the
  sealing overhead, and a file near the limit can land on the other side of it
  from its plaintext size. Protected and plain blobs follow the same rule. No new
  information leaks: ciphertext length is already visible to anyone who can fetch
  the object.
- **Private branches.** A filtered transfer excludes them (ADR-0044), now under
  any active filter (decision 5).
- **Sealed objects, signatures, transcripts.** Not path-reached blobs; never
  subject to the limit.
- **Sparse and prefix filters.** The prefix decides scope first, the limit prunes
  inside it. A size-only clone leaves `.sc/sparse` empty (a full view). It may
  narrow that view with `sc sparse set` and return to it with `sc sparse set`
  (no prefixes) or `sc sparse disable`: a full view is its starting state, so
  those two refusals apply to prefix scopes only, and the closure is filled
  (lazy) or refused with `GapInView` before anything changes.
- **Push, verify, gc.** Presence-based (ADR-0048).
- **Merge, pick, rebase, ws, work** (ADR-0049/0050). No new engine code; a size
  gap is "asked for" like any other (decision 7).
  Named and concurrent sessions (ADR-0056) hold too: a session records the
  host's view at fork, which for a size-only clone is the full view (`sparse`
  empty), a fork starts at a ref tip so its base is complete, and each harvest
  lands through the same merge. `named_sessions_on_a_size_limited_clone` pins it.
- **Server cost and limits (D5).** The walk measures a blob with `Store::blob_size`
  (streamed through a fixed buffer, hash-verified, never admitted to the object
  cache) and caches each verdict by blob id, so a distinct blob is measured at
  most once per request (a limit of 0 or `u64::MAX` measures nothing). The work
  is bounded by the stored bytes of the distinct candidate blobs; a kept blob is
  read twice (measure, then pack), so the read cost is at most twice that of an
  unfiltered `GetPack`, which already reads every blob into its pack. The filter
  changes bandwidth, not the order of magnitude of the work. Reads are unbudgeted (#233 budgets
  writes), and the filter does not change that: `--max-connections`, `--timeout`
  and the listener limits remain the bounds. A size index on the server is a later
  optimization.

### 9. `sc fetch` carries the recorded limit (#217)

A fetch from the promisor origin sends the limit in `.sc/promisor-blob-limit`
(`GetPack.blob_limit`, already on the wire: no version bump). Blobs of at least
the limit that no fetched ref tip's root tree reaches arrive as gaps, so later
growth is bounded the way the clone was, and every fetched tip is complete
(decision 4's rule, applied to the fetch's wants).

- **Only the limit, never the prefixes.** A fetch stays path-unfiltered
  (ADR-0048), so a prefix+limit clone fetches every path's tips whole and gaps
  history-only large blobs under every path. The sender sees `AllPaths` plus a
  limit, the same shape as a size-only clone.
- **No per-path exemptions.** The first version of this ADR expected a user's
  `sc backfill <path>` to need an exemption so a later fetch would not re-gap the
  file. It does not: backfill fills what exists now; a new version of that file
  that lands at a tip is complete (decision 4), and one that lands only in
  history is a gap exactly like any other history blob, which a lazy fill or
  `sc backfill <path>` repairs again. Nothing already present is ever removed.
- **Opt-out: `sc fetch --no-blob-limit`.** Sends no limit for that one command,
  so the new history arrives whole; the recorded limit and scope stay, and the
  next plain fetch is limited again. Per command, like `--no-transcripts`. It
  does nothing on a clone without a limit and on a full clone. The alternative to
  a flag, `sc backfill --all`, converts the clone for good; the flag covers "pull
  this once in full" without that. Rejected: a `--blob-limit <size>` override
  (a second size parser and a way to widen the recorded limit by accident).
- **Unchanged.** Haves are still the local tips and the sender still subtracts
  their full closure, so a fetch cannot re-send a blob a gapped tip names (the
  D2 revert case stays a `GapInView`/lazy-fill case). Non-promisor remotes are
  unaffected: the origin check runs first and refuses any other remote on a
  partial clone, and a clone with no limit sends `None` as before. A bucket origin
  refuses a limit-bearing fetch (decision 5), though a limited clone cannot be
  made from one, so it takes a hand-edited `.sc/promisor`. Push, verify, gc,
  merge and sessions are presence-based and untouched.
- **Private branches.** A filtered fetch drops manifest wants (decision 5), so
  fetch skips a remote ref whose tip did not arrive instead of writing a dangling
  remote-tracking ref, as clone does. This is a change for a size-limited clone
  that used to receive private-branch ciphertext on fetch; it matches what its
  clone never received. `--no-blob-limit` is an unfiltered fetch, so it does
  receive private manifests and their sealed closures (ciphertext, as any
  unfiltered fetch always did); a later limited fetch leaves such a
  remote-tracking ref at its old value rather than advancing it.
- **Tips and gaps the clone already has.** "Every fetched tip is complete"
  means every blob the fetch sends for it; a tip that names a blob the clone
  already gapped (a revert, a restore of an old version) still arrives without
  it, because the sender subtracts the haves' closure (decision 4, D2). A lazy
  clone fills it on fast-forward or switch; otherwise `GapInView` names
  `sc backfill <file>`. Because every fetch can now add history gaps, this is
  more visible than before; filling it at fetch time (a by-id request for each
  new tip's missing blobs) is not done here and would also contact the origin
  from a command that already does.
- **Server cost.** The want walk receives the haves' closure (`held`) and keeps
  any blob in it without measuring, so a fetch measures only blobs the client
  lacks and a no-op fetch measures nothing (`the_limited_walk_does_not_measure_blobs_the_receiver_holds`
  counts `blob_size` calls). The haves' closure walk
  reads trees and snapshots only. Without that, every fetch would have
  stream-hashed all of history. Otherwise as decision 8.

Tests: `fetch_sends_the_recorded_limit_and_keeps_the_new_tip_complete`,
`no_blob_limit_fetches_history_in_full_and_keeps_the_marker`,
`fetch_on_a_prefix_plus_limit_clone_applies_the_limit_to_every_path`,
`fetch_without_a_recorded_limit_is_unchanged`,
`fetch_with_a_limit_skips_private_refs_it_did_not_receive` and, through the
binary, `fetch_keeps_the_limit_and_no_blob_limit_opts_out` and
`a_bucket_origin_refuses_a_limit_bearing_fetch`; the demo's step 8 repeats it.

### 10. No object-count limit

Closed as rejected, not deferred. Git has no such filter, and no definition
survives: the transfer set is a `BTreeSet` ordered by id, so "the first N
objects" is an arbitrary, server-dependent set, and a client cannot tell a
cut-off object from a missing one by any rule. The deterministic candidates
mean something else and are other features: "the newest N commits" is a shallow
clone (grafted parents, a history-rewrite hazard for merge, push and gc, and a
different ADR), and "the N smallest or largest blobs" is the size filter with a
worse interface. The need behind the issue, bounding a clone, is met by
`blob:limit` and by path prefixes. Reopen only with a concrete use case that
those cannot serve.

## Consequences

- A clone can skip the old revisions of large files, with a complete checkout and
  every ref tip complete.
- Wire version 6; servers and clients upgrade together.
- A new marker file, one new scope case in `Promisor`, one new error variant
  (`GapBySize`) and a field on `GapInView`.
- `sc fetch` sends the recorded limit; `--no-blob-limit` opts out for one fetch (decision 9). No object-count limit (decision 10).

## Open questions

1. A `tree:<depth>`-style filter, if a use case appears.
2. A server-side size index so a limited request need not stream-measure.
