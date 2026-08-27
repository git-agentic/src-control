# ADR-0046: Bucket remotes via an immutable-pack WAL + one CAS'd manifest

- **Status:** Accepted
- **Date:** 2026-08-26
- **Phase:** 36a

## Context

Every remote sc has to date (ADR-0013's local-path transport, ADR-0022's
`ssh://`, ADR-0026's `sc+http://`/`sc+https://`) requires a long-lived `sc
serve` process or a reachable host running one: something has to be up,
listening, and single-writer-locked (`.sc/lock`) to accept a push. That rules
out the "no server to run" deployment shape a plain object store (S3, GCS, a
shared directory) offers — durable, highly available, IAM-native storage with
no process to keep alive. Cursor's public *Git at any scale* write-up (the
"Continuity" architecture) and the `walgit` project built on it
(`docs/research/walgit-evaluation.md`) demonstrate the shape: treat the
bucket itself as the repository, linearized by one small object that every
writer contends for with a compare-and-swap.

We want the same property without the coordinator process: bucket write
access should be equivalent to `sc serve --http`-hosted write access, but the
"server" is whatever bucket API the storage vendor already runs.

## Decision

Add a **bucket remote**: a `Transport` implementation (`BucketTransport` in
`crates/repo/src/bucket_transport.rs`) whose object graph and refs live
entirely in a flat key/value bucket, structured as a **write-ahead log of
immutable packs plus one compare-and-swapped manifest**:

- **Packs are immutable and content-addressed** — every `put_pack`/staged
  `put_object` flush uploads a new pack keyed by its own hash
  (`scl_core::pack::PackWriter`); nothing already in the bucket is ever
  overwritten.
- **The log is parent-linked, not self-numbered.** Each `log/<seq>` entry
  (`walfmt::LogEntry`) records the ref updates it applied and a
  `parent_seq` pointing at the entry it was built on. Readers walk backward
  from the manifest's `head_seq` following `parent_seq` — an entry's own
  claimed `seq` is trusted only for self-consistency (it must match the slot
  it was read from and strictly exceed its parent), never for reachability.
  A losing racer's orphaned append is invisible to every reader by
  construction, not by convention.
- **One manifest is the sole linearization point.** `walfmt::Manifest`
  (`head_seq`, `checkpoint_seq`, `head_branch`) lives at a single well-known
  key, rewritten with `Bucket::put_if_tag` (compare-and-swap on the prior
  read's tag). A push appends its log entry, then CASes the manifest forward;
  a 412-equivalent (tag mismatch) means someone else's push landed first —
  the caller refreshes and reports `Error::NonFastForward`, exactly the
  contract `LocalTransport`/`sc+http://` already give the CLI. **No leader
  election, no lock file, no lease** — the bucket's native compare-and-swap
  primitive is the only coordination the design needs.
- **`objio` is a new leaf crate** exposing the `Bucket` trait (`get`,
  `put_new`, `put_if_tag`, `list`) plus two backends: `DirBucket` (a local
  directory, for tests/demos and the `sc+wal://` scheme) and `S3Bucket`
  (an S3-compatible object store, for `sc+s3://`). It depends on no other
  workspace crate — object-store SDKs (`aws-sdk-s3`) are quarantined here the
  same way `gix` is quarantined in `gitio` and RustCrypto in `crypto`.
  `repo → objio` is a new leaf dependency edge alongside `repo → tlsio`.
- **Two URL schemes, one transport.** `sc+wal://<dir>` opens a `DirBucket` at
  a local path (everything after the scheme is the directory); `sc+s3://
  <bucket>/<prefix…>` splits the first path segment as the bucket name and
  the remainder as a key prefix, opening an `S3Bucket`. Both dispatch through
  the same `BucketTransport`; `BucketUrl::parse` rejects a malformed URL
  (e.g. bare `sc+s3://` with no bucket name) at `sc remote add` time, before
  any network or filesystem call.
- **Partial clone (`--filter`) is refused against bucket remotes.** The WAL
  format has no per-prefix negotiation yet; a filtered clone needs a served
  remote (ADR-0037) until that lands.
- **Untrusted-length guard on reads.** Manifest, log entries, and idx
  metadata are capped at `MAX_OBJECT_SIZE` (256 MiB, ADR-0039) before
  decoding — a hostile or corrupted bucket cannot force an unbounded
  allocation. Pack bodies are read through
  `scl_core::pack::read_object_at_bounded`, which caps both the compressed
  record length and the decompressed output at `MAX_OBJECT_SIZE`, mirroring
  `parse_pack_reader`'s bounded decode — this is the same zstd-bomb guard
  P28 put on every other untrusted transfer path. **This is deliberately a
  different code path from `Store`'s own on-disk reads:** the trusted local
  object store still calls the unbounded `read_object_at`, per ADR-0039's
  explicit split between "objects this process already verified onto local
  disk" (unbounded) and "objects arriving from something we don't control"
  (bounded). A bucket, even one the user configured, is on the untrusted
  side of that line — nothing about owning the credentials that let you
  *write* to a bucket implies the bytes already sitting there are trustworthy
  reads.

**Confidentiality property, unchanged from ADR-0013:** transfer moves objects
verbatim. Encrypted-path blobs (P7) and secret objects travel as ciphertext
through the bucket exactly as through any other transport — a bucket reader
without the recipient key gets bytes it cannot decrypt. What *is* new:
**public (unprotected) content sits in the bucket as plaintext at rest**,
same as it would in a served remote's `.sc/objects/`, so bucket ACLs are the
confidentiality perimeter for public content, not the sc protocol.

## Consequences

- A bucket remote needs no long-running `sc serve` process and no listener
  to secure (ADR-0031/ADR-0040 resource-limit and access-control machinery
  is simply not in play) — the trade is that the bucket vendor's IAM/ACL
  becomes the access-control surface instead.
- Multiple writers can push concurrently with no shared lock file and no
  out-of-band coordination; the manifest CAS is the only serialization
  point, proven under a fleet of racing writers (`bucket_transport.rs` test
  suite).
- The log grows unboundedly with no compaction yet — every open reader walks
  the full parent chain back from `head_seq`. Checkpoint folding (P36b) and
  bucket GC/compaction are deferred (see `ROADMAP.md`).
- `sc serve` still cannot host a bucket as its backing store (P36c) — a
  bucket remote today is written to directly by every `sc push`/`sc fetch`
  client, not brokered through a server process.
- Partial clone, and by extension every partial-clone-only op, is unavailable
  against a bucket remote until per-prefix negotiation is designed.

## Alternatives considered

- **A dumb ref-file-per-branch bucket** (one object per branch pointing at a
  tip, objects written loose). Simpler to implement, but has no atomic
  multi-branch update and no append-only log for a fleet of writers to
  reconcile against — two concurrent pushes to different branches can leave
  the bucket in a state no single writer ever intended, and there is nothing
  to replay to detect or recover from it. Rejected.
- **A `Store`-level backend** (make the object store itself pluggable, with
  a bucket-backed `Store` impl sitting where `.sc/objects/` sits today).
  Reopens the P3 (persistent store) and P8 (packfiles/GC) designs to a third
  backend and blurs the transport/storage boundary those phases established.
  Deferred — the transport-level design keeps `Store` untouched and ships
  faster.
- **Adopt `walgit` itself** as (or in front of) `sc serve`. `walgit` is a
  git-smart-HTTP server over a bucket WAL, not an sc-native peer — using it
  would mean speaking git's wire protocol, which is exactly the git-bridge
  role P18 already covers (`sc remote add --git`). Its design (CAS'd
  manifest as linearization point, checkpoint-plus-log-tail cold start,
  bundle-uri static clones) is the direct inspiration for this ADR's
  structure; see `docs/research/walgit-evaluation.md` for the full
  evaluation and which of its ideas remain deferred (checkpoint folding,
  static-bundle clone offload).

## As built (P36a)

`crates/objio` (leaf crate: `Bucket` trait, `DirBucket`, `S3Bucket`);
`crates/repo/src/walfmt.rs` (versioned, strict, fail-closed WAL encoding:
`Manifest`, `LogEntry`, `RefUpdate`); `crates/repo/src/bucket_transport.rs`
(`BucketTransport`, full `Transport` impl, `BucketUrl` parse/dispatch); wired
into `open_transport` for `sc+wal://` and `sc+s3://`, validated eagerly at
`sc remote add`. 12 tests in `bucket_transport.rs` covering the base
round-trip, racing/fleet pushes, crash-mid-push recovery, and the
`MAX_OBJECT_SIZE` cap. CLI plumbing (remote-add validation, push, clone,
fetch through the real binary) proven in
`crates/cli/tests/bucket_remote.rs`.

## As built (P36b/P36c, 2026-08-26)

**P36b — checkpoint fold.** `walfmt::Checkpoint` (magic `SCWC`; a `seq`, a
sorted branch→tip `refs` list, and a cumulative `packs` hash list, all
strict-decoded fail-closed like every other WAL record) and
`checkpoint_key(seq)` join the existing `Manifest`/`LogEntry` kinds.
`BucketTransport::refresh()` now seeds from `manifest.checkpoint_seq` when
non-zero: it fetches that checkpoint, takes its refs/packs as the fold base,
then walks only the log tail from `head_seq` down to `checkpoint_seq`
(rather than to `0`) before rebuilding the object index over the
checkpoint's cumulative packs plus the tail's. Every checkpoint input is
untrusted like the rest of the WAL and fails closed: a manifest naming a
checkpoint that's absent, a checkpoint object claiming a different `seq`
than the key it was fetched at, and a log chain that steps past
`checkpoint_seq` without landing on it exactly are all refused
(`Error::Wal`), never best-effort recovered. After a successful commit,
`maybe_fold_checkpoint` opportunistically folds once
`head_seq - checkpoint_seq > CHECKPOINT_INTERVAL` (64): it claims
`checkpoints/<head_seq>` via `put_new` (idempotent — a racing folder's
duplicate claim is a no-op, not an error), then CASes the manifest to point
at it. A lost manifest CAS (someone else advanced the WAL meanwhile) drops
the fold silently — a checkpoint is derived data any reader can refold from
the log later, so there is nothing to retry — and the push that triggered
the fold attempt has already durably landed either way.

**P36c — bucket-backed serve.** A new `wire::ServeTransport` enum
(`Local(LocalTransport)` / `Bucket { transport: BucketTransport, tmp:
TempServeDir }`) lets `serve_session` dispatch every verb except the
`GetPack`/`PutPack` pair identically regardless of backend.
`serve_bucket_with_policy(store_url, …)` mirrors `serve_with_policy`
verb-for-verb — same handshake, same `PROTOCOL_VERSION`, same P29/P31
read-only gate and pack-spool caps — but opens a `BucketTransport` instead
of a local repo. `TempServeDir` is an RAII scratch directory under
`std::env::temp_dir()` (created per session, removed best-effort on drop)
standing in for a local repo's `.sc/tmp/`, since a bucket has no scratch directory of
its own — this keeps the ephemeral-mode zero-residue invariant intact for
bucket-backed serve too. `sc serve --http`/`--stdio` gained `--store <url>`:
`path` remains the serve **home** (`.sc/` — tokens, TLS identity/pins,
scratch), while served content routes to the bucket at `<url>` instead of
the home's own object store. A malformed `--store` URL is rejected via
`BucketUrl::parse` before any bind (`run_serve`'s fail-fast check, mirroring
`run_remote`'s). Proven by `two_disposable_instances_serve_one_bucket_with_strict_consistency`
and `read_only_floor_holds_in_store_mode` in
`crates/repo/src/http_transport.rs` (two independent `sc serve --http
--store` server instances, each with its own serve home, observe each
other's pushes to the shared bucket with no propagation delay — the
manifest-CAS strict-consistency contract from P36a, now exercised end to
end over HTTP) and
`serve_store_serves_a_bucket_and_second_instance_sees_pushes` in
`crates/cli/tests/bucket_remote.rs` (the same property across two real,
separately-spawned `sc` **processes**).

This supersedes the two now-stale Consequences bullets above about
checkpoint folding and `sc serve` being unable to host a bucket as its
backing store — both are built as of P36b/P36c.
