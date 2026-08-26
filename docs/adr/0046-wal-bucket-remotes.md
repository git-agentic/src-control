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
