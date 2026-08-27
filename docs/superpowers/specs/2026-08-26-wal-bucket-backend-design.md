# Design: WAL + manifest-CAS object-storage backend for sc (P36)

- **Date:** 2026-08-26
- **Status:** Approved design, pre-implementation
- **Origin:** walgit/Cursor-Continuity evaluation in
  `docs/research/walgit-evaluation.md` (slot (c): borrow the coordination
  layer, keep sc's sealing)
- **ADR to write at build time:** ADR-0046

## Goal and use cases

Let an S3-compatible bucket be an sc remote — and let `sc serve` run as a
disposable cache in front of the same bucket — using immutable
content-addressed writes plus one compare-and-swapped manifest as the only
consensus mechanism. No database, no leader, no coordinator process.

The MVP must prove two use cases:

1. **Team sharing, zero ops.** A team (or one person on several machines)
   collaborates through one bucket: push/fetch/clone with multi-writer safety
   via manifest CAS; sealed content stays sealed at rest. Acceptance: two
   writers race a push — one lands, the other cleanly retries; nothing
   corrupts; an unauthorized bucket reader gets only ciphertext for
   protected/private/secret content.
2. **Agent fleets at scale.** Many parallel agents share state through the
   bucket with high-frequency small pushes and cheap cold starts
   (checkpoint + log tail). Acceptance: N concurrent writers hammer the WAL
   with no coordinator and no corruption.

Hosted-service ops machinery (compaction, leases) is explicitly deferred.

Both front doors ship over one bucket format:

- **Direct-bucket transport:** `sc remote add origin sc+s3://bucket/prefix`
  — clients read/write the WAL and CAS the manifest themselves using
  object-store credentials. No server anywhere.
- **Bucket-backed `sc serve`:** stateless/disposable instances; clients keep
  speaking sc's native protocol (wire `PROTOCOL_VERSION` 4) and never see
  the bucket.

## Bucket format (the load-bearing contract)

One repository per bucket prefix. Four key kinds; only the manifest is
mutable:

| Key | Mutability | Content |
|---|---|---|
| `manifest` | CAS-rewritten only | Tiny versioned binary: format version, head log seq, latest checkpoint seq |
| `log/<seq>` | Immutable | Parent-linked chain entries: `PUSH {pack ids, ref updates old→new}`, `CHECKPOINT {folded-through seq}` |
| `packs/<blake3>.pack` | Immutable | Existing P8 pack format, unchanged, keyed by pack checksum |
| `checkpoints/<seq>` | Immutable | Full ref-map fold at `<seq>`, so cold start = checkpoint + log tail |

Rules:

- **The manifest CAS is the entire consensus.** S3: conditional PUT with
  `If-Match` ETag (`If-None-Match` on create). Local-dir backend: atomic
  rename compare. GCS-native (deferred) would use generation preconditions.
- **Readers trust only what the manifest chain references.** Any other key
  is unreferenced garbage (crash debris) — harmless, swept by future
  compaction (deferred).
- **Format version is strict.** Unknown manifest/log/checkpoint version →
  refuse, fail closed (format-break discipline mirrors the canonical-
  encoding invariant in CLAUDE.md).

## Crates and the dependency rule

- **New leaf crate `objio`** quarantines the S3 SDK, exactly parallel to
  `tlsio`: it depends on no workspace crate. Public trait `Bucket`:
  `get` (conditional, returns bytes + tag), `put` (immutable,
  if-none-match), `put_if_match`, `list`. Two impls:
  - S3-compatible (AWS, MinIO, Cloudflare R2 via endpoint override).
  - Local-directory (tests, demos, `sc+wal://<path>`).
- **Credentials:** the SDK's standard chain (env, config, IMDS). sc grows no
  credential surface — same stance as the git bridge (ADR-0028).
- **WAL format + sync logic live in `repo`**, behind the existing
  `Transport` seam from ADR-0013 (which anticipated exactly this backend).
  New workspace edge: `repo → objio`, like `repo → tlsio`.
- **CLI schemes:** `sc+s3://bucket/prefix` (S3-compatible) and
  `sc+wal://<path>` (local backend, demos/tests).
- CLAUDE.md gains the quarantine sentence: object-store SDKs stay in
  `objio`; reach for a function there, never for the SDK elsewhere.

## Data flow

**Push.** Compute missing objects by ref-frontier reachability (existing
push logic) → upload pack (idempotent: keyed by checksum) → write
`log/<head+1>` with if-none-match (seq taken → try next) → CAS the manifest
with the fast-forward gate re-checked against the freshly read state.
CAS conflict → re-read manifest, re-verify fast-forward, retry with bounded
backoff; on exhaustion fail loudly (never silently drop — house invariant).
A crash at any step leaves only unreferenced keys; the commit point is
atomic at the manifest.

**Fetch.** Conditional GET of the manifest (tag unchanged → up to date in
one round trip) → walk the log **by parent links from the manifest head**
back to the last-seen entry → download referenced packs → ingest through
the existing P25 two-pass atomic-after-verify path → update remote-tracking
refs. Seq numbers are claims, not truth: a CAS loser may abandon an entry
at a claimed seq (it re-reads and writes a fresh entry with the correct
parent before retrying the CAS), so the chain may have holes and orphan
siblings. Readers never scan seq ranges; only the parent chain from the
manifest head is authoritative, and off-chain entries are garbage.

**Clone / cold start.** Manifest → latest checkpoint → tail the log →
download packs. Never replays the whole log.

**Checkpoints.** Opportunistic, coordinator-free: any client that observes a
log tail longer than a threshold (default 64 entries, one tunable
constant) after its own push folds the
refs and writes `checkpoints/<seq>`, then CASes the manifest's checkpoint
pointer. Concurrent folds are harmless — both are valid; the CAS picks one;
the loser's checkpoint is unreferenced garbage.

## Bucket-backed `sc serve`

`sc serve --http|--https` gains a bucket-backed store mode. Local disk is a
pure cache of immutable packs (content-addressed, so trivially correct);
freshness is one conditional manifest GET per request — reads are strictly
consistent, there is no "eventually". Pushes from native-protocol clients go
through the same WAL commit path as direct-bucket clients. Instances are
disposable: kill one mid-push and nothing corrupts (the client retries; the
bucket never saw a manifest CAS). Existing access control and limits are
untouched: bearer tokens (P29), TLS via `tlsio` (P32), connection/timeout/
pack-size limits (P31), `MAX_OBJECT_SIZE` (P28).

## Security boundaries

- **Sealed content needs zero new work.** Protected-path ciphertext
  (P7/P33), private-branch sealed objects (P34), and wrapped secrets (P2)
  travel and rest in the bucket verbatim as ciphertext — ADR-0013's
  "confidential by construction" property, unchanged.
- **Public content is plaintext at rest in the bucket.** Bucket ACL is its
  perimeter — the same trust model as any remote clone. Gets an explicit
  THREAT-MODEL.md entry.
- **Everything read from the bucket is untrusted input:** BLAKE3
  verification on every object (id == hash), `MAX_OBJECT_SIZE` caps on
  every length, strict ref-name validation on log/checkpoint contents (P28
  parity), strict versioned decode failing closed on unknown versions.
- Direct-bucket mode's write authorization IS bucket-write permission;
  fast-forward gates are cooperative, not adversarial (a hostile bucket
  writer can already destroy data). Server-fronted mode keeps the P29 token
  model for adversarial clients.

## Error handling

Per-crate `thiserror`: `objio::Error` (network, auth, precondition-failed,
not-found); new `repo` variants (`CasConflict` internal-retried, surfaced
only on retry exhaustion; format-version refusal; garbage/chain-integrity
errors). CLI converts to `anyhow` with `?` as everywhere else.

## Testing

- **Cross-backend contract suite** both `Bucket` impls must pass
  (conditional semantics, CAS atomicity, list ordering) — borrowed from
  walgit's store-contract idea.
- **Two-writer race:** concurrent pushes; exactly one CAS wins; loser
  retries and lands; final refs and reachability consistent.
- **Crash injection:** abort between each push step (after pack, after log
  entry, before/after CAS) — repository always intact, only unreferenced
  garbage remains.
- **Fleet hammer:** N threads pushing small commits concurrently against
  the local-dir backend; no coordinator, no corruption, all commits land.
- **Cold start:** checkpoint + tail reconstruction equals full-log replay.
- CI runs the local-dir backend; MinIO parity runs behind an opt-in env
  flag. Tests that touch disk clean up and assert the path is gone (house
  rule).

## Phasing

- **P36a:** `objio` + bucket format + `BucketTransport` clone/fetch/push,
  race + crash tests green.
- **P36b:** checkpoints + log-tail cold start.
- **P36c:** bucket-backed `sc serve`.

**Deferred (record in ROADMAP → Deferred):** bucket compaction/gc, leases,
static-bundle clone offload (CDN-able clones), native GCS backend.

## What we deliberately do not copy from walgit

Plaintext-at-rest with perimeter-only auth. sc keeps end-to-end sealing;
we borrow only the coordination layer (WAL + manifest CAS + checkpoint
cold start).
