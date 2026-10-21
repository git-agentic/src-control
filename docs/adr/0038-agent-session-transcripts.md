# ADR-0038: Agent session transcripts as CAS objects

- **Status:** Accepted
- **Date:** 2026-07-09
- **Phase:** 30
- **Builds on:** ADR-0002 (content addressing), ADR-0008/0010 (envelope
  encryption), ADR-0017 (secret scanner), ADR-0023/0030 (agent
  workspaces/sessions), ADR-0032 (side-metadata CAS-object pattern)
- **Prior art:** Entire (`entireio/cli`) — agent-session checkpoints as a
  dedicated git branch; validates demand, and its gaps (transcripts
  inherit repo visibility, no commit↔transcript integrity, ref-namespace
  pollution) are exactly what a native design closes.
- **Spec:** `docs/superpowers/specs/2026-07-09-p28-session-transcripts-brainstorm.md`
  (decision-complete; grilling resolved every open tension into D1–D7)

## Brainstorm resolution (2026-07-09)

The grilling session settled the decisions this ADR left open (see the brainstorm's
"Decisions locked" section for the reasoning):

- **Wrap location — Secret-shape confirmed** over the split-envelope alternative this ADR
  flagged as "the main open design tension" (D1): wraps live inside the object; a recipient-set
  change mints a new transcript object + re-points the index. Chosen for natural zero-wire
  transfer and `TAG_SECRET` reuse, accepted because transcripts are per-session and rarely
  rewrapped.
- **Signed transcripts — in the MVP, opt-in** (D2/D3): reuse `SignatureObj` + `.sc/signatures`
  with a `"sc-transcript-sig-v1"` domain; `--sign` at attach + retroactive `sc transcript sign`.
- **Index — one-to-many, additive, no silent carry under amend/rebase/merge** (D4).
- **Access lifecycle deferred** — seal fixed at attach; no rewrap/grant/revoke for transcripts
  in the MVP (D5). **Deletion (`sc transcript drop` + resurrection tombstone) deferred** (D6).
  **`--transcript auto` probing deferred** — MVP takes an explicit `<path>` (D6).

## Context

P22 made provenance identity-deep: signatures bind *who* to a snapshot
and make rewrites detectable. Nothing records *why* — for agent-produced
changes, the session (prompts, tool calls, decisions) that motivated the
diff is discarded at harvest. The P20 session lifecycle already owns the
capture point: agents run in checkouts we forked, under env we injected.
Recording the conversation next to the landing it produced is the missing
half of provenance, and the market (Entire) has proven people want it —
as a git sidecar, with plaintext transcripts and best-effort redaction.

## Decision

Transcripts are CAS OBJECTS — a new kind, `TAG_TRANSCRIPT = 6`, bytes-only
in `crates/core` (the crypto quarantine holds):

```
Transcript { snapshot: ObjectId, agent: String, session: String,
             nonce, ciphertext, wrapped_keys: Vec<WrappedKey> }
```

The body is **always sealed** — Phase 2 envelope (fresh random DEK under
XChaCha20-Poly1305, wrapped per recipient via X25519), the `TAG_SECRET`
shape rather than P7's convergent split-envelope: transcript dedup is
worthless and prompts are precisely the guessable content the convergent
confirmation-attack caveat excludes. Plaintext transcripts never enter
the CAS, so an unauthorized or public clone carries ciphertext only —
Entire's visibility-inheritance problem cannot occur by construction.
Recipient set is the full `[recipients]` set + escrow from `recipients.toml`
(sealing to the whole recipient pool, not a caller-chosen subset — there is no
separate `[transcripts]` section and no `--to` flag in the MVP). Before sealing, the P5 scanner
runs over the plaintext and **warns** (never rejects — the body is
sealed, and refusing to record would destroy provenance because an agent
echoed a credential); redaction is defense-in-depth, not the boundary.

Snapshot ids are untouched; retroactive attachment is natural;
attachment is deliberate, mirroring P22's stance that a new object
(amend/rebase/merge result) is a new claim — transcripts are not carried
forward silently. A local gc-rooted index (`.sc/transcripts`,
snapshot → transcript ids) provides lookup and reachability; gc drops
entries whose snapshot died, so transcripts never retain — or outlive —
dead history. Transfer needs ZERO wire changes: transcripts ride the
existing pack format (P25 streaming keeps large bodies bounded-RAM);
senders over-send indexed transcripts for the transfer set with
idempotent index dedup on the receiver — adopting the P22 refetch fix
from day one rather than rediscovering it. `sc clone` reindexes from a
full post-copy object scan. Git boundary drops transcripts with a
`transcripts_dropped` count (signatures precedent).

Surface: `sc ws harvest --transcript <path>` attaches a workspace's
session transcript to the snapshot its landing produced (`--transcript auto`
probing of well-known agent transcript locations is deferred — see the
Brainstorm-resolution note above); retroactive
`sc transcript attach <ref> <file> [--agent <name>] [--sign]`;
`sc transcript show <ref> [--identity <key>]` and `sc transcript list`;
`sc log` gains a presence marker beside the signature marker (index-only,
status precomputed for the whole history before printing — the P22
pipe-safety discipline).

## Consequences

- Provenance becomes intent-deep: `sc log` shows who signed a snapshot
  AND that its motivating session is preserved; `sc transcript show`
  replays the why. Combined with P22 this exceeds what Entire offers
  (their transcripts are unauthenticated branch content).
- Sealed-by-default inverts the industry default: sharing a transcript
  with a wider audience is an explicit grant/rewrap act, not a
  repo-visibility accident.
- New store growth axis: transcripts are KB–MB, not signature-sized.
  Over-send-on-transfer is correct but potentially heavy; the
  `--no-transcripts` opt-out (see the addendum below) is that knob.
- Wraps living inside the object mean recipient cutover (P17 `sc rewrap`)
  cannot re-wrap in place — it must mint replacement transcript objects
  and re-point the index. Acceptable for the MVP (transcripts are
  per-session, not long-lived standing seals); flagged as the main open
  design tension in the brainstorm (a split envelope — wraps in the
  index — would trade Secret-shape precedent for cheap rewrap).
- Deletion semantics deferred: `sc transcript drop <ref>` (index-side
  removal + gc) and its resurrection-on-merge tombstone question (P16
  shape) are follow-on scope.
- `crates/crypto` gains no new primitives; `core` gains a bytes-only
  object kind. Both quarantines hold.

## Alternatives considered

- **Dedicated transcript branch (Entire's model):** portable to git but
  pollutes the ref namespace, versions metadata as code, inherits repo
  visibility, and carries no integrity binding to the commits it
  describes. Rejected as the store; retained as a possible *export
  target* (`sc export --transcripts=entire`, deferred) for interop with
  Entire's tooling.
- **Transcript inside the snapshot encoding:** changes every id and
  forecloses retroactive attachment; rejected on ADR-0002 grounds — the
  same reasoning as ADR-0032.
- **Oplog attachment:** the oplog is local bookkeeping and does not
  travel on clone/fetch; team-visible provenance is the point. Rejected.
- **Plaintext bodies with scanner-gated redaction:** Entire's model;
  rejected on the layered-hygiene principle (ADR-0017) — redaction is
  best-effort by their own admission, and we own an envelope stack that
  makes the failure mode structurally impossible instead.
- **Convergent encryption (P7 machinery) for the body:** preserves dedup
  we don't need at the cost of a confirmation attack on low-entropy
  prompt content; rejected — Phase 2 random-DEK envelope fits.

## Threat model honesty

- **Defends:** transcript disclosure to unauthorized clones (sealed
  always); loss of agent context at harvest; transcripts outliving the
  history they describe (gc-coupled index).
- **Does NOT defend:** a fabricated transcript attached by an authorized
  writer — attachment alone is a claim. Opt-in signing (`sc transcript
  --sign` / `sc transcript sign`, over the `"sc-transcript-sig-v1"` domain)
  upgrades it to an *attested* claim binding a specific identity, but an
  unsigned transcript from an authorized writer is still just a claim.
  Also does not defend: secrets echoed into a transcript remaining readable to
  *authorized* transcript recipients (scan-and-warn mitigates, rotation
  remedies); content quality or truthfulness of the recorded session.

## Addendum: `--no-transcripts` on fetch, clone and push (2026-10, #211)

`sc fetch`, `sc clone` and `sc push` accept `--no-transcripts`. Decisions:

1. **Client-side only, no `PROTOCOL_VERSION` bump.** `GetPack` has no field a
   receiver could use to say "no transcripts", and the sender over-sends
   indexed transcripts unconditionally. So the opt-out lives where the
   client already has control:
   - `push`: the client builds the outgoing set, so it leaves out indexed
     transcripts and the signatures keyed by them. This saves bandwidth.
   - `fetch` / `clone`: the server still sends them. The receiver
     hash-checks every record in pass 1 of `ingest_pack_file` as usual (a
     hash check, not signature verification), then pass 2 does not write
     `Transcript` objects, nor a signature whose target is a transcript
     dropped from the same pack. This transfer therefore writes and indexes
     no transcript. It saves disk and exposure (no ciphertext, no index
     entry), **not** bandwidth. A server-side skip would need a new
     `GetPack` field and a version bump; it is a deferred follow-on in
     `ROADMAP.md`.
2. **Per command, not persisted.** A clone made with `--no-transcripts`
   records nothing; a later plain `sc fetch` brings every indexed transcript
   in (the sender re-sends all of them each time, because they are never
   subtracted via the have-set). The same re-send means a `--no-transcripts`
   fetch also drops a new signature over a transcript the receiver already
   holds; the next plain fetch brings it in. A plain `sc push` after a
   `--no-transcripts` push carries them only once the branch moves again,
   because `push` returns early when the remote tip already equals the local
   tip (the same limit a retroactive attach has).
3. **Sealing and integrity unchanged.** Bodies stay sealed whether or not they
   travel. Snapshots, trees, blobs and the snapshot's own signatures transfer
   and are hash-checked exactly as before. Index entries are left out with the
   objects, so no `.sc/transcripts` or `.sc/signatures` entry created by this
   transfer points at a transcript the repo does not hold.
4. **Remotes where the flag does nothing.** Git remotes never carry
   transcripts, so the flag is a no-op there. Bucket remotes (`sc+wal://`,
   `sc+s3://`) serve transcripts since #229 (see the bucket addendum below),
   so the flag works on them like on any native remote: fetch and clone
   discard what the bucket over-sends, and push skips the upload.
5. **Interaction with transcript-drop tombstones (second addendum below,
   #212).** A drop tombstone is a `Transcript` object with an empty envelope,
   so `--no-transcripts` treats it like any other transcript: the pack is
   hash-checked, then the tombstone and its drop-digest signature are not
   written, and `index_incoming` never sees them, so no `.sc/transcript-drops`
   line is recorded by that transfer. This breaks none of the drop
   invariants: nothing is indexed that is not held, gc only roots what is
   stored, and a transcript that was already dropped is never sent by the
   dropper in the first place. The consequence is the same as for any
   transcript: a receiver that still holds a transcript keeps showing it
   after a `--no-transcripts` fetch, even though the sender dropped it, until
   a plain fetch brings the tombstone in and the receiver's trust list
   honors it. A clone made with the flag from a store that dropped the
   transcript holds neither. On `push`, the flag likewise leaves tombstones
   (and their signatures) out, because `indexed_transcript_ids_for` returns
   them with the transcripts; a drop pushed with `--no-transcripts` does not
   reach the remote.

## Addendum: `sc transcript drop` and the drop tombstone (issue #212)

Closes the deferral in D6 and the "Deletion semantics deferred" consequence.

### Tombstone format

A drop is recorded as a **drop tombstone: a `Transcript` object with an
empty `nonce`, `ciphertext` and `wrapped_keys`**, `agent` set to the marker
`sc-transcript-drop-v1`, `snapshot` copied from the dropped transcript, and
`session` set to the hex id of the dropped transcript. A real transcript is
always sealed to at least one recipient, so it never has an empty ciphertext
or wrap list; the two shapes cannot collide. `core` exposes
`Transcript::drop_tombstone` / `Transcript::dropped_id` (bytes only, no new
crypto).

Reusing `TAG_TRANSCRIPT` is deliberate. A new object tag would be refused by
peers that predate it and force a `PROTOCOL_VERSION` bump (the P34 route). A
tombstone shaped as a transcript decodes everywhere and rides the existing
pack format, the existing `snapshot -> transcripts` over-send and the
existing receiver seam (`index_incoming`) with no wire change.

### Semantics: grow-only set, not an epoch register

P16 needs a last-writer-wins epoch because a recipient can be revoked and
then legitimately re-granted. A transcript cannot come back under the same
id: transcript ids are content hashes over a randomly sealed envelope, so
re-attaching a body mints a new id. Each `(snapshot, dropped id)` pair
therefore has exactly one transition, live to dropped, and the register
collapses to a grow-only set of dropped ids. A concurrent drop and keep
always resolve to dropped (the P16 tie rule, fail-closed). There is no
undrop; to restore a body, attach it again.

### Local index and convergence

A second local file, `.sc/transcript-drops`, holds one
`<snapshot-hex> <tombstone-hex> <dropped-hex>` line per tombstone. It is a
derived cache like `.sc/transcripts`: `sc clone` rebuilds it with the same
full-store scan (`reindex`). The live index is read through the drop set, so
a dropped id is invisible to `list`, `show`, `sc log` markers and the
over-send, whatever order the lines landed in.

- **drop:** write the tombstone object (and its signature, if signing), then
  append the drop line. The live `.sc/transcripts` line is not rewritten:
  every read filters it through the drop set and gc purges it. A crash before
  the drop line leaves only an unrooted tombstone object and the transcript
  stays visible until the drop is retried.
- **fetch/clone/push receive:** `index_incoming` records an incoming
  tombstone as a drop only after the checks in "Who may drop" pass, and never
  indexes a transcript whose id is already dropped, so a pack from a peer
  that still has the transcript cannot restore it, in either arrival order.
  A tombstone that fails the checks stays an inert object. A fetching peer
  re-evaluates it whenever it is sent again (for example after the operator
  adds the signer to the trust list and fetches). `push` never re-sends an
  object the remote already holds; a remote that received the tombstone by
  push before trusting the signer re-evaluates it from
  `.sc/transcript-pending` (#230, delivery addendum below).
- **sender:** the over-send of every transfer includes each retained
  tombstone that has an indexed signature, with its signatures (selection
  widened by #230, see the delivery addendum below; it was the tombstones of
  the transfer set's snapshots). An unsigned (local-only) drop is never sent.
  Fetching from the dropper (or a push that moves the ref) propagates the drop. A peer that still holds the
  transcript object hides it once it ingests an honored tombstone. `push`
  still skips all I/O when the remote tip already equals the local tip, so a
  drop alone does not push, the same pre-existing behavior as a retroactive
  attach.
- **merge, cherry-pick, rebase:** transcripts are not part of snapshots, so
  history operations neither carry nor restore them; only transfer can
  reintroduce one, and that path is covered above.

### Who may drop

P16 does not authenticate its tombstones: a revoke is a commit on a branch,
and the operator decides to merge that branch, so the merge is the trust
boundary. A drop tombstone has no such gate, because it arrives with a plain
fetch or push. Honoring it blindly would let any peer that can write to a
remote hide, and let gc reclaim, any transcript. The P16 trust model
therefore does not carry over, and drops are authenticated with the P22
machinery instead.

- **Local drop:** always honored by the store that ran it.
- **Signed drop:** `sc transcript drop <id> --identity <key>` signs a
  domain-separated digest, `BLAKE3("sc-transcript-drop-v1" || tombstone id)`,
  with the existing transcript signing functions. The signature object is
  keyed by the tombstone id in the shared `.sc/signatures` index so it rides
  with the tombstone. A plain transcript signature over the bare tombstone id
  does NOT authorize a drop. That matters because an older binary indexes a
  tombstone as a live transcript, and its bulk `sc transcript sign <ref>`
  would sign it by trusted signers who never meant to drop anything. No new
  crypto primitives. A v1 identity is refused before anything is stored.
- **Receiving a tombstone** (`index_incoming`, clone `reindex`) honors it
  only if all of these hold: the tombstone's snapshot exists locally; if the
  dropped transcript is held locally it is a real transcript on that same
  snapshot; and a valid signature over the drop digest comes from a key
  under `[signers] trusted` in the receiver's `.sc/recipients.toml` (the set
  `sc verify` already uses). Missing or malformed trust config trusts nobody.
  If the dropped transcript is not held yet, the snapshot check is the only
  structural one, so a trusted signer can drop an id ahead of its arrival.
- **Unsigned or untrusted tombstones are inert:** never recorded, so they
  cannot hide a transcript and gc never reclaims a body because of them.

Operational consequences. A tombstone that arrives while its signer is
untrusted is not recorded as a drop. A fetching peer retries it on its next
fetch. A push-only or served remote re-evaluates what it holds (delivery
addendum below, #230), so trusting the signer later is enough. Any key under `[signers] trusted` can hide transcripts on every peer that
trusts it, and make that peer's gc reclaim the bodies. `GetObjects` still
serves a dropped body until gc sweeps it, and a peer that still holds the
body re-sends it on a later transfer, which restarts its grace window. All of
this follows from drop not being erasure.

Trade-offs. Trust is local configuration, not repository content, so a fresh
clone ignores tombstones until its operator trusts the signer and fetches
again (a clone of a store that already honored the drop never receives the
body in the first place). Trust is checked when a tombstone is evaluated (at ingest, or on a later open or ingest for a held one, #230), not retroactively, so removing a signer
later does not undo drops already recorded. "Trusted signer" is the same
project-level authority that can sign commits; it is deliberately not
narrowed to the transcript's recipients or its own signer, because
transcripts are usually unsigned and recipient ids (X25519) do not map to
signing keys. An unsigned local drop does not propagate.

### gc

The dropped transcript is no longer rooted, so a loose body falls to the
ordinary loose-object grace window (`--prune-expire`) like any other
unreachable object. A body an earlier gc already packed gets no grace: the
repack leaves it out of the new pack and deletes the superseded packs, so the
next gc reclaims it whatever `--prune-expire` says. Its own signature entry
is pruned with it (`signatures::gc_prune` keys off the same `reachable` set).
Tombstones are the opposite: gc roots
every tombstone object and keeps every drop line, **even when its snapshot is
dead**, as P16 keeps revocation tombstones forever. They are load-bearing
against a later fetch of the same history from a stale peer, and cost about
100 bytes each. This is the one place the drop index outlives its snapshot;
no transcript content does.
Retention alone protects only the dropper. Delivery of a tombstone whose
snapshot gc has collected is the #230 addendum below.

### `sc verify`

`sc verify` checks snapshot signatures only and never inspects transcripts,
so it is unchanged. A dropped transcript's own signature is no longer
reported anywhere (it is pruned by gc, hidden before that).

### Limits

- **Drop is not erasure.** Peers that never receive the tombstone keep the
  sealed body, and a recipient who already decrypted it keeps the plaintext.
  Rotation is not erasure here either.
- **Mixed versions.** A binary that predates this change indexes a tombstone
  as a live transcript: it shows in `sc transcript list` and the `sc log`
  marker, and `sc transcript show <ref>` fails on it with a not-a-recipient
  error, because the empty envelope has no wraps. Upgrade every peer before
  using drop on a shared remote. Such a peer's bulk `sc transcript sign` may
  also sign the tombstone id; that signature is over the bare id, not the drop
  digest, so it never authorizes a drop.
- `sc export` still counts only transcripts that are not tombstones; a
  dropped body that gc has not swept yet is still counted as dropped history.

## Addendum: bucket remotes serve transcripts and signatures (issue #229)

Before this change `BucketTransport::get_pack` built its pack from
reachability only. A push to a bucket uploaded signatures, transcripts and
signed drop tombstones (the sender seam runs on the pushing side), but a
fetch or clone never got them back: snapshot signatures were lost too, so a
signed snapshot cloned from a bucket was `Unsigned` and `sc verify --require`
failed. (Confirmed by test before the fix; the issue left this open.)

- **No format change, no `PROTOCOL_VERSION` bump.** A bucket keeps no
  `.sc/signatures` or `.sc/transcripts` index, and its pack idx carries no
  object kind. `get_pack` therefore rebuilds the sender seam from the packs
  the manifest chain already names: it decodes each on-chain pack once
  (`parse_pack_reader`, same hash and `MAX_OBJECT_SIZE` guards as any
  untrusted pack), keeps only `{id, target}` for signatures and
  `{id, snapshot, is-tombstone}` for transcripts, and applies the same rule as
  `LocalTransport::build_pack_tempfile`: over-send every transcript attached
  to a snapshot in the want or have closure, plus signatures over those
  snapshots and over the chosen transcripts and tombstones, never subtracting
  them via the have set. A tombstone is sent only if a signature covers it
  (an unsigned drop is never pushed anyway).
- **Trust stays on the receiver.** The bucket cannot judge a tombstone, so it
  serves what it holds; `index_incoming` and clone `reindex` still honor a
  tombstone only for a signer under `[signers] trusted`. A transcript the
  bucket still holds next to its tombstone is served too, and a bucket cannot
  filter it the way `LocalTransport` filters through its drop set. So unlike a
  clone of a local origin that honored the drop (which never receives the
  body), a clone from a bucket receives the body and the tombstone together;
  the receiver never indexes a dropped id once it trusts the signer, and until
  then shows the transcript. Withholding the body whenever a signed tombstone
  exists would let anyone with bucket write access hide transcripts from
  peers.
- **`--no-transcripts`** needs nothing bucket-specific: the receiver-side skip
  in `ingest_pack_file` applies to the over-sent transcripts, tombstones and
  their signatures. Snapshot signatures still arrive.
- **Cost.** The scan downloads and decodes every on-chain pack body once per
  `BucketTransport` (leaf results cached per pack hash; packs are immutable),
  including packs the transfer does not otherwise touch, and every fetch
  (also `--no-transcripts`, which still needs the snapshot signatures) pays
  it. That is the same order as the existing `get_pack`, whose have/want
  reachability walks already fetch every pack that holds a reachable commit
  or tree, but it is up to a second download of each pack per fresh transport
  (each CLI fetch). Peak RAM is one pack body plus one decoded object (the
  walk's cached body is released before the scan). A persisted per-pack leaf sidecar
  would avoid the decode; deferred in `ROADMAP.md`.
- `sc serve --store` uses the same `get_pack`, so served-bucket fetch and
  clone get the same behavior.

## Addendum: tombstone delivery after gc and late trust (issue #230)

Two gaps in the drop addendum above, closed with no `PROTOCOL_VERSION` bump,
no new object kind and no change to the trust gate. A tombstone is still
honored only when a drop-digest signature verifies under a key in the
receiver's `[signers] trusted`; unsigned drops still never leave the dropper.

### 1. Send retained signed tombstones whose snapshot is in the set or gone

`indexed_transcript_ids_for` (used by `LocalTransport::build_pack_tempfile`
for fetch/clone/serve and by `push_opts`) no longer selects tombstones only
through the transfer set's snapshots. A retained tombstone that has an indexed
signature is also sent when its snapshot is **no longer held** by the sender,
which is exactly the gc case: the dropper cannot resolve a stale peer's have
to a collected snapshot, so no have-based match can find it. A tombstone whose
snapshot is still held but outside the transfer set (an unpublished branch)
stays home. The bucket sender keeps its rule (snapshot in the want or have
closure): a bucket never collects snapshots, so the gap cannot arise there.

Cost and limits:

- One tombstone (about 100 bytes) plus its signatures per qualifying drop, per
  transfer. Nothing is capped: capping would silently withhold a drop from a
  peer, and the set only grows by explicit drops (the dropper's own and ones
  it honored from trusted signers). It is never subtracted via the have set,
  like transcripts and signatures.
- **Disclosure.** A tombstone names its snapshot id, the dropped transcript id
  and (through its signature) the signer's public key. Any peer that fetches
  from or is pushed to by the dropper now learns these for every drop whose
  snapshot the dropper has since collected, including a snapshot that peer
  never had. Before this change the same peer received them only for drops on
  snapshots in the transfer. Ids are hashes; the body stays sealed. Drops on
  snapshots still held but unpublished are not sent.
- A receiver that has the drop recorded skips it (one read of the drop file
  per ingest). One whose snapshot is unknown or whose signer is untrusted
  stores the small object and ignores it.
- A push sends only tombstones the remote lacks (`has_object`), so repeat
  pushes cost one existence check per drop. `--no-transcripts` still leaves
  tombstones and their signatures out of both directions (#228).

### 2. Index only signatures that verify, and remember held tombstones

**Signature index hygiene (the crowding fix).** A tombstone id depends only on
its snapshot and transcript ids, so a writer can target it before it exists,
and a pack is ordered by object id, so a writer can grind junk signature ids
that sort ahead of the real one. `signatures::index_incoming` and `reindex`
therefore index a signature only if its target is held and it verifies under
the key it names, in the domain of its target kind (snapshot domain for a
snapshot, transcript domain for a transcript, the drop digest for a
tombstone). Forged and dangling signatures are never indexed, so a
`LocalTransport` or `sc serve` sender never forwards them (it sends indexed
signatures) and gc never keeps them. A bucket is the exception: `get_pack`
forwards the on-chain signatures it finds unverified, and the receiver's
ingest filters them. Side effect: a received
signature that fails to verify no longer turns a snapshot `Invalid`; it is
simply absent (`Unsigned`, which `--require` also rejects). A signature
indexed before this change is read as before.

**Former residual limit (#257, resolved).** A signature that verified under a
key the attacker controlled was still indexed, so a writer could add more
than 256 of them over a predictable tombstone id, ahead of the real one, and
the capped read in `tombstone_honored` never reached the trusted signer's
signature (a denial of the drop on every peer that ingested them, never an
honored one). Resolved by keying the index per (target, signer); see the #257
and #260 addendum below.

**Pending index.** A push-only or served remote holds the tombstone from an
earlier push, so `push` (has-object) never re-sends it and `index_incoming`
never re-runs.

- `.sc/transcript-pending`: one tombstone object id per line, newest last.
  `index_incoming` appends a tombstone that **has an indexed signature**, whose
  **snapshot is held**, and that failed `tombstone_honored`. Unsigned
  tombstones and ones whose snapshot is absent are not kept: the latter can
  only hide a body that arrives later, and a fetching peer is re-sent it
  anyway. A signature that arrives later, in a transfer without the tombstone,
  is also a trigger: `index_incoming` looks up the tombstone it covers (each
  distinct target once per batch, at most 1024 per batch). A derived cache
  like `.sc/transcript-drops`: losing it only loses the retry.
- `.sc/transcript-pending-trust`: a fingerprint of the trusted-signer key set
  the pending entries were last judged under. The re-check runs only when the
  current set differs (`trust_changed`: one `exists` check and one config read
  when nothing is pending or nothing changed, no lock, no store access). A
  snapshot arriving later is not a trigger, because only entries whose
  snapshot is held are kept.
- `reevaluate_if_trust_changed` runs `reevaluate_pending`, which re-runs the
  unchanged `tombstone_honored` on each entry, records the ones that now pass
  as drops and removes them from the file, forgets entries whose object is
  gone or no longer a tombstone, and keeps the rest (an unreadable object
  stays). It runs at `Repo::open` (under the lock `open` holds), at
  `LocalTransport::open` (what `sc serve` and local-path remotes use; it takes
  the repo lock itself, only after `trust_changed` is true, and skips if the
  lock is busy, so a served remote does not take the exclusive lock per
  connection) and before the indexing step of every ingest except a
  `--no-transcripts` one. All are best effort: a failure never fails an open
  or a transfer, and the fingerprint is saved with the pass's outcome
  (`<fingerprint> <failed passes>`), computed from the same trusted-signer map
  the entries were judged with. A pass in which an object failed to read does
  not count as done and is retried by the next trigger, at most
  `MAX_RETRIES` (3) times per trusted set, so an unreadable object cannot make
  every open or served connection take the exclusive lock forever; a changed
  trusted set resets the count.
- **Lost-update safety.** `append_drop` appends one short line with
  `O_APPEND` and `fsync` instead of rewriting the file, so concurrent
  ingests (the HTTP serve path holds no repo lock) cannot lose a drop line. A
  pending entry is removed only after its drop line is appended. The pending
  file itself is still a read-modify-write: two concurrent ingests can lose a
  pending entry. That costs a push-only remote the retry for that tombstone
  (trust the signer before the push, or have a fetching peer re-send it), but
  never a recorded drop and never the rooting of one: gc roots every drop
  line. (The pending file and the other indexes were unlocked
  read-modify-writes when this addendum was written; the index lock below,
  #260, serializes them.) `O_APPEND` atomicity is
  a local-filesystem guarantee (none on NFS). `append_drop` starts on a new
  line when the file ends in a torn line.
- **Bounded.** The file is a FIFO ring of 1024 ids. A writer who pushes many
  signed tombstones evicts older entries, so a genuine pending entry can be
  lost on a push-only remote; a fetching peer is re-sent every qualifying
  tombstone (part 1). The work per trigger is at most 1024 tombstone reads
  plus the per-tombstone signature work above. A pack's batch is
  deduplicated and cut to the newest 1024 before it touches the file; the
  file stays under about 70 KiB. Eviction never makes a drop honored.
- **gc** roots pending tombstones like drop lines, so they survive the
  loose-object sweep, and the signature index keeps their (verified)
  signatures (`transcripts::gc_prune` runs before `signatures::gc_prune`; a
  test pins it). An unreadable pending file fails gc rather than reading as
  empty.
- Trust is checked at evaluation time and is not retroactive: removing a
  signer later does not undo a recorded drop.

### Other accepted limits

- Ordering across separate pushes on a push-only remote. A tombstone that
  arrives before its snapshot is not kept as pending, and a signature that
  arrives before its target is not indexed (the target must be held); a later
  push resends neither, because the remote already has the object. Within one
  pack (the normal case: snapshot, transcript, tombstone and signature travel
  together) the order does not matter, and a fetching peer is re-sent
  everything. The signature-driven lookup of a late signature is capped at
  1024 distinct held targets per batch, so a pack that signs more held objects
  than that before the tombstone's signature can skip it.

- Verifying a signature before indexing costs one Ed25519 check per incoming
  signature object, linear in the pack size like hash-checking its records. A
  per-ingest verification budget was considered and refused: it would drop
  legitimate signatures from a large fetch (a long signed history), which is a
  worse failure than the cost.

- Re-evaluation scans `.sc/signatures.v2` once per trigger (time proportional to
  the file, memory proportional to the pending targets).
- A bucket serves every signed tombstone-shaped object it holds, and its
  contents are whatever writers uploaded; receivers still judge each one.
- A tombstone a repo already held when it upgraded to this build has no
  pending entry, so a push-only remote in that state still needs the signer
  trusted before the drop is pushed (a fetching peer is re-sent it and
  recovers). A full-store scan would fix it but is unbounded, so it is not
  done.
- `Repo::open` and `LocalTransport::open` may update the derived drop indexes
  when the trusted-signer set changed; failures there are ignored, not
  reported. No key material is involved.
- `push` still returns early when the remote tip equals the local tip, so a
  drop alone does not push (unchanged). Clone `reindex` rebuilds drops from
  the store (verifying signatures as above) and does not touch the pending
  file.

## Addendum: signature index per signer, and the index lock (issues #257, #260)

Two hardening follow-ups to the #230 delivery work, with no `PROTOCOL_VERSION`
bump, no new object kind and no change to the trust gate.

### 1. The signature index holds one slot per (target, signer) (#257)

`.sc/signatures` kept every verified signature over a target. A signature
made by a key the attacker controls verifies, so a writer could index 256 or
more of them over a tombstone id ahead of the trusted signer's, and the capped
scan in `tombstone_honored` never reached it. Now:

- **Format.** `.sc/signatures.v2`, one `<target> <sig-object> <signer>` line
  per signature (signer = 32-byte Ed25519 key, hex). An append is a no-op when
  the `(target, signer)` slot is taken: the first entry keeps it. This loses
  nothing: Ed25519 is deterministic, so a signer has one valid signature per
  target, and for any target kind only one signing domain is acceptable (see
  `signatures::acceptable`), so a signature in the wrong domain is never
  indexed and cannot occupy a slot. The local signing paths hold the same
  bar: `append_index` refuses a signature that is not acceptable, so a plain
  transcript signature over a drop tombstone cannot take the owner's slot
  ahead of the real drop signature. Appends write only the new lines
  (`O_APPEND`, under the lock) and never rewrite the file, so a large index
  costs a read, not a rewrite and fsync, while the lock is held. Entries are bounded by the distinct
  signers, not by the number of signature objects.
- **Honoring.** `tombstone_honored` iterates the trusted signers, looks up the
  one signature each holds over the tombstone (`signatures::SigIndex`), reads
  that object and verifies the drop digest. At most one read and one
  verification per trusted signer; signatures by other keys are never read.
  `MAX_SIG_READS` and `MAX_SIG_VERIFIES` are gone. The index loader keeps
  per-signer entries only for trusted signers, so a flood costs a file scan,
  not memory.
- **Why a new file name.** An older binary parses exactly two columns and
  skips any other line, then rewrites the file on its next append from the
  lines it understood, so appending a third column to `.sc/signatures` would
  make an older binary drop every new entry. The new binary leaves the old
  file alone and uses `.sc/signatures.v2`.
- **Migration.** `signatures::migrate_legacy` imports `.sc/signatures` into
  the v2 file once (when v2 is absent): it reads each signature object for
  its signer and runs `acceptable` again, because an index written before #230
  may hold forgeries, and one naming a trusted key would take that signer's
  slot. Entries that do not verify, or whose object is gone, are dropped, so a
  snapshot that was `Invalid` only through such an entry reads `Unsigned`
  (the #230 behavior). It runs at `Repo::open` and `LocalTransport::open`
  (best effort), and is mandatory before any v2 write (`append_entries`) and
  before gc prunes, which fail rather than start a v2 file, or root nothing,
  while legacy entries are unread. The old file is not deleted or rewritten.
  `reindex` rebuilds v2 from the store and ignores the legacy file.
- **Downgrade.** Do not run an older binary's `sc gc` on a repo this build
  has signed in or ingested into. An older gc roots only the legacy
  `.sc/signatures`, so it sweeps the signature objects that only
  `.sc/signatures.v2` lists, and the v2 entries then dangle. Otherwise an older
  binary keeps using `.sc/signatures`: signatures it adds after the upgrade are
  in the object store but not in v2 (`sc clone` rebuilds the index; there is no
  standalone reindex command), and signatures made by this build are not
  visible to it.
- **Failed migration.** `Repo::open` and `LocalTransport::open` ignore a
  failed import (for example a read-only `.sc/`), and until it succeeds the
  index reads as empty: signatures read `Unsigned` and a served repo forwards
  none. The trust re-evaluation does not run while an import is pending, so it
  cannot record the trust as judged against an empty index. Every writer and
  gc retry the import and fail rather than proceed.
  An object that is gone or will not decode is dropped from the import like
  any entry that does not verify, so one bad object does not block it; only a
  transient I/O error fails it. Every pack ingest retries the import too
  (best effort, at most two stats when nothing is pending), including a pack with no
  signature in it, so a served repo does not leave legacy entries unread until
  its next open (#270).
- **Forwarding.** `indexed_signature_ids_for` (sender seam for fetch, clone,
  serve and push) returns the indexed signatures, which are now one per
  (target, signer), so a sender forwards at most one signature per signer per
  target. `sc verify` / `sig_status` read all entries of a snapshot, as
  before: the index is no longer growable past one per key.
- **Limit.** Distinct attacker keys still get one slot each. Their cost is one
  line, one object and one Ed25519 check per key at ingest (as in #230); they
  can no longer stop a drop from being honored, because honoring never reads
  them.
- **`reindex` and a concurrent ingest (#270).** The clone's post-clone
  `signatures::reindex` scans and verifies without the index lock and makes a
  few unlocked catch-up passes. It then takes the lock, lists the store once
  more and verifies only what appeared since, plus the signatures it refused
  only because their target was not held yet (an ingest stores a pack's
  objects one by one), before it rewrites the file. An ingest stores its
  objects before it appends, so one that lands during the scan is picked up by
  a later pass and one that lands after the rewrite appends on top of it. No
  append is lost, and the lock is never held across the bulk of the
  verification. The relisting sees loose objects (what ingest writes), not
  packs another handle wrote since the store opened.
- **`transcripts::reindex` and a concurrent ingest (#274).** The same shape
  for the transcript index and the drops file. The scan, and every tombstone
  signature check, run without the index lock, followed by up to four
  unlocked catch-up passes. Under the lock it lists the store once more and
  judges only what is new: transcripts whose snapshot was not held when they
  were listed, tombstones not honored yet (their signature or the signer's
  trust may have landed since) and tombstones whose dropped body is new. Each
  pass re-reads the trusted set and the signature index, and a changed set
  discards the earlier verdicts, so only trusted signers are ever honored.
  The rewrite of `.sc/transcripts` and `.sc/transcript-drops` then happens
  under the lock, so an ingest that landed during the scan is relisted and one
  that lands after appends on top; the pending ring is untouched. Unlike the
  signature rebuild, the locked listing first reloads the pack index
  (`Store::reload_packs`), so objects another handle packed since this store
  opened count as well; it costs one read of the `.idx` files, once, under the
  lock. This is defensive: today only `gc` writes packs, and it needs the
  repo lock the cloning `Repo` holds. (`signatures::reindex` still relists
  loose objects only.) The locked pass reads the signature index only when a
  trusted signer exists and some tombstone needs a verdict, and refuses a
  tombstone no trusted signer has signed before any object read.

### 2. The index lock (#260)

Serve-path ingest (`LocalTransport::put_pack` and the wire/HTTP `ingest_from`)
updated the derived indexes without the repo lock, so two connections, or a
connection racing a local `sc` command, could lose a signature, transcript or
pending entry to a read-modify-write race.

Decision: **a dedicated short-lived index lock, `.sc/index.lock`**
(`lock::with_index_lock`), distinct from `RepoLock`. Alternatives considered:

- *`RepoLock` around the post-ingest updates.* `RepoLock` is try-once and a
  local `sc` command holds it for its whole life, so a push would fail
  `Locked` for the duration of any open command, and two concurrent pushes
  would fail each other. Rejected: it changes `Locked` behavior for serving.
- *Append-only indexes with `O_APPEND` lines.* Appends do not lose each other,
  but gc prune, `reindex` and the pending ring (removal, FIFO eviction) are
  rewrites that still race an append, so a lock is needed anyway. Rejected as
  not smaller.

Design:

- An advisory `flock` (`File::try_lock`) on a file that is never removed. The
  OS releases it when the holder dies, so there is no stale-lock breaking.
  Threads of one process conflict too (separate open files). Reentrant per
  thread, so a nested critical section reuses the held lock.
- **Bounded wait**: polls up to 30 seconds, then `Error::IndexBusy` (a distinct
  error: its message must not tell anyone to delete the lock file, which would
  let two holders lock different inodes). The sections it guards are single file updates, not command
  lifetimes.
- **Lock order**: the index lock is a leaf. Code may take it while holding
  `RepoLock` (a local command, `LocalTransport::open`'s re-evaluation) and
  never takes `RepoLock` or waits on anything else while holding it.
  `update_ref` takes `RepoLock` after the ingest has returned, so the two
  cannot deadlock; tests drive `put_pack`-path ingests and `update_ref` from
  threads together.
- **Atomic groups**: an ingest takes the lock once around its signature and
  transcript index updates (its Ed25519 checks run before the lock, so a large
  pack does not lengthen the hold), and gc once around its transcript and signature prunes
  (the signature prune relies on the transcript prune having rooted the
  transcript ids), so neither can interleave with the other's half.
- **Covered**: every read-modify-write or rewrite of `.sc/signatures.v2`,
  `.sc/transcripts`, `.sc/transcript-drops` (the `O_APPEND` line and
  `reindex`'s rewrite), `.sc/transcript-pending` and its trust state: the
  appends, `gc` prune, `reindex`, `note_pending` and the whole
  trust-change re-evaluation pass. Readers take no lock (writes are atomic
  renames or single appended lines).
- **Unchanged**: `RepoLock` and its `Locked` behavior for local commands. A
  local command never fails because an ingest holds the index lock, nor the
  reverse.
- A failure to get the lock (a holder busy for more than 30 seconds) fails
  that ingest after its objects are stored. The client sees an error, but a
  retried push sends only objects the remote lacks, so the objects of that
  ingest stay unindexed on that remote until a reindex (`sc clone` of it). This
  is the old loss window, now reachable only after the wait; the longest
  holders are the one-time legacy import and the trust-change re-evaluation
  (at most 1024 tombstones).
- `flock` is advisory and only as good as the filesystem's support for it
  (like the `O_APPEND` note above, not guaranteed on NFS).
