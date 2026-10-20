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
   transcripts. Bucket remotes (`sc+wal://`, `sc+s3://`) never serve them:
   `BucketTransport::get_pack` walks reachability only, so a fetch or clone
   from a bucket delivers no transcripts or transcript signatures whether or
   not the flag is given, and a plain fetch does not change that. For `push`
   the flag still works: a normal bucket push uploads and stores the
   transcripts (they are simply never served back), and `--no-transcripts`
   skips that upload. The serving gap is tracked in #229.
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
  object the remote already holds, so a remote that received the tombstone by
  push before trusting the signer keeps it inert.
- **sender:** the over-send for a transfer set includes the tombstones of its
  snapshots that have an indexed signature, with those signatures. An
  unsigned (local-only) drop is never sent. Fetching from the dropper (or a
  push that moves the ref) propagates the drop. A peer that still holds the
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
untrusted is ignored and not recorded. A fetching peer retries it on its next
fetch. A push-only or served remote has no retry: it already holds the object,
so a later push does not send it again and nothing re-runs the check, and the
drop stays inert there even after the signer is trusted (tracked in #230).
Configure
`[signers] trusted` on a remote before the first drop is pushed to it. Any key under `[signers] trusted` can hide transcripts on every peer that
trusts it, and make that peer's gc reclaim the bodies. `GetObjects` still
serves a dropped body until gc sweeps it, and a peer that still holds the
body re-sends it on a later transfer, which restarts its grace window. All of
this follows from drop not being erasure.

Trade-offs. Trust is local configuration, not repository content, so a fresh
clone ignores tombstones until its operator trusts the signer and fetches
again (a clone of a store that already honored the drop never receives the
body in the first place). Trust is checked at ingest, not retroactively, so removing a signer
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
Retention is local protection only. The sender selects tombstones through the
snapshots of the transfer set, and a snapshot gc has removed is never in it,
so a stale peer that still lists the body is not told about a drop whose
snapshot the dropper has since collected. Sending every retained tombstone on
every transfer would close that, at the cost of one object per drop per fetch
for receivers that cannot use it; deferred to #230, together with the
push-only remote limit above (a tombstone rejected on arrival is never
re-evaluated there).

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
