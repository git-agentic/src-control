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
  Over-send-on-transfer is correct but potentially heavy; a
  `--no-transcripts` fetch knob is anticipated as a fast-follow if
  measurement warrants (logged, never silent).
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

- **drop:** write the tombstone object, append the drop line, then remove the
  live entry. A crash between steps leaves the drop line present, so the
  transcript is still hidden (fail-closed).
- **fetch/clone/push receive:** `index_incoming` records an incoming
  tombstone as a drop and never indexes a transcript whose id is already
  dropped, so a pack from a peer that still has the transcript cannot
  restore it, in either arrival order.
- **sender:** the over-send for a transfer set includes the tombstones of its
  snapshots, so fetching from the dropper (or a push that moves the ref)
  propagates the drop. A peer that still holds the transcript object hides
  it as soon as it ingests the tombstone. `push` still skips all I/O when
  the remote tip already equals the local tip, so a drop alone does not push,
  the same pre-existing behavior as a retroactive attach.
- **merge, cherry-pick, rebase:** transcripts are not part of snapshots, so
  history operations neither carry nor restore them; only transfer can
  reintroduce one, and that path is covered above.

### gc

The dropped transcript is no longer rooted, so its object falls to the
ordinary loose-object grace window and repack like any other unreachable
object, and its own signature entry is pruned with it (`signatures::gc_prune`
keys off the same `reachable` set). Tombstones are the opposite: gc roots
every tombstone object and keeps every drop line, **even when its snapshot is
dead**, as P16 keeps revocation tombstones forever. They are load-bearing
against a later fetch of the same history from a stale peer, and cost about
100 bytes each. This is the one place the drop index outlives its snapshot;
no transcript content does.

### `sc verify`

`sc verify` checks snapshot signatures only and never inspects transcripts,
so it is unchanged. A dropped transcript's own signature is no longer
reported anywhere (it is pruned by gc, hidden before that).

### Limits

- **Drop is not authenticated.** Anyone who can write to a store can drop any
  transcript, the same trust level as attaching one. Signed drops are a
  follow-on.
- **Drop is not erasure.** Peers that never receive the tombstone keep the
  sealed body, and a recipient who already decrypted it keeps the plaintext.
  Rotation is not erasure here either.
- **Older peers** that predate this change see a tombstone as an unopenable
  transcript and do not honor it. Upgrade before relying on drop across a
  shared remote.
- `sc export` still counts only transcripts that are not tombstones; a
  dropped body that gc has not swept yet is still counted as dropped history.
