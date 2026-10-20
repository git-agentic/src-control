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
   transcripts. Bucket remotes (`sc+wal://`, `sc+s3://`) do not either:
   `BucketTransport::get_pack` walks reachability only, so a fetch or clone
   from a bucket delivers no transcripts or transcript signatures whether or
   not the flag is given, and a plain fetch does not change that. (A push to a
   bucket still honours the flag by not uploading them.) That gap is tracked
   in #229.
5. **Interaction with transcript-drop tombstones (PR #226).** A tombstone is
   an empty-envelope `Transcript` object, so `--no-transcripts` drops it like
   any other transcript: a receiver keeps showing a dropped transcript after a
   `--no-transcripts` fetch until a plain fetch brings the tombstone in.
   Whether tombstones should be exempt is for #226 to decide; this change
   does not special-case them.
