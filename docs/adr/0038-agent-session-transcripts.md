# ADR-0038: Agent session transcripts as CAS objects

- **Status:** Proposed
- **Date:** 2026-07-09
- **Phase:** P30 (candidate — after P29 sc+http access control closes the security horizon;
  slot decided in the brainstorm, D7)
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
Recipient set comes from a `[transcripts]` section in `recipients.toml`
(default: full recipient set + escrow). Before sealing, the P5 scanner
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

Surface: `sc ws harvest --transcript <path|auto>` attaches a workspace's
session transcript to the snapshot its landing produced (`auto` probes
well-known agent transcript locations relative to the checkout);
retroactive `sc transcript attach <ref> <file> [--agent <name>]`;
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
  writer (attachment is a claim; signing transcript ids — a
  `"sc-transcript-sig-v1"` domain — is the natural extension, spec
  decision); secrets echoed into a transcript remaining readable to
  *authorized* transcript recipients (scan-and-warn mitigates, rotation
  remedies); content quality or truthfulness of the recorded session.
