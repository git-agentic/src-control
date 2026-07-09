# Phase brainstorm — Agent session transcripts as CAS objects (P28 candidate)

**Date:** 2026-07-09
**Status:** Brainstorm (feeds a spec + Proposed ADR-0038)
**Prior art:** [Entire](https://entire.io/) (`entireio/cli`, MIT, Go, ~4.6K stars)

## The problem

src-control's provenance chain is identity-deep but not intent-deep. P22
signatures answer *who* created a snapshot and make history rewriting
detectable; nothing anywhere records *why* a change exists. For
agent-produced code that "why" is concrete and capturable: the prompts,
tool calls, and decisions of the session that produced the diff. Today
that context evaporates at harvest — `sc ws harvest` lands a merge and
the conversation that motivated it is gone.

Entire has validated demand for exactly this: it hooks into agent CLIs
(Claude Code, Codex, Cursor, Gemini, OpenCode, Copilot, Factory Droid),
captures the session transcript, and pairs it with commits as
"checkpoints" on a dedicated git branch (`entire/checkpoints/v1`). It is
a recorder bolted onto git. Its architecture also exposes the gaps a
*native* implementation can close:

1. **Visibility inheritance.** Checkpoint transcripts inherit repo
   visibility — a public repo publishes every prompt. Their mitigation is
   "push the checkpoint branch to a different repo," a topology
   workaround, plus best-effort regex redaction that they themselves
   caveat (shadow branches may hold unredacted content).
2. **No integrity.** Transcripts are ordinary branch content; nothing
   binds a transcript to the commit it claims to describe, and either
   side can be rewritten independently.
3. **Ref-namespace pollution.** A metadata branch that must be excluded
   from normal fetch/merge/CI flows by convention.

We already own the machinery that fixes all three: an envelope-encryption
stack (Phase 2 / P7), a CAS-object side-metadata pattern with a gc-rooted
index and zero-wire-change transfer (P22 signatures), and agent sessions
as a first-class lifecycle (P13/P20) that gives us a *natural capture
point* Entire has to approximate with per-agent hooks.

## Design space

### Where does a transcript live?

- **(a) CAS object, indexed on the side — proposed.** New object kind
  `TAG_TRANSCRIPT = 6`, mirroring `TAG_SIGNATURE = 5`: snapshot ids
  untouched, retroactive attachment natural, dedup free, rides existing
  packs with zero wire changes, `.sc/transcripts` index gc-rooted so
  transcripts of dead history are pruned with it.
- **(b) Inside the snapshot encoding.** Changes every id, makes
  retroactive attachment impossible — rejected on ADR-0002 grounds, the
  same reasoning that killed it for signatures.
- **(c) A dedicated branch of transcript files (Entire's model).**
  Portable to git, but pollutes the ref namespace, versions metadata as
  if it were code, and gets none of our encryption or gc semantics.
  Rejected as the primary store; kept as an *export target* (below).
- **(d) Oplog attachment.** The oplog is local, per-repo bookkeeping; it
  doesn't travel on clone/fetch, which defeats the point (team-visible
  provenance). Rejected.

### Encryption stance

The defining choice, and where we beat Entire outright: **transcript
bodies are always sealed** — Phase 2 envelope (fresh random DEK,
XChaCha20-Poly1305, DEK wrapped per recipient via X25519), never
plaintext in the CAS. Convergent encryption (P7) is wrong here: dedup of
transcripts is worthless (every session is unique) and prompts are
exactly the low-entropy, guessable content the convergent
confirmation-attack caveat warns about. The `TAG_SECRET` shape — nonce,
ciphertext, wraps inline in the object — is the closer precedent than
P7's split envelope, since there is no dedup to preserve.

Consequences of always-sealed:

- A public/unauthorized clone carries transcripts as ciphertext. Entire's
  visibility problem does not exist by construction.
- Redaction becomes defense-in-depth instead of the only line: run the
  P5 scanner over the plaintext *before* sealing and **warn** (not
  reject — the body is sealed, and refusing to record the session would
  destroy provenance because an agent echoed an env var).
- Recipient set: a `[transcripts]` section in `recipients.toml`
  (defaulting to the full recipient set + escrow), so P11 escrow and P17
  rewrap semantics extend naturally. Open question below on whether
  rewrap should cover transcript wraps in the same sweep.

### Capture mechanics

- **Session-integrated (primary).** P20 sessions are the natural seam:
  agents run inside `sc ws` checkouts we created, with env we injected
  (`SC_WORKSPACE`). `sc ws harvest --transcript <path|auto>` attaches the
  workspace's transcript to the snapshot its landing produced. `auto`
  discovers well-known agent transcript locations (Claude Code JSONL,
  etc.) relative to the checkout — the moral equivalent of Entire's hook
  matrix, but pull-based at harvest instead of push-based per turn, so no
  per-agent hook installation is required for the MVP.
- **Retroactive (mirror of `sc sign`).** `sc transcript attach <ref>
  <file> [--agent <name>]` for anything the session flow didn't cover —
  including humans attaching design notes. Retroactivity falls out of the
  CAS-object choice for free.
- **Live per-turn checkpointing (Entire's granularity).** Deferred.
  Requires hook installation into each agent CLI and a daemon-ish
  accumulation story; the MVP records per-harvest, which matches our
  merge-granular integration model.

### Read/consume surface

- `sc transcript show <ref> [--identity <key>]` — decrypt and render.
- `sc transcript list [<ref>]` — index walk.
- `sc log` grows a per-commit transcript marker alongside the P22
  signature marker (presence only; no decryption on the log path, and
  status is precomputed batch-style — the BrokenPipe lesson).
- `sc verify` composition: a transcript is itself CAS content, so a
  *signed* snapshot whose transcript index entry survives gives
  tamper-evident pairing; signing the transcript id itself is an open
  question below.

### Interop (the Entire bridge)

`sc export --to <git>` currently drops non-git-representable metadata
with a count (signatures precedent). Option: `sc export
--transcripts=entire` additionally emits an Entire-compatible
`entire/checkpoints/v1` branch so teams using Entire's viewer see
sc-authored sessions. Decrypt-on-export under an identity, which makes
the visibility trade-off *explicit and chosen* rather than inherited.
Deferred beyond the MVP but shapes the transcript body format choice: we
should store the body in (or losslessly convertible to) Entire's
session/checkpoint JSON layout rather than inventing a gratuitously
different one.

## Open questions (for the spec)

1. **Size discipline.** Transcripts are KBs–MBs, not signature-sized.
   P22's over-send-on-every-transfer fix (the refetch Critical) is cheap
   for signatures but not obviously for transcripts. Options: same
   over-send (bounded by P25 streaming so RAM is fine, bandwidth pays),
   a has-check round-trip, or transcript transfer as opt-in/opt-out
   (`fetch --no-transcripts`). Leaning: over-send correctness first,
   measure, then add the knob.
2. **Rewrap scope.** Should P17 `sc rewrap` re-seal transcript wraps in
   the same one-commit sweep? Leaning yes — transcripts indexed at the
   tip's reachable history are exactly the "standing seals" rewrap
   exists to cut over. But wraps live inside the object (Secret-shaped),
   and objects are immutable — rewrap would mint *new* transcript objects
   and re-point the index, unlike the policy-side re-wrap P7 enjoys.
   This is the strongest argument for reconsidering a split envelope
   (wraps in the index file, not the object) despite the Secret
   precedent. Must be settled in the spec.
3. **Multiple transcripts per snapshot.** A P20 harvest lands N
   workspaces cumulatively — one transcript per landing snapshot is
   natural. But an amend/rebase mints new ids with no transcripts
   (P22's "new object is a new claim" stance says: correct, re-attach
   deliberately). Confirm the same stance.
4. **Signed transcripts.** `SignatureObj` signs snapshot ids with a
   domain-separated message. A second domain string
   (`"sc-transcript-sig-v1"`) signing transcript ids would give attested
   reasoning — nobody in the market has this. Cheap if done in the same
   phase; decide whether MVP or fast-follow.
5. **Retention/deletion.** Transcripts may need to die before their
   snapshots (compliance, embarrassment). gc prunes with dead snapshots,
   but a live snapshot with an unwanted transcript needs `sc transcript
   drop <ref>` — an index-side removal (object becomes unreachable,
   pruned at next gc). Does a drop need a P16-style tombstone so a merge
   from an old clone doesn't resurrect the index entry? Probably yes —
   same shape as revocation resurrection.
6. **Phase slotting.** P27 (partial clone) closes the approved P25–P27
   horizon. This proposal is the anchor candidate for the *next* horizon
   — agent/workspace depth — alongside the deferred named/multiple ws
   sessions, which it composes with (named sessions → named transcript
   streams).

## MVP cut proposal

`TAG_TRANSCRIPT = 6` (bytes-only in core, quarantine held) + sealed body
+ `.sc/transcripts` gc-rooted index + zero-wire-change pack transfer with
idempotent index dedup + `sc ws harvest --transcript` + `sc transcript
attach/show/list` + `sc log` marker + P5 scan-and-warn before seal + git
export drops-with-count. Deferred: per-turn checkpoints, Entire-format
export, signed transcripts (unless cheap), transfer opt-out knob,
drop-tombstones.

Demoable outcome: `demo/run_transcript_demo.sh` — run a session, harvest
with a transcript, clone to a second repo, prove the transcript rode the
pack, prove a keyless clone gets ciphertext only (positive control per
the P7 demo discipline), decrypt with an authorized identity, gc a
deleted branch and prove the transcript died with it.
