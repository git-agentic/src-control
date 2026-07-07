# Roadmap horizon P16–P20 — design

**Date:** 2026-07-07
**Status:** Approved (roadmap-level; each phase gets its own focused
brainstorm → spec → plan when it becomes active)

## Goal of this horizon

Finish the confidentiality story end to end before pushing for adoption:
P15 shipped protected merge & replay but documented a real boundary — a
prefix-rule `sc revoke` is reversed by merging any branch created before
the revoke. The project's headline claim (per-file permissions that hold)
should not carry a documented bypass into an adoption push. So this
horizon leads with durable revocation, makes cutover practical at org
scale, then unlocks hosted-Git interop, polishes the human history-editing
workflow, and finally extends the agent pillar.

## Phases

### P16 — Revocation tombstones / rule narrowing (ADR-0026)

Make `sc revoke` on a protected-path prefix durable across merges.

Direction: protection rules stop being a plain recipient set that merges
by union. They become grant/revoke **events** with enough ordering
(per-prefix epoch or DAG causality — decided in the phase brainstorm)
that merge unions the events and derives the effective recipient set.
Concurrent grant + revoke resolves revoke-wins (fail-closed, consistent
with P15's union philosophy: nothing silently *widens* access).

Open questions reserved for the phase brainstorm:

- Epoch counter vs. DAG-causality semantics for event ordering.
- Whether tombstones are ever GC'd (likely not — they are tiny and
  load-bearing).
- Escrow interaction (does a revoke event exclude the escrow key? No —
  escrow is policy, appended at seal time).
- This is almost certainly a rules-format break: existing
  `PROTECTED`-rule encodings change, so ids of snapshots embedding rules
  change. Treat per CLAUDE.md's format-break rule (update tests, call it
  out loudly).

Demoable outcome: the exact ADR-0025 boundary scenario — branch, revoke
on main, merge the pre-revoke branch — ends with the recipient still
revoked, and future commits under the prefix do **not** seal DEKs to
them. Proven by a demo script.

### P17 — Bulk re-wrap + multiple escrow keys (ADR-0027)

Make recipient/escrow cutover practical at org scale.

One command (working name `sc rewrap`, shape decided in the phase
brainstorm) re-wraps every secret and every protected prefix to the
current recipient/escrow sets in one operation — closing P11's
one-at-a-time limitation. Escrow grows from a single break-glass key to
a managed list with add/remove/rotate.

Constraints: pure composition of existing `seal`/`open` + P11 rotate
machinery — `crates/crypto` does not change. The operation is
oplog-recorded and undoable. `secrets::require_recipients` guards every
new seal path (established footgun).

Demoable outcome: change the escrow key, run one command, every entry in
`secret list` / protected-prefix listing is sealed to the new set.

### P18 — Network Git remotes (ADR-0028)

`sc fetch`/`push` against hosted Git (GitHub) over https and ssh.

A transport swap underneath P10's marks-map translation core, which
ADR-0018 explicitly anticipated. `gix` network features stay quarantined
in `crates/gitio`. The main open design area is auth: ssh-agent
passthrough, https tokens/credential helpers. Scope guard: no sc-native
HTTP transport here (that remains deferred) — this is Git protocol only.

Demoable outcome: `sc remote add origin git@github.com:…`, fetch, merge,
push — the pushed commits visible on github.com.

### P19 — History-editing polish (ADR-0029)

`sc amend`, stop-and-continue rebase (`--continue`), `cherry-pick
--abort`, and merge-commit replay with mainline selection.

Rides the P14/P15 replay core, and lands **after** P16 so the rule-merge
semantics it must honor are settled — nothing built here gets reworked.
All new ref-movers are oplog-recorded and undoable, matching P14's crash
discipline (ref update is the atomic commit point).

Demoable outcome: extended `demo/run_history_demo.sh` covering an
interrupted-and-resumed rebase and an aborted cherry-pick.

### P20 — Agent sessions + auto-merge (ADR-0030)

`sc ws fork` … `sc ws harvest` as durable sessions across invocations,
plus auto-merge of clean workspace results onto an integration branch —
closing both explicit P13 scope cuts.

Session state lives under `.sc/` (durable by design, like refs);
ephemeral checkouts remain zero-residue on teardown, preserving the
mode-scoped disk invariant: a session is still "bounded ephemeral hosted
by a persistent repo," just bounded by an explicit `harvest`/`abandon`
instead of one process lifetime. Auto-merge applies only to workspaces
whose results merge cleanly (no conflict markers ever land unattended);
conflicted ones fall back to `work-<i>` branches for manual `sc merge`.

Demoable outcome: fork workspaces, exit, return in a later invocation,
harvest, and watch clean results land on an integration branch without
manual merges.

## Ordering rationale

- **P16 → P17** are one story: the tombstone makes revoke durable at the
  rule level; bulk re-wrap makes acting on it practical. Shipping them
  adjacently delivers "revocation that actually works, end to end."
- **P18** is the biggest adoption unlock and is order-independent of the
  crypto pair; it follows them so the security arc closes first.
- **P19 before P20** because agent sessions multiply branches, and the
  human integrating them wants `--continue`/`--abort`/amend already in
  hand. P19 also must follow P16 (rule-merge semantics settle first).

## Explicitly still deferred beyond this horizon

HTTP transport (sc-native), streaming (>4 GiB) frames, sub-tree/partial
sharing and sparse checkouts, signed commits/provenance, operation
objects in the CAS (Jujutsu-deep oplog upgrade), oplog entries for
remote-tracking refs, richer conflict-resolution UX.
