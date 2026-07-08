# Roadmap horizon P25–P27 — Scale & reach

**Date:** 2026-07-08
**Status:** Approved (horizon shape; each phase gets its own spec + ADR)

## Goal (user-decided)

Push src-control's transport/monorepo frontier so it is viable at real
network and monorepo scale. Chosen over two alternatives: a
consolidate-then-trust sweep of the accumulated review follow-ons, and an
agent/workspace-depth horizon. The review follow-ons stay tracked in
ROADMAP's Deferred section and are closed opportunistically where a
phase's code lands in the relevant path.

## Phases and ordering (user-decided: foundation → reach → capstone)

1. **P25 — Streaming pack transfer.** Lift P12's 4 GiB frame cap AND bound
   transfer memory: a pack becomes a multi-frame chunk stream, sender
   builds to a temp file, receiver spills + verifies from disk. Most
   self-contained (a wire-protocol limitation), foundational (HTTP and
   partial clone both move large data over the same wire), and de-risks
   the transport layer before the bigger features build on it.
   Spec: `2026-07-08-p25-streaming-transfer-design.md` (ADR-0035).
2. **P26 — sc-native HTTP transport.** A second transport alongside
   ssh://, over the streaming wire from P25. New reach (HTTP endpoints).
3. **P27 — Partial clone.** Promisor store + prefix-scoped fetch so
   out-of-prefix objects are never downloaded — P24 sparse-checkout's
   deferred other half, the monorepo payoff. The capstone, built on a
   proven streaming wire: the store must tolerate missing objects and
   every reader (gc/verify/export) must handle promisor gaps.

## Why this ordering

Streaming first because it is the foundational limitation lift with the
smallest new surface (existing framing only) — both later phases move
large data and benefit, and a proven bounded-memory wire de-risks the
capstone. HTTP second (new reach on the proven wire). Partial clone last:
highest value, highest risk, and best built once the wire is solid.

## Standing constraints

Every phase holds the CLAUDE.md invariants (crypto/gix quarantines,
content-addressing, disk mode-scoping) and the delivery process
(brainstorm → spec + Proposed ADR → plan → subagent-driven build → task +
final reviews → local `Merge P<N>:` merge). Each phase's ADR firms from
Proposed to Accepted with a code-verified refinements section at build
time.
