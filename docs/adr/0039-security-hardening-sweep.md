# ADR-0039: Security hardening sweep

- **Status:** Proposed
- **Date:** 2026-07-09
- **Phase:** 28
- **Builds on:** ADR-0021 (durability/concurrency hardening — the P21 sweep precedent), ADR-0022 (ssh wire protocol), ADR-0015 (packfiles), ADR-0014 (protected paths), ADR-0008/0009 (secrets)

## Context

A 2026-07-09 security audit surfaced six findings; each was dispositioned via the
wayfinder map (`docs/superpowers/specs/2026-07-09-security-hardening-design.md`,
tracker issues #1–#9). Four are small, independent, fix-now items with settled
designs; they group into one P21-shaped hardening sweep, security-only with no new
feature axis. The larger fifth (sc+http access control) is deferred to its own phase
(ADR-0040, P29). This ADR covers only the sweep.

## Decision

Build the four fix-now decisions from the security-hardening spec verbatim — no new
design; this ADR points at that spec for detail:

1. **Remote UpdateRef ref-name validation (audit High, the one genuine bug).** Apply
   the strict `validate_branch_name` at the lowest ref-write boundary
   (`refs::write_branch_tip` + `read_branch_tip`) — one choke point for every writer
   (CLI, wire `UpdateRef`, undo, ws), protecting both the `refs/heads/` filesystem path
   and the space-delimited oplog format. Also upgrade `write_remote_tip`'s
   `is_unsafe_ref_component` to reject whitespace/control (a hostile-git-remote gap
   found while resolving). Both ref-write paths hardened.
2. **DoS caps (audit High).** A single `MAX_OBJECT_SIZE` constant (~256 MiB) caps the
   wire frame size (`read_frame_inner`), the pack-record compressed length, and the
   zstd decompressed output (decompression-bomb guard); chunk frames stay bounded by
   the existing `CHUNK_SIZE`. The four object-decode `Vec::with_capacity(n)` sites
   (tree entries, snapshot parents, secrets, signature wrapped-keys) switch to the
   existing `Reader::count()` guard.
3. **Protected-path equality nudge (audit Medium — accept + surface).** Accept the
   convergent-encryption caveat (deliberate, ADR-0014); add a pattern-aware `sc protect`
   stderr nudge steering low-entropy secret basenames (`.env`/`*.key`/creds…) to
   `sc secret`, plus stronger help/docs. Randomized protected mode deferred.
4. **Secret env-var confidentiality (audit Medium — accept + docs + zeroize).** Tighten
   threat-model wording to "authorized local process context, NOT strong isolation";
   wrap the intermediate decrypted plaintext buffer in `crypto::Zeroizing` to zero the
   parent's copy on drop. fd/stdin injection deferred.

## Consequences

- The two concrete-bug Highs (ref-traversal, DoS) are closed; the two Mediums are
  accepted-and-surfaced. No new user-facing feature axis; no new dependency.
- Demoable outcome is P21-shaped: each audit repro becomes a pinned regression test,
  and every existing demo stays green — the sweep ships no new demo script.
- sc+http access control (auth) is explicitly deferred to P29 (ADR-0040).

## Alternatives considered

- **One combined phase with the sc+http auth.** Rejected: mixes four mechanical fixes
  with a substantial auth feature (CLI + config + wire-opening parse) — heterogeneous,
  plan-heavy, weaker review boundaries.
- **Auth phase first.** Rejected: the auth is the larger, higher-risk unit; the sweep
  first closes the concrete bugs sooner and de-risks.
