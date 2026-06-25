# src-control — Roadmap

This roadmap sequences the phases that build src-control from its current state
(a persistent, branchable, content-addressed VCS with committed secrets) toward
the full thesis: a snapshot-and-tag version control system with **per-file
permissions**, **native committed secrets**, and **in-memory clones**, that
interoperates with Git rather than replacing it wholesale.

Each phase is a vertical slice that ends in something demoable to a real user.
Phases are built **one at a time, systematically**: each gets its own focused
brainstorm → spec (`docs/superpowers/specs/`) → plan (`docs/superpowers/plans/`)
→ implementation, and its roadmap ADR is firmed from **Proposed** to **Accepted**
(with refinements) at that point. The architecture invariants in `CLAUDE.md` hold
across every phase.

## Done

- **Phase 1 — In-RAM virtual worktrees.** Fork N copy-on-write worktrees of a
  repo entirely in RAM with a bounded memory budget + eviction and optional
  spill, leaving zero residual files on disk. (ADR-0005, 0006, 0007.)
- **Phase 2 — Native committed secrets.** Env vars/keys committed into repo state
  as envelope-encrypted objects (per-secret DEK under XChaCha20-Poly1305, DEK
  wrapped per X25519 recipient), decrypted only in an authorized execution
  context and injected into a child process environment. (ADR-0008, 0009, 0010.)
- **Phase 3 — Persistent repo + branches.** A durable `.sc/` repository (loose
  content-addressed objects, named branches, symbolic HEAD, single-writer lock)
  with a git-like working tree and `init`/`commit`/`status`/`log`/`branch`/
  `switch`/`secret`/`run`. Commits and secrets survive across `sc` invocations.
  (ADR-0011.)

## Planned phases (usability-first ordering)

| Phase | Goal | Demoable outcome | ADR |
|-------|------|------------------|-----|
| **P4 — Merge & conflict resolution** | Combine work from two branches | `sc merge <branch>` creates a merge snapshot; clean merges auto-resolve, conflicts are detected and reported | [0012](docs/adr/0012-three-way-merge.md) |
| **P5 — Secret scanner (accidental-plaintext guard)** | Stop plaintext secrets being committed | a `put`-time pattern + entropy scan **hard-rejects** plaintext secrets (`SecretDetected`), with a hash-scoped allowlist; complements the Phase 2 *deliberate, encrypted* secrets | [0017](docs/adr/0017-secret-scanner.md) |
| **P6 — Remotes: clone / push / fetch** | Sync a repo between locations | `sc clone <src> <dst>`, `sc push`, `sc fetch` transfer objects + refs; `fetch` then `merge` integrates remote work | [0013](docs/adr/0013-remote-sync-model.md) |
| **P7 — Per-file permissions (encrypted paths)** | Read-confidentiality for designated paths | `sc protect <path> --to …`; an **unauthorized clone receives ciphertext it cannot read**; an authorized checkout decrypts transparently | [0014](docs/adr/0014-per-file-permissions-encrypted-paths.md) |
| **P8 — Packfiles + GC** | Scale storage; reclaim space | `sc gc` packs reachable objects into a packfile and drops unreachable ones; pack transfer accelerates P6 | [0015](docs/adr/0015-packfiles-and-gc.md) |
| **P9 — Git export / interop** | Round-trip with Git | `sc export --to <git-repo>` writes snapshots as Git commits; `git log` shows them | [0016](docs/adr/0016-git-export.md) |

> **Prior art.** Phases P5–P9 adapt decisions from the sibling project
> [git.agentic](https://github.com/git-agentic/git.agentic) (same BLAKE3
> content-addressed substrate): the secret scanner (its ADR-0013), the pluggable
> ObjectStore backend trait (its ADR-0006/0011), object sharding + zstd
> compression, and the destructive-operation approval gate (its ADR-0014). See the
> Cross-cutting principles section.

## Why this order

Usability-first: make src-control a genuinely usable VCS before layering the
remaining differentiators.

- **P4 before P6** so that, once remotes land, `fetch` has a `merge` to feed into
  — the natural collaborative loop (fetch remote work, merge it) works end to end.
- **P5 (secret scanner) early** because it is independent of every other phase,
  cheap, and hardens an already-shipped pillar (Phase 2): it stops *accidental*
  plaintext-secret commits, the natural counterpart to Phase 2's *deliberate*
  encrypted secrets. It blocks nothing and could move earlier or later, but a
  quick safety win slots well right after merge.
- **P6 before P7** so the headline confidentiality demo — *an unauthorized clone
  gets the protected files as ciphertext it cannot decrypt* — is demonstrable the
  moment encrypted paths ship, using the clone built in P6.
- **P7** completes the third thesis pillar (per-file permissions), reusing the
  Phase 2 `scl-crypto` envelope and recipient identities.
- **P8 (GC/packfiles)** is a scaling/operability phase; it also speeds P6's
  transfer, but no earlier phase depends on it, so it slots after the
  feature-bearing phases.
- **P9 (Git export)** is independent interop; it lands last because it serves
  migration/coexistence rather than core capability.

## Dependencies

```
Phase 3 (persistence) ─┬─> P4 Merge
                       ├─> P5 Secret scanner  (independent; hardens Phase 2)
                       ├─> P6 Remotes ──> (fetch feeds P4 merge)
                       ├─> P7 Encrypted paths ── needs P6 clone for the headline demo
                       ├─> P8 Packfiles + GC ── benefits P6 transfer
                       └─> P9 Git export
scl-crypto (Phase 2) ──> P5 Secret scanner, P7 Encrypted paths
```

All planned phases build on the Phase 3 persistent store. P5 and P7 additionally
build on the Phase 2 cryptography. Otherwise the phases are loosely coupled and
could be reordered if priorities change.

## Cross-cutting principles (adapted from git.agentic)

These apply across phases rather than to one:

- **Pluggable storage/transport seam.** P6 (remotes) and P8 (GC) are designed
  around a single backend trait — `put`/`get`/`has` plus `delete`/`list_prefix`
  and an async variant — with the local filesystem as the default impl and remote
  backends (and managed-Git adapters) behind the same trait. Storage-layer
  concepts never leak into the CLI/API surface. (git.agentic ADR-0006/0011.)
- **Destructive-operation approval gate.** Any operation that can discard work —
  `merge --abort`, `switch` over a dirty tree, future `rollback`/`gc --prune` —
  must either refuse on uncommitted state (today's guards) or require explicit
  confirmation before proceeding. No silent destruction. (git.agentic ADR-0014.)
- **Secret hygiene is layered.** Deliberate secrets are encrypted (Phase 2 / P7);
  accidental plaintext secrets are rejected at `put` time (P5). The two are
  complementary, not alternatives.

## Deferred beyond P9

Tracked but out of scope for this roadmap horizon:

- **Network transport for remotes** (P6 starts with a local-filesystem transport;
  SSH/HTTP transports come later).
- **Secret/permission lifecycle**: value rotation, break-glass / escrow recipient
  keys, and bulk re-wrap ergonomics.
- **Sub-tree / partial sharing** and sparse checkouts.
- **Merge ergonomics**: rebase, cherry-pick, and richer conflict resolution UX
  beyond P4's detection/representation.
- **Signed commits / provenance** as a first-class governance feature.

## How a phase gets built

1. Focused brainstorm for the phase (this skill) → phase spec.
2. `writing-plans` → a task-by-task implementation plan.
3. Subagent-driven (or inline) execution with spec + code-quality review per task.
4. Firm the phase's ADR from **Proposed** to **Accepted**, recording any
   refinements discovered during the build.
