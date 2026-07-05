# ADR-0020: Six-crate workspace with a strict dependency direction

- **Status:** Accepted
- **Date:** 2026-07-05
- **Phase:** Foundation (revision)
- **Supersedes:** ADR-0004

## Context

ADR-0004 fixed a four-crate workspace (`core`, `vfs`, `gitio`, `cli`) with a
strict, compiler-enforced dependency direction and the `gix` quarantine rule.
Two phases later grew the workspace: Phase 2 added `crates/crypto`
(`scl-crypto`, envelope encryption) and Phase 3 added `crates/repo`
(`scl-repo`, the persistent `.sc/` repository). ADR-0004 anticipated the
crypto crate but was never updated, so the record no longer matches the code.
This ADR supersedes it to restate the layout as built; the *principles* of
ADR-0004 (acyclic direction, dependency quarantine) are unchanged.

## Decision

Use a Cargo workspace of six crates with a **strict, acyclic dependency
direction**:

```
crates/core   → content-addressed store, object model, budget + eviction
crates/vfs    → in-memory worktree engine   (depends on core)
crates/gitio  → Git import/export via gix   (depends on core; ONLY crate that links gix)
crates/crypto → envelope encryption         (depends on core; ONLY crate linking RustCrypto)
crates/repo   → persistent .sc/ repo: objects, refs, branches, working tree
                                            (depends on core, vfs, crypto — NOT gitio)
crates/cli    → `sc` binary                 (depends on repo + vfs + gitio + crypto + core)

cli → repo → {vfs, crypto} → core
cli → gitio → core
```

Rules, extending ADR-0004's:

- **`core` must never depend on Git, worktrees, or crypto.**
- **`gix` stays quarantined in `gitio`** — if `gix` is needed elsewhere, add a
  function to `gitio` instead.
- **RustCrypto stays quarantined in `crypto`** — same rule, second boundary.
- **`repo` must not depend on `gitio`.** `cli` links both and passes imported
  snapshots (and git-remote orchestration, per ADR-0018) down; `repo` stays
  Git-agnostic.

## Consequences

- The record matches the code again; CLAUDE.md and ARCHITECTURE.md already
  describe this layout, so this ADR brings the decision log in line rather
  than changing anything.
- The two-quarantine model (Git in `gitio`, cryptography in `crypto`) gives
  each heavy dependency exactly one compile boundary and one review surface.
- Keeping `repo` free of `gitio` forced Phase 10's git-remote dispatch up into
  `cli`, above the `Transport` trait — recorded in ADR-0018 and validated by
  the build.

## Alternatives considered

- **Amending ADR-0004 in place.** Rejected: this directory's convention is
  that Accepted ADRs are immutable and are superseded, not edited
  (`docs/adr/README.md`).
- **Folding `repo` into `core`.** Rejected: `core` stays free of filesystem
  layout and policy concerns so the in-memory (Phase 1) and persistent
  (Phase 3) modes share one object model without entangling their disk
  invariants.
