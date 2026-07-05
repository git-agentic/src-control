# ADR-0004: Four-crate workspace with a strict dependency direction

- **Status:** Superseded by [ADR-0020](0020-six-crate-workspace.md)
- **Date:** 2026-06-24
- **Phase:** Foundation

## Context

The system has clearly separable concerns: the object model and store, the
worktree engine, Git interop, and a CLI. Git interop in particular pulls a large
dependency (`gix`) that we do not want leaking into the core. We want module
boundaries that are enforced by the compiler, not by convention.

## Decision

Use a Cargo workspace of four crates with a **strict, acyclic dependency
direction**:

```
crates/core   → content-addressed store, object model, budget + eviction
crates/vfs    → in-memory worktree engine            (depends on core)
crates/gitio  → Git import via gix                   (depends on core; ONLY crate that links gix)
crates/cli    → `sc` binary                          (depends on vfs + gitio + core)

cli → {vfs, gitio} → core
```

Rules: **`core` must never depend on Git or worktrees**, and **`gix` must stay
quarantined in `gitio`**. If `gix` is needed elsewhere, add a function to `gitio`
instead of taking a second dependency on it.

## Consequences

- The core object model can be reused (e.g. by a future server or a Phase 2
  `scl-crypto` crate) without dragging in Git or filesystem concerns.
- `gix`'s compile-time cost and API churn are isolated to one crate.
- Errors compose cleanly: each crate exposes a `thiserror` enum; the CLI uses
  `anyhow` and converts with `?` at the boundary.
- A future `scl-crypto` crate for Phase 2 slots in between `core` and `cli`
  without disturbing the direction.

## Alternatives considered

- **Single crate with modules.** Simpler to start but relies on discipline alone
  to keep `gix` and filesystem code out of the core; the boundary would erode.
- **Splitting `core` further (separate `store` and `object` crates).** Premature;
  they change together and share the codec. Revisit if either grows large.
