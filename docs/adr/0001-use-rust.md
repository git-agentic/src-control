# ADR-0001: Implement src-control in Rust

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** Foundation

## Context

src-control is systems software: a content-addressed object store, an in-memory
worktree engine with a strict memory budget, and (in Phase 2) cryptography for
committed secrets. Three properties dominate the choice of language:

1. A **deterministic memory budget**. Phase 1's headline claim is that N agent
   worktrees can run in a bounded amount of RAM. A language with a tracing
   garbage collector makes "resident bytes" a fuzzy, runtime-dependent quantity
   and introduces pause behaviour that muddies the very measurement we want to
   advertise.
2. **Zero-copy sharing** of blob content across many worktrees, without
   defensive copies, so forking is cheap.
3. **Mature, audited cryptography** for Phase 2 (AEAD, X25519, KDFs).

The realistic candidates were Rust and Go (both were on the table per the brief).

## Decision

Implement the system in **Rust (stable, edition 2021)**.

Rust gives us manual control over allocation and lifetime, so the heap budget we
enforce is the heap we actually use; `Arc<[u8]>` gives cheap shared-ownership of
blob bytes with no copy on fork; and the RustCrypto ecosystem (plus `ring`)
provides the Phase 2 primitives with good ergonomics. Git interop is available
in-process through the pure-Rust `gix` crate, avoiding a subprocess boundary.

## Consequences

- Precise, GC-free accounting of resident blob bytes — the eviction logic in
  ADR-0006 can be reasoned about exactly.
- Forking a worktree never copies file content (ADR-0005).
- Higher upfront implementation cost (borrow checker, more explicit error
  handling) than Go; mitigated by per-crate `thiserror` enums and `anyhow` at
  the CLI boundary.
- Compile times grow once `gix` is pulled in; kept tolerable by quarantining
  `gix` in a single crate (ADR-0007) and keeping the build cache out of the
  project tree via `CARGO_TARGET_DIR`.

## Alternatives considered

- **Go.** Faster to scaffold, excellent concurrency, pure-Go `go-git`. Rejected
  because GC makes a precise heap budget and deterministic eviction materially
  harder to demonstrate — which is exactly the property Phase 1 sells.
- **C/C++.** Maximum control but no memory safety and a weaker crate/crypto
  story; unjustified risk for greenfield work.
- **Zig.** Attractive control story but an immature ecosystem for Git interop
  and crypto at the time of writing.
