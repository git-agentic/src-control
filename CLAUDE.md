# CLAUDE.md — working guide for src-control

Read this before making changes. It captures what this project is, how it's
structured, and the conventions to keep it coherent over time.

## What this is

A next-gen version control system. Long-term thesis: a snapshot-and-tag model
(Jujutsu-inspired) with per-file permissions, native committed secrets, and
in-memory clones. We are **not** replacing Git wholesale — we build on / interop
with Git where it saves time.

MVP scope is two wedges:
- **Phase 1 (done):** in-memory virtual worktrees for parallel agents, with a
  bounded memory budget + eviction, leaving zero residual files on disk.
- **Phase 2 (built):** native committed secrets via envelope encryption,
  decrypted only in an authorized execution context.

Full design is in `ARCHITECTURE.md`; the rationale behind each major decision is
recorded as an ADR in `docs/adr/`. Keep them in sync when the design changes.

## Stack & tooling

- **Language:** Rust (stable). Rationale in ARCHITECTURE.md ("Why Rust").
- **Edition:** 2021, inherited via `[workspace.package]`.
- **Key deps (pin latest stable; no LTS concept in Rust/crates):**
  `blake3`, `thiserror`, `hex`, `gix` (Git interop only), `clap`, `anyhow`.
  Phase 2 added RustCrypto AEAD (XChaCha20-Poly1305) + X25519 in `crates/crypto`.
- Bump deps with `cargo add`/`cargo update`; do not hand-edit version pins to
  guesses. `gix` must keep its **default features** (it needs the `sha1`
  hashing feature — disabling defaults breaks `gix-hash`).

## Workspace layout & dependency rule

```
crates/core   → content-addressed store, object model, budget + eviction
crates/vfs    → in-memory worktree engine (depends on core)
crates/gitio  → Git import via gix (depends on core; ONLY crate that links gix)
crates/crypto → envelope encryption (depends on core; ONLY crate linking RustCrypto)
crates/cli    → `sc` binary (depends on vfs + gitio + crypto + core)
```

Strict dependency direction: `cli → {vfs, gitio, crypto} → core`. **`core` must
never depend on Git, worktrees, or crypto.** **`gix` must stay quarantined in
`gitio`** — if you find yourself reaching for `gix` elsewhere, add a function to
`gitio` instead. **RustCrypto must stay quarantined in `crypto`** — if you find
yourself reaching for it elsewhere, add a function to `crypto` instead.

## Core invariants (do not break)

- **Content addressing:** every object's id is `BLAKE3(canonical_encoding)`.
  Encoding is length-prefixed and tree entries are sorted, so the same content
  hashes identically on any machine. If you change the encoding, you change all
  ids — treat it as a format break and update tests.
- **Blobs are `Arc<[u8]>`-shared.** Forking a worktree must not copy file
  content. Don't introduce a code path that deep-copies blob bytes per worktree.
- **Disk is touched only by `Worktree::checkout`.** No other code path may write
  files except the spill backend, which writes only under a session temp dir and
  removes it on `Store` drop. This is the property the whole Phase 1 pitch rests
  on — guard it.
- **Memory budget bounds resident blob bytes.** Trees/snapshots/secrets stay
  resident (small) and are not evicted. Only reconstructible blobs are evictable.
  Dirty overlay writes are pinned in the worktree and never spilled.
- **Without spill, over-budget inserts fail loudly** (`Error::BudgetExceeded`).
  Never silently drop data to stay under budget.

## Conventions

- Every public type/fn gets a doc comment explaining intent, not mechanics.
- Errors: per-crate `thiserror` enums; the CLI uses `anyhow`. Convert with `?`
  (a bare `return some_vfs_result;` won't coerce into `anyhow::Error`).
- Tests live in `#[cfg(test)] mod tests` next to the code. Every new behavior
  ships with a test. Tests that materialize to disk must clean up after
  themselves and assert the path is gone.
- Keep the CLI demo (`sc demo`) honest: it must end by proving zero residue, and
  `demo/run_demo.sh` provides an independent before/after filesystem diff.

## Commands

```sh
cargo test                                   # whole workspace
cargo run --bin sc -- demo --agents 4        # parallel-agent demo
cargo run --bin sc -- demo --agents 6 --budget-mb 4 --spill   # exercise eviction
cargo run --bin sc -- import --repo <path>   # import a Git repo's HEAD
bash demo/run_demo.sh                         # independent zero-residue proof
cargo run --bin sc -- keygen                 # generate an X25519 identity
cargo run --bin sc -- secret-demo            # committed-secrets authorize/deny/grant proof
```

Set `CARGO_TARGET_DIR` to a path outside this folder to keep `target/` out of
the project tree if desired.

## Phase 2 is built

`crates/crypto` (`scl-crypto`) exists and owns all cryptography: envelope
encryption (per-secret DEK under XChaCha20-Poly1305, DEK wrapped per recipient
via X25519 ECDH + HKDF-SHA256), keygen, and a `KeyProvider` abstraction for
loading identities. `Snapshot` carries a `secrets: BTreeMap<String, ObjectId>`
side registry (separate from the file tree) so secrets are env vars, not files
— `checkout` never materializes them. An authorized context decrypts the value
in memory and injects it into a child process environment via `run_with_secret`.

The deferred bits (persistent store, standalone `sc secret add`/`sc run` across
invocations, break-glass escrow key guidance) can be added without changing the
Phase 1 or Phase 2 invariants. Do not weaken either set of invariants to get
there.
