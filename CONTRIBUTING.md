# Contributing to src-control

Thanks for your interest. src-control is a pre-1.0 research/MVP codebase built one
vertical-slice "phase" at a time; contributions are welcome, and this guide covers
what you need to get a change merged cleanly.

## Before you start

- Read [`CLAUDE.md`](CLAUDE.md) — it is the working guide: what the project is, the
  crate layout, and the **core invariants that must not break**. (`AGENTS.md` is a
  pointer to it, for tooling that looks for that filename.)
- Read [`ARCHITECTURE.md`](ARCHITECTURE.md) for the design, and skim
  [`docs/adr/`](docs/adr/) for the decision records behind each subsystem.
- For anything security-relevant, read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)
  first — several "limitations" are deliberate, documented boundaries, not bugs.

## Development setup

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup`
will install it automatically. From a clone:

```sh
cargo test --workspace          # the whole suite
cargo fmt --all                 # format (CI enforces --check)
cargo clippy --workspace --all-targets -- -D warnings   # lint (CI enforces this)
```

The demos under `demo/` are independent end-to-end proofs and double as
integration tests — if you touch a subsystem, run the relevant `demo/run_*.sh`.

## The bar for a change

CI runs `fmt --check`, `clippy -D warnings`, `cargo test --workspace`, and
`cargo doc`. Your PR must be green on all of them. In addition:

1. **Every new behavior ships with a test.** Tests live in `#[cfg(test)] mod
   tests` next to the code. A test that materializes to disk must clean up after
   itself and assert the path is gone.
2. **Respect the dependency rule and quarantines** (enforced socially, not just by
   the compiler): `cli → repo → {vfs, gitio, crypto, tlsio} → core` (`tlsio` is a
   leaf with no workspace deps). `core` never depends on Git, worktrees, or
   crypto. **`gix` stays in `gitio` only**; **RustCrypto stays in `crypto`
   only**; **rustls/rcgen stay in `tlsio` only**. If you find yourself reaching
   for `gix`, a RustCrypto type, or TLS elsewhere, add a function to
   `gitio`/`crypto`/`tlsio` instead.
3. **Do not break the [core invariants in `CLAUDE.md`](CLAUDE.md#core-invariants-do-not-break)** —
   content addressing (`BLAKE3(canonical_encoding)`), `Arc<[u8]>`-shared blobs, the
   mode-scoped disk invariant (ephemeral = zero residue), and "never silently drop
   data."
4. **Public types/fns get a doc comment explaining intent, not mechanics.**
5. **Keep the demos honest.** `sc demo` must still end by proving zero residue, and
   any new capability that warrants it gets a `demo/run_*.sh` proof.

## Larger design changes

The project records significant decisions as ADRs (`docs/adr/`, Nygard format:
Context → Decision → Consequences → Alternatives). An **Accepted** ADR is
immutable — to change a decision, add a new ADR that supersedes it. If your change
alters the architecture, open an issue to discuss the design before a large PR, and
expect to add or amend an ADR alongside the code.

## Reporting bugs and requesting features

- **Bugs / features:** open a [GitHub issue](https://github.com/git-agentic/src-control/issues).
- **Security vulnerabilities:** do **not** open a public issue — follow
  [`SECURITY.md`](SECURITY.md) (private email or GitHub private reporting).

## Licensing of contributions

By submitting a contribution you agree it is licensed under the project's
[Apache License 2.0](LICENSE), consistent with Section 5 of that license.
