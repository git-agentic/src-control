# src-control

A next-generation version control system built around a snapshot-and-tag model
(Jujutsu-inspired), with per-file permissions, native committed secrets, and
in-memory clones as the long-term thesis. This repository is the MVP, which
proves the two wedges with the clearest near-term value:

1. **In-memory virtual worktrees** (the agent wedge) — fork N parallel worktrees
   of a repo entirely in RAM, run and check out against each, and tear them down
   leaving zero residual files on disk. **Implemented (Phase 1).**
2. **Native committed secrets** — env vars / keys committed into repo state,
   encrypted at rest and in transit, decrypted only in an authorized execution
   context. **Designed; implementation is Phase 2.**

The MVP builds on / interoperates with Git rather than replacing it: it imports
an existing Git repo's `HEAD` in-process (via `gix`) so worktrees can fork from
real history.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design,
[docs/adr/](docs/adr/) for the architecture decision records covering both
phases, and [CLAUDE.md](CLAUDE.md) for project conventions.

## Workspace layout

```
crates/
  core/   content-addressed object store, snapshot model, memory budget + eviction
  vfs/    in-memory virtual worktree engine (fork / edit / checkout / commit / teardown)
  gitio/  Git interop boundary — import a Git repo's HEAD into the store via gix
  cli/    `sc` binary — import repos and run the parallel-agent demo
demo/
  run_demo.sh   independent before/after filesystem diff proving zero residue
```

Dependency direction is strict: `cli → {vfs, gitio} → core`. Only `gitio` links
`gix`, keeping the rest of the system Git-agnostic.

## Quick start

```sh
# Build and test the whole workspace
cargo test

# Run the parallel-agent demo (4 agents, default 8 MiB blob budget)
cargo run --bin sc -- demo --agents 4

# Exercise the bounded budget: 6 agents under a 4 MiB budget with spill enabled,
# which forces LRU eviction and rehydration from the (auto-cleaned) spill dir
cargo run --bin sc -- demo --agents 6 --budget-mb 4 --spill

# Import a real Git repo's HEAD and list its files
cargo run --bin sc -- import --repo /path/to/some/git/repo

# Independent zero-residue proof (snapshots the filesystem before/after)
bash demo/run_demo.sh
```

## How Phase 1 works

A worktree is a copy-on-write overlay over an immutable base snapshot. Forking
allocates only a small overlay — base blob bytes are shared through the store
behind `Arc` and never copied — so forking N agents off one snapshot is O(N) in
overlay size, not repo size. Reads fall through the overlay to the base tree;
writes land in the overlay. Content lives only in RAM and touches disk **only**
on an explicit `checkout` to a caller-chosen directory. There is no FUSE mount
and no kernel extension, which is what makes "zero residual artifacts" provable
rather than aspirational.

The store enforces a bounded blob-byte budget with LRU eviction. Without spill,
an over-budget insert fails loudly (`BudgetExceeded`). With spill, the coldest
reconstructible blobs are written to a content-addressed temp directory and
rehydrated on demand; that directory is removed when the store is dropped, so
the zero-residue guarantee holds even with spill enabled.

## Status

Phase 1 is implemented and tested. Phase 2 (committed secrets via envelope
encryption) is designed in ARCHITECTURE.md; the object model already carries a
`Secret` object kind through fork/checkout/clone untouched so it lands additively.
