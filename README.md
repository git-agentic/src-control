# src-control

A next-generation version control system built around a snapshot-and-tag model
(Jujutsu-inspired), with per-file permissions, native committed secrets, and
in-memory clones as the long-term thesis. This repository is the MVP, which now
proves the core thesis end to end:

1. **In-memory virtual worktrees** (the agent wedge) — fork N parallel worktrees
   of a repo entirely in RAM, run and check out against each, and tear them down
   leaving zero residual files on disk. **Implemented (Phase 1).**
2. **Native committed secrets** — env vars / keys committed into repo state,
   encrypted at rest and in transit, decrypted only in an authorized execution
   context. **Implemented (Phase 2).**
3. **Persistent collaborative VCS features** — durable `.sc/` repos, branches,
   merge, accidental-secret scanning, local remotes, per-path encryption,
   packfiles/GC, and Git export. **Implemented (Phases 3-9).**

The MVP builds on / interoperates with Git rather than replacing it: it imports
an existing Git repo's `HEAD` in-process (via `gix`) and exports src-control
history back to Git commits.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design,
[docs/adr/](docs/adr/) for the architecture decision records covering both
phases, and [CLAUDE.md](CLAUDE.md) for project conventions.

## Workspace layout

```
crates/
  core/   content-addressed object store, snapshot model, memory budget + eviction
  vfs/    in-memory virtual worktree engine (fork / edit / checkout / commit / teardown)
  gitio/  Git interop boundary — import/export Git history via gix
  crypto/ envelope encryption for committed secrets and protected paths
  repo/   durable .sc repo, refs, worktree, merge, remotes, protection, GC
  cli/    `sc` binary
demo/
  run_demo.sh         independent before/after filesystem diff proving zero residue
  run_repo_demo.sh    persistent repo end-to-end demo
  run_protect_demo.sh protected-path confidentiality demo
```

Dependency direction is strict: `cli → repo → {vfs, gitio, crypto} → core`.
Only `gitio` links `gix`, keeping the rest of the system Git-agnostic.

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

# Initialize a persistent repo and commit the working tree
cargo run --bin sc -- init
cargo run --bin sc -- commit -m "initial import"

# Export the current branch history to Git
cargo run --bin sc -- export --to /path/to/git/repo

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

Phases 1-9 are implemented and tested. The system now covers in-RAM virtual
worktrees, committed secrets, persistent repos, merge, secret scanning, remotes,
encrypted paths, packfiles/GC, and Git export. Remaining work is beyond the P9
roadmap: network transports, richer merge ergonomics, secret/permission
lifecycle, sparse/subtree sharing, and signed provenance.
