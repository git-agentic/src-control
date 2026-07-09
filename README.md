# src-control

A next-generation version control system built around a snapshot-and-tag model
(Jujutsu-inspired), with per-file permissions, native committed secrets, and
in-memory clones as the long-term thesis. Across 30 shipped phases, this
repository now proves that thesis end to end:

1. **In-memory virtual worktrees** (the agent wedge) — fork N parallel worktrees
   of a repo entirely in RAM, run and check out against each, and tear them down
   leaving zero residual files on disk. **Implemented (Phase 1).**
2. **Native committed secrets** — env vars / keys committed into repo state,
   encrypted at rest and in transit, decrypted only in an authorized execution
   context. **Implemented (Phase 2).**
3. **Per-file permissions** — individual paths encrypted to a chosen set of
   recipients via convergent encryption, merged/replayed/revoked/rewrapped
   without ever writing plaintext to the object store. **Implemented (Phase 7,
   hardened through Phases 15-17.)**
4. **A full persistent collaborative VCS** on top of those three pillars:
   durable `.sc/` repos, branches, three-way merge, history editing
   (cherry-pick/rebase/amend/undo), durable multi-invocation agent sessions,
   signed commits with session-transcript provenance, sparse and partial
   checkouts, and local/ssh/HTTP/Git network transports. **Implemented
   (Phases 3-30.)**

The system builds on / interoperates with Git rather than replacing it: it
imports an existing Git repo's `HEAD` in-process (via `gix`), exports history
back to Git commits, and reaches hosted Git (e.g. GitHub) through a spawned
system-git mirror bridge.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design,
[docs/adr/](docs/adr/) for the architecture decision records covering every
phase, and [CLAUDE.md](CLAUDE.md) for project conventions and the full phase
log.

> ⚠️ **Pre-1.0, not independently audited — don't trust production secrets to it
> yet.** src-control implements real cryptography (committed-secret envelope
> encryption, convergent-encryption protected paths, Ed25519 signed provenance),
> but these are MVP implementations that have **not had an independent security
> audit**. There are deliberate boundaries you should understand first — e.g.
> convergent encryption is equality-confirmable, `sc serve --http` is plaintext
> (no TLS), and rotation cuts off future reads but cannot erase ciphertext already
> in history. They are consolidated in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
> Report vulnerabilities privately per [SECURITY.md](SECURITY.md).

## Workspace layout

```
crates/
  core/   content-addressed object store (blob/tree/snapshot/secret/signature/
          transcript), memory budget + eviction
  vfs/    in-memory virtual worktree engine (fork / edit / checkout / commit / teardown)
  gitio/  Git interop boundary — import/export Git history and the network-git
          mirror bridge, via gix (the ONLY crate that links gix)
  crypto/ envelope encryption for committed secrets and protected paths, plus
          Ed25519 signing (the ONLY crate that links RustCrypto)
  repo/   durable .sc repo — refs, branches, working tree, merge, history
          editing, remotes, protection, GC, sparse/partial clone, transcripts,
          transport
  cli/    `sc` binary
demo/
  ~22 end-to-end proof scripts covering everything below, e.g.:
  run_demo.sh              independent before/after filesystem diff, zero residue
  run_repo_demo.sh         persistent repo end-to-end demo
  run_ssh_remote_demo.sh   ssh-native transport round trip
  run_provenance_demo.sh   signed history + rewrite-attack proof
  run_transcript_demo.sh   sealed agent-session transcript proof
```

Dependency direction is strict: `cli → repo → {vfs, gitio, crypto} → core`.
Only `gitio` links `gix` and only `crypto` links RustCrypto, keeping the rest
of the system Git- and crypto-library-agnostic.

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

# Sign a commit and verify the resulting history
cargo run --bin sc -- commit -m "signed change" --sign
cargo run --bin sc -- verify --require

# Serve a repo over the sc-native HTTP transport and clone it elsewhere
cargo run --bin sc -- serve --http 127.0.0.1:8730 .
cargo run --bin sc -- clone sc+http://127.0.0.1:8730/repo /path/to/dst

# Export the current branch history to Git
cargo run --bin sc -- export --to /path/to/git/repo

# Independent zero-residue proof (snapshots the filesystem before/after)
bash demo/run_demo.sh
```

See `CLAUDE.md`'s Commands section for the full command surface (merge,
history editing, secrets lifecycle, sparse/partial clone, ssh/HTTP remotes,
session transcripts, and more).

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

The long-term thesis is proven end to end, not just prototyped: in-RAM virtual
worktrees (Phase 1), native committed secrets (Phase 2), and per-file
permissions via encrypted paths (Phase 7) all ship alongside a full persistent,
branchable, content-addressed VCS — merge and history editing, durable
multi-invocation agent sessions with auto-merge, a commit-time secret scanner,
secret/permission lifecycle (rotation, escrow, revocation tombstones, bulk
rewrap), signed commits with sealed session-transcript provenance, sparse and
partial checkouts, and local, ssh-native, sc-native HTTP, and Git (including
hosted GitHub) network transports. All 30 phases are implemented and tested;
`demo/` holds roughly 22 independent end-to-end proofs, one per major
capability. Remaining follow-ons (transparent lazy-fetch, per-case
gap-tolerant merge on partial clones, connection pooling for `sc serve
--http`, and similar hardening items) are tracked in
[ROADMAP.md](ROADMAP.md)'s Deferred section rather than being open MVP scope.
