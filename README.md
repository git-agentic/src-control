# src-control

A next-generation version control system built around a snapshot-and-tag model
(Jujutsu-inspired), with per-file permissions, native committed secrets, and
in-memory clones as the long-term thesis. Across 36 shipped phases plus the
P37 partial-clone series (37a-37d), this repository now proves that thesis end
to end:

1. **In-memory virtual worktrees** (the agent wedge) — fork N parallel worktrees
   of a repo entirely in RAM, run and check out against each, and tear them down
   leaving zero residual files on disk. **Implemented (Phase 1).**
2. **Native committed secrets** — env vars / keys committed into repo state,
   encrypted at rest and in transit, decrypted only in an authorized execution
   context. **Implemented (Phase 2).**
3. **Per-file and per-branch permissions** — individual paths encrypted to a
   chosen set of recipients (randomized sealing since Phase 33, with dual-read
   of older convergent ciphertext), merged/replayed/revoked/rewrapped without
   ever writing plaintext to the object store; and whole **private branches**
   (Phase 34) whose commits, trees, file paths, and messages are all sealed —
   opaque to non-recipients until an atomic `sc branch publish`. **Implemented
   (Phase 7, hardened through Phases 15-17 and 33; per-branch in Phase 34.)**
4. **A full persistent collaborative VCS** on top of those three pillars:
   durable `.sc/` repos, branches, three-way merge, history editing
   (cherry-pick/rebase/amend/undo), durable multi-invocation agent sessions,
   signed commits with session-transcript provenance, sparse and partial
   checkouts (including merge and agent sessions on a partial clone), local/
   ssh/HTTP+TLS/bucket/Git network transports, and a read-only native desktop
   browser. **Implemented (Phases 3-37.)**

The system builds on / interoperates with Git rather than replacing it: it
imports an existing Git repo's `HEAD` in-process (via `gix`), exports history
back to Git commits, and reaches hosted Git (e.g. GitHub) through a spawned
system-git mirror bridge.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design,
[docs/adr/](docs/adr/) for the architecture decision records (0001-0054) behind
every phase, and [CLAUDE.md](CLAUDE.md) for project conventions and the
per-phase capability map. [CONTRIBUTING.md](CONTRIBUTING.md) covers the
development workflow.

> ⚠️ **Pre-1.0, not independently audited — don't trust production secrets to it
> yet.** src-control implements real cryptography (committed-secret envelope
> encryption, encrypted protected paths, Ed25519 signed provenance, in-binary
> TLS), but these are MVP implementations that have **not had an independent
> security audit**. There are deliberate boundaries you should understand first —
> e.g. pre-Phase-33 convergent ciphertext in history stays equality-confirmable
> forever, `sc+https://` trust defaults to TOFU pinning (the first connection to
> a host is unverified unless you pre-pin it or opt into CA validation), and
> rotation cuts off future reads but cannot erase ciphertext already in
> history. They are consolidated in
> [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Report vulnerabilities privately
> per [SECURITY.md](SECURITY.md).

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
  tlsio/  TLS for the sc+https:// transport (the ONLY crate that links
          rustls/rcgen; a leaf — no workspace deps)
  objio/  object-store buckets for sc+wal:// and sc+s3:// remotes (the ONLY crate
          that links the S3 SDK; a leaf — no workspace deps)
  repo/   durable .sc repo — refs, branches, working tree, merge, history
          editing, remotes, protection, GC, sparse/partial clone, transcripts,
          transport (ssh, sc+http(s), bucket WAL)
  cli/    `sc` binary
apps/
  desktop/ read-only Tauri v2 + React/TypeScript repository browser (see
          apps/desktop/README.md); calls `repo` directly, never the `sc` binary
demo/
  27 end-to-end proof scripts covering everything below, e.g.:
  run_demo.sh              independent before/after filesystem diff, zero residue
  run_repo_demo.sh         persistent repo end-to-end demo
  run_ssh_remote_demo.sh   ssh-native transport round trip
  run_provenance_demo.sh   signed history + rewrite-attack proof
  run_transcript_demo.sh   sealed agent-session transcript proof
```

Dependency direction is strict: the adapters `cli` and `desktop` sit on top of
`repo`; `repo → {vfs, crypto} → core`, plus the leaf edges `repo → tlsio` and
`repo → objio` (`tlsio` and `objio` depend on no other workspace crate). `gitio`
depends only on `core`, and `repo` never links it: `cli` links both and passes
imported snapshots down. Only `gitio` links `gix`, only `crypto` links
RustCrypto, only `tlsio` links rustls, and only `objio` links the S3 SDK,
keeping the rest of the system Git-, crypto-, TLS- and object-store-agnostic.

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

Run `sc --help` (and `sc <command> --help`) for the full command surface:
merge, history editing, secrets lifecycle, sparse/partial clone, ssh/HTTP(S)/
bucket remotes, session transcripts, and more. The annotated reference lives in
the `sc-cli-reference` skill (`.claude/skills/sc-cli-reference/SKILL.md`).

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
permissions via encrypted paths (Phase 7, randomized sealing since Phase 33)
all ship alongside a full persistent, branchable, content-addressed VCS —
merge and history editing, durable multi-invocation agent sessions with
auto-merge, a commit-time secret scanner, secret/permission lifecycle
(rotation, escrow, revocation tombstones, bulk rewrap, `sc rewrap --rotate`
for protected paths), signed commits with sealed session-transcript
provenance (droppable through signed tombstones), sparse and partial checkouts (lazy want-by-id fetch, merge,
cherry-pick, rebase and agent sessions on a partial clone), and local,
ssh-native, sc-native HTTP/TLS (bearer tokens with expiry and rotation,
listener resource limits, TOFU pinning managed by `sc tls`, or CA validation
via `SC_HTTPS_CA_FILE`/`SC_HTTPS_CA=system`), bucket (`sc+wal://`, `sc+s3://`),
and Git (including hosted GitHub) network transports, plus private branches
sealed to a recipient set until publish and a read-only Tauri desktop
browser. All 36 phases and P37a-37d are implemented and tested; `demo/` holds
27 independent end-to-end proofs, one per major capability. Remaining
follow-ons (signatures and transcripts not travelling through bucket remotes
(#229), transcript drop delivery gaps, bucket
compaction and gc, named concurrent `sc ws` sessions, size/count clone
filters, an operator-configurable object-size cap, and similar hardening
items) are tracked in [ROADMAP.md](ROADMAP.md)'s Deferred section and as open
GitHub issues rather than being open MVP scope.
