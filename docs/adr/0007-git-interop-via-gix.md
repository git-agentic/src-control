# ADR-0007: In-process Git interop via gix, quarantined in one crate

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** 1

## Context

The MVP must build on / interoperate with Git rather than replace it, so agents
can fork worktrees from existing repositories. We need to read a Git repo's
`HEAD` tree and blobs and import them into our content-addressed store. Two
mechanisms exist: shell out to the `git` binary, or read the object database
in-process with a library.

## Decision

Import in-process using **`gix`** (pure-Rust Git), confined to the **`gitio`**
crate (ADR-0004). `import_head(store, repo_path)` opens the repo, resolves the
`HEAD` commit's tree, walks it recursively, inserts equivalent `Blob`/`Tree`
objects into the store, and returns a `Snapshot` id that worktrees fork from.

`gix` must be used **with its default features**: disabling them drops the `sha1`
hashing feature and `gix-hash` fails to compile. This is recorded as an
invariant in CLAUDE.md because it is non-obvious and already cost a build cycle.

Export (writing a snapshot back out as a Git commit) is the symmetric operation
and is deferred post-MVP; import is what the agent wedge needs first.

## Consequences

- No subprocess and no dependency on an installed `git` at runtime — faster and
  with typed errors instead of parsing CLI output.
- The large `gix` dependency and its API churn are isolated to one crate; the
  rest of the system stays Git-agnostic and could target a different VCS source.
- Submodule (`Commit`) tree entries are skipped in the MVP import; symlinks are
  imported as blobs with a symlink mode. Documented limitations, not blockers.
- We deliberately do **not** adopt Git's SHA-1 object ids (ADR-0002); import
  re-hashes content under BLAKE3.

## Alternatives considered

- **Shell out to `git`.** Simplest to start, but slower, depends on a correct
  `git` install, and turns every operation into fragile text parsing and error
  handling.
- **`git2` (libgit2 bindings).** Mature, but a C dependency with its own build
  requirements; `gix` keeps the toolchain pure-Rust and aligns with the language
  decision in ADR-0001.
