# ADR-0005: Pure in-RAM copy-on-write worktrees, not FUSE

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** 1

## Context

Phase 1's wedge is letting an autonomous agent fork many worktrees of a repo,
work against each, and tear them down **leaving zero residual files on disk**.
Two realizations were considered: a FUSE mount that agents access as a normal
filesystem path, or a pure in-RAM virtual filesystem that agents access through
the library/CLI API, materializing to disk only on explicit checkout.

The motivating pain is that disk-based clones are slow on APFS, which bottlenecks
multi-agent workflows; and the headline guarantee is *zero residue*, which must
be demonstrable, not aspirational.

## Decision

Implement worktrees as a **pure in-RAM copy-on-write overlay** over an immutable
base snapshot. A `Worktree` holds an overlay map of path → (written bytes | tombstone).
Reads fall through the overlay to the base tree resolved from the store; writes
and removes stay in the overlay. Base blob bytes are shared through the store
behind `Arc<[u8]>`, so forking N worktrees off one snapshot is **O(N) in overlay
size, not O(repo size)**, and file content is never copied on fork.

Content lives only in RAM. The **only** operation that writes files is an
explicit `Worktree::checkout(dest)` to a caller-chosen directory, which the
caller then owns and removes.

## Consequences

- "Zero residual files" is provable: if nothing but `checkout` writes to disk,
  and the caller removes its checkout dirs, a before/after filesystem diff is
  clean (see `demo/run_demo.sh`).
- No kernel extension, no platform-specific mount code, trivially portable.
- Forks are cheap and isolated — demonstrated by parallel agents editing the same
  base without interfering.
- Agents cannot use arbitrary external tools directly against an in-RAM path;
  they either use the API or check out first. Accepted: agent runners integrate
  with the API, and checkout covers the "run a real tool" case.

## Alternatives considered

- **FUSE mount.** Most "transparent" — agents see real paths and use normal
  tools. Rejected for the MVP: on macOS it requires the macFUSE kernel extension
  (fragile, privileged install), complicates the zero-residue guarantee (mount
  lifecycle, stale mounts), and adds platform-specific code. Worth revisiting as
  an optional backend once the core model is proven.
- **OverlayFS / per-clone disk copies.** Defeats the purpose: touches disk and is
  slow on APFS, the exact problem being solved.
