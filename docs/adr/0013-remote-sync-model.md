# ADR-0013: Remote sync via object + ref transfer over a pluggable transport

- **Status:** Proposed
- **Date:** 2026-06-25
- **Phase:** 5

## Context

Phase 3 made repos durable on disk. The "in-memory clones" thesis pillar and real
collaboration need a way to copy a repo and synchronize objects and refs between
locations. This also sets up the headline P6 demo: an *unauthorized clone* that
receives encrypted content it cannot read.

## Decision

Add **clone / push / fetch** built on transferring content-addressed objects plus
ref updates, behind a **pluggable `Transport` abstraction** whose first
implementation is a **local filesystem path** (copy between two `.sc/` repos):

- **`sc clone <src> <dst>`** — create `<dst>/.sc`, transfer all objects reachable
  from the source's refs, then copy the refs and set HEAD. Because objects are
  content-addressed, transfer is idempotent and integrity is verified on read
  (BLAKE3 == name), exactly as for local reads.
- **`sc fetch`** — negotiate which objects the local repo is missing (walk
  reachability from remote refs, skip objects already present), transfer them, and
  update remote-tracking refs (e.g. `refs/remotes/<name>/<branch>`). Integration
  into a local branch is via `merge` (ADR-0012).
- **`sc push`** — the symmetric operation, gated by a fast-forward check on the
  remote ref (no force this round).
- A `Transport` trait abstracts "list refs", "has object?", "get/put object",
  "update ref" so SSH/HTTP transports can be added later without touching the
  sync logic.

**Confidentiality property:** transfer moves objects verbatim. Encrypted-path
blobs (P6) and secret objects (Phase 2) travel as ciphertext; a clone whose holder
is not a recipient receives them intact but cannot decrypt — confidential by
construction, no special-casing in the transport.

## Consequences

- Completes a usable collaboration loop with P4 (fetch → merge).
- Reachability-based negotiation avoids resending objects; it gets materially
  faster once packfiles (P7) allow bulk transfer, but does not require them.
- Single-writer `.sc/lock` (Phase 3) must be respected on the receiving side
  during ref updates.
- Push fast-forward-only avoids clobbering remote history this round; non-ff
  push / force is deferred.

## Alternatives considered

- **Rsync/dumb file copy of the whole `.sc/`.** Works for clone but wastes
  bandwidth on fetch and ignores reachability/negotiation; the `Transport` trait
  keeps the dumb copy as the local-path implementation while allowing smarter
  transports.
- **Network transport (SSH/HTTP) first.** More moving parts (auth, framing) before
  the core sync logic is proven; deferred — local-path transport proves the model.
- **Git's smart protocol / packfile negotiation now.** Premature before P7 defines
  our pack format; negotiation starts object-granular and upgrades later.
