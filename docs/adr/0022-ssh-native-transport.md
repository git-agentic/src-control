# ADR-0022: sc-native network transport over SSH (trait-mirror wire protocol)

- **Status:** Accepted
- **Date:** 2026-07-05
- **Phase:** 12
- **Builds on:** ADR-0013 (Transport trait), ADR-0015 (packs), ADR-0021 (CAS ref updates)

## Context

P6 proved the sync model over a local-path `Transport`; P8 made bulk transfer
one pack; ADR-0021 made concurrent ref updates safe. The noted follow-on —
network transport — is what turns src-control from local-only into a real
DVCS. The design question: what protocol, and how much new machinery?

## Decision

Mirror the existing 8-verb `Transport` trait 1:1 onto a framed stdio protocol,
and reach the far side by spawning the user's `ssh` binary:

- **Wire format:** `u32` big-endian length + payload frames. Requests are one
  opcode per trait verb plus `HELLO {version}` / `BYE`; responses are
  `OK body` or `ERR code message`. `NonFastForward` and `NotARepo` round-trip
  as typed errors (push semantics depend on the former); everything else
  degrades to a message-carrying generic.
- **Server:** `sc serve --stdio <path>` — a dispatch loop around the existing
  `LocalTransport`, so CAS ref updates, pack verification, and BLAKE3-on-read
  apply verbatim on the serving side. Verb failures are replies; only
  protocol violations end a session. The opcode surface is the only thing a
  client can ask for — no arbitrary path access, no exec.
- **Client:** `StdioTransport` implements `Transport` over a child process's
  stdio. `ssh://[user@]host[:port]/abs/path` remotes spawn
  `$SC_SSH-or-ssh [-p port] [user@]host -- sc serve --stdio <path>`, and
  rejects hosts or usernames beginning with `-` (argv flag smuggling into
  ssh). The `SC_SSH` override (Git's `GIT_SSH` pattern) lets tests and the
  demo drive the full ssh:// code path with a local shim, no sshd required.
- **Dispatch:** `open_transport(url)` picks `StdioTransport` for `ssh://`,
  `LocalTransport` otherwise; git remotes keep their existing path above the
  trait (ADR-0018). `clone/fetch/push` gain network support without changes
  to their logic.

Authn/authz is entirely SSH's; we never touch credentials. Confidentiality is
by construction: objects cross the wire as canonical bytes, so protected-path
ciphertext and secrets stay encrypted, and an interrupted push leaves at worst
unreachable objects (pack lands before the ref CAS), never a torn ref.

## Consequences

- Two machines with SSH access and `sc` on `PATH` can collaborate.
- Zero new dependencies; the server side reuses `LocalTransport` wholesale.
- Per-verb RPC is chattier than a session protocol; the heavy payloads
  (packs) are single-round-trip, and composite opcodes can be added behind
  the version handshake if latency ever matters.
- Accepted limitations: frames cap at 4 GiB (packs are in-memory anyway);
  `sc` must be installed on the server.
- Security: because `ssh host -- sc serve --stdio <path>` concatenates the
  remote args into the far host's login shell, `SshUrl::parse` rejects at
  parse time (a) hosts/usernames starting with `-` (argv flag smuggling, the
  Git CVE-2017-1000117 class) and (b) repo paths carrying any non-shell-inert
  character (command injection). The path allow-list is conservative
  (alphanumeric plus `/._-+@:~=,%`), which also means repo paths with spaces
  or shell metacharacters are unsupported over ssh — fail-closed rather than
  shell-quoted, since we control both ends of the URL space.
- Interaction inherited from P7 (not new to this phase): three-way merges of
  history containing protected paths are refused fail-closed, so the demo
  proves merge-recovery before protecting a path; fast-forwards are
  unaffected.

## Alternatives considered

- **Purpose-built session protocol (git smart-protocol style).** Fewer round
  trips, but a second sync code path that re-solves CAS/verification the
  trait impls already solved. The trait-mirror protocol can evolve into it.
- **Embedded SSH library (`russh`).** No external ssh dependency, but a large
  crate plus our own key/agent/host-verification handling — against the
  lean-deps taste, and Git proves shelling out is fine.
- **HTTP transport.** Needs a daemon and an auth design; SSH gives auth for
  free. HTTP remains a candidate follow-on for hosting scenarios.
