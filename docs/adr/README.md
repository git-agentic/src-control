# Architecture Decision Records

This directory records the significant architectural decisions for src-control,
using a lightweight [Michael Nygard](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
format: **Context → Decision → Consequences → Alternatives considered**.

Each ADR is immutable once **Accepted**. To change a decision, add a new ADR that
supersedes the old one and update the **Status** line of the superseded record.

## Index

| ADR | Title | Status | Phase |
|-----|-------|--------|-------|
| [0001](0001-use-rust.md) | Implement in Rust | Accepted | foundation |
| [0002](0002-content-addressed-blake3.md) | Content-addressed objects keyed by BLAKE3 | Accepted | foundation |
| [0003](0003-snapshot-and-tag-model.md) | Snapshot-and-tag model over a Git-style staging model | Accepted | foundation |
| [0004](0004-crate-layout-and-dependency-rule.md) | Four-crate workspace with a strict dependency direction | Superseded by 0020 | foundation |
| [0005](0005-in-ram-vfs-over-fuse.md) | Pure in-RAM copy-on-write worktrees, not FUSE | Accepted | 1 |
| [0006](0006-memory-budget-and-eviction.md) | Bounded blob budget with LRU eviction and optional spill | Accepted | 1 |
| [0007](0007-git-interop-via-gix.md) | In-process Git interop via gix, quarantined in one crate | Accepted | 1 |
| [0008](0008-committed-secrets-envelope-encryption.md) | Native committed secrets via envelope encryption | Accepted | 2 |
| [0009](0009-key-management-and-authorization.md) | Recipient-based key management and authorization | Accepted | 2 |
| [0010](0010-secret-registry-and-opaque-wrapped-dek.md) | Secrets as a snapshot-side registry with an opaque wrapped DEK | Accepted | 2 |
| [0011](0011-persistent-store-and-working-tree.md) | Persistent loose-object store and git-like working tree | Accepted | 3 |
| [0012](0012-three-way-merge.md) | Three-way merge with a snapshot common ancestor | Accepted | 4 |
| [0017](0017-secret-scanner.md) | Accidental-plaintext secret scanner at commit time | Accepted | 5 |
| [0013](0013-remote-sync-model.md) | Remote sync via object + ref transfer over a pluggable transport | Accepted | 6 |
| [0014](0014-per-file-permissions-encrypted-paths.md) | Per-file permissions as encrypted paths (convergent encryption) | Accepted | 7 |
| [0015](0015-packfiles-and-gc.md) | Packfiles and reachability-based garbage collection | Accepted | 8 |
| [0016](0016-git-export.md) | Git export for round-trip interop | Accepted | 9 |
| [0018](0018-git-as-a-remote.md) | Git as a remote (bidirectional sync) | Accepted | 10 |
| [0019](0019-secret-lifecycle.md) | Secret/permission lifecycle (rotation + escrow) | Accepted | 11 |
| [0020](0020-six-crate-workspace.md) | Six-crate workspace with a strict dependency direction | Accepted | foundation |
| [0021](0021-durability-and-concurrency-hardening.md) | Durability and concurrency hardening for `.sc/` | Accepted | hardening |
| [0022](0022-ssh-native-transport.md) | sc-native network transport over SSH (trait-mirror wire protocol) | Accepted | 12 |
| [0023](0023-agent-workspaces.md) | Agent workspaces — vfs-backed sessions over the persistent store | Accepted | 13 |
| [0024](0024-history-editing.md) | History editing via replay + operation log | Accepted | 14 |
| [0025](0025-protected-merge-and-replay.md) | Protected merge & replay — perms-aware three-way with decrypt-on-demand | Accepted | 15 |
| [0026](0026-revocation-tombstones.md) | Revocation tombstones — durable prefix-rule revocation | Accepted | 16 |
| [0027](0027-bulk-rewrap-and-multi-escrow.md) | Bulk re-wrap and multiple escrow keys | Accepted | 17 |
| [0028](0028-network-git-remotes.md) | Network Git remotes (GitHub over https/ssh) | Accepted | 18 |
| [0029](0029-history-editing-polish.md) | History-editing polish — amend, resumable rebase, pick abort, merge replay | Accepted | 19 |
| [0030](0030-agent-sessions-and-automerge.md) | Agent sessions and auto-merge of clean results | Accepted | 20 |
| [0031](0031-hardening-consolidation.md) | Hardening & consolidation sweep — closing the P16–P20 review tail | Accepted | 21 |
| [0032](0032-signed-commits-provenance.md) | Signed commits & provenance | Accepted | 22 |
| [0033](0033-merge-ergonomics.md) | Merge ergonomics — conflict UX beyond markers | Accepted | 23 |
| [0034](0034-sparse-checkouts.md) | Sparse checkouts / sub-tree sharing | Accepted | 24 |
| [0035](0035-streaming-transfer.md) | Streaming pack transfer (bounded-RAM, >4 GiB) | Accepted | 25 |
| [0036](0036-http-transport.md) | sc-native HTTP transport (`sc+http://`) | Accepted | 26 |
| [0037](0037-partial-clone.md) | Partial clone (promisor store + prefix-scoped fetch) | Accepted | 27 |
| [0038](0038-agent-session-transcripts.md) | Agent session transcripts as CAS objects | Accepted | 30 |
| [0039](0039-security-hardening-sweep.md) | Security hardening sweep (audit fix-now items) | Accepted | 28 |
| [0040](0040-sc-http-access-control.md) | sc+http access control (read-only, fail-closed bind, bearer tokens) | Accepted | 29 |
| [0041](0041-listener-resource-limits.md) | Listener resource limits (connection cap, session timeout, spool cap, accept backoff) | Accepted | 31 |
| [0042](0042-in-binary-tls-sc-https.md) | In-binary TLS — `sc+https://` via rustls | Accepted | 32 |

See [`ROADMAP.md`](../../ROADMAP.md) for the phase sequence. ADR numbers are
assigned in creation order, so 0017 — the secret scanner — sequences as phase P5,
ahead of 0015–0016.

## Status legend

- **Proposed** — under discussion, not yet built.
- **Accepted** — decided and implemented.
- **Superseded by ADR-NNNN** — replaced; kept for history.
