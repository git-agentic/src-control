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
| [0004](0004-crate-layout-and-dependency-rule.md) | Four-crate workspace with a strict dependency direction | Accepted | foundation |
| [0005](0005-in-ram-vfs-over-fuse.md) | Pure in-RAM copy-on-write worktrees, not FUSE | Accepted | 1 |
| [0006](0006-memory-budget-and-eviction.md) | Bounded blob budget with LRU eviction and optional spill | Accepted | 1 |
| [0007](0007-git-interop-via-gix.md) | In-process Git interop via gix, quarantined in one crate | Accepted | 1 |
| [0008](0008-committed-secrets-envelope-encryption.md) | Native committed secrets via envelope encryption | Proposed | 2 |
| [0009](0009-key-management-and-authorization.md) | Recipient-based key management and authorization | Proposed | 2 |

## Status legend

- **Proposed** — under discussion, not yet built.
- **Accepted** — decided and (for Phase 1) implemented.
- **Superseded by ADR-NNNN** — replaced; kept for history.
