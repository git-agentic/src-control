# ADR-0010: Secrets as a snapshot-side registry with an opaque wrapped DEK

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** 2

## Context

ADR-0008/0009 fixed the cryptography but left two structural questions open: how
a `Secret` is referenced from repo state, and how the per-recipient wrapped DEK
is laid out in the object format.

## Decision

1. **Secrets live in a side registry on `Snapshot`** — `secrets:
   BTreeMap<String, ObjectId>` (a sorted name→id map) — *not* in the file tree.
   Secrets are environment variables, not files. `checkout` only materializes the
   file tree, so plaintext (or even ciphertext) is never written as a file; an
   authorized context injects decrypted values into a child process environment
   instead. Because `BTreeMap` iterates in sorted key order, the canonical
   encoding (and thus `ObjectId`) is independent of insertion order. The registry
   encodes empty for ordinary commits and Git imports.

2. **`WrappedKey.wrapped_dek` is an opaque blob owned by `scl-crypto`** with the
   layout `ephemeral_pubkey(32) ‖ wrap_nonce(24) ‖ wrapped-DEK ciphertext+tag`.
   `scl-core` stores it without interpreting it, so the object model carries no
   cryptographic structure and `core` stays free of any crypto dependency.

## Consequences

- Adding the registry changes the canonical encoding of every `Snapshot`, hence
  its `ObjectId`. Accepted as a pre-release format break.
- `core` depends on neither Git, worktrees, nor crypto — a new invariant.
- The wrapped-DEK layout can evolve (versioned by the `scl-dek-wrap-v1` HKDF info
  string) without touching `core`.

## Alternatives considered

- **Secrets in the file tree (new `EntryKind::Secret`).** Conflates files and env
  vars and forces `checkout` to learn to skip entries to avoid writing ciphertext
  to disk. Rejected.
- **A dedicated secrets `Tree`.** More machinery than a flat registry buys for an
  env-var namespace that is naturally flat. Deferred.
- **An explicit `ephemeral_pubkey` field on `WrappedKey`.** Pushes crypto layout
  into `core`. Rejected in favor of the opaque blob.
