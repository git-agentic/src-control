# ADR-0008: Native committed secrets via envelope encryption

- **Status:** Accepted
- **Date:** 2026-06-24
- **Phase:** 2

## Context

Git's all-or-nothing access model makes committing secrets impossible: anyone
who can read the repo reads everything. Teams work around this with `.env` files,
`.gitignore`, and external vaults — brittle, easy to leak, and out-of-band from
the code they configure. Phase 2's wedge is to let env vars / keys be committed
**directly into repo state**, encrypted at rest and in transit, and decrypted
only inside an authorized execution context.

The object model already reserves a `Secret` object kind that flows through
fork/checkout/clone untouched (ADR-0002), so this is additive.

## Decision

Encrypt committed secrets with **envelope encryption**:

1. Each secret value is encrypted under a fresh, per-secret **data-encryption key
   (DEK)** using **XChaCha20-Poly1305** (AEAD: confidentiality + integrity, with
   a large random nonce that makes nonce reuse a non-issue).
2. The DEK is **wrapped** (encrypted) once per authorized recipient public key
   (see ADR-0009 for the recipient/identity model).
3. The `Secret` object stores the ciphertext, the AEAD nonce, and the set of
   wrapped DEKs keyed by recipient id. It is content-addressed and stored like
   any other object.

Decryption happens only in an authorized execution context: the runtime unwraps
the DEK with a held private key, decrypts the value, and injects it into the
process environment — it is never written to disk in plaintext.

A new `scl-crypto` crate will own the primitives; `sc secret add` and
decryption-on-checkout wire it into the CLI.

## Consequences

- A clone in an **unauthorized** context receives the secret object intact but
  cannot unwrap any DEK, so the value stays ciphertext — confidential by
  construction, with no separate vault. This is the flow the Phase 2 demo must
  show end-to-end.
- Secrets are versioned and diffable as first-class repo objects, travelling with
  the code they configure.
- Granting/revoking access is **re-wrapping the DEK** for a changed recipient set
  (ADR-0009) — cheap metadata, no need to rotate the secret value itself. (True
  revocation of an already-disclosed secret still requires rotating the value;
  this is a property of all such schemes, not a defect of ours.)
- New cryptographic surface area: key handling, nonce generation, and constant-
  time comparisons must be done with vetted crates and reviewed carefully.
- The Phase 1 invariant that **plaintext never touches disk except via checkout**
  extends to secrets: decrypted values go to process environment/memory only.
- Injecting a decrypted secret into a child process's environment is an
  **authorized LOCAL PROCESS context, NOT strong isolation**: the decrypted
  secret is observable by same-user processes, crash dumps, and shell
  wrappers through the child environment. The parent's intermediate
  decryption buffer is `Zeroizing` (best-effort, zeroed on drop), but the
  `OsString`/child-env copy handed to the spawned process is fundamental to
  env-var injection and cannot be zeroized — the kernel owns that copy once
  the child is spawned. This is a stated boundary, not a defect (P28).

## Alternatives considered

- **Whole-repo encryption (e.g. `git-crypt`, transparent filters).** Coarse:
  all-or-nothing per file and entangled with Git smudge/clean filters. We want
  per-secret recipients and a native object, not a filter hack.
- **External KMS/vault only (no committed ciphertext).** Keeps the vault problem
  we are trying to remove and breaks the "secret travels with the code" goal.
- **Symmetric shared passphrase for the whole repo.** No per-recipient
  authorization, painful rotation, easy to leak. Rejected.
- **age as the on-disk format directly.** age is the right *model* (and informs
  this design) but we want secrets as first-class content-addressed objects in
  our own store rather than opaque files; we reuse age's proven envelope approach
  rather than its file format.
