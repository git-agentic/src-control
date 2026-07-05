# ADR-0021: Durability and concurrency hardening for `.sc/`

- **Status:** Accepted
- **Date:** 2026-07-05
- **Phase:** hardening (cross-cutting)

## Context

`.sc/` is user-owned durable state, "like `.git/`" (CLAUDE.md), and the
project's fail-loud invariant says data is never silently dropped. An audit
found four gaps between that standard and the implementation:

1. **No fsync anywhere.** All three write-then-rename helpers (`refs`, loose
   objects, packfiles) gave readers a consistent view but neither the file
   contents nor the rename were crash-durable — a power loss could orphan a
   committed ref or leave a zero-length object.
2. **Push was check-then-write without revalidation.** The fast-forward check
   ran against `list_refs()` unlocked; `update_ref` then wrote whatever it was
   given. Two concurrent pushes could both pass the check and the second would
   silently clobber the first's ref, orphaning its commits.
3. **A SIGKILLed process bricked the repo.** The lock file was existence-only;
   `Drop` never ran on kill/power-loss and every later invocation failed
   `Locked` until manual deletion.
4. **A confidentiality-relevant error was swallowed.** `materialize` removed
   stale plaintext for newly-protected paths with `let _ = remove_file(…)`; a
   failed removal silently left plaintext on disk.

## Decision

- **One durable atomic-write helper.** `scl_core::fsutil::atomic_write_durable`
  writes a per-process temp sibling, fsyncs it, renames, then fsyncs the parent
  directory (Git's discipline). All former copies (`refs::atomic_write`,
  `store::write_atomic`, the inline writer in `write_object_file`) delegate to
  it, so future durability changes are a one-site edit. Directory fsync is
  best-effort on platforms that cannot open directories.
- **Ref updates are compare-and-swap.** `Transport::update_ref` takes
  `expected_old: Option<&ObjectId>` (`None` = branch must not exist) and
  revalidates under the *remote's* lock, failing `NonFastForward` when the ref
  moved since the caller's check. Setting a ref to the value it already holds
  succeeds (idempotent re-push). `Repo::push` threads the tip it fast-forward
  -checked against into `update_ref`.
- **The lock file records the holder's PID** and `acquire` breaks a lock whose
  process is *provably* dead (`kill(pid, 0)` → `ESRCH`; unix only). Anything
  inconclusive — unreadable file, no parseable PID, `EPERM`, non-unix — is
  conservatively respected. Breaking retries the create exactly once, so a
  racing breaker degrades to a normal `Locked` error.
- **`materialize` propagates a failed stale-plaintext removal** (`NotFound` is
  still fine) instead of swallowing it.

## Consequences

- Commit/push durability now matches the "like `.git/`" claim; each loose
  object, pack, and ref write costs one file fsync + one directory fsync.
  No batching yet — if commit latency on huge trees ever matters, batch the
  directory fsyncs per commit (one-site change in `fsutil`).
- The push race window is closed at the ref write. The unlocked FF pre-check
  remains as a fast path; correctness no longer depends on it.
- A crashed `sc` self-heals on the next invocation; `libc` becomes a direct
  (unix-gated) dependency of `scl-repo` for the liveness probe.
- Legacy PID-less lock files are never auto-broken — the error still names the
  file for manual removal.

## Alternatives considered

- **`flock`/`fcntl` advisory locks** instead of PID stamping: kernel-released
  on process death (strictly better semantics), but not sensibly expressible
  for the lock-*file* protocol shared with future network transports, and OS
  advisory-lock portability (NFS, macOS quirks) is its own swamp. PID stamping
  is observable, debuggable, and good enough for a local single-writer lock.
- **A `Transport::update_ref` that re-runs the ancestor check** (not just
  equality with an expected tip): needs object access inside the lock and
  duplicates merge logic in every transport; CAS against the checked tip gives
  the same safety with strictly less machinery.
- **fsync only refs, not objects** (objects are content-addressed and
  re-derivable): a ref that survives pointing at an object that didn't is
  exactly the corruption users cannot self-diagnose; sync both.
