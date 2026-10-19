# ADR-0052: Secret injection by file descriptor (`sc run --secrets-fd`)

- **Status:** Accepted (built)
- **Date:** 2026-10-19
- **Builds on:** ADR-0008/0009 (committed secrets), ADR-0019 (secret lifecycle); the threat model's "fd/stdin injection stays deferred" note

## Context

`sc run` injects decrypted secrets as child-process environment variables. The threat model records that this is an authorized local-process context, not isolation, and that fd/stdin injection was deferred with an additive fd-pipe opt-in named as the presumptive shape. The honest claim for a descriptor is narrow: against a same-user attacker who can read the identity key and `.sc/` it changes nothing. What it removes is accidental propagation: values in `/proc/<pid>/environ`, in an env dump that a script or an agent writes to a log or a committed file, and in the environment of every descendant.

## Decision

`sc run --secrets-fd N -- cmd` (`Repo::run_with_secrets_fd`, unix only):

- The parent opens a pipe and gives the child the read end as descriptor `N`; the secrets are **not** put in the child's environment. `SC_SECRETS_FD=N` (not a secret) tells the child where to read.
- The payload is NUL-terminated `NAME=VALUE` records, the shape of `/proc/<pid>/environ`, read to EOF. A shell can use `tr '\0' '\n' <&3` or `xargs -0`.
- `N` must be 3 to 1023. Descriptors 0, 1 and 2 are refused: the command keeps its stdio.
- A secret whose value holds a NUL byte, or whose name is empty or holds `=` or NUL, is refused before anything runs (it cannot be framed, and a forged record would otherwise reach the child).
- The write end is close-on-exec and never reaches the child; the read end is placed by `dup2` in `pre_exec` (or has close-on-exec cleared if it already sits at `N`). The parent drops its read end after the spawn, so a child that exits unread breaks the pipe.
- The requested descriptor is held open (close-on-exec) across the spawn when it is free, so the standard library cannot pick it for its own exec-error pipe and have the `dup2` clobber it; without that, asking for the descriptor `std` happens to choose makes a failed `exec` abort the child instead of reporting the error.
- The write end is non-blocking and fed by its own thread, so a payload larger than the pipe buffer cannot block the parent before the child has read it. The thread stops when the child has exited (the parent sets a flag and joins it), so a child that never reads does not hang `sc run` and a grandchild that keeps the descriptor open cannot pin the thread or the plaintext buffer. The payload is allocated once at its exact size, because a growing `Vec` leaves freed copies that `Zeroizing` never wipes, and the thread's drop wipes it.
- A descendant that inherits the descriptor and keeps it can still read it: closing or sealing the descriptor is the consumer's job.
- The decrypted values now stay in `Zeroizing` buffers from `secret_values` all the way to the pipe; the environment path converts them to `OsString` as before (the un-zeroizable hand-off the threat model already names).

## Not decided here

`sc ws run --with-secrets` and `sc work --with-secrets` keep the environment, and there is no stdin variant (it would take the command's stdin). Both are additive and can follow if a user needs them.

## Consequences

- The default contract does not change: without the flag `sc run` behaves exactly as before.
- It is hygiene, not isolation. A same-user process can read the child's descriptor table, and the child decides what to do with what it read; a child that re-exports its secrets into its own environment has undone the benefit.
- Unix only. Other targets refuse the flag with a clear error.

## Tests

`crates/cli/tests/secrets_fd.rs`: the secrets arrive on the descriptor as framed records and are absent from the environment, which names the descriptor; the default environment path is unchanged; another descriptor number works and 0, 1, 2, -1 and 1024 are refused before the command runs; a 300 kB payload arrives whole; a child that never reads, and a grandchild that keeps the descriptor, do not hang `sc run`; a missing command reports its real error for every nearby descriptor number; a NUL-bearing value and an unframeable name are refused.
