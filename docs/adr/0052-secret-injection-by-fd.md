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
- A secret whose value holds a NUL byte is refused (it cannot be framed, and could not be an environment value either).
- The write end is close-on-exec and never reaches the child; the read end is placed by `dup2` in `pre_exec` (or has close-on-exec cleared if it already sits at `N`). The parent drops its read end after the spawn, so a child that exits unread breaks the pipe.
- The payload is written on its own thread, so a payload larger than the pipe buffer cannot block the parent before the child has read it, and a child that never reads does not hang `sc run`. The thread owns the zeroizing buffer and wipes it when it ends.
- The decrypted values now stay in `Zeroizing` buffers from `secret_values` all the way to the pipe; the environment path converts them to `OsString` as before (the un-zeroizable hand-off the threat model already names).

## Not decided here

`sc ws run --with-secrets` and `sc work --with-secrets` keep the environment, and there is no stdin variant (it would take the command's stdin). Both are additive and can follow if a user needs them.

## Consequences

- The default contract does not change: without the flag `sc run` behaves exactly as before.
- It is hygiene, not isolation. A same-user process can read the child's descriptor table, and the child decides what to do with what it read; a child that re-exports its secrets into its own environment has undone the benefit.
- Unix only. Other targets refuse the flag with a clear error.

## Tests

`crates/cli/tests/secrets_fd.rs`: the secrets arrive on the descriptor as framed records and are absent from the environment, which names the descriptor; the default environment path is unchanged; another descriptor number works and 0, 1, 2, -1 and 1024 are refused before the command runs; a 300 kB payload arrives whole; a child that never reads does not hang `sc run`.
