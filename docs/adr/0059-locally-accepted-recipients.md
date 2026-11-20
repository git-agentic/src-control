# ADR-0059: Locally accepted recipients

- **Status:** Accepted
- **Date:** 2026-11-20
- **Phase:** security hardening (post-P38)
- **Amends:** ADR-0025 (protected merge and replay: rules merge by union, and
  the union decides who a reseal wraps to), ADR-0027 (bulk rewrap: the target
  set is the rule plus escrow, or the secret's wrap labels plus escrow)
- **Builds on:** ADR-0008/0009 (secrets), ADR-0014 (protected paths), ADR-0019
  (rotation), ADR-0044 (private branches)

## Context

Three pieces of repository data decide whose key a seal wraps a DEK to, and a
writer needs no key to change any of them:

- **Protection rules** (`Protection.prefixes`). A writer can add a rule, or a
  narrower one under an existing prefix, granting their own key.
- **Secret wrap lists.** `Secret.wrapped_keys` labels are recipient ids with no
  proof attached. `sc secret rotate` without `--to` and `sc rewrap` resolve
  those labels back to keys and re-seal to the result.
- **Private-branch KEK wrap labels.** `BranchManifest.kek_wraps` is read the
  same way by `sc branch revoke`.

The victim then does something ordinary: fast-forwards, edits a file under the
new rule, commits. The commit seals the file and wraps its DEK to the writer.
The same happens through a clean merge or a replay that reseals a carried
plain file under a union rule (ADR-0025), a conflict completion, `sc rewrap`,
`sc secret rotate` and `sc branch revoke`. Nothing on the victim's side marks
the key as foreign, and signed commits do not help: the rule travels inside a
commit the victim has every reason to merge.

The fix must put the decision where a key is actually wrapped, must not need
the writer's cooperation, and must not turn every ordinary commit into a
prompt.

## Decision

### The record

`.sc/accepted-recipients` lists the keys **this clone** accepted, one
`<scope>\t<key>` line each. A scope is `path:<prefix>` (the winning rule's own
prefix string), `secret:<NAME>` or `branch:<name>`. A `path:` line holds the
full public key (`scl-pk-...`), since a rule holds full keys; `secret:` and
`branch:` lines hold the recipient id, since a wrap label is an id. Scope text
is escaped (`%`, tab, newline, carriage return) because a path prefix can hold
any byte but NUL. Local `[escrow]` keys from `.sc/recipients.toml` count as
accepted in every scope.

It is local state like `.sc/local-key`: written atomically (temp file and
rename) by a command that holds the repo lock, never part of a snapshot, never
in a pack, never sent by clone, fetch or push, and not read by `sc gc`. `sc ws`
and `sc work` commit through the host repo, so they use the host's record. Its
integrity depends on the working-tree path guard (a checkout never writes under
`.sc/`, fix/sc-path-guard): without it a cloned tree could plant the file.

Escrow keys are never recorded. They count as accepted from the `[escrow]`
section as it is when a seal is checked, so removing a key from `[escrow]`
withdraws its acceptance everywhere. The record loads only when something is
about to be sealed (or accepted, forgotten or checked by a revoke), so a commit
or a rewrap that wraps nothing does not depend on it being readable.

### The gate

A seal refuses, before anything is written, when a key it would wrap to is
neither accepted for the seal's scope nor escrow. The error names every
unaccepted pair: the scope, the recipient id, the local `[recipients]` name or
`UNKNOWN`, the `sc policy accept` command (with `--allow-unknown` for an
unknown key; a `path:` scope shows the full key to pass) and the command that
removes the key from the data. A scope is a rule prefix, secret name or branch
name, so the repository controls it: every field is escaped with
`sanitize_display_line`, and a scope with control characters gets no command
at all, only a pointer to `sc protect --list`, `sc secret list` or
`sc branch list`:

```
path:secret/sub/ grants a recipient you have not accepted: 3f9a... (UNKNOWN).
  Accept: sc policy accept path:secret/sub/ --key scl-pk-... --allow-unknown
  Remove: sc revoke secret/sub/ --recipient-id 3f9a...
Nothing was written.
```

Remove is `sc revoke <prefix> --recipient-id <id>`, `sc secret revoke <NAME>
--recipient-id <id>` or `sc branch revoke <name> --recipient-id <id>
--identity <key>`. A target that starts with `-` is written flags first and
after `--` (`sc revoke --recipient-id <id> -- -x/`).

The gate sits where wraps are minted, after the carry-or-seal decision, so a
carry that copies existing wraps is never gated:

| Site | Scope | Behavior |
|---|---|---|
| `protect::encrypt_protected`, the one function that turns a rule's recipients into wraps | `path:<winning prefix>` | refuses the whole call, naming every pair |
| callers: `snapshot_files` (commit, amend, merge/pick/rebase completion, `sc ws harvest`, `sc work`, `ws refresh`), the clean merge, `replay_commit` (cherry-pick, rebase), `branch_publish` (private-branch protected files) | | inherit it |
| `sc protect` | `path:<prefix>` | validates the candidate rule before anything moves (even with nothing to seal), then builds the rule's snapshot and the sealing commit before either ref moves (it advanced the ref before its sealing commit), so a refusal under any rule leaves ref and oplog alone |
| `secret_rotate` | `secret:<NAME>` | refuses on the final recipient set |
| `rewrap` (secrets and protected paths) | `secret:<NAME>`, `path:<prefix>` | an entry with an unaccepted key is skipped and reported, the rest is committed, the exit code is non-zero (ADR-0027 skip-and-report) |
| `branch_revoke` | `branch:<name>` | refuses on the remaining set |

A conflict stop writes plaintext and seals nothing, so it is not gated; its
completion commit is.

### Auto-accept

Only keys the user names on the command line are accepted without asking:
`sc protect --to`, `sc grant`, `sc secret add`, `sc secret grant`,
`sc secret rotate --to`, `sc branch --private --to` (and the creator's own
key) and `sc branch grant`. The library functions behind them record the keys
they were given, minus any key in the current `[escrow]` (a command appends the
escrow keys to the list it passes in, and those are not the user's choice); the
CLI then records the keys the user named, so a named key that is also escrow
survives its removal from `[escrow]`. `sc secret rotate --to` records from the
CLI because the library cannot tell a named set from one derived from wrap
labels. A key that comes from repository data, by any route, is never
auto-accepted. The local revoke commands remove the pair they revoke, after
validation and before the new ref is published, so an interruption leaves a
revoke that did not land (retry it), never a landed revoke whose approval
outlives it.

### Commands

`sc policy accept <scope> --key <scl-pk|id>[,...] [--allow-unknown]` records
pairs. A key in neither `[recipients]` nor `[escrow]` needs `--allow-unknown`,
so accepting a key you cannot identify takes a flag you typed. A `path:` scope
needs the full key: pass the `scl-pk-` string, or an id that resolves through
`[recipients]` or `[escrow]`. `--allow-unknown` does not lift that: an id with
no key behind it is an error for a `path:` scope. The batch is checked as a
whole and written once, so a bad entry leaves the record as it was.
`sc policy forget <scope> <key>` removes one. Both touch only the local file,
so both work while a merge, pick or rebase is stopped, and a refused
completion can be retried after an accept.

### Migration

The record starts empty and is not seeded from the tip: seeding would accept
exactly what an attacker already merged. The first seal in each clone that
reaches a key lists the pairs and refuses; the cost is one `sc policy accept`
per scope per clone, then silence. CI provisions the file from trusted
configuration. No snapshot encoding or wire change, and `PROTOCOL_VERSION`
stays 6.

## Consequences

- A writer without a key can no longer get a wrap by editing rules, wrap
  labels or manifests. They can still make a victim's seals refuse (below).
- A spurious reseal (a lost protected-path cache, ADR-0043) of unchanged
  content under a rule with an unaccepted key refuses too: the gate sees a
  seal, not a change.
- Accepting is a trust decision about a key, per scope and per clone. The
  error is the review prompt; `UNKNOWN` and the `--allow-unknown` flag mark
  the ones the user has no record of.
- Binaries from before this ADR do not enforce it. History already sealed to a
  writer's key stays readable by them (rotation is not erasure).

## Alternatives considered

- **Seal only to `.sc/recipients.toml`.** A rule would grant nothing the local
  file does not already list. Rejected: `recipients.toml` is a name directory
  of everyone the clone has ever wanted to talk to, not a per-scope decision,
  and a key listed there for one prefix would become valid for every rule and
  every secret. It also cannot express "this key for `secret/prod/` only".
  (A key in `recipients.toml` is still not accepted: test 2 pins that.)
- **Signed policy.** Rules and wrap labels authenticated by a trusted signer
  set. Rejected for now: it needs a trust root and key distribution that
  `sc` does not have for recipients (ADR-0032 signs snapshots, not policy), a
  format change to carry the signature, and it still leaves a trusted signer's
  mistake or compromise as a path to a wrap. A signed policy could later
  *supply* the accepted set; it would not remove the gate.
- **Gate at merge, not at seal.** Refuse a merge that brings in a new key.
  Rejected: a fast-forward brings the rule in without a merge, and a carried
  key that is never sealed to is harmless; the seal is the moment a key gets a
  DEK.
- **Seed the record from the tip on first use.** Rejected (see Migration).

## Deferred and residual risks

- **Protected ciphertext is not bound to its path.** Binding it is a format
  change. Until then a file relocated under an accepted prefix can gain
  recipients through that prefix's rewrap.
- **The private-branch KEK generation is not pinned.** `sc undo` can restore a
  pre-revoke manifest and so reuse a retired KEK.
- **A value can be replaced under an allowed secret name.** The registry is not
  authenticated; `sc verify --require` before `sc run` is the mitigation
  (THREAT-MODEL).
- **Denial of service.** Any writer can make a victim's seals refuse by adding
  keys; the cure is to revoke or accept, never silent.
- **`sc policy status` and `--all`** (list the record, accept every pending
  pair) are not built.
- **The printed Remove command does not always work.** `sc revoke` refuses to
  revoke a rule's last recipient (the attacker's own narrower rule: run
  `sc grant <prefix> --to <name>` first) and refuses while a merge, pick or
  rebase is stopped (accept, or abort the operation). A writer with a higher
  epoch can add the key back after a revoke.
- **`sc work` discards a refused agent's work.** Its harvest error is reported
  per workspace, but the temporary checkouts go with the session. Accept the
  keys first (`sc policy accept`); `sc ws` workspaces persist and can retry.
