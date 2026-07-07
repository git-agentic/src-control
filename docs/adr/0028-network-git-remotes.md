# ADR-0028: Network Git remotes (GitHub over https/ssh)

- **Status:** Proposed
- **Date:** 2026-07-07
- **Phase:** 18
- **Builds on:** ADR-0018 (git as a remote), ADR-0016 (git export), ADR-0007 (gix quarantine)

## Context

ADR-0018 made a local `.git` path a first-class remote via a persisted
marks map, and explicitly deferred network Git as "a transport swap onto
the same translation core." Reaching hosted repos (GitHub over https/ssh)
is the largest remaining adoption gap.

## Decision

Extend `crates/gitio` to fetch/push over the Git network protocols using
`gix`'s transport support, underneath the unchanged P10 marks-map
translation and P9 confidentiality gate (`--include-encrypted` still
required for protected content). `gix` stays quarantined in `gitio`. Auth
rides the ecosystem's existing mechanisms (ssh-agent, credential
helpers/tokens) — the exact surface is fixed in the phase spec. This is
Git protocol only; an sc-native HTTP transport remains deferred.

## Consequences

- `sc remote add origin git@github.com:…` + fetch/merge/push works
  against real hosted repos; the demo shows pushed commits on github.com.
- Network failure modes (auth, partial transfer) enter the git-remote
  path for the first time; fast-forward-only push semantics are kept.

## Alternatives considered

- **Shell out to the `git` binary:** breaks the in-process interop
  decision of ADR-0007 and adds an external runtime dependency.
- **sc-native HTTP transport first:** serves no existing hosts; Git
  protocol reaches every forge today.
