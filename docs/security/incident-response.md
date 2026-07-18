# Security-incident response process

What to do when the project itself — not its code — is attacked or compromised.
Distinct from [`vulnerability-response.md`](vulnerability-response.md), which
handles *reports about bugs*; this handles *incidents in progress or
discovered after the fact*. Written as OSTIF-audit follow-up T-17
(G-011/G-030 — [`docs/audit/ostif-best-practices-audit.md`](../audit/ostif-best-practices-audit.md)).

For every incident class: **contain first, investigate second, disclose
honestly third.** The access inventory in
[`docs/agents/ACCESS.md`](../agents/ACCESS.md) is the checklist of what can be
revoked; keep it current or this document degrades.

## Incident classes and first moves

### 1. Maintainer credential or signing-key compromise

GitHub account, `git-agentic.com` DNS/registrar, or an `scl` identity/signing
key.

- Rotate the compromised credential at its source (GitHub password + tokens +
  sessions; registrar account; generate a fresh `scl` identity).
- Audit everything the credential could write since last-known-good:
  `git log` on all branches, releases, repo settings, workflow files, ruleset
  changes (`gh api .../rulesets`), org membership.
- For a compromised `scl` signing key: signatures bind identity to snapshot
  ids — enumerate commits signed by the key after the compromise window,
  re-sign or disavow them publicly. Remember **rotation ≠ erasure**: anything
  the key could decrypt (secrets, protected paths, private branches it was a
  recipient of) must be treated as read; rotate the underlying external
  credentials, then `sc rewrap` at the tip.

### 2. Compromised or prompt-injected agent (this project's distinctive class)

AI agents operate this repository with real write authority (`gh` CLI issue/PR
operations, commits — see `docs/agents/`). A manipulated agent — via a crafted
issue body, poisoned dependency docs, or a compromised upstream skill — is an
incident, not a code bug.

- **Contain:** revoke the agent's credential/session (the token it runs `gh`
  with); stop any running agent sessions.
- **Audit:** review every agent-authored commit, PR, issue action, and label
  change since last-known-good. Agent-authored security-relevant changes merged
  without distinct human review are presumed tainted until re-reviewed.
- **Revert** anything harmful; force-push is blocked on `main` by ruleset, so
  revert forward with explicit commits.
- **Find the injection source:** the issue/comment/document the agent ingested.
  Remove it, and record the pattern — it is the signature to screen future
  agent inputs against.
- **Disclose** in the repo (issue or advisory, depending on impact) — an
  agent-authored malicious commit that shipped to users is a supply-chain
  incident (class 4).

### 3. Development/CI infrastructure compromise

A compromised GitHub Action (repointed tag), a malicious dependabot PR merged,
CI secrets exfiltration.

- Actions are SHA-pinned (audit T-2) precisely to narrow this: verify the pins
  in `.github/workflows/*.yml` against upstream, and check the Actions run log
  for the compromise window.
- `GITHUB_TOKEN` is ephemeral per-run; the blast radius is what its per-workflow
  permissions allowed in tainted runs (see ACCESS.md). Check issues, checks,
  and security-events written during the window.
- Rotate any non-ephemeral secret that was ever exposed to a tainted run
  (currently: none configured beyond `GITHUB_TOKEN` — keep it that way).

### 4. Supply-chain incident (dependency backdoored, or we shipped bad code)

- **Inbound** (a dependency we use is announced backdoored): identify exposure
  window from `Cargo.lock`/`package-lock.json` history; both lockfiles are
  committed, so `git log -p` on them dates exactly when the bad version
  entered and left. Assume CI and any local builds in the window are tainted;
  see class 3.
- **Outbound** (we shipped it onward): nothing is published to crates.io or as
  binaries today (`publish = false`), so the outbound surface is people
  building from git. Disclose prominently (README banner + advisory), identify
  the bad commit range, and provide a known-good commit to reset to.

### 5. Data breach (user-entrusted content exposed)

The system's design bounds this: secrets and protected content are ciphertext
to non-recipients, but **escrow holders and recipients can read what they hold,
and nothing already fetched can be un-fetched** (rotation ≠ erasure). If a
recipient/escrow key is exposed: treat every secret/protected file/private
branch it could read as disclosed; rotate the *underlying* external
credentials (API keys etc.), then rotate src-control-side keys and `sc rewrap`.
Notify affected users plainly about what was readable and for how long.

## Every incident, after containment

1. Timeline: what happened, when detected, window of exposure, what was
   audited, what was rotated/reverted.
2. Disclose to affected parties (users, downstream projects) before or with
   any public write-up; if operating law requires reporting, that is the
   maintainer's jurisdiction-specific call (currently undocumented — audit
   G-026).
3. Post-incident: what guardrail would have prevented or shortened it; file it
   as an issue; update this document and `THREAT-MODEL.md` if a boundary
   changed.
