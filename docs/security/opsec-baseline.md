# Operational-security baseline

The standing rules for this project's development and CI infrastructure, so
they survive as policy rather than habit. Written as OSTIF-audit follow-up
T-20 (G-025).

## CI

- **GitHub-hosted ephemeral runners only.** No self-hosted runners — adding one
  creates a persistent trust boundary this project has deliberately avoided.
- **`GITHUB_TOKEN` is the only CI credential.** No long-lived cloud keys, PATs,
  or deploy tokens in Actions secrets. Any new secret needs a written
  justification in [`docs/agents/ACCESS.md`](../agents/ACCESS.md) first.
- **Least-privilege, job-scoped permissions.** Workflow-level `permissions:`
  stays read-only (`contents: read` / `read-all`); write scopes are granted
  per job, only where used (audit T-20 scoped `audit.yml`'s
  `checks: write` + `issues: write` to the job level).
- **Third-party actions are SHA-pinned** with a version comment; Dependabot
  maintains the pins (audit T-2). New actions enter SHA-pinned or not at all.
- **Merges to `main` are ruleset-gated**: PR required, **1 required approval**
  from a principal other than the last pusher (since 2026-07-18), stale
  approvals dismissed on push, last-push approval required, four required
  status checks, up-to-date branch, no force-push/deletion, no bypass actors.
  Nobody self-merges — the two admin accounts review each other's PRs.

## Accounts and devices

- **Org 2FA requirement: ENFORCED.** `two_factor_requirement_enabled` was
  enabled on the `git-agentic` org by the maintainer and verified via the API.
  ☑ done as of 2026-07-18. Any future member must have 2FA before joining.
- Maintainer GitHub account uses 2FA and per-device SSH keys; identity/signing
  keys for `scl` live outside any working tree (see ACCESS.md).
- Development machines: full-disk encryption and OS auto-update expected; no
  further device policy is codified for a solo project (revisit at second
  maintainer).

## Repository security features (all enabled 2026-07-18, audit Now-tier)

Secret scanning + push protection, Dependabot alerts + security updates,
private vulnerability reporting, CodeQL (3 languages), Scorecard (weekly).
Disabling any of these is a policy change: PR + note here, not a quiet toggle.
