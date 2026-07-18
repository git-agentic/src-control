# Security-announcement subscriptions

Who watches which advisory feeds, and what is automated vs. human-watched.
Written as OSTIF-audit follow-up T-19 (G-013/G-024).

## Automated feeds (machine-checked, no human diligence required)

| Feed | Mechanism | Cadence |
|---|---|---|
| RustSec advisories (cargo tree) | `rustsec/audit-check` in `audit.yml`, live DB fetch | Daily cron + every Cargo change |
| npm advisories (desktop tree) | `npm audit` in the `desktop` CI job + Dependabot alerts/security updates | Every PR + continuous |
| GitHub Advisory Database (all ecosystems) | Dependabot alerts + security updates (enabled 2026-07-18) | Continuous |
| CodeQL (rust, actions, javascript-typescript) | `codeql.yml` | Push/PR + weekly |
| OpenSSF Scorecard | `scorecard_analysis.yml` | Push + weekly |

## Human subscriptions (maintainer: Toni Bergholm)

The feeds a human should actually read, because they announce things scanners
only catch after a version is flagged:

- **Rust security announcements** — `rustsec.org` feed and the Rust blog
  security posts (toolchain CVEs are invisible to cargo-audit).
- **Tauri security advisories** (GHSA for `tauri-apps/*`) — covers both the
  Rust crates and the JS bindings; the JS side has no RustSec coverage.
- **GitHub watch → security alerts** on this repository and on
  direct-dependency repos of the crypto stack (RustCrypto orgs, rustls).
- **GitHub Changelog / Actions security announcements** — the CI supply chain
  (this is how repointed-tag incidents get announced).

Status: the maintainer should confirm these subscriptions are actually in place
— a repository cannot verify an inbox (audit G-024). Tick and date on
confirmation: ☐ confirmed as of ____.

## Rule of thumb

If a new dependency or ecosystem enters the project (first release channel,
new language, new platform), add its advisory feed here in the same PR.
