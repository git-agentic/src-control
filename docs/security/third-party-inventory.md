# Third-party dependency and tool inventory

The human-readable list of what this project is built from, spanning both
ecosystems. The machine-precise versions live in `Cargo.lock` and
`apps/desktop/package-lock.json` (both committed, integrity-hashed, and CI
verified); the CI-generated SBOM artifacts are the shareable form. Written as
OSTIF-audit follow-up T-11 (G-020/G-033).

## ⚠️ Vendored, hand-patched dependency (read first)

**`vendor/glib-0.18.5-patched/`** is an in-tree fork of the published
`glib 0.18.5` crate, wired in via `[patch.crates-io]` in the root `Cargo.toml`.
It carries a soundness backport for **RUSTSEC-2024-0429** ahead of the GTK3
stack it belongs to. Consequences:

- `Cargo.lock` records plain `glib 0.18.5` — any version-keyed scanner or SBOM
  will misreport it (as vulnerable, or as clean upstream) unless annotated.
  Scorecard's OSV check does exactly this (audit G-033/G-035; alert dismissed
  with rationale).
- Provenance, patch content, and removal condition are documented in
  `vendor/glib-0.18.5-patched/PROVENANCE.md`. Removal gate: Tauri 3 moving the
  Linux stack to GTK4.

## Rust workspace — direct dependencies by crate

Architectural quarantine rules (which crate may use what) are in
[`CLAUDE.md`](../../CLAUDE.md); this is the inventory view.

| Crate | Direct third-party deps | Role |
|---|---|---|
| `scl-core` | blake3, hex, thiserror, zstd | Content addressing, object model |
| `scl-vfs` | thiserror | In-RAM worktrees |
| `scl-gitio` | gix, anyhow, thiserror | Git interop (gix quarantined here) |
| `scl-crypto` | chacha20poly1305, x25519-dalek, ed25519-dalek, sha2, hkdf, rand_core, rand_chacha, zeroize, blake3, hex, thiserror | All cryptography (RustCrypto quarantined here) |
| `scl-repo` | blake3, hex, libc, regex, serde, thiserror, toml | Persistent store, merge, transports, policy |
| `scl-tlsio` | rustls, rcgen, ring, rustls-pki-types, hex, thiserror | TLS (quarantined leaf) |
| `scl-cli` | clap, anyhow, serde, serde_json, toml, hex | The `sc` binary |
| `scl-desktop` | tauri, tauri-build, tauri-plugin-dialog, serde, serde_json, toml | Desktop backend (read-only adapter) |

Transitive tree: ~`Cargo.lock` (includes the Tauri/GTK3 Linux stack, source of
most accepted advisories in `audit.yml`'s documented ignore list).

## Desktop frontend (npm, `apps/desktop`) — direct dependencies

| Package | Kind | Notes |
|---|---|---|
| react, react-dom (19.x) | runtime | Renderer |
| @tauri-apps/api | runtime | IPC bindings to the Tauri backend |
| @pierre/diffs, @pierre/trees | runtime | Diff/tree rendering of repository content. **Watch items**: small-publisher, `@pierre/trees` is a pre-release pin (`1.0.0-beta.5`) — in the untrusted-content render path (audit G-006 note) |
| typescript, vite, vitest, @vitejs/plugin-react, jsdom, @testing-library/*, @types/*, @tauri-apps/cli | dev | Build/test toolchain |

## Tools and services

| Tool | Where | Purpose |
|---|---|---|
| GitHub Actions (SHA-pinned: actions/checkout, dtolnay/rust-toolchain, Swatinem/rust-cache, rustsec/audit-check, github/codeql-action, ossf/scorecard-action, actions/setup-node, actions/upload-artifact) | `.github/workflows/` | CI, advisory audit, CodeQL, Scorecard |
| Dependabot | `.github/dependabot.yml` | Version + security updates: cargo, npm, github-actions |
| system `git` / `ssh` | runtime (P12/P18) | Spawned for ssh transport and hosted-Git bridge (`SC_SSH`/`SC_GIT` override) |
| Rust toolchain 1.96.1 | `rust-toolchain.toml` | Pinned; bumped deliberately |

## Maintenance

Update this file in the same PR that adds/removes a direct dependency, a
vendored copy, a CI action, or a tool. Transitive churn is Dependabot's job,
not this file's.
