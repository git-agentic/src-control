# Desktop application strategy

Research date: 2026-07-14

## Recommendation

A desktop app is a stronger first product surface than a multi-tenant hosting
platform. It can make `sc` understandable and attractive without first taking
on accounts, organizations, billing, abuse prevention, high availability, and
other forge operations. More importantly, recipient identities and decrypted
protected content can remain on the user's machine.

The app must be an `sc` client, not a generic Git GUI. GitKraken already has a
visual commit DAG, worktree management, merge tooling, hosting integrations,
and a current Agent Sessions view that launches and monitors parallel coding
agents ([interface](https://help.gitkraken.com/gitkraken-desktop/interface/),
[worktrees](https://help.gitkraken.com/gitkraken-desktop/worktrees/),
[2026 release notes](https://help.gitkraken.com/gitkraken-desktop/current/)).
The differentiation therefore has to come from `sc` semantics: bounded
in-memory agent workspaces, sealed private branches, path-level permissions,
committed secrets, signature verification, transcript provenance, and
snapshot/operation-log workflows.

## Product shape

The primary screen should combine:

- a repository/branch/workspace sidebar;
- a snapshot DAG, including signatures, transcript presence, private/public
  state, and operation history;
- a change inspector with tree, file, and diff views;
- an agent-session dashboard showing status, changed files, conflicts, and
  harvest/merge results;
- clear lock/recipient UI for protected paths and private branches.

The workflow should avoid copying Git's index/staging terminology. Show the
working-tree delta as the next snapshot, then offer snapshot/commit, amend,
undo, branch, merge, resolve, fetch, and push actions using `sc`'s own model.

## MVP

1. Open an existing `.sc` repository.
2. Browse branches, snapshots, files, signatures, and transcript metadata.
3. View working changes and compare any two snapshots.
4. Commit/amend/undo, branch/switch, fetch/push, merge, and resolve conflicts.
5. Create, monitor, inspect, harvest, and abandon `sc ws` agent sessions.
6. Select a local identity and render protected content only when authorized.
7. Show private branches as opaque without an authorized identity and expose
   grant/revoke/publish as deliberate security operations.

Do not include hosted reviews, issues, CI, marketplace integrations, or team
administration in the first release.

## Technical direction

Use Tauri with a bundled TypeScript frontend:

- The existing implementation is Rust, so the Tauri command layer can call
  `scl-repo` and related crates directly instead of shelling out to the CLI.
- A web frontend can reuse the Apache-2.0
  [`@pierre/trees`](https://github.com/pierrecomputer/pierre/tree/main/packages/trees)
  and [`@pierre/diffs`](https://github.com/pierrecomputer/pierre/tree/main/packages/diffs)
  packages evaluated in the platform research.
- Tauri uses Rust for the application core and HTML in an OS WebView, connected
  by message passing, and supports macOS, Windows, and Linux packaging
  ([architecture](https://v2.tauri.app/concept/architecture/)).

Keep the trust boundary narrow. The frontend should be fully bundled with no
remote scripts; private-key bytes must never cross IPC; Rust commands should
accept typed, scoped operations; repository Markdown/HTML must be treated as
untrusted; and Tauri capabilities plus CSP should expose only required APIs.
Tauri itself emphasizes that the Rust core and WebView are different trust
groups and that IPC and capabilities must enforce the boundary
([security model](https://v2.tauri.app/security/)). Plaintext necessarily
enters the local renderer when an authorized user views a protected file, but
it need not leave the device.

Prefer Tauri over a pure-Rust immediate-mode GUI for this product because the
high-value work is polished tree/diff/code rendering and the selected Pierre
components are web-native. A pure-Rust GUI remains viable if eliminating the
WebView becomes a stronger requirement than UI reuse and development speed.

## Relationship to hosting

Desktop and hosting are complementary. Start with the desktop app to validate
the native workflow and security UX. Continue using GitHub mirrors for public
collaboration. Later, add a narrow hosted review/sync service whose links open
the local app for authorized decryption and private-branch operations.
