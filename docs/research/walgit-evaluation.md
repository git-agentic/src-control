# walgit evaluation — could/should src-control use it as a git server?

Research date: 2026-08-26

## Recommendation (summary)

walgit ([github.com/tobi/walgit](https://github.com/tobi/walgit)) is a
three-day-old, MIT-licensed Rust git server — one binary in front of an
S3/GCS bucket, implementing Cursor's "Continuity" write-ahead-log
architecture, serving git **smart HTTP v0/v2 only** (no SSH), by Tobi Lütke
with two other contributors and 9 commits total.

- **(a) As a P18 bridge remote endpoint:** **Could: yes, today, zero code
  changes.** It is a standard smart-HTTP git server and our bridge delegates
  transport and auth to system `git`. **Should: no action needed** — nothing
  to build; at most a smoke test if a user reports it.
- **(b) As a recommended/bundled self-hostable server:** **Should: not yet.**
  Days old, pre-1.0 with an explicit no-backward-compat policy for everything
  except bucket data, effectively a single-org project. Revisit in 6–12
  months; the deployment story (one binary + bucket) is genuinely the best in
  class if it matures.
- **(c) As a design source:** **Should: yes — this is the real value.** The
  CAS'd-manifest-as-linearization-point, bundle-uri static clones, and
  checkpoint-plus-log-tail cold start map directly onto sc's content-addressed
  store and Deferred roadmap items. Read `AGENTS.md` and
  `docs/BUNDLE_URI_DESIGN.md` there; do not import code.

## What walgit is (primary sources)

All claims from the repo itself unless noted.

**Metadata** ([GitHub API `/repos/tobi/walgit`](https://api.github.com/repos/tobi/walgit),
fetched 2026-08-26): language Rust, license MIT, created 2026-08-23, last push
2026-08-25, 1,686 stars, 92 forks, 3 open issues. **9 commits total**, 3
contributors — igrigorik (5), tobi (3, Tobi Lütke), dsfaccini (1) — per the
[commits](https://api.github.com/repos/tobi/walgit/commits) and
[contributors](https://api.github.com/repos/tobi/walgit/contributors) API.
Initial public release commit is dated 2026-08-23 ("walgit: initial public
release"), i.e. the code was developed privately and dropped as one squash —
the public history says nothing about real development duration.

**Thesis** ([README.md](https://github.com/tobi/walgit/blob/main/README.md)):
"a git server that is one binary in front of an object store … no database, no
leader and no local state that matters." Every instance is a disposable cache;
"the bucket is the repository." It is explicitly "a Rust implementation of the
architecture Cursor described in *Git at any scale* (the system they call
Continuity)" — the Cursor post is vendored verbatim at
`docs/reference/cursor-git-at-any-scale.md`.

**Storage model** (README "How it works" + [AGENTS.md](https://github.com/tobi/walgit/blob/main/AGENTS.md) §2):
the repository lives in the bucket as a WAL under `repos/<owner>/<repo>/`:

- `manifest.pb` — tiny, **compare-and-swap rewritten**; the single
  linearization point. "That CAS *is* the consensus — no election, no quorum,
  no primary" (README).
- `log/<seq>.pb` — immutable entries (PUSH, COMPACT, CHECKPOINT, SETTINGS).
- `wal/<checksum>.pack|.idx|.rev|.bitmap|.commit-graph` — immutable
  content-addressed packs.
- `checkpoints/<seq>/` — folded ref snapshot so cold start is snapshot + tail.
- `leases/` — CAS-with-TTL, "the only cross-instance mutex."

A push: index the pack in a scratch dir (`git index-pack --fix-thin`), check
connectivity + policy, upload pack + log entry, CAS the manifest; on a 412
re-read and retry. A read: one conditional GET of the manifest (304 → serve
local). Reads are strictly consistent — "there is no 'eventually'" (README
invariants).

**Protocols served** (README "What it does" table): git **smart HTTP v0/v2**
— `ls-refs` with prefixes, fetch with filter/shallow/deepen, receive-pack
(atomic, deletes, tags, push options, report-status-v2), sha1 and sha256
repos; plus **bundle-uri** static-file clones, **Git LFS** (batch API + basic
transfer, objects in the bucket), a React web UI + JSON API/SDK, per-repo push
policy (`policy.json`), webhooks, and auth modes `none`/`token`(bearer or
Basic)/`oidc`. **No SSH transport anywhere in the tree** — the git surface is
HTTP-only (confirmed against the full recursive
[tree listing](https://api.github.com/repos/tobi/walgit/git/trees/main?recursive=1):
no ssh module exists; `crates/walgit-server/src/tls.rs` + rustls/rcgen handle
in-process HTTPS).

**Implementation** ([Cargo.toml](https://github.com/tobi/walgit/blob/main/Cargo.toml)):
Rust edition 2024, rust-version 1.90, tokio + axum + hyper, prost/tonic
protobuf, aws-sdk-s3 + google-cloud-storage backends, rustls 0.23 + rcgen for
in-process TLS, and a **heavy `gix` dependency** (gix 0.86 plus ~18 individual
gix-* crates: gix-pack, gix-protocol, gix-transport, gix-odb, gix-negotiate,
…). Division of labor per README: "Upstream `git` does upload-pack/repack/
bundle; walgit does receive-pack, the WAL and the plumbing" — i.e. **system
git is a runtime requirement on the server**, with gix used where measured
faster (GOAL.md §7: "Upstream `git` where it is right … `gix` where it is
faster and measured"). There is also a gix-based upload-pack driver
(`crates/walgit-git/src/upload_gix.rs`).

**Maturity signals, both directions.** Young: created 2026-08-23; 9 commits;
version 0.1.0; AGENTS.md opens with "**No backwards compatibility (pre-1.0)**
… Data in the bucket is the one exception." CI was only added 2026-08-25 by
the second contributor ("Add a CI workflow", commit history), fixing a broken
workspace build and non-gating test gates in the same PR — the initial drop
did not build clean. Serious: the test surface is unusually large for a new
repo — a ~104 KB fault-injection simulation suite
(`crates/walgit-server/tests/sim.rs`, "crashes, partitions, stale reads" per
README), a ~109 KB e2e suite driving real git, a cross-backend store contract
suite (`crates/walgit-store/tests/contract.rs`), and a 500k-ref scale test
(`crates/walgit-git/tests/refs500k.rs`). [GOAL.md](https://github.com/tobi/walgit/blob/main/GOAL.md)
cites a reference workload of a 57 GiB / 73 M-object / 466 k-ref monorepo
(clone 2075 s → 8 s with blob:none + bundles). These are the project's own
claims; nobody outside it has had time to validate them.

**License:** MIT (`LICENSE`, confirmed by the API license field). No
compatibility issue with this workspace.

## The src-control side (what "a git server" means for us)

Grounding, from this repo's own docs:

- Hosted-Git interop (P18) is a **system-git mirror bridge**
  (`docs/adr/0028-network-git-remotes.md`): each git-backed network remote
  keeps a bare mirror at `.sc/git-remotes/<name>/mirror.git`; `sc fetch` runs
  `git fetch --prune` into it, `sc push` runs the P10 export then `git push`.
  "Auth is fully delegated to the spawned `git` (ssh-agent, credential
  helpers, tokens); … `sc` has no credential surface." `SC_GIT` overrides the
  binary (`crates/gitio/src/bridge.rs:30`). The chosen ADR rationale: gix
  cannot push, so system git is transport-only and the gix quarantine
  (ADR-0007) holds for object translation.
- Identity across the boundary is the persisted `git_oid ↔ sc_id` marks map
  (`docs/adr/0018-git-as-a-remote.md`), independent of which git server sits
  at the other end.
- sc's native transports are its own: framed-stdio ssh:// (ADR-0022),
  sc+http:// (ADR-0036), sc+https:// via `tlsio` with TOFU pinning
  (ADR-0042), wire `PROTOCOL_VERSION` 4, streaming packs (ADR-0035). These
  speak the sc object model (BLAKE3 CAS, sealed objects) — **not** git's
  protocol — so a git server can never serve them.

Consequence: for src-control, "the git side of interop needs a standard git
remote endpoint" is the whole requirement. Anything `git fetch`/`git push`
can talk to works, unmodified.

## Evaluation by slot

### (a) Remote endpoint for the P18 bridge — could: yes; should: nothing to do

walgit serves standard smart HTTP v0/v2 including receive-pack with
report-status-v2 (README feature table), and authenticates via
`Authorization: Bearer` or the token as an HTTP Basic password, with an
install script that configures a git credential helper (README
"Authentication"). Our bridge spawns real `git` and delegates auth to git's
credential machinery (ADR-0028), so `sc remote add wg https://git.example.com/owner/repo.git --git`
should work against walgit exactly as against GitHub — including
`auto_create_on_push` creating the repo on first push (README quickstart).

Two caveats, neither blocking:

- **HTTP only.** A user whose walgit is auth'd via bearer token uses git's
  credential helper (walgit's installer sets one up); our bridge passes git's
  stderr through unmodified, so walgit's sideband-2 progress narration
  surfaces naturally.
- **bundle-uri** is a client-side optimization git negotiates itself
  (`transfer.bundleURI`); the mirror fetch neither needs nor conflicts
  with it.

Fit: automatic. Maturity/maintenance risk: irrelevant here — the risk is the
user's, whoever operates the endpoint, and no src-control code or docs depend
on it. **Recommendation: no work. Optionally note in a future P18 doc pass
that any smart-HTTP server (GitHub, GitLab, cgit+nginx, walgit) works.**

### (b) A self-hostable server to recommend or bundle — should: not yet

What it would buy over alternatives: `git daemon`/gitolite/plain-ssh-bare-repo
need a real filesystem and per-machine state; forges (Gitea/GitLab) need a
database and upkeep. walgit is one binary + one bucket, disposable instances,
built-in TLS, OIDC, LFS, and a web UI — operationally the simplest
self-hosting story described anywhere, *if the claims hold*.

Why not yet, with evidence:

- **Age and bus factor.** Public for three days at research time (created
  2026-08-23); 9 commits; effectively one author plus two drive-by
  contributors. No releases, no tags, no published binaries or crates.io
  packages (API: `has_downloads: false`, no releases).
- **Explicit instability.** AGENTS.md: pre-1.0, "no backwards compatibility …
  delete the old shape in the same change" for routes, config keys, clients —
  only bucket data formats are stable. Recommending it to users means
  recommending a moving target.
- **Unvalidated by anyone else.** The impressive numbers (2075 s → 8 s clone)
  are the project's own acceptance table (GOAL.md); the fault-injection sim
  is self-authored. Three days is not enough external exercise for a system
  whose consistency story rests on object-store CAS semantics across S3
  vendors.
- **We have no bundling need.** src-control's native remotes already cover
  self-hosting sc-to-sc (`sc serve --stdio|--http`, ADR-0022/0036/0042); the
  git side exists for interop with wherever users already are, which is
  overwhelmingly hosted forges.

**Recommendation: do not recommend or bundle now. Re-evaluate around
2027-Q1: look for tagged releases, external contributors, and independent
deployment reports.** MIT license poses no obstacle whenever that happens.

### (c) Design source for our own roadmap — should: yes, actively

This is where walgit (and the Cursor Continuity design it implements —
vendored at walgit's `docs/reference/cursor-git-at-any-scale.md`) earns study
time. Direct resonances with sc:

- **CAS'd manifest as the only commit point.** walgit's entire consistency
  model is "immutable content-addressed objects + one tiny CAS'd pointer"
  (README invariants). sc's store is already content-addressed
  (BLAKE3, CLAUDE.md invariants); its refs are the mutable pointer. If sc
  ever grows an object-storage backend or a multi-writer hosted mode, the
  manifest-CAS pattern is the proven shape — it replaces our single-writer
  `.sc/` lock (ADR-0011) with object-store primitives and no coordinator.
  Notably, ADR-0013 already anticipated "remote/managed-Git backends behind
  adapters" on the `Transport`/store seam.
- **Checkpoint + log-tail cold start** (walgit AGENTS.md §2.1) is the same
  idea as our oplog (ADR-0024) applied to *state reconstruction* rather than
  undo — relevant if sc servers ever need to be disposable caches.
- **bundle-uri static clones** (walgit `docs/BUNDLE_URI_DESIGN.md`): moving
  clone bytes out of the server into CDN-able immutable artifacts. sc's
  streaming pack transfer (ADR-0035) still ships every byte through
  `sc serve`; a "static bundle cut as a pure function of the log" would bound
  server cost for large sc repos. Candidate ROADMAP → Deferred entry.
- **Tasks/narration** ("nothing waits silently" — walgit README): sideband
  progress for long server-side work is a UX idea our transports could adopt.
- **What not to copy:** walgit is plaintext-at-rest by design (the bucket
  holds cleartext packs; auth is perimeter-only). sc's sealed objects,
  protected paths, and private branches (ADR-0014/0043/0044) are exactly the
  properties walgit's model lacks — an sc-over-object-store design would keep
  our sealing and borrow only their coordination layer.

**Recommendation: add a ROADMAP → Deferred note referencing this file for
(i) object-store-backed sc remotes via manifest-CAS and (ii) static bundle
offload for `sc serve` — both explicitly "recorded, not built."** (Not done
in this research pass; ROADMAP edits are out of scope for a research note.)

## Sources

- https://api.github.com/repos/tobi/walgit (metadata, license, dates, counts)
- https://api.github.com/repos/tobi/walgit/commits, …/contributors
- https://github.com/tobi/walgit/blob/main/README.md
- https://github.com/tobi/walgit/blob/main/GOAL.md
- https://github.com/tobi/walgit/blob/main/AGENTS.md
- https://github.com/tobi/walgit/blob/main/Cargo.toml
- Repo tree: https://api.github.com/repos/tobi/walgit/git/trees/main?recursive=1
- Local: `CLAUDE.md`, `docs/adr/0013-remote-sync-model.md`,
  `docs/adr/0018-git-as-a-remote.md`, `docs/adr/0028-network-git-remotes.md`,
  `docs/adr/0022-ssh-native-transport.md`, `docs/adr/0036-http-transport.md`,
  `docs/adr/0042-in-binary-tls-sc-https.md`, `crates/gitio/src/bridge.rs`
