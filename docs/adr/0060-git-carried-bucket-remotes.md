# ADR-0060: Git-carried bucket remotes (`sc+git::`)

- **Status:** Accepted
- **Date:** 2026-11-21
- **Phase:** 39
- **Builds on:** ADR-0046 (bucket WAL remotes), ADR-0044 (private branches),
  ADR-0058 (sc-forge, addendum for `refs/sc/*`)
- **Amends:** ADR-0020 (dependency rule: `objio` may spawn the system `git`
  binary), ADR-0044 (reason 4 for rejecting opaque sealed refs through the Git
  bridge, reversed only under a per-remote opt-in)

## Context

Theo asked for three things in the place teams already host code, a Git host:
files only some teammates can read, branches only some teammates can see, and
secrets committed with the code. src-control has all three (P7 protected paths,
P34 private branches, P2 secrets), and none survives a Git host today. The Git
bridge (ADR-0016/0018/0028) refuses private branches, drops secrets, and
exports a protected path as bare ciphertext that loses its rules on re-import.
sc-forge (P38) is plain Git and adds nothing here.

An experiment showed the bucket WAL already carries all three. A repository
with a protected `config/`, a secret `API_TOKEN` and a private branch `hotfix`
was pushed to `sc+wal://<dir>`. A keyless clone listed `hotfix (private, no
access)`, had no `config/prod.env`, and saw the secret name without its value.
A keyed clone decrypted the file, injected the secret with `sc run`, and read
the embargoed branch. The WAL moves opaque values, so sealed content passes
through untouched. What is missing is a `Bucket` backend that stores those
values in a Git repository, which any Git host can hold.

## Decision

Add `sc+git::<git-url>`: the existing bucket WAL, with `objio::GitBucket`
storing the bucket inside the Git repository at `<git-url>`. No format change,
no wire change, no `PROTOCOL_VERSION` bump, no new crypto.

### Mapping

Bucket key `K` lives at the ref `refs/sc/K` (`refs/sc/manifest`,
`refs/sc/log/<seq>`, `refs/sc/packs/<hash>.pack`). Keys get a strict check on
top of `validate_key`, on every method including reads: `[A-Za-z0-9._/-]`, at
most 1024 bytes, no `..`, no component that starts with `.` or ends with `.` or
`.lock`. A default `git clone` or `git fetch` takes only heads and tags, and
the P18 bridge touches only `refs/heads/*`, so one Git repository can hold an
sc store and a plain Git mirror of the public branches side by side.

### Value encoding

A value is a parentless commit whose tree holds the bytes as chunk blobs `c0000`,
`c0001`, ... of at most 32 MiB each (GitHub's per-blob limit is 100 MB). The
commit message is `sc-bucket new <nonce>` for a create-only write and
`sc-bucket cas <nonce>` for a compare-and-swap write. The nonce makes every
write a new commit, so a fresh write can never be "up to date". Author and
committer are fixed (`sc <sc@invalid>`), so a clean account with no
`user.name` can write. The tag is the commit id. There is no parent link, so
fetching the manifest never pulls an old manifest. A value is at most 2 GiB,
for writes and reads (GitHub's per-push cap, and sc-forge's
`receive.maxInputSize` default); a larger value fails with an error naming the
cap.

### Atomicity: leases, never `+`

`put_new` pushes with `--force-with-lease=refs/sc/K:` (an empty lease: the ref
must not exist). `put_if_tag(Some(t))` pushes with `--force-with-lease=refs/sc/K:<t>`.
The receiving `receive-pack` checks the sent old value under its ref lock, so
two racing creates yield one `[new reference]` and one `[remote rejected]
(reference already exists)`, and two racing swaps on the same expected value
yield one winner. A `+` refspec is never used: with `+`, a wrong lease still
force-updated in the experiment (git 2.54).

A rejected push is classified by re-reading the exact ref with `ls-remote`,
never by the host's wording:

- the ref now holds the commit this write just built: the push landed and only
  its acknowledgement was lost, so the write succeeded (`true` / `Some(tag)`);
- `put_new`: the ref exists with another value means someone else created it
  (`false`); absent means a genuine refusal (error).
- `put_if_tag`: the ref no longer equals the expected tag (changed or deleted)
  means someone else won (`None`); it still equals the expected tag means a
  genuine refusal such as `pre-receive hook declined` (error).

Any write that is not a success drops the key's cached tag, so the 2 s freshness
window can never answer `Unchanged` for a tag that just lost a CAS.

So a hook or permission refusal never looks like a lost race, which
`BucketTransport` would report as a non-fast-forward and the user would retry
forever. A tag that is not a full nonzero hex object id returns `None`. Delete
pushes `:refs/sc/K` and treats an already absent ref as success.

### Reads: freshness, create-only caching, family batching

Each `GitBucket` has a private bare repository in `sc-git-bucket-<pid>-<random>`
under the temp directory (mode 0700), removed on `Drop`.

- A `get` whose cached tag equals the tag this instance observed or wrote for
  that key less than 2 s ago returns `Unchanged` with no network call.
  `BucketTransport::has_object` refreshes per object, which would otherwise cost
  one `ls-remote` each. Staleness is bounded and only causes a failed server-side
  CAS or a redundant upload.
- A key is create-only by its layout alone: `log/`, `checkpoints/`, or a `.pack`
  or `.idx` under `packs/`. Never by anything the writer controls, such as a
  commit message. This instance serves such a key from the local cache with no
  network call at all; its bytes stay valid even if compaction later deletes
  the key. Every other key (the manifest) is re-read once the freshness window
  passes.
- The first cache miss under `log/`, `checkpoints/` or a `packs/*.idx` key
  fetches that whole family in one `git fetch` (a glob refspec). This is
  GitBucket's knowledge of the WAL key layout. `.pack` values are fetched one
  by one. All fetches are `--depth=1`, so a hostile commit's parents are never
  downloaded. A counting `SC_GIT` shim test bounds the git network calls of a
  cold clone and an incremental push independent of the log length.
- A fetched value is validated before assembly: a commit with no parent, a tree
  of regular blobs named `c0000` onward without gaps, nothing else, each chunk
  at most 32 MiB, total at most 2 GiB for a `.pack` and 256 MiB for any other
  key. The ref must point directly at the commit (a tag object is not peeled),
  and family ref names are checked like any key before they enter the cache.
  Anything else is a corrupt store and an error. Fetches run with
  `fetch.fsckObjects=true`.

### URL allowlist and process hygiene

The inner URL must be `https://`, `http://`, `ssh://`, `file:///abs`, scp-form
`user@host:path` or an absolute local path. Refused: `git://`, relative paths,
a leading `-`, control characters, `::` (git transport helpers), any userinfo at
all on an `http(s)://` URL (credentials go through git's credential helper; a
token used as the username would otherwise be stored in `.sc/config` and echoed),
a password in an `ssh://` URL, an `ssh://` or scp-form user starting with `-`,
and an `ssh://` host outside the scp-form host charset. `sc+git:` in any letter
case with a single colon, or any near miss, is a reserved prefix and is refused
unless it is exactly lowercase `sc+git::<inner>`, so it never falls through to a
local path or to the mirror bridge. `--git` is an error on an `sc+git::` URL.
sc's own messages show a remote URL only with its userinfo redacted.

Every git call runs with `-c protocol.allow=never` plus `always` for `file`,
`ssh`, `http` and `https`, and `protocol.ext.allow=never`, `protocol.fd.allow=never`
and `protocol.git.allow=never` so a user config cannot re-enable them; `--end-of-options` before the URL; stdin closed;
`GIT_TERMINAL_PROMPT=0` and `LC_ALL=C`; hooks off (`core.hooksPath=/dev/null`),
`gc.auto=0`, `maintenance.auto=false`, signing off, `core.useReplaceRefs=false`,
and `http.lowSpeedLimit`/`lowSpeedTime` so a stalled host cannot hang a push.
`GIT_DIR` and every other `GIT_*` variable is removed except the user's
transport and credential setup (`GIT_SSH*`, `GIT_ASKPASS`, `GIT_CONFIG_GLOBAL`,
`GIT_SSL_*` and a few more), then `GIT_DIR` is set to the cache. The user's
credential helper and ssh agent keep working. `SC_GIT` overrides the binary, as
for the P18 bridge. Captured stderr is scrubbed (URL userinfo redacted, control
bytes dropped, length bounded), and the `repo` error type escapes control bytes
from any bucket error and exposes no raw `source`, so a hostile hook message
cannot drive the terminal. `ls-remote` patterns tail-match, so every result is
compared by exact full ref name.

### Caps against a hostile host

2 GiB per `.pack` value and 256 MiB for every other value (checked before
reading), 32 MiB per chunk, 10,000 chunks per value, 64 MiB of captured
`ls-remote` output, 1 MiB for other captured output. The WAL's own caps on
manifest, log, checkpoint and idx reads (256 MiB) and the pack record bounds
apply on top.

### Private-branch opt-in

Pushing a private branch to an `sc+git::` remote needs a per-remote setting,
`allow_private_branches`, set by `sc remote add <name> sc+git::... --allow-private-branches`,
`sc clone sc+git::... <dst> --allow-private-branches` (which sets it on the
new `origin`), or `sc remote set <name> --allow-private-branches` for an existing
remote (`--no-allow-private-branches` clears it). The push reads the branch and
its tip once, gates on that tip and pushes exactly it. Without the setting, `sc push` refuses before any upload and names the
flag. The gate lives in `repo` (the push path), not only the CLI. Protected paths
and secrets need no extra opt-in: choosing the scheme is the opt-in. `remote
add` and `clone` print one notice that public content and sealed metadata are
readable by everyone who can read the Git repository.

This reverses ADR-0044's reason (4) for rejecting "opaque sealed refs through
the git bridge", and only under that opt-in. Reasons (1) to (3) do not apply:
there is no Git rendering of sc history (the store holds opaque values, so
there is no incoherent Git structure to write), no marks map is involved (so it
gains no second meaning), and publish is an ordinary push to the same store (so
it cannot go stale against an exported artifact). Reason (4), a one-command
path to durably publishing embargo ciphertext on a public host, does apply, and
is why it is gated and why the notice and the refusal message say what stays
behind.

### Deferred in v1

- `sc remote compact` on an `sc+git::` remote is refused. A Git repository gives
  the compactor no trustworthy age for a stored pack: committer time is
  writer-controlled and predates publication, so it cannot drive pruning.
  `list_meta` exists for the trait contract and reports the observation time as
  `modified`.
- `sc serve --store sc+git::...` is refused. A daemon cannot answer ssh or
  credential prompts, and it would sit between clients and the client-side
  private-branch gate.

### sc-forge

The forge accepts exactly the `refs/sc/` prefix for create, update (including
non-fast-forward) and delete, for every repository, with no per-repository
switch. The details and tests are in the ADR-0058 addendum and
`docs/FORGE-OPERATIONS.md`. Stock `git receive-pack` and sc-forge are verified
to check the sent old value under the ref lock; a host that does not has no
atomic CAS and cannot carry this store safely.

### Dependency rule

`objio` stays a leaf, but it may spawn the system `git` binary for `sc+git::`.
`gix` stays quarantined in `gitio`. The system `git` binary is spawned only by
`gitio::bridge` and by objio's git backend. `GitBucket` does not live in `gitio`
because `repo` must not depend on `gitio`, and `repo` chooses the bucket backend
(clone, fetch, push); injecting it from `cli` would thread a factory through
every transport path.

## Consequences

- A user can run `sc remote add origin sc+git::git@github.com:org/repo.git` and
  push, fetch and clone private branches, protected paths and secrets through a
  Git repository. A keyless clone sees what a keyless clone of an `sc+wal://`
  remote sees. Proven by `crates/cli/tests/git_bucket.rs`, the forge end-to-end
  tests, and `demo/run_git_carrier_demo.sh`. Not tested against real GitHub
  (outside this work's grant); expect per-ref and per-push limits and any host
  that refuses unknown ref namespaces to be the failure modes.
- **The writer set is wider than S3.** Everyone with push access to the Git
  repository (collaborators, deploy keys, CI tokens) holds bucket put and
  delete, and there is no object versioning to recover. They can rewind
  `refs/sc/manifest` to a pre-revoke manifest, delete keys, or add packs. Branch
  protection and rulesets do not cover `refs/sc/*`. This is the same class as S3
  write access, with more holders. Rollback and rewind stay the tracked
  follow-ons (ROADMAP: P34 follow-on 6, a fetch-time freshness attestation;
  ADR-0059 follow-on 2).
- **Deleting a ref is not erasure.** A host may keep the objects fetchable by
  id, forks and mirrors keep their own copies, and compaction (when it exists
  for Git) only unreferences values. Sealed content stays ciphertext, so
  rotation is the cutover (`sc rewrap --rotate`), as for any transport.
- **Public content is plaintext in packs** on the host, as on any bucket remote.
- **Sealed metadata is readable by every reader of the repository:** private
  branch names, recipient ids, sealed-object counts and sizes, and the public
  fork point. Any one of them can fetch `refs/sc/*` by exact refspec, and
  `git ls-remote` lists the refs to everyone.
- A killed process (SIGKILL, or SIGINT, which skips `Drop`) can leave
  `sc-git-bucket-<pid>-<random>` behind in the temp directory. It holds fetched
  store objects. There is no reaper. A normal exit and an error returned to `main` remove it.
- v1 scaling limit: every `ls-remote` and push downloads the whole ref advertisement (the pattern given to `ls-remote` filters on the client; a packet trace showed the server sends every ref, protocol v2 `ref-prefix` or not), and a cold read fetches every `log/` and `checkpoints/` entry. With compaction refused, refs grow by at least three per push (a log entry, a pack and its idx), so a long-lived store gets slower to open until compaction or a ref-filtering host exists.
- Each cold read or push costs git round trips. The freshness window and family
  batching bound them, but a Git host is slower than S3. If push over `sc+git::`
  stays slow on large histories, the next step is a batched `has_objects`.
- sc-forge repositories keep a deleted or replaced value fetchable by id until
  the gc prune stage runs.
- The "not independently audited, do not commit production secrets" warning is
  unchanged.

## Alternatives considered

- **The Git bridge.** Lossy: private branches are refused, secrets dropped,
  protected paths lose their rules. Rejected; it stays the way to publish public
  history as a plain Git branch, and the same repository can host both.
- **One carrier ref holding the whole bucket tree** (Astra's alternative). One
  commit per bucket state gives coherent snapshots, but it serializes every pack
  upload behind one ref compare-and-swap and moves the transaction above the
  `Bucket` trait, so `BucketTransport` would need a second write path. Rejected.
- **A forge-native sc protocol** (sc-forge speaking `sc+http`). Works only where
  we run the server, not on GitHub or any other Git host. Rejected for v1.
- **`GitBucket` in `gitio`.** `repo` must not depend on `gitio`, and the backend
  is chosen inside `repo`. Rejected; see the dependency rule above.
- **`gix` instead of the system binary.** `gix` can fetch but not push (ADR-0028),
  and the user's credential helper and ssh setup only work through `git`.
  Rejected.

## As built

`crates/objio/src/git.rs` (`GitBucket`, the contract suite and race tests);
`crates/repo/src/bucket_transport.rs` (`BucketScheme::Git`, `is_bucket_url`,
`check_private_push_allowed`, `refuse_git_store`, `refuse_git_compact`);
`crates/repo/src/remote.rs` (`allow_private_branches`); `crates/cli` (flags,
notice, URL routing); `crates/forge/src/policy.rs` (`refs/sc/`). Tests:
`crates/objio/src/git.rs`, `crates/repo/src/bucket_transport/git_remote_tests.rs`,
`crates/cli/tests/git_bucket.rs`, `crates/forge/tests/e2e_git.rs`;
proof: `demo/run_git_carrier_demo.sh`.
