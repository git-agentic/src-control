# ADR-0060: Git-carried bucket remotes (`sc+git::`)

- **Status:** Accepted
- **Date:** 2026-11-21
- **Phase:** 39
- **Builds on:** ADR-0046 (bucket WAL remotes), ADR-0044 (private branches),
  ADR-0058 (sc-forge, addendum for `refs/sc/*`), ADR-0057 (compaction; its
  addendum lifts the v1 compaction refusal)
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
`delete_leased` (used by compaction) pushes `:refs/sc/K` with
`--force-with-lease=refs/sc/K:<oid>` for every key of a chunk, never `+` and
never `--atomic`: a key re-created since the caller's listing holds another oid
and survives; a key still at its lease after a refused push is an error.

### Reads: freshness, create-only caching, family batching

Each `GitBucket` has a private bare repository in `sc-git-bucket-<pid>-<random>`
under the temp directory (mode 0700), removed on `Drop`.

- A `get` whose cached tag equals the tag this instance observed or wrote for
  that key less than 2 s ago returns `Unchanged` with no network call.
  `BucketTransport::has_object` refreshes per object, which would otherwise cost
  one `ls-remote` each. For a pusher, staleness is bounded by the window and
  normally costs a failed server-side CAS or a redundant upload. It is not
  harmless for a delete: a view up to 2 s old can miss a push that has just
  named a pack, so compaction never trusts it. It reads the manifest with no
  cache (`get("manifest", None)`) and compares tags before every destructive
  batch (ADR-0057 addendum).
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
- **Batched writes and presence checks.** `Bucket::put_new_batch` pushes the
  value commits of several create-only keys in one `git push --porcelain` per
  chunk (at most 64 MiB of values, an item over that alone, and the leased
  delete's item and command-line bounds), with one `--force-with-lease=refs/sc/K:`
  per ref; never `+`, never `--atomic`, since the keys are independent (a pack
  without its idx is an orphan compaction sweeps, as after two separate pushes).
  Which refs landed is read from the per-ref porcelain lines whatever the exit
  status; every other ref is dropped from the cache and classified together by
  one `ls-remote` of its exact refs, with the same rules as a single `put`
  (our commit there: landed; another value: lost; nothing: the host refused).
  If that re-read fails the push refusal is returned, never `false`.
  `exists_batch` is one `ls-remote` per command-line-bounded chunk with an exact
  refname compare, and is never answered from the local cache. `BucketTransport`
  uploads a pack and its idx with one `put_new_batch`, checks every pending pack
  and idx with one `exists_batch` before the manifest CAS, and after a won CAS
  builds its view from the manifest it just wrote instead of reading it back.
  Counted with a logging `SC_GIT` shim through `sc push` of one small commit: a
  first push 19 network git calls → 10 (three probes of the empty remote at open,
  in `list_refs` and in `update_ref`, three pushes, one existence check), a second
  push 11 → 8. The old tip's pack is still downloaded by the ref rule on every
  push after the first (bandwidth, not round trips).
- A mutable key (the manifest) is read with one call, `git fetch --depth=1
  +refs/sc/K:refs/sc/K`, instead of `ls-remote` followed by `fetch`. The local ref
  after the fetch is the tag; if it equals the caller's cached tag the read is
  `Unchanged`. Every git call pins `protocol.version=2`, so the fetch sends
  `ref-prefix refs/sc/K` and a v2 host lists that ref alone, not its branches
  and other keys (packet traces: a local bare repository and sc-forge over
  smart HTTP, both in the tests). A failed fetch does not say whether the ref is
  absent, so an exact `ls-remote` of that one ref decides absent versus error.
  Git resolves a refspec source that no remote ref matches exactly by its
  abbreviation rules, so a branch, tag or remote-tracking ref spelled
  `refs/sc/K` after its own prefix would stand in for an absent key. The fetch
  carries negative refspecs for those five spellings, which keeps the exact-name
  semantics `ls-remote` plus a compare had.
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
A stored carrier URL therefore never holds a password or token. sc's refusal and
error messages redact userinfo; `remote list` and the clone summary print the
stored URL as for every other remote kind, which can include an ssh user name
such as `git@`.

Every git call runs with `-c protocol.allow=never` plus `always` for `file`,
`ssh`, `http` and `https`, and `protocol.ext.allow=never`, `protocol.fd.allow=never`
and `protocol.git.allow=never` so a user config cannot re-enable them; `--end-of-options` before the URL; stdin closed;
`GIT_TERMINAL_PROMPT=0` and `LC_ALL=C`; hooks off (`core.hooksPath=/dev/null`),
`gc.auto=0`, `maintenance.auto=false`, signing off, `core.useReplaceRefs=false`,
and `http.lowSpeedLimit`/`lowSpeedTime` so a stalled host cannot hang a push;
`protocol.version=2`, `fetch.unpackLimit=1` and `fetch.uriProtocols=` are pinned for the
filtered manifest read and the fetch watchdog below.
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

### Fetch watchdog: a download budget

`git fetch` has no input-size limit (`fetch.maxInputSize` and
`transfer.maxInputSize` are ignored), so the caps above used to apply only after
a hostile host had already written its data into the cache. Every fetch now runs
under a watchdog:

- `fetch.unpackLimit=1` makes all incoming data land in one
  `objects/pack/tmp_pack_*` file, never in loose objects, and
  `fetch.uriProtocols=` and `transfer.bundleURI=false` stop a host from moving
  the download to packfile or bundle URLs the watchdog could not see.
- The fetch reads the total size of `objects/pack` before it starts and polls it
  while it runs (2 ms at first, backing off to 50 ms), while detached threads drain
  git's pipes. Git is killed when the growth passes the budget: the key's value cap
  plus 0.1% and 1 MiB for a fetch of one key (256 MiB or 2 GiB plus), 2 GiB for a
  family or batched fetch. It is also killed when nothing grows and nothing exits
  for 120 s, so a silent host cannot park a served session on a fetch. Only
  fetches are watched: `ls-remote` and push run unwatched. Over HTTP,
  `http.lowSpeedLimit`/`lowSpeedTime` bound them; over ssh the operator should set
  `ServerAliveInterval` (and `ServerAliveCountMax`) for the daemon's ssh user.
  The 2 GiB family budget is not a cliff for a legitimate store. A store whose
  `log/`, `checkpoints/` or `packs/*.idx` entries together exceed it would
  otherwise be unreadable, and so could never be compacted. When a family fetch
  passes its budget it is killed and discarded as usual, and the requested key is
  then read with a fetch of its own, under that key's own value cap. The instance
  remembers that the family is too big (one note on stderr) and reads that
  family's other keys by single fetches straight away, with no further 2 GiB
  attempts; each family is judged on its own. The cost is one git round trip per
  key of that family in a cold read, until compaction has shrunk it. Any other
  failure of a family fetch is an error as before, and a hostile value in an
  oversized family still fails its own cap.
- A fetch that finished between two polls is caught by a check after it exits.
  After git exits the watchdog keeps measuring `objects/pack` for the one deadline
  both pipes share, because a helper that outlived git can still be writing, and
  measures once more after both pipes have closed, before it calls the fetch good.
  Every breach (the budget during the run, the budget after git exited, no
  progress, a pipe a helper keeps open after git exits) takes one path: stop git
  (the group in serve mode), reap it, keep watching until the pipes have closed
  and `objects/pack` has stopped changing or 5 s have passed, then discard. The
  files the fetch added to `objects/pack` and every local ref under `refs/sc/`
  are removed (the cache only mirrors the host; the next read fetches again) and
  the error names the cap. Discarding before the helpers are gone would let a
  survivor write into the cleaned directory.
- The cache path is made absolute before any git runs: git runs with the cache as
  its working directory and `GIT_DIR` set to it, so a relative serve home (`.`)
  would be resolved from inside the cache.
- Serve mode, on unix, spawns git in its own process group and signals the group
  (`kill -s KILL -- -<pgid>`, std only, no `unsafe`), so `ssh` and
  `git-remote-https` die with it. The group is signalled only while the leader is
  unreaped: its pid pins the group id then. Once the leader is reaped, the id of
  the group is free to be reused by an unrelated process group of the same user,
  and nothing observable shows that it has not been (an open pipe proves a live
  member only at the instant it is looked at, and the external `kill` runs
  later). Pinning the pid without reaping needs `waitid(WNOWAIT)`, which is
  `unsafe` and not allowed here. So after the reap the group is never signalled,
  whatever the pipes say; the decision is `may_signal_group`. That needs a `kill`
  program on the PATH; if it cannot be run, the watchdog falls back to killing
  git alone and prints one warning. The CLI does not use a process group: Ctrl-C
  must still reach git and ssh must still be able to prompt on the terminal. It
  kills git alone, and the pipe readers are detached threads, so a helper that
  outlives git and holds the pipes cannot block the call. A git that exits while
  a helper holds its pipes is an error once one shared 120 s deadline for both
  pipes has passed, after which the watchdog settles for a bounded time and
  discards what the fetch added. Windows kills the child only.
- A helper that outlives git's exit is therefore not killed, in either mode, and
  may keep writing after the discard until it exits. That covers a smart-HTTP
  v0/v1 helper chain, an ssh `ControlPersist` master, and a hostile process. The
  watchdog bounds disk only while git itself is running (or its group can still
  be signalled); after git exits it measures, settles and discards, and cannot
  stop a survivor. The planned fix (ROADMAP, `sc+git::` follow-on 10) is a
  group-leading supervisor: in serve mode, run git under a std-only `sh` leader
  (`sh -c 'git "$@"; echo $? > <status file>; read _' sh <args>`, with stdin piped
  from sc) so the process group id stays pinned after git exits. The watchdog could
  then group-kill a helper that outlives git, which closes this gap, before it
  closes the leader's stdin and reaps it. Not built in v1.

The exact limits:

- The bound is disk bytes per fetch. It is not RAM inside git's `index-pack`, and
  not the total size of the cache, which grows by what each fetch keeps and lives
  as long as the process. An HTTP daemon opens one cache per connection, so its
  worst case is the per-fetch budget times `--max-connections`, plus what the
  caches keep.
- Refs a family fetch writes are not measured. A hostile host can advertise a
  great many refs; only the 120 s no-progress deadline bounds that.
- Only serve mode on unix actually bounds disk against a hostile HTTP host. Outside
  it (the unix CLI, Windows), and possibly against a smart-HTTP host on protocol
  v0 or v1, the kill may not reach the helper chain that writes the pack
  (`git-remote-https`, `index-pack`), which can keep writing after git is killed.
  Those cases are not disk-bounded; the watchdog still frees the call.
- A fetch in its own process group outlives a killed `sc serve`: a supervisor
  that kills the whole cgroup covers it.

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

### Serving a Git store (`sc serve --store sc+git::<url>`)

`sc serve --store sc+git::<url>` works over `--stdio` and `--http`. The server is a
client of the Git host with the operator's credentials, so git must authenticate
without prompting (an ssh agent, a key without a passphrase, or a credential
helper; `GIT_TERMINAL_PROMPT=0` is already set). The private-branch opt-in moves
to the server: `sc serve ... --store sc+git::... [--allow-private-branches]` (the
flag is refused for any other store). The client-side gate cannot cover this path,
because the client talks to the server with `sc+http` or `ssh` and has no idea a
Git host sits behind it.

Without the flag, the gate sits inside `BucketTransport` behind a per-instance
flag the serve opener sets (`open_for_serve`), at the three places sealed-branch
data can arrive, not in `upload_pack`:

1. `PutPack`: the parse callback stops at the first object of a sealed-branch kind
   (`Sealed`, `Manifest`, the predicate `is_sealed_branch_object`) before
   `upload_pack`, whatever the order of the records.
2. `PutObject`: the object is refused before it is staged, so a later `UpdateRef`
   cannot flush it.
3. `UpdateRef`: after the shared ref rule, a ref pointed at a manifest is refused,
   including a manifest already on the chain (written by a direct writer), so an
   existing private branch cannot be advanced or re-pointed through the server.

The error is `InvalidArgument` (`EC_OTHER`, no wire change) and names the server
flag. The check runs per request, so no order of `PutObject`, `PutPack` and
`UpdateRef` gets a sealed object to the host: the tests drive the hostile orders
against a real bare repository and inspect it afterwards. Reads are unchanged: a
private branch that is already on the host is served. A writer with direct push
access bypasses the server entirely; that is the writer-set point under
Consequences.

The cache lives under the serve home's `.sc/tmp/` (`GitBucket::open_in`), not the
system temp directory, and the bucket holds an advisory `File::lock` on
`<cache>/.owner.lock` for its whole life. `sc serve` removes `sc-git-bucket-*`
directories there at startup, but only those whose lock it can take (`try_lock`
succeeds), which means no live bucket holds it: many `sc serve --stdio` processes
share one home, so a sweep of every directory would delete a live session's cache.
The OS drops a lock with its holder, so this needs no pid number and no helper
program: it is correct under pid reuse, with every server being pid 1 in a
container, and across several pid namespaces on one host. A directory with no lock
file, a symlink and any other name are kept. The sweep holds the lock while it
removes the directory, and an opener whose lock file disappears starts over. The
lock is an advisory file lock on one host, and unreliable over NFS and similar, as
for `DirBucket` (#264). An `sc serve` run by an ssh user is run by an operator: that
user can pass `--store` and `--allow-private-branches`, so the gate protects against
clients of the server, not against whoever starts it.

This reverses ADR-0044's reason (4) for rejecting "opaque sealed refs through
the git bridge", and only under that opt-in. Reasons (1) to (3) do not apply:
there is no Git rendering of sc history (the store holds opaque values, so
there is no incoherent Git structure to write), no marks map is involved (so it
gains no second meaning), and publish is an ordinary push to the same store (so
it cannot go stale against an exported artifact). Reason (4), a one-command
path to durably publishing embargo ciphertext on a public host, does apply, and
is why it is gated and why the notice and the refusal message say what stays
behind.

### Compaction

`sc remote compact` works on an `sc+git::` remote (ADR-0057 addendum has the
algorithm; v1 refused it). A Git repository gives the compactor no trustworthy
age for a stored pack: committer time is writer-controlled and predates
publication. So on a carrier the compactor keeps its own record of when it first
saw each pack and checkpoint (`refs/sc/compact/sightings`: `<first_seen> <oid>
<key>` per line, generation-aware by oid), sizes packs from their idx instead of
downloading them (`list_meta` still downloads every value and compaction never
calls it here), deletes with leases (`delete_leased`), and reads the manifest
with no cache before every delete call. The first run after an object
appears never deletes it (with a zero grace, `--allow-short-grace`, a first
sighting is immediately old). Consequences to know:

- Run compaction from one host. Runs that share the record need clocks within
  far less than the grace window; a first-seen time more than five minutes ahead
  of the compactor's clock is refused.
- Every pusher holds delete, unlike the ADR-0057 advice to withhold it: on a Git
  host a push to `refs/sc/*` is a push. The record adds no authority (anyone who
  can write it can already delete the store); it can only make something
  unreferenced look older, never a live object deletable.
- A push that stalls longer than the grace window between uploading a pack and
  committing it can lose the pack, as on any backend; byte-identical reuse of an
  aged orphan pack at the moment its delete lands remains a narrowed race.
- Deleting a ref is not erasure (see Consequences).

### Deferred in v1

- `sc serve --store sc+git::...` was refused in v1 (a daemon cannot answer
  prompts, and it sat between clients and the client-side gate). It is built now,
  with a server-side gate; see "Serving a Git store".
- SHA-256 Git repositories are not supported: values and tags are SHA-1 ids, and
  the local cache is created with `--object-format=sha1` whatever the user's
  `init.defaultObjectFormat`.

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
  tests, and `demo/run_git_carrier_demo.sh`. Validated against a private GitHub repository
  on 2026-11-21 (git 2.54, HTTPS through the gh credential helper, synthetic data only,
  every ref deleted afterwards): GitHub accepted `refs/sc/*` creates, lease
  CAS updates and deletes; of two racing pushers exactly one won and the other got
  non-fast-forward; a v2 fetch of `refs/sc/manifest` was answered with that ref
  only; keyless and keyed clones behaved as on sc-forge; two compaction runs took
  the store from 18 refs to 5 and a clone afterwards read the private branch.
  Each git call is its own HTTPS round trip (about 1-2 s), so a first push of a
  tiny repository took 56 s and a clone 13 s. Not exercised on GitHub: its
  per-push (2 GiB) and per-blob (100 MB; values are chunked at 32 MiB) limits,
  rulesets on custom refs, and CAS atomicity across its replicas beyond one race.
- **The writer set is wider than S3.** Everyone with push access to the Git
  repository (collaborators, deploy keys, CI tokens) holds bucket put and
  delete, and there is no object versioning to recover. They can rewind
  `refs/sc/manifest` to a pre-revoke manifest, delete keys, or add packs. Branch
  protection and rulesets do not cover `refs/sc/*`. This is the same class as S3
  write access, with more holders. Rollback and rewind stay the tracked
  follow-ons (ROADMAP: P34 follow-on 6, a fetch-time freshness attestation;
  ADR-0059 follow-on 2).
- **Deleting a ref is not erasure.** A host may keep the objects fetchable by
  id, forks and mirrors keep their own copies, and compaction only unreferences
  values. Sealed content stays ciphertext, so rotation is the cutover
  (`sc rewrap --rotate`), as for any transport.
- **Public content is plaintext in packs** on the host, as on any bucket remote.
- **Sealed metadata is readable by every reader of the repository:** private
  branch names, recipient ids, sealed-object counts and sizes, and the public
  fork point. Any one of them can fetch `refs/sc/*` by exact refspec, and
  `git ls-remote` lists the refs to everyone.
- A killed process (SIGKILL, or SIGINT, which skips `Drop`) can leave
  `sc-git-bucket-<pid>-<random>` behind in the temp directory. It holds fetched
  store objects. The CLI has no reaper; `sc serve` reaps the caches in the serve
  home whose owner lock is free at startup (unix). A normal exit and an error returned to `main` remove it.
- Scaling: `ls-remote` and push download the whole ref advertisement (the pattern given to `ls-remote` filters on the client; a packet trace showed the server sends every ref; the manifest read no longer does, it is one fetch that a v2 host answers with that ref alone), and a cold read fetches every `log/` and `checkpoints/` entry behind the last checkpoint. Refs grow by at least three per push (a log entry, a pack and its idx); `sc remote compact` (above) is what bounds that, folding the small packs and deleting what nothing names, so a long-lived store should be compacted on a schedule. Between runs the advertisement still grows with the pushes since the last one, until a ref-filtering host exists.
- Each cold read or push costs git round trips. The freshness window and family
  batching bound them, but a Git host is slower than S3. The per-object probe is
  free on an empty remote (the transport remembers it for 2 s). On a non-empty
  `sc+git::` remote the freshness window answers the per-object probes, and git
  reads the manifest again only once the cached tag is older than 2 s; S3 and
  `sc+wal://` have no such window and read the manifest on every probe. If push stays slow on large histories, the next step is a batched
  `has_objects`.
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
`check_private_push_allowed`, `open_for_serve` and the serve gate
`refuse_sealed`);
`crates/repo/src/bucket_transport/compact/` (the age record and the carrier
sweep, ADR-0057 addendum);
`crates/repo/src/wire.rs` (`WirePolicy::allow_private_branches`, the serve opener,
`reap_stale_serve_scratch`); `crates/repo/src/http_transport.rs`
(`ServeLimits::allow_private_branches`);
`crates/repo/src/remote.rs` (`allow_private_branches`); `crates/cli` (flags,
notice, URL routing, `sc serve --allow-private-branches`);
`crates/forge/src/policy.rs` (`refs/sc/`). The fetch watchdog is `run_watched` in
`crates/objio/src/git.rs`. Tests:
`crates/objio/src/git.rs`, `crates/repo/src/bucket_transport/git_remote_tests.rs`,
`crates/repo/src/bucket_transport/git_serve_tests.rs`,
`crates/cli/tests/git_bucket.rs`, `crates/forge/tests/e2e_git.rs`;
proof: `demo/run_git_carrier_demo.sh`.
