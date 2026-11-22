# src-control — Threat model & security boundaries

This document consolidates, in one place, the **deliberate security boundaries**
of src-control's cryptographic features — the things it does *not* defend against
by design. They are drawn from the per-phase ADRs (linked below); this page
exists so a newcomer evaluating whether to trust real data to the system does not
have to read 57 ADRs to find the caveats.

> **Status: pre-1.0, not independently audited.** These are MVP implementations
> reviewed by the project's own process only. Do not commit production secrets to
> a src-control repo yet. See [`SECURITY.md`](../SECURITY.md).

A recurring principle underlies most boundaries below: src-control is
**content-addressed and history-preserving**. Rotation, revocation, and deletion
cut off *future* reads through the current registry; they cannot erase ciphertext
or objects already written into history and copied to other clones. Real cutover
of a leaked credential always means rotating the underlying external credential
too, not just the src-control-side metadata.

## Committed secrets (`sc secret` / `sc run`) — ADR-0008/0009/0010/0019

- **Defends:** an unauthorized clone (no recipient private key) receives the
  secret object intact but cannot unwrap any DEK, so the value stays ciphertext —
  confidential at rest and in transit, no separate vault.
- **Does NOT defend:** the decrypted value once injected. `sc run` injects secrets
  as **child-process environment variables** — an *authorized local process
  context, NOT strong isolation*. Same-user processes, crash dumps, and shell
  wrappers can observe the plaintext through the child environment; this is
  fundamental to env-var injection. The parent's intermediate buffer is zeroized
  (best-effort), the child copy is not.
- **`sc run --secrets-fd N` (ADR-0052) is the opt-in non-env mode.** The earlier
  re-affirmation (map ticket #31) kept fd injection deferred because the security
  claim against a same-user attacker is mostly illusory: that attacker can read
  the identity key file and `.sc/` directly and decrypt everything whatever the
  injection mechanism. What a descriptor removes is *accidental* propagation: the
  values are not in `/proc/<pid>/environ`, not in an env dump a script or agent
  logs, and not inherited by every descendant through the environment; the
  parent's copy stays in a zeroizing buffer. It is hygiene, not isolation: a
  same-user process can still read the child's descriptor table, and the child
  decides what to do with what it read. Env stays the default for `sc run`,
  `sc work --with-secrets` and `sc ws run --with-secrets`.
- **The registry is repository data, so injection validates it.** `secret_add`
  needs no key: any writer can register a secret sealed to your public key under
  any name. A secret name must therefore match `[A-Za-z_][A-Za-z0-9_]*` and not
  be a variable that changes how a process loads code, which program runs, or
  where a tool reads its config or trust roots (`PATH`, `LD_*`, `DYLD_*`,
  `NODE_OPTIONS`, `GIT_*`, `SC_*`, proxy and CA-bundle variables, and the other
  names in `secrets.rs`; a deny list, so not complete). The match is
  case-insensitive on every platform, since tools such as npm read
  `npm_config_*` in any case. `secret_add` refuses such a name. Every injecting
  path (`sc run`, `--secrets-fd`, `sc ws run --with-secrets`,
  `sc work --with-secrets`) validates the registry before the requested command
  starts (`sc work`'s preflight can start an ssh transport on a lazy clone
  first), and before decrypting anything. An entry whose name fails the rule
  (planted, or added by an older CLI that took any name such as `db-pass`) is
  skipped with a stderr warning, never opened and never injected, in strict and
  non-strict mode alike. A wrap label is repository data too: `sc secret rotate`
  without `--to` and `sc rewrap` seal only to recipients accepted for
  `secret:<NAME>` in this clone (ADR-0059, see Protected paths). An entry whose key differs from the `name` the secret
  was sealed under (the AEAD binds that name) refuses the whole run, and
  `sc secret rotate` without `--value` refuses it too (`--value` re-seals it
  afresh). **Residual:** a writer can still replace the value of an allowed name
  (say `DATABASE_URL`) with one sealed to you, so the child connects where the
  writer chose. The registry is not authenticated; review registry changes like
  code, and use `sc verify --require` on the commits you run from.
- **Rotation ≠ erasure:** `sc secret rotate` re-seals under a fresh DEK and cuts
  off future reads through the current registry, but the old ciphertext object
  remains reachable and decryptable by anyone who kept the old DEK. `sc secret
  revoke` is metadata-only. Real security requires rotating the underlying
  external credential.

## Protected paths (`sc protect`) — ADR-0014/0026/0027/0043

- **Defends:** read-confidentiality of designated file content for a chosen
  recipient set; an unauthorized clone gets ciphertext it cannot read.
- **Equality-confirmation oracle — closed for new content (P33, ADR-0043);
  pre-P33 convergent ciphertext in history stays confirmable forever
  (rotation ≠ erasure, ADR-0019).** Protected paths *used to*
  use *convergent encryption* (DEK and nonce derive from `BLAKE3(plaintext)`),
  so identical plaintext dedups to identical ciphertext and an observer could
  confirm that two protected files are identical, or that a protected file
  matches a **guessed** plaintext. As of P33, **all content sealed from this
  phase on uses a fresh random DEK + random nonce** — two seals of the same
  plaintext yield different ciphertext ids, closing the oracle. Convergent
  ciphertext already written into history stays readable (dual-read) and
  remains equality-confirmable **forever** to anyone holding a clone — this is
  the same rotation ≠ erasure boundary ADR-0019 already names for secrets:
  content addressing means the old convergent object stays reachable in
  history regardless of what happens at the tip. `sc rewrap` re-seals a
  still-convergent blob randomized **at the live tip**, which stops that
  plaintext's convergent form from propagating into *future* snapshots built
  on top — it does not erase the historical convergent object, which any clone
  that already fetched it (or fetches it later) can still equality-confirm
  against. Real cutover of guessable content means changing the content (or
  underlying credential) itself, not just re-sealing at the tip. Low-entropy
  secrets (API keys, `.env`) still belong in `sc secret`, not `sc protect` —
  `sc protect` prints a nudge to that effect, and the P28 rationale is
  unchanged (governed secret lifecycle beats a protected file even with
  randomized sealing).
- **Revocation is durable but not retroactive:** `sc revoke` survives merges of
  pre-revoke branches (revocation tombstones, ADR-0026), so a revoked recipient
  never seals a *fresh* DEK again. But a recipient who already held a wrap can
  still decrypt the ciphertext sealed *before* the revoke — cryptographic cutover
  is rotation, not revoke: `sc rewrap --rotate` on the live tip re-seals every
  protected blob under a fresh key (ADR-0051), whereas a plain `sc rewrap` only
  replaces wrap lists and leaves the key a revoked holder already has. History
  keeps the old wraps and ciphertext regardless.
- **A dropped rule cannot turn a recipient's commit into a plaintext leak:**
  protection rules are repository data, so a writer can hand-build a tip that
  keeps a path's `PROTECTED` entry but omits its rule. A recipient who checks
  that tip out holds the plaintext, and an unguarded `sc commit` would store it
  unsealed. Snapshot assembly (commit, amend, merge/pick/rebase completion,
  `sc ws harvest`, `sc work`) therefore refuses, before it writes any snapshot
  object, when a tip entry is `PROTECTED` and no rule in the resulting policy
  covers it, when a plain working-tree path is `PROTECTED` on the merge or pick
  head, or when a plain path differs only in ASCII case from a rule prefix or a
  protected tip path and the checkout makes the two spellings one file (same
  device and inode; always assumed off unix), so a case-insensitive checkout
  would write the decrypted file under that spelling. A lazy, online partial
  clone fetches the other parent's missing trees by id for that lookup. Callers may first clean sparse-widen residue, fill
  objects or mint the cache key. The hint is to restore the rule with
  `sc protect`, or, while a merge, pick or rebase is stopped, to abort it,
  restore the rule and retry. Case aliases of the other parent's protected
  paths are not checked.
- **A seal wraps only to recipients you accepted (ADR-0059):** protection rules,
  secret wrap lists and private-branch KEK wrap labels are repository data, so a
  writer with no key could add a rule (or a narrower one under your prefix)
  granting their key and wait for your next commit, merge or replay reseal,
  `sc rewrap`, `sc secret rotate` without `--to` or `sc branch revoke` to wrap a
  DEK to them. `.sc/accepted-recipients` (local; written atomically under the
  repo lock; never committed, packed, transferred or read by gc; `sc ws` and
  `sc work` use the host's) lists what you accepted per scope: the full public
  key for `path:<prefix>`, the recipient id for `secret:<NAME>` and
  `branch:<name>`; local `[escrow]` keys count in every scope. The gate is
  `encrypt_protected`, the one function that turns a rule into wraps, plus
  `sc protect` (it checks the rule it changes, builds its sealing commit with the
  pending approvals passed to that call's gate only, records them, then moves the
  refs), `secret_rotate`, `rewrap` (an entry with an
  unaccepted key is skipped, the rest commits, the exit code is non-zero) and
  `branch_revoke`. The record is written durably (fsynced, as durable as the ref
  write). `sc rewrap` skips, and `sc secret grant` refuses, a secret registered under a
  name other than the one it is sealed under (grant also opens the secret with the
  identity, since the AEAD binds the sealed name and the metadata name can be edited).
  The named key of a grant or rotate is recorded only after the identity is
  authorized. An interruption after the approval write and before the ref move can
  leave an approval for a key the user named on that command (accepted). The record loads only when something is sealed, so a commit
  that wraps nothing does not depend on it. Escrow keys are never recorded: they
  count from the current `[escrow]` section, so removing one withdraws it. A
  scope in a refusal comes from the repository, so it is escaped and a scope
  with control characters gets no runnable command. The record's integrity
  relies on the working-tree path guard (a checkout never writes under `.sc/`).
  A carry that copies
  existing wraps is not a seal and is not gated. A refusal writes nothing and
  names the scope, the id, the local `[recipients]` name or `UNKNOWN`, the
  `sc policy accept` command and the revoke command. Only keys you name on the
  command line are accepted automatically (`sc protect --to`, `sc grant`,
  `sc secret add|grant|rotate`, `sc branch --private --to`, `sc branch grant`);
  a key found in the data never is, and a key listed in `recipients.toml` is
  still not accepted. `sc policy accept|forget` edit the file and work while a
  merge, pick or rebase is stopped. The record starts empty in every clone (not
  seeded from the tip, which would accept what an attacker merged), so the first
  affected seal lists the pairs and refuses; CI provisions the file from trusted
  configuration. **Residual:** any writer can still make your seals refuse by
  adding keys (denial of service); history already sealed to a writer's key
  stays readable; binaries from before ADR-0059 do not enforce it; protected
  ciphertext is not bound to its path, so a file relocated under an accepted
  prefix can gain recipients through that prefix's rewrap (a format change,
  deferred). A spurious reseal of unchanged content (a lost cache) is a seal and
  refuses like any other. A revoke made in another clone does not remove this
  clone's acceptance: if Alice revokes Mallory, Bob's clone still accepts her, and
  a later re-grant at a higher epoch is sealed to without a prompt (recording the
  grant epoch with each `path:` pair would close it; deferred). The printed
  revoke command can itself refuse (`sc revoke` will not remove a rule's last
  recipient, and will not run while a merge, pick or rebase is stopped), and a
  refused `sc work` harvest discards that agent's temporary checkout with the
  session; accept first, or use `sc ws`.
- **Local cache key, `sc keygen` identity and TLS serve key are owner-only on
  unix and Windows (P33, #214, #281):** the
  unchanged-detection cache is keyed by `.sc/local-key`, created owner-only from
  its first byte: mode `0600` on unix, a protected DACL with a single
  `GENERIC_ALL` ACE for the current user on Windows (no inherited entries; the
  advisory `windows` CI job reads it back with `icacls`). Windows keys minted
  before #214 keep their inherited DACL, and the warning no longer fires for
  them; delete `.sc/local-key` to have the next run recreate it owner-only (the
  cost is one round of spurious re-seals). The Windows DACL grants no explicit
  access to SYSTEM or Administrators, so backup and admin tooling can still take
  ownership of the file, as root can read a `0600` file on unix. The same
  creation primitive (`scl_core::owner_only`) makes the `sc keygen --out`
  identity file and the auto-minted TLS serve key (`.sc/serve-tls/key.pem`)
  owner-only from their first byte on both platforms (the `windows` CI job
  reads each back with `icacls`); keygen refuses to overwrite an existing
  identity on every platform. Windows identity files and serve keys created
  before #281 keep their inherited DACL; restrict them yourself or regenerate
  (a regenerated serve key changes the pinned fingerprint). A
  `--tls-key` PEM supplied by the operator is theirs to protect. On any other
  target, or if the Windows ACL call fails, the file is written with inherited
  default permissions and `sc` prints a one-time stderr warning naming it
  (for `.sc/local-key`, once a cache holds a protected entry). For `.sc/local-key` the exposure is small: checkout already
  writes protected plaintext into the working tree with default permissions on every platform, and
  the cache holds tags only for files whose plaintext is on disk, so a reader of
  the key could read that plaintext directly. What remains is the tags of the
  last-committed version of a file edited since, and stale entries until the
  next save. A filesystem that ignores mode bits or ACLs (unix vfat, exFAT, some
  network mounts; Windows FAT, exFAT, some SMB shares) is not detected. For an
  identity file or TLS serve key the fallback is not small: it leaves the
  unencrypted private key under inherited permissions, so other local users may
  be able to read it. On unix, `sc` warns once on stderr (it does not refuse)
  when an identity file passed with `--identity` is accessible to group or others
  (`mode & 0o077`), as ssh does for keys.
- **Sealed blobs bind no path or position (decision):** sealed protected blobs
  and private-branch objects use constant associated data, so a writer can move
  a sealed blob to another path or roll a path back to an older sealed version.
  Accepted: binding the path would force a reseal on every rename and break
  carry-by-id. Integrity of placement comes from signed commits
  (`sc verify --require`).

## Private branches (`sc branch --private` / `sc branch publish`) — ADR-0044

- **Defends:** the full content of a private branch — file bytes, **file
  paths**, commit messages, authors, timestamps, and inner DAG shape — against
  any party lacking a recipient (or escrow) key. Every object a private commit
  introduces is individually sealed (`Object::Sealed`, fresh random DEK per
  object) under a per-branch KEK; the ref points at a manifest whose only
  plaintext is structural (a flat sealed-object id list + the public fork
  point). An unauthorized clone, the hosting server, and every transport
  (plaintext `sc+http://` included) see **ciphertext only** — verified by
  `demo/run_private_branch_demo.sh` and by the wire-pack decode test in
  `crates/repo/src/private.rs` (the honest structural check a shell grep
  cannot make: it decodes every non-sealed object off the wire and asserts no
  private plaintext).
- **Leaks by design (accepted metadata):** a private branch's **existence and
  name** (name blandly — `hotfix-CVE-1234` in a ref itself discloses), the
  sealed-object **count and sizes**, closure **growth over time** (commit
  activity is observable as count deltas), the **recipient ids** (in the
  manifest's KEK wraps), the **public fork point**, and **which public commits
  were merged in** (both plaintext reachability anchors in the manifest — the
  fork point plus the tips of any public branch merged in to keep the embargo
  current, so the sealed trees' references stay transferable). No content,
  path, or message is among these.
- **Revoke is a KEK rotation, not erasure:** `sc branch revoke` mints a fresh
  KEK, re-encrypts the index, and rewraps for the remaining recipients — with
  zero content plaintext written and zero sealed-object id churn. A revoked
  recipient who **already fetched** the branch keeps the old manifest + old KEK
  and can decrypt everything sealed *before* the revoke, forever (the same
  rotation ≠ erasure boundary ADR-0019 names for secrets — content addressing
  keeps the old manifest reachable in any clone that has it). The rotation
  guarantees they can read nothing sealed *after*. Real cutover of already-
  disclosed content also means rotating the underlying credential.
- **A KEK wrap label is repository data:** `sc branch revoke` rewraps the fresh
  KEK only to keys accepted for `branch:<name>` in this clone (ADR-0059, see
  Protected paths); `sc branch grant` and the creator's key accept themselves.
  The KEK generation is not pinned, so `sc undo` can restore a pre-revoke
  manifest and reuse a retired KEK (deferred).
- **Escrow holders can read pre-publish:** the branch KEK is wrapped to the
  configured escrow set at creation (and re-wrapped on every membership
  change), so break-glass holders can open an embargoed branch — the standing
  meaning of escrow, applied consistently.
- **Publish makes intermediate commit messages public** and gives every
  published commit a **new snapshot id** (a sealed id is BLAKE3(ciphertext), a
  public id is BLAKE3(plaintext) — equal ids would be the very oracle P33
  closed), so **published commits start unsigned** (re-sign with `sc sign`).
  Publish re-runs the P5 secret scanner over all decrypted content **before**
  writing any public object, so a secret committed under seal cannot sail into
  plaintext history at release.
- **A writer without a key can roll a private branch back (tracked
  follow-on).** The server only checks that a pushed manifest chains to the
  current one through `prev`, so a keyless writer can push a manifest that
  reuses an older manifest's index and key wraps under a new `prev`. The index
  AAD does not bind `prev`, so recipients decrypt it as the branch's content at
  that older point. Binding `prev` into the AAD closes it.
- **Does NOT defend:** a malicious *recipient* (any key-holder can read,
  commit, grant, or publish); the git bridge carries private branches **not at
  all** (export/push refuse unconditionally — `--include-encrypted` does not
  apply, ADR-0044 §7); and integrating a private branch *into* a public one is
  refused everywhere except `sc branch publish` — the one loudly-named,
  atomic, scanner-gated crossing.

## Desktop WebView (`apps/desktop`) — ADR-0045

- **Defends:** the Rust backend constrains the renderer to five typed,
  read-only repository queries. The selected root stays in backend state;
  snapshot ids must be reachable from public refs and paths must be canonical
  repository-relative paths. The bundled WebView has no general filesystem,
  shell, URL, process, or object-store command and remote scripts are denied.
- **Protected and private data fail closed:** protected entries become a
  fieldless `protected_locked` DTO without loading their blobs; private refs
  stop at accepted manifest metadata. Private paths, messages, authors,
  timestamps, inner DAG shape, transcript bodies, ciphertext, and identity
  material have no renderer DTO representation.
- **Does NOT defend:** public repository content against a compromised local
  WebView after the user opens that repository; metadata already accepted as
  public by ADR-0044 (private-branch name/existence, recipient/count/fork-point
  structure); or plaintext copied elsewhere by another authorized local tool.
  Phase 35 has no identity import or decryption path, so adding either requires
  a new threat-model review rather than widening these commands in place.
- **"Read-only" means no refs, objects or working-tree files.** Each query
  briefly takes the repository's single-writer lock, and opening the repository
  can update derived indexes (`.sc/transcript-drops`, `.sc/transcript-pending`
  when the trusted-signer set changed, and the one-time import into
  `.sc/signatures.v2`), best effort; no key material is involved.

## Signed commits & provenance (`sc commit --sign` / `sc verify`) — ADR-0032

- **Defends:** history rewriting (an `amend`/`rebase`/`merge`-attack in a clone or
  on a remote is caught by `sc verify --require`, since a rewrite produces a new,
  unsigned snapshot id) and attribution disputes (a signature binds a specific
  identity to a snapshot).
- **Does NOT defend:** a *trusted signer acting maliciously*; the code quality or
  truthfulness of what was signed; or **replay** of a legitimately-signed snapshot
  into a different branch position (a signature binds identity to a snapshot *id*,
  not to a branch position). `amend`/`rebase`/`merge` results start **unsigned by
  design** — a new snapshot id is a new claim that must be re-signed.
- **Re-affirmed and sharpened (map ticket #32): replay is ref binding only.** A
  snapshot's parents are hashed into its id, so a signature over the id already
  binds identity to the snapshot **and its entire ancestry** — a signed snapshot
  cannot be grafted under different parents without voiding the signature.
  "Replayed elsewhere in history" overstates the residue; the accurate claim is
  narrower: a legitimately-signed snapshot is **replayable to a ref tip within
  its own history** — nothing stops a hostile remote from pointing a branch name
  at an older or side-branch signed snapshot (a rollback/ref-swap), the same gap
  git addresses with signed pushes or gittuf-class ref metadata. Deferred: a
  gittuf-shaped signed ref attestation (freshness/monotonicity semantics,
  verified at fetch/clone) is its own trust-model effort, not a corner of an
  unrelated map. Revisit triggers: the first real multi-writer or hosted `sc
  serve` deployment, or hosting sc repos on untrusted infrastructure.
- **Received signatures are verified before they are indexed (ADR-0038 addenda,
  #230/#257).** The index (`.sc/signatures.v2`) takes a signature only when its
  target is held and it verifies under the key it names, in the signing domain of
  its target kind. A forged or dangling signature that arrives in a pack stays in
  the object store until gc but is never indexed, so ingest cannot turn a
  snapshot `Invalid`: it reads `Unsigned`, which `sc verify --require` also
  rejects. Trust fails closed, but a forgery attempt is reported as an absent
  signature, not as an invalid one. A bucket
  remote forwards the signatures it holds without checking them; the receiver
  filters. The index keeps one slot per (target, signer). **Downgrade:** an
  older binary's `sc gc` roots only the legacy `.sc/signatures` file and sweeps
  signatures that only the v2 file lists, so do not run one on a repo this build
  has signed in or ingested into.

## Agent session transcripts (`sc transcript`) — ADR-0038

- **Defends:** transcript disclosure to unauthorized clones (the body is *always*
  sealed — a keyless clone gets ciphertext only); loss of agent context at harvest;
  transcripts outliving the history they describe (gc-coupled index).
- **Does NOT defend:** a *fabricated* transcript attached by an authorized writer
  (attachment is a claim; opt-in signing upgrades it to an attested claim, but an
  unsigned transcript is still just a claim); secrets an agent echoed into a
  transcript remaining readable to *authorized* transcript recipients (the P5
  scanner warns at attach time but never blocks; rotation of the underlying secret
  remedies).
- **Drop tombstones (`sc transcript drop`, ADR-0038 addendum).** A drop is honored
  by a peer only if it carries a signature over its drop digest from a key under
  that peer's `[signers] trusted` list, and its snapshot checks out. An unsigned or
  untrusted tombstone is inert. The new power: any trusted signer can hide
  transcripts on every peer that trusts it and make those peers' gc reclaim the
  bodies. Drop is not erasure: peers without the tombstone keep the body,
  `GetObjects` serves it until gc sweeps it, and a peer that still holds it can
  re-send it. A tombstone held while its signer is untrusted is remembered
  (`.sc/transcript-pending`, capped at 1024, FIFO) and judged again when the
  trusted-signer set changes (on open, transport open and ingest), so trusting
  the signer later is enough on a push-only or served remote. A retained signed
  tombstone is also sent when its snapshot was collected by the sender's gc, so
  a stale peer is told; this discloses the snapshot id, dropped transcript id
  and signer public key of such drops to any peer the dropper transfers with,
  including one that never had the snapshot (ids are hashes, bodies stay
  sealed). Only signatures that verify for a held target are indexed, so
  forged signatures stay in the object store (until gc sweeps them) but are
  never indexed, so a `sc serve` or local sender never forwards them and gc
  never keeps them (a bucket forwards what it holds; receivers filter). The signature
  index keeps one signature per (target, signer) and honoring looks up only the
  trusted signers, so signatures valid under keys a writer made themselves
  cannot crowd out the real one (resolved, #257); they cost a line and a
  check each. Index updates on the serve path take a short `.sc/index.lock`, so
  concurrent pushes and local commands do not lose index or pending entries
  (resolved, #260). The lock is an advisory `flock` on a file that is never
  removed, held only for single index updates, and waited for at most 30
  seconds; past that the ingest fails with `IndexBusy` after its objects are
  stored, and the signatures stay unindexed on that remote: they are not served
  and its gc sweeps them after the grace window (no reindex of a remote is built,
  and a re-push skips objects the remote already holds). Advisory locking is only as reliable as the filesystem's `flock` (not
  guaranteed on NFS). Writers
  can also evict pending entries from a push-only remote (trust the signer
  before the push). Trust is checked at evaluation and is not retroactive. A tombstone a remote already held before
  upgrading to a build with the pending index is not remembered: trust the
  signer before the drop is pushed, or have a fetching peer re-send it.

## Network transport (`sc serve --http` / `sc+http(s)://` / `ssh://`) — ADR-0022/0036/0040/0041/0042

- **Two confidential transports now ship: `sc+https://` (P32, ADR-0042) and
  `ssh://` (P12, ADR-0022).** `ssh://` has been fully confidential since
  Phase 12 — it delegates the entire channel to the user's `ssh`, inheriting
  whatever SSH's own transport security and host-key trust already provide;
  it was never plaintext and needed no separate TLS story. `sc+https://` adds
  the same property for operators without ssh reach: a bearer token (P29) and
  all repository traffic are encrypted end to end, at both the server and the
  client leg, with no reverse proxy required.
- **`sc+https://` trust model is accept-new TOFU, stated plainly (the SSH
  `known_hosts` trade).** The server auto-mints a self-signed identity
  (`.sc/serve-tls/`) or loads an operator-supplied PEM cert; the client pins
  `SHA-256(SPKI)` on first connect into `~/.config/sc/known_hosts`
  (`SC_HTTPS_KNOWN_HOSTS` overrides the path). **The first connection to any
  host is unverified by construction** — an active MITM present on that
  specific first connection is not detected. Every subsequent connection
  compares against the stored pin and hard-fails on any mismatch, never
  silently proceeding and never prompting to accept a changed key.
  `SC_HTTPS_FINGERPRINT` lets an operator (e.g. CI) pre-pin out-of-band
  instead of trusting the first connection; `SC_HTTPS_STRICT=1` refuses to
  connect to any host with no existing pin, closing the accept-new window
  entirely for operators who need it. Pin trust ignores certificate names
  and validity periods deliberately. The TLS handshake signature is still
  verified even though names/validity are not, so a captured certificate
  replayed without its matching private key is rejected regardless of pin
  state. `sc tls list/forget/pin/path` (ADR-0053) manages the pin file: `forget`
  is the deliberate recovery after a legitimate server key change (the next
  accept-new connect re-pins, so it reopens the first-connection window for that
  host unless `SC_HTTPS_STRICT` or `SC_HTTPS_FINGERPRINT` is set), and `pin`
  records an out-of-band fingerprint without connecting. A mismatch is still
  never resolved by the client on its own.
- **Serve tokens can expire and be rotated (ADR-0040 addendum, #209).**
  `sc serve token add --expires` stores an absolute `expires_at`; an expired
  token behaves exactly like an unknown one (the same `401`, no oracle for
  "was valid once"), and expired entries stay in the file and still count as
  configured tokens, so a server whose tokens have all expired keeps refusing
  everyone. `sc serve token rotate <label>` swaps the secret in one step, keeps
  the absolute expiry, and kills the old secret at once. Expiry is checked when
  a connection opens: a transfer already in flight can outlive its token. Tokens
  remain all-or-nothing per connection (`ro`/`rw`); there are no per-path or
  per-ref scopes.
- **CA validation is the additive alternative (ADR-0054).** A client that sets
  `SC_HTTPS_CA_FILE=<pem>` (a CA bundle) or `SC_HTTPS_CA=system` (the platform
  roots) stops pinning and validates like a browser: the chain to a trusted
  root, the validity window, and that the certificate covers the name or IP the
  client dialled. This removes the first-connection blind spot for a server
  whose certificate comes from a CA (certbot/ACME, a private CA), and a
  rotating certificate no longer invalidates a pin. It is a client choice per
  process: the pin file is neither read nor written, an unusable or empty
  bundle fails the connection (it never falls back to accept-new), an
  unrecognized `SC_HTTPS_CA` value, both knobs at once, or a pre-pin
  (`SC_HTTPS_FINGERPRINT`) together with CA trust is an error, and
  `SC_HTTPS_STRICT` has no meaning in this mode. What it does not give: trust
  is only as good as the CA set (the whole platform store for `system`), and
  revocation (CRL/OCSP) is not checked.
- **`sc+http://` (plaintext) still exists, and its boundary is now narrower
  and clearer: it applies only to loopback or explicitly `--allow-public`
  deployments.** A public (non-loopback) plaintext deployment protected by
  bearer tokens *alone* is no longer a supported configuration — as of P32,
  `--tls` is required alongside ≥1 token to justify a non-loopback bind (the
  P29 gate is narrowed; a token guarding only a plaintext channel was always
  a weaker guarantee than the earlier wording implied). A loopback bind with
  no tokens configured stays unauthenticated by design (local-dev
  ergonomics, unchanged since P29); `--allow-public` with no tokens is still
  a sanctioned foot-gun — a deliberately open, unauthenticated, plaintext
  server, for the operator who explicitly asked for it.
  **Residual plaintext-token exposure, stated plainly:** a public bind
  justified by `--read-only` or `--allow-public` *with* tokens configured
  still requires the bearer on every connection — the P32 gate closes only
  the tokens-ALONE justification, not plaintext token use in general — so
  those tokens still cross the wire in cleartext on such a deployment. Use
  `sc+https://` (or `ssh://`) instead of `sc+http://` whenever a public bind
  needs its bearer tokens to stay confidential in transit.
- **Reverse-proxy guidance, corrected to cover both legs.** Prior guidance
  ("front with a TLS reverse proxy") was incomplete: a server-side proxy
  terminates TLS toward clients that speak TLS, but before P32 the `sc`
  client itself spoke only plaintext TCP, so a server-side proxy alone
  encrypted nothing end-to-end. Now that `sc+https://` and `ssh://` both
  exist, the reverse-proxy path is a **fallback for operators who want their
  existing proxy infrastructure in front of `sc`**, not the primary
  confidentiality answer. If used, both legs need care:
  - **Server side — raw-TCP/stream-mode TLS termination, never HTTP mode.**
    The post-opening protocol is not HTTP, so an HTTP-mode reverse proxy will
    not tunnel it. Use nginx `stream {}` + `ngx_stream_ssl_module` (note:
    neither the `stream` block nor its ssl module is built into a default
    nginx — check `nginx -V`; and `ssl_preread` is routing-only, it does
    **not** terminate TLS), or HAProxy `mode tcp` with `bind :<port> ssl crt
    <pem>`, or stunnel's server mode (`accept`/`connect`/`cert`). Forward
    decrypted bytes to a **loopback-bound** `sc serve --http 127.0.0.1:…`
    and keep bearer tokens configured — the proxy→`sc serve` hop is
    plaintext loopback, and the token is still the authorization mechanism
    on that hop.
  - **Client side — the leg the old guidance omitted.** The unmodified `sc`
    client cannot itself speak TLS to a plaintext `sc+http://` remote it
    thinks it's talking to over an encrypted channel; a client-side tunnel
    (stunnel's client mode, `client = yes`, or `ssh -L`) is required to give
    that plaintext client an encrypted leg to the proxy. **Simplest fix:
    skip both legs of this section entirely and use `sc+https://` or
    `ssh://` directly** — they exist now specifically so this two-legged
    proxy dance is no longer the only option.
  - See `docs/research/tls-options-sc-http.md` §B for the full comparison
    (nginx/HAProxy/stunnel capabilities, Caddy's non-bundled layer-4 caveat)
    that this guidance is drawn from.
- **Repo presence is not observable from pre-auth status responses (both `sc+http://` and `sc+https://`):**
  the `404` (no repo) is written after the auth gate, so behind mandatory auth an
  unauthenticated client gets `401` whether or not a repo is served (timing is not
  equalized: a present repo costs a token-file read first). With no tokens
  configured there is no auth to leak around and a missing repo still answers `404`.
- **Not proxy/CDN-safe** (raw post-opening protocol, both plaintext and TLS
  variants) — this remains open, deferred in [`ROADMAP.md`](../ROADMAP.md).
- **Listener resource bounds — closed by P31 (ADR-0041).** The three operational-
  hardening items this section used to track as open are now closed, plus a
  fourth gap P31's own research pass first named:
  - **Connection exhaustion:** an atomic connection counter enforces
    `--max-connections` (default 32, matching `git-daemon`); at the limit a new
    connection is accepted, immediately given a busy status at the pre-handshake
    opening seam, and closed — no queuing, no unbounded thread spawn.
  - **Idle/stalled-peer exhaustion:** `--timeout` (default 300s, 0 disables) sets
    read *and* write timeouts on the session socket for its whole lifetime — not
    just the opening's original 30s, which used to be cleared once the wire
    handoff began. A trip is connection-fatal (frame desync precludes recovery);
    the spooled temp pack is guard-cleaned on the resulting unwind. A per-read
    timeout does not bound a peer that sends a byte just inside it each time, and
    before authentication that held a connection slot for hours (8 KiB of opening
    at 29 s a byte), so 32 such peers filled the default `--max-connections`
    before any token check. The TLS handshake and the HTTP opening now share one
    30 s deadline fixed at accept (every socket read and write narrows the timeout
    to the time left); the session timeout replaces it after the 200 status. Known
    limit: on macOS one blocking `send` can wait more than once with the same
    relative timeout, so a `--tls-cert` chain larger than the socket send buffer
    (over about 128 KiB) sent to a peer that reads slowly can outlast the deadline;
    the minted identity is a few KiB and is not affected. An empty
    `ST_PACK_CHUNK` frame, which moves neither the `--max-pack-size` count nor the
    idle timeout, is a protocol error; the sender never emits one.
  - **Accept-loop hot-spin under fd exhaustion:** a hardcoded exponential backoff
    (5ms doubling to a 1s cap, reset on the next successful accept — Go
    `net/http`'s shape) paces retries around `EMFILE`/`ENFILE` instead of
    busy-looping.
  - **Aggregate pack-spool exhaustion (named and closed together, P31):** this
    item was never listed here or in ADR-0036 before P31's research pass found
    it. The incoming-pack spool used no aggregate size bound — only ADR-0039's
    per-frame/per-record caps applied — so a single oversized or endless pack
    could exhaust server disk on **either** transport. `--max-pack-size`
    (default 16 GiB, 0 = unlimited, floor = the max object size, 256 MiB by default) now
    counts the running total and aborts mid-stream past the cap. This includes
    the **read-only drain path**: the pre-`EC_READONLY` drain that keeps a
    connection in sync when a read-only-scoped client streams a pack the server
    is about to reject was itself unbounded — an `ro`-token client could still
    write arbitrary bytes to `.sc/tmp` before being told no. It is now capped at
    ~8 MiB (`RO_DRAIN_CAP`): an honest small misconfigured push still gets the
    clean typed `EC_READONLY` error, while a larger bulk spool is dropped
    mid-send instead of fully drained to disk.
  - **Not closed by P31:** per-IP/per-token sub-limiting (a distributed
    many-connections-from-many-sources attack below the per-listener cap is
    unaddressed), and a legitimate transfer slower than a true 300s zero-byte
    stall is unaffected by `--timeout`, but an operator on an unusually slow
    network must raise it explicitly. See ADR-0041 for the full decision,
    including rejected alternatives.
- The ssh:// transport delegates authentication entirely to ssh (ADR-0022);
  `--max-pack-size`, `--max-conn-bytes` and `--max-object-size` are the bounds
  that also apply to `--stdio` (the connection, timeout and TLS knobs are
  `--http` only).
- **The wire protocol is version 6, matched exactly.** Each side refuses a peer
  of another version at the handshake, in both directions, so a stale client or
  server cannot be talked into an older, weaker framing. This is compatibility,
  not authentication: any peer that speaks version 6 and passes the access gates
  is served. An `ssh://` remote runs the remote host's own `sc`, so that binary
  must match too.
- **`.sc/serve-tokens.toml` is owner-only.** Created and rewritten (add, rotate,
  remove) through a `0600` staging file on unix (protected DACL on Windows), so a
  default umask does not expose the token hashes and scopes.
- **Remote-controlled text is escaped before printing.** A server's error string
  and a commit's author and message may carry ANSI or OSC escapes, so the CLI
  prints C0 controls (other than newline and tab), DEL and C1 controls as visible
  escapes (`\x1b`) when displaying those errors and the ref-name diagnostics.
  `sc log` and `sc transcript` rows are escaped as one line (newlines and bidi
  controls too); remote, protocol and ref diagnostics print on one line as well.
  Stored data and `--json` output are unchanged. Wire framing and error codes are
  unchanged; the diagnostic text is now sent raw (not as escaped `Display`
  output) and without the doubled prefix `Protocol` and `Remote` used to carry,
  and is escaped only when displayed. Paths are not escaped.
- **The server decides a ref move itself, not just the client** (`ref_guard`).
  Every `UpdateRef` (all transports, local-path pushes and `sc serve --store`
  included) is judged before the repo-wide lock is taken, so a long walk does
  not hold it; under the lock the compare-and-swap is confirmed and every
  object the verdict relied on is checked to still be on disk (a gc prune
  cannot slip between the two).
  The new tip must be a snapshot or a private-branch manifest of the **same
  kind** as the branch's current tip, and the current tip must be its ancestor
  (a snapshot's parents, which must be snapshots; a manifest's `prev` chain,
  which must be manifests; a manifest's `base` is not an ancestor link). It
  must also be **connected**: every parent, root tree, nested object, secret,
  manifest `closure` entry, `base` and `anchor` the push added is held and of
  the right kind, checked only along what differs from an existing ref tip. Anything absent, of the
  wrong kind or unreadable is refused. This stops a rewind, a sideways move, a
  public/private kind flip and a tip whose history dangles, which would break
  clone, fetch and gc for everyone. It is not a content check: write access
  still adds any history and fast-forwards any branch it can name. Cost: a push
  whose history joins an existing branch below its tip (not at a tip) is walked
  back to the root, so an rw client can make a push cost a full-history walk.

## Bucket remotes (`sc+wal://` / `sc+s3://`) — ADR-0046/0057

- **The bucket is untrusted storage with cooperative writers, not a trusted
  peer.** Unlike `sc serve`, no process authenticates a push or enforces
  policy at write time — the bucket vendor's own IAM/ACL is the only gate on
  who may call `put`/`get`/`list` against it. sc treats every byte read back
  from the bucket as untrusted input, symmetrically with how it already
  treats bytes arriving over `ssh://`/`sc+http(s)://`.
- **Write access is full authority over refs and history.** Anyone who can
  write to the bucket's manifest key can move any branch to any commit —
  fast-forward-only enforcement (the manifest compare-and-swap plus the
  `Error::NonFastForward` check) is **cooperative** for a writer that talks to
  the bucket directly (a served `--store` instance enforces it, see Network
  transport), not cryptographically enforced by the bucket. A writer with raw
  bucket access (outside the `sc` client) can bypass it entirely, the same
  way a user with raw filesystem access to a git bare repo can force-move a
  ref underneath git's own client-side checks. Scope bucket write credentials
  accordingly — they are equivalent to `sc serve --http` write-token
  authority, not read-only authority.
- **Readers verify every object independently of the bucket's own
  guarantees.** Every pack object's `BLAKE3` id is checked on read, exactly
  as for local and served objects — a bucket that returns corrupted or
  substituted bytes for a given key is caught, not trusted. The WAL metadata
  (manifest, log entries, idx) is strict-decoded fail-closed
  (`walfmt.rs`): unknown versions, bad magic, and any length that would
  overrun the buffer are refused outright rather than best-effort parsed.
  Untrusted-length caps apply throughout: manifest/log/idx bytes are capped
  at a fixed 256 MiB (not the operator's cap) after download, before decode, and pack bodies are read through
  `scl_core::pack::read_object_at_bounded` (not the unbounded
  `read_object_at` the trusted local `Store` uses for its own already-
  verified on-disk packs, per ADR-0039's explicit trust split) — capping
  both the compressed record length and the decompressed output, so a
  hostile or corrupted bucket cannot mount a decompression-bomb DoS via
  `get_object`/`get_pack`.
- **Checkpoints are untrusted input too (P36b).** A checkpoint object is
  strict-decoded like the rest of the WAL, and a reader refuses (`Error::Wal`)
  a manifest that names an absent checkpoint, a checkpoint whose `seq` differs
  from the key it was fetched at, and a log chain that steps past the
  checkpoint without landing on it. A writer with bucket access can fold a
  checkpoint, but it is derived data any reader can refold from the log, and a
  lost manifest CAS drops a fold silently. A hostile writer can grow a bucket
  without bound; bucket quotas are the operator's bound, and `sc remote
  compact` reclaims what is unreferenced (below).
- **Compaction deletes data, so it is a privileged operation (#216,
  ADR-0057).** `sc remote compact` needs bucket **list and delete** rights in
  addition to the get/put/head permissions a pusher holds (pushes themselves need no list
  or delete rights; on an `sc+git::` carrier every pusher holds them, see the carrier
  section). Grant them to a dedicated operator or
  scheduled-job identity, not to ordinary pushers, read-only clients or the
  `sc serve --store` instances (they never need them: compaction is not a wire
  verb, so a served bucket's clients cannot trigger a delete). It cannot
  create new authority: it never touches the manifest's refs, only removes
  objects no current manifest chain names, and a writer who can already
  write to the bucket can do worse with raw access. What it does change for a
  hostile or mistaken writer: (a) a stalled push whose uploaded pack is older
  than `--prune-expire` can lose it and fail on retry, or, if its pack is byte-identical to an old
  orphan that a sweep is deleting at that moment, commit an entry naming a
  deleted pack, which
  makes the remote unreadable until fixed (hence the 24h default, and
  leases as the real fix); (b) a hostile write that fills `log/` or
  `checkpoints/` with junk is reclaimed once it falls behind the cutoff; junk
  at a far-future seq never falls behind it, and an undecodable one stops pack
  deletion (fail closed, the report names the key to remove by hand). Use
  `--dry-run` first on a new bucket: it deletes and uploads nothing, but it
  downloads and decodes the same candidate packs a real run would, so on S3 it
  costs the same egress and requests. A `--prune-expire` under 1h is refused
  unless `--allow-short-grace` is given, which is only safe while nothing
  pushes to or fetches from the bucket.
- **Manifest CAS retries are bounded, and contention is a denial of service,
  not a bypass.** `update_ref` retries a lost compare-and-swap up to 16 attempts
  with a jittered, capped exponential backoff (about 2.5 s in total at worst),
  then fails with "manifest cas contention". A busy fleet or a hostile writer
  can starve a pusher this way and force a rerun; it cannot move a ref the
  pusher did not ask for, and every retry re-reads the manifest it races.
- **`DirBucket` (`sc+wal://<dir>`) is a single-host, local-filesystem backend,
  and its CAS lock has limits (#264).** The lock is an OS advisory file lock
  (`File::lock`, `flock` on unix) on `<root>/.cas-lock`; it replaced a
  create-exclusive spin file. (a) The file is never removed, and `list` skips
  it. (b) `lock()` blocks without a timeout: a holder that stalls while holding
  it (a suspended process, a hung filesystem) blocks every writer of that
  directory until it is released; the OS drops the lock when the holder dies.
  (c) Binaries from before and after #264 do not exclude each other: the old
  one does not take the OS lock and the new one ignores its create-exclusive
  file, so running both against one bucket directory at the same time can lose
  an update, and an old binary that finds a `.cas-lock` left by a new one fails
  with "cas lock stuck". Upgrade every user of a directory bucket together. (d)
  Advisory locks are only as reliable as the filesystem: `flock` on NFS and
  some other network filesystems is not dependable, so do not share a
  `DirBucket` across hosts. Use S3, whose CAS is a server-side precondition and
  is not affected, when more than one machine writes.
- **Sealed content stays end-to-end sealed, unchanged.** Protected-path
  ciphertext (ADR-0014/0043) and committed secrets travel through a bucket
  remote exactly as through any other transport: a bucket reader without the
  recipient key receives intact ciphertext it cannot decrypt. Bucket
  read/write access confers no additional decryption capability.
- **Public (unprotected) content sits in the bucket as plaintext at rest.**
  This is not a new exposure relative to a served remote's `.sc/objects/` —
  both put unprotected object bytes on a disk or store the operator
  controls — but a bucket has no `sc`-native access-control layer at all
  (no bearer tokens, no `--read-only`, no loopback-bind gate). **Bucket ACL
  is the entire confidentiality perimeter for public content on a bucket
  remote** written to directly by `sc push`/`sc fetch`; an operator who
  needs `sc`-native read/write scoping for public content should front it
  with `sc serve --http`/`--https` (including via `--store`, serving that
  very bucket — see below).
- **Partial clone (`--filter`) against a bucket remote is refused**, not
  silently ignored — the WAL format has no per-prefix negotiation yet, so
  there is no partial-fetch code path to reason about for a bucket remote at
  all.
- **`sc serve --store <bucket-url>` (P36c) splits content from
  access-control state.** The bucket holds all served content; the serve
  **home** (`path`, still a plain `.sc/` directory) holds tokens, TLS
  identity/pins, and pack-spool scratch. A bucket-backed serve instance
  enforces the exact same P29/P31 gates against its clients as a
  local-store instance — bearer tokens, `--read-only`, the loopback-bind
  default, connection/timeout/pack-size limits — while itself trusting the
  bucket no further than any other reader does: every object's BLAKE3 id is
  re-verified and the WAL metadata is strict-decoded fail-closed exactly as
  described above, so a hostile or corrupted bucket gets no more leverage
  against a serve instance than it would against a direct `sc` client.

- **Signatures, transcripts and drop tombstones are served from what the
  bucket holds (#229).** The bucket does not judge them: it returns every
  signature over a snapshot in the transfer and every transcript or signed
  tombstone attached to one. A writer with raw bucket access can therefore add
  a tombstone or a signature, but the receiver's checks are unchanged: a
  signature is verified against `[signers] trusted` when read, and a tombstone
  is honored only with a valid drop-digest signature from a trusted signer.
  A hostile bucket can also make `get_pack` read every pack on the chain (the
  scan is not limited to packs holding wanted objects); each pack stays under
  the `MAX_OBJECT_SIZE` guards, so this costs bandwidth and CPU, not memory
  beyond one pack body.

## Git-carried bucket remotes (`sc+git::`) — ADR-0060

The bucket model above applies unchanged, with the Git repository as the bucket and
`refs/sc/*` as its keys. What differs:

- **The writer set is wider than S3.** Everyone with push access to the Git repository
  (collaborators, deploy keys, CI tokens) holds bucket put **and** delete, with no object
  versioning to recover from. A writer can rewind `refs/sc/manifest` to a pre-revoke
  manifest, delete keys or add packs. Branch protection and rulesets do not cover
  `refs/sc/*` (sc-forge applies none to it either). Rewind is the same tracked follow-on as
  for any bucket (a fetch-time freshness attestation, ROADMAP P34 follow-on 6, and
  ADR-0059 follow-on 2); `sc+git::` makes it reachable by more people.
- **Metadata exposure.** Anyone who can read the repository can list `refs/sc/*` (`git
  ls-remote`) and fetch it by exact refspec; a default `git clone`/`git fetch` does not. They
  see public content as plaintext in the packs, and for private branches the branch name,
  recipient ids, sealed-object counts and sizes and the public fork point (ADR-0044's accepted
  leak, now to every reader of a Git host). Protected-path and secret ciphertext stays
  ciphertext. Because that exposure is wider, pushing a private branch needs the per-remote
  opt-in `--allow-private-branches`, enforced in `repo` before any upload; protected paths and
  secrets need none. A server in front of the repository carries the same gate under the
  operator's own `--allow-private-branches` (below).
- **Deleting a ref is not erasure.** A host can keep the objects fetchable by id (sc-forge does,
  until its gc prune stage), and forks, mirrors and clones keep their own copies. A deleted
  private-branch ciphertext or a pre-rewrap value should be treated as published; the cutover
  is rotation (`sc rewrap --rotate`), as everywhere.
- **Transport allowlist and process hygiene.** The inner URL is `https://`, `http://`, `ssh://`,
  `file:///abs`, scp-form or an absolute path. `git://`, relative paths, `::` transport helpers,
  a leading `-`, control characters, a password in the URL and any userinfo on an `http(s)://`
  URL (credentials belong to git's credential helper, not to a URL stored in `.sc/config`) are
  refused, as are an `ssh://` or scp-form user starting with `-` and an unusual `ssh://` host.
  Every git call carries `-c protocol.allow=never` plus `always` for `file`, `ssh`, `http` and
  `https`, and `protocol.ext|fd|git.allow=never`, so a hostile URL or redirect, or a user config,
  cannot reach `ext::`, `fd::` or `git://`; fetches run with `fetch.fsckObjects=true`. The environment is scrubbed of
  `GIT_DIR`-family and config-injection variables, hooks and signing are off, stdin is closed and
  prompts are disabled. `http` stays allowed because plaintext is the user's choice, as in git.
  Errors carry git's captured stderr with URL userinfo redacted and control bytes escaped, so a
  hostile hook message cannot drive the terminal.
- **A hostile host is bounded per fetch, on disk only: not in RAM inside `index-pack`, not in the
  total cache.** A pack value is capped at 2 GiB, any other value at 256 MiB
  (checked before reading into memory), and a chunk at 32 MiB, a tree at 10,000
  chunks, captured `ls-remote` output at 64 MiB; fetches are shallow so a hostile commit's parents
  are never downloaded; a fetched value must be a parentless commit over contiguous regular chunk
  blobs or it is refused as corrupt. The WAL's own 256 MiB metadata cap and pack bounds still
  apply. `git fetch` has no input-size limit, so every fetch runs under a watchdog:
  `fetch.unpackLimit=1` puts all incoming data in one `objects/pack/tmp_pack_*`, the growth of
  `objects/pack` is polled (2 ms at first, backing off to 50 ms), and git is killed once it
  passes the budget (the key's value cap plus 0.1% and 1 MiB for a fetch of one key, 2 GiB for a
  family or batched fetch) or after 120 s with no growth and no exit. What the fetch added is
  removed and the error names the cap. A fetch that ends between two polls is caught by a check
  after it exits, and the measuring goes on while a helper still holds git's pipes and once
  more after they close. Every breach (budget, budget after exit, no progress, a pipe held open
  after exit) stops git, waits up to 5 s for helpers to go and the directory to settle, then
  discards; in serve mode a normal exit takes the same stop and settle steps first. The
  process group is signalled only while its leader is unreaped, when the leader's pid pins the
  group id; after the reap it is never signalled, because the id may have been reused by an
  unrelated process group of the same user and nothing observable shows otherwise (pinning the
  pid without reaping needs `unsafe`). In serve mode the leader is a `/bin/sh` supervisor that
  sc never waits for before the group is dead, so that is always the case until the final reap.
  The limits, plainly:
  - The bound is disk bytes per fetch. It does not cover git's memory while `index-pack`
    resolves a pack, and it does not cover the total size of the cache, which grows by what each
    fetch keeps and lives as long as the process. An HTTP daemon opens one cold cache per
    connection, so its disk cost is up to the per-fetch budget times `--max-connections`, plus
    what the caches keep.
  - Refs a family fetch writes are not measured. A hostile host can advertise a great many refs;
    only the 120 s no-progress deadline bounds that.
  - A family fetch (`log/`, `checkpoints/`, `packs/*.idx`) over the 2 GiB budget is killed and
    discarded, then the reader falls back to one fetch per key, each under its own value cap
    (256 MiB, or 2 GiB for a `.pack`), and remembers it for that instance, so a legitimate
    store that has grown past the family budget stays readable and can compact itself. A
    hostile host can force that slower path (one git round trip per key) by serving a big
    family; it cannot lift any per-key cap by doing so.
  - Only serve mode on unix is disk-bounded against a hostile HTTP host. There git runs under
    a `/bin/sh` supervisor that leads its process group, holds a stdin pipe only sc has, and
    writes git's exit code to a status file in the private cache directory. When the fetch ends
    (a normal exit or any breach) sc closes that pipe and the supervisor kills the whole group
    with its builtin `kill`, itself included; the system `kill` signals the group too, as a
    backup while the supervisor is unreaped (without one the watchdog warns once). So `ssh`,
    `git-remote-https`, `index-pack` and any helper that outlives git, a smart-HTTP v0/v1
    helper chain included, die and cannot write after the discard, and a group also dies when
    `sc serve` itself does. Outside serve mode (the unix CLI, Windows) the kill may not reach the
    helper chain that writes the pack, which can keep writing after git is killed, and a helper
    that outlives git is not killed: those cases are not disk-bounded. The call still returns, since detached pipe
    readers keep a surviving helper from blocking it.
  - A process that leaves git's process group (`setsid`: an ssh `ControlPersist` master, a
    credential-cache daemon, a hostile process) escapes serve mode's kill. If it holds git's
    pipes the fetch fails after the shared deadline; if it closes them and writes into
    `objects/pack`, only the measuring bounds it.
  - The status file trusts local executables: any process running as the user can write it, and
    a forged exit code ends the fetch early with no new authority. git is run by the supervisor
    through `command` with the `SC_GIT` program resolved by `/bin/sh` (a bare name through the
    PATH, a path as is; shell functions are skipped).
  - Only fetches are watched. `ls-remote` and push run unwatched: over HTTP
    `http.lowSpeedLimit`/`lowSpeedTime` bound them, over ssh the operator should set
    `ServerAliveInterval` for the daemon's ssh user.
- **Rejections are classified by re-reading the ref**, not by the host's wording, so a hook or
  permission refusal is never reported as a lost race. The atomic CAS relies on the host checking
  the sent old value under its ref lock: stock `git receive-pack` and sc-forge do (verified);
  another host that does not cannot carry the store safely.
- **Compaction on a carrier has no trusted clock, so it keeps its own (ADR-0057 addendum).**
  Committer time is writer-controlled and predates publication, so it is never an age.
  `sc remote compact` instead records when it first saw each pack and checkpoint in
  `refs/sc/compact/sightings` and ages objects from that (a re-created key is a new generation by
  oid, so it starts over). The record is writer-trusted like the rest of the store: anyone who can
  push can backdate it, but that person can already delete refs directly, so it adds no
  authority. It supplies ages only: the candidates come from the listing minus everything the
  live chain and the retained checkpoints and log entries name, so a record cannot make a live
  object deletable. A malformed record, one naming a key outside `packs/` and `checkpoints/`,
  or one dated more than five minutes ahead of the compactor's clock, blocks the run (it is
  never read as "everything is old"). Deletes are leased to the oid the listing showed, so a key
  re-created since survives, and the manifest is read uncached before every delete call.
  Left open: a pusher reusing an aged orphan pack byte for byte can still lose it if the delete
  lands after the manifest check and before its commit (no lease on the manifest), and a push
  that stalls past the grace window loses its pack, as on any backend. A writer can also make the
  compactor download a pack it did not need to: sizes for the merge plan come from the pack's idx,
  which the writer controls, so a pack whose idx understates it is downloaded whole (up to the
  2 GiB value cap, in RAM) before the real length is checked and the pack is left unmerged.
  A retained log entry or checkpoint whose value changed since the listing (a writer deleted and
  re-created it) keeps every candidate pack for that run. **Every pusher holds
  delete** (a push to `refs/sc/*` is a push); unlike S3, delete rights cannot be withheld from
  them. Run compaction from one host (clocks).
- **Serving a Git store (`sc serve --store sc+git::<url>`).** The server is a client of the Git
  host with the operator's credentials, so git must authenticate without prompting (an ssh
  agent, a key without a passphrase, or a credential helper); the server holds a credential as
  strong as any bucket writer's. A server not started with `--allow-private-branches` (the flag
  is refused for other stores) refuses, as `InvalidArgument` with no wire change, every object of
  a sealed-branch kind (`Sealed`, `Manifest`) in `PutPack` (before anything is uploaded, in any
  record order) and in `PutObject` (before it is staged), and any `UpdateRef` whose new tip is a
  manifest, even one already on the chain, so no private-branch ciphertext reaches the Git host
  through it and an existing private branch cannot be advanced or re-pointed. A client cannot
  lift the gate: the opt-in is the operator's, and without it any holder of a server token is
  kept from publishing private-branch names, recipient ids and sizes to everyone who can read
  the repository. It does not hide what is already on the host (reads still serve existing
  private branches), and a writer with direct push access bypasses the server. The refusal says
  that no private-branch object was uploaded, not that nothing was: public objects of the same
  push may already sit on the host as an orphan pack. An ssh user who can run `sc serve` is an
  operator: they can pass `--store` and `--allow-private-branches`, so the gate protects against
  the server's clients, not against whoever starts it.
- **Scaling.** `ls-remote` and push download the whole ref advertisement (the pattern given to `ls-remote` filters on the client; a packet trace showed the server sends every ref; the manifest read no longer does, it is one `git fetch` that a protocol v2 host answers with that ref alone), and a cold read fetches every `log/` and `checkpoints/` entry behind the last checkpoint. Refs grow by at least three per push (a log entry, a pack and its idx); `sc remote compact` bounds that by merging small packs and deleting what nothing names, so a long-lived store should be compacted on a schedule. Between runs the advertisement still grows until a ref-filtering host exists.
- **Local cache.** A temporary bare repository `sc-git-bucket-<pid>-<random>` (mode 0700) holds
  fetched store objects and is removed on exit; a killed process (SIGKILL, or SIGINT) can leave it
  behind. The CLI has no reaper. `sc serve` keeps the cache under the serve home's `.sc/tmp/`, holds
  an advisory lock on `<cache>/.owner.lock` for the bucket's life, and at startup removes the caches
  whose lock is free (unix). Liveness is that lock, not a pid, so a live `sc serve --stdio`
  session's cache on the same home is never removed and pid reuse, pid-1 containers and several pid
  namespaces on one host do not matter; it is an advisory lock on one host, unreliable over NFS and
  similar, as for `DirBucket`.
- Validated against a private GitHub repository (ADR-0060): custom refs, lease CAS,
  the filtered fetch and compaction behave as on sc-forge; GitHub's size limits, rulesets
  on custom refs and CAS across its replicas were not exercised. The "not independently audited, do not commit production
  secrets" warning at the top of this document applies unchanged.

## By-id object reads (`GetObjects`, `sc cat`) — ADR-0047

- **A hash is not a capability.** Anyone who can reach a served repo and
  knows (or guesses) an object id can ask for it by id. Reads are scoped by
  who may connect (ADR-0040 tokens, `--read-only`), not by which ids they
  name. This is no wider than `GetObject`, which already returns any stored
  object by id.
- **Sealed private-branch objects and manifests are refused by kind**
  (`Object::Sealed`, `Object::Manifest`) and reported as "not sent", the same
  reply as an absent id. This keeps `GetObjects` consistent with filtered
  `GetPack`. It is **not** a confidentiality boundary: those objects are
  ciphertext, an unfiltered fetch still serves them, and `HasObject` still
  reveals whether an id exists. `GetObject` is unchanged and still serves any
  kind; closing that is a tracked follow-on, not part of this phase.
- **The client trusts nothing in the reply.** Every record is BLAKE3-verified,
  and the reply must partition the request exactly (nothing unrequested,
  nothing both sent and refused, nothing omitted) before any object is
  written. A hostile remote can at worst answer "not sent"; it cannot plant an
  object under another id or smuggle in extras. The reply stream a client will
  read is capped at 4 GiB, a constant independent of the object cap (it
  bounds a disk spool, not RAM).
- **Server cost is bounded per request:** 1024 ids (checked while decoding,
  before any id is read), a ceiling on the summed encoded size of
  `min(--max-pack-size, 2 GiB)` (the 2 GiB is a constant, independent of the
  object cap; `--max-pack-size 0` leaves only the 2 GiB), and 1 GiB (the largest
  configurable object cap) per object. A batch over the ceiling is refused and
  the client splits it. The server's own object cap is not applied to replies,
  since the cap is receiver-only: a lower-cap server serves a larger local
  object to a client whose cap admits it, as `GetPack` does.
- **Laziness is a local opt-in.** `.sc/promisor-lazy` is never committed or
  transferred; without it a partial clone never dials the remote after clone,
  and `SC_OFFLINE=1` forces that per process.

## Partial clones (`--filter`, `--lazy`, merge and sessions on a clone) — ADR-0037/0047/0048/0049/0050/0055/0056

- **A partial clone is a store plus one promise, and the promise is about the
  origin (ADR-0048).** Every id referenced by an object the clone holds, that
  the clone lacks, is held by the promisor origin. Hash verification at ingest
  proves identity, not that a sender has a complete closure, so the client
  cannot check the promise locally; it trusts the origin for completeness. That
  is why a partial clone **fetches from its promisor origin only**: a fetch
  from another remote could leave a gap the origin does not hold, and the
  filler only ever dials the origin. A hostile or pruned origin can make a gap
  permanent (it can answer "not sent", or prune history a clone still
  points at); it cannot plant an object under another id, and a gap surfaces
  as `GapInView` or a fill error before any ref, operation-state or
  working-tree change, never as silently missing content. Objects a fill had
  already fetched by id stay in the store.
- **`--filter` is request scope, not access control.** The filter says what a
  clone asked for. Any client that can read the served repository can still
  fetch the rest (`sc backfill`, or by id where By-id object reads allows it);
  a filter hides nothing from the user running the clone, and sealed or
  protected content is governed by its keys, not by the filter.
- **Merge carries subtrees by id without reading them (ADR-0049), so the
  protection check happens before the carry.** A subtree is carried only when
  the sides agree and no protection rule of either side covers it or lies
  inside it; otherwise it is read and sealed like on a full clone. One accepted
  divergence: a subtree identical on all three sides is carried even under a
  rule, so a merge does not force a clone to fetch every protected prefix
  (plaintext that already sat under a rule stays as it was). The wrap map is
  not pruned when anything was carried, since a carried subtree is never
  enumerated; it can keep wraps for blobs the merge did not see, but never
  drops one a carried blob needs.
- **Conflicts and sealing stay inside the view.** A conflict outside the sparse
  view, or a result that must be sealed outside it, is refused before any ref,
  merge-state or working-tree change, so no conflict marker or sealing-input
  plaintext is written outside the view (the sparse boundary of ADR-0034).
- **A session on a partial clone sees the host's view and nothing else
  (ADR-0050).** An agent from `sc work` or `sc ws` cannot read or change what the
  clone does not hold, and a workspace commit grafts the out-of-view subtrees
  from the base by id. This scopes what a session lays out, not what an agent can
  reach: an agent is a same-user process that can read the host repository's
  store and working tree and, on a lazy clone, fetch more (`sc sparse set`,
  `sc cat`, `sc backfill`). It is not an isolation boundary (compare Secret
  injection). A command run by `sc ws run`
  no longer holds the repo lock (ADR-0056), so an `sc` it runs from inside the
  workspace finds the host repo and can change it, as a hand-started agent always
  could. Several sessions can be open at once (the unnamed one in `.sc/ws/`,
  named ones in `.sc/ws-<name>/`); their harvests are serialized by the repo
  lock and the first to land wins, a later conflicting one falls back to a
  `<name>-<i>` branch. Do not run a binary from before ADR-0056 against a repo
  with a named session open: its `sc gc` does not root that session's base
  snapshot.
- **`sc ws refresh` writes into a workspace the user or an agent may be using
  (ADR-0056).** It overwrites or removes a file only if it still holds what the
  refresh read, checked again right before each write (plain files by bytes,
  protected ones by the workspace cache's keyed tag or by re-encryption); it
  never touches an untracked or ignored file and refuses before any write when
  one is in the way. An edit in the instant between that check and the write
  can still be lost. It decrypts a protected path only with the identity passed
  to it and refuses rather than leave a stale plaintext copy; the throwaway
  candidate seals protected edits like a harvest does and is left for gc. It
  also refuses, before any write, a tip that drops the protection of a path the
  workspace holds as plaintext (a later harvest would otherwise publish it), and
  an `.scignore` change that would hide a file the agent added or expose an
  untracked one a harvest would then commit. An interrupted refresh leaves a
  `pending_refresh` marker, kept with the target and the per-workspace
  candidate and result snapshots as gc roots, so harvest and `sc ws run` refuse
  and a rerun of `sc ws refresh` finishes it; a retry needs `--identity` to
  resume a protected file it cannot otherwise verify. While the marker is set
  the manifest's `base_snapshot` reads `refresh-unfinished`, so a binary from
  before this change fails to parse the manifest, and so does its gc.
  Known limits: the marker records no per-file progress, so a file
  the interrupted refresh added and the agent then deleted comes back on the
  retry, and a power loss (not a process crash) can leave a mode or a deletion
  to redo.
- **A blob-size limit (`--filter blob:limit=<size>`, ADR-0055) is request scope
  like the prefix filter, and the server evaluates it.** It hides nothing: any
  client that can read the repository can fetch the left-out blobs (`sc
  backfill`, by-id fill), and a server that sends fewer blobs than asked can
  only create a gap, which surfaces as `GapInView`/`GapBySize` or a fill error
  before any write, never as wrong content (objects are hash-verified). The
  size is the stored payload length, so for a protected path it is the
  ciphertext size, which anyone who can fetch the object already sees; the
  filter reveals nothing new. A limited `GetPack` makes the server stream-measure
  each distinct candidate blob once (`Store::blob_size`, fixed buffer, hash
  checked, cached by id; a limit of 0 or `u64::MAX` measures nothing), bounded by
  the stored bytes of those blobs. A blob that is kept is read twice, once to
  measure and once to write the pack, so the read cost is at most twice an
  unfiltered `GetPack`'s, which already reads every blob into its pack. Reads are not budgeted (#233 budgets writes)
  and the filter does not change that; the listener limits are the bound. Every
  active filter, a limit alone included, still excludes private branches and is
  refused by bucket remotes. The wire bump (version 6) makes a mixed-version pair
  fail closed at the handshake in both directions. `sc fetch` sends the recorded
  limit to the promisor origin only (the origin check precedes it), so the
  same request scope and server cost apply per fetch; `--no-blob-limit` removes
  the scope and adds no plaintext access (it is an unfiltered fetch, which also
  receives private-branch ciphertext).
- **A filtered walk is bounded by the object count, not the path count.** A
  chain of trees whose two entries name the same child is a few KB with `2^depth`
  paths, and any writer can plant one with `PutObject`. The filtered reachability
  walk (`blob:limit` and prefix `GetPack`) keys a directory by id alone once it is
  wholly inside the filter scope, so each tree is read once; only the ancestors of
  a filter prefix are keyed by path.
- **Operations that need a complete closure refuse on a partial clone, fail
  closed:** `sc export`, `sc rewrap`, `sc grant`/`revoke`, private branches, and
  `sc push` to a git remote. They refuse rather than run on partial data.
- **Laziness is a local opt-in** (see By-id object reads above), and bucket
  remotes refuse `--filter` (see Bucket remotes).

## Working-tree writes (merge, switch, abort, sparse) — ADR-0034 refinements 6-8, ADR-0044

This is data safety for the user's own files, not confidentiality. The checkout
is user-owned disk that `sc` rewrites during merge, switch, undo, rebase, abort
and `sparse set`; a stopped operation also writes conflict markers and, for
protected paths, plaintext.

- **Enforced:**
  - A merge, switch, cherry-pick, rebase, undo or sparse-spec change refuses,
    before any write, to lay a file or directory onto an untracked or ignored
    one (`refuse_untracked_overwrite`), including a path outside the sparse
    view that the result adds (#248, #251). A refusal changes nothing; move the
    file away and retry. Not guarded: merging into an unborn branch (and a
    clone), except that every `materialize` refuses, before its first write, a
    path with a symlink among its parent directories, so a remote entry
    `link/x` cannot write through a user's `link -> .sc` or out of the
    checkout; and the conflict stop of a merge into a private branch (it checks
    only out-of-view paths, and refuses a `.theirs` sidecar onto an existing
    file).
  - A stop's `materialize` deletes or overwrites a path only if the tree it
    replaces tracks it and the disk copy is a regular file with exactly the
    tracked bytes, or the stop itself recorded the path (`.sc/CONFLICT_PLAINTEXT`,
    `.sc/CONFLICT_SIDECARS`, `.sc/sparse-widen`) and it still matches what was
    laid. An edit, a replacement or a symlink survives (#255, #256, #259).
  - `merge --abort`, `cherry-pick --abort` and `rebase --abort` finish past a
    kept resolution edit instead of refusing, so it cannot trap the user in the
    stop (a directory holding untracked content, or a file of yours where a
    directory must be, still refuses; a path with a symlink among its parents is
    left alone and reported in `kept`, never written through):
    they restore the tip, drop the stop's state and return an `AbortReport`
    whose `kept` paths (changed since the stop) and `skipped` protected paths
    `sc` prints. Recorded plaintext and sidecars are removed whatever their
    bytes, since an edit of them is the resolution the abort discards.
  - A file/directory change at one path crosses switch, undo, abort and
    `--continue` (#247, #250). Emptied directories are cleared, but every
    directory is checked before the first removal, so a directory that holds a
    user file refuses and an abort stays retryable.
  - A sparse view change never counts a case alias of a laid-out path as tracked
    (#241); where the guard cannot tell, it refuses.
  - A snapshot never holds one path as both a file and a directory (#278, #280,
    ADR-0034 refinement 9). An absent protected or out-of-view file is carried
    back verbatim, so a directory made at its path would otherwise yield a tree
    with a blob and a tree under one name; both tree builders (public and
    private-branch) refuse it with `FileDirCollision` before any tree is written,
    for commit, merge completion, `sc ws harvest` and `sc ws refresh`. Remove the
    directory and retry.
  - A tree path is never written if it could reach the `.sc/` control directory
    or leave the checkout. A tree comes from a peer and decode accepts any entry
    name, so `scl_core::check_tree_path` refuses, per component, an empty, `.`,
    `..` or NUL name, `.sc` at any depth under its filesystem aliases (HFS
    ignorable code points, NTFS `:stream`, trailing dots and spaces, Unicode case
    folding such as `.ſc` on APFS, the 8.3 short names `sc~1` to `sc~4` and
    `sc<4 hex>~1` to `~9`), and on Windows any `\` or `:`. The tree flatteners and
    `safe_join` apply it before the first write (`sc ws fork` and `sc work` check
    first, before they touch the filesystem), so clone, switch, merge, undo and
    `scl_vfs::Worktree::checkout` refuse with `UnsafePath` before any
    working-tree write or ref move; both tree builders refuse to commit such a
    path. The guarantee covers working-tree writes and refs, not every file: an
    unborn merge can mint `.sc/local-key` before the refusal, and a lazy fill can
    keep the (hash-verified) objects it fetched. A native clone writes branch
    refs and HEAD in its new `.sc/` before the path check; a failed clone removes
    them with the `.sc/` (it holds the repo lock until then). It removes only
    what it made: a `.sc/` it created exclusively, and the destination and
    parents it created while they are empty. An existing clone destination must
    be an empty directory.
- **Not enforced (known limits):**
  - A user file whose bytes equal the tracked or laid ones cannot be told from
    the stop's own write, so it is removed.
  - The private-branch stop keeps no decided root and no record of the bytes it
    laid, so its `merge --abort` (which needs `--identity`) restores the tip over
    every path the tip tracks: a post-stop edit of one, or a user file at a path
    the stop removed, is lost, and a conflicted path counts as the stop's. Private
    forward operations remove in-view paths on the dirty check alone, without a
    byte comparison.
  - Protected old paths are plaintext on disk and cannot be compared without a
    key: a forward operation still removes a user's plaintext copy, and an abort
    restores one only if the stop recorded it. A stop recorded by a build before
    #259 lacks the decrypted entries, so its abort keeps such a file.
  - A crash after the sidecar record is retired and before the sidecar is
    unlinked leaves the `.theirs` file unrecorded, and a retried `sc commit`
    would commit it as ordinary content (ROADMAP.md, Deferred).
  - On a partial clone the out-of-view check sees only the subtrees the store
    holds; an addition inside an absent subtree fails the later commit with
    `GappedPathContent` instead.

## Untrusted-input hardening (DoS) — ADR-0039

- A single max object size caps every untrusted length: wire frames,
  pack-record compressed length, the zstd *decompressed* output (decompression-bomb
  guard), bucket pack bodies, by-id reply objects, the `SC_PACK_CHUNK` clamp (fixed at the
  2 MiB minimum cap minus one, since caps are receiver-local and unnegotiated),
  and object-decode collection counts. The default is 256 MiB. An operator can
  lower or raise it with `sc serve --max-object-size` and `SC_MAX_OBJECT_SIZE`
  (#213), within a compile-time range of 2 MiB to 1 GiB; a value outside that
  range aborts startup rather than being clamped; an empty `SC_MAX_OBJECT_SIZE`
  counts as unset. A guard checks the claimed length before allocating, and
  frame bodies, pack records and the zstd output are then read in exact-size
  growth steps as bytes arrive, so over-allocation is bounded (at most the
  larger of 8 MiB and 12.5% of the bytes received) and a hostile header or
  compression bomb cannot buy a cap-sized allocation without sending the bytes.
  **Accepted boundaries:**
  - The cap is a *transfer-path* guard. A locally-committed blob above it
    commits fine but cannot be transferred.
  - **The receiver's cap must admit the object.** There is no negotiation and
    no protocol bump, and only the receiving side's cap applies to incoming
    frames and records (a default server serves a 3 MiB object to a client
    capped at 4 MiB). An object above the receiver's cap is refused there,
    loudly, with an error naming `SC_MAX_OBJECT_SIZE`. A server raised
    to 1 GiB accepts a peer's gigabyte claim only if that peer sends the bytes,
    but then holds that object in memory. Raising the cap raises
    per-connection memory in two parts. Transient pack-decode memory: a record
    holds its compressed payload plus the decompressed output (each up to the
    cap) while decompressing, then the decompressed output plus the decoded
    object while decoding (the compressed copy is released first), so the peak
    is about 2 x cap. A single-object `PutObject` is also about 2 x cap: the
    request frame is moved, not copied, into the object body, and storing it
    decodes one more copy; a `GetObject` reply on the server holds the body and
    its response frame. A read-only listener rejects a `PutObject` only after
    reading the frame, so it can hold one cap-sized frame per connection to
    refuse it. Plus the connection's own store budget,
    `max(512 MiB, 2 x cap)`, because each served connection opens its own
    store. That is about 0.5 GiB + 0.5 GiB per connection at the default and
    about 2 GiB + 2 GiB at the 1 GiB ceiling, and it multiplies by
    `--max-connections` (default 32); size `--max-connections` down when
    raising the cap. Lowering the cap below a repository's largest object
    makes that repository unpushable until it is restored. `SC_MAX_OBJECT_SIZE`
    also sets the default store budget of every local command that opens a
    repo or serves one (`Repo::open`, `LocalTransport`), not only transfers.
    An explicit budget overrides it: `sc work --budget-mb` and
    `Repo::open_with_budget` use exactly the size given, and one smaller than
    an object fails with `BudgetExceeded`.
  - **Frames carry 64 bytes of framing beyond the cap.** A frame may be
    `cap + 64` bytes (`PutObject` header 37 bytes, response status 1, chunk
    tag 1), so an object of exactly the cap fits; the object body itself is then
    checked against the cap exactly.
  - **A local-path source loads before the receiver refuses.** A clone or
    fetch from a local-path remote reads each object through
    `LocalTransport::get_object` (load plus encode) before the receiver's cap
    rejects it, bounded by the local store budget. Wire sources refuse in
    `WireClient::get_object`, before decoding.
  - **Writes are budgeted per connection (`--max-conn-bytes`, #233), but the
    default does not protect RAM.** `Object::blob_size` is 0 for trees,
    snapshots, secrets and transcripts, so the store budget does not see them;
    a running per-connection counter now covers every `PutObject` (decoded
    length) and every `PutPack` (the larger of its spooled bytes and the
    decoded bytes the receiver holds: structural records on a local store,
    every record on a `--store` bucket, which decodes them all before upload).
    A request that would exceed it gets `ConnectionBudgetExceeded` and the
    connection closes. The default is `--max-pack-size` plus the max object
    size, about 16.25 GiB per connection, times `--max-connections` (default
    32): finite, but not a meaningful memory or disk bound. On a writable
    listener, lower `--max-conn-bytes` and `--max-pack-size` together (the
    budget must stay at least the pack cap); `sc serve --http` warns at
    startup when a writable non-loopback listener runs on the default. Objects
    the store already holds still count. A client sees the typed error only if
    it overshoots by less than the 8 MiB drain cap; otherwise the connection
    may reset. Reads are not budgeted. See the ADR-0039 #233 addendum.
  - **One length is checked after allocation:** bucket WAL metadata (manifest,
    log entry, idx) is capped at a fixed 256 MiB after the bucket GET has
    buffered it, so it bounds decode work, not the download. It is not tied to
    the operator's cap, so lowering the cap cannot make a bucket unreadable.
  - By-id reply spools (server ceiling `min(--max-pack-size, 2 GiB)`, client
    read cap 4 GiB) do not depend on the object cap: the 2 GiB and 4 GiB are
    constants, and the spools bound disk, not RAM.
  - The ceiling (1 GiB) is compile-time, so no configuration can make a length
    claim unbounded.
- **Git export refuses unsafe tree names.** `sc export` and a push to a git
  remote check every entry name at the one place export builds a Git tree from an
  sc tree: `.git`, `.gitmodules` and their HFS/NTFS aliases (git's own rules, via
  `gix::validate`), `.`, `..`, empty names and names containing `/`, `\` or NUL
  are refused. The check runs before the branch ref (and the mirror push) moves;
  blobs and subtrees written before the refusal stay in the target as
  unreferenced objects, and a repository the export created stays, with no refs
  (it is never removed, since another export may be writing into it; a retry
  points its unborn `HEAD` at the exported ref). A commit reused through a mark is never rewritten, so it
  is not judged, while anything export writes is, including a commit
  re-synthesized after its mark went stale. **Residual:** commits an older client
  already wrote into the mirror are pushed as they are, subject only to the
  receiver's own `fsck` rules, which are not export's policy (they accept a
  regular `.gitmodules`, which export refuses). An entry recorded with symlink mode still
  exports as a Git symlink (changing that would change re-synthesized tree ids),
  and a symlinked `.gitattributes`, `.gitignore` or `.mailmap` stays exportable
  (git treats them as informational); a Git symlink is ordinary Git content that
  git's own checkout and `fsck` handle.

## sc-forge: authentication, tenancy, transport, resources — P38 F1/F2

`sc-forge serve` is a separate trust domain from the `.sc/` features above: hosted repositories are plain
Git, there is no per-file encryption, and the boundary is the server's authentication and its process
isolation. This is threat-model pass #1 (auth, tenancy, transport, resources); passes on the content API
and on merge/protection come with F3 and F4. Each line names the test that pins it (`crates/forge/tests/e2e_git.rs`
unless said otherwise).

- **Credentials.** Git transport accepts access tokens only, in every recorded form (`token`/`Bearer`, Basic with
  the token as the password under any user name, or as the user name with an empty password); a user password is
  never a git credential (`a_password_is_never_a_git_credential`). Failures answer the recorded texts:
  401 `Unauthorized`/`Verify`, 403 `Forbidden`, 404 `Repository not found`
  (`every_credential_form_is_accepted_and_each_failure_has_its_recorded_text`). Authorization is evaluated once, at
  the start of the request: revoking a token or a collaborator does not cancel a push already running (it is bounded
  by `--git-timeout`, 30 minutes by default).
- **Existence oracles.** A repository the caller may not see, one that does not exist, and one being deleted give the
  same 404 body on both services (`missing_and_invisible_repositories_answer_identically`); a private organization the
  caller cannot see answers like a missing one on `GET /orgs/{o}`, `GET /users/{u}/orgs/{o}/permissions` and
  `GET /orgs/{o}/repos` (the last only while the caller can read nothing in it; a collaborator of a repository there still
  lists it), where Gitea 1.22 answers `HasOrgOrUserVisible` or 200 and so confirms the name (recorded departures for
  B#32, K#54 and K#55; `private_org_permissions_are_hidden_from_outsiders`); a token restricted to
  public repositories is refused before the repository is looked up, and a read-only collaborator is refused at the
  `receive-pack` advertisement (`scopes_and_permissions_gate_each_service`).
- **Tenant isolation.** The directory a transport can reach is built from the integer repository id
  (`GIT_PROJECT_ROOT=<data>/repos`, `PATH_INFO=/<id>.git/...`), never from client text, and git is told the repository
  explicitly (no discovery). Owner and repository segments must be plain name characters after percent-decoding
  (`.`/`..` are refused); the rest of the path must match a whitelist byte for byte, and the sub-path handed to the CGI
  is rebuilt from it (`only_the_whitelisted_shapes_and_methods_are_served`, `transport::tests`). `.git/config`, hooks,
  `objects/info/alternates` and every other file are 404. Objects of a deleted branch stay readable by anyone with read
  access to *that* repository (`uploadpack.allowAnySHA1InWant=true` is what makes fetch by id work; it is not a
  cross-tenant read, since each repository is a separate object store and no alternates exist).
- **Ref namespace.** Only `refs/heads/*`, `refs/tags/*` and `refs/sc/*` (a native sc store, writable by every repository
  writer, outside branch protection; see ADR-0058's addendum) are writable: `refs/replace/*`, `refs/pull/*`, `refs/notes/*`,
  `refs/changes/*` and everything else are refused by the `pre-receive` hook
  (`the_ref_policy_is_enforced_for_every_unwritable_namespace_and_the_default_branch`); `refs/forge/` (reserved for the
  server) is hidden from both services (`transfer.hideRefs`) and cannot be fetched by name
  (`refs_forge_is_hidden_from_both_services_even_when_it_exists`); replace refs are ignored on every spawn
  (`GIT_NO_REPLACE_OBJECTS`, `core.useReplaceRefs=false`). The default branch cannot be deleted, compared by Unicode
  lower case so a case alias does not slip past (`policy::tests`; the hook binary test
  `the_hook_binary_fails_closed`). Known gap: NFC/NFD-equivalent spellings of a non-ASCII default branch are not
  folded (a macOS-filesystem quirk; marked `shortcut:` in `policy.rs`). A push in flight read the default branch when it
  started, so `PATCH default_branch` commits only while no push has registered on the repository since it checked the
  branch, else 503 (`a_push_in_flight_keeps_the_default_branch_off_a_branch_it_deletes`, #316). Only a `receive-pack`
  run registers as a writer: a fetch or a dumb-protocol GET (read permission, no service) does not, so a slow reader can
  neither stall that change nor hold off run-time lock cleanup (`cgi::tests::only_receive_pack_registers_as_a_writer`).
- **Hook integrity.** `core.hooksPath` is pinned on every spawn to `<data>/hooks`, whose `pre-receive` is a symlink to
  the `sc-forge` binary, re-pointed at every start; repositories are created with `--template=` and carry no hooks of
  their own. The hook reads the database through a read-only opener (no create, `query_only`, schema version checked),
  never takes the data-directory lock, and **fails closed**: a database error, a missing repository, a repository that
  is not `live`, a malformed or non-UTF-8 update line, or a missing environment refuses the push
  (`the_hook_binary_fails_closed`, `hook::tests`). Authorization of branch protection (F4) plugs into the same
  `policy::check_update` function.
- **Environment and config injection.** The CGI environment is built from scratch (`env_clear`): fixed `PATH`, a scratch
  `HOME`, `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`, per-spawn config through `GIT_CONFIG_COUNT`. Of the
  request only these reach the child: a rebuilt `PATH_INFO`, the method, `service=` rebuilt from the parsed service,
  `Content-Length`, a printable `Content-Type` of at most 128 bytes, and `Git-Protocol` only when it matches
  `version=N[:key=value...]` of safe characters (`transport::tests`). `REMOTE_USER` is set only after the write check, so
  `http-backend` enables `receive-pack` for that request alone. The advertisement carries the server's git
  version and platform (`agent=git/2.x-<os>`), as stock git does.
- **Request framing.** Plain request bodies are never buffered: they stream through a bounded channel to the child. A
  gzip `upload-pack` request is read (within 5 minutes in total) and inflated **by the server before any process starts**, under a cap on both the
  compressed and the *inflated* size (`--max-request-bytes`, 16 MiB), because `git http-backend` has no counter on
  expanded bytes; the child gets the plain bytes with an exact `Content-Length` and never sees `Content-Encoding`. A bomb
  or bad gzip is therefore a deterministic 413/400 and never gets a process
  (`gzip_request_bodies_are_inflated_by_the_server_under_a_cap`; other encodings and gzip on a push are 415). Server
  memory is bounded per transport by about twice the cap while a gzip body is inflated (the buffer plus its chunked
  copy) and a few fixed channel buffers otherwise; with `--max-transports` 64 the worst case is the product.
- **Password verification.** Argon2 checks run under a global gate (`--argon2-concurrency`); a check waits at most 2 s for a
  slot, then answers 503 + `Retry-After: 5` and hands its per-source attempt back, so a burst of logins cannot pin the
  blocking pool or count against honest sources (`a_busy_password_gate_answers_503_and_refunds_the_attempt`).
- **Client address behind a proxy.** The forwarded-for header is read only from a trusted peer, from the right: addresses
  of our own proxies are skipped, entries may carry a port (`ip:port`, `[v6]:port`), and the first entry that does not
  parse ends the walk on the last trusted hop instead of falling through to text the client chose
  (`limits::tests::forwarded_for_ports_are_parsed_and_junk_stops_the_walk`).
- **Decided and unchanged.** Repository scopes are not required on `/user/repos` and `/orgs/{o}/repos` (Gitea's requirement is
  unrecorded, see #316). Access tokens never expire and survive a password change (Gitea 1.22 parity); revoke tokens by hand.
- **Cache policy.** Everything served is authenticated, so nothing may be cached publicly: git's `public,
  max-age=31536000` on loose objects and packs is replaced with Gitea's private policy and its `Expires` dropped, and RPC
  results and 401s carry the same private policy (`authenticated_object_reads_are_never_publicly_cacheable`).
- **Resource exhaustion.** Admission before any process exists: a per-repository slot, then a global slot, both under one
  `--admission-wait` deadline (503 + `Retry-After`; per-repository first so a flood on one repository cannot hold global
  slots while it waits). Pushes reserve disk (`--min-free-bytes` floor, `--push-reserve` up front, grown in 64 MiB
  steps as bytes arrive); an unreservable push is 507 before it starts, or aborted mid-stream. The reservation is
  accounting, not enforcement: a push can write more than it reserved up to `--max-pack-size`
  (`receive.maxInputSize`, `RLIMIT_FSIZE`); a hard guarantee needs filesystem quotas or the container's cgroup limits.
  The child runs with `RLIMIT_CPU` (900 s), `RLIMIT_FSIZE`, `RLIMIT_CORE=0` and, on Linux, `RLIMIT_DATA`
  (`--git-memory-limit`, 8 GiB per child, so the host-wide bound is `--max-transports` times that; anonymous memory,
  which stops a pack declaring a huge compressed object from growing one child without limit;
  not enforced on macOS; on Linux a push whose object needs more fails with git's out-of-memory error and moves nothing,
  `the_git_memory_limit_stops_a_push_whose_object_needs_more`, and a cgroup limit on the service is the host-wide bound), a wall-clock limit
  (`--git-timeout`) and directional stall deadlines (`--git-idle-timeout`: no request bytes while git waits for them, or
  no room in the response because the client does not read), all of which end the transport
  (`slots_are_bounded_then_released_when_the_client_disconnects`, `a_stalled_upload_is_cut_off_by_the_idle_deadline`,
  `the_wall_clock_limit_ends_a_transport`, `a_push_over_the_size_cap_fails_and_changes_nothing`,
  `a_full_disk_reserve_refuses_pushes_with_507_but_not_reads`). Remaining exposure: any authenticated user with read
  access can hold transport slots, for `--git-timeout` (30 minutes) each by trickling a byte just inside the idle
  deadline, and a user who can create repositories gets 16 slots per repository, so one account can fill the 64 global
  slots and make everyone else wait out `--admission-wait` (503). There are no per-user quotas yet (F5; a per-user
  limit would also throttle Engine, whose clones come from one service account, so it needs a deliberate budget).
  A push's growth check credits its own written bytes back, but other pushes in flight are still counted twice (free space has dropped and they still hold the bytes), so it
  errs on the side of refusing. A killed push gets SIGTERM first (git removes its lock files and quarantine directory
  from its signal handlers; we wait up to one second for the leader to exit and stderr to close) and then SIGKILL. A push
  cancelled mid-pack moves no ref, but its `objects/tmp_objdir-incoming-*` quarantine can survive (seen with Apple git
  2.54); maintenance removes it once it is old enough to have no owner, as it does for a server killed outright
  (`a_push_cancelled_mid_pack_moves_no_ref_and_its_quarantine_is_reclaimed`). A push cancelled while it holds its ref
  lock (held in git's `reference-transaction prepared` hook) releases the lock and moves no ref
  (`a_push_cancelled_while_holding_its_ref_lock_releases_it`). A client whose close the server never receives (seen on macOS loopback in about 1 run in 8)
  is found by TCP keepalive, whose probes start after 15 s of silence (`Limits::tcp_keepalive`): a peer whose host
  answers a probe with a reset ends at once, and a paused but live client answers them
  (`keepalive_probes_leave_a_paused_live_client_alone`, #316). An unanswered probe follows the platform's retry
  defaults (Linux's can exceed 120 s), so for a dead host or a dropped NAT entry `--git-idle-timeout` remains the
  bound; behind a proxy the probes reach only the proxy.
- **Process control.** One supervisor thread owns each child and its process group and signals the group while the
  leader is still an unreaped zombie (so a reused group id cannot be hit); the registry holds a cancel flag, never a
  group id. A client that hangs up ends the child (`a_large_push_and_clone_stream_and_a_vanished_client_ends_the_child`);
  deleting a repository first closes its registry slot, cancels and waits for every transport on it, and refuses to
  rename the directory while one survives (`deleting_a_repository_ends_its_running_transports_first`); shutdown
  cancels what is left after the drain deadline and refuses to register anything new, so a request still queued for a slot
  cannot start git afterwards (`shutdown_ends_a_running_transport`,
  `a_request_queued_for_a_slot_does_not_start_git_after_shutdown`). A server killed outright
  (SIGKILL, OOM) leaves children running until the container's PID namespace or the service manager's cgroup ends them.
- **Response integrity.** The CGI header block is parsed and only a whitelist of headers (content type, cache and
  validator headers) is forwarded, each validated against control characters; a child that fails after the response head
  was sent ends the stream with an error so the connection drops instead of finishing a truncated body with a clean
  terminator: the response body ends only with an explicit end marker from the supervisor's clean verdict, so a closed
  channel is an error (`a_stalled_upload_is_cut_off_by_the_idle_deadline`). Behind a proxy that speaks HTTP/1.0 to its
  upstream (nginx's default) a cut stream can look like a clean end; git's own pkt-line framing still detects most
  truncations, and the deployment should set `proxy_http_version 1.1`. Because `git http-backend` writes its response head
  before it reads the request, an aborted push is visible to the client as a broken connection, not as a 408/413 status.
- **Transport security.** The server speaks plaintext HTTP and refuses a non-loopback bind unless told that a TLS proxy
  fronts it (`--behind-proxy`) or plaintext is wanted (`--allow-plaintext`); tokens cross this socket. No TLS and no SSH
  in sc-forge itself.

### Content API reads (F3a)

Threat-model pass #2 for the read endpoints. Tests are in `crates/forge/tests/e2e_content.rs`.

- **Revision and path injection.** A client string never reaches git as a revision or pathspec: revisions go through a
  grammar that yields a ref name or an object id, paths are literal (`--literal-pathspecs`, `--`), so `--output=`,
  `:/x`, `main^{/x}`, `@{0}`, glob and pathspec magic and `refs/forge/*` are 404 or 422
  (`revisions_are_names_or_ids_never_git_syntax`, `paths_are_literals_not_patterns`).
- **Hidden refs.** Only `refs/heads` and `refs/tags` are listed or resolvable by name; `refs/forge` and any future `refs/pull`
  are not (`refs_tags_and_trees`).
- **Visibility parity.** A repository a caller cannot read answers the same 404 as a missing one on every content route
  (`a_reader_without_access_gets_the_same_404_as_for_a_missing_repository`).
- **Resource use.** Every read is a bounded child process (output cap, runner gate, 503 when busy) under the
  repository read lock; capped commands get 120 s, the rest the runner's own timeout. The git runner's permit ends
  with the process, so memory held *after* it is bounded separately: at most 4 archives exist at once server-wide
  (`ArchiveSlot`; a fifth is 503), each held until its body has been written, up to 128 MiB of tar plus its gzip
  while it is built (`archive_slots_are_limited_and_come_back_when_dropped`). Listings, recursive trees and diffs are
  parsed in memory up to their 64 MiB output cap each, bounded only by `--max-connections`; a directory listing reads
  at most 100 symlink targets of at most 4 KiB. A single request can still run up to about 100 sequential `git log`
  calls while holding the repository read lock, so a delete or default-branch change can wait behind it.
- **Revision resolution is by object id.** A hex id names any object in the repository's object store, including
  commits reachable only from a deleted branch, as in Gitea (the F2b note on fetch by id applies); only branch and
  tag *names* are limited to `refs/heads` and `refs/tags`.
- **Not covered.** Content is served as stored: a file in a repository is returned base64-encoded in JSON, and raw/web
  URLs are not served, so no response is rendered as HTML.

### Content API writes (F3b)

Threat-model pass #2, first half (server-side writes; merge races and the protection bypass tests come with F4).
Tests are in `crates/forge/tests/e2e_write.rs` and the `gitwrite` unit tests.

- **Server-made commits bypass `receive.fsckObjects`.** The API therefore refuses what fsck would refuse on a push:
  `.git` aliases (including NTFS and HFS spellings), `.gitmodules` (any content: the URL/path/name checks are not
  reproduced), a `.gitattributes` (any alias, including `gitatt~1` and `gi7d29~1`) line of 2048 bytes or more, `.gitmodules` aliases (`gitmod~1` to `~4`, `gi7eba~1` to `~9`), backslashes, and paths deeper than 64 or with a component over
  255 bytes (`git_aliases_and_separators_are_refused`, `paths_that_a_checkout_could_misread_are_refused`). Names that only
  a case-insensitive or Windows checkout would collide (device names, `a:b`, `Foo` beside `foo/`) are not prevented.
- **A write cannot damage what it did not touch.** Trees are rewritten from raw bytes; the entries the request did not name
  keep their names and ids (`a_rewrite_keeps_every_untouched_entry_byte_for_byte`, `untouched_siblings_keep_their_exact_names`).
  Legacy modes in a rebuilt directory are normalised.
- **Concurrent writes.** The ref moves only by compare-and-swap; a lost round rebuilds from the new tip and re-checks the
  precondition (`concurrent_api_writers_and_an_independent_ref_writer_lose_nothing`: an independent real-git writer races
  twelve API writers and loses no commit). A push is not excluded by the write gate, so a writer can get 409 under sustained
  pushes.
- **Resource use.** One write at a time per repository (503 after 10 s); at most 3 attempts, 64 levels and 32 MiB of listings
  per attempt, and 60 s for the whole operation; disk is reserved from the push pool (the content plus slack up front, then per attempt the bytes of the tree listings read). A write holds the shared lifecycle lock, so a delete waits for it
  (`deleting_the_repository_while_writes_are_queued_does_not_hang`).
- **Identity cannot be chosen.** `author`, `committer` and `dates` in a request are ignored; the commit is the
  authenticated user's. A write collaborator can still push any identity over git, as in Gitea.
- **Unreferenced objects.** A refused or lost write leaves blobs/trees/commits no ref reaches; automatic gc is off (F5 adds gc).

### Branch protection and commit statuses (F4a)

Threat-model pass #2, second part (protection across write paths); the merge path and the bypass matrix come with F4c.
Tests: `crates/forge/tests/e2e_protection.rs`, the `policy`, `hook`, `protection` and `statuses` unit tests.

- **One policy for every ref move.** Push (`pre-receive`), contents API and branch DELETE call the same
  `policy` functions on rules read from SQLite. Administrators are not exempt: `enable_push: false` refuses them too
  (`pushes_under_a_rule`, `contents_writes_under_a_rule`). Tests use a non-default protected branch so the default-branch
  rule cannot mask a missing check.
- **Fail closed.** An unreadable database, a hook without `FORGE_GIT_BIN`, an unexpected object directory, a malformed object
  id, or an ancestry check that errors refuses the update. The ancestry check runs `git merge-base --is-ancestor` with the
  runner's pinned environment (no replace objects, no system or global config, hooks directory fixed) and only the
  quarantine's object directories added, each required to be under the repository's `objects/`.
- **Names.** Matching is exact and case-insensitive (a case alias of a protected name is protected); glob rule names, glob
  context names and every unenforced protection setting are refused rather than stored, so a rule never looks stronger than it is.
  A rule on a branch that does not exist yet reserves the name against push and contents creation.
- **Ordering.** Rule create/PATCH/DELETE hold the repository's write gate, as do contents writes, which re-read the rules
  immediately before `update-ref`: after a PATCH returns, no contents write lands under the old rule
  (`a_rule_change_is_ordered_against_contents_writes`). `receive-pack` does not take the gate: a rule created while a push is
  between `pre-receive` and its ref transaction does not stop that push. Rule changes answer 503 while a write holds the gate.
- **Statuses are not attestations.** Any caller with write access may post any context for any commit of the repository
  (Gitea's trust boundary). They gate merges only (F4c). Posting is bounded: 100 contexts per commit, 100 rows per context,
  field length caps, `target_url` limited to plain `http(s)` so a status link cannot be a `javascript:` URL in a web client.
  The author's stored email is not shown in the creator object.
- **Operator note.** The hook accepts the quarantine's object directories only when they are plain absolute paths under the
  repository's `objects/`. A data directory whose path contains `:` or starts with `"` makes git quote or split them, and every
  fast-forward push to a protected branch that allows pushes is then refused (fail closed, but easy to miss): keep such
  characters out of `--data-dir`.
- **Branch delete.** The API refuses a protected branch and deletes with compare-and-swap on the observed tip, so a concurrent
  push is not erased by a stale delete.

### Pull requests, reviews and retention refs (F4b)

Threat-model pass #2, third part; merge races and the protection bypass matrix come with F4c. Tests: `crates/forge/tests/e2e_pulls.rs`
and the `pulls` unit tests.

- **Who can do what.** Opening a PR needs write access (Gitea allows readers); changing one needs write access or being its
  creator; reviews and comments need read access, and a reviewer without write access cannot make a review `official`. Reviews
  and comments are bounded (64 KiB each; 1000 reviews and 5000 comments per PR). Inline review comments are refused rather than
  dropped.
- **Retention refs.** `refs/forge/pull/<n>/head` is server-only: pushes to the namespace are refused (F2b), reads hide it. Every
  write to it happens under the repository's write gate, except the `pre-receive` hook's record of a deleted head's tip, which
  runs without git's quarantine variables, validates the object id as hex, and refuses the push if it fails. The ref is written
  before the PR row, so a crash leaves an orphan ref (removed at startup), never a PR whose head can be pruned. Deleting a PR head
  branch (API or push) closes the PR and keeps the commit reachable (`deleting_the_head_branch_closes_the_pull_and_keeps_its_head`,
  `a_push_that_deletes_or_rewrites_the_head_keeps_it_reachable`); the startup reconcile repairs any disagreement
  (`startup_reconcile_restores_retention_refs_and_closes_vanished_heads`). Unreferenced objects are not collected until F5's gc.
- **Fetch by id.** `uploadpack.allowAnySHA1InWant` stays on, so a commit kept only by a hidden PR ref is fetchable by anyone who
  can read the repository and knows its id (as for any object over protocol v2); a PR head is no more secret than a branch.
- **Locks.** PR reads take the shared lifecycle lock once and never call `repo_json` (which takes it again); a read that finds a
  vanished head runs the sync before taking the lock (`reads_do_not_deadlock_against_exclusive_repository_operations`).
- **Account objects.** A PR's `user` and `merged_by` carry the full account object (stored email, admin flag), as recorded
  from Gitea and as `GET /users/{u}` already shows to any signed-in caller; only the objects Gitea itself nests in statuses,
  comments are masked (login-derived email, no admin flag), and a review list shows the stored email, as recorded (F#33). Anyone with read access to a repository can
  therefore see the stored email of its PR authors. Accounts that must not be identifiable should use a placeholder email.
- **Cost.** Mergeability and diff statistics run `git` per PR on a cache miss; a page lists at most 50 PRs. A repository with
  many open PRs and a huge history makes a list slow, not wrong; the runner's concurrency and timeouts bound it.

### Merge, recovery and the protection matrix (F4c)

Threat-model pass #2, last part. Tests: `crates/forge/tests/e2e_merge.rs`, `e2e_crash.rs` (a real `sc-forge serve` killed with
SIGKILL during merges, restarted and checked), and the `bypass_matrix_*` tests in `e2e_protection.rs`.

- **The matrix.** Against a protected non-default branch, for `enable_push` off and on and for an administrator and a write
  collaborator: a fast-forward push and a contents write succeed only with pushes on; a forced push, a push deletion and the
  API branch delete never do; a new branch cut from the protected one is allowed; a pull request merge into it works under both
  settings and is the only way in when pushes are off. Receive-pack, the contents API and the branch API go through the
  same `policy` functions on rules read from SQLite; the merge deliberately does not (it ignores `enable_push`) and reads the same rules
  only for the required status contexts.
- **Required checks gate the merge, not a push** (recorded, W#8). They are read for the head commit under the write gate
  immediately before the intent is written; a status posted by a repository writer for that commit counts (statuses are not
  attestations). There is no administrator override. A rule that requires checks but lists none refuses every merge.
- **A merge cannot publish a stale decision.** Rule changes, PR changes and merges serialize on the gate and every merge round
  re-reads the PR, rules, both tips and the statuses. The head is `verify`d inside the same ref transaction that moves the base,
  so "the head I checked is the head I merged" is atomic; a head that moved answers 409 and is never substituted.
- **Crash consistency.** Git and SQLite cannot commit together, and Git's files backend commits several refs one after another, so
  the protocol uses only single-ref atomic steps and evidence that survives a crash between them: the journal row precedes the
  base compare-and-swap (one ref, with the head `verify`d in the same transaction), the `landed` marker follows it, and recovery
  trusts, in order, the marker, the merge commit being in the base's history, and a lock file on the base (a live writer holding it
  keeps the intent pending; git children that outlived a SIGKILLed server are killed, and their locks removed, by the startup
  cleanup before any recovery runs, `startup_cleanup`/`a_restart_kills_an_orphaned_git_writer_and_clears_its_lock`); only a definite "no" aborts, and a git error leaves the intent pending. Recovery also
  runs before any pull-request mutation or sync, so a close cannot overtake a landed merge, and finalization never runs against a
  pull request that is not open (`a_close_cannot_overtake_a_landed_merge`,
  `a_git_writer_still_holding_the_base_keeps_the_intent_pending`,
  `a_crash_between_the_base_moving_and_its_marker_is_recognized_by_the_base_history`,
  `a_landed_merge_with_its_marker_is_still_merged_after_the_base_was_force_pushed_away`). `kill_nine_during_merges_leaves_a_consistent_forge`
  SIGKILLs a real server inside the merge windows (a test-only environment knob, `SC_FORGE_MERGE_PAUSE_MS`, stretches the two windows
  that matter), restarts it, and asserts after every restart: no pending intent, no marker, every pull request merged with a
  two-parent commit on the base or open with its head not on the base; it keeps going until the database shows an intent aborted
  by recovery and one finished by recovery.
- **Operator note.** A merge's `update-ref` killed by the runner's deadline can leave `refs/heads/<base>.lock` and `refs/heads/<head>.lock`
  (the transaction locks the verified head as well as the base). Nothing removes a lock at run time, because a lock cannot be told from
  a live push's: the intent stays pending while the base is locked, pushes and merges to those branches wait, and the next restart's
  startup cleanup removes every `refs/**/*.lock` once no matching git process is left alive (it leaves them, and says so, if one cannot
  be killed). That cleanup passes over the process table repeatedly until it finds nothing new (an `http-backend` can fork a
  `receive-pack` while it is being killed), and matches git processes by command line (`--git-dir=<data>/repos/...`) or by the
  `FORGE_DATA_DIR` the HTTP transport sets, on whole tokens (another instance's `/srv/forge-secondary` is not `/srv/forge`; on Linux a
  space inside a value is not a boundary). Migration 5 was rewritten while the feature was unreleased (no database at version 5 exists outside
  CI); a later change to it needs a new migration.
- **Known windows.** A rule created while a push is between `pre-receive` and its ref update is not stopped (the push does not
  take the gate). A merge computes its tree before it takes the base lock in git, so a base that moves under it only costs a retry,
  not a wrong merge (the compare-and-swap refuses). Objects of aborted or lost merges stay unreferenced until the maintenance
  pass collects them (F5a, below).
- **Identity.** The merge commit is authored and committed by the authenticated user (name and stored email, or
  `<login>@noreply.localhost`), as for contents writes; a client cannot choose it.

### Maintenance: garbage collection and leftover cleanup (F5a)

`maintenance.rs` deletes data, so it is the part of the forge where a mistake loses an acknowledged write. What it deletes, and
why each deletion is safe:

- **Unreferenced objects, in two stages.** Stage 1 (`git gc --prune=never --force`, no gate, `gc.cruftPacks=false` pinned) packs
  what refs reach and loosens unreachable packed objects with their old pack's mtime; it deletes nothing. Stage 2 runs under the
  repository's write gate: it first confirms every retention ref (`pulls::reconcile_repo` recreates a missing head, final-head or
  merge-commit ref from the database, and `pulls::verify_roots` then checks each pull request row independently, because a sync
  logs and skips a PR it cannot repair; any error, or a merge intent still pending, skips the prune; the reconcile runs under the
  shared lifecycle lock like every gated writer, taken with `try_read` so a queued delete cannot deadlock it), then `git prune --expire=<window>` removes loose unreachable
  objects older than the window (`--gc-prune-expire`, default 14 days, refused below twice `--git-timeout` and an hour). Holding the
  gate keeps the API writers away: a contents write or merge copies existing, possibly old, trees and blobs into new objects
  (`mktree` does not touch the referenced objects), and without the gate prune could unlink one between that read and the
  ref update. A first draft held no gate; Sol found this interleaving and the draft was dropped.
- **Merge commits.** A finished merge used to keep only its head alive; rewriting the base afterwards orphaned the merge commit that
  `merge_commit_sha` still names. `refs/forge/pull/<n>/merge` now holds it (written by `finish`, recreated by the reconciler).
- **Leftover locks and quarantine directories.** `refs/**/*.lock`, `packed-refs.lock`, `HEAD.lock`, the commit-graph locks a killed gc leaves and receive-pack's `objects/tmp_objdir-incoming-*` quarantine directories go at
  startup unconditionally (after orphaned git processes are killed) and at run time only when the write gate is held, the
  exclusive lifecycle lock is free (default-branch changes and branch deletes write refs under that lock alone), the
  repository has no registered run that can write (`Registry::with_only` ignores read-only fetches and holds the registry lock so
  no writer can register meanwhile; under that lock a quarantine is only renamed to `objects/dead-*` and deleted afterwards)
  and the item is older than 10 minutes. Age alone is never enough: a stepped clock or a suspended host can make a live owner's file
  look old.
- **Delete.** A run registers like a transport and carries the registry's cancel flag into every git spawn, so a repository delete
  cancels it (group kill) and waits for it before the rename. The run never waits for the lifecycle lock (`try_read`/`try_write`
  only); the gate wait is sliced so a cancel is noticed. The reconcile between the two does not carry the cancel flag; it is a handful of short git commands, and a
  delete that outwaits it answers 503 and reopens the repository rather than renaming under it.
- **Cruft packs are off on purpose.** Stage 1 pins `gc.cruftPacks=false`: with git's default, `gc --prune=never` writes unreachable
  objects into a cruft pack and `git prune` never touches packed objects, so nothing would be collected (a test packs an old
  object and fails if the pin goes). The cost: unreachable objects are stored loose, without deltas, for up to the window. Not
  measured on a realistic repository.
- **Prune holds the gate** for at most 10 minutes (its own limit). It runs only after a complete stage 1 (git's own gc does not
  prune after a failed repack either): without it reachable objects may still be loose and old, and the walk is slower. A repository
  that is too full to repack therefore keeps its garbage until space is freed.
- **Base commits.** An unmerged PR whose base branch is gone shows its stored `base_sha`; `refs/forge/pull/<n>/base` keeps that
  commit (recreated by the reconciler while it exists). Duration flags above ten years are refused at startup (a cutoff that wrapped
  would have meant "prune now"), and the pass also refuses a cutoff before the epoch.
- **Remaining exposure.** A push built on an object older than the window while a concurrent force-push has just unreferenced it
  and stage 2 runs, is not excluded (receive-pack does not take the gate); its objects would have to be older than 14 days and
  unreachable in that instant. A pending merge intent whose merge commit stays unreferenced for the whole window reads as "not
  landed" and aborts (a landed merge is reachable from the base or its marker). `git gc` is bounded by `--gc-timeout` and the
  cgroup, not by `RLIMIT`s; a repack needs roughly the repository's size in free disk (the pass skips the repack below
  `--min-free-bytes` plus that size). Writers to a repository wait on the gate (10 s) while stage 2 runs and see 503 if it
  outlasts that; stage 2 is a reachability walk and a scan of loose objects, not a repack.

### Operating surface: logs, shutdown, bind gate, image (F5b)

- **Logs carry no secret by construction.** `log.rs` writes JSON lines; the access log records method, path without query, status,
  duration and client address, never a header, body or query (a query could carry a token a client wrongly sends). Strings are cut
  at 512 bytes and JSON-escaped, so a hostile path or branch name cannot forge a line or grow one. A test sends a wrong password, a
  token in the query and in the clone URL, and asserts none of them appears in the output, that every line parses, and that
  health probes stay out. Limits: an error text from SQLite or git is logged as it comes (they have not been seen to echo
  credentials); a repository, branch or user name appears in paths and messages by design.
- **Shutdown.** SIGTERM closes the listening socket first (a restarting service is refused rather than left hanging in the backlog),
  closes idle keep-alive connections at once (they used to hold the drain for the whole deadline), lets requests in flight finish up
  to `--shutdown-timeout`, then cancels the git processes still running. The signal handlers are installed before the "listening"
  line, so a supervisor that stops the service as soon as it is up still gets the drain. A stalled request does not hold the exit past
  the deadline plus up to ten seconds for the cancelled git processes to be reaped and the runtime's two-second teardown. Log
  writes cannot hold it either: they go through a bounded queue and a writer thread, and a stderr nobody reads costs dropped lines,
  not a frozen server (a test fills a pipe with 6400 requests). A git transfer in flight across SIGTERM finishes if it ends
  within the drain (`sigterm_lets_a_clone_in_flight_finish_within_the_drain`); one still running at the deadline is cut
  without its terminating chunk, so the client sees an error, and no git process group outlives the server
  (`sigterm_cancels_a_clone_still_running_at_the_drain_deadline`). A repository delete cuts a clone the same way
  (`deleting_a_repository_during_a_clone_fails_the_clone`).
- **Bind gate.** Process tests pin it: `0.0.0.0`, `[::]`, a private address and a v4-mapped loopback are refused without
  `--behind-proxy` or `--allow-plaintext`; loopback needs no flag. Fail-closed on an address it cannot classify.
- **Image.** Base images pinned by digest; trixie git (2.47) because the server needs 2.40 and bookworm has 2.39; runs as uid 10001; no
  sshd or shell tooling added. The image build is an advisory CI job with a smoke test, not a required check. Not done: scanning
  the image for known vulnerabilities, signing it, a read-only root filesystem (the server writes only under `/data` and, through
  git, `/data/tmp`; untested with a read-only root).

## Reporting

Security reports go to **toni@git-agentic.com** or GitHub private vulnerability
reporting — see [`SECURITY.md`](../SECURITY.md). Reports about the deliberate
boundaries above are welcome as hardening suggestions, but they are known
limitations, not vulnerabilities.
