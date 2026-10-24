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
  be able to read it.

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
    the spooled temp pack is guard-cleaned on the resulting unwind.
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
  `Error::NonFastForward` check) is **cooperative**, honored by the `sc`
  client, not cryptographically enforced by the bucket. A writer with raw
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
  or delete rights). Grant them to a dedicated operator or
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
    file away and retry. Not guarded: merging into an unborn branch, and the
    conflict stop of a merge into a private branch (it checks only out-of-view
    paths, and refuses a `.theirs` sidecar onto an existing file).
  - A stop's `materialize` deletes or overwrites a path only if the tree it
    replaces tracks it and the disk copy is a regular file with exactly the
    tracked bytes, or the stop itself recorded the path (`.sc/CONFLICT_PLAINTEXT`,
    `.sc/CONFLICT_SIDECARS`, `.sc/sparse-widen`) and it still matches what was
    laid. An edit, a replacement or a symlink survives (#255, #256, #259).
  - `merge --abort`, `cherry-pick --abort` and `rebase --abort` finish past a
    kept resolution edit instead of refusing, so it cannot trap the user in the
    stop (a directory holding untracked content, or a blocked parent, still refuses):
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
  same 404 body on both services (`missing_and_invisible_repositories_answer_identically`); a token restricted to
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
- **Ref namespace.** Only `refs/heads/*` and `refs/tags/*` are writable: `refs/replace/*`, `refs/pull/*`, `refs/notes/*`,
  `refs/changes/*` and everything else are refused by the `pre-receive` hook
  (`the_ref_policy_is_enforced_for_every_unwritable_namespace_and_the_default_branch`); `refs/forge/` (reserved for the
  server) is hidden from both services (`transfer.hideRefs`) and cannot be fetched by name
  (`refs_forge_is_hidden_from_both_services_even_when_it_exists`); replace refs are ignored on every spawn
  (`GIT_NO_REPLACE_OBJECTS`, `core.useReplaceRefs=false`). The default branch cannot be deleted, compared by Unicode
  lower case so a case alias does not slip past (`policy::tests`; the hook binary test
  `the_hook_binary_fails_closed`). Known gap: NFC/NFD-equivalent spellings of a non-ASCII default branch are not
  folded (a macOS-filesystem quirk; marked `shortcut:` in `policy.rs`).
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
  not enforced on macOS and untested in CI: a cgroup limit on the service is the real bound), a wall-clock limit
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
  from its signal handlers; we wait up to one second for the leader to exit and stderr to close, not tested) and then SIGKILL; a server killed outright can still leave a stale
  `refs/heads/<x>.lock` or `objects/incoming-*` behind (cleanup is F5).
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
  settings and is the only way in when pushes are off. Receive-pack, the contents API, the branch API and the merge all go
  through the same `policy` functions on rules read from SQLite.
- **Required checks gate the merge, not a push** (recorded, W#8). They are read for the head commit under the write gate
  immediately before the intent is written; a status posted by a repository writer for that commit counts (statuses are not
  attestations). There is no administrator override. A rule that requires checks but lists none refuses every merge.
- **A merge cannot publish a stale decision.** Rule changes, PR changes and merges serialize on the gate and every merge round
  re-reads the PR, rules, both tips and the statuses. The head is `verify`d inside the same ref transaction that moves the base,
  so "the head I checked is the head I merged" is atomic; a head that moved answers 409 and is never substituted.
- **Crash consistency.** Git and SQLite cannot commit together, so the journal row precedes the ref transaction and the receipt ref
  is part of it. After SIGKILL at any point the receipt says whether the merge committed; recovery then finalizes or aborts, never
  guesses from where the base branch is (a landed merge stays merged after a force push of an unprotected base:
  `a_landed_merge_is_still_merged_after_the_base_was_force_pushed_away`). `kill_nine_during_merges_leaves_a_consistent_forge`
  kills a real server at delays that sweep a merge, five times, and asserts after each restart: no pending intent, no receipt, every
  pull request merged with a two-parent commit on the base or open with its head not on the base.
- **Known windows.** A rule created while a push is between `pre-receive` and its ref update is not stopped (the push does not
  take the gate). A merge computes its tree before it takes the base lock in git, so a base that moves under it only costs a retry,
  not a wrong merge (the compare-and-swap refuses). Objects of aborted or lost merges stay unreferenced until F5's gc.
- **Identity.** The merge commit is authored and committed by the authenticated user (name and stored email, or
  `<login>@noreply.localhost`), as for contents writes; a client cannot choose it.

## Reporting

Security reports go to **toni@git-agentic.com** or GitHub private vulnerability
reporting — see [`SECURITY.md`](../SECURITY.md). Reports about the deliberate
boundaries above are welcome as hardening suggestions, but they are known
limitations, not vulnerabilities.
