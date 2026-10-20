# src-control — Threat model & security boundaries

This document consolidates, in one place, the **deliberate security boundaries**
of src-control's cryptographic features — the things it does *not* defend against
by design. They are drawn from the per-phase ADRs (linked below); this page
exists so a newcomer evaluating whether to trust real data to the system does not
have to read 54 ADRs to find the caveats.

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
- **Local cache key is owner-only on unix only (P33, #214):** the
  unchanged-detection cache is keyed by `.sc/local-key`, created `0600` from its
  first byte. Only unix can do that; on a non-unix target the key and the cache
  files are written with inherited default permissions, and `sc` prints a
  one-time stderr warning once a cache holds a protected entry. The exposure is
  small: checkout already writes protected plaintext into the working tree with
  default permissions on every platform, and the cache holds tags only for files
  whose plaintext is on disk, so a reader of the key could read that plaintext
  directly. What remains is the tags of the last-committed version of a file
  edited since, and stale entries until the next save. The real fix is an
  owner-only Windows ACL (`windows-sys` is already a transitive dependency); it is
  unverified without a Windows host and tracked in ROADMAP.md. A unix filesystem
  that ignores mode bits (vfat, exFAT, some network mounts) is not detected.

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
  (resolved, #260). Writers
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

## Bucket remotes (`sc+wal://` / `sc+s3://`) — ADR-0046

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
  deletion (fail closed, the report names the key to remove by hand). Use `--dry-run` first on a new bucket.
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
  before any id is read), the server's `--max-pack-size` over the summed
  encoded size, and 1 GiB (the largest configurable object cap) per object. The
  server's own object cap is not applied to replies, since the cap is
  receiver-only: a lower-cap server serves a larger local object to a client
  whose cap admits it, as `GetPack` does. The reply ceiling is a constant
  2 GiB.
- **Laziness is a local opt-in.** `.sc/promisor-lazy` is never committed or
  transferred; without it a partial clone never dials the remote after clone,
  and `SC_OFFLINE=1` forces that per process.

## Partial clones (`--filter`, `--lazy`, merge and sessions on a clone) — ADR-0037/0047/0048/0049/0050

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
  could.
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
  fail closed at the handshake in both directions.
- **Operations that need a complete closure refuse on a partial clone, fail
  closed:** `sc export`, `sc rewrap`, `sc grant`/`revoke`, private branches, and
  `sc push` to a git remote. They refuse rather than run on partial data.
- **Laziness is a local opt-in** (see By-id object reads above), and bucket
  remotes refuse `--filter` (see Bucket remotes).

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
  - By-id reply spools (server ceiling 2 GiB, client read cap 4 GiB) are
    constants independent of the cap: they bound disk, not RAM.
  - The ceiling (1 GiB) is compile-time, so no configuration can make a length
    claim unbounded.

## Reporting

Security reports go to **toni@git-agentic.com** or GitHub private vulnerability
reporting — see [`SECURITY.md`](../SECURITY.md). Reports about the deliberate
boundaries above are welcome as hardening suggestions, but they are known
limitations, not vulnerabilities.
