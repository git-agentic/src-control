# ADR-0044: Per-branch access control (private branches)

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 34
- **Builds on:** ADR-0043 (P33 randomized sealing — the seal primitive private
  branches reuse), ADR-0014 (P7 protected paths — the split-envelope
  discipline generalized here), ADR-0027 (P17 rewrap mechanics — mirrored at
  the KEK level), ADR-0026 (P16 revocation semantics — the rotation ≠ erasure
  boundary restated), ADR-0032 (P22 signatures — why published commits start
  unsigned), ADR-0037 (P27 partial clone — the filter non-interaction),
  ADR-0016/0018 (git bridge — the export refusal)

## Context

The one thesis capability not yet built: staging work — canonically an
embargoed security fix — on a branch that is **fully opaque** to
non-authorized readers until a coordinated release, then made public in one
atomic operation.

Nothing existing composes into this. P7/P33 protection encrypts **blob
content only**: trees (file paths), snapshot messages, authors, timestamps,
and the DAG shape are plaintext CAS objects. The requirement here is
stronger — a non-recipient must not read content, must not confirm the
presence of specific file contents, and must not **enumerate the branch's
file paths**. That demands sealing trees and snapshots too, which is
structurally new.

The equality-confirmation question the original task brief raised
(convergent vs. randomized encryption) was settled by ADR-0043 before this
phase: all protected sealing has been randomized (fresh DEK + nonce) since
P33. Private branches inherit that primitive; this ADR does not re-litigate
the choice — a deterministic seal for branch objects would reopen exactly
the oracle P33 closed, and is rejected below on those grounds.

## Decision

### 1. Unit of sealing: per-object

Every object a private commit introduces — snapshot, tree, blob — is
individually encrypted into a **sealed object**: a new CAS object kind whose
payload is `nonce(24) ‖ AEAD(canonical encoding of the inner object)` under
a fresh random per-object DEK (the ADR-0043 randomized primitive, applied to
object encodings rather than file bytes). The sealed object's id is
BLAKE3 of the ciphertext, so ids reveal nothing about the plaintext.
Content, paths, messages, and the inner DAG are all hidden; object count and
sizes leak (accepted, §Threat-model delta).

**Accepted cost — no dedup with public objects.** A private branch forked
from `main` re-seals its **entire closure**, including unchanged content: a
sealed tree referencing a public plaintext blob would announce "this file is
unchanged from public" and pre-seed an equality oracle. A private branch
therefore roughly doubles storage for its closure. For the intended shape —
small, short-lived embargo branches — this is acceptable and deliberate.

### 2. Closure visibility: a sealed-branch manifest

A private branch's ref points at a **sealed-branch manifest**, a small CAS
object with plaintext *structure* (its fields are visible; the content they
guard is not):

- the flat list of every sealed object id in the branch closure,
- the sealed tip snapshot's id,
- the key material (§3).

Keyless parties get exactly one rule each. **gc:** manifest reachable ⇒
every listed id reachable. **Transport:** diff the flat list against the
peer's haves; a private branch always travels as a whole closure. No inner
DAG shape is visible — strictly less leakage than per-object edge lists.
The manifest is rewritten on every private commit; it is a growing flat
list, and optimizing it is a **non-goal** at hotfix scale. A non-recipient
can watch the closure count grow over time (commit activity is observable
as count deltas) — accepted metadata leakage, stated here deliberately.

### 3. Key architecture: two-level envelope

- Each sealed object's DEK is wrapped under a per-branch **branch KEK**.
- The KEK is wrapped per recipient (X25519 → HKDF → AEAD, reusing
  `wrap_dek_for`/`unwrap_dek_with` from `crates/crypto`) **and to the
  configured escrow set** — the P17 `granted_keys() + escrow` posture.
- All wraps live **in the manifest, never inside sealed object bytes** (the
  P7 split-envelope discipline): membership churn never moves an object id.

Consequences of the shape:

- **Grant is O(1):** wrap the KEK for the new recipient; one manifest edit.
- **Revoke is O(closure) in wrap operations only:** mint a fresh KEK, unwrap
  each object DEK with the old KEK and rewrap under the new, write the new
  recipient wrap list. **Zero content plaintext is produced, zero object ids
  change** — revocation rewraps without writing plaintext to the object
  store, mirroring P17 mechanics one envelope level up.
- **Rotation ≠ erasure, restated (ADR-0019/0026):** a revoked recipient who
  already fetched the branch holds the old manifest and old KEK and can
  decrypt everything sealed *before* the revoke, forever. The rewrap
  guarantees they cannot read anything sealed *after*. Escrow holders can
  read embargoed content pre-publish — the standing meaning of break-glass
  escrow, applied consistently; a `--no-escrow` creation flag is recorded in
  ROADMAP, not built.

### 4. Publish: atomic full-history replay into public space

`sc branch publish <name>` (recipient identity required):

1. Decrypts the sealed closure through the manifest.
2. **Re-runs the P5 secret scanner over every decrypted file** before
   writing any public object — a secret committed under seal must not sail
   into plaintext history at the moment of publish. (The scanner also runs
   at private-commit time, where the plaintext is in hand; publish is the
   last line.)
3. Replays each private commit as a plaintext public snapshot — message,
   author, timestamp, and tree content preserved; parents remapped to the
   previously-published ids; the fork-point parent keeps its existing
   public id. Files under protected prefixes seal through the normal
   P7/P33 commit path, so path protection applies in public space.
4. Moves the branch ref to the published tip — the branch simply **becomes
   public**. The single ref move is the atomic commit point; one oplog
   record; `sc undo`-able. The manifest is dropped; the sealed closure
   becomes unreachable and `sc gc` prunes it under the normal grace window.

**Object ids change on publish, necessarily.** A sealed id is BLAKE3 of
ciphertext; a public id is BLAKE3 of the plaintext canonical encoding. If
they could be equal, the sealed id would be a deterministic function of the
plaintext — precisely the equality oracle ADR-0043 closed. Publish is
therefore a history rewrite by construction, with the standard P22
consequences: **signatures over private snapshot ids do not carry over;
published commits start unsigned** (re-sign with `sc sign`, the existing
amend/rebase/merge posture), and peers that fetched the private ref see a
non-fast-forward ref move.

Intermediate commit **messages become public** at publish — operators
staging embargoed fixes must write messages accordingly. A `--squash`
publish mode is recorded in ROADMAP, not built.

### 5. Operation policy matrix

| Actor | Operation | Policy |
|---|---|---|
| Recipient | `switch`, `commit`, `status`, `diff`, `log` on the private branch | Normal semantics; reads decrypt through the manifest, commits seal new objects and rewrite the manifest |
| Recipient | `merge main` *into* the private branch | **Allowed** — public content flows in and is re-sealed (it was already public); keeps a long embargo branch current |
| Anyone | merge / cherry-pick / rebase **from** a private ref while on a public branch | **Refused, always**, with a hint → `sc branch publish`. Decrypt-and-commit-to-public *is* publishing minus the atomicity, the scan, and the deliberate decision; the only path to plaintext goes through the one loudly-named command |
| Non-recipient | `fetch` / `push` / `clone` / `gc` | Work by design — ciphertext + manifest travel and collect without keys |
| Non-recipient | `log` / branch listing | Branch **name** visible with a `(private, no access)` marker |
| Non-recipient | `switch`, `merge`, `diff`, `publish`, everything else | Clean refusal |

Branch existence and **name** are visible by design; embargo branches
should be named blandly (the demo uses `hotfix-CVE-2026-1234` only as a
worked example — a real embargo would not put the CVE id in the ref name).

### 6. Creation and membership surface

- `sc branch <name> --private --to <recipient>...` — the existing creation
  verb plus flags, matching the house `--to <pubkey-or-name>` idiom (the
  task brief's `branch create --private --recipients` spelling is
  deliberately not used). Identity required (`--identity` / `SC_IDENTITY` /
  `~/.sc/identity`); the **creator is always wrapped in** even if absent
  from `--to` (a branch its creator cannot read is a pure foot-gun).
- `sc branch grant <name> --to <recipient> --identity <key>` — O(1) KEK wrap.
- `sc branch revoke <name> --recipient-id <id> --identity <key>` —
  **revoke implies immediate, atomic KEK rotation + DEK rewrap** in the same
  command. Unlike P7 path revoke (policy-only, rewrap separate), a private
  branch revoke that left the old KEK live until a later manual rewrap would
  be a standing foot-gun on exactly the branch type where it matters most;
  the Q3 architecture makes the rewrap cheap enough to fuse. `--identity`
  is required (unwrapping DEKs from the old KEK needs a key).
- Both are ref-moving ops (they rewrite the manifest the ref points at):
  in-progress-op guarded, oplogged, `sc undo`-able — the standard treatment.
- **P17 `sc rewrap` does not touch private-branch manifests.** Branch
  membership is managed only through the `sc branch` surface; the bulk
  cutover command stays scoped to secrets + protected paths rather than
  growing a fourth semantics.
- **Local branch names stay flat** (P28 ref grammar unchanged); `/` remains
  reserved for remote-tracking refs. Slash-names are an independent naming
  feature, recorded in ROADMAP.

### 7. Git bridge: unconditional exclusion

`sc export --to <git-repo>` refuses when the current branch is private
(hint: publish first). `sc push <git-remote>` refuses a private branch.
Fetch through the bridge can never mint one (git has no source for a
manifest). **`--include-encrypted` does not cover private branches**: that
flag exists for P7 protected *paths*, where the exported git repo stays
structurally coherent (public trees, sealed file contents). A private
branch has no exportable git structure at all — the structure is what's
sealed — so the refusal is unconditional, not flag-gated. `crates/gitio`
never learns the new object kinds exist.

### 8. Format and wire

**No existing object's on-disk format changes.** Snapshots, trees, blobs,
secrets, and signatures are untouched; `TAG_SNAPSHOT` stays 4. The two new
object kinds (sealed object, sealed-branch manifest) are **additive tags**.

Because the new kinds cross the wire on push/fetch/clone,
**`PROTOCOL_VERSION` bumps 3 → 4**: a pre-P34 peer fails cleanly at the
handshake with a version error instead of hitting an unknown object tag
deep in pack ingest. A P34 client cannot talk to a P33 server even about
public branches — zero cost in practice under the same no-deployed-old-peers
reality every prior format-touching phase leaned on, and it fails loud at
the seam.

**Transport safety is by construction, and pinned by test:** the wire ships
stored bytes, and a private branch's stored bytes are ciphertext + the
plaintext-structure manifest (ids and wraps — no content, no paths, no
messages). The plaintext `sc+http://` transport therefore never carries
private plaintext. A regression test captures the wire bytes of a private
push/fetch and asserts known plaintext markers (file content, paths, commit
message) appear nowhere in the stream.

### 9. Partial clone and sparse

Filtering and privacy do not compose: a server cannot path-filter inside
sealed trees — that inability is the feature. So:

- `sc clone --filter <prefix…>` **excludes private branches entirely** (no
  ref created).
- Everywhere else, a private branch travels as its whole manifest closure
  or not at all.
- `sc sparse` on a private branch works normally for a recipient — sparse
  is checkout-only (ADR-0034) and applies after decryption.

No P27 promisor/gap machinery grows manifest-aware cases.

## Threat-model delta (to be added to docs/THREAT-MODEL.md)

- **Defends:** content, file paths, commit messages, authors, timestamps,
  and DAG shape of a private branch against any party lacking a recipient
  (or escrow) key — including the hosting server, all transports (plaintext
  `sc+http://` included), and every clone.
- **Does NOT defend / leaks by design:** branch **existence and name**;
  sealed object **count and sizes**; closure **growth over time** (commit
  activity); who the recipients are is not hidden from manifest holders
  (recipient ids are in the wraps). Revoked recipients keep everything
  sealed before the revoke (rotation ≠ erasure). Escrow holders can read
  pre-publish. Publish makes intermediate commit messages public.

## Alternatives considered

- **Whole-branch sealed bundle.** One encrypted object holding the entire
  serialized history. Maximal opacity, but every commit re-writes and
  re-transfers the whole branch, and every merge/replay path needs a second
  codepath outside the CAS grain. Rejected.
- **Reuse per-file protection (`sc protect ""`) + encrypted commit
  messages.** Trees stay plaintext, so paths enumerate — fails the core
  requirement outright. Rejected.
- **Convergent/deterministic sealing of branch objects** (dedup with public
  space, dedup across private branches). Reopens the equality-confirmation
  oracle ADR-0043 closed, and against a *sealed tree* it would confirm
  whole-subtree equality with public history. Rejected.
- **Per-object plaintext edge lists instead of a manifest** (gc/transport
  walk sealed objects like a DAG). Leaks the inner DAG shape — snapshot vs.
  tree fanout, parent counts, per-commit structure evolution. The manifest
  leaks strictly less and gives keyless parties one dumb rule. Rejected.
- **Flat per-recipient wraps per object (no KEK).** Grant becomes
  O(closure) and a true revoke-rewrap forces re-sealing every object (full
  id churn). Rejected for the two-level envelope.
- **Keys required for gc/serve.** Breaks the unauthorized-ciphertext-host
  story that the rest of the system is built on. Rejected.
- **Opaque sealed refs through the git bridge.** No coherent git structure
  to write; the marks map gains a second incompatible meaning; publish
  goes permanently stale against the exported artifact; and it hands
  operators a one-command path to durably publishing embargo ciphertext on
  a public host where it is archived beyond any later rewrap. Rejected.
- **Keep `PROTOCOL_VERSION` 3 (ADR-0043's no-bump posture).** The failure
  mode against an old peer is an unknown-tag decode error mid-ingest rather
  than a clean handshake refusal. New object kinds crossing the wire is
  what a protocol version is for (P27 precedent). Rejected.
- **Publish preserving object ids.** Impossible without making sealed ids a
  deterministic function of plaintext — the oracle again. Not a real
  alternative; recorded because the task brief asked the question.

## As built (P34)

The decision shipped as designed; the concrete shape settled as follows.

- **Two additive object kinds, no existing-format change.** `TAG_SEALED` (7)
  is `nonce(24) ‖ AEAD(inner encoding)` under a per-object random DEK;
  `TAG_MANIFEST` (8) carries `base`, `prev` (the superseded manifest — a
  meta-history chain the push ff-check and gc walk over like parents),
  `closure` (sorted sealed-object ids), `index_ct` (the KEK-encrypted
  branch index), and `kek_wraps`. Snapshots/trees/blobs/secrets/signatures
  are byte-for-byte unchanged (`TAG_SNAPSHOT` stays 4); `PROTOCOL_VERSION`
  bumped 3 → 4 so a v3 peer refuses at the handshake rather than hitting an
  unknown tag deep in pack ingest.
- **`crates/crypto/src/private.rs`** owns the three new primitives —
  `seal_object`/`open_object` (per-object DEK, distinct AAD domain from P7
  path blobs so a sealed body can never be opened as a path blob), the branch
  KEK (`generate_kek`/`wrap_kek_for`/`unwrap_kek_with`, reusing the P2
  X25519 envelope), and `BranchIndex` (the `inner id → (sealed id, DEK)` map
  + inner tip, encrypted under the KEK; DEKs zeroize on drop). RustCrypto
  stays quarantined.
- **Copy-on-write sealing.** `crates/repo/src/private.rs` resolves inner
  objects through the index with a public-store fallback: an inner id absent
  from the index is public content read directly, so a private branch forked
  from `main` seals nothing at creation and reseals only what actually
  changes — an unchanged subtree keeps its public id (the tree builder
  matches vfs byte-for-byte, `FileMode(0o755)` on dir entries). Verified by
  `cow_sealing_unchanged_content_is_never_resealed`.
- **Grant is one wrap; revoke is KEK rotation.** `branch_grant` appends one
  KEK wrap (index + closure untouched). `branch_revoke` mints a fresh KEK,
  re-encrypts the index, rewraps for the remaining recipients, and **refuses
  loudly** if any still-wrapped recipient has no known public key (never
  silent access loss) — zero content plaintext, zero sealed-object churn.
- **Publish is two-phase.** Every public object is built in memory and the P5
  scanner runs over all decrypted plain files **before** the first
  `store.put` — a failed publish moves no ref and writes no object
  (`publish_scanner_gate_aborts_before_any_public_write`). Protected-prefix
  files re-seal through the normal P7/P33 path (stay `PROTECTED` in public
  space, `protected_paths_survive_a_private_round_trip`).
- **Refusals are centralized.** `refuse_on_private` guards every
  snapshot-assuming ref-moving op (`commit`/`amend`/`branch`/`protect`/
  `secret *`/`rewrap`/`sparse *`/`ws`/`work`/`transcript attach`/`sign`);
  `PrivateIntegration` refuses merge/cherry-pick/rebase *from* a private ref;
  `commit`/`status`/`diff`/`log`/`merge`/`switch` dispatch to the private
  variant when HEAD is private. `undo` restores manifest refs but skips
  rematerialize (no identity in hand) — the working tree goes stale until
  `sc switch … --identity`.
- **Operator footgun, unchanged from every prior phase:** keep identity
  files **outside** the working tree — a key committed under a private
  branch is sealed into it and vanishes from disk on the next switch (the
  standing [[scanner-false-positive-own-keys]] hazard).
- **Reachability anchors for merged-in public content (review Critical).**
  `merge_into_private` carries the merged public tip's objects into the
  sealed inner tree as **unsealed public references** (copy-on-write — they
  are already public, resealing them would waste space and fight dedup). But
  a keyless party can't walk a sealed tree to discover those references, and
  the manifest's `base` only anchors the *fork point* — so a public object
  added *after* the fork and merged in was reachable through no root a
  transfer or gc could follow. Pushing just the private branch to a peer
  lacking those commits would strand the sealed tree (`NotFound` on the
  recipient's `switch`). Fixed by a cumulative plaintext `anchors: Vec<
  ObjectId>` on the manifest — the merged-in public tips — walked as
  reachability roots alongside `base`. Costs one metadata leak (*which*
  public commits were merged in), the same class as `base` leaking the fork
  point. Pinned by `merged_in_private_branch_is_self_contained_for_transfer`
  (reachability from the manifest alone includes the merged blob) and
  `recipient_opens_a_merged_branch_cloned_without_the_public_source` (a peer
  that never received the public branch still opens the merged private one).

## Deferred (to ROADMAP.md)

- `sc branch publish --squash` (hide intermediate history at publish).
- `--no-escrow` at private-branch creation.
- Slash-names for local branches (independent of access control).
- Manifest scalability beyond hotfix-scale closures.
- Sealing the recipient set and fork point (currently plaintext manifest
  metadata) — would need an anonymous-recipient KEK-wrap scheme.
- `sc branch grant/revoke`-style rotation of the KEK on a schedule, and a
  fetch-time freshness attestation so a stale pre-revoke manifest can't be
  re-served (the gittuf-shaped ref-attestation effort ADR-0032 already
  defers).
