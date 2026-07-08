# P22 — Signed Commits & Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Optional Ed25519 commit signatures as CAS objects, with trust-policy verification and zero-wire-change transfer (spec: `docs/superpowers/specs/2026-07-08-p22-provenance-design.md`, ADR-0032).

**Architecture:** `crates/crypto` gains `signing.rs` (Ed25519, domain-separated over the snapshot id) and a seed-based unified identity v2. `crates/core` gains `Object::Signature` (`TAG_SIGNATURE = 5`, raw bytes only — core stays crypto-free). `crates/repo` gains a gc-rooted `.sc/signatures` index and sign/verify machinery; transfer rides existing packs (sender includes, `LocalTransport::put_pack` indexes — the ssh transport dispatches onto it, so one seam covers both). CLI: keygen v2, `sc sign`, `--sign` flags, log markers, `sc verify`.

**Tech Stack:** Rust stable; `ed25519-dalek` added to `crates/crypto` ONLY (the one justified new dependency; **stage Cargo.lock in the same commit** — established project memory).

## Global Constraints

- Snapshot ids untouched; the signed message is exactly `"sc-snapshot-sig-v1" || id` (32-byte id appended to the ASCII domain string) (spec).
- `crates/core` must NOT depend on crypto — the Signature object holds raw `[u8;32]` signer + `[u8;64]` sig bytes; verification lives in `crates/crypto`, called from repo/cli (CLAUDE.md dependency rule).
- Zero wire-protocol changes: no new Transport verbs, no frame format changes (spec).
- gc: index entries whose SNAPSHOT is unreachable are dropped, un-rooting their signature objects (spec).
- Four distinct verification states — trusted ✓ / valid-but-untrusted ? / INVALID ✗ / unsigned — and INVALID must never render as merely untrusted (spec).
- v1 identity files keep working for encryption; signing with one errors clearly (spec).
- ed25519-dalek stays quarantined in `crates/crypto` (CLAUDE.md).
- Tests next to code; disk tests clean up and assert removal (CLAUDE.md).

---

### Task 1: crypto — Ed25519 signing + unified identity v2 (+ ROADMAP flip)

**Files:**
- Create: `crates/crypto/src/signing.rs`
- Modify: `crates/crypto/src/lib.rs` (module + re-exports), `crates/crypto/src/key.rs` (only if identity parsing lives there — implementer's judgment, state it), `crates/crypto/Cargo.toml` (+ ed25519-dalek; check whether `hkdf`/`sha2` are already deps from the envelope — they are used for DEK wrapping; reuse), `Cargo.lock` (same commit)
- Modify: `ROADMAP.md` (flip P22 to Active; horizon table → P23–P24)

**Interfaces (produced, all re-exported from `scl_crypto`):**

```rust
/// Ed25519 signing half of a v2 identity.
pub struct SigningKey(/* ed25519_dalek::SigningKey */);
/// Ed25519 verifying key; string form `scl-sig-<hex>`.
pub struct SigPublicKey(/* ed25519_dalek::VerifyingKey */);
impl SigPublicKey { pub fn to_key_string(&self) -> String; pub fn from_key_string(&str) -> Result<Self>; pub fn to_bytes(&self) -> [u8;32]; pub fn from_bytes([u8;32]) -> Result<Self>; }

/// A parsed identity file: v1 (`scl-sk-…`, encryption only) or v2
/// (`scl-id-<hex64 seed>`, seed-derived encryption + signing keys).
pub struct Identity { pub enc: SecretKey, pub signing: Option<SigningKey> }
pub fn parse_identity(text: &str) -> Result<Identity>;   // accepts both forms
pub fn generate_identity_v2() -> (String /* scl-id-… */, Identity);

/// Domain-separated snapshot-id signing (spec: "sc-snapshot-sig-v1" || id).
pub fn sign_snapshot_id(key: &SigningKey, id: &[u8; 32]) -> [u8; 64];
pub fn verify_snapshot_sig(signer: &[u8; 32], id: &[u8; 32], sig: &[u8; 64]) -> bool; // false on bad key bytes too
```

Derivation (document in signing.rs's header): v2 seed (32 bytes) → X25519 secret = HKDF-SHA256(seed, info=`"scl-id-v2-enc"`), Ed25519 = HKDF-SHA256(seed, info=`"scl-id-v2-sig"`) — reusing the crate's existing HKDF machinery, distinct info strings.

- [ ] **Step 1: ROADMAP flip** (mirror the P21 flip's shape).
- [ ] **Step 2: Failing tests** (signing.rs in-module; full bodies):

```rust
#[test]
fn sign_verify_round_trip_and_domain_separation() {
    // generate_identity_v2 → sign an id → verify true; verify with a
    // DIFFERENT id false; verify a signature produced over raw id bytes
    // WITHOUT the domain prefix (construct manually via ed25519 sign of
    // the bare id) → false, proving the domain string is load-bearing.
}
#[test]
fn identity_v2_round_trip_and_deterministic_derivation() {
    // scl-id string → parse → both keys present; parse the SAME string
    // twice → identical enc pubkey and sig pubkey (derivation is
    // deterministic); enc key ENCRYPTS interoperably (seal to its pubkey,
    // open with the parsed identity's enc half — reuse envelope tests' idiom).
}
#[test]
fn identity_v1_parses_encryption_only() {
    // existing scl-sk string → Identity { enc, signing: None }; and
    // from_key_string on the SAME string still works unchanged (no
    // regression for every existing caller).
}
#[test]
fn sig_pubkey_string_form_round_trips() { /* scl-sig- prefix, parse errors on bad hex/length */ }
```

- [ ] **Step 3: Implement** (ed25519-dalek dep + module; `parse_identity` dispatching on prefix). **Step 4: Run** `cargo test -p scl-crypto` then `cargo test` → green (nothing else changed). **Step 5: Commit** — `git add -A` (lockfile included) `&& git commit -m "feat(crypto): Ed25519 signing + unified seed-derived identity v2 — scl-id files carry encryption and signing halves (P22)"`

---

### Task 2: core Signature object + repo index, sign/verify machinery, gc

**Files:**
- Modify: `crates/core/src/object.rs` (`TAG_SIGNATURE = 5`, `Object::Signature(SignatureObj)`, encode/decode + round-trip tests; struct is bytes-only)
- Modify: `crates/core/src/lib.rs` (export)
- Create: `crates/repo/src/signatures.rs` (index + machinery)
- Modify: `crates/repo/src/lib.rs`, `crates/repo/src/gc.rs`
- Modify: `crates/repo/src/layout.rs` ONLY if paths are centralized there (check how `.sc/oplog` is pathed; mirror)

**Interfaces:**

```rust
// core:
pub struct SignatureObj { pub snapshot: ObjectId, pub signer: [u8; 32], pub sig: [u8; 64] }
// encode: tag 5, then id, signer, sig (fixed width — no length prefixes needed); decode strict.

// repo::signatures:
pub enum SigStatus { Trusted(String /* signer name */), Untrusted([u8; 32]), Invalid, Unsigned }
impl Repo {
    /// Sign `snapshot` with the identity's signing half: put the Signature
    /// object, append to the index. Idempotent (same signer+snapshot →
    /// same object id → single index entry). Errors on a v1 identity.
    pub fn sign_snapshot(&self, snapshot: ObjectId, identity: &scl_crypto::Identity) -> Result<ObjectId>;
    /// All indexed signatures for a snapshot (loaded objects).
    pub fn signatures_for(&self, snapshot: &ObjectId) -> Result<Vec<scl_core::SignatureObj>>;
    /// Verification status of one snapshot against a trust map
    /// (signer pubkey bytes → display name). Precedence: any INVALID
    /// signature ⇒ Invalid (never masked by a valid one — spec's
    /// four-state rule); else any trusted ⇒ Trusted; else any valid ⇒
    /// Untrusted; else Unsigned.
    pub fn sig_status(&self, snapshot: &ObjectId, trusted: &std::collections::HashMap<[u8;32], String>) -> Result<SigStatus>;
}
pub(crate) fn index_incoming(layout: &Layout, store: &mut Store, ids: &[ObjectId]) -> Result<usize>; // detect TAG_SIGNATURE among ids, index them (Task 3's receiver seam)
pub(crate) fn indexed_signature_ids_for(layout: &Layout, snapshots: &[ObjectId]) -> Result<Vec<ObjectId>>; // Task 3's sender seam
```

Index file `.sc/signatures`: lines `<snapshot-hex> <sig-object-hex>`, append-only with atomic rewrite on gc prune; dedup on append.

- [ ] **Step 1: Failing tests** — core round-trip (encode/decode Signature, strict decode errors on truncation); repo: `sign_is_idempotent_and_indexed`, `sig_status_four_states` (construct: trusted signer, untrusted signer, a Signature object with corrupted sig bytes → Invalid EVEN when a second valid trusted signature exists — precedence pinned), `gc_prunes_signatures_of_dead_snapshots_keeps_live` (mirror gc's state-root test shape: live snapshot's signature survives `gc --prune-expire 0`; orphan a snapshot (undo + oplog trim? simpler: sign a snapshot on a branch, delete the branch ref file directly, gc) → its index entry dropped AND signature object pruned).
- [ ] **Step 2: Implement** (gc: after computing the reachable snapshot set, partition the index; keep+root live entries' signature ids, rewrite the index without dead ones — placement beside the other root collection in `gc.rs::roots`/`run`, matching how reachability output is available there; check the actual structure and state your placement in the report).
- [ ] **Step 3: Run** `cargo test -p scl-core -p scl-repo` then `cargo test` → green. **Step 4: Commit** — `git commit -am "feat(core,repo): TAG_SIGNATURE objects + gc-rooted signature index with four-state verification (P22)"`

---

### Task 3: Transfer — pack riding, receiver indexing, clone reindex, git boundary

**Files:**
- Modify: `crates/repo/src/transport.rs` (`LocalTransport::{get_pack, put_pack}`)
- Modify: `crates/repo/src/sync.rs` (fetch ingestion + local-path clone reindex; find where clone copies objects — `clone_to`/`clone_url`)
- Modify: `crates/gitio/src/export.rs` + `crates/cli/src/main.rs` (`signatures_dropped` counter + warning line, mirroring `secrets_dropped` exactly)

**Interfaces:**
- Consumes Task 2's `index_incoming` / `indexed_signature_ids_for`.
- Sender seam: `get_pack(wants, haves)` walks reachability to assemble the pack — after collecting the object set, extend it with `indexed_signature_ids_for(<snapshot ids in the set>)`. Signatures are leaves (reference nothing the walk needs).
- Receiver seam: `put_pack` returns/knows the ingested ids — call `index_incoming` there. Because `sc serve --stdio` dispatches onto `LocalTransport`, ssh pushes index automatically; fetch's client-side ingestion (sync.rs ~204, after `get_pack` → local put) calls `index_incoming` on the received ids too.
- Clone: the local wholesale-copy path copies signature objects already (they're objects) — rebuild the index post-copy by scanning refs-reachable snapshots... simpler and O(store): scan ALL store objects for TAG_SIGNATURE via the store's iteration mechanism if one exists (check `reachable.rs`/`gc.rs` for how objects are enumerated); index every found signature whose snapshot exists. Wrap as `signatures::reindex(layout, store)` and call it at the end of the local clone path.

- [ ] **Step 1: Failing tests:**

```rust
#[test]
fn signatures_ride_fetch_push_and_clone_local() {
    // Repo A: commit, sign. Push to bare B (or fetch from A into C —
    // exercise BOTH directions): the signature object exists in the
    // receiver's store AND its index lists it; sig_status in the receiver
    // (with A's signer trusted) is Trusted.
}
#[test]
fn signatures_ride_ssh_transport() {
    // The SC_SSH shim pattern (see stdio_transport tests / sync ssh tests
    // — reuse their harness): clone or fetch over ssh:// → signature
    // indexed at the receiver. This proves the put_pack seam covers wire.
}
#[test]
fn export_drops_signatures_with_count() { /* sign, export --to git, report.signatures_dropped == 1, warning printed at CLI (repo-level: assert the report field) */ }
```

- [ ] **Step 2: Implement** the three seams + reindex. **Step 3: Run** targeted + `cargo test` → green (P6/P12/P18 transport tests must be undisturbed). **Step 4: Commit** — `git commit -am "feat(repo,gitio): signatures ride existing packs — sender includes, receivers index, clone reindexes, git export drops with a count (P22)"`

---

### Task 4: CLI — keygen v2, trust config, sign/verify/log

**Files:**
- Modify: `crates/cli/src/main.rs` (keygen output; `load_identity` → returns `Identity` where signing is needed — check every current `load_identity` caller and keep encryption-only callers on `.enc` without behavior change; `[signing]`/`[signers]` parsing in the RecipientsFile struct; new `Sign { r#ref: String, identity: Option<PathBuf> }` and `Verify { r#ref: Option<String>, require: bool }` commands; `--sign` flag on Commit and Amend; log markers)

**Interfaces:**
- Consumes: Tasks 1–2 (`parse_identity`, `Repo::{sign_snapshot, sig_status}`, `SigStatus`).
- Trust map assembly: `[signing]` name → `scl-sig-…` parsed to bytes; `[signers] trusted = [names]` selects which entries populate the map. A name in `trusted` missing from `[signing]` errors clearly.

- [ ] **Step 1: Implement + tests:**
  - `sc keygen` prints the v2 `scl-id-…` line plus BOTH public halves (`scl-pk-…` and `scl-sig-…`) with registration hints (mirror current keygen output shape — read it first).
  - `sc commit --sign` / `sc amend --sign`: after the commit lands, `sign_snapshot(new_tip, &identity)`; a v1 identity errors naming the fix ("identity has no signing key; generate a v2 identity with sc keygen").
  - `sc sign <ref>`: resolve tip, sign, print `signed <short> as <scl-sig prefix>`.
  - `sc log`: per commit, `sig_status` renders — Trusted: `  signed: <name> ✓`; Untrusted: `  signed: <8-hex-prefix>… ?`; Invalid: `  signature INVALID ✗`; Unsigned: no line. JSON mode gains a `"signature"` field with `{"status": "trusted|untrusted|invalid|unsigned", ...}`.
  - `sc verify [<ref>] [--require]`: walk ALL parents from the tip (BFS, dedup — reuse how `reachable`/log walks), print one line per commit + a summary count per state; `--require` exits 1 (drop(repo) first) if any non-Trusted state exists.
  - Tests (cli or repo level as fits): the four log states render distinctly (drive `sig_status` + a render helper unit test rather than string-matching full CLI output where possible); verify --require exit semantics via the repo-level walk function with each state present.
- [ ] **Step 2: Run** `cargo test` → green. **Step 3: Commit** — `git commit -am "feat(cli): keygen v2, [signing]/[signers] trust config, sc sign/verify, --sign flags, four-state log markers (P22)"`

---

### Task 5: Demo + docs

**Files:**
- Create: `demo/run_provenance_demo.sh` (mode 755)
- Modify: `docs/adr/0032-signed-commits-provenance.md` (→ Accepted + build refinements, code-verified — seven phases of precision precedent), `docs/adr/README.md`, `ROADMAP.md` (P22 → Done + table row; Active → Phase 23; horizon P23–P24), `CLAUDE.md` (commands: keygen note, sign/verify/--sign, demo line; a `**Phase 22 is built.**` paragraph INCLUDING the threat-model honesty summary from the spec; follow-ons list unchanged — trust depth already listed)

- [ ] **Step 1: Demo** (house style; separate invocations; case-based assertions): keygen v2 ×2 (alice, bob), register both in `[signing]`, trust ONLY alice; alice commits `--sign` twice; `sc verify --require` green; clone; verify green in clone (signatures traveled); REWRITE ATTACK: in the clone, `sc amend -m "innocent-looking"` → `sc verify --require` exits 1 naming the unsigned tip while the ORIGINAL still verifies; bob retroactively `sc sign`s a commit → log shows `?` until bob joins `[signers]`, then ✓. Zero-residue trap.
- [ ] **Step 2: Docs** (P21-completion commit shape; refinement candidates: where identity parsing landed, the derivation info strings, the clone-reindex mechanism, put_pack-as-single-receiver-seam).
- [ ] **Step 3: Full verification** — `cargo test && bash demo/run_provenance_demo.sh && bash demo/run_ssh_remote_demo.sh && bash demo/run_git_remote_demo.sh && bash demo/run_secret_demo_if_exists` → adjust to `ls demo/`; the ssh + git-remote demos are the transfer-regression gates. `git diff main -- '*Cargo.toml'` shows ONLY the ed25519-dalek addition in crates/crypto (+ lock).
- [ ] **Step 4: Commit** — `git commit -am "docs+demo: accept ADR-0032 signed commits & provenance; rewrite-attack demo (P22)"`
