# P30 — Agent session transcripts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record the agent session (prompts, tool calls, decisions) that produced a change as a sealed, optionally-signed CAS object attached to the snapshot it motivated — intent-deep provenance on top of P22's identity-deep provenance.

**Architecture:** A new bytes-only `TAG_TRANSCRIPT = 6` object mirrors `TAG_SECRET`'s envelope shape plus three metadata fields; a `crates/repo/src/transcripts.rs` module mirrors `signatures.rs` (a gc-rooted `.sc/transcripts` index, over-send transfer, clone reindex). Sealing reuses `scl_crypto::seal`/`open` verbatim; signing reuses P22's `SignatureObj` + `.sc/signatures` index with a new domain. No wire change.

**Tech Stack:** Rust (stable, edition 2021). Reuses `scl_crypto::{seal, open}` (envelope), the P22 signature machinery, and the P22 signatures-module patterns. One additive crypto change (a transcript signing domain). No new dependency.

**Spec:** `docs/superpowers/specs/2026-07-09-p28-session-transcripts-brainstorm.md` (Decisions D1–D7). **ADR:** 0038 (Proposed → Accepted at Task 6).

## Global Constraints

- **NO new dependency.** **NO crypto changes for SEALING** — reuse `scl_crypto::seal(name, plaintext, recipients) -> Secret` and `open(secret, identity) -> Zeroizing<Vec<u8>>` verbatim; `open` ignores the `Secret.name`, so a `Transcript`'s `{nonce, ciphertext, wrapped_keys}` constructs a `Secret { name: String::new(), .. }` to decrypt. **Signing adds ONE domain** (`b"sc-transcript-sig-v1"`) + thin wrappers inside `crates/crypto` only — RustCrypto never crosses the crate boundary; decrypted buffers stay `crypto::Zeroizing`.
- **`crates/core` stays crypto-free.** `TAG_TRANSCRIPT` is a bytes-only object exactly like `TAG_SIGNATURE` — no crypto in core.
- **Content addressing (BLAKE3 canonical) unchanged.** A `Transcript` is a new object kind, not a change to any existing encoding; snapshot ids are untouched.
- **Plaintext NEVER enters the CAS.** The body is sealed before it becomes an object. Positive control (a demo + a test): a keyless clone carries ciphertext only and cannot decrypt.
- **Transfer is ZERO wire change.** Transcripts ride the existing pack; the sender over-sends indexed transcript ids into the transfer want-set (has-gated by the existing pack diff, so a transcript the receiver already holds is never re-shipped), and the receiver reindexes idempotently — adopting the P22 refetch fix from day one. `PROTOCOL_VERSION` untouched.
- **One-to-many, additive, no silent carry** (D4). amend/rebase/merge mint new snapshot ids that start with no transcripts.
- **Seal fixed at attach** (D5): no transcript rewrap/grant/revoke in the MVP.
- **Ships `demo/run_transcript_demo.sh`.** ADR-0038 Proposed → Accepted at Task 6.
- Per-crate `thiserror`; CLI uses `anyhow`; every public type/fn gets a doc comment; tests in `#[cfg(test)] mod tests`. Use `r.count()` (the P28 DoS guard) for every decode length prefix.

**DEFERRED — name in the docs, do NOT build:** `--transcript auto` probing (MVP = explicit `<path>`), `sc transcript drop` + resurrection tombstone, transcript access lifecycle (rewrap/grant/revoke), a `--no-transcripts` transfer knob, `sc export --transcripts=entire`, per-turn live checkpointing.

---

### Task 1: Core `TAG_TRANSCRIPT` object

**Files:**
- Modify: `crates/core/src/object.rs` (add `Transcript` struct, `Object::Transcript` variant, `TAG_TRANSCRIPT = 6`, encode + decode)
- Modify: `crates/core/src/lib.rs` (re-export `Transcript` alongside `Secret`, `SignatureObj`)

**Interfaces:**
- Consumes: the existing `Writer`/`Reader` codec (`Writer::{tag,id,str,bytes,u32}`, `Reader::{id,str,bytes,count,u8}`), `WrappedKey`.
- Produces: `pub struct Transcript { pub snapshot: ObjectId, pub agent: String, pub session: String, pub nonce: Vec<u8>, pub ciphertext: Vec<u8>, pub wrapped_keys: Vec<WrappedKey> }`; `Object::Transcript(Transcript)`; `const TAG_TRANSCRIPT: u8 = 6`.

- [ ] **Step 1: Write the failing test** (`crates/core/src/object.rs` `#[cfg(test)] mod tests`):

```rust
#[test]
fn transcript_round_trips_and_id_is_stable() {
    let t = Transcript {
        snapshot: ObjectId::of(b"snap"),
        agent: "claude-code".into(),
        session: "sess-42".into(),
        nonce: vec![1, 2, 3],
        ciphertext: vec![9, 8, 7, 6],
        wrapped_keys: vec![WrappedKey { recipient_id: "rid".into(), wrapped_dek: vec![4, 5] }],
    };
    let obj = Object::Transcript(t.clone());
    let bytes = obj.encode();
    let back = Object::decode(&bytes).unwrap();
    assert_eq!(back, obj);
    // id-stability: same content encodes byte-identically → same id.
    assert_eq!(ObjectId::of(&bytes), ObjectId::of(&Object::Transcript(t).encode()));
}

#[test]
fn transcript_decode_rejects_fabricated_wrap_count() {
    // TAG_TRANSCRIPT(6) + snapshot(32) + agent str(0) + session str(0)
    // + nonce bytes(0) + ciphertext bytes(0) + wrap-count = 0xFFFF_FFFF, no wraps.
    let mut buf = vec![6u8];
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&0u32.to_be_bytes()); // agent len
    buf.extend_from_slice(&0u32.to_be_bytes()); // session len
    buf.extend_from_slice(&0u32.to_be_bytes()); // nonce len
    buf.extend_from_slice(&0u32.to_be_bytes()); // ciphertext len
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // wrap count
    assert!(matches!(Object::decode(&buf), Err(Error::Malformed(_))));
}
```

- [ ] **Step 2: Run to confirm failure** — `cargo test -p scl-core transcript_round_trips` → FAIL (`Transcript` undefined).

- [ ] **Step 3: Add the struct + tag + variant.** Near `TAG_SIGNATURE: u8 = 5` add `const TAG_TRANSCRIPT: u8 = 6;`. Near `pub struct Secret` add:

```rust
/// A sealed agent-session transcript (P30): the session that motivated
/// `snapshot`, encrypted like a `Secret` (fresh random DEK, wrapped per
/// recipient) so plaintext never enters the CAS. `agent`/`session` are
/// opaque metadata labels; the body is opaque bytes (no schema).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub snapshot: ObjectId,
    pub agent: String,
    pub session: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub wrapped_keys: Vec<WrappedKey>,
}
```

Add `Transcript(Transcript)` to the `pub enum Object { … }` (beside `Signature(SignatureObj)`).

- [ ] **Step 4: Add encode + decode.** In `Object::encode`'s match, beside the `Object::Signature` arm, add (mirroring `TAG_SECRET`'s encode — confirm the exact Writer method names by reading the `Secret` encode arm):

```rust
Object::Transcript(t) => {
    w.tag(TAG_TRANSCRIPT);
    w.id(&t.snapshot);
    w.str(&t.agent);
    w.str(&t.session);
    w.bytes(&t.nonce);
    w.bytes(&t.ciphertext);
    w.u32(t.wrapped_keys.len() as u32);
    for wk in &t.wrapped_keys {
        w.str(&wk.recipient_id);
        w.bytes(&wk.wrapped_dek);
    }
}
```

In `Object::decode`'s match, beside `TAG_SIGNATURE`, add:

```rust
TAG_TRANSCRIPT => {
    let snapshot = r.id()?;
    let agent = r.str()?;
    let session = r.str()?;
    let nonce = r.bytes()?;
    let ciphertext = r.bytes()?;
    let nk = r.count()?;
    let mut wrapped_keys = Vec::with_capacity(nk);
    for _ in 0..nk {
        let recipient_id = r.str()?;
        let wrapped_dek = r.bytes()?;
        wrapped_keys.push(WrappedKey { recipient_id, wrapped_dek });
    }
    Object::Transcript(Transcript { snapshot, agent, session, nonce, ciphertext, wrapped_keys })
}
```

(Match the exact `Writer`/`Reader` method spellings from the neighboring `Secret` arms — if the codec uses `w.bytes`/`r.bytes` for length-prefixed byte fields and `w.str`/`r.str` for strings, as `Secret` does, the above is correct verbatim.)

- [ ] **Step 5: Re-export** in `crates/core/src/lib.rs`: add `Transcript` to the `pub use object::{… Secret, SignatureObj, Transcript, …}` list.

- [ ] **Step 6: Run to confirm pass** — `cargo test -p scl-core transcript` → PASS (both tests), then `cargo test -p scl-core` → all green.

- [ ] **Step 7: Commit**

```bash
git add crates/core/src/object.rs crates/core/src/lib.rs
git commit -m "feat(core): TAG_TRANSCRIPT bytes-only object (sealed session transcript) (P30 t1)"
```

---

### Task 2: Repo `transcripts` module — seal, attach, `.sc/transcripts` index

**Files:**
- Create: `crates/repo/src/transcripts.rs`
- Modify: `crates/repo/src/lib.rs` (`pub mod transcripts;`)
- Modify: `crates/repo/src/layout.rs` (add `transcripts_path`)

**Interfaces:**
- Consumes: `scl_crypto::seal`, `scl_core::{Object, Transcript, ObjectId, Secret}`, `crate::scanner`, `crate::layout::Layout`, `Repo::store_arc`, the `Secret` fields.
- Produces: `Layout::transcripts_path`; module fns `load(&Layout) -> Result<Vec<(ObjectId /*snapshot*/, ObjectId /*transcript*/)>>`, `gc_prune(&Layout, &mut BTreeSet<ObjectId>) -> Result<usize>`, `index_incoming(&Layout, &mut Store, &[ObjectId]) -> Result<usize>`, `reindex(&Layout, &mut Store) -> Result<usize>`, `indexed_transcript_ids_for(&Layout, &[ObjectId]) -> Result<Vec<ObjectId>>`; `Repo::attach_transcript(&self, snapshot: ObjectId, agent: &str, session: &str, body: &[u8], recipients: &[scl_crypto::PublicKey]) -> Result<ObjectId>` and `Repo::transcripts_for(&self, snapshot: &ObjectId) -> Result<Vec<(ObjectId, Transcript)>>`.

- [ ] **Step 1: Add `Layout::transcripts_path`** (beside `signatures_path`):

```rust
/// `.sc/transcripts` — the append-only snapshot→transcript index (P30),
/// one `<snapshot-hex> <transcript-hex>` line per attachment (one-to-many).
pub fn transcripts_path(&self) -> std::path::PathBuf {
    self.dot_sc.join("transcripts")
}
```

- [ ] **Step 2: Write the failing tests** (`crates/repo/src/transcripts.rs` `#[cfg(test)] mod tests`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    #[test]
    fn attach_seals_body_and_plaintext_never_in_cas() {
        let root = tmp_root("attach");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let snap = repo.commit("t", "c1").unwrap();
        let (_sk_str, id) = scl_crypto::generate_identity_v2();
        let pk = id.enc.public();

        let body = b"USER: fix the bug\nAGENT: done";
        let tid = repo.attach_transcript(snap, "claude-code", "s1", body, &[pk]).unwrap();

        // Indexed one-to-many under the snapshot.
        let idx = load(repo.layout()).unwrap();
        assert!(idx.iter().any(|(s, t)| *s == snap && *t == tid));

        // The stored object is a Transcript whose ciphertext != plaintext, and
        // the plaintext appears in NO object in the store (sealed, never in CAS).
        let arc = repo.store_arc();
        let mut store = arc.lock().unwrap();
        match store.get(&tid).unwrap() {
            scl_core::Object::Transcript(t) => {
                assert_eq!(t.snapshot, snap);
                assert_ne!(t.ciphertext.as_slice(), body);
                assert!(!t.wrapped_keys.is_empty());
            }
            _ => panic!("not a transcript"),
        }
    }

    #[test]
    fn gc_prunes_transcripts_of_dead_snapshots() {
        // A transcript whose snapshot is NOT in `reachable` is dropped from the
        // index and its id is NOT rooted; a live one is kept and rooted.
        let root = tmp_root("gc");
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let live = repo.commit("t", "c1").unwrap();
        let (_s, id) = scl_crypto::generate_identity_v2();
        let t_live = repo.attach_transcript(live, "a", "s", b"body", &[id.enc.public()]).unwrap();
        let dead = ObjectId::of(b"dead-snap");
        // hand-insert a dead-snapshot index line:
        append_index(repo.layout(), dead, ObjectId::of(b"dead-transcript")).unwrap();

        let mut reachable: std::collections::BTreeSet<ObjectId> = [live].into_iter().collect();
        let dropped = gc_prune(repo.layout(), &mut reachable).unwrap();
        assert_eq!(dropped, 1, "the dead-snapshot entry is dropped");
        assert!(reachable.contains(&t_live), "the live transcript id is rooted");
        assert!(load(repo.layout()).unwrap().iter().all(|(s, _)| *s == live));
    }
}
```

Add a `tmp_root(tag)` helper mirroring `signatures.rs`'s test helper (`std::env::temp_dir().join(...)` + `create_dir_all`), and note `append_index` is a module fn you implement in Step 3.

- [ ] **Step 3: Run to confirm failure** — `cargo test -p scl-repo transcripts` → FAIL (module undefined).

- [ ] **Step 4: Implement the module.** Read `crates/repo/src/signatures.rs` first and mirror its `parse_line`/`read_index`/`write_index`/`append_index`/`gc_prune`/`index_incoming`/`reindex`/`indexed_signature_ids_for` — they are `<hex> <hex>` line CRUD keyed by the object's `snapshot` field. The ONLY differences: the file is `layout.transcripts_path()`, the matched object kind is `Object::Transcript` (not `Signature`), and `index_incoming`/`reindex` key by `transcript.snapshot`. Then add the seal + attach on `Repo`:

```rust
//! Session transcripts (P30 provenance): the repo-side `.sc/transcripts`
//! index over core's bytes-only `Transcript`, plus sealing/attachment.
//! `crates/core` stays crypto-free — a `Transcript` is raw bytes; this module
//! is the only place it meets `scl_crypto` (sealing the body, opening it in
//! Task 3). Mirrors `signatures.rs`'s index discipline verbatim.

use std::collections::BTreeSet;
use scl_core::{Object, ObjectId, Secret, Transcript};
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::repo::Repo;

// --- index CRUD: mirror signatures.rs (parse_line/read_index/write_index/
//     append_index) against layout.transcripts_path(). ---
//  fn parse_line(&str) -> Option<(ObjectId, ObjectId)>            (verbatim)
//  fn read_index(&Layout) -> Result<Vec<(ObjectId, ObjectId)>>   (transcripts_path)
//  fn write_index(&Layout, &[(ObjectId,ObjectId)]) -> Result<()> (atomic_write_durable)
//  fn append_index(&Layout, ObjectId, ObjectId) -> Result<()>    (dedup identical)

/// Public snapshot→transcript index (one-to-many), for lookup/tests.
pub fn load(layout: &Layout) -> Result<Vec<(ObjectId, ObjectId)>> {
    read_index(layout)
}

/// gc: keep only index entries whose snapshot is reachable, ROOT each surviving
/// transcript id into `reachable` (so the repack keeps it AND — since transcript
/// signatures live in `.sc/signatures` keyed by the transcript id —
/// `signatures::gc_prune` run AFTER this sees the transcript id as reachable and
/// keeps its signature). Returns dropped count. Identical in shape to
/// `signatures::gc_prune`; the rooting of the transcript id is what makes the
/// ORDERING (transcripts before signatures in gc::run) load-bearing.
pub(crate) fn gc_prune(layout: &Layout, reachable: &mut BTreeSet<ObjectId>) -> Result<usize> {
    let entries = read_index(layout)?;
    if entries.is_empty() { return Ok(0); }
    let mut kept = Vec::with_capacity(entries.len());
    for (snap, tid) in &entries {
        if reachable.contains(snap) {
            reachable.insert(*tid);
            kept.push((*snap, *tid));
        }
    }
    let dropped = entries.len() - kept.len();
    if dropped > 0 { write_index(layout, &kept)?; }
    Ok(dropped)
}

/// Receiver seam: index any `Transcript` objects among ids just written (keys by
/// `t.snapshot`). Mirror `signatures::index_incoming` — NotFound is a hard error
/// (same "ids just written" contract).
pub(crate) fn index_incoming(layout: &Layout, store: &mut scl_core::Store, ids: &[ObjectId]) -> Result<usize> {
    let mut count = 0;
    for id in ids {
        if let Object::Transcript(t) = store.get(id)? {
            append_index(layout, t.snapshot, *id)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Full-store rebuild (clone path): scan all ids, index every `Transcript`
/// whose `snapshot` also resolves locally. Mirror `signatures::reindex`.
pub(crate) fn reindex(layout: &Layout, store: &mut scl_core::Store) -> Result<usize> {
    let mut entries = Vec::new();
    for id in store.all_ids()? {
        if let Object::Transcript(t) = store.get(&id)? {
            if store.get(&t.snapshot).is_ok() {
                entries.push((t.snapshot, id));
            }
        }
    }
    let n = entries.len();
    write_index(layout, &entries)?;
    Ok(n)
}

/// Over-send want-set helper (transfer): every indexed transcript id for the
/// transferred snapshots. Mirror `signatures::indexed_signature_ids_for`.
pub(crate) fn indexed_transcript_ids_for(layout: &Layout, snapshots: &[ObjectId]) -> Result<Vec<ObjectId>> {
    let wanted: BTreeSet<ObjectId> = snapshots.iter().copied().collect();
    let mut out: BTreeSet<ObjectId> = BTreeSet::new();
    for (snap, tid) in read_index(layout)? {
        if wanted.contains(&snap) { out.insert(tid); }
    }
    Ok(out.into_iter().collect())
}

impl Repo {
    /// Seal `body` for `recipients` and attach it as a `Transcript` to
    /// `snapshot`: the body is scanned by the P5 scanner (warn-only — the body
    /// is sealed, and refusing to record would destroy provenance), sealed via
    /// `scl_crypto::seal` (plaintext never enters the CAS), stored, and indexed.
    /// Returns the transcript object id. Errors if `recipients` is empty
    /// (`secrets::require_recipients` — an unreadable transcript is a footgun).
    pub fn attach_transcript(
        &self,
        snapshot: ObjectId,
        agent: &str,
        session: &str,
        body: &[u8],
        recipients: &[scl_crypto::PublicKey],
    ) -> Result<ObjectId> {
        crate::secrets::require_recipients(recipients)?;
        // P5 scan-and-WARN (never reject): reuse the scanner over the plaintext.
        for finding in crate::scanner::scan_bytes(body) {
            eprintln!(
                "warning: transcript body matched the secret scanner ({finding}); it is \
                 sealed, so this is recorded — rotate any real secret it exposes"
            );
        }
        let sealed = scl_crypto::seal(session, body, recipients); // Secret{name,nonce,ciphertext,wrapped_keys}
        let transcript = Transcript {
            snapshot,
            agent: agent.to_string(),
            session: session.to_string(),
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            wrapped_keys: sealed.wrapped_keys,
        };
        let id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Transcript(transcript))?;
            i
        };
        append_index(self.layout(), snapshot, id)?;
        Ok(id)
    }

    /// All indexed transcripts for `snapshot`, loaded from the CAS (id + object).
    pub fn transcripts_for(&self, snapshot: &ObjectId) -> Result<Vec<(ObjectId, Transcript)>> {
        let entries = read_index(self.layout())?;
        let arc = self.store_arc();
        let mut store = arc.lock().unwrap();
        let mut out = Vec::new();
        for (snap, tid) in entries {
            if snap != *snapshot { continue; }
            match store.get(&tid)? {
                Object::Transcript(t) => out.push((tid, t)),
                _ => return Err(Error::InvalidArgument(format!(
                    "transcript index entry {tid} does not resolve to a transcript object"))),
            }
        }
        Ok(out)
    }
}
```

Confirm `crate::scanner` exposes a byte-scanning entrypoint; if the P5 scanner's public API is `scan(path)`/a different name, adapt to a bytes-in → findings-out call (read `crates/repo/src/scanner.rs` for the exact signature) — the warn-loop is the requirement, not the exact fn name. Confirm `secrets::require_recipients` exists (it does — see the seal-empty-recipient guard). Register `pub mod transcripts;` in `crates/repo/src/lib.rs`.

- [ ] **Step 5: Run to confirm pass** — `cargo test -p scl-repo transcripts` → PASS, then `cargo test -p scl-repo` → green.

- [ ] **Step 6: Commit**

```bash
git add crates/repo/src/transcripts.rs crates/repo/src/lib.rs crates/repo/src/layout.rs
git commit -m "feat(repo): transcripts module — seal+attach + .sc/transcripts one-to-many index (P30 t2)"
```

---

### Task 3: Decrypt (show) + opt-in signing

**Files:**
- Modify: `crates/crypto/src/signing.rs` (add `TRANSCRIPT_SIG_DOMAIN` + `sign_transcript_id`/`verify_transcript_sig`, factoring the shared body out of `sign_snapshot_id`/`verify_snapshot_sig`)
- Modify: `crates/crypto/src/lib.rs` (re-export the two new fns)
- Modify: `crates/repo/src/transcripts.rs` (add `Repo::open_transcript`, `Repo::sign_transcript`, `Repo::transcript_sig_status`)

**Interfaces:**
- Consumes: `scl_crypto::{sign_transcript_id, verify_transcript_sig, open}`, `Secret`, `SignatureObj`, the shared `.sc/signatures` index (`crate::signatures::append_index`-equivalent — expose what's needed or re-append inline).
- Produces: `scl_crypto::sign_transcript_id(&SigningKey, &[u8;32]) -> [u8;64]`, `verify_transcript_sig(&[u8;32], &[u8;32], &[u8;64]) -> bool`; `Repo::open_transcript(&self, tid: &ObjectId, identity: &scl_crypto::SecretKey) -> Result<crypto::Zeroizing<Vec<u8>>>`; `Repo::sign_transcript(&self, tid: ObjectId, identity: &scl_crypto::Identity) -> Result<ObjectId>`; `Repo::transcript_sig_status(&self, tid: &ObjectId, trusted: &HashMap<[u8;32], String>) -> Result<SigStatus>`.

- [ ] **Step 1: Write the failing tests** (`crates/crypto/src/signing.rs` tests + `crates/repo/src/transcripts.rs` tests):

```rust
// crates/crypto/src/signing.rs tests:
#[test]
fn transcript_domain_is_separated_from_snapshot_domain() {
    let (_s, id) = generate_identity_v2();
    let sk = id.signing.as_ref().unwrap();
    let idb = [7u8; 32];
    let tsig = sign_transcript_id(sk, &idb);
    // A transcript signature verifies under the transcript domain,
    assert!(verify_transcript_sig(&sk.public().to_bytes(), &idb, &tsig));
    // but NOT under the snapshot domain (domain separation).
    assert!(!verify_snapshot_sig(&sk.public().to_bytes(), &idb, &tsig));
}
```

```rust
// crates/repo/src/transcripts.rs tests:
#[test]
fn open_recovers_body_and_sign_status_is_trusted() {
    let root = tmp_root("open");
    let repo = Repo::init(&root).unwrap();
    std::fs::write(root.join("f"), b"x").unwrap();
    let snap = repo.commit("t", "c1").unwrap();
    let (_s, id) = scl_crypto::generate_identity_v2();
    let body = b"USER: hi\nAGENT: hello";
    let tid = repo.attach_transcript(snap, "a", "s", body, &[id.enc.public()]).unwrap();

    // decrypt round-trips
    let got = repo.open_transcript(&tid, &id.enc).unwrap();
    assert_eq!(got.as_slice(), body);

    // sign + verify four-state
    repo.sign_transcript(tid, &id).unwrap();
    let mut trusted = std::collections::HashMap::new();
    trusted.insert(id.signing.as_ref().unwrap().public().to_bytes(), "me".to_string());
    assert_eq!(repo.transcript_sig_status(&tid, &trusted).unwrap(), crate::signatures::SigStatus::Trusted("me".into()));
}
```

- [ ] **Step 2: Run to confirm failure** — `cargo test -p scl-crypto transcript_domain` and `cargo test -p scl-repo open_recovers_body` → FAIL.

- [ ] **Step 3: Crypto — add the transcript signing domain.** In `crates/crypto/src/signing.rs`, factor the shared message-build out and add the transcript domain. Find `const SIG_DOMAIN: &[u8] = b"sc-snapshot-sig-v1";` and add beside it `const TRANSCRIPT_SIG_DOMAIN: &[u8] = b"sc-transcript-sig-v1";`. Refactor:

```rust
fn sign_id(domain: &[u8], key: &SigningKey, id: &[u8; 32]) -> [u8; 64] {
    let mut message = Vec::with_capacity(domain.len() + id.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(id);
    key.0.sign(&message).to_bytes()
}
fn verify_id(domain: &[u8], signer: &[u8; 32], id: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(signer) else { return false; };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    let mut message = Vec::with_capacity(domain.len() + id.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(id);
    vk.verify_strict(&message, &signature).is_ok()
}

pub fn sign_snapshot_id(key: &SigningKey, id: &[u8; 32]) -> [u8; 64] { sign_id(SIG_DOMAIN, key, id) }
pub fn verify_snapshot_sig(signer: &[u8; 32], id: &[u8; 32], sig: &[u8; 64]) -> bool { verify_id(SIG_DOMAIN, signer, id, sig) }
/// Sign a transcript id under the domain-separated message `"sc-transcript-sig-v1" || id`.
pub fn sign_transcript_id(key: &SigningKey, id: &[u8; 32]) -> [u8; 64] { sign_id(TRANSCRIPT_SIG_DOMAIN, key, id) }
/// Verify a transcript-id signature under its domain.
pub fn verify_transcript_sig(signer: &[u8; 32], id: &[u8; 32], sig: &[u8; 64]) -> bool { verify_id(TRANSCRIPT_SIG_DOMAIN, signer, id, sig) }
```

Re-export `sign_transcript_id`/`verify_transcript_sig` from `crates/crypto/src/lib.rs` beside `sign_snapshot_id`/`verify_snapshot_sig`.

- [ ] **Step 4: Repo — open, sign, verify.** In `crates/repo/src/transcripts.rs` `impl Repo`, add:

```rust
/// Decrypt a transcript's body with `identity`. Constructs a `Secret` from the
/// transcript's envelope fields (the `name` is irrelevant to `open`) and reuses
/// `scl_crypto::open` — zero new crypto. Returns a `Zeroizing` buffer.
pub fn open_transcript(&self, tid: &ObjectId, identity: &scl_crypto::SecretKey) -> Result<scl_crypto::Zeroizing<Vec<u8>>> {
    let obj = { let arc = self.store_arc(); let o = arc.lock().unwrap().get(tid)?; o };
    let t = match obj {
        Object::Transcript(t) => t,
        _ => return Err(Error::InvalidArgument(format!("{tid} is not a transcript"))),
    };
    let secret = Secret { name: String::new(), nonce: t.nonce, ciphertext: t.ciphertext, wrapped_keys: t.wrapped_keys };
    Ok(scl_crypto::open(&secret, identity)?)
}

/// Sign a transcript id under the transcript domain; store the `SignatureObj`
/// and index it in `.sc/signatures` (SHARED with snapshot signatures, keyed by
/// the signed target id — a transcript id here). Idempotent (deterministic Ed25519).
pub fn sign_transcript(&self, tid: ObjectId, identity: &scl_crypto::Identity) -> Result<ObjectId> {
    let signing = identity.signing.as_ref().ok_or_else(|| Error::InvalidArgument(
        "identity has no signing half (v1 identity); signing requires a v2 (scl-id-) identity".into()))?;
    let sig = scl_crypto::sign_transcript_id(signing, tid.as_bytes());
    let sig_obj = scl_core::SignatureObj { snapshot: tid, signer: signing.public().to_bytes(), sig };
    let id = { let arc = self.store_arc(); let i = arc.lock().unwrap().put(Object::Signature(sig_obj))?; i };
    crate::signatures::append_index(self.layout(), tid, id)?; // shared .sc/signatures index
    Ok(id)
}

/// Four-state verification of a transcript's signatures — mirrors
/// `Repo::sig_status` but verifies under the TRANSCRIPT domain
/// (`verify_transcript_sig`). Reuses `SigStatus`.
pub fn transcript_sig_status(&self, tid: &ObjectId, trusted: &std::collections::HashMap<[u8; 32], String>) -> Result<crate::signatures::SigStatus> {
    // Read the shared .sc/signatures index for entries keyed by this transcript id,
    // load each SignatureObj, and apply the SAME precedence as sig_status but with
    // verify_transcript_sig. (Extract a shared helper from sig_status taking a
    // verify fn pointer if you prefer — but do NOT change snapshot verification.)
    // ... mirror sig_status's loop, calling scl_crypto::verify_transcript_sig(&s.signer, tid.as_bytes(), &s.sig) ...
}
```

For `transcript_sig_status`, either expose a `pub(crate) fn signatures_indexed_for(layout, target) -> Vec<ObjectId>` from `signatures.rs` or read the shared index the same way `signatures_for` does; then apply the four-state precedence (any invalid → `Invalid`; else trusted signer → `Trusted`; else `Untrusted`; none → `Unsigned`) with `verify_transcript_sig`. `crate::signatures::append_index` and `SigStatus` must be reachable — make `append_index` `pub(crate)` if it isn't. Confirm `scl_crypto::Zeroizing` is re-exported (it is, since P15).

- [ ] **Step 5: Run to confirm pass** — `cargo test -p scl-crypto transcript_domain` + `cargo test -p scl-repo "open_recovers_body|transcripts"` → PASS, then full `cargo test` green.

- [ ] **Step 6: Commit**

```bash
git add crates/crypto/src/signing.rs crates/crypto/src/lib.rs crates/repo/src/transcripts.rs
git commit -m "feat(crypto,repo): transcript decrypt (reuse open) + opt-in signing (sc-transcript-sig-v1 domain) (P30 t3)"
```

---

### Task 4: Transfer over-send + gc rooting + git-export drop count

**Files:**
- Modify: `crates/repo/src/transport.rs` (over-send indexed transcript ids into the want-set; `index_incoming` on receipt)
- Modify: `crates/repo/src/sync.rs` (clone/fetch reindex path — call `transcripts::reindex`/`index_incoming` beside signatures)
- Modify: `crates/repo/src/gc.rs` (call `transcripts::gc_prune` BEFORE `signatures::gc_prune`)
- Modify: `crates/gitio/src/export.rs` + its repo/cli caller (a `transcripts_dropped` count)

**Interfaces:**
- Consumes: `transcripts::{indexed_transcript_ids_for, index_incoming, reindex, gc_prune}` (Task 2).
- Produces: transcripts travel on the pack; `ExportReport.transcripts_dropped` (or the count surfaced where export is driven).

- [ ] **Step 1: Write the failing test** (`crates/repo/src/sync.rs` or the transport test module — model on the P22 signature-transfer test): a repo attaches a transcript to a snapshot, clones over the in-process wire harness, and the CLONE has the transcript object AND a `.sc/transcripts` index entry; a KEYLESS clone (no identity) still gets the ciphertext object but cannot `open_transcript`. Plus a refetch-propagation test (a transcript attached AFTER an earlier fetch arrives on a later fetch — the P22 fix).

```rust
#[test]
fn transcript_rides_the_pack_and_keyless_clone_gets_ciphertext_only() {
    // origin: commit + attach a transcript sealed to `id`.
    // clone origin -> dst over the wire harness (see clone_over_wire test sibling).
    // assert dst store has the transcript object and load(dst.layout()) indexes it.
    // assert a DIFFERENT identity id2 cannot open it (NotARecipient), but the
    // original id can open it in dst (proving ciphertext rode intact).
}
```

- [ ] **Step 2: Run to confirm failure** — FAIL (transcript not transferred).

- [ ] **Step 3: Over-send on the sender.** In `crates/repo/src/transport.rs`, beside the existing `want_set.extend(crate::signatures::indexed_signature_ids_for(&self.layout, &all_snaps)?);` (~line 152), add:

```rust
        want_set.extend(crate::transcripts::indexed_transcript_ids_for(&self.layout, &all_snaps)?);
```

- [ ] **Step 4: Index on the receiver.** Beside the receiver's `crate::signatures::index_incoming(layout, store, &ids)?;` (~transport.rs:300 / the `put_pack` ingest seam), add `crate::transcripts::index_incoming(layout, store, &ids)?;`. In `crates/repo/src/sync.rs`'s clone path, beside `signatures::reindex(...)`, add `transcripts::reindex(...)`.

- [ ] **Step 5: gc ordering.** In `crates/repo/src/gc.rs`, add `stats.transcripts_pruned = transcripts::gc_prune(layout, &mut reachable)?;` **BEFORE** the `signatures::gc_prune(layout, &mut reachable)?;` line — the ordering is load-bearing: `transcripts::gc_prune` roots live transcript ids into `reachable`, so `signatures::gc_prune` (run after) sees a transcript's id as reachable and keeps that transcript's signature. Add a `transcripts_pruned` field to the gc stats struct (mirror `signatures_pruned`). Add a test asserting a signed transcript on a LIVE snapshot survives gc (object + index + its signature all kept), and a transcript on a gc'd-away snapshot is pruned.

- [ ] **Step 6: git export drop count.** Add `transcripts_dropped: usize` to `ExportReport` (`crates/gitio/src/export.rs:317`, beside `signatures_dropped`). **Seam note:** `gitio` must NOT link `repo` (dependency rule). If `export.rs` already counts signatures by scanning the store it walks, add a `count_transcripts(store, &seen_snaps)` beside `count_signatures` (it only needs `Object::Transcript` matching, which is core, not repo — fine). If instead the transcript count is more naturally produced by the repo/CLI that drives export (because the `.sc/transcripts` index is a repo concern), surface it there and have the CLI print it. Pick the seam that keeps `gitio` repo-agnostic; the requirement is that `sc export` reports how many transcripts were dropped (they are never Git-representable), mirroring the signatures-dropped line. Add/extend a test.

- [ ] **Step 7: Run to confirm pass** — `cargo test -p scl-repo "transcript_rides|gc"` + `cargo test -p scl-gitio` + full `cargo test` → green.

- [ ] **Step 8: Commit**

```bash
git add crates/repo/src/transport.rs crates/repo/src/sync.rs crates/repo/src/gc.rs crates/gitio/src/export.rs
git commit -m "feat(repo,gitio): transcripts ride the pack (over-send+reindex), gc rooting ordered before signatures, export drop-count (P30 t4)"
```

---

### Task 5: CLI surface — `sc transcript`, `sc ws harvest --transcript`, `sc log` marker

**Files:**
- Modify: `crates/cli/src/main.rs` (a `Transcript` command group, `--transcript`/`--sign` on `ws harvest`, the `sc log` marker)
- Modify: `crates/repo/src/ws.rs` (thread `--transcript`/`--sign` into `ws_harvest`)

**Interfaces:**
- Consumes: `Repo::{attach_transcript, open_transcript, sign_transcript, transcripts_for, transcript_sig_status}` (Tasks 2–3), `load_recipients`/`load_escrows`/`append_escrow` (the `[transcripts]` recipient set = full recipients + escrow), `load_identity`.
- Produces: `sc transcript attach <ref> <file> [--agent <name>] [--sign] [--identity <key>]`, `sc transcript show <ref> [--identity <key>]`, `sc transcript list [<ref>] [--json]`, `sc transcript sign <ref> [--identity <key>]`; `sc ws harvest --transcript <path> [--sign] [--identity <key>]`; a `sc log` presence marker.

- [ ] **Step 1: Write a failing CLI smoke test** (`crates/cli/tests/` — model on an existing CLI integration test): `sc init`; commit; `sc transcript attach <tip> <file> --agent claude --sign --identity <id>`; `sc transcript list` shows the tip with a transcript; `sc transcript show <tip> --identity <id>` prints the body; `sc log` shows a transcript marker on that commit.

- [ ] **Step 2: Run to confirm failure** — FAIL (subcommand missing).

- [ ] **Step 3: Add the `Transcript` command + `TranscriptOp`** (mirror the P22 sign/verify CLI + the `Secret`/`Protect` command shapes). The `[transcripts]` recipient set for `attach`/`ws harvest --transcript`: resolve ALL recipients from `recipients.toml` (the full `[recipients]` value set) + `append_escrow` — a helper `fn transcript_recipients(recipients_path) -> Result<Vec<PublicKey>>` = every recipient pubkey + escrow. `attach` reads the file bytes, resolves a ref → its tip snapshot (reuse the ref-resolution the sign/log commands use), calls `repo.attach_transcript(tip, agent, session_label, &body, &recips)`, then if `--sign` calls `repo.sign_transcript(tid, &identity)`. `show` resolves the ref → `transcripts_for(tip)` → `open_transcript(tid, &identity)` for each, printing the plaintext (gated on `--identity`). `list` prints `snapshot → [transcript ids, agent, sig-status]`; `--json` structured. `sign` resolves ref → its transcript(s) → `sign_transcript`. Use a `session` label: default to the file basename or a timestamp-free constant (no `Date::now` in core, but the CLI may use wall-clock — keep it simple: default `session = <file basename>` unless a `--session` is given; do NOT add a flag beyond the brief unless needed).

- [ ] **Step 4: `ws harvest --transcript`.** Thread an optional `transcript: Option<PathBuf>` + `sign: bool` through `Repo::ws_harvest`; after a workspace lands its snapshot, if `--transcript` is set, read the file and `attach_transcript(landed_snapshot, agent="sc-ws", session=<workspace label>, &body, &recips)` (+ `sign_transcript` if `--sign`). Keep it minimal — one transcript attached to the harvested snapshot.

- [ ] **Step 5: `sc log` marker.** In `run_log`, precompute transcript presence for the WHOLE history before printing (the P22 pipe-safety discipline — one index read, not a per-commit CAS hit), and render a per-commit marker (e.g. `transcript: <n> [signed ✓]` when present, nothing when absent) beside the existing signature marker. Do NOT decrypt on the log path.

- [ ] **Step 6: Run to confirm pass** — `cargo test -p scl-cli <the new test>` (solo) + `cargo test -p scl-repo` → green.

- [ ] **Step 7: Commit**

```bash
git add crates/cli/src/main.rs crates/repo/src/ws.rs
git commit -m "feat(cli): sc transcript attach/show/list/sign, ws harvest --transcript, sc log marker (P30 t5)"
```

---

### Task 6: Demo + docs + ADR acceptance

**Files:**
- Create: `demo/run_transcript_demo.sh`
- Modify: `docs/adr/0038-agent-session-transcripts.md` (Proposed → Accepted), `docs/adr/README.md` (0038 → Accepted)
- Modify: `ROADMAP.md` (P30 Active → Done + Completed-phases row + Deferred follow-ons), `CLAUDE.md` (a `**Phase 30 is built.**` paragraph + the new commands)

- [ ] **Step 1: Write the demo** `demo/run_transcript_demo.sh` (mirror `demo/run_repo_demo.sh` / a P7 protected demo for the keyless positive-control discipline). Assert, with `exit 1` on failure: (1) `sc init` + a commit + `sc keygen` an identity; (2) `sc transcript attach <tip> <body-file> --agent claude --sign --identity <id>` succeeds; (3) `sc clone` to a second repo — the clone has the transcript (`sc transcript list` shows it) and it "rode the pack" (object present); (4) **keyless positive control:** a clone/inspection WITHOUT the identity cannot `sc transcript show` (ciphertext only), while `--identity <id>` decrypts the exact body; (5) `sc log` shows the transcript marker; (6) gc a deleted branch whose only commit carried a transcript and prove the transcript object is pruned (gone from `sc transcript list` and the object store). Run twice; assert zero residue outside `.sc/`.

- [ ] **Step 2: Run the demo** — `bash demo/run_transcript_demo.sh` → prints OK, exit 0. Run twice.

- [ ] **Step 3: Accept ADR-0038** — flip `Status: Proposed` → `Accepted`; update `docs/adr/README.md` 0038 row → `Accepted`, phase `P30` → `30`. (The brainstorm-resolution section is already in the ADR.)

- [ ] **Step 4: ROADMAP** — move P30 from `## Active` to `## Done` (house-style narrative bullet ending `(ADR-0038.)`); set `## Active` to `**None.**` (or the next candidate); add a P30 row to `## Completed phases`; add the DEFERRED follow-ons to `## Deferred`: `--transcript auto` probing, `sc transcript drop` + resurrection tombstone, transcript access lifecycle (rewrap/grant/revoke), `--no-transcripts` transfer knob, `sc export --transcripts=entire`, per-turn live checkpointing.

- [ ] **Step 5: CLAUDE.md** — add a `**Phase 30 is built.**` paragraph (house style, ends "See ADR-0038.") covering: sealed `TAG_TRANSCRIPT` objects, opt-in signing (`sc-transcript-sig-v1`), one-to-many `.sc/transcripts` index, zero-wire-change transfer, gc-coupled lifetime, git-export drop-count, and the accepted boundaries (opaque body; sealed-by-default so a keyless clone gets ciphertext; no access-lifecycle/deletion in the MVP). Add the commands: `sc transcript attach/show/list/sign`, `sc ws harvest --transcript <path> [--sign]`.

- [ ] **Step 6: Full verification** — `cargo test` (whole workspace, green), then `bash demo/run_transcript_demo.sh`, `bash demo/run_ssh_remote_demo.sh`, `bash demo/run_http_remote_demo.sh`, `bash demo/run_repo_demo.sh`, `bash demo/run_provenance_demo.sh` (all green — signatures/transfer/gc unaffected on the no-transcript path), then `git diff main -- '*Cargo.toml' '*Cargo.lock'` (EMPTY — no new dependency).

- [ ] **Step 7: Commit**

```bash
git add demo/run_transcript_demo.sh docs/adr/0038-agent-session-transcripts.md docs/adr/README.md ROADMAP.md CLAUDE.md
git commit -m "docs+demo: accept ADR-0038; P30 session transcripts done; run_transcript_demo.sh (P30 t6)"
```

---

## Self-review (author checklist, completed)

- **Spec coverage:** D1 → T1 (TAG_TRANSCRIPT) + T2 (seal); D2/D3 → T3 (signing domain + opt-in) + T5 (`--sign`/`sc transcript sign`); D4 → T2 (one-to-many index) + T4 (no-carry is inherent — amend/rebase/merge never call attach); D5 → not-built (no rewrap/grant/revoke tasks — deferred); D6 IN items → T2 (recipients+scan+opaque), T4 (transfer/gc/export), T5 (surface+log); D6 DEFERRED → documented in T6, no tasks. D7 → T6 (P30 slot). Positive control (keyless ciphertext) → T2 + T4 + the T6 demo.
- **No-new-dep / quarantines:** sealing reuses `seal`/`open` (zero crypto change); signing adds only a domain + wrappers INSIDE `crates/crypto`; `core` gains a bytes-only object; `gitio` stays repo-agnostic (T4 seam note). `git diff main -- '*Cargo.toml'` must stay empty (T6 Step 6).
- **Type consistency:** `Transcript{snapshot,agent,session,nonce,ciphertext,wrapped_keys}` (T1) consumed unchanged by T2's `attach_transcript` and T3's `open_transcript`; `attach_transcript`/`open_transcript`/`sign_transcript`/`transcript_sig_status`/`transcripts_for` (T2/T3) consumed by T4 (transfer/gc) and T5 (CLI); `indexed_transcript_ids_for`/`index_incoming`/`reindex`/`gc_prune` (T2) consumed by T4.
- **gc ordering** (the one non-obvious correctness point) is called out in T4 Step 5: transcripts::gc_prune BEFORE signatures::gc_prune, because a transcript's signature lives in the shared `.sc/signatures` keyed by the transcript id, which must be rooted first.
