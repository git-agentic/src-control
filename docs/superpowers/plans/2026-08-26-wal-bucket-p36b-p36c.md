# P36b + P36c: WAL Checkpoints and Bucket-Backed Serve Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** P36b — cold start over a bucket remote reads one checkpoint plus the log tail instead of replaying the whole log, with checkpoints folded opportunistically and coordinator-free; P36c — `sc serve --http|--stdio` can serve a bucket (`--store sc+wal://…|sc+s3://…`), making server instances disposable while tokens, TLS, and limits work unchanged.

**Architecture:** P36b adds a third record kind to `walfmt` (`Checkpoint`: folded refs + cumulative pack list), teaches `BucketTransport::refresh()` to stop its parent-chain walk at `manifest.checkpoint_seq` and seed from the checkpoint, and hooks a best-effort fold into `update_ref` after a successful CAS. P36c generalizes the wire serve loop's transport from concrete `LocalTransport` to a two-variant `ServeTransport` enum (only `GetPack`/`PutPack` differ; the other verbs already dispatch through the `Transport` trait), threads an optional store URL through the HTTP path, and adds a `--store` CLI flag. The serve host keeps a local `.sc/` "serve home" for tokens/TLS/tmp spills — the bucket is the object source of truth.

**Tech Stack:** Rust, existing crates only (`scl-objio`, `scl-repo`, `scl-cli`); no new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-26-wal-bucket-backend-design.md` (sections "Data flow → Checkpoints", "Clone / cold start", "Bucket-backed sc serve"). Prior phase: ADR-0046, plan `docs/superpowers/plans/2026-08-26-wal-bucket-backend-p36a.md`.

## Global Constraints

- Everything read from the bucket is untrusted: new checkpoint bytes go through the existing `capped()` guard (`crates/repo/src/bucket_transport.rs:61-79`) before decode; strict versioned decode fails closed; every count capped before allocation; branch names from checkpoints validated with `crate::refs::validate_branch_name`.
- Readers trust only what the manifest chain references: a checkpoint is authoritative only when `manifest.checkpoint_seq` names it AND its own `seq` field matches; a chain that bypasses the checkpoint (parent < checkpoint_seq without landing on it) is a loud `Error::Wal`.
- Checkpoint folding is opportunistic and best-effort: a fold failure or lost CAS must NEVER fail the push that triggered it (the commit already landed; the checkpoint is derived data any reader can rebuild). Threshold: `const CHECKPOINT_INTERVAL: u64 = 64` — one tunable constant (spec: "default 64 entries, one tunable constant").
- P36c changes no wire protocol byte: `PROTOCOL_VERSION` stays 4; clients are untouched; `WirePolicy` read-only gates, P29 tokens, P31 limits, P32 TLS behave identically in `--store` mode.
- The serve home (`<path>` arg) must contain `.sc/` exactly as today (404 gate at `http_transport.rs:996-999`, token load at `:1008`, TLS dir) — in `--store` mode its object store is simply never consulted.
- Errors: per-crate `thiserror`, lowercase, no trailing period; CLI uses `anyhow`.
- Every public type/fn gets an intent doc comment; tests live in `#[cfg(test)] mod tests` next to the code, clean up temp dirs, and assert the path is gone.
- Verification gate for EVERY task (CI runs fmt before tests): `cargo fmt --all -- --check` in addition to the task's tests and `cargo clippy` — a clippy-clean, test-green diff still fails CI if rustfmt is unhappy.
- Never silently drop data; refusals are loud and typed.

---

### Task 1: `walfmt::Checkpoint` — third record kind + key helper

**Files:**
- Modify: `crates/repo/src/walfmt.rs` (constants at :7-12, key helpers at :225-237, tests at :240+)

**Interfaces:**
- Consumes: existing private `Cursor` (`take/u8/u32/u64/string/id/done`, walfmt.rs:17-66), `header()` (:70), `push_string()` (:47), consts `VERSION`, `MAX_NAME`, `MAX_LIST`, `MAX_HASH`.
- Produces (used by Tasks 2, 3):
  - `pub struct Checkpoint { pub seq: u64, pub refs: Vec<(String, ObjectId)>, pub packs: Vec<String> }` with `#[derive(Debug, Clone, PartialEq, Eq)]`, `pub fn encode(&self) -> Vec<u8>`, `pub fn decode(bytes: &[u8]) -> Result<Checkpoint>`
  - `pub fn checkpoint_key(seq: u64) -> String` → `checkpoints/<seq zero-padded 20>`
  - New const `CHECKPOINT_MAGIC: &[u8; 4] = b"SCWC"` (private, beside the other two)

- [ ] **Step 1: Write the failing tests** (append inside `mod tests`; helper `some_id` exists at walfmt.rs:244)

```rust
    #[test]
    fn checkpoint_round_trips_and_rejects_garbage() {
        let c = Checkpoint {
            seq: 64,
            refs: vec![
                ("feat".to_string(), some_id(2)),
                ("main".to_string(), some_id(1)),
            ],
            packs: vec!["ab12".to_string(), "cd34".to_string()],
        };
        let bytes = c.encode();
        assert_eq!(Checkpoint::decode(&bytes).unwrap(), c);
        // wrong magic, truncated, future version, trailing junk: refused
        assert!(Checkpoint::decode(b"XXXX").is_err());
        assert!(Checkpoint::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut future = bytes.clone();
        future[4] = 0xFF;
        assert!(Checkpoint::decode(&future).is_err());
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(Checkpoint::decode(&junk).is_err());
        // a log-entry buffer is not a checkpoint (magic mismatch, not a panic)
        let entry = LogEntry { seq: 1, parent_seq: 0, packs: vec![], updates: vec![] };
        assert!(Checkpoint::decode(&entry.encode()).is_err());
    }

    #[test]
    fn checkpoint_decode_caps_hostile_counts() {
        // corrupt the refs count to u32::MAX: must fail fast, not allocate
        let c = Checkpoint { seq: 1, refs: vec![("m".to_string(), some_id(1))], packs: vec![] };
        let mut evil = c.encode();
        // refs count sits right after magic(4)+version(4)+seq(8) = offset 16
        evil[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Checkpoint::decode(&evil).is_err());
    }

    #[test]
    fn checkpoint_key_is_stable() {
        assert_eq!(checkpoint_key(64), "checkpoints/00000000000000000064");
    }
```

- [ ] **Step 2: Run to verify compile failure**

Run: `cargo test -p scl-repo walfmt`
Expected: FAIL — `Checkpoint`, `checkpoint_key` not found.

- [ ] **Step 3: Implement**

Beside `ENTRY_MAGIC` (walfmt.rs:8): `const CHECKPOINT_MAGIC: &[u8; 4] = b"SCWC";`. Struct + codec mirroring `LogEntry`'s exact patterns (count capped against `MAX_LIST` BEFORE `Vec::with_capacity`; branch names via `c.string(MAX_NAME)?` then 32-byte `c.id()?`; pack hashes via `c.string(MAX_HASH)?`; end with `c.done()?`):

```rust
/// A fold of the WAL at `seq`: every branch tip and every on-chain pack hash
/// accumulated from the chain's start through log entry `seq`. Cold start =
/// this + the log tail after `seq`, instead of replaying the whole chain.
/// Referenced (and made authoritative) only by `Manifest.checkpoint_seq`;
/// an unreferenced checkpoint object is garbage like any off-chain key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub seq: u64,
    /// branch -> tip pairs, sorted by branch (BTreeMap iteration order).
    pub refs: Vec<(String, ObjectId)>,
    /// Cumulative pack hashes in chain order (oldest first).
    pub packs: Vec<String>,
}

impl Checkpoint {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CHECKPOINT_MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&(self.refs.len() as u32).to_le_bytes());
        for (branch, id) in &self.refs {
            push_string(&mut out, branch);
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&(self.packs.len() as u32).to_le_bytes());
        for hash in &self.packs {
            push_string(&mut out, hash);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Checkpoint> {
        let mut c = header(bytes, CHECKPOINT_MAGIC, "checkpoint")?;
        let seq = c.u64()?;
        let nrefs = c.u32()? as usize;
        if nrefs > MAX_LIST {
            return Err(Error::Wal(format!("checkpoint ref count {nrefs} exceeds cap")));
        }
        let mut refs = Vec::with_capacity(nrefs);
        for _ in 0..nrefs {
            let branch = c.string(MAX_NAME)?;
            let id = c.id()?;
            refs.push((branch, id));
        }
        let npacks = c.u32()? as usize;
        if npacks > MAX_LIST {
            return Err(Error::Wal(format!("checkpoint pack count {npacks} exceeds cap")));
        }
        let mut packs = Vec::with_capacity(npacks);
        for _ in 0..npacks {
            packs.push(c.string(MAX_HASH)?);
        }
        c.done()?;
        Ok(Checkpoint { seq, refs, packs })
    }
}
```
And beside `log_key` (:225):
```rust
/// `checkpoints/<seq>` zero-padded so lexical order == numeric order.
pub fn checkpoint_key(seq: u64) -> String {
    format!("checkpoints/{seq:020}")
}
```
(`id.as_bytes()` / `ObjectId::from_bytes` are the constructors the existing codec already uses — walfmt.rs:52, LogEntry encode.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo walfmt && cargo fmt --all -- --check && cargo clippy -p scl-repo --all-targets`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/walfmt.rs
git commit -m "feat(repo): walfmt Checkpoint record kind + checkpoint_key (P36b)"
```

---

### Task 2: checkpoint-aware `refresh()` — cold start = checkpoint + log tail

**Files:**
- Modify: `crates/repo/src/bucket_transport.rs` (`WalView` :18-28, `refresh()` :172-238, tests)

**Interfaces:**
- Consumes: Task 1's `Checkpoint`, `checkpoint_key`; existing `capped()` (:61), `log_key`/`idx_key`, `crate::refs::validate_branch_name`, `parse_index`.
- Produces (used by Task 3): `WalView` gains `packs: Vec<String>` (cumulative, chain order — checkpoint-seeded packs first, then tail packs); `refresh()` stops the chain walk at `checkpoint_seq` and seeds refs+packs from the checkpoint. Everything else about `WalView` (`tag`, `manifest`, `refs`, `index`) unchanged.

- [ ] **Step 1: Write the failing tests** (in `mod tests`; helpers `pack_of` :523, `tiny_history` :538 exist; hand-building a WAL directly against `DirBucket` is the established pattern — see :588 and :652)

```rust
    /// Hand-build a WAL with `n` single-branch pushes; returns (bucket root,
    /// final tip per branch map as Vec sorted, all pack hashes in order).
    /// Each push i creates branch "b-<i>" pointing at a distinct object.
    fn hand_built_wal(tag: &str, n: u64) -> (std::path::PathBuf, Vec<(String, ObjectId)>, Vec<String>) {
        let broot = std::env::temp_dir().join(format!("scl-bt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&broot);
        let bucket = DirBucket::open(&broot).unwrap();
        let mut refs = Vec::new();
        let mut packs = Vec::new();
        for i in 1..=n {
            let obj = scl_core::Object::Blob(scl_core::Blob {
                bytes: format!("wal-entry-{i}").into_bytes().into(),
            });
            let id = obj.id();
            let (hash, pack, idx) = pack_of(&[(id, obj.encode())]);
            bucket.put_new(&pack_key(&hash), &pack).unwrap();
            bucket.put_new(&idx_key(&hash), &idx).unwrap();
            let entry = LogEntry {
                seq: i,
                parent_seq: i - 1,
                packs: vec![hash.clone()],
                updates: vec![RefUpdate { branch: format!("b-{i}"), old: None, new: id }],
            };
            bucket.put_new(&log_key(i), &entry.encode()).unwrap();
            refs.push((format!("b-{i}"), id));
            packs.push(hash);
        }
        let m = Manifest { head_seq: n, checkpoint_seq: 0, head_branch: "b-1".into() };
        bucket.put_if_tag("manifest", &m.encode(), None).unwrap().unwrap();
        refs.sort();
        (broot, refs, packs)
    }
    // NOTE: adapt the Object construction line to however `pack_of`'s existing
    // callers mint distinct blob objects in this test module (see
    // tiny_history_distinct at :566) — the intent is "n distinct valid objects".

    #[test]
    fn view_via_checkpoint_equals_full_replay_and_skips_folded_entries() {
        let (broot, expected_refs, packs) = hand_built_wal("ckpt-eq", 6);
        let bucket = DirBucket::open(&broot).unwrap();
        // fold through seq 4 by hand
        let full = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let full_refs = full.list_refs().unwrap();
        let ck = Checkpoint {
            seq: 4,
            refs: expected_refs.iter().filter(|(b, _)| {
                let i: u64 = b.strip_prefix("b-").unwrap().parse().unwrap();
                i <= 4
            }).cloned().collect(),
            packs: packs[..4].to_vec(),
        };
        bucket.put_new(&checkpoint_key(4), &ck.encode()).unwrap();
        let Fetched::New { bytes, tag } = bucket.get("manifest", None).unwrap() else { panic!() };
        let mut m = Manifest::decode(&bytes).unwrap();
        m.checkpoint_seq = 4;
        bucket.put_if_tag("manifest", &m.encode(), Some(&tag)).unwrap().unwrap();

        // DELETE the folded log entries: a checkpoint-aware reader must not
        // need them. (Direct file removal = simulated compaction.)
        for seq in 1..=4u64 {
            std::fs::remove_file(broot.join(log_key(seq))).unwrap();
        }
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t.list_refs().unwrap(), full_refs);
        // objects from folded packs still readable (index seeded from checkpoint.packs)
        let (b1, id1) = &expected_refs[0];
        assert!(b1.starts_with("b-"));
        assert!(t.has_object(id1).unwrap());
        drop((t, full));
        std::fs::remove_dir_all(&broot).unwrap();
    }

    #[test]
    fn corrupt_or_bypassing_checkpoints_fail_closed() {
        let (broot, _refs, packs) = hand_built_wal("ckpt-bad", 3);
        let bucket = DirBucket::open(&broot).unwrap();
        // (a) manifest names a checkpoint that does not exist
        let Fetched::New { bytes, tag } = bucket.get("manifest", None).unwrap() else { panic!() };
        let mut m = Manifest::decode(&bytes).unwrap();
        m.checkpoint_seq = 2;
        let tag = bucket.put_if_tag("manifest", &m.encode(), Some(&tag)).unwrap().unwrap();
        assert!(BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).is_err());
        // (b) checkpoint exists but its seq field lies
        let ck = Checkpoint { seq: 1, refs: vec![], packs: packs[..2].to_vec() };
        bucket.put_new(&checkpoint_key(2), &ck.encode()).unwrap();
        assert!(BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).is_err());
        // (c) chain bypasses the checkpoint: entry at seq 3 has parent 1 (< 2)
        let obj_end = {
            // repair (b) first so the error is unambiguously the bypass
            std::fs::remove_file(broot.join(checkpoint_key(2))).unwrap();
            let good = Checkpoint { seq: 2, refs: vec![], packs: packs[..2].to_vec() };
            bucket.put_new(&checkpoint_key(2), &good.encode()).unwrap();
            let bad_entry = LogEntry { seq: 3, parent_seq: 1, packs: vec![], updates: vec![] };
            std::fs::remove_file(broot.join(log_key(3))).unwrap();
            bucket.put_new(&log_key(3), &bad_entry.encode()).unwrap()
        };
        assert!(obj_end);
        assert!(BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).is_err());
        let _ = tag;
        std::fs::remove_dir_all(&broot).unwrap();
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo bucket_transport::tests::view_via`
Expected: FAIL — `checkpoint_key`/`Checkpoint` unimported at first, then (after imports) the equals test fails because refresh walks past the checkpoint into the deleted entries (`Error::Wal("log entry 4 referenced by chain but absent")` from `from_bucket`).

- [ ] **Step 3: Implement**

`WalView` gains the field (after `refs`):
```rust
    /// Every on-chain pack hash in chain order (checkpoint fold first, then
    /// the tail) — retained so a checkpoint fold (Task 3) is a pure copy.
    packs: Vec<String>,
```
`refresh()`'s `Fetched::New` arm changes (current body verbatim at :186-231; the walk is `while seq != 0 { … }` then `entries.reverse()` then the refs/index build). New shape:

```rust
                let manifest = Manifest::decode(&bytes)?;
                let stop = manifest.checkpoint_seq;
                // Seed from the checkpoint when the manifest names one. The
                // checkpoint is untrusted input like everything else here.
                let (mut refs, mut packs): (BTreeMap<String, ObjectId>, Vec<String>) =
                    if stop != 0 {
                        let ck_bytes = match self.bucket.get(&checkpoint_key(stop), None)? {
                            Fetched::New { bytes, .. } => capped("checkpoint", bytes)?,
                            _ => {
                                return Err(Error::Wal(format!(
                                    "checkpoint {stop} referenced by manifest but absent"
                                )))
                            }
                        };
                        let ck = Checkpoint::decode(&ck_bytes)?;
                        if ck.seq != stop {
                            return Err(Error::Wal(format!(
                                "checkpoint at {stop} claims seq {}",
                                ck.seq
                            )));
                        }
                        let mut refs = BTreeMap::new();
                        for (branch, id) in &ck.refs {
                            crate::refs::validate_branch_name(branch)?;
                            refs.insert(branch.clone(), *id);
                        }
                        (refs, ck.packs)
                    } else {
                        (BTreeMap::new(), Vec::new())
                    };
                let mut entries = Vec::new();
                let mut seq = manifest.head_seq;
                while seq != stop {
                    if seq < stop {
                        return Err(Error::Wal(format!(
                            "log chain bypasses checkpoint {stop} (reached {seq})"
                        )));
                    }
                    let Fetched::New { bytes, .. } = self.bucket.get(&log_key(seq), None)? else {
                        return Err(Error::Wal(format!(
                            "log entry {seq} referenced by chain but absent"
                        )));
                    };
                    let e = LogEntry::decode(&capped("log entry", bytes)?)?;
                    // …seq/parent validation identical to today (:195-206)…
                    seq = e.parent_seq;
                    entries.push(e);
                }
                entries.reverse(); // oldest first
                for e in &entries {
                    for u in &e.updates {
                        crate::refs::validate_branch_name(&u.branch)?;
                        refs.insert(u.branch.clone(), u.new);
                    }
                    for hash in &e.packs {
                        packs.push(hash.clone());
                    }
                }
                // Index build: over the FULL cumulative pack list (checkpoint
                // packs + tail packs), fetching each idx exactly as today.
                let mut index = BTreeMap::new();
                for hash in &packs {
                    let Fetched::New { bytes, .. } = self.bucket.get(&idx_key(hash), None)? else {
                        return Err(Error::Wal(format!("pack {hash} on chain but idx absent")));
                    };
                    let bytes = capped("pack idx", bytes)?;
                    for IndexEntry { id, offset, length } in parse_index(&bytes)? {
                        index.insert(id, (hash.clone(), offset, length));
                    }
                }
                *self.view.borrow_mut() = Some(WalView { tag, manifest, refs, index, packs });
```
Note the `head_seq == checkpoint_seq` case falls out naturally (`while seq != stop` runs zero times). Keep the existing seq-claims-vs-slot and parent-strictly-decreasing checks verbatim inside the loop.

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo bucket_transport && cargo fmt --all -- --check && cargo clippy -p scl-repo --all-targets`
Expected: all pass (the 13 existing tests prove no regression for `checkpoint_seq == 0`), clean.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/bucket_transport.rs
git commit -m "feat(repo): checkpoint-aware refresh — cold start reads checkpoint + log tail (P36b)"
```

---

### Task 3: opportunistic checkpoint fold in `update_ref`

**Files:**
- Modify: `crates/repo/src/bucket_transport.rs` (`update_ref` success arm :488-498, new helper, tests)

**Interfaces:**
- Consumes: Task 2's `WalView.packs`; Task 1's `Checkpoint`/`checkpoint_key`; `Bucket::{put_new, put_if_tag}`.
- Produces: `const CHECKPOINT_INTERVAL: u64 = 64;` (module-level, doc-commented as the spec's single tunable) and private `fn maybe_fold_checkpoint(&self)` called after the successful CAS + refresh in `update_ref`. Fold is best-effort: all its errors are swallowed by the caller (`let _ = …`), with a doc comment stating why that is correct (derived data; next over-threshold push retries; losing the fold CAS to a racing pusher is the expected outcome, not a failure).

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn pushes_past_the_interval_fold_a_checkpoint_and_cold_start_uses_it() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-fold-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        let n = CHECKPOINT_INTERVAL + 2;
        for i in 0..n {
            let obj = /* distinct blob, same construction as fleet test :960 */;
            t.put_object(&obj.id(), &obj.encode()).unwrap();
            t.update_ref(&format!("w-{i}"), &obj.id(), None).unwrap();
        }
        // the bucket now carries a manifest whose checkpoint_seq > 0 and the
        // matching checkpoints/<seq> object
        let bucket = DirBucket::open(&broot).unwrap();
        let Fetched::New { bytes, .. } = bucket.get("manifest", None).unwrap() else { panic!() };
        let m = Manifest::decode(&bytes).unwrap();
        assert!(m.checkpoint_seq > 0, "no fold happened after {n} pushes");
        let Fetched::New { bytes, .. } = bucket.get(&checkpoint_key(m.checkpoint_seq), None).unwrap() else {
            panic!("manifest names checkpoint {} but object absent", m.checkpoint_seq)
        };
        let ck = Checkpoint::decode(&bytes).unwrap();
        assert_eq!(ck.seq, m.checkpoint_seq);
        assert!(!ck.refs.is_empty() && !ck.packs.is_empty());
        // cold start through it sees all n branches
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t2.list_refs().unwrap().len(), n as usize);
        drop((t, t2));
        std::fs::remove_dir_all(&broot).unwrap();
    }

    /// A bucket whose checkpoint writes always fail must not fail pushes.
    struct FoldHostileBucket(DirBucket);
    impl Bucket for FoldHostileBucket {
        fn get(&self, key: &str, tag: Option<&str>) -> scl_objio::Result<Fetched> {
            self.0.get(key, tag)
        }
        fn put_new(&self, key: &str, bytes: &[u8]) -> scl_objio::Result<bool> {
            if key.starts_with("checkpoints/") {
                return Err(scl_objio::Error::Backend("injected checkpoint write failure".into()));
            }
            self.0.put_new(key, bytes)
        }
        fn put_if_tag(&self, key: &str, bytes: &[u8], tag: Option<&str>) -> scl_objio::Result<Option<String>> {
            self.0.put_if_tag(key, bytes, tag)
        }
        fn list(&self, prefix: &str) -> scl_objio::Result<Vec<String>> {
            self.0.list(prefix)
        }
    }

    #[test]
    fn fold_failure_never_fails_the_push() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-bt-foldfail-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        let t = BucketTransport::from_bucket(Box::new(FoldHostileBucket(DirBucket::open(&broot).unwrap()))).unwrap();
        for i in 0..(CHECKPOINT_INTERVAL + 2) {
            let obj = /* distinct blob as above */;
            t.put_object(&obj.id(), &obj.encode()).unwrap();
            t.update_ref(&format!("w-{i}"), &obj.id(), None).unwrap(); // must all be Ok
        }
        // no checkpoint could land; manifest still says 0 and reads still work
        let t2 = BucketTransport::from_bucket(Box::new(DirBucket::open(&broot).unwrap())).unwrap();
        assert_eq!(t2.list_refs().unwrap().len(), (CHECKPOINT_INTERVAL + 2) as usize);
        drop((t, t2));
        std::fs::remove_dir_all(&broot).unwrap();
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo bucket_transport::tests::pushes_past`
Expected: FAIL — `CHECKPOINT_INTERVAL` not found; then (once compiling) `m.checkpoint_seq > 0` assert fails because no fold exists.

- [ ] **Step 3: Implement**

Module-level, near `capped()`:
```rust
/// Fold a checkpoint once the log tail exceeds this many entries past the
/// last checkpoint (spec: "default 64 entries, one tunable constant").
const CHECKPOINT_INTERVAL: u64 = 64;
```
Private helper on `BucketTransport`:
```rust
    /// Opportunistic, coordinator-free checkpoint fold. Called after a
    /// successful commit; every failure path is deliberately non-fatal —
    /// the checkpoint is derived data any reader can rebuild from the log,
    /// a lost CAS just means a racing pusher's fold (or push) won, and the
    /// next over-threshold push retries. The push that triggered this has
    /// already durably landed.
    fn maybe_fold_checkpoint(&self) -> Result<()> {
        let (head_seq, checkpoint_seq, head_branch, tag, refs, packs) = {
            let view = self.view.borrow();
            let Some(v) = view.as_ref() else { return Ok(()) };
            (
                v.manifest.head_seq,
                v.manifest.checkpoint_seq,
                v.manifest.head_branch.clone(),
                v.tag.clone(),
                v.refs.iter().map(|(b, id)| (b.clone(), *id)).collect::<Vec<_>>(),
                v.packs.clone(),
            )
        };
        if head_seq - checkpoint_seq <= CHECKPOINT_INTERVAL {
            return Ok(());
        }
        let ck = Checkpoint { seq: head_seq, refs, packs };
        // Claim the object first (idempotent), then point the manifest at it.
        self.bucket.put_new(&checkpoint_key(head_seq), &ck.encode())?;
        let manifest = Manifest { head_seq, checkpoint_seq: head_seq, head_branch };
        // CAS from the tag our fresh post-commit view carries. A loss means
        // someone advanced the WAL meanwhile — their problem to fold later.
        if self.bucket.put_if_tag("manifest", &manifest.encode(), Some(&tag))?.is_some() {
            self.refresh()?;
        }
        Ok(())
    }
```
Call site — inside `update_ref`'s successful-CAS arm (currently `self.refresh()?; return Ok(());` at :496-497):
```rust
                self.refresh()?;
                let _ = self.maybe_fold_checkpoint(); // best-effort by design (see its doc)
                return Ok(());
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo bucket_transport && cargo fmt --all -- --check && cargo clippy -p scl-repo --all-targets`
Expected: all pass — including the P36a race/fleet/crash proofs unchanged. The fleet test (8 pushes) stays under the interval, so folds don't interfere with it.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/bucket_transport.rs
git commit -m "feat(repo): opportunistic coordinator-free checkpoint fold after commit (P36b)"
```

---

### Task 4: generalize the wire serve loop — `ServeTransport` + bucket stdio serve

**Files:**
- Modify: `crates/repo/src/wire.rs` (`serve_with_policy` :692-731, `GetPack` arm :799-826, `PutPack` arm :827-856, read-only drain :757-786, `spill_pack_stream` :907-916)
- Modify: `crates/repo/src/transport.rs` (`TempPackGuard::new` :228-236 — add a dir-based constructor)
- Test: `#[cfg(test)] mod tests` in `wire.rs` (mirror its existing in-memory serve tests)

**Interfaces:**
- Consumes: `BucketTransport` (implements `Transport` fully; `get_pack(wants, haves, filter, out)` and `put_pack(src)` on the trait, transport.rs:142-153); existing `LocalTransport` inherent fns (`layout` :98, `build_pack_tempfile` :121, `ingest_from` :208).
- Produces (used by Tasks 5, 6):
  - `pub(crate) enum ServeTransport { Local(LocalTransport), Bucket { transport: BucketTransport, tmp: TempServeDir } }` in wire.rs, with `fn as_transport(&self) -> &dyn Transport` and `fn tmp_dir(&self) -> &Path`.
  - `pub(crate) struct TempServeDir` — RAII temp dir under `std::env::temp_dir()` (`sc-serve-bucket-<pid>-<counter>`), created on construction, best-effort removed on `Drop` (ephemeral-mode hygiene: serve spills must not outlive the session).
  - `pub fn serve_bucket_with_policy(store_url: &str, r: &mut impl Read, w: &mut impl Write, policy: WirePolicy) -> Result<()>` — the bucket twin of `serve_with_policy` (:692). `serve_with_policy`'s signature and behavior are UNCHANGED.
  - `pub(crate) fn TempPackGuard::new_in(dir: &std::path::Path) -> Result<TempPackGuard>`; the existing `new(layout)` becomes a one-line wrapper reserving in `layout.tmp_dir()`.
  - `spill_pack_stream(r, dir: &Path, max_bytes)` — parameter changes from `&Layout` to `&Path`; both call sites (:769 read-only drain, :828 PutPack) pass `transport.tmp_dir()`-equivalent.

- [ ] **Step 1: Write the failing test** (wire.rs has in-memory serve tests — find its pattern, e.g. `serve_verb_errors_are_replies_not_session_teardown`, and mirror the pipe/duplex setup; the wire client half is `WireClient` from stdio_transport.rs:59)

```rust
    #[test]
    fn bucket_stdio_serve_round_trips_refs_and_packs() {
        // seed a bucket WAL with one commit via BucketTransport directly
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-wire-bucket-{pid}"));
        let _ = std::fs::remove_dir_all(&broot);
        let url = format!("sc+wal://{}", broot.display());
        {
            let t = crate::bucket_transport::BucketTransport::open(&url).unwrap();
            // reuse however this test module (or bucket_transport's) mints a
            // one-commit pack: build objects from a scratch repo, put_pack,
            // update_ref "main"
            /* seed as in bucket_transport::tests::push_via_trait_round_trips… */
        }
        // serve it over an in-memory duplex exactly like the local serve tests
        let (mut client_r, mut server_w) = /* this module's existing pipe pair helper */;
        let (mut server_r, mut client_w) = /* … */;
        let srv = std::thread::spawn(move || {
            serve_bucket_with_policy(&url, &mut server_r, &mut server_w, WirePolicy::default())
        });
        let client = crate::stdio_transport::WireClient::handshake(&mut client_r, &mut client_w).unwrap();
        let refs = client.list_refs().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "main");
        // GetPack streams; PutPack + UpdateRef land in the bucket
        /* clone-style GetPack with wants=[tip], haves=[] and assert nonempty;
           then push a second commit through PutPack + UpdateRef and assert a
           fresh BucketTransport::open(&url) sees the moved tip */
        drop(client);
        srv.join().unwrap().unwrap();
        std::fs::remove_dir_all(&broot).unwrap();
    }
```
(The comment-marked seeding/piping lines are direction, not placeholders: the implementer copies the concrete duplex + seeding code from the named existing tests in the same two files — `wire.rs`'s serve tests and `bucket_transport.rs:702` — which are the authoritative in-repo patterns. New test must clean up and assert-gone.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo wire::tests::bucket_stdio`
Expected: FAIL — `serve_bucket_with_policy` not found.

- [ ] **Step 3: Implement**

1. `TempPackGuard::new_in(dir)` in transport.rs — same body as `new` (:228-236) but reserving `dir.join(format!("pack-{pid}-{counter}.tmp"))` after `std::fs::create_dir_all(dir)?`; `new(layout)` delegates: `Self::new_in(&layout.tmp_dir())`.
2. `spill_pack_stream(r: &mut impl Read, tmp_dir: &Path, max_bytes: u64)` — replace the `layout` param (:907-916); body swaps `TempPackGuard::new(layout)` for `TempPackGuard::new_in(tmp_dir)`.
3. In wire.rs:
```rust
/// RAII scratch dir for a bucket-backed serve session's pack spills.
/// Removed (best-effort) on drop — a serve session leaves no residue.
pub(crate) struct TempServeDir(std::path::PathBuf);
impl TempServeDir {
    fn create() -> Result<TempServeDir> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "sc-serve-bucket-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(TempServeDir(dir))
    }
}
impl Drop for TempServeDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The two transports the serve loop can sit on. Six verbs dispatch through
/// the `Transport` trait either way; only the pack verbs differ (local uses
/// the tempfile fast paths, bucket uses the trait's streaming methods).
pub(crate) enum ServeTransport {
    Local(LocalTransport),
    Bucket {
        transport: crate::bucket_transport::BucketTransport,
        tmp: TempServeDir,
    },
}
impl ServeTransport {
    fn as_transport(&self) -> &dyn Transport {
        match self {
            ServeTransport::Local(t) => t,
            ServeTransport::Bucket { transport, .. } => transport,
        }
    }
    fn tmp_dir(&self) -> std::path::PathBuf {
        match self {
            ServeTransport::Local(t) => t.layout().tmp_dir(),
            ServeTransport::Bucket { tmp, .. } => tmp.0.clone(),
        }
    }
}
```
4. Extract the current post-handshake body of `serve_with_policy` (from the `LocalTransport::open` match at :721 to the end) into `fn serve_session(transport: ServeTransport, r, w, policy) -> Result<()>`, with these substitutions:
   - Generic verbs (`ListRefs`…`UpdateRef` arm :857-887): call through `transport.as_transport()`.
   - Read-only PutPack drain (:769): `spill_pack_stream(r, &transport.tmp_dir(), policy.ro_drain_cap)`.
   - `GetPack` arm: `Local` keeps `build_pack_tempfile` verbatim; `Bucket` builds the same OK-before-stream shape by writing to a `TempPackGuard::new_in(&transport.tmp_dir())` file first: `transport.get_pack(&wants, &haves, filter_opt, &mut file)` then stream the file — same "fully succeeded before any wire byte" invariant as the comment at :600-603.
   - `PutPack` arm: spill via `spill_pack_stream(r, &transport.tmp_dir(), policy.max_pack_size)`; then `Local` → `ingest_from(guard.path())` verbatim; `Bucket` → `transport.put_pack(&mut File::open(guard.path())?)` mapping to the same `ids_body` reply.
5. `serve_with_policy` becomes: handshake, `LocalTransport::open(root)` (unchanged error reply), `serve_session(ServeTransport::Local(t), …)`. New:
```rust
/// Serve a bucket WAL (`sc+wal://`/`sc+s3://`) over the wire protocol —
/// the disposable-instance mode (P36c): all durable state lives in the
/// bucket; this process keeps only an RAII scratch dir for pack spills.
pub fn serve_bucket_with_policy(
    store_url: &str,
    r: &mut impl Read,
    w: &mut impl Write,
    policy: WirePolicy,
) -> Result<()> {
    // handshake identical to serve_with_policy (:698-720), then:
    let transport = match crate::bucket_transport::BucketTransport::open(store_url)
        .and_then(|t| Ok(ServeTransport::Bucket { transport: t, tmp: TempServeDir::create()? }))
    {
        Ok(t) => {
            write_ok(w, &u32_body(PROTOCOL_VERSION))?;
            t
        }
        Err(e) => {
            let (code, msg) = err_to_wire(&e);
            write_err(w, code, &msg)?;
            return Ok(());
        }
    };
    serve_session(transport, r, w, policy)
}
```
(Factor the duplicated handshake into a small private helper if it keeps both entry fns readable — implementer's call; behavior is pinned by tests.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo wire && cargo test -p scl-repo stdio_transport && cargo test -p scl-repo http_transport && cargo fmt --all -- --check && cargo clippy -p scl-repo --all-targets`
Expected: new test passes; every existing serve/wire test passes unchanged (the refactor must be behavior-preserving for `Local`).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src
git commit -m "feat(repo): ServeTransport seam + serve_bucket_with_policy — wire serve over a bucket (P36c)"
```

---

### Task 5: bucket-backed HTTP serve — store threading + disposable-instance proof

**Files:**
- Modify: `crates/repo/src/http_transport.rs` (`serve_http` :752, `serve_http_listener` :826, `handle_http_connection` :959-1063)
- Test: `#[cfg(test)] mod tests` there (mirror `spawn_real_http_server*` :1347-1374)

**Interfaces:**
- Consumes: Task 4's `serve_bucket_with_policy`.
- Produces (used by Task 6): `serve_http`, `serve_http_listener`, and `handle_http_connection` each gain a trailing `store: Option<&str>` / owned `Option<String>` parameter (threaded through the connection thread's `move` closure like `root`/`tls` at :865-866). Semantics: `None` = today's behavior byte-for-byte; `Some(url)` = the final hand-off (:1054-1063) calls `serve_bucket_with_policy(url, …)` instead of `serve_with_policy(root, …)` — everything before it (`.sc` presence gate, token load from the serve home, read-only floor, TLS, limits, timeouts) runs identically against `root`, which in store mode is the serve HOME, not the object source.

- [ ] **Step 1: Write the failing test**

```rust
    fn spawn_bucket_http_server(home: std::path::PathBuf, store: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            serve_http_listener(
                listener,
                &home,
                false,
                false,
                ServeLimits::default(),
                None,
                Some(store),
            )
            .unwrap();
        });
        port
    }

    #[test]
    fn two_disposable_instances_serve_one_bucket_with_strict_consistency() {
        let pid = std::process::id();
        let broot = std::env::temp_dir().join(format!("scl-http-bstore-{pid}"));
        let home_a = tmp_repo("bstore-home-a"); // existing helper :1245 — an sc repo as serve home
        let home_b = tmp_repo("bstore-home-b");
        let _ = std::fs::remove_dir_all(&broot);
        let store = format!("sc+wal://{}", broot.display());
        // seed the bucket with one commit (same seeding as the wire test — a
        // scratch repo pushed through BucketTransport::open(&store))
        /* seed one commit on "main" into the bucket */
        let port_a = spawn_bucket_http_server(home_a.clone(), store.clone());
        let port_b = spawn_bucket_http_server(home_b.clone(), store.clone());

        // clone through instance A
        let dst = std::env::temp_dir().join(format!("scl-http-bstore-dst-{pid}"));
        let _ = std::fs::remove_dir_all(&dst);
        let dst_repo = crate::repo::Repo::clone_url(&format!("sc+http://127.0.0.1:{port_a}/x"), &dst).unwrap();
        // push through instance A…
        std::fs::write(dst.join("f2.txt"), b"instance hop").unwrap();
        let tip2 = dst_repo.commit("t", "c2").unwrap();
        dst_repo.push("origin").unwrap();
        drop(dst_repo);
        // …and observe it through instance B with no propagation delay:
        // strict consistency — "there is no eventually" (spec).
        let dst2 = std::env::temp_dir().join(format!("scl-http-bstore-dst2-{pid}"));
        let _ = std::fs::remove_dir_all(&dst2);
        let d2 = crate::repo::Repo::clone_url(&format!("sc+http://127.0.0.1:{port_b}/x"), &dst2).unwrap();
        assert_eq!(d2.head_tip().unwrap(), Some(tip2));
        drop(d2);
        for p in [&broot, &home_a, &home_b, &dst, &dst2] {
            std::fs::remove_dir_all(p).unwrap();
        }
    }

    #[test]
    fn read_only_floor_holds_in_store_mode() {
        // spawn with read_only=true + store; a push through it must fail with
        // the ReadOnly wire error while clone still works — mirrors the
        // existing server_read_only_floors_rw_token shape (:1719).
        /* same setup as above, read_only: true; assert push Err, clone Ok */
    }
```
(Seeding/`/* */` blocks: copy the concrete code from `bucket_transport.rs:702` (seed) and `http_transport.rs:1384` (clone/push over real socket) — in-repo authoritative patterns. All existing `serve_http_listener(...)` call sites in tests gain a trailing `None`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-repo http_transport::tests::two_disposable`
Expected: FAIL — `serve_http_listener` has no 7th parameter.

- [ ] **Step 3: Implement**

Signature changes (store LAST, after `tls`):
- `serve_http(addr, root, read_only, allow_public, limits, tls, store: Option<&str>)`
- `serve_http_listener(listener, root, read_only, mandatory_auth, limits, tls, store: Option<String>)`
- `handle_http_connection(stream, root, server_read_only, mandatory_auth, limits, tls, store: Option<&str>)`

Thread through the spawn closure exactly like `root` (:865-867): `let store = store.clone();` before the `move`. In `handle_http_connection`, the hand-off (:1053-1063) becomes:
```rust
    let read_only = server_read_only || token_read_only;
    let policy = crate::wire::WirePolicy {
        read_only,
        max_pack_size: limits.max_pack_size,
        ro_drain_cap: crate::wire::RO_DRAIN_CAP,
    };
    match store {
        Some(url) => crate::wire::serve_bucket_with_policy(url, &mut reader, &mut writer, policy),
        None => crate::wire::serve_with_policy(root, &mut reader, &mut writer, policy),
    }
```
`serve_http` forwards `store` to the listener after the existing gates — the bind gate, mandatory-auth computation, and token warning all keep reading the serve home's `.sc/`, unchanged.

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-repo http_transport && cargo fmt --all -- --check && cargo clippy -p scl-repo --all-targets`
Expected: 2 new tests pass; all ~38 existing http tests pass with their trailing `None`.

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/http_transport.rs
git commit -m "feat(repo): bucket-backed sc serve --http — disposable instances over one bucket (P36c)"
```

---

### Task 6: CLI `--store` flag + integration test

**Files:**
- Modify: `crates/cli/src/main.rs` (`Cmd::Serve` :307-365, dispatch :939-981, `run_serve` :3480-3551)
- Create: test in `crates/cli/tests/bucket_remote.rs` (helpers `sc` :8, `tmp` :14 exist)

**Interfaces:**
- Consumes: Tasks 4-5 (`serve_bucket_with_policy`, `serve_http(… store)`), `scl_repo::BucketUrl::parse` for fail-fast validation.
- Produces: `sc serve --stdio|--http <addr> --store <sc+wal://…|sc+s3://…> <serve-home-path>`. `<path>` stays required (serve home: `.sc/` for tokens/TLS/tmp). Malformed `--store` URL is refused before any bind. All other flags compose exactly as before.

- [ ] **Step 1: Write the failing CLI test** (in `bucket_remote.rs`; readiness pattern copied from `crates/cli/tests/http_remote.rs:39-64` — the `listening on <addr>` line)

```rust
#[test]
fn serve_store_serves_a_bucket_and_second_instance_sees_pushes() {
    let bucket = tmp("srv-bucket");
    let home = tmp("srv-home");
    assert!(sc(&home, &["init"]).status.success());
    let store = format!("sc+wal://{}", bucket.display());

    // seed: a repo pushed straight to the bucket
    let seed = tmp("srv-seed");
    assert!(sc(&seed, &["init"]).status.success());
    std::fs::write(seed.join("f.txt"), b"served from bucket").unwrap();
    assert!(sc(&seed, &["commit", "-m", "c1"]).status.success());
    assert!(sc(&seed, &["remote", "add", "origin", &store]).status.success());
    assert!(sc(&seed, &["push", "origin"]).status.success());

    // malformed store URL refused before binding
    let bad = sc(&home, &["serve", "--http", "127.0.0.1:0", "--store", "sc+s3://", home.to_str().unwrap()]);
    assert!(!bad.status.success());

    let (mut child, addr) = spawn_http_server_with(&home, &["--store", &store]);
    let parent = tmp("srv-clone");
    let dst = parent.join("d");
    let url = format!("sc+http://{addr}/repo");
    assert!(sc(&parent, &["clone", &url, dst.to_str().unwrap()]).status.success());
    assert_eq!(std::fs::read(dst.join("f.txt")).unwrap(), b"served from bucket");
    // push through the server, then read it back via a SECOND instance
    std::fs::write(dst.join("g.txt"), b"hop").unwrap();
    assert!(sc(&dst, &["commit", "-m", "c2"]).status.success());
    assert!(sc(&dst, &["push", "origin"]).status.success());
    child.kill().ok();
    let (mut child2, addr2) = spawn_http_server_with(&home, &["--store", &store]);
    let parent2 = tmp("srv-clone2");
    let d2 = parent2.join("d2");
    assert!(sc(&parent2, &["clone", &format!("sc+http://{addr2}/repo"), d2.to_str().unwrap()]).status.success());
    assert_eq!(std::fs::read(d2.join("g.txt")).unwrap(), b"hop");
    child2.kill().ok();

    for p in [&bucket, &home, &seed, &parent, &parent2] {
        std::fs::remove_dir_all(p).unwrap();
        assert!(!p.exists());
    }
}
```
Add a local `spawn_http_server_with(root, extra)` helper — copy `http_remote.rs:39-64` verbatim (same readiness line contract). Mirror the exact clap argv the existing tests in this file use for init/commit/clone/push.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p scl-cli --test bucket_remote serve_store`
Expected: FAIL — `--store` is an unknown flag (clap error in the child's stderr → non-success where success asserted).

- [ ] **Step 3: Implement**

Clap (inside `Cmd::Serve`, after `tls_key`):
```rust
        /// Serve a bucket WAL remote (`sc+wal://…` or `sc+s3://…`) instead of
        /// this repo's own object store (P36c). `<path>` remains the serve
        /// home: its `.sc/` still provides access tokens, the TLS identity,
        /// and scratch space — but all served content lives in the bucket,
        /// making this instance disposable.
        #[arg(long)]
        store: Option<String>,
```
Dispatch (:939-981): pass `store` through to `run_serve` (12th param). In `run_serve`:
- Immediately after entry: `if let Some(url) = &store { scl_repo::BucketUrl::parse(url)?; }` (fail fast, before any bind — same idiom as `run_remote` :3650-3651).
- stdio arm (:3494-3517): replace the `serve_with_policy` call with
```rust
            match &store {
                Some(url) => scl_repo::wire::serve_bucket_with_policy(url, &mut stdin, &mut stdout, policy)?,
                None => scl_repo::wire::serve_with_policy(&path, &mut stdin, &mut stdout, policy)?,
            }
```
- http arm (:3518-3547): `serve_http(&addr, &path, read_only, allow_public, limits, tls_mode, store.as_deref())?`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p scl-cli && cargo fmt --all -- --check && cargo clippy --workspace --all-targets`
Expected: PASS across the CLI suites (14 test binaries), clean.

- [ ] **Step 5: Commit**

```bash
git add crates/cli crates/repo
git commit -m "feat(cli): sc serve --store — bucket-backed serving via CLI (P36c)"
```

---

### Task 7: docs + full gate — P36 complete

**Files:**
- Modify: `docs/adr/0046-wal-bucket-remotes.md` (extend "As built" with P36b/P36c)
- Modify: `CLAUDE.md` (P36 capability row; standing-boundaries bullet)
- Modify: `ROADMAP.md` (Deferred: remove the P36b/P36c entries; add one new entry)
- Modify: `docs/THREAT-MODEL.md` (bucket section: serve-home note)

**Interfaces:**
- Consumes: everything above, as actually built (verify claims against the code before writing them).
- Produces: docs matching reality; the workspace fully green.

- [ ] **Step 1: Doc edits**

- ADR-0046 "As built" gains a dated P36b/P36c paragraph: checkpoint record (`SCWC`, seq/refs/cumulative-packs), refresh stops at `checkpoint_seq` and fails closed on absent/lying/bypassed checkpoints, `CHECKPOINT_INTERVAL = 64` opportunistic best-effort fold after commit; `ServeTransport` seam, `serve_bucket_with_policy`, `--store` flag, serve home carries tokens/TLS/tmp, strict consistency across instances (two-instance tests named).
- CLAUDE.md P36 row: replace "P36a built … checkpoints (P36b) and bucket-backed serve (P36c) pending" with "Bucket WAL remotes (sc+wal://, sc+s3://): immutable packs + CAS'd manifest, checkpoints + log-tail cold start, bucket-backed `sc serve --store` with disposable instances" (keep the ADR link). Standing-boundaries bullet gains: "`sc serve --store` still requires a local serve home with `.sc/` — tokens, TLS identity, and pack spills live there; the bucket holds all served content."
- ROADMAP Deferred: delete the "Checkpoint fold (P36b)" and "Bucket-backed serve (P36c)" entries; keep compaction/gc, leases, partial-clone, static bundles, GCS, S3 streaming, incremental refresh, batched negotiation; add "**Serve-side persistent pack cache (P36c follow-on).** A bucket-backed serve instance re-downloads packs per connection; a content-addressed on-disk cache in the serve home would make warm instances cheap without affecting correctness."
- THREAT-MODEL bucket section: one added sentence — the serve-home split (bucket = content, home = access-control state) and that a bucket-backed serve enforces the same P29/P31 gates against clients while itself trusting the bucket only as far as BLAKE3 + strict WAL decode allow (same reader defenses as any client).

- [ ] **Step 2: Full verification gate**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets && cargo fmt --all -- --check && cargo run --bin sc -- demo --agents 4`
Expected: all green; demo still proves zero residue. Paste the demo tail + workspace totals in the task report.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md ROADMAP.md docs
git commit -m "docs: ADR-0046 As-built P36b/c, CLAUDE.md P36 complete, ROADMAP/THREAT-MODEL (P36b+c)"
```
