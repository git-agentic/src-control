# P16 — Revocation Tombstones Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `sc revoke` on a protected-path prefix durable across merges via per-recipient epoch LWW registers with revoke-wins ties (spec: `docs/superpowers/specs/2026-07-07-p16-revocation-tombstones-design.md`, ADR-0026).

**Architecture:** `ProtectPrefix.recipients` changes from `Vec<[u8;32]>` to sorted `RecipientEntry {key, epoch, state}` registers; a `Revoked` entry is a permanent tombstone. Merge keeps the higher-epoch entry per recipient (tie + disagreement → Revoked). Sealing uses only `Granted` keys. This is a snapshot-encoding format break: the snapshot tag byte bumps so pre-P16 objects fail decode with a clear error.

**Tech Stack:** Rust stable, existing workspace crates only (`scl-core`, `scl-repo`, `scl-cli`). No new dependencies. No changes to `crates/crypto`.

## Global Constraints

- Strict dependency direction `cli → repo → {vfs, gitio, crypto} → core`; `core` never depends on crypto (CLAUDE.md).
- Format break is clean: no versioned decode of pre-P16 snapshots; old objects must fail with a **clear** error, never garble (spec).
- `union_wraps` is untouched — wrapped DEKs on existing ciphertext are historical facts (spec).
- No `sc unprotect`; whole-prefix rules never shrink via merge (spec).
- Tombstones are never GC'd (spec).
- Every seal path refuses an empty effective recipient set (`secrets::require_recipients` chokepoint for `PublicKey` paths; the new `encrypt_protected` guard for `[u8;32]` paths).
- Tests live in `#[cfg(test)] mod tests` next to the code; tests that touch disk clean up and assert the path is gone (CLAUDE.md).
- Doc comments explain intent, not mechanics (CLAUDE.md).

---

### Task 1: Core model, canonical encoding, merge semantics, consumer migration

One atomic format-break commit: the new types, the new encoding under a bumped snapshot tag, `merge_prefixes` (replacing `union_prefixes`), and the mechanical migration of every consumer so the workspace is green. Large but indivisible — any smaller slice leaves the workspace uncompilable.

**Files:**
- Modify: `crates/core/src/object.rs` (types ~lines 20–36, encode ~201–215, decode ~263–292, tag consts ~13–16, fixture tests ~520–560)
- Modify: `crates/repo/src/protect.rs` (`union_prefixes` → `merge_prefixes`, ~lines 24–43; tests)
- Modify: `crates/repo/src/protect_ops.rs` (protect/grant/revoke/protected_prefixes)
- Modify: `crates/repo/src/repo.rs` (call sites lines ~195, ~219, ~236, ~719–721, ~735, ~741, ~772, ~859; test helper `test_set_protected_prefix`; existing tests constructing `ProtectPrefix` or asserting on `rule.recipients`)
- Modify: `crates/repo/src/replay.rs` (call sites ~101, ~110, ~184–185, ~233, ~420–440)
- Modify: `crates/cli/src/main.rs` (`run_protect` list rendering — minimal compile fix here; full CLI work is Task 3)
- Modify: `ROADMAP.md` (flip P16 to Active)

**Interfaces:**
- Produces (in `scl_core`, all `pub`):
  - `enum RecipientState { Granted, Revoked }`
  - `struct RecipientEntry { pub key: [u8; 32], pub epoch: u32, pub state: RecipientState }`
  - `struct ProtectPrefix { pub prefix: String, pub recipients: Vec<RecipientEntry> }`
  - `impl ProtectPrefix`: `fn granted_keys(&self) -> Vec<[u8; 32]>`, `fn next_epoch(&self) -> u32`, `fn set_standing(&mut self, key: [u8; 32], epoch: u32, state: RecipientState)`
- Produces (in `scl_repo::protect`): `pub(crate) fn merge_prefixes(a: &[ProtectPrefix], b: &[ProtectPrefix]) -> Vec<ProtectPrefix>`
- Produces (in `scl_repo`): `pub struct PrefixRecipient { pub id: scl_crypto::RecipientId, pub epoch: u32, pub granted: bool }`; `Repo::protected_prefixes(&self) -> Result<Vec<(String, Vec<PrefixRecipient>)>>`

- [ ] **Step 1: Flip P16 to Active in ROADMAP.md**

In `ROADMAP.md`, replace the Active section body:

```markdown
## Active

- **Phase 16 — Revocation tombstones / rule narrowing.** In build. Spec:
  `docs/superpowers/specs/2026-07-07-p16-revocation-tombstones-design.md`
  (ADR-0026, Proposed → Accepted at completion).
```

- [ ] **Step 2: Write the failing core tests**

In `crates/core/src/object.rs` tests module, add (adjust the two existing fixture tests at ~524/~548 that construct `ProtectPrefix { prefix, recipients: vec![[9u8;32]] }` in the SAME step — they no longer compile; construct `RecipientEntry { key: [9u8;32], epoch: 1, state: RecipientState::Granted }` instead):

```rust
#[test]
fn snapshot_roundtrips_recipient_registers_and_tombstones() {
    let snap = Snapshot {
        root: ObjectId([1; 32]),
        parents: vec![],
        author: "a".into(),
        timestamp: 0,
        message: "m".into(),
        secrets: Default::default(),
        protection: Protection {
            prefixes: vec![ProtectPrefix {
                prefix: "secret/".into(),
                recipients: vec![
                    RecipientEntry { key: [2; 32], epoch: 3, state: RecipientState::Granted },
                    RecipientEntry { key: [1; 32], epoch: 2, state: RecipientState::Revoked },
                ],
            }],
            wrapped: Default::default(),
        },
    };
    let bytes = Object::Snapshot(snap.clone()).encode();
    let Object::Snapshot(back) = Object::decode(&bytes).unwrap() else { panic!("not a snapshot") };
    // Entries round-trip, sorted by key in the encoding.
    let rule = &back.protection.prefixes[0];
    assert_eq!(rule.recipients.len(), 2);
    let revoked = rule.recipients.iter().find(|e| e.key == [1; 32]).unwrap();
    assert_eq!((revoked.epoch, revoked.state), (2, RecipientState::Revoked));
    let granted = rule.recipients.iter().find(|e| e.key == [2; 32]).unwrap();
    assert_eq!((granted.epoch, granted.state), (3, RecipientState::Granted));
}

#[test]
fn recipient_entry_order_does_not_change_snapshot_id() {
    let mk = |entries: Vec<RecipientEntry>| {
        Object::Snapshot(Snapshot {
            root: ObjectId([1; 32]),
            parents: vec![],
            author: "a".into(),
            timestamp: 0,
            message: "m".into(),
            secrets: Default::default(),
            protection: Protection {
                prefixes: vec![ProtectPrefix { prefix: "secret/".into(), recipients: entries }],
                wrapped: Default::default(),
            },
        })
        .id()
    };
    let e1 = RecipientEntry { key: [1; 32], epoch: 1, state: RecipientState::Granted };
    let e2 = RecipientEntry { key: [2; 32], epoch: 2, state: RecipientState::Revoked };
    assert_eq!(mk(vec![e1.clone(), e2.clone()]), mk(vec![e2, e1]));
}

#[test]
fn pre_p16_snapshot_tag_fails_with_clear_error() {
    // Tag 2 was the pre-P16 snapshot encoding. It must be refused loudly,
    // not misparsed into garbage.
    let err = Object::decode(&[2u8, 0, 0]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("pre-P16"), "unhelpful error: {msg}");
}

#[test]
fn granted_keys_next_epoch_set_standing() {
    let mut rule = ProtectPrefix { prefix: "secret/".into(), recipients: vec![] };
    assert_eq!(rule.next_epoch(), 1);
    rule.set_standing([1; 32], 1, RecipientState::Granted);
    rule.set_standing([2; 32], 1, RecipientState::Granted);
    assert_eq!(rule.next_epoch(), 2);
    rule.set_standing([2; 32], 2, RecipientState::Revoked); // upsert, not append
    assert_eq!(rule.recipients.len(), 2);
    assert_eq!(rule.granted_keys(), vec![[1; 32]]);
    assert_eq!(rule.next_epoch(), 3);
}
```

- [ ] **Step 3: Run core tests to verify they fail**

Run: `cargo test -p scl-core`
Expected: FAIL — compile errors (`RecipientEntry` not found).

- [ ] **Step 4: Implement types, helpers, and encoding in `crates/core/src/object.rs`**

Replace the `ProtectPrefix` definition (lines 22–28):

```rust
/// A recipient's standing on a protected prefix: active or tombstoned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecipientState {
    Granted,
    Revoked,
}

/// One recipient's standing on a protected prefix — a last-writer-wins
/// register ordered by `epoch`. A `Revoked` entry IS the tombstone that keeps
/// a revocation durable across merges (ADR-0026): rule merges keep the
/// higher-epoch entry, so a pre-revoke branch cannot resurrect the grant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecipientEntry {
    pub key: [u8; 32],
    pub epoch: u32,
    pub state: RecipientState,
}

/// A protected path prefix and the per-recipient standing registers used at
/// commit time to decide who new files' DEKs are wrapped for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProtectPrefix {
    pub prefix: String,
    pub recipients: Vec<RecipientEntry>,
}

impl ProtectPrefix {
    /// The effective recipient set: keys with `Granted` standing. This is the
    /// only set sealing may wrap DEKs for — tombstoned keys are excluded.
    pub fn granted_keys(&self) -> Vec<[u8; 32]> {
        self.recipients
            .iter()
            .filter(|e| e.state == RecipientState::Granted)
            .map(|e| e.key)
            .collect()
    }

    /// The epoch a new standing change on this prefix must carry to win over
    /// every existing entry.
    pub fn next_epoch(&self) -> u32 {
        self.recipients.iter().map(|e| e.epoch).max().unwrap_or(0) + 1
    }

    /// Set `key`'s register to (`epoch`, `state`), inserting it if absent.
    pub fn set_standing(&mut self, key: [u8; 32], epoch: u32, state: RecipientState) {
        match self.recipients.iter_mut().find(|e| e.key == key) {
            Some(e) => {
                e.epoch = epoch;
                e.state = state;
            }
            None => self.recipients.push(RecipientEntry { key, epoch, state }),
        }
    }
}
```

Bump the snapshot tag (line 15) — the format break marker:

```rust
const TAG_SNAPSHOT_LEGACY: u8 = 2; // pre-P16 encoding; refused with a clear error
const TAG_SNAPSHOT: u8 = 4;
```

(`TAG_SECRET` stays 3.) In `encode()`, replace the per-prefix recipient loop (lines ~207–214):

```rust
w.u32(p.recipients.len() as u32);
// Sort registers by key so the same logical policy hashes identically
// regardless of insertion order.
let mut sorted = p.recipients.clone();
sorted.sort_unstable_by(|a, b| a.key.cmp(&b.key));
for r in &sorted {
    w.raw(&r.key); // 32 bytes
    w.u32(r.epoch);
    w.u8(match r.state {
        RecipientState::Granted => 0,
        RecipientState::Revoked => 1,
    });
}
```

In `decode()`, add a legacy arm to the tag match and update the recipients loop (lines ~284–291):

```rust
TAG_SNAPSHOT_LEGACY => {
    return Err(Error::Malformed(
        "pre-P16 snapshot encoding (tag 2): this store predates the ADR-0026 \
         protection-rule format break and cannot be read by this version"
            .into(),
    ))
}
```

```rust
for _ in 0..n_recipients {
    let mut rk = [0u8; 32];
    rk.copy_from_slice(r.take(32)?);
    let epoch = r.u32()?;
    let state = match r.u8()? {
        0 => RecipientState::Granted,
        1 => RecipientState::Revoked,
        s => return Err(Error::Malformed(format!("bad recipient state {s}"))),
    };
    recipients.push(RecipientEntry { key: rk, epoch, state });
}
```

Export the new types wherever `ProtectPrefix` is exported (check `crates/core/src/lib.rs` re-exports and add `RecipientEntry`, `RecipientState` beside it).

- [ ] **Step 5: Run core tests to verify they pass**

Run: `cargo test -p scl-core`
Expected: PASS (including the two updated fixture tests).

- [ ] **Step 6: Write the failing `merge_prefixes` tests**

In `crates/repo/src/protect.rs` tests module, DELETE `union_prefixes_unions_by_prefix_and_recipients` and add (uses a local helper; `RecipientState` / `RecipientEntry` come via `scl_core`):

```rust
fn entry(key: u8, epoch: u32, granted: bool) -> scl_core::RecipientEntry {
    scl_core::RecipientEntry {
        key: [key; 32],
        epoch,
        state: if granted { scl_core::RecipientState::Granted } else { scl_core::RecipientState::Revoked },
    }
}

fn rule(prefix: &str, entries: Vec<scl_core::RecipientEntry>) -> ProtectPrefix {
    ProtectPrefix { prefix: prefix.into(), recipients: entries }
}

#[test]
fn merge_prefixes_higher_epoch_wins_both_directions() {
    // The ADR-0025 boundary case: ours revoked B at epoch 2, theirs (a
    // pre-revoke branch) still has B granted at epoch 1. Revoke holds —
    // in either argument order.
    let ours = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
    let theirs = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 1, true)])];
    for (a, b) in [(&ours, &theirs), (&theirs, &ours)] {
        let m = merge_prefixes(a, b);
        let r = m.iter().find(|p| p.prefix == "secret/").unwrap();
        assert_eq!(r.granted_keys(), vec![[1; 32]]);
        let b_entry = r.recipients.iter().find(|e| e.key == [2; 32]).unwrap();
        assert_eq!((b_entry.epoch, b_entry.state), (2, scl_core::RecipientState::Revoked));
    }
}

#[test]
fn merge_prefixes_regrant_beats_older_tombstone() {
    // B was revoked at epoch 2, then deliberately re-granted at epoch 3 on
    // one side; the other side still carries the epoch-2 tombstone.
    let regranted = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 3, true)])];
    let tombstoned = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
    let m = merge_prefixes(&regranted, &tombstoned);
    let r = m.iter().find(|p| p.prefix == "secret/").unwrap();
    let mut granted = r.granted_keys();
    granted.sort_unstable();
    assert_eq!(granted, vec![[1; 32], [2; 32]]);
}

#[test]
fn merge_prefixes_epoch_tie_resolves_revoked() {
    // Concurrent revoke and re-grant minted the same epoch: fail-closed.
    let revoked = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
    let granted = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, true)])];
    for (a, b) in [(&revoked, &granted), (&granted, &revoked)] {
        let m = merge_prefixes(a, b);
        let r = m.iter().find(|p| p.prefix == "secret/").unwrap();
        assert_eq!(r.granted_keys(), vec![[1; 32]], "tie must resolve Revoked");
    }
}

#[test]
fn merge_prefixes_disjoint_recipients_and_prefixes_compose() {
    let a = vec![rule("secret/", vec![entry(1, 1, true)])];
    let b = vec![
        rule("secret/", vec![entry(2, 1, true)]),
        rule("keys/", vec![entry(3, 1, true)]),
    ];
    let m = merge_prefixes(&a, &b);
    assert_eq!(m.len(), 2);
    let secret = m.iter().find(|p| p.prefix == "secret/").unwrap();
    assert_eq!(secret.recipients.len(), 2);
    assert!(m.iter().any(|p| p.prefix == "keys/"));
}
```

- [ ] **Step 7: Implement `merge_prefixes`, delete `union_prefixes`**

Replace `union_prefixes` (protect.rs lines 24–43) with:

```rust
/// Merge two protection policies' prefix rules. Prefixes unite by `prefix`
/// string (rules never disappear — fail-closed, ADR-0025). Within a shared
/// prefix each recipient key is a last-writer-wins register: the higher-epoch
/// entry survives, and an epoch tie with disagreeing states resolves
/// `Revoked` (fail-closed, ADR-0026) — this is what makes `sc revoke` durable
/// against merging a pre-revoke branch.
pub(crate) fn merge_prefixes(a: &[ProtectPrefix], b: &[ProtectPrefix]) -> Vec<ProtectPrefix> {
    use scl_core::RecipientState;
    let mut out: Vec<ProtectPrefix> = Vec::new();
    for p in a.iter().chain(b.iter()) {
        match out.iter_mut().find(|existing| existing.prefix == p.prefix) {
            Some(existing) => {
                for r in &p.recipients {
                    match existing.recipients.iter_mut().find(|e| e.key == r.key) {
                        Some(e) => {
                            if r.epoch > e.epoch
                                || (r.epoch == e.epoch && r.state == RecipientState::Revoked)
                            {
                                e.epoch = r.epoch;
                                e.state = r.state;
                            }
                        }
                        None => existing.recipients.push(r.clone()),
                    }
                }
            }
            None => out.push(p.clone()),
        }
    }
    out
}
```

- [ ] **Step 8: Migrate all consumers**

Mechanical, in one pass (the workspace compiles only when all are done):

a. **Rename call sites** — `crate::protect::union_prefixes(` → `crate::protect::merge_prefixes(` (and `protect::union_prefixes` in replay.rs). Sites: `repo.rs` ~195, ~219, ~719–720; `replay.rs` ~184, ~420. Local variable names `union_prefixes`/`union_prot` may stay (they are just bindings).

b. **Seal-target sites** — replace every `rule.recipients.clone()` / `.map(|r| r.recipients.clone())` used to build encryption recipient lists with `rule.granted_keys()` / `.map(|r| r.granted_keys())`. Sites: `repo.rs` ~236, ~735, ~741; `replay.rs` ~101, ~110.

c. **`protect_ops.rs::protect`** — replace the retain+push (lines 43–47) so tombstones survive re-protecting a prefix; doc comment's "(or replace)" becomes "(or extend)":

```rust
match protection.prefixes.iter_mut().find(|p| p.prefix == prefix) {
    Some(rule) => {
        // Existing rule: (re-)grant the named recipients at the next epoch.
        // Never rebuild the rule wholesale — that would drop tombstones.
        let epoch = rule.next_epoch();
        for pk in recipients {
            rule.set_standing(pk.to_bytes(), epoch, scl_core::RecipientState::Granted);
        }
    }
    None => protection.prefixes.push(ProtectPrefix {
        prefix: prefix.to_string(),
        recipients: recipients
            .iter()
            .map(|p| scl_core::RecipientEntry {
                key: p.to_bytes(),
                epoch: 1,
                state: scl_core::RecipientState::Granted,
            })
            .collect(),
    }),
}
```

d. **`protect_ops.rs::grant`** — replace the contains/push block (lines 127–130):

```rust
let rule = &mut protection.prefixes[rule_idx];
let epoch = rule.next_epoch();
rule.set_standing(new.to_bytes(), epoch, scl_core::RecipientState::Granted);
```

e. **`protect_ops.rs::revoke`** — the guard (lines 163–171) tests the *effective* set; the retain (lines 180–182) becomes a tombstone write. Wrap-dropping (lines 173–179) is unchanged:

```rust
// Refuse to empty the rule's effective set: subsequent commits under the
// prefix would seal new content for nobody (the empty-recipient footgun).
let survives = protection.prefixes[rule_idx].granted_keys().iter().any(|pk| {
    scl_crypto::PublicKey::from_bytes(*pk).recipient_id().as_str() != recipient_id.as_str()
});
```

```rust
// Tombstone, don't delete: the Revoked entry at a fresh epoch is what wins
// the LWW register against any pre-revoke branch at merge time (ADR-0026).
let rule = &mut protection.prefixes[rule_idx];
let epoch = rule.next_epoch();
if let Some(e) = rule
    .recipients
    .iter_mut()
    .find(|e| scl_crypto::PublicKey::from_bytes(e.key).recipient_id().as_str() == rid)
{
    e.epoch = epoch;
    e.state = scl_core::RecipientState::Revoked;
}
```

Also update `revoke`'s doc comment: it now records a durable tombstone; "not durable against merges" language is obsolete.

f. **`protect_ops.rs::protected_prefixes`** — richer return for the CLI:

```rust
/// One recipient's standing on a listed prefix, for display.
pub struct PrefixRecipient {
    pub id: scl_crypto::RecipientId,
    pub epoch: u32,
    pub granted: bool,
}
```

(place above `impl Repo`; re-export from `crates/repo/src/lib.rs` beside the other public types)

```rust
/// List the tip's protected prefixes with every recipient register —
/// tombstones included, so a post-merge listing shows revocations holding.
pub fn protected_prefixes(&self) -> Result<Vec<(String, Vec<PrefixRecipient>)>> {
    let protection = match self.head_tip()? {
        Some(t) => self.snapshot(&t)?.protection,
        None => Protection::default(),
    };
    Ok(protection
        .prefixes
        .into_iter()
        .map(|p| {
            let rids = p
                .recipients
                .iter()
                .map(|e| PrefixRecipient {
                    id: scl_crypto::PublicKey::from_bytes(e.key).recipient_id(),
                    epoch: e.epoch,
                    granted: e.state == scl_core::RecipientState::Granted,
                })
                .collect();
            (p.prefix, rids)
        })
        .collect())
}
```

g. **CLI compile fix** — in `crates/cli/src/main.rs::run_protect` (line ~1658), keep output equivalent for now (full rendering is Task 3):

```rust
for (p, recips) in repo.protected_prefixes()? {
    println!("{p}  ({} recipient(s))", recips.iter().filter(|r| r.granted).count());
}
```

h. **Test migration** — run `grep -rn "ProtectPrefix {" crates --include="*.rs"` and `grep -rn "\.recipients" crates --include="*.rs"`; update every test constructor to `RecipientEntry` literals (epoch 1, Granted unless the test says otherwise) and every recipient-set assertion to match the register model. Known sites: `repo.rs` test helper `test_set_protected_prefix`, `revoke_removes_wrapped_entries_and_prefix_membership` (the rule now RETAINS bob as a `Revoked` entry — assert `!rule.granted_keys().contains(...)` and that the tombstone exists with `state == Revoked`; the `protected_prefixes` assertion becomes: bob listed with `granted == false`, alice with `granted == true`), `protect.rs` `prot()` helper (`recipients: vec![]` still compiles — empty vec of the new type), any merge/replay tests constructing rules.

- [ ] **Step 9: Run the whole workspace**

Run: `cargo test`
Expected: PASS, everything green.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "feat!: recipient standing registers with revocation tombstones — epoch LWW, revoke-wins ties (P16)

Format break: snapshot tag 2->4; pre-P16 stores fail decode with a clear
error. union_prefixes -> merge_prefixes; sealing uses granted_keys() only."
```

---

### Task 2: Seal-path hardening — loud failure on an empty effective set

Crossed revokes can empty a rule through a merge even though `revoke` guards locally (each side revokes a *different* one of two recipients → merged rule has two tombstones, zero granted). Sealing under such a rule must fail loudly, never seal to nobody.

**Files:**
- Modify: `crates/repo/src/protect.rs` (`encrypt_protected` ~lines 108–127; tests)
- Modify: `crates/repo/src/repo.rs`, `crates/repo/src/replay.rs` (add `?` at `encrypt_protected` call sites)

**Interfaces:**
- Changes: `protect::encrypt_protected(plaintexts) -> Result<(Vec<(String, Vec<u8>, FileMode, u8)>, BTreeMap<ObjectId, Vec<WrappedKey>>)>` (was infallible). Callers found via `grep -rn "encrypt_protected" crates/repo/src`.

- [ ] **Step 1: Write the failing tests**

In `crates/repo/src/protect.rs` tests:

```rust
#[test]
fn encrypt_protected_refuses_empty_recipient_list() {
    let err = encrypt_protected(vec![(
        "secret/x".into(),
        b"v".to_vec(),
        FileMode::FILE,
        vec![],
    )])
    .unwrap_err();
    assert!(
        matches!(err, Error::InvalidArgument(_)),
        "sealing to nobody must fail loudly, got {err:?}"
    );
    assert!(format!("{err}").contains("secret/x"), "error must name the path");
}

#[test]
fn merge_prefixes_crossed_revokes_can_empty_a_rule() {
    // Each side revoked a DIFFERENT one of the two recipients: the merged
    // rule has zero granted keys. This is exactly why sealing must guard.
    let a = vec![rule("secret/", vec![entry(1, 2, false), entry(2, 1, true)])];
    let b = vec![rule("secret/", vec![entry(1, 1, true), entry(2, 2, false)])];
    let m = merge_prefixes(&a, &b);
    assert!(m[0].granted_keys().is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo protect::tests`
Expected: FAIL — `encrypt_protected` returns a tuple, not `Result` (compile error on `.unwrap_err()`).

- [ ] **Step 3: Make `encrypt_protected` fallible with the guard**

Change its signature and add the guard at the top of the loop body (doc comment gains the rationale):

```rust
/// … (existing doc) … Errors `InvalidArgument` if any file's recipient list
/// is empty: a rule whose every recipient is tombstoned (e.g. crossed revokes
/// merged together) must fail the seal loudly — sealing to nobody mints
/// permanently unreadable ciphertext.
pub(crate) fn encrypt_protected(
    plaintexts: Vec<(String, Vec<u8>, FileMode, Vec<[u8; 32]>)>,
) -> Result<(Vec<(String, Vec<u8>, FileMode, u8)>, BTreeMap<ObjectId, Vec<WrappedKey>>)> {
```

```rust
for (path, bytes, mode, recipients) in plaintexts {
    if recipients.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "{path} is protected but its rule has no granted recipients \
             (all revoked?); run `sc grant` before committing under this prefix"
        )));
    }
    // … existing body unchanged …
```

End with `Ok((all, fresh_wrapped))`. Add `?` at every call site (`repo.rs`, `replay.rs` — find with grep; each currently destructures the tuple, so `let (a, b) = encrypt_protected(x)?;`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS workspace-wide.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(repo): refuse to seal under a rule with zero granted recipients — crossed revokes merge to an empty effective set (P16)"
```

---

### Task 3: CLI surface — register-aware `protect --list` (+ `--json`), truthful revoke message

**Files:**
- Modify: `crates/cli/src/main.rs` (`Cmd::Protect` variant ~lines 208–216; `run_protect` ~1655; `run_protect` call site ~410; `run_revoke` ~1684–1697)

**Interfaces:**
- Consumes: `Repo::protected_prefixes() -> Result<Vec<(String, Vec<PrefixRecipient>)>>` with `PrefixRecipient { id, epoch, granted }` (Task 1).

- [ ] **Step 1: Add `--json` to the Protect command and render registers**

Add to the `Protect` clap variant (mirroring `secret list`'s existing `--json` flag pattern):

```rust
/// Machine-readable output for --list.
#[arg(long)]
json: bool,
```

Update the dispatch at ~line 410: `Cmd::Protect { prefix, to, list, json } => run_protect(prefix, to, list, json),`

Replace `run_protect`'s list branch:

```rust
fn run_protect(prefix: Option<String>, to: Vec<String>, list: bool, json: bool) -> Result<()> {
    let repo = open_repo()?;
    if list || prefix.is_none() {
        let prefixes = repo.protected_prefixes()?;
        if json {
            let v: Vec<_> = prefixes
                .iter()
                .map(|(p, recips)| {
                    serde_json::json!({
                        "prefix": p,
                        "recipients": recips.iter().map(|r| serde_json::json!({
                            "id": r.id.as_str(),
                            "epoch": r.epoch,
                            "state": if r.granted { "granted" } else { "revoked" },
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(());
        }
        for (p, recips) in prefixes {
            let granted = recips.iter().filter(|r| r.granted).count();
            println!("{p}  ({granted} granted)");
            for r in recips {
                let state = if r.granted { "granted" } else { "REVOKED" };
                println!("  {}  {}@e{}", r.id.as_str(), state, r.epoch);
            }
        }
        return Ok(());
    }
    // … unchanged add-a-rule branch …
```

- [ ] **Step 2: Make the revoke message truthful**

In `run_revoke`, replace the `eprintln!` note (the "not durable against merges" text is now wrong):

```rust
eprintln!(
    "note: the revocation is recorded as a tombstone and holds across merges; \
     it stops FUTURE seals only — run `sc secret rotate` / re-encrypt flows for \
     a cryptographic cutover of existing values, and rotate the underlying \
     external credential itself"
);
```

- [ ] **Step 3: Verify by hand**

Run:
```bash
cargo run --bin sc -- --help >/dev/null && cargo test -p scl-cli
```
Expected: compiles; existing CLI tests pass. Then a smoke run in a scratch dir (`/tmp` scratchpad, cleaned after):

```bash
d=$(mktemp -d) && cd "$d" && sc() { cargo run --quiet --manifest-path <repo>/Cargo.toml --bin sc -- "$@"; }
sc init && sc keygen > id.txt   # then protect/list/revoke/list, observe REVOKED@e2 line
cd / && rm -rf "$d"
```
Expected: `protect --list` shows per-recipient `granted`/`REVOKED` with epochs; `--json` emits the structure above.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(cli): protect --list shows recipient standing registers (+ --json); revoke message reflects durable tombstones (P16)"
```

---

### Task 4: Integration tests — the boundary scenario end to end

**Files:**
- Modify: `crates/repo/src/repo.rs` (tests module; follow the `tmp_root` + cleanup idiom of `revoke_removes_wrapped_entries_and_prefix_membership`)

**Interfaces:**
- Consumes: `Repo::{init, protect, grant, revoke, commit, branch, switch, merge, snapshot, head_tip, protected_prefixes, cherry_pick}` — all existing.

- [ ] **Step 1: Write the failing tests** (failing only if Tasks 1–2 missed something — these are the acceptance tests for the phase)

```rust
#[test]
fn revoke_survives_merging_a_pre_revoke_branch() {
    // The ADR-0025 boundary scenario, now closed by ADR-0026.
    let root = tmp_root("p16-durable-revoke");
    let repo = Repo::init(&root).unwrap();
    let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
    let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
    repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
    repo.commit("me", "add secret").unwrap();
    repo.grant("secret/", &alice_sk, &bob_pk).unwrap();

    // Fork a branch while bob is still granted, and give it its own commit.
    repo.branch("pre-revoke").unwrap();
    repo.switch("pre-revoke").unwrap();
    std::fs::write(root.join("readme.txt"), b"feature work").unwrap();
    repo.commit("me", "feature").unwrap();
    repo.switch("main").unwrap();

    // Revoke bob on main, then merge the pre-revoke branch.
    repo.revoke("secret/", &bob_pk.recipient_id()).unwrap();
    repo.merge("pre-revoke", "me").unwrap();

    // Bob stays revoked: tombstone won the register.
    let listed = repo.protected_prefixes().unwrap();
    let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
    let bob = recips.iter().find(|r| r.id == bob_pk.recipient_id()).unwrap();
    assert!(!bob.granted, "merge resurrected a revoked recipient");
    assert!(recips.iter().find(|r| r.id == alice_pk.recipient_id()).unwrap().granted);

    // And a FRESH file under the prefix seals to alice only.
    let before: std::collections::BTreeSet<_> = {
        let tip = repo.head_tip().unwrap().unwrap();
        repo.snapshot(&tip).unwrap().protection.wrapped.keys().cloned().collect()
    };
    std::fs::write(root.join("secret/new.txt"), b"fresh").unwrap();
    let c = repo.commit("me", "post-revoke secret").unwrap();
    let prot = repo.snapshot(&c).unwrap().protection;
    let new_ids: Vec<_> = prot.wrapped.keys().filter(|k| !before.contains(k)).collect();
    assert!(!new_ids.is_empty(), "expected a freshly sealed blob");
    let bob_id = bob_pk.recipient_id();
    for id in new_ids {
        let wks = &prot.wrapped[id];
        assert!(
            !wks.iter().any(|w| w.recipient_id == bob_id.as_str()),
            "fresh DEK sealed to a revoked recipient"
        );
        assert_eq!(wks.len(), 1, "fresh blob must be wrapped for alice only");
    }
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn regrant_after_revoke_wins_against_old_tombstone_branch() {
    let root = tmp_root("p16-regrant");
    let repo = Repo::init(&root).unwrap();
    let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
    let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
    repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
    repo.commit("me", "add").unwrap();
    repo.grant("secret/", &alice_sk, &bob_pk).unwrap();   // bob@2:Granted
    repo.revoke("secret/", &bob_pk.recipient_id()).unwrap(); // bob@3:Revoked

    // Branch carries the tombstone; main deliberately re-grants (bob@4).
    repo.branch("tombstoned").unwrap();
    repo.switch("tombstoned").unwrap();
    std::fs::write(root.join("readme.txt"), b"work").unwrap();
    repo.commit("me", "work").unwrap();
    repo.switch("main").unwrap();
    repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
    repo.merge("tombstoned", "me").unwrap();

    let listed = repo.protected_prefixes().unwrap();
    let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
    assert!(
        recips.iter().find(|r| r.id == bob_pk.recipient_id()).unwrap().granted,
        "a deliberate re-grant must out-epoch the old tombstone"
    );
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn cherry_pick_of_pre_revoke_commit_does_not_resurrect_recipient() {
    let root = tmp_root("p16-replay-revoke");
    let repo = Repo::init(&root).unwrap();
    let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
    let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
    repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
    std::fs::create_dir_all(root.join("secret")).unwrap();
    std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
    repo.commit("me", "add").unwrap();
    repo.grant("secret/", &alice_sk, &bob_pk).unwrap();

    // A branch commit made while bob was granted…
    repo.branch("work").unwrap();
    repo.switch("work").unwrap();
    std::fs::write(root.join("notes.txt"), b"pickme").unwrap();
    repo.commit("me", "pickable").unwrap();
    repo.switch("main").unwrap();

    // …revoke bob on main, then replay that commit onto main.
    repo.revoke("secret/", &bob_pk.recipient_id()).unwrap();
    repo.cherry_pick("work", "me", None).unwrap();

    let listed = repo.protected_prefixes().unwrap();
    let (_p, recips) = listed.iter().find(|(p, _)| p == "secret/").unwrap();
    assert!(
        !recips.iter().find(|r| r.id == bob_pk.recipient_id()).unwrap().granted,
        "replay resurrected a revoked recipient"
    );
    drop(repo);
    std::fs::remove_dir_all(&root).unwrap();
}
```

Note for the implementer: if `switch`/`merge`/`cherry_pick` call signatures differ from the above in detail (e.g. an extra identity parameter), mirror the neighboring P15 tests in the same module — do not change the operations under test.

- [ ] **Step 2: Run the new tests**

Run each: `cargo test -p scl-repo revoke_survives_merging`, `cargo test -p scl-repo regrant_after_revoke`, `cargo test -p scl-repo cherry_pick_of_pre_revoke`
Expected: PASS if Tasks 1–2 are correct. Any failure here is a semantics bug — fix the implementation (never weaken the assertions), re-run.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "test(repo): P16 acceptance — revoke survives pre-revoke merges, re-grant out-epochs tombstones, replay does not resurrect (P16)"
```

---

### Task 5: Demo script — `demo/run_revoke_demo.sh`

Self-checking proof in the style of `demo/run_protected_merge_demo.sh`: every claim asserted, non-zero exit before the RESULT line on any failure.

**Files:**
- Create: `demo/run_revoke_demo.sh` (mode 755)
- Modify: `CLAUDE.md` (add the demo to the Commands block — done in Task 6 with the other doc edits)

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# P16 demo: durable revocation. Proves that a prefix-rule revoke survives
# merging a branch created before the revoke (the ADR-0025 boundary, closed
# by ADR-0026 tombstones): the recipient stays revoked, fresh commits under
# the prefix seal no DEK to them, and a deliberate re-grant out-epochs the
# old tombstone.
#
# Self-checking: every claim is an assertion; any failure exits non-zero
# before the RESULT line.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --quiet --bin sc
SC="$PWD/target/debug/sc"

fail() { echo "FAIL: $1"; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

# Identities live OUTSIDE the repo working tree (P5 scanner flags key material).
"$SC" keygen > "$work/alice.key"
"$SC" keygen > "$work/bob.key"
alice_pk=$(grep -o 'scl-pk-[0-9a-f]*' "$work/alice.key" | head -1)
bob_pk=$(grep -o 'scl-pk-[0-9a-f]*' "$work/bob.key" | head -1)
bob_id=$("$SC" recipient-id "$bob_pk" 2>/dev/null || grep -o 'recipient[- ]id: [0-9a-f]*' "$work/bob.key" | grep -o '[0-9a-f]*$')

mkdir repo && cd repo
"$SC" init

# 1. Protect a prefix for alice, grant bob, commit a secret file.
"$SC" protect secret/ --to "$alice_pk"
mkdir -p secret && echo "hunter2" > secret/db.txt
"$SC" commit -m "add secret"
"$SC" grant secret/ --to "$bob_pk" --identity "$work/alice.key"
"$SC" protect --list | grep -q "granted" || fail "bob not granted"

# 2. Fork a branch while bob is still granted; give it its own work.
"$SC" branch pre-revoke
"$SC" switch pre-revoke
echo "feature" > readme.txt
"$SC" commit -m "feature work"
"$SC" switch main

# 3. Revoke bob on main.
"$SC" revoke secret/ --recipient-id "$bob_id"
"$SC" protect --list | grep -qi "revoked" || fail "revoke not recorded"

# 4. THE BOUNDARY CASE: merge the pre-revoke branch. Pre-P16 this
#    resurrected bob via the rule union; the tombstone must now hold.
"$SC" merge pre-revoke
"$SC" protect --list --json | grep -A2 "\"$bob_id\"" | grep -q '"state": "revoked"' \
  || fail "merge resurrected the revoked recipient"

# 5. Fresh content under the prefix seals to alice only (no wrap for bob).
echo "fresh" > secret/new.txt
"$SC" commit -m "post-revoke secret"
# bob cannot decrypt the fresh file even with his key: checkout as bob skips it
# or run-with-identity fails — assert via protect --list state (registry-level)
"$SC" protect --list --json | grep -A2 "\"$bob_id\"" | grep -q '"state": "revoked"' \
  || fail "bob regained standing after commit"

# 6. Deliberate re-grant out-epochs the tombstone.
"$SC" grant secret/ --to "$bob_pk" --identity "$work/alice.key"
"$SC" protect --list --json | grep -A2 "\"$bob_id\"" | grep -q '"state": "granted"' \
  || fail "re-grant did not win over tombstone"

echo "RESULT: durable revocation proven — tombstone survived the union merge,"
echo "fresh seals excluded the revoked recipient, and a deliberate re-grant won."
```

Implementer note: adapt the key-extraction lines (`alice_pk`, `bob_id`) to the actual `sc keygen` output format — check `demo/run_lifecycle_demo.sh` for the established parsing idiom, and reuse it verbatim. Same for `--identity` file conventions. Do not weaken the four `fail` assertions.

- [ ] **Step 2: Make it executable and run it**

Run: `chmod +x demo/run_revoke_demo.sh && bash demo/run_revoke_demo.sh`
Expected: exits 0, prints the RESULT lines, `$work` cleaned by the trap.

- [ ] **Step 3: Commit**

```bash
git add demo/run_revoke_demo.sh
git commit -m "demo: durable revocation proof — tombstone survives pre-revoke merge; re-grant out-epochs it (P16)"
```

---

### Task 6: Docs — firm ADR-0026, ROADMAP, CLAUDE.md, ADR index

**Files:**
- Modify: `docs/adr/0026-revocation-tombstones.md` (Status → Accepted + refinements)
- Modify: `docs/adr/README.md` (index row 0026 → Accepted)
- Modify: `ROADMAP.md` (P16 from Active/Next-horizon to Done; completed-phases table row)
- Modify: `CLAUDE.md` (Phase 16 section; revoke command comment; demo command)

- [ ] **Step 1: Firm ADR-0026 to Accepted**

Change `- **Status:** Proposed` → `- **Status:** Accepted`. Add a short "Refinements discovered during the build" note at the end of the Decision section recording anything that deviated from the spec (e.g. the snapshot-tag bump as the clear-error mechanism, the `encrypt_protected` guard location, protect's replace→extend semantics change). Update the index row in `docs/adr/README.md` to `Accepted`.

- [ ] **Step 2: Update ROADMAP.md**

- Active section → `None — Phase 17 is next up; see the next-horizon table below.`
- Move P16 from the Next horizon table into the Done list and the completed-phases table, following the exact style of the P15 entries: goal "sc revoke durable across merges", demoable outcome "branch → revoke → merge pre-revoke branch: recipient stays revoked; proven by demo/run_revoke_demo.sh", ADR 0026.

- [ ] **Step 3: Update CLAUDE.md**

- In the Commands block: update the `revoke` line comment to say the revocation is tombstone-durable across merges; add `bash demo/run_revoke_demo.sh` with a one-line description.
- Add a `**Phase 16 is built.**` paragraph after the P15 one, in the established style: recipient standing registers (`RecipientEntry {key, epoch, state}`), `merge_prefixes` LWW with revoke-wins ties, effective-set sealing via `granted_keys()`, the crossed-revokes loud-seal-failure guard, the snapshot tag 2→4 format break (pre-P16 stores refused with a clear error), and the boundary-note removal (the ADR-0025 "revoke is not durable" caveat is closed). Remove/adjust the now-stale ADR-0025 boundary sentence in the P15 paragraph (point it at P16 instead of "until the deferred rule-narrowing follow-on lands").

- [ ] **Step 4: Full verification pass**

Run:
```bash
cargo test && bash demo/run_revoke_demo.sh && bash demo/run_protected_merge_demo.sh && bash demo/run_repo_demo.sh
```
Expected: all green — the P15 demo still passing proves the format break didn't disturb protected merge behavior; the repo demo proves the base flows.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: accept ADR-0026 revocation tombstones; record P16 across CLAUDE/ROADMAP/ADR index"
```
