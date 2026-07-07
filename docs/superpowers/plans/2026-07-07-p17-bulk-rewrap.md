# P17 — Bulk Re-wrap + Multi-Key Escrow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sc rewrap --identity <key> [--dry-run]` re-seals every secret and replaces every protected blob's wrap list at the tip in one undoable commit, and escrow grows to a managed key list (spec: `docs/superpowers/specs/2026-07-07-p17-bulk-rewrap-design.md`, ADR-0027).

**Architecture:** A new `crates/repo/src/rewrap.rs` module (the `impl Repo` extension pattern of `secrets.rs`/`protect_ops.rs`) composes existing primitives: secrets re-seal via `scl_crypto::open` + `seal` (fresh DEK), protected blobs via the `grant`-style wrap lookup + `wrap_dek_for`, all folded into ONE `commit_snapshot` + one oplog record. The CLI grows the escrow list surface (back-compat TOML parse) and the `rewrap` command with skip-and-report exit semantics.

**Tech Stack:** Rust stable, existing workspace crates only. `crates/crypto` untouched.

## Global Constraints

- `crates/crypto` unchanged — pure composition of existing `seal`/`open`/`unwrap_dek_with`/`wrap_dek_for` (spec).
- One commit, one oplog record; ref update is the atomic commit point (spec).
- Root tree byte-identical across rewrap — policy-only; assert in tests (spec).
- Skip-and-report: commit what succeeded, report each skipped entry (name/path + reason), exit non-zero when incomplete; `--dry-run` prints the same report, commits nothing, same exit semantics (spec).
- Decrypted values/DEKs stay in `Zeroizing` buffers; plaintext never written to CAS or disk (spec).
- `secrets::require_recipients` on every secret reseal; empty-granted rules reported (pointing at `sc grant`), never sealed to nobody (spec).
- Old escrow TOML form (`[escrow] key = "…"`) still read; migrated to `keys = […]` on next write (spec).
- Tests live in `#[cfg(test)] mod tests` next to the code; disk tests clean up and assert removal (CLAUDE.md).
- Strict dependency direction `cli → repo → {vfs, gitio, crypto} → core` (CLAUDE.md).

---

### Task 1: Multi-key escrow — TOML model, loader, CLI ops

**Files:**
- Modify: `crates/cli/src/main.rs` (`RecipientsFile`/`EscrowEntry` ~lines 692–705, `load_escrow` ~723–740, `append_escrow` ~1411, `EscrowOp` clap enum ~260–276, `run_escrow` ~1253–1295, every `load_escrow`/`append_escrow` call site — find with `grep -n "load_escrow\|append_escrow" crates/cli/src/main.rs`)
- Modify: `ROADMAP.md` (flip P17 to Active)

**Interfaces:**
- Produces: `fn load_escrows(path: &Path) -> Result<Vec<scl_crypto::PublicKey>>` (replaces `load_escrow`; returns ALL escrow keys, empty vec when none), `fn append_escrow(pks: Vec<PublicKey>, escrows: &[PublicKey]) -> Vec<PublicKey>` (appends all, deduped by recipient_id). Task 3 consumes both.

- [ ] **Step 1: Flip P17 to Active in ROADMAP.md**

Replace the Active section body:

```markdown
## Active

- **Phase 17 — Bulk re-wrap + multiple escrow keys.** In build. Spec:
  `docs/superpowers/specs/2026-07-07-p17-bulk-rewrap-design.md`
  (ADR-0027, Proposed → Accepted at completion).
```

(Also remove the P17 row from the "Next horizon" table and retitle it P18–P20, adjusting its intro the way the P16 completion commit did for P17.)

- [ ] **Step 2: Write the failing tests**

In `crates/cli/src/main.rs`'s existing `#[cfg(test)] mod tests` (find it with `grep -n "mod tests" crates/cli/src/main.rs`; if the escrow helpers are free functions tested there, follow suit):

```rust
#[test]
fn escrow_toml_reads_old_single_key_form() {
    let dir = std::env::temp_dir().join(format!("scl-escrow-old-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("recipients.toml");
    let (_sk, pk) = scl_crypto::generate_keypair();
    std::fs::write(&path, format!("[escrow]\nkey = \"{}\"\n", pk.to_key_string())).unwrap();
    let keys = load_escrows(&path).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].recipient_id(), pk.recipient_id());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn escrow_toml_reads_list_form_and_missing_is_empty() {
    let dir = std::env::temp_dir().join(format!("scl-escrow-list-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("recipients.toml");
    let (_s1, p1) = scl_crypto::generate_keypair();
    let (_s2, p2) = scl_crypto::generate_keypair();
    std::fs::write(
        &path,
        format!("[escrow]\nkeys = [\"{}\", \"{}\"]\n", p1.to_key_string(), p2.to_key_string()),
    )
    .unwrap();
    let keys = load_escrows(&path).unwrap();
    assert_eq!(keys.len(), 2);
    // Missing file → empty, not an error.
    assert!(load_escrows(&dir.join("absent.toml")).unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn append_escrow_appends_all_deduped() {
    let (_s1, p1) = scl_crypto::generate_keypair();
    let (_s2, p2) = scl_crypto::generate_keypair();
    let out = append_escrow(vec![p1.clone()], &[p1.clone(), p2.clone()]);
    assert_eq!(out.len(), 2, "p1 deduped, p2 appended");
    assert!(out.iter().any(|k| k.recipient_id() == p2.recipient_id()));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p scl-cli escrow`
Expected: FAIL — `load_escrows` not found (and `append_escrow` has the old single-`Option` signature).

- [ ] **Step 4: Implement the model + loader + writer**

Replace `EscrowEntry`/the `escrow` field with a back-compat section (serde handles both forms):

```rust
/// The `[escrow]` section: historically a single `key = "scl-pk-…"`, now a
/// `keys = […]` list. Both forms parse; writes always emit `keys` (P17).
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct EscrowSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    keys: Vec<String>,
}
```

(`RecipientsFile.escrow: Option<EscrowSection>` — field name unchanged so `[escrow]` still maps.)

```rust
/// All configured escrow public keys (old `key` + new `keys`, deduped, in
/// file order). Missing file or section → empty vec.
fn load_escrows(path: &std::path::Path) -> Result<Vec<scl_crypto::PublicKey>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let parsed: RecipientsFile = toml::from_str(&text)?;
    let Some(section) = parsed.escrow else { return Ok(Vec::new()) };
    let mut out: Vec<scl_crypto::PublicKey> = Vec::new();
    for k in section.key.iter().chain(section.keys.iter()) {
        let pk = scl_crypto::PublicKey::from_key_string(k)
            .map_err(|_| anyhow::anyhow!("bad escrow public key"))?;
        if !out.iter().any(|e| e.recipient_id() == pk.recipient_id()) {
            out.push(pk);
        }
    }
    Ok(out)
}
```

Update `append_escrow` to the slice form:

```rust
/// Append every escrow key to a seal recipient set, deduped by recipient id.
fn append_escrow(
    mut pks: Vec<scl_crypto::PublicKey>,
    escrows: &[scl_crypto::PublicKey],
) -> Vec<scl_crypto::PublicKey> {
    for e in escrows {
        if !pks.iter().any(|p| p.recipient_id() == e.recipient_id()) {
            pks.push(e.clone());
        }
    }
    pks
}
```

Update every `load_escrow(...)` call site to `load_escrows(...)` and every `append_escrow(pks, escrow_option)` to `append_escrow(pks, &escrows)` — sites are in `run_protect`, `run_secret` (add/rotate), and the recipient-id resolution pool (~line 1221–1234: the pool extends with ALL escrow keys now). Delete the old `load_escrow` and `EscrowEntry`.

- [ ] **Step 5: Extend the `EscrowOp` clap enum and `run_escrow`**

```rust
enum EscrowOp {
    /// Replace the whole escrow list with this one key (back-compat sugar).
    Set { key_or_name: String },
    /// Append a key to the escrow list (deduped).
    Add { key_or_name: String },
    /// Remove one escrow key by recipient id or [recipients] name.
    Remove { id_or_name: String },
    /// List the configured escrow keys.
    Show,
}
```

In `run_escrow`, factor the existing pubkey-or-name resolution into a closure/helper (it's the same for Set and Add), and the file round-trip into read-modify-write of `EscrowSection` where the write always normalizes to `keys` (`key: None`):

```rust
fn write_escrow_keys(path: &std::path::Path, keys: Vec<scl_crypto::PublicKey>) -> Result<()> {
    let mut file: RecipientsFile = match std::fs::read_to_string(path) {
        Ok(t) => toml::from_str(&t)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RecipientsFile::default(),
        Err(e) => return Err(e.into()),
    };
    file.escrow = if keys.is_empty() {
        None
    } else {
        Some(EscrowSection {
            key: None,
            keys: keys.iter().map(|k| k.to_key_string()).collect(),
        })
    };
    std::fs::write(path, toml::to_string(&file)?)?;
    Ok(())
}
```

- `Set` → `write_escrow_keys(path, vec![pk])`, print `escrow set to <rid>`.
- `Add` → load current, dedupe-append, write; print `escrow key added: <rid> (<N> total)`.
- `Remove` → resolve `id_or_name` to a recipient id (try `RecipientId::from_hex`, else look the name up in `[recipients]` and take its key's id); drop the matching entry; error `anyhow!("'<arg>' is not an escrow key")` when absent; print `escrow key removed: <rid> (<N> remain)`.
- `Show` → list every key (`to_key_string` + recipient id per line) followed by the existing policy-not-enforcement note; `no escrow keys set` when empty.

- [ ] **Step 6: Run tests + workspace**

Run: `cargo test -p scl-cli escrow` then `cargo test`
Expected: new tests PASS; whole workspace green (the P11 lifecycle demo still parses the old file form via back-compat).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(cli): escrow becomes a managed key list — add/remove/show, set kept as sugar, old single-key TOML still read (P17)"
```

---

### Task 2: `Repo::rewrap` — the one-commit tip cutover

**Files:**
- Create: `crates/repo/src/rewrap.rs`
- Modify: `crates/repo/src/lib.rs` (register `mod rewrap;`, re-export `RewrapReport`)
- Test: in `crates/repo/src/rewrap.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `self.registry()`, `self.commit_snapshot(root, parents, secrets, protection, author, message)`, `crate::oplog::record`, `crate::worktree::tree_file_entries_with_perms`, `crate::protect::matching_prefix`, `scl_crypto::{open, seal, unwrap_dek_with, wrap_dek_for}`, `crate::secrets::require_recipients`, `ProtectPrefix::granted_keys()`.
- Produces (Task 3 consumes):

```rust
pub struct RewrapReport {
    pub secrets_rewrapped: Vec<String>,
    pub blobs_rewrapped: usize,
    /// (entry label e.g. "secret db-pass" / "path secret/db.txt", reason)
    pub skipped: Vec<(String, String)>,
    /// The commit id; None on --dry-run or when nothing needed rewrapping.
    pub commit: Option<scl_core::ObjectId>,
}

impl Repo {
    pub fn rewrap(
        &self,
        identity: &scl_crypto::SecretKey,
        escrows: &[scl_crypto::PublicKey],
        known_keys: &[scl_crypto::PublicKey], // pubkey pool for reverse recipient_id resolution
        dry_run: bool,
    ) -> Result<RewrapReport>
}
```

- [ ] **Step 1: Write the failing tests**

`crates/repo/src/rewrap.rs` with a tests module first (implementation stubs after). Follow the `tmp_root` idiom from `repo.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;
    use crate::error::Error;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-rewrap-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn rewrap_adds_escrow_to_pre_escrow_secret_in_one_commit() {
        let root = tmp_root("secret-escrow");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_esc_sk, esc_pk) = scl_crypto::generate_keypair();
        repo.secret_add("db-pass", b"hunter2", std::slice::from_ref(&alice_pk)).unwrap();
        repo.secret_add("api-key", b"tok", std::slice::from_ref(&alice_pk)).unwrap();
        let tip_before = repo.head_tip().unwrap().unwrap();

        let report = repo
            .rewrap(&alice_sk, std::slice::from_ref(&esc_pk), std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert_eq!(report.secrets_rewrapped.len(), 2);
        assert!(report.skipped.is_empty());
        let commit = report.commit.expect("must commit");

        // ONE commit: new tip's sole parent is the old tip.
        assert_eq!(repo.snapshot(&commit).unwrap().parents, vec![tip_before]);
        // Both secrets now sealed to alice + escrow.
        for name in ["db-pass", "api-key"] {
            let rids = repo.secret_recipients(name).unwrap();
            assert_eq!(rids.len(), 2, "{name} must gain the escrow key");
            assert!(rids.contains(&esc_pk.recipient_id()));
        }
        // Root unchanged (policy/registry-only).
        assert_eq!(
            repo.snapshot(&commit).unwrap().root,
            repo.snapshot(&tip_before).unwrap().root
        );
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_strips_reattached_wraps_after_pre_revoke_merge() {
        // The ADR-0026 R1 scenario, closed: merge re-attaches a revoked
        // recipient's wrap; rewrap strips it from the tip.
        let root = tmp_root("r1-strip");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"hunter2").unwrap();
        repo.commit("me", "add").unwrap();
        repo.grant("secret/", &alice_sk, &bob_pk).unwrap();
        repo.branch("pre-revoke").unwrap();
        repo.switch("pre-revoke").unwrap();
        std::fs::write(root.join("readme.txt"), b"work").unwrap();
        repo.commit("me", "feature").unwrap();
        repo.switch("main").unwrap();
        repo.revoke("secret/", &bob_pk.recipient_id()).unwrap();
        repo.merge("pre-revoke", "me").unwrap();

        // Precondition (per ADR-0026 Consequences): bob's wrap is BACK at tip.
        let tip = repo.head_tip().unwrap().unwrap();
        let prot = repo.snapshot(&tip).unwrap().protection;
        let bob_id = bob_pk.recipient_id();
        assert!(
            prot.wrapped.values().any(|wks| wks.iter().any(|w| w.recipient_id == bob_id.as_str())),
            "test setup must reproduce the R1 re-attachment"
        );

        let report = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert!(report.blobs_rewrapped >= 1);
        assert!(report.skipped.is_empty());

        // Tip wraps no longer include bob anywhere; root unchanged.
        let commit = report.commit.unwrap();
        let snap = repo.snapshot(&commit).unwrap();
        assert!(
            !snap.protection.wrapped.values().any(|wks| wks.iter().any(|w| w.recipient_id == bob_id.as_str())),
            "rewrap must strip the revoked recipient's re-attached wrap"
        );
        assert_eq!(snap.root, repo.snapshot(&tip).unwrap().root);
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_skips_unopenable_entries_and_reports() {
        let root = tmp_root("skip");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        // One secret alice can open, one she cannot (bob-only).
        repo.secret_add("mine", b"a", std::slice::from_ref(&alice_pk)).unwrap();
        repo.secret_add("theirs", b"b", std::slice::from_ref(&bob_pk)).unwrap();

        let known = [alice_pk.clone(), bob_pk.clone()];
        let report = repo.rewrap(&alice_sk, &[], &known, false).unwrap();
        assert_eq!(report.secrets_rewrapped, vec!["mine".to_string()]);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].0.contains("theirs"));
        assert!(report.commit.is_some(), "partial success still commits");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_skips_secret_with_unresolvable_recipient_id() {
        // A wrap whose recipient_id has no pubkey in the known pool cannot be
        // re-sealed to that recipient — must be reported, not silently dropped.
        let root = tmp_root("unresolvable");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_ghost_sk, ghost_pk) = scl_crypto::generate_keypair();
        repo.secret_add("shared", b"v", &[alice_pk.clone(), ghost_pk]).unwrap();
        // ghost's pubkey is NOT in the known pool.
        let report = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert!(report.secrets_rewrapped.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].1.contains("not resolvable"));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_dry_run_commits_nothing() {
        let root = tmp_root("dry");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_e, esc_pk) = scl_crypto::generate_keypair();
        repo.secret_add("s", b"v", std::slice::from_ref(&alice_pk)).unwrap();
        let tip_before = repo.head_tip().unwrap();
        let report = repo
            .rewrap(&alice_sk, std::slice::from_ref(&esc_pk), std::slice::from_ref(&alice_pk), true)
            .unwrap();
        assert_eq!(report.secrets_rewrapped.len(), 1, "dry-run still REPORTS the work");
        assert!(report.commit.is_none());
        assert_eq!(repo.head_tip().unwrap(), tip_before, "tip must not move");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_is_undoable_as_one_operation() {
        let root = tmp_root("undo");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_e, esc_pk) = scl_crypto::generate_keypair();
        repo.secret_add("s", b"v", std::slice::from_ref(&alice_pk)).unwrap();
        let tip_before = repo.head_tip().unwrap().unwrap();
        repo.rewrap(&alice_sk, std::slice::from_ref(&esc_pk), std::slice::from_ref(&alice_pk), false)
            .unwrap();
        repo.undo().unwrap();
        assert_eq!(repo.head_tip().unwrap().unwrap(), tip_before, "one undo reverts the whole rewrap");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rewrap_reports_empty_granted_rule_not_silently() {
        // Crossed revokes can empty a rule (see Task 2 of P16). Simulate the
        // merged state directly, then rewrap: the blob must land in skipped
        // with a reason pointing at `sc grant`.
        let root = tmp_root("empty-rule");
        let repo = Repo::init(&root).unwrap();
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        repo.protect("secret/", std::slice::from_ref(&alice_pk), None).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("secret/db.txt"), b"x").unwrap();
        repo.commit("me", "add").unwrap();
        // Tombstone alice directly in a synthetic snapshot (bypasses the CLI
        // guard, which is exactly what a crossed-revoke merge does).
        let tip = repo.head_tip().unwrap().unwrap();
        let mut snap = repo.snapshot(&tip).unwrap();
        for rule in snap.protection.prefixes.iter_mut() {
            for e in rule.recipients.iter_mut() {
                e.epoch += 1;
                e.state = scl_core::RecipientState::Revoked;
            }
        }
        repo.commit_snapshot(snap.root, vec![tip], snap.secrets, snap.protection, "test", "empty rule")
            .unwrap();

        let report = repo
            .rewrap(&alice_sk, &[], std::slice::from_ref(&alice_pk), false)
            .unwrap();
        assert_eq!(report.blobs_rewrapped, 0);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].1.contains("sc grant"), "reason must point at sc grant");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
```

(If `commit_snapshot`, `registry`, or `undo` have different visibility than assumed, mirror how sibling modules `secrets.rs`/`protect_ops.rs`/`replay.rs` reach them — `pub(crate)` paths exist for all three; do not widen public API beyond `rewrap` + `RewrapReport`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo rewrap`
Expected: FAIL — module/functions don't exist yet (add `mod rewrap;` to `crates/repo/src/lib.rs` first so the failure is about the missing items, not the missing file).

- [ ] **Step 3: Implement `Repo::rewrap`**

`crates/repo/src/rewrap.rs`:

```rust
//! `sc rewrap` (P17): one-commit bulk cutover of every secret and protected
//! blob at the tip to the current recipient/escrow sets. Composes the P11
//! rotate machinery (secrets) and the P7 grant-style wrap lookup (paths);
//! skip-and-report semantics — see ADR-0027 for why not all-or-nothing.

use std::collections::BTreeMap;

use scl_core::{Object, ObjectId};
use scl_crypto::{PublicKey, SecretKey, WrappedKey};

use crate::error::{Error, Result};
use crate::repo::Repo;

/// What a `rewrap` run did (or would do, on dry-run).
pub struct RewrapReport {
    pub secrets_rewrapped: Vec<String>,
    pub blobs_rewrapped: usize,
    pub skipped: Vec<(String, String)>,
    pub commit: Option<ObjectId>,
}

impl Repo {
    /// Re-seal every secret (fresh DEK, current recipients + escrow) and
    /// replace every protected blob's wrap list (rule's granted set + escrow)
    /// at the tip, as ONE commit and ONE oplog record. Entries `identity`
    /// cannot open are skipped and reported. Policy/registry-only: the root
    /// tree id is untouched. Cuts the LIVE TIP only — history keeps old wraps
    /// and old secret objects (content addressing; same boundary as rotation,
    /// ADR-0019).
    pub fn rewrap(
        &self,
        identity: &SecretKey,
        escrows: &[PublicKey],
        known_keys: &[PublicKey],
        dry_run: bool,
    ) -> Result<RewrapReport> {
        let tip = self.head_tip()?.ok_or(Error::Unborn)?;
        let snap = self.snapshot(&tip)?;
        let mut skipped: Vec<(String, String)> = Vec::new();

        // ---- Secrets half: fresh-DEK reseal to current set + escrow. ----
        let mut registry = snap.secrets.clone();
        let mut secrets_rewrapped = Vec::new();
        let mut new_secret_objs: Vec<(String, Object)> = Vec::new();
        for (name, sid) in registry.clone() {
            let secret = {
                let arc = self.store_arc_pub();
                let obj = arc.lock().unwrap().get(&sid)?;
                match obj {
                    Object::Secret(s) => s,
                    _ => {
                        skipped.push((format!("secret {name}"), "registry entry is not a secret".into()));
                        continue;
                    }
                }
            };
            // Resolve current recipient ids to pubkeys from the known pool.
            let mut targets: Vec<PublicKey> = Vec::new();
            let mut unresolvable = None;
            for w in &secret.wrapped_keys {
                match known_keys.iter().find(|k| k.recipient_id().as_str() == w.recipient_id) {
                    Some(pk) => {
                        if !targets.iter().any(|t| t.recipient_id() == pk.recipient_id()) {
                            targets.push(pk.clone());
                        }
                    }
                    None => {
                        unresolvable = Some(w.recipient_id.clone());
                        break;
                    }
                }
            }
            if let Some(rid) = unresolvable {
                skipped.push((
                    format!("secret {name}"),
                    format!("recipient id {rid} not resolvable to a public key (add to recipients.toml)"),
                ));
                continue;
            }
            let mut targets = crate::secrets::append_dedup(targets, escrows);
            let value = match scl_crypto::open(&secret, identity) {
                Ok(v) => v,
                Err(_) => {
                    skipped.push((format!("secret {name}"), "identity cannot open this secret".into()));
                    continue;
                }
            };
            crate::secrets::require_recipients(&targets)?;
            if dry_run {
                secrets_rewrapped.push(name);
                continue;
            }
            let sealed = scl_crypto::seal(&secret.name, &value, &targets);
            new_secret_objs.push((name, Object::Secret(sealed)));
        }

        // ---- Paths half: replace wrap lists with granted + escrow. ----
        let mut protection = snap.protection.clone();
        let mut blobs_rewrapped = 0usize;
        let entries = {
            let arc = self.store_arc_pub();
            let mut store = arc.lock().unwrap();
            crate::worktree::tree_file_entries_with_perms(&mut store, snap.root)?
        };
        for (path, (blob_id, _mode, perms)) in entries {
            if perms & scl_core::PROTECTED == 0 {
                continue;
            }
            let Some(rule) = crate::protect::matching_prefix(&protection, &path) else {
                skipped.push((format!("path {path}"), "no governing rule (bit/rule mismatch)".into()));
                continue;
            };
            let granted = rule.granted_keys();
            if granted.is_empty() {
                skipped.push((
                    format!("path {path}"),
                    "rule has no granted recipients (crossed revokes?); run `sc grant` first".into(),
                ));
                continue;
            }
            let Some(wks) = protection.wrapped.get(&blob_id) else {
                skipped.push((format!("path {path}"), "no wrapped DEKs recorded for blob".into()));
                continue;
            };
            let my_id = identity.public().recipient_id().to_string();
            let Some(wk) = wks.iter().find(|w| w.recipient_id == my_id) else {
                skipped.push((format!("path {path}"), "identity is not a recipient of this blob".into()));
                continue;
            };
            let dek = match scl_crypto::unwrap_dek_with(wk, identity) {
                Ok(d) => d,
                Err(e) => {
                    skipped.push((format!("path {path}"), format!("wrap failed to open: {e}")));
                    continue;
                }
            };
            if dry_run {
                blobs_rewrapped += 1;
                continue;
            }
            // Rebuild the wrap list: exactly granted + escrow, reusing prior
            // wrap bytes for recipients already present (id-stability), fresh
            // wraps for the rest. Tombstoned/stale wraps are dropped.
            let prior = wks.clone();
            let mut new_wks: Vec<WrappedKey> = Vec::new();
            let mut target_pks: Vec<PublicKey> =
                granted.iter().map(|b| PublicKey::from_bytes(*b)).collect();
            for e in escrows {
                if !target_pks.iter().any(|t| t.recipient_id() == e.recipient_id()) {
                    target_pks.push(e.clone());
                }
            }
            for pk in &target_pks {
                let rid = pk.recipient_id().to_string();
                match prior.iter().find(|w| w.recipient_id == rid) {
                    Some(existing) => new_wks.push(existing.clone()),
                    None => new_wks.push(scl_crypto::wrap_dek_for(&dek, pk)),
                }
            }
            new_wks.sort_by(|a, b| a.recipient_id.cmp(&b.recipient_id));
            protection.wrapped.insert(blob_id, new_wks);
            blobs_rewrapped += 1;
        }

        // ---- Nothing to do / dry-run: report only. ----
        if dry_run || (secrets_rewrapped.is_empty() && new_secret_objs.is_empty() && blobs_rewrapped == 0) {
            return Ok(RewrapReport { secrets_rewrapped, blobs_rewrapped, skipped, commit: None });
        }

        // ---- One commit + one oplog record. ----
        for (name, obj) in new_secret_objs {
            let id = {
                let arc = self.store_arc_pub();
                let i = arc.lock().unwrap().put(obj)?;
                i
            };
            registry.insert(name.clone(), id);
            secrets_rewrapped.push(name);
        }
        let head = crate::refs::current_branch(self.layout())?;
        let before = crate::refs::read_branch_tip(self.layout(), &head)?;
        let msg = format!(
            "rewrap: {} secret(s), {} blob(s)",
            secrets_rewrapped.len(),
            blobs_rewrapped
        );
        let id = self.commit_snapshot(snap.root, vec![tip], registry, protection, "system", &msg)?;
        crate::oplog::record(self.layout(), "rewrap", &head, &head, &[(head.clone(), before, Some(id))])?;
        Ok(RewrapReport { secrets_rewrapped, blobs_rewrapped, skipped, commit: Some(id) })
    }
}
```

Implementation notes (adapt, don't fight the codebase):
- `store_arc_pub` stands for however sibling modules reach the store — `secrets.rs` uses a private `store_arc(&self)`; either make that `pub(crate)` or add the same 3-line helper here. Do NOT duplicate store logic.
- `crate::secrets::append_dedup(targets, escrows)` — small `pub(crate)` helper to add to `secrets.rs` (dedupe-append by recipient_id, the same loop `append_escrow` does CLI-side); if you'd rather not touch `secrets.rs`, inline the 5-line loop here. Keep ONE of the two, not both.
- `scl_crypto::open` returns a `Zeroizing` buffer; keep it in scope only as long as `seal` needs it. The DEK from `unwrap_dek_with` is likewise `Zeroizing`.
- Secrets ordering: `dry_run` pushes names into `secrets_rewrapped` immediately; the real path defers to the commit block so a mid-loop error can't misreport. Keep that split.
- Register the module in `crates/repo/src/lib.rs`: `mod rewrap;` + `pub use rewrap::RewrapReport;` (mirror how `PrefixRecipient` is re-exported).

- [ ] **Step 4: Run the tests**

Run: `cargo test -p scl-repo rewrap` then `cargo test`
Expected: all 7 new tests PASS; workspace green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(repo): sc rewrap core — one-commit bulk reseal of secrets and protected wrap lists to current recipient/escrow sets (P17)"
```

---

### Task 3: CLI `sc rewrap` + revoke-hint wording pass

**Files:**
- Modify: `crates/cli/src/main.rs` (new `Rewrap` clap variant, dispatch arm, `run_rewrap`; `run_revoke` note; `secret revoke` hint — find with `grep -n "rotate" crates/cli/src/main.rs` in the secret-revoke handler)

**Interfaces:**
- Consumes: `repo.rewrap(&sk, &escrows, &known_keys, dry_run) -> Result<RewrapReport>` (Task 2), `load_escrows`/`load_recipients` (Task 1), `load_identity` (existing).

- [ ] **Step 1: Add the clap command**

```rust
/// Re-seal every secret and protected file's wrap list at the tip to the
/// current recipient + escrow sets, in one undoable commit.
Rewrap {
    /// Identity able to open the entries being re-wrapped.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Report what would be re-wrapped without committing.
    #[arg(long)]
    dry_run: bool,
},
```

Dispatch: `Cmd::Rewrap { identity, dry_run } => run_rewrap(identity, dry_run),`

- [ ] **Step 2: Implement `run_rewrap`**

```rust
fn run_rewrap(identity: Option<PathBuf>, dry_run: bool) -> Result<()> {
    let repo = open_repo()?;
    let sk = load_identity(identity)?;
    let recipients_path = repo.layout().dot_sc.join("recipients.toml");
    let escrows = load_escrows(&recipients_path)?;
    // Known-key pool for reverse recipient_id resolution: every [recipients]
    // key + every escrow key + the identity's own public key.
    let mut known: Vec<scl_crypto::PublicKey> = match load_recipients(&recipients_path) {
        Ok(dir) => dir.into_values().collect(),
        Err(_) => Vec::new(), // missing file: pool is escrow + self
    };
    for e in &escrows {
        if !known.iter().any(|k| k.recipient_id() == e.recipient_id()) {
            known.push(e.clone());
        }
    }
    let me = sk.public();
    if !known.iter().any(|k| k.recipient_id() == me.recipient_id()) {
        known.push(me);
    }

    let report = repo.rewrap(&sk, &escrows, &known, dry_run)?;
    let verb = if dry_run { "would rewrap" } else { "rewrapped" };
    println!(
        "{verb} {} secret(s), {} protected blob(s)",
        report.secrets_rewrapped.len(),
        report.blobs_rewrapped
    );
    if let Some(id) = &report.commit {
        println!("commit: {}", id.short());
    }
    if !report.skipped.is_empty() {
        eprintln!("skipped {} entr(ies):", report.skipped.len());
        for (entry, reason) in &report.skipped {
            eprintln!("  {entry}: {reason}");
        }
        eprintln!("re-run `sc rewrap` with an identity that can open them to complete the sweep");
    }
    eprintln!(
        "note: rewrap cuts the live tip only — snapshots already in history keep \
         their old wraps and secret objects (content addressing); rotating the \
         underlying external credential is still the real cutover"
    );
    if !report.skipped.is_empty() {
        std::process::exit(1); // drop(repo) first — see run_run's lock-leak comment
    }
    Ok(())
}
```

IMPORTANT: `std::process::exit` skips destructors — follow `run_run`'s existing pattern (`drop(repo);` before `exit`) or restructure to return a sentinel error the caller maps to exit code 1. Match whichever pattern `main()` already uses for nonzero exits (check `run_merge`, which exits 1 on conflicts).

- [ ] **Step 3: Reword the two revoke hints**

`run_revoke` (path prefixes) — replace the note's cutover sentence so it names the right surface:

```rust
eprintln!(
    "note: the revocation is recorded as a tombstone and holds across merges; \
     it stops FUTURE seals only. Run `sc rewrap --identity <key>` to strip the \
     recipient's wraps from the tip (old history snapshots keep theirs), and \
     rotate the underlying external credential itself for a real cutover"
);
```

`secret revoke` handler — extend its existing rotate hint to mention the bulk path:

```rust
eprintln!("hint: run `sc secret rotate {name} --identity <key>` for a cryptographic cutover of this secret, or `sc rewrap` to re-seal everything at once");
```

(Adapt variable names to the handler's actual bindings.)

- [ ] **Step 4: Verify by hand + tests**

Run: `cargo test` and a smoke run in a scratch dir: init, keygen ×2, add a secret, `sc escrow add`, `sc rewrap --dry-run` (expect "would rewrap 1 secret(s)…", exit 0), `sc rewrap`, `sc secret list` shows 2 recipients, `sc undo`, `sc secret list` shows 1. Clean up the scratch dir.
Expected: workspace green; smoke run matches.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(cli): sc rewrap — bulk tip cutover with skip-and-report; revoke hints point at rewrap (P17)"
```

---

### Task 4: Demo — `demo/run_rewrap_demo.sh`

**Files:**
- Create: `demo/run_rewrap_demo.sh` (mode 755)

- [ ] **Step 1: Write the script**

Reuse the parsing/identity idioms of `demo/run_revoke_demo.sh` VERBATIM (keygen output parsing, recipients registration, `--identity` files outside the repo tree, `mktemp -d` + trap, `fail()` helper, `set -euo pipefail`, build once). Structure and binding assertions:

```bash
#!/usr/bin/env bash
# P17 demo: bulk re-wrap + multi-key escrow. Proves that one `sc rewrap`
# (1) re-seals every pre-escrow secret to the new escrow list,
# (2) strips a revoked recipient's re-attached wraps after a pre-revoke
#     merge (the ADR-0026 R1 boundary, closed), and
# (3) is one undoable operation. Self-checking: every claim is an
# assertion; any failure exits non-zero before the RESULT line.
```

Sequence (each step asserted with the demo-house `grep -q || fail` pattern):
1. init; register alice + bob + escrow keys; `sc secret add db-pass` (alice only — pre-escrow).
2. `sc escrow add <escrow-pk>`; assert `sc escrow show` lists it.
3. Protect `secret/` for alice, commit a file, grant bob, branch `pre-revoke` + commit on it, revoke bob on main, merge — assert via `sc protect --list --json` that bob is `"state": "revoked"` (P16 holds).
4. `sc rewrap --identity alice.key` — assert output contains `rewrapped 1 secret(s)` and at least 1 blob; assert `sc secret list --json` shows db-pass with 2 recipients.
5. THE R1 STRIP: assert bob's recipient id appears NOWHERE in the tip's wraps. (`sc protect --list --json` shows rule standing, not wraps — if no CLI surface exposes wraps, assert behaviorally: `SC_IDENTITY=bob.key sc run` or a bob-identity checkout of `secret/db.txt` must FAIL to decrypt the post-rewrap tip while it SUCCEEDED pre-rewrap. Prefer the behavioral assertion; it is the user-visible truth.)
6. `sc undo`; assert `sc secret list` is back to 1 recipient.
7. RESULT lines.

- [ ] **Step 2: Run it (twice) + the neighbors**

Run: `chmod +x demo/run_rewrap_demo.sh && bash demo/run_rewrap_demo.sh && bash demo/run_rewrap_demo.sh && bash demo/run_revoke_demo.sh`
Expected: exit 0 each time; temp dirs cleaned (trap); the P16 demo undisturbed.

- [ ] **Step 3: Commit**

```bash
git add demo/run_rewrap_demo.sh
git commit -m "demo: bulk rewrap proof — escrow sweep, R1 wrap strip after pre-revoke merge, one-operation undo (P17)"
```

---

### Task 5: Docs — firm ADR-0027, ROADMAP, CLAUDE.md, ADR index

**Files:**
- Modify: `docs/adr/0027-bulk-rewrap-and-multi-escrow.md` (Status → Accepted + refinements note)
- Modify: `docs/adr/README.md` (index row 0027 → Accepted)
- Modify: `ROADMAP.md` (P17 → Done + completed-phases table row; Active → "None — Phase 18 is next up"; horizon table shrinks to P18–P20)
- Modify: `CLAUDE.md` (Commands block: `sc rewrap`, `sc escrow add/remove/show`, demo line; new `**Phase 17 is built.**` paragraph; update the "Remaining follow-ons" list — bulk re-wrap and multiple escrow keys come OFF it)

- [ ] **Step 1: Firm ADR-0027 to Accepted with build refinements**

Status → Accepted; add a "Refinements discovered during the build" section recording actual deviations (candidates: where the known-key pool for recipient_id reverse-resolution ended up, the exit-code plumbing pattern, wrap-byte reuse for still-current recipients, anything else that shifted). Verify each claim against code before writing — the P16 review caught an authorization-surface overclaim; don't repeat it. Update the index row.

- [ ] **Step 2: ROADMAP + CLAUDE.md**

Follow the exact shape of the P16 completion edits (see commit tagged "docs: accept ADR-0026" in `git log`): Done entry + table row (goal "org-scale recipient/escrow cutover", demoable outcome "change escrow, one `sc rewrap`, every entry re-sealed; R1 wraps stripped; proven by demo/run_rewrap_demo.sh"), Active → Phase 18 next, horizon table P18–P20. CLAUDE.md command lines:

```
cargo run --bin sc -- rewrap [--identity <key>] [--dry-run]   # one-commit bulk reseal of all
                                              # secrets + protected wrap lists to current
                                              # recipient/escrow sets (skip-and-report;
                                              # exits 1 when entries were skipped)
cargo run --bin sc -- escrow add <pubkey-or-name>    # append a break-glass key (list)
cargo run --bin sc -- escrow remove <id-or-name>
cargo run --bin sc -- escrow show                    # lists all escrow keys
bash demo/run_rewrap_demo.sh                          # bulk rewrap + escrow-list proof
```

The Phase-17 paragraph states: what rewrap does (both halves, one commit, one oplog record, undoable), skip-and-report semantics + exit code, the honesty caveat (tip-only; history keeps old wraps — same ADR-0019 boundary), escrow list + back-compat TOML, and that the ADR-0026 R1 corollary now has its practical answer (point the P16 paragraph's R1 sentence at `sc rewrap`).

- [ ] **Step 3: Full verification pass**

Run:
```bash
cargo test && bash demo/run_rewrap_demo.sh && bash demo/run_revoke_demo.sh && bash demo/run_lifecycle_demo.sh
```
Expected: all green — the lifecycle demo proves P11 rotation/escrow back-compat survived the escrow-list change. (Known pre-existing failure in `demo/run_protect_demo.sh` — pre-P8 issue, do not chase.)

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs: accept ADR-0027 bulk re-wrap + multi-escrow; record P17 across CLAUDE/ROADMAP/ADR index"
```
