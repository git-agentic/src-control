# P11 — Secret/permission lifecycle (rotation + escrow) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give committed secrets a lifecycle — `sc secret rotate` re-seals a secret's value under a fresh DEK, and a break-glass escrow recipient is auto-included at seal/protect time for recovery.

**Architecture:** Rotation is a compose of the existing `seal`/`open` crypto primitives, so `crates/crypto` is untouched; a new `Repo::secret_rotate` mirrors the existing `secret_add`/`secret_grant` snapshot-commit pattern. Escrow is config in `.sc/recipients.toml` (`[escrow]` section, owned by `cli`) auto-appended to the recipient slice `cli` passes into `repo`. `revoke` stays metadata-only; rotation is the true cryptographic cutover.

**Tech Stack:** Rust 2021; `scl-crypto` (`seal`/`open`/`PublicKey`/`SecretKey`/`RecipientId`), `scl-repo` (registry + snapshot commit), `scl-cli` (`clap`, `toml`, `serde`, `anyhow`).

## Global Constraints

- **Dependency direction unchanged:** `cli → repo → {vfs, gitio, crypto} → core`. `repo` receives resolved `scl_crypto::PublicKey`s and never learns the `recipients.toml` format. (spec §"Crate boundaries")
- **`crates/crypto` is unchanged this phase** — no new crypto primitive; rotation reuses `seal`/`open`. (spec §1)
- **Rotation is secrets-only.** Protected-path value-rotation is out (convergent DEK = `HKDF(BLAKE3(plaintext))`, so a recipient with the plaintext re-derives the key). Escrow still applies to paths (recipient-set management). (spec §2)
- **`revoke` stays metadata-only** (unchanged behavior); it only gains a printed hint to rotate. (spec §5)
- **Escrow is forward-only and policy-not-enforcement.** Auto-appended at `secret add`/`secret rotate`/`protect`, deduped; never revocable via the recipient path. Single escrow key this phase. (spec §4)
- **Rotation ≠ erasure** — the old ciphertext object stays reachable from history and `sc gc` won't reclaim it. State this in `--help`, `escrow show`, the demo, and ADR-0019. (spec §"Honest limitations")
- Every public type/fn gets a doc comment; every new behavior ships with a test; disk-touching tests clean up their temp dirs. (CLAUDE.md)
- No new Rust deps (so no `Cargo.lock` change expected).

---

## File Structure

- `crates/repo/src/secrets.rs` (modify) — add `Repo::secret_rotate` and a `Repo::secret_recipients` read accessor.
- `crates/repo/src/error.rs` (verify only) — reuse `Error::NoSuchSecret` and `Error::InvalidArgument` (both already exist; confirm before use).
- `crates/cli/src/main.rs` (modify) — `SecretOp::Rotate` variant + `run_secret` arm; a `recipient_id → pubkey` reverse-lookup helper; the revoke→rotate hint; `[escrow]` in the recipients file struct; `EscrowOp` (`set`/`show`) command + handler; escrow auto-append at `secret add`/`secret rotate`/`protect`.
- `demo/run_lifecycle_demo.sh` (create) — end-to-end rotation + escrow proof.
- `docs/adr/0019-secret-lifecycle.md` (create), `docs/adr/README.md`, `ROADMAP.md`, `CLAUDE.md` (modify) — record P11.

---

## Task 1: `repo::secret_rotate` + `secret_recipients` (the crypto/registry heart)

**Files:**
- Modify: `crates/repo/src/secrets.rs`
- Test: in `crates/repo/src/secrets.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `scl_crypto::{seal, open, PublicKey, SecretKey, RecipientId}`; existing private `Repo::registry()`, `Repo::store_arc()`, `Repo::commit_registry(reg, author, message)`; `scl_core::Object::Secret`; `Repo::store()` (pub) for tests.
- Produces:
  - `Repo::secret_rotate(&self, name: &str, new_value: Option<&[u8]>, recipients: &[PublicKey], identity: Option<&SecretKey>) -> Result<ObjectId>`
  - `Repo::secret_recipients(&self, name: &str) -> Result<Vec<RecipientId>>` — the current recipient ids for `name` (for cli's default-set reverse lookup).

- [ ] **Step 1: Write the failing tests**

Add to `crates/repo/src/secrets.rs` tests (the module already has `tmp_root` and imports `super::*`):

```rust
    #[test]
    fn rotate_new_value_reseals_and_recipients_read_it() {
        let root = tmp_root("rot-newval");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        let s0 = repo.secret_add("DB_URL", b"v0", std::slice::from_ref(&alice_pk)).unwrap();
        let reg0 = repo.registry().unwrap();
        let id0 = reg0["DB_URL"];

        repo.secret_rotate("DB_URL", Some(b"v1"), std::slice::from_ref(&alice_pk), None).unwrap();
        let reg1 = repo.registry().unwrap();
        let id1 = reg1["DB_URL"];
        assert_ne!(id0, id1, "rotation must repoint the registry to a new object");

        let obj0 = repo.store().lock().unwrap().get(&id0).unwrap();
        let obj1 = repo.store().lock().unwrap().get(&id1).unwrap();
        let (sec0, sec1) = match (obj0, obj1) {
            (scl_core::Object::Secret(a), scl_core::Object::Secret(b)) => (a, b),
            _ => panic!("expected secrets"),
        };
        assert_ne!(sec0.ciphertext, sec1.ciphertext, "value was re-sealed under a fresh DEK");
        assert_eq!(&*scl_crypto::open(&sec1, &alice_sk).unwrap(), b"v1");
        let _ = s0;
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rotate_same_value_needs_identity_and_gets_fresh_ciphertext() {
        let root = tmp_root("rot-sameval");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.secret_add("DB_URL", b"keepme", std::slice::from_ref(&alice_pk)).unwrap();
        let id0 = repo.registry().unwrap()["DB_URL"];

        // No value, no identity → error.
        assert!(repo.secret_rotate("DB_URL", None, std::slice::from_ref(&alice_pk), None).is_err());

        repo.secret_rotate("DB_URL", None, std::slice::from_ref(&alice_pk), Some(&alice_sk)).unwrap();
        let id1 = repo.registry().unwrap()["DB_URL"];
        let obj0 = repo.store().lock().unwrap().get(&id0).unwrap();
        let obj1 = repo.store().lock().unwrap().get(&id1).unwrap();
        let (sec0, sec1) = match (obj0, obj1) {
            (scl_core::Object::Secret(a), scl_core::Object::Secret(b)) => (a, b),
            _ => panic!("expected secrets"),
        };
        assert_ne!(sec0.ciphertext, sec1.ciphertext, "same value, fresh DEK → different ciphertext");
        assert_eq!(&*scl_crypto::open(&sec1, &alice_sk).unwrap(), b"keepme");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn revoke_is_metadata_only_rotate_is_the_cutover() {
        // The headline property: revoke drops the wrapped key but NOT the value;
        // rotate re-seals so the ciphertext itself changes.
        let root = tmp_root("cutover");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (bob_sk, bob_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.secret_add("DB_URL", b"V", &[alice_pk.clone(), bob_pk.clone()]).unwrap();
        let id0 = repo.registry().unwrap()["DB_URL"];
        let sec0 = match repo.store().lock().unwrap().get(&id0).unwrap() {
            scl_core::Object::Secret(s) => s, _ => panic!(),
        };
        assert_eq!(&*scl_crypto::open(&sec0, &bob_sk).unwrap(), b"V", "bob could read pre-revoke");

        // Revoke Bob: metadata-only. Bob loses his wrapped key, but the value is unchanged.
        repo.secret_revoke("DB_URL", &bob_pk.recipient_id()).unwrap();
        let id1 = repo.registry().unwrap()["DB_URL"];
        let sec1 = match repo.store().lock().unwrap().get(&id1).unwrap() {
            scl_core::Object::Secret(s) => s, _ => panic!(),
        };
        assert_eq!(sec1.ciphertext, sec0.ciphertext, "revoke did NOT rotate the value");
        assert!(scl_crypto::open(&sec1, &bob_sk).is_err(), "bob's wrapped key was dropped");

        // Rotate (same value, alice authorizes): the ciphertext is now fresh.
        repo.secret_rotate("DB_URL", None, std::slice::from_ref(&alice_pk), Some(&alice_sk)).unwrap();
        let id2 = repo.registry().unwrap()["DB_URL"];
        let sec2 = match repo.store().lock().unwrap().get(&id2).unwrap() {
            scl_core::Object::Secret(s) => s, _ => panic!(),
        };
        assert_ne!(sec2.ciphertext, sec1.ciphertext, "rotate re-sealed under a fresh DEK");
        assert_eq!(&*scl_crypto::open(&sec2, &alice_sk).unwrap(), b"V", "alice still reads new object");
        assert!(scl_crypto::open(&sec2, &bob_sk).is_err(), "bob is not a recipient of the rotated object");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn secret_recipients_lists_current_ids() {
        let root = tmp_root("recips");
        let (_a_sk, a_pk) = scl_crypto::generate_keypair();
        let (_b_sk, b_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.secret_add("K", b"v", &[a_pk.clone(), b_pk.clone()]).unwrap();
        let mut got = repo.secret_recipients("K").unwrap();
        got.sort_by(|x, y| x.as_str().cmp(y.as_str()));
        let mut want = vec![a_pk.recipient_id(), b_pk.recipient_id()];
        want.sort_by(|x, y| x.as_str().cmp(y.as_str()));
        assert_eq!(got, want);
        assert!(matches!(repo.secret_recipients("nope"), Err(_)));
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p scl-repo secrets::tests::rotate_new_value_reseals_and_recipients_read_it secrets::tests::revoke_is_metadata_only_rotate_is_the_cutover secrets::tests::secret_recipients_lists_current_ids secrets::tests::rotate_same_value_needs_identity_and_gets_fresh_ciphertext`
Expected: FAIL — `secret_rotate` / `secret_recipients` not found.

- [ ] **Step 3: Implement `secret_rotate` and `secret_recipients`**

Add to the `impl Repo` block in `crates/repo/src/secrets.rs` (after `secret_revoke`). Use the existing `registry()`, `store_arc()`, `commit_registry()` helpers already in the file:

```rust
    /// Rotate a secret's value under a **fresh DEK**, re-sealing for `recipients`.
    /// With `new_value = Some(..)`, that plaintext is sealed (no identity needed).
    /// With `new_value = None`, the current value is recovered with `identity`
    /// (which must be a current recipient) and re-sealed unchanged. Either way the
    /// stored ciphertext changes, so a party holding the *old* DEK cannot read the
    /// new object. NOTE: the old object stays reachable from history — rotation
    /// cuts off future registry reads, it does not erase the old ciphertext.
    pub fn secret_rotate(
        &self,
        name: &str,
        new_value: Option<&[u8]>,
        recipients: &[PublicKey],
        identity: Option<&SecretKey>,
    ) -> Result<ObjectId> {
        let mut reg = self.registry()?;
        let sid = *reg.get(name).ok_or_else(|| Error::NoSuchSecret(name.to_string()))?;

        // Resolve the plaintext to seal: the supplied new value, or the current
        // value recovered with an authorized identity.
        let recovered;
        let plaintext: &[u8] = match new_value {
            Some(v) => v,
            None => {
                let id = identity.ok_or_else(|| {
                    Error::InvalidArgument(
                        "rotate requires --value or an authorizing --identity".into(),
                    )
                })?;
                let secret = {
                    let arc = self.store_arc();
                    let obj = arc.lock().unwrap().get(&sid)?;
                    match obj {
                        Object::Secret(s) => s,
                        _ => return Err(Error::NoSuchSecret(format!("{name} is not a secret"))),
                    }
                };
                recovered = scl_crypto::open(&secret, id)?;
                &recovered[..]
            }
        };

        let sealed = scl_crypto::seal(name, plaintext, recipients);
        let new_id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Secret(sealed))?;
            i
        };
        reg.insert(name.to_string(), new_id);
        self.commit_registry(reg, "secret", &format!("rotate {name}"))
    }

    /// The current recipient ids for `name` (so callers can resolve the existing
    /// recipient set back to public keys). Errors if `name` is not a secret.
    pub fn secret_recipients(&self, name: &str) -> Result<Vec<RecipientId>> {
        let reg = self.registry()?;
        let sid = *reg.get(name).ok_or_else(|| Error::NoSuchSecret(name.to_string()))?;
        let arc = self.store_arc();
        let obj = arc.lock().unwrap().get(&sid)?;
        match obj {
            Object::Secret(s) => Ok(s
                .wrapped_keys
                .iter()
                .map(|w| RecipientId::from_hex(&w.recipient_id))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::InvalidArgument("corrupt recipient id in secret".into()))?),
            _ => Err(Error::NoSuchSecret(format!("{name} is not a secret"))),
        }
    }
```

> `scl_crypto::open` returns `Zeroizing<Vec<u8>>`; binding it to `recovered` keeps it alive while `plaintext` borrows it. Confirm `Error::InvalidArgument(String)` and `Error::NoSuchSecret(String)` exist in `crates/repo/src/error.rs` (both are already used in this file) and that `RecipientId::from_hex` is the correct constructor (`crates/crypto/src/key.rs`). Add `use scl_crypto::RecipientId;` if not already imported (the file already imports `PublicKey, RecipientId, SecretKey`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p scl-repo secrets::tests`
Expected: PASS (the four new tests + the two existing secret tests).

- [ ] **Step 5: Commit**

```bash
git add crates/repo/src/secrets.rs
git commit -m "feat(repo): secret_rotate (fresh-DEK re-seal) + secret_recipients accessor"
```

---

## Task 2: `sc secret rotate` command + recipient reverse-lookup + revoke hint

**Files:**
- Modify: `crates/cli/src/main.rs` (`SecretOp` enum, `run_secret`)
- Test: `crates/cli/tests/secret_lifecycle.rs` (create; no existing cli test dir for this — use `env!("CARGO_BIN_EXE_sc")`)

**Interfaces:**
- Consumes: `Repo::secret_rotate`, `Repo::secret_recipients` (Task 1); existing `load_recipients`, `resolve_names`, `load_identity`, `open_repo`; `scl_crypto::{PublicKey, RecipientId}`.
- Produces:
  - `SecretOp::Rotate { name, value: Option<String>, to: Vec<String>, identity: Option<PathBuf> }`
  - A helper `fn resolve_ids_to_pubkeys(ids: &[RecipientId], pool: &[PublicKey]) -> Result<Vec<PublicKey>>` — maps each id to a pool pubkey whose `recipient_id()` matches; errors listing unresolved ids.

- [ ] **Step 1: Write the failing test**

Create `crates/cli/tests/secret_lifecycle.rs`:

```rust
//! End-to-end: sc secret rotate and escrow.

use std::path::Path;
use std::process::Command;

fn sc(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sc")).args(args).current_dir(dir).output().expect("sc runs")
}
fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("scl-cli-lifecycle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
/// keygen an identity, returning (identity_file_path, public_key_string).
fn keygen(dir: &Path, name: &str) -> (std::path::PathBuf, String) {
    let idfile = dir.join(format!("{name}.id"));
    let out = sc(dir, &["keygen", "--out", idfile.to_str().unwrap()]);
    assert!(out.status.success(), "keygen: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pk = stdout.lines().find(|l| l.contains("public key"))
        .and_then(|l| l.split_whitespace().find(|w| w.starts_with("scl-pk-")))
        .expect("public key in keygen output").to_string();
    (idfile, pk)
}

#[test]
fn secret_rotate_new_value_changes_what_run_injects() {
    let root = tmp("rotate");
    // keys live OUTSIDE the work tree (P5 scanner would flag scl-sk- in-tree).
    let keys = tmp("rotate-keys");
    let (alice_id, alice_pk) = keygen(&keys, "alice");

    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(repo.join(".sc/recipients.toml"), format!("[recipients]\nalice = \"{alice_pk}\"\n")).unwrap();

    assert!(sc(&repo, &["secret", "add", "DB_URL", "--to", "alice", "--value", "v0"]).status.success());
    // Rotate to a new value; recipients default to the current set (alice).
    let out = sc(&repo, &["secret", "rotate", "DB_URL", "--value", "v1"]);
    assert!(out.status.success(), "rotate: {}", String::from_utf8_lossy(&out.stderr));

    // run injects the NEW value.
    let code = sc(&repo, &["run", "--identity", alice_id.to_str().unwrap(),
        "--", "sh", "-c", "test \"$DB_URL\" = v1"]).status.code().unwrap();
    assert_eq!(code, 0, "run injected the rotated value");

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p scl-cli --test secret_lifecycle secret_rotate_new_value_changes_what_run_injects`
Expected: FAIL — `sc secret rotate` is an unknown subcommand.

- [ ] **Step 3: Add the `Rotate` variant, the helper, and the `run_secret` arm**

In `crates/cli/src/main.rs`, add to `enum SecretOp` (after `Revoke`):

```rust
    /// Rotate a secret's value under a fresh DEK (the cryptographic cutover that
    /// revoke does not perform). With --value, seal a new value (no identity
    /// needed); without, recover the current value with --identity and re-seal it.
    /// Recipients default to the secret's current set; --to overrides.
    Rotate {
        name: String,
        /// New value. Omit to keep the current value (requires --identity).
        #[arg(long)]
        value: Option<String>,
        /// Recipient names (default: the secret's current recipients).
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// Your identity (required when --value is omitted, to recover the value).
        #[arg(long)]
        identity: Option<PathBuf>,
    },
```

Add the reverse-lookup helper near `resolve_names`:

```rust
/// Map current recipient ids back to public keys drawn from `pool`. Errors,
/// listing the unresolved ids, when a current recipient has no key in `pool`
/// (e.g. missing from `.sc/recipients.toml`) — we cannot re-wrap a key we lack.
fn resolve_ids_to_pubkeys(
    ids: &[scl_crypto::RecipientId],
    pool: &[scl_crypto::PublicKey],
) -> Result<Vec<scl_crypto::PublicKey>> {
    let mut out = Vec::with_capacity(ids.len());
    let mut unresolved = Vec::new();
    for id in ids {
        match pool.iter().find(|pk| pk.recipient_id().as_str() == id.as_str()) {
            Some(pk) => out.push(pk.clone()),
            None => unresolved.push(id.as_str().to_string()),
        }
    }
    if !unresolved.is_empty() {
        anyhow::bail!(
            "cannot rotate: no public key in .sc/recipients.toml for current recipient(s): {}",
            unresolved.join(", ")
        );
    }
    Ok(out)
}
```

In `run_secret`, add the `Rotate` arm and the revoke hint. Replace the existing `SecretOp::Revoke` arm and add `Rotate`:

```rust
        SecretOp::Revoke { name, recipient_id } => {
            let rid = scl_crypto::RecipientId::from_hex(&recipient_id)
                .map_err(|_| anyhow::anyhow!("bad recipient id"))?;
            repo.secret_revoke(&name, &rid)?;
            println!("revoked {recipient_id} from {name}");
            eprintln!("note: revoke is metadata-only; run `sc secret rotate {name}` for a cryptographic cutover");
        }
        SecretOp::Rotate { name, value, to, identity } => {
            let dir = load_recipients(&recipients_path)?;
            // Recipient set: explicit --to, else the secret's current recipients.
            let pks = if to.is_empty() {
                let ids = repo.secret_recipients(&name)?;
                let pool: Vec<scl_crypto::PublicKey> = dir.values().cloned().collect();
                resolve_ids_to_pubkeys(&ids, &pool)?
            } else {
                resolve_names(&dir, &to)?
            };
            let new_value = value.as_deref().map(|s| s.as_bytes());
            let identity = match &value {
                Some(_) => None, // sealing a new value needs no decryption
                None => Some(load_identity(identity)?),
            };
            repo.secret_rotate(&name, new_value, &pks, identity.as_ref())?;
            println!("rotated secret {name} for {} recipient(s)", pks.len());
            eprintln!("note: rotation cuts off future reads via the current registry; the old \
                       ciphertext stays in history and anyone holding the old DEK keeps it — \
                       rotate the underlying credential too");
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p scl-cli --test secret_lifecycle`
Expected: PASS.

- [ ] **Step 5: Run the crate build + tests**

Run: `cargo test -p scl-cli && cargo build`
Expected: builds clean; tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/cli/src/main.rs crates/cli/tests/secret_lifecycle.rs
git commit -m "feat(cli): sc secret rotate (default/explicit recipients) + revoke->rotate hint"
```

---

## Task 3: escrow config — `[escrow]` in `recipients.toml` + `sc escrow set/show`

**Files:**
- Modify: `crates/cli/src/main.rs` (`RecipientsFile` struct, top-level `Cmd`, new `EscrowOp`, handlers)
- Test: add to `crates/cli/tests/secret_lifecycle.rs`

**Interfaces:**
- Consumes: existing `load_recipients`, `open_repo`; `scl_crypto::PublicKey`.
- Produces:
  - `RecipientsFile` gains `escrow: Option<EscrowEntry>` (Serialize + Deserialize); `struct EscrowEntry { key: String }`.
  - `fn load_escrow(path: &Path) -> Result<Option<scl_crypto::PublicKey>>` — read the configured escrow pubkey, if any.
  - `Cmd::Escrow { op: EscrowOp }` with `EscrowOp::Set { key_or_name: String }` and `EscrowOp::Show`.

- [ ] **Step 1: Write the failing test**

Add to `crates/cli/tests/secret_lifecycle.rs`:

```rust
#[test]
fn escrow_set_and_show_roundtrip() {
    let root = tmp("escrow-cfg");
    let keys = tmp("escrow-cfg-keys");
    let (_e_id, escrow_pk) = keygen(&keys, "escrow");

    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(repo.join(".sc/recipients.toml"), "[recipients]\n").unwrap();

    // show with none set
    let none = sc(&repo, &["escrow", "show"]);
    assert!(none.status.success());
    assert!(String::from_utf8_lossy(&none.stdout).to_lowercase().contains("no escrow"));

    // set by raw pubkey, then show it back + the non-guarantee note
    assert!(sc(&repo, &["escrow", "set", &escrow_pk]).status.success());
    let shown = sc(&repo, &["escrow", "show"]);
    let out = String::from_utf8_lossy(&shown.stdout);
    assert!(out.contains(&escrow_pk), "escrow show prints the key");
    assert!(out.to_lowercase().contains("policy") || out.to_lowercase().contains("not enforce"),
        "escrow show states the non-guarantee");

    // recipients section preserved after the rewrite
    let cfg = std::fs::read_to_string(repo.join(".sc/recipients.toml")).unwrap();
    assert!(cfg.contains("[recipients]"));
    assert!(cfg.contains("[escrow]"));

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p scl-cli --test secret_lifecycle escrow_set_and_show_roundtrip`
Expected: FAIL — `sc escrow` is an unknown subcommand.

- [ ] **Step 3: Implement the config struct, commands, and handlers**

In `crates/cli/src/main.rs`, extend the recipients file struct (it is currently `Deserialize`-only at the `RecipientsFile` definition):

```rust
/// Parsed `.sc/recipients.toml`: `[recipients] name -> scl-pk-<hex>`, plus an
/// optional `[escrow]` break-glass key auto-included at seal/protect time.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct RecipientsFile {
    #[serde(default)]
    recipients: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    escrow: Option<EscrowEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EscrowEntry {
    key: String,
}
```

Add the escrow reader near `load_recipients`:

```rust
/// The configured escrow public key, if any. Missing file or missing `[escrow]`
/// section → `None`.
fn load_escrow(path: &std::path::Path) -> Result<Option<scl_crypto::PublicKey>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let parsed: RecipientsFile = toml::from_str(&text)?;
    match parsed.escrow {
        Some(e) => Ok(Some(
            scl_crypto::PublicKey::from_key_string(&e.key)
                .map_err(|_| anyhow::anyhow!("bad escrow public key"))?,
        )),
        None => Ok(None),
    }
}
```

Add the command to the top-level `enum Cmd` (near `Secret`):

```rust
    /// Manage the break-glass escrow recipient (auto-included at seal/protect).
    Escrow {
        #[command(subcommand)]
        op: EscrowOp,
    },
```

Add the subcommand enum (near `SecretOp`):

```rust
#[derive(Subcommand)]
enum EscrowOp {
    /// Set the escrow key (a `scl-pk-…` pubkey, or a name from [recipients]).
    Set { key_or_name: String },
    /// Show the configured escrow key (and its recovery non-guarantee).
    Show,
}
```

Add the dispatch arm in `main` (near `Cmd::Secret`):

```rust
        Cmd::Escrow { op } => run_escrow(op),
```

Add the handler:

```rust
fn run_escrow(op: EscrowOp) -> Result<()> {
    let repo = open_repo()?;
    let path = repo.layout().dot_sc.join("recipients.toml");
    match op {
        EscrowOp::Set { key_or_name } => {
            // Accept a raw pubkey, else resolve a [recipients] name.
            let pk = match scl_crypto::PublicKey::from_key_string(&key_or_name) {
                Ok(pk) => pk,
                Err(_) => {
                    let dir = load_recipients(&path)?;
                    dir.get(&key_or_name).cloned().ok_or_else(|| {
                        anyhow::anyhow!("'{key_or_name}' is not a public key or a known recipient")
                    })?
                }
            };
            // Round-trip the file so [recipients] is preserved.
            let mut file: RecipientsFile = match std::fs::read_to_string(&path) {
                Ok(t) => toml::from_str(&t)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => RecipientsFile::default(),
                Err(e) => return Err(e.into()),
            };
            file.escrow = Some(EscrowEntry { key: pk.to_key_string() });
            std::fs::write(&path, toml::to_string(&file)?)?;
            println!("escrow set to {}", pk.recipient_id());
        }
        EscrowOp::Show => match load_escrow(&path)? {
            Some(pk) => {
                println!("escrow key: {}", pk.to_key_string());
                println!("recipient id: {}", pk.recipient_id());
                println!(
                    "note: escrow is a recovery *policy* convenience, not enforcement — a \
                     committer using the raw API can seal without it."
                );
            }
            None => println!("no escrow key set"),
        },
    }
    Ok(())
}
```

> Writing the file via `toml::to_string` reformats it (comments are not preserved) — acceptable for this generated config. Confirm `PublicKey::{from_key_string, to_key_string, recipient_id}` exist in `crates/crypto/src/key.rs` (they do).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p scl-cli --test secret_lifecycle escrow_set_and_show_roundtrip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/main.rs crates/cli/tests/secret_lifecycle.rs
git commit -m "feat(cli): escrow config in recipients.toml + sc escrow set/show"
```

---

## Task 4: auto-append escrow at `secret add` / `secret rotate` / `protect`

**Files:**
- Modify: `crates/cli/src/main.rs` (`run_secret` Add + Rotate arms, `run_protect`)
- Test: add to `crates/cli/tests/secret_lifecycle.rs`

**Interfaces:**
- Consumes: `load_escrow` (Task 3), `resolve_ids_to_pubkeys` (Task 2), `Repo::{secret_add, secret_rotate, protect, secret_recipients}`.
- Produces: a dedup-append helper `fn append_escrow(pks: Vec<PublicKey>, escrow: Option<PublicKey>) -> Vec<PublicKey>`.

- [ ] **Step 1: Write the failing test**

Add to `crates/cli/tests/secret_lifecycle.rs`:

```rust
#[test]
fn escrow_is_auto_included_on_add_and_recoverable() {
    let root = tmp("escrow-auto");
    let keys = tmp("escrow-auto-keys");
    let (_a_id, alice_pk) = keygen(&keys, "alice");
    let (escrow_id, escrow_pk) = keygen(&keys, "escrow");

    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert!(sc(&repo, &["init"]).status.success());
    std::fs::write(repo.join(".sc/recipients.toml"), format!("[recipients]\nalice = \"{alice_pk}\"\n")).unwrap();
    assert!(sc(&repo, &["escrow", "set", &escrow_pk]).status.success());

    // add a secret only to alice; escrow must be auto-included → 2 recipients.
    assert!(sc(&repo, &["secret", "add", "DB_URL", "--to", "alice", "--value", "topsecret"]).status.success());
    let list = sc(&repo, &["secret", "list"]);
    let out = String::from_utf8_lossy(&list.stdout);
    assert!(out.contains("DB_URL") && out.contains("2 recipient"), "escrow auto-included: {out}");

    // the escrow identity can recover the value.
    let code = sc(&repo, &["run", "--identity", escrow_id.to_str().unwrap(),
        "--", "sh", "-c", "test \"$DB_URL\" = topsecret"]).status.code().unwrap();
    assert_eq!(code, 0, "escrow identity recovers the secret");

    // rotating (default recipients) keeps escrow (still 2, still recoverable).
    assert!(sc(&repo, &["secret", "rotate", "DB_URL", "--value", "rotated"]).status.success());
    let list2 = sc(&repo, &["secret", "list"]);
    assert!(String::from_utf8_lossy(&list2.stdout).contains("2 recipient"), "escrow retained on rotate");
    let code2 = sc(&repo, &["run", "--identity", escrow_id.to_str().unwrap(),
        "--", "sh", "-c", "test \"$DB_URL\" = rotated"]).status.code().unwrap();
    assert_eq!(code2, 0, "escrow recovers the rotated value");

    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&keys).unwrap();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p scl-cli --test secret_lifecycle escrow_is_auto_included_on_add_and_recoverable`
Expected: FAIL — escrow is not yet auto-included (recipient count is 1, and the escrow identity cannot decrypt).

- [ ] **Step 3: Add the dedup-append helper and wire it into the three seal/wrap paths**

Add the helper near `resolve_ids_to_pubkeys`:

```rust
/// Append `escrow` to `pks` unless a key with the same bytes is already present
/// (so passing escrow explicitly is harmless).
fn append_escrow(
    mut pks: Vec<scl_crypto::PublicKey>,
    escrow: Option<scl_crypto::PublicKey>,
) -> Vec<scl_crypto::PublicKey> {
    if let Some(e) = escrow {
        if !pks.iter().any(|p| p.to_bytes() == e.to_bytes()) {
            pks.push(e);
        }
    }
    pks
}
```

In `run_secret`, wire escrow into the `Add` and `Rotate` arms. For `Add`:

```rust
        SecretOp::Add { name, to, value } => {
            let dir = load_recipients(&recipients_path)?;
            let mut pks = resolve_names(&dir, &to)?;
            pks = append_escrow(pks, load_escrow(&recipients_path)?);
            repo.secret_add(&name, value.as_bytes(), &pks)?;
            println!("added secret {name} for {} recipient(s)", pks.len());
        }
```

For `Rotate`, extend the resolution pool to include the escrow key (so a current escrow recipient id resolves) AND append escrow to the final set. Replace the recipient-resolution block in the `Rotate` arm:

```rust
        SecretOp::Rotate { name, value, to, identity } => {
            let dir = load_recipients(&recipients_path)?;
            let escrow = load_escrow(&recipients_path)?;
            let pks = if to.is_empty() {
                let ids = repo.secret_recipients(&name)?;
                // Pool = named recipients + escrow, so an escrow-only id resolves.
                let mut pool: Vec<scl_crypto::PublicKey> = dir.values().cloned().collect();
                if let Some(e) = escrow.clone() { pool.push(e); }
                resolve_ids_to_pubkeys(&ids, &pool)?
            } else {
                resolve_names(&dir, &to)?
            };
            let pks = append_escrow(pks, escrow);
            let new_value = value.as_deref().map(|s| s.as_bytes());
            let identity = match &value {
                Some(_) => None,
                None => Some(load_identity(identity)?),
            };
            repo.secret_rotate(&name, new_value, &pks, identity.as_ref())?;
            println!("rotated secret {name} for {} recipient(s)", pks.len());
            eprintln!("note: rotation cuts off future reads via the current registry; the old \
                       ciphertext stays in history and anyone holding the old DEK keeps it — \
                       rotate the underlying credential too");
        }
```

In `run_protect`, append escrow to the protected-path recipient set:

```rust
    let dir = load_recipients(&repo.layout().dot_sc.join("recipients.toml"))?;
    let mut pks = resolve_names(&dir, &to)?;
    pks = append_escrow(pks, load_escrow(&repo.layout().dot_sc.join("recipients.toml"))?);
    let id = repo.protect(&prefix, &pks, None)?;
    println!("protected {prefix} for {} recipient(s): {}", pks.len(), id.short());
```

> `PublicKey::to_bytes()` exists (`crates/crypto/src/key.rs:107`). The `Rotate` arm's `println!` uses `pks.len()`, which now counts escrow — correct.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p scl-cli --test secret_lifecycle`
Expected: PASS (all lifecycle tests: rotate, escrow config, auto-include).

- [ ] **Step 5: Run whole workspace**

Run: `cargo test`
Expected: PASS across all crates.

- [ ] **Step 6: Commit**

```bash
git add crates/cli/src/main.rs crates/cli/tests/secret_lifecycle.rs
git commit -m "feat(cli): auto-include escrow recipient on secret add/rotate and protect"
```

---

## Task 5: End-to-end demo, clippy sweep, and docs (ADR-0019 / ROADMAP / CLAUDE.md)

**Files:**
- Create: `demo/run_lifecycle_demo.sh`
- Create: `docs/adr/0019-secret-lifecycle.md`
- Modify: `docs/adr/README.md`, `ROADMAP.md`, `CLAUDE.md`

- [ ] **Step 1: Write the demo script**

Read `demo/run_repo_demo.sh` first for the exact shebang, `set -euo pipefail`, `SC=`/`cargo build --bin sc` + absolute-path pattern, and `mktemp -d` + `trap 'rm -rf' EXIT` conventions, then match them. Create `demo/run_lifecycle_demo.sh`:

```bash
#!/usr/bin/env bash
# P11 demo: secret rotation + break-glass escrow. Proves escrow auto-inclusion,
# that rotation changes the injected value, and that escrow recovers after a
# user is revoked. Ends by stating the rotation-is-not-erasure caveat.
set -euo pipefail

ROOT="$(mktemp -d)"; KEYS="$(mktemp -d)"
trap 'rm -rf "$ROOT" "$KEYS"' EXIT
cargo build --quiet --bin sc
SC="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)/debug/sc"
[ -x "$SC" ] || SC="target/debug/sc"

REPO="$ROOT/repo"; mkdir -p "$REPO"
alice_pk=$("$SC" keygen --out "$KEYS/alice" | grep 'public key' | awk '{print $3}')
escrow_pk=$("$SC" keygen --out "$KEYS/escrow" | grep 'public key' | awk '{print $3}')

( cd "$REPO" && "$SC" init >/dev/null
  printf '[recipients]\nalice = "%s"\n' "$alice_pk" > .sc/recipients.toml
  echo "== set escrow key =="
  "$SC" escrow set "$escrow_pk"
  echo "== add secret to alice only (escrow auto-included) =="
  "$SC" secret add DB_URL --to alice --value 'v0'
  "$SC" secret list
  echo "== rotate to a new value =="
  "$SC" secret rotate DB_URL --value 'v1'
  echo "escrow recovers rotated value:"
  "$SC" run --identity "$KEYS/escrow" -- sh -c 'echo "  DB_URL=$DB_URL"'
)
echo "OK: rotation + escrow verified"
echo "caveat: rotation cuts off future registry reads; the old ciphertext remains in history."
```

- [ ] **Step 2: Run the demo**

Run: `bash demo/run_lifecycle_demo.sh`
Expected: prints the secret list (DB_URL, 2 recipients), `DB_URL=v1` recovered via the escrow identity, ends with `OK:` and the caveat. Exit 0.

- [ ] **Step 3: Clippy + full test sweep**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo test`
Expected: no warnings; all tests pass. Fix any clippy nits inline.

- [ ] **Step 4: Write ADR-0019**

Read `docs/adr/0018-git-as-a-remote.md` for the exact Nygard format, then create `docs/adr/0019-secret-lifecycle.md` (`- **Status:** Accepted`, `- **Date:** 2026-07-04`, `- **Phase:** 11`, Context → Decision → Consequences → Alternatives). Pull content from `docs/superpowers/specs/2026-07-04-p11-secret-lifecycle-design.md`: rotation as a `seal`/`open` compose (no new crypto primitive); rotation secrets-only (convergent-path rationale); `revoke` stays metadata-only; escrow single-key in `recipients.toml [escrow]`, auto-appended, forward-only, policy-not-enforcement; and the rotation-≠-erasure caveat. Note it records decisions ADR-0008/0009/0014 deferred (cross-reference; do not edit those).

- [ ] **Step 5: Update the ADR index, ROADMAP, and CLAUDE.md**

- `docs/adr/README.md`: add the ADR-0019 row (Accepted, Phase 11).
- `ROADMAP.md`: add a **Phase 11 — Secret/permission lifecycle** bullet under "Done", a P11 table row, and update the "Deferred beyond P10" list — drop break-glass escrow; note **bulk re-wrap** and **multiple escrow keys** as remaining sub-follow-ons; secret value rotation is now built. Rename the section header to "Deferred beyond P11".
- `CLAUDE.md`: add commands to the command list —
  ```sh
  cargo run --bin sc -- secret rotate <name> --value <new>       # re-seal under a fresh DEK
  cargo run --bin sc -- secret rotate <name> --identity <key>    # same value, fresh DEK
  cargo run --bin sc -- escrow set <pubkey-or-name>              # break-glass recovery key
  cargo run --bin sc -- escrow show
  bash demo/run_lifecycle_demo.sh                                # rotation + escrow proof
  ```
  Add a "**Phase 11 is built.**" paragraph summarizing rotation (fresh-DEK re-seal; secrets-only; the not-erasure caveat), `revoke` staying metadata-only, and escrow (auto-included, forward-only, policy-not-enforcement). Update the "Remaining follow-ons" line to drop break-glass escrow (leaving network transport, and noting bulk re-wrap / multi-escrow).

- [ ] **Step 6: Commit**

```bash
git add demo/run_lifecycle_demo.sh docs/adr/0019-secret-lifecycle.md docs/adr/README.md ROADMAP.md CLAUDE.md
git commit -m "docs: accept ADR-0019; record P11 secret lifecycle; demo script"
```

---

## Self-Review

**Spec coverage** (each spec section → task):
- §1 rotation = seal/open compose, no new crypto primitive → Task 1 (repo `secret_rotate` reuses `scl_crypto::seal`/`open`). ✓
- §2 rotation secrets-only; path value-rotation out → not built for paths; documented in ADR (Task 5). Escrow still applies to paths → Task 4 (`run_protect` append). ✓
- §3 `secret rotate` shape (two flavors, default/`--to` recipients, reverse lookup) → Task 1 (mechanics) + Task 2 (command, reverse lookup). ✓
- §4 escrow: `[escrow]` in recipients.toml, `set`/`show`, auto-append at add/rotate/protect, deduped, forward-only → Task 3 (config + commands) + Task 4 (auto-append). ✓
- §5 revoke stays metadata-only + hint → Task 2 (`Revoke` arm hint; behavior unchanged). ✓
- Honest limitations (not-erasure caveat, policy-not-enforcement) → Task 2 (rotate note), Task 3 (`escrow show` note), Task 5 (demo + ADR). ✓
- Crate boundaries (repo gets resolved pubkeys; recipients.toml stays in cli) → Task 1 (repo takes `&[PublicKey]`), Tasks 2–4 (cli owns the file). ✓
- Testing (rotate mechanics, true-cutover property, escrow) → Task 1 (property test), Tasks 2–4 (cli/escrow). ✓
- Demo + docs → Task 5. ✓
- Non-goals (bulk re-wrap, multi-escrow, path rotation, revoke-reseal) → not built; recorded in ADR/ROADMAP (Task 5). ✓

**Placeholder scan:** no TBD/TODO; every code step carries complete code. The one deliberately-prose step is Task 5 Step 4 (ADR-0019 wording), which points at the exact source spec and sibling ADR format — appropriate for a docs artifact.

**Type consistency:** `secret_rotate(name, new_value: Option<&[u8]>, recipients: &[PublicKey], identity: Option<&SecretKey>) -> Result<ObjectId>` and `secret_recipients(name) -> Result<Vec<RecipientId>>` are defined in Task 1 and consumed with those exact shapes in Tasks 2/4. `resolve_ids_to_pubkeys(ids: &[RecipientId], pool: &[PublicKey]) -> Result<Vec<PublicKey>>` (Task 2) and `append_escrow(Vec<PublicKey>, Option<PublicKey>) -> Vec<PublicKey>` / `load_escrow(&Path) -> Result<Option<PublicKey>>` (Tasks 3/4) are used consistently. `RecipientsFile { recipients, escrow: Option<EscrowEntry> }` / `EscrowEntry { key }` are defined in Task 3 and reused in Task 4 via `load_escrow`.

**Verification note for implementers:** Task 1 assumes `Error::InvalidArgument(String)` and `Error::NoSuchSecret(String)` already exist in `crates/repo/src/error.rs` (both are used elsewhere in `secrets.rs`) and that `RecipientId::from_hex` is the constructor — confirm before writing rather than inventing variants.
