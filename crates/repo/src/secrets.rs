//! Committed-secrets operations on a persistent repo. Each op produces a new
//! snapshot carrying the updated registry onto the current branch.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Command;
use std::sync::{Arc, Mutex};

use scl_core::{Object, ObjectId, Store};
use scl_crypto::{PublicKey, RecipientId, SecretKey};

use crate::error::{Error, Result};
use crate::repo::Repo;

/// One entry for `secret list`: name and how many recipients can read it.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretInfo {
    pub name: String,
    pub recipients: usize,
}

impl Repo {
    /// The Arc-wrapped object store (raw object access for tests/CLI).
    pub fn store(&self) -> Arc<Mutex<Store>> {
        self.vfs_handle().store()
    }

    /// Return the Arc-wrapped store (avoids borrow-of-temporary issues).
    pub(crate) fn store_arc(&self) -> Arc<Mutex<Store>> {
        self.store()
    }

    /// The current tip's secret registry (empty if unborn).
    pub(crate) fn registry(&self) -> Result<BTreeMap<String, ObjectId>> {
        match self.head_tip()? {
            Some(t) => {
                let arc = self.store_arc();
                let secrets = arc.lock().unwrap().get_snapshot(&t)?.secrets;
                Ok(secrets)
            }
            None => Ok(BTreeMap::new()),
        }
    }

    /// Commit a changed registry, keeping the tip's file tree. Logs one oplog
    /// record (`oplog_desc`) for the branch advance — the current branch is
    /// unchanged, only its tip moves.
    fn commit_registry(
        &self,
        registry: BTreeMap<String, ObjectId>,
        author: &str,
        message: &str,
        oplog_desc: &str,
    ) -> Result<ObjectId> {
        let head = crate::refs::current_branch(self.layout())?;
        let before = crate::refs::read_branch_tip(self.layout(), &head)?;
        let tip = self.head_tip()?;
        let (root, protection) = match tip {
            Some(t) => {
                let arc = self.store_arc();
                let snap = arc.lock().unwrap().get_snapshot(&t)?;
                (snap.root, snap.protection)
            }
            None => (self.vfs_handle().write_tree(&[])?, scl_core::Protection::default()),
        };
        let id =
            self.commit_snapshot(root, tip.into_iter().collect(), registry, protection, author, message)?;
        crate::oplog::record(self.layout(), oplog_desc, &head, &head, &[(head.clone(), before, Some(id))])?;
        Ok(id)
    }

    /// Seal `value` to `recipients` and register it under `name`.
    pub fn secret_add(&self, name: &str, value: &[u8], recipients: &[PublicKey]) -> Result<ObjectId> {
        // P19-I1: policy ops that move the branch tip via `commit_registry`
        // had no in-progress guard of their own, letting them silently
        // discard a stopped merge/pick/rebase's pending resolution. Same
        // guard trio as `commit`/`rewrap` (P21).
        if crate::merge_state::in_progress(self.layout()) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(self.layout()) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(self.layout()) {
            return Err(Error::RebaseInProgress);
        }
        require_recipients(recipients)?;
        let secret = scl_crypto::seal(name, value, recipients);
        let id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Secret(secret))?;
            i
        };
        let mut reg = self.registry()?;
        reg.insert(name.to_string(), id);
        self.commit_registry(reg, "secret", &format!("add secret {name}"), &format!("secret add {name}"))
    }

    /// Grant `new` access to `name` by re-wrapping the DEK with `authorized`.
    pub fn secret_grant(&self, name: &str, authorized: &SecretKey, new: &PublicKey) -> Result<ObjectId> {
        // P21: `secret_grant` also moves the branch tip via `commit_registry`
        // (confirmed by inspection per the P21 brief) — same guard trio as
        // `secret_add`/`secret_rotate`.
        if crate::merge_state::in_progress(self.layout()) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(self.layout()) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(self.layout()) {
            return Err(Error::RebaseInProgress);
        }
        let mut reg = self.registry()?;
        let sid = *reg.get(name).ok_or_else(|| Error::NoSuchSecret(name.to_string()))?;
        let secret = {
            let arc = self.store_arc();
            let obj = arc.lock().unwrap().get(&sid)?;
            match obj {
                Object::Secret(s) => s,
                _ => return Err(Error::NoSuchSecret(format!("{name} is not a secret"))),
            }
        };
        let regranted = scl_crypto::rewrap_for(&secret, authorized, new)?;
        let new_id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Secret(regranted))?;
            i
        };
        reg.insert(name.to_string(), new_id);
        self.commit_registry(reg, "secret", &format!("grant {name}"), &format!("secret grant {name}"))
    }

    /// Revoke a recipient from `name` (metadata-only re-wrap).
    pub fn secret_revoke(&self, name: &str, recipient: &RecipientId) -> Result<ObjectId> {
        // P21: `secret_revoke` also moves the branch tip via `commit_registry`
        // (confirmed by inspection per the P21 brief) — same guard trio as
        // `secret_add`/`secret_rotate`.
        if crate::merge_state::in_progress(self.layout()) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(self.layout()) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(self.layout()) {
            return Err(Error::RebaseInProgress);
        }
        let mut reg = self.registry()?;
        let sid = *reg.get(name).ok_or_else(|| Error::NoSuchSecret(name.to_string()))?;
        let secret = {
            let arc = self.store_arc();
            let obj = arc.lock().unwrap().get(&sid)?;
            match obj {
                Object::Secret(s) => s,
                _ => return Err(Error::NoSuchSecret(format!("{name} is not a secret"))),
            }
        };
        let revoked = scl_crypto::revoke(&secret, recipient);
        // Same footgun as sealing to an empty set: a secret with zero wrapped
        // keys is permanently unreadable. Rotate (choosing new recipients) is
        // the operation that changes who can read; revoke can't empty the set.
        if revoked.wrapped_keys.is_empty() {
            return Err(Error::InvalidArgument(format!(
                "revoking the last recipient would leave {name} readable by nobody; \
                 use `secret rotate --to <names>` to change the recipient set instead"
            )));
        }
        let new_id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Secret(revoked))?;
            i
        };
        reg.insert(name.to_string(), new_id);
        self.commit_registry(reg, "secret", &format!("revoke from {name}"), &format!("secret revoke {name}"))
    }

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
        // P21: same in-progress guard as `secret_add` — see its comment.
        if crate::merge_state::in_progress(self.layout()) {
            return Err(Error::MergeInProgress);
        }
        if crate::pick_state::in_progress(self.layout()) {
            return Err(Error::PickInProgress);
        }
        if crate::rebase_state::in_progress(self.layout()) {
            return Err(Error::RebaseInProgress);
        }
        require_recipients(recipients)?;
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
        self.commit_registry(reg, "secret", &format!("rotate {name}"), &format!("secret rotate {name}"))
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

    /// List secrets at HEAD with recipient counts.
    pub fn secret_list(&self) -> Result<Vec<SecretInfo>> {
        let reg = self.registry()?;
        let mut out = Vec::new();
        for (name, id) in reg {
            let arc = self.store_arc();
            let obj = arc.lock().unwrap().get(&id)?;
            if let Object::Secret(s) = obj {
                out.push(SecretInfo { name, recipients: s.wrapped_keys.len() });
            }
        }
        Ok(out)
    }

    /// Decrypt every registered secret with `identity` into `(name, value)`
    /// env pairs. `strict: true` errors on the first secret the identity
    /// cannot open (workspace preflight — fail before any agent runs);
    /// `strict: false` warns and skips (`sc run` behavior).
    pub(crate) fn secret_env(
        &self,
        identity: &SecretKey,
        strict: bool,
    ) -> Result<Vec<(String, OsString)>> {
        let reg = self.registry()?;
        let mut envs: Vec<(String, OsString)> = Vec::new();
        for (name, id) in reg {
            let obj = {
                let arc = self.store_arc();
                let o = arc.lock().unwrap().get(&id)?;
                o
            };
            let secret = match obj {
                Object::Secret(s) => s,
                _ => continue,
            };
            match scl_crypto::open(&secret, identity) {
                Ok(plaintext) => {
                    // The decrypted bytes are copied into an `OsString` for the
                    // child's environment. That `OsString` is NOT separately
                    // zeroized (and the kernel copies the environment into the
                    // child anyway), so this is a best-effort confidentiality
                    // limit inherent to env-var injection — the plaintext lives
                    // in this process's memory until `command` is dropped.
                    #[cfg(unix)]
                    let val = {
                        use std::os::unix::ffi::OsStrExt;
                        std::ffi::OsStr::from_bytes(&plaintext).to_os_string()
                    };
                    #[cfg(not(unix))]
                    let val = OsString::from(
                        std::str::from_utf8(&plaintext)
                            .map_err(|_| Error::InvalidArgument(format!("secret {name} not UTF-8")))?,
                    );
                    envs.push((name, val));
                }
                Err(scl_crypto::Error::NotARecipient) if strict => {
                    return Err(Error::InvalidArgument(format!(
                        "identity is not a recipient of secret {name}"
                    )));
                }
                Err(scl_crypto::Error::NotARecipient) => {
                    eprintln!("warning: not authorized for secret {name}; skipping");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(envs)
    }

    /// Decrypt all secrets the `identity` can read, inject into the environment,
    /// and run `cmd`. Secrets the identity cannot read are skipped with a
    /// stderr warning; a corrupt/tampered secret is a hard error. Returns the
    /// child's exit code.
    pub fn run(&self, identity: &SecretKey, cmd: &[String]) -> Result<i32> {
        let envs = self.secret_env(identity, false)?;
        let (exe, args) =
            cmd.split_first().ok_or_else(|| Error::InvalidArgument("empty command".into()))?;
        let mut command = Command::new(exe);
        command.args(args);
        for (k, v) in &envs {
            command.env(k, v);
        }
        let status = command.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Refuse an empty recipient set on every seal/wrap path (`secret_add`,
/// `secret_rotate`, `protect`): sealing to nobody silently mints a value that
/// can never be decrypted — always a caller mistake, never intent.
pub(crate) fn require_recipients(recipients: &[PublicKey]) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::InvalidArgument(
            "recipient set is empty; sealing to zero recipients would make the value \
             permanently unreadable"
                .into(),
        ));
    }
    Ok(())
}

/// Append `extra` onto `base`, deduping by `recipient_id` (base wins on
/// collision). The same dedupe-append loop `append_escrow` does CLI-side,
/// shared here so `rewrap` composes it instead of re-implementing it.
pub(crate) fn append_dedup(mut base: Vec<PublicKey>, extra: &[PublicKey]) -> Vec<PublicKey> {
    for pk in extra {
        if !base.iter().any(|t| t.recipient_id() == pk.recipient_id()) {
            base.push(pk.clone());
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("scl-repo-sec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn sealing_to_zero_recipients_is_an_error() {
        // An empty recipient set would silently mint a value nobody can ever
        // decrypt. Guard every seal/wrap path: add, rotate, and protect.
        let root = tmp_root("norecip");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();

        assert!(
            matches!(repo.secret_add("K", b"v", &[]), Err(Error::InvalidArgument(_))),
            "secret_add must reject an empty recipient set"
        );

        repo.secret_add("K", b"v", std::slice::from_ref(&alice_pk)).unwrap();
        assert!(
            matches!(
                repo.secret_rotate("K", Some(b"v2"), &[], Some(&alice_sk)),
                Err(Error::InvalidArgument(_))
            ),
            "secret_rotate must reject an empty recipient set"
        );

        assert!(
            matches!(repo.protect("secret/", &[], None), Err(Error::InvalidArgument(_))),
            "protect must reject an empty recipient set"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn revoking_the_last_recipient_is_an_error() {
        // Dropping the last wrapped key would leave a value sealed to nobody —
        // the same unreadable-value footgun as sealing to an empty set.
        let root = tmp_root("lastrevoke");
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();

        // Secret surface: two recipients — revoking one is fine, the last is not.
        repo.secret_add("K", b"v", &[alice_pk.clone(), bob_pk.clone()]).unwrap();
        repo.secret_revoke("K", &bob_pk.recipient_id()).unwrap();
        assert!(
            matches!(
                repo.secret_revoke("K", &alice_pk.recipient_id()),
                Err(Error::InvalidArgument(_))
            ),
            "revoking the last secret recipient must fail"
        );
        // The secret is still readable metadata-wise (registry unchanged).
        assert_eq!(repo.secret_list().unwrap()[0].recipients, 1);

        // Path-protection surface: same rule.
        repo.protect("vault/", std::slice::from_ref(&alice_pk), None).unwrap();
        assert!(
            matches!(
                repo.revoke("vault/", &alice_pk.recipient_id()),
                Err(Error::InvalidArgument(_))
            ),
            "revoking the last path recipient must fail"
        );

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn secret_persists_across_reopen_and_run_injects() {
        let root = tmp_root("persist");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        {
            let repo = Repo::init(&root).unwrap();
            repo.secret_add("DB_URL", b"postgres://secret", std::slice::from_ref(&alice_pk)).unwrap();
        } // dropped: store + lock released, secret only on disk now
        let repo2 = Repo::open(&root).unwrap();
        let list = repo2.secret_list().unwrap();
        assert_eq!(list, vec![SecretInfo { name: "DB_URL".into(), recipients: 1 }]);
        // run injects it into a child that echoes the value back via exit-code check
        let code = repo2
            .run(&alice_sk, &["sh".into(), "-c".into(), "test \"$DB_URL\" = postgres://secret".into()])
            .unwrap();
        assert_eq!(code, 0, "child saw the decrypted DB_URL");
        drop(repo2);
        std::fs::remove_dir_all(&root).unwrap();
    }

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
        assert!(repo.secret_recipients("nope").is_err());
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unauthorized_identity_is_skipped_not_failed() {
        let root = tmp_root("unauth");
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.secret_add("DB_URL", b"v", &[alice_pk]).unwrap();
        // mallory can't read it; run should still succeed (skip + warn), env unset
        let code = repo
            .run(&mallory_sk, &["sh".into(), "-c".into(), "test -z \"$DB_URL\"".into()])
            .unwrap();
        assert_eq!(code, 0, "DB_URL was not injected for unauthorized identity");
        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn secret_env_strict_rejects_non_recipient() {
        let root = tmp_root("env-strict");
        let (_alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (mallory_sk, _mallory_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.secret_add("DB_URL", b"v", &[alice_pk]).unwrap();

        let err = repo.secret_env(&mallory_sk, true).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        // lenient mode skips instead of erroring.
        let envs = repo.secret_env(&mallory_sk, false).unwrap();
        assert!(envs.is_empty());

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn secret_env_decrypts_for_recipient() {
        let root = tmp_root("env-ok");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.secret_add("DB_URL", b"v", &[alice_pk]).unwrap();

        let envs = repo.secret_env(&alice_sk, true).unwrap();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, "DB_URL");
        assert_eq!(envs[0].1, std::ffi::OsString::from("v"));

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn secret_add_grant_revoke_rotate_append_oplog_records() {
        let root = tmp_root("oplog-secret");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        let (_bob_sk, bob_pk) = scl_crypto::generate_keypair();
        let repo = Repo::init(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        repo.commit("me", "base").unwrap();

        // secret add: moves the current branch's tip.
        let head = crate::refs::current_branch(repo.layout()).unwrap();
        let before_add = crate::refs::read_branch_tip(repo.layout(), &head).unwrap();
        let id_add = repo.secret_add("DB_URL", b"v1", &[alice_pk]).unwrap();
        let rec = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(rec.desc, "secret add DB_URL");
        assert_eq!(rec.head_before, head);
        assert_eq!(rec.head_after, head);
        assert_eq!(rec.refs, vec![(head.clone(), before_add, Some(id_add))]);

        // secret grant.
        let recipient = alice_sk.public().recipient_id();
        let id_grant = repo.secret_grant("DB_URL", &alice_sk, &bob_pk).unwrap();
        let rec = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(rec.desc, "secret grant DB_URL");
        assert_eq!(rec.refs, vec![(head.clone(), Some(id_add), Some(id_grant))]);

        // secret revoke.
        let id_revoke = repo.secret_revoke("DB_URL", &recipient).unwrap();
        let rec = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(rec.desc, "secret revoke DB_URL");
        assert_eq!(rec.refs, vec![(head.clone(), Some(id_grant), Some(id_revoke))]);

        // secret rotate.
        let id_rotate = repo.secret_rotate("DB_URL", Some(b"v2"), &[bob_pk], None).unwrap();
        let rec = crate::oplog::last(repo.layout()).unwrap().unwrap();
        assert_eq!(rec.desc, "secret rotate DB_URL");
        assert_eq!(rec.refs, vec![(head.clone(), Some(id_revoke), Some(id_rotate))]);

        drop(repo);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
