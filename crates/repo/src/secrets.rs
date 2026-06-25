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
    /// Return the Arc-wrapped store (avoids borrow-of-temporary issues).
    fn store_arc(&self) -> Arc<Mutex<Store>> {
        self.vfs_handle().store()
    }

    /// The current tip's secret registry (empty if unborn).
    fn registry(&self) -> Result<BTreeMap<String, ObjectId>> {
        match self.head_tip()? {
            Some(t) => {
                let arc = self.store_arc();
                let secrets = arc.lock().unwrap().get_snapshot(&t)?.secrets;
                Ok(secrets)
            }
            None => Ok(BTreeMap::new()),
        }
    }

    /// Commit a changed registry, keeping the tip's file tree.
    fn commit_registry(
        &self,
        registry: BTreeMap<String, ObjectId>,
        author: &str,
        message: &str,
    ) -> Result<ObjectId> {
        let tip = self.head_tip()?;
        let root = match tip {
            Some(t) => {
                let arc = self.store_arc();
                let r = arc.lock().unwrap().get_snapshot(&t)?.root;
                r
            }
            None => self.vfs_handle().write_tree(&[])?, // empty tree
        };
        self.commit_snapshot(root, tip, registry, author, message)
    }

    /// Seal `value` to `recipients` and register it under `name`.
    pub fn secret_add(&self, name: &str, value: &[u8], recipients: &[PublicKey]) -> Result<ObjectId> {
        let secret = scl_crypto::seal(name, value, recipients);
        let id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Secret(secret))?;
            i
        };
        let mut reg = self.registry()?;
        reg.insert(name.to_string(), id);
        self.commit_registry(reg, "secret", &format!("add secret {name}"))
    }

    /// Grant `new` access to `name` by re-wrapping the DEK with `authorized`.
    pub fn secret_grant(&self, name: &str, authorized: &SecretKey, new: &PublicKey) -> Result<ObjectId> {
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
        self.commit_registry(reg, "secret", &format!("grant {name}"))
    }

    /// Revoke a recipient from `name` (metadata-only re-wrap).
    pub fn secret_revoke(&self, name: &str, recipient: &RecipientId) -> Result<ObjectId> {
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
        let new_id = {
            let arc = self.store_arc();
            let i = arc.lock().unwrap().put(Object::Secret(revoked))?;
            i
        };
        reg.insert(name.to_string(), new_id);
        self.commit_registry(reg, "secret", &format!("revoke from {name}"))
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

    /// Decrypt all secrets the `identity` can read, inject into the environment,
    /// and run `cmd`. Secrets the identity cannot read are skipped with a
    /// stderr warning; a corrupt/tampered secret is a hard error. Returns the
    /// child's exit code.
    pub fn run(&self, identity: &SecretKey, cmd: &[String]) -> Result<i32> {
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
                Err(scl_crypto::Error::NotARecipient) => {
                    eprintln!("warning: not authorized for secret {name}; skipping");
                }
                Err(e) => return Err(e.into()),
            }
        }
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
    fn secret_persists_across_reopen_and_run_injects() {
        let root = tmp_root("persist");
        let (alice_sk, alice_pk) = scl_crypto::generate_keypair();
        {
            let repo = Repo::init(&root).unwrap();
            repo.secret_add("DB_URL", b"postgres://secret", &[alice_pk.clone()]).unwrap();
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
}
