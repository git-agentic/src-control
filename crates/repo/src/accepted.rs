//! Locally accepted recipients (ADR-0059).
//!
//! Protection rules, secret wrap lists and private-branch KEK wrap labels are
//! repository data, so a writer without a key can make your next seal wrap a
//! DEK to them. `.sc/accepted-recipients` is the local answer: one
//! `<scope>\t<key>` line per key YOU accepted for a scope (`path:<prefix>`
//! with the full public key, `secret:<NAME>` and `branch:<name>` with the
//! recipient id). A seal that would wrap to a key not accepted for its scope
//! (and not in the local `[escrow]`) refuses before anything is written.
//!
//! The file is local state like `.sc/local-key`: written atomically under the
//! repo lock, never committed, never in a pack, never transferred, never read
//! by gc. Sessions (`sc ws`, `sc work`) commit through the host repo, so they
//! read the host's record.

use std::collections::{BTreeMap, BTreeSet};

use scl_crypto::{PublicKey, RecipientId};

use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::repo::Repo;

/// Scope of a protected-path rule: the rule's own prefix string.
pub(crate) fn path_scope(prefix: &str) -> String {
    format!("path:{prefix}")
}

/// Scope of a committed secret's wrap list.
pub(crate) fn secret_scope(name: &str) -> String {
    format!("secret:{name}")
}

/// Scope of a private branch's KEK wrap list.
pub(crate) fn branch_scope(name: &str) -> String {
    format!("branch:{name}")
}

/// What `scope` records for `key`: the full public key for a path rule (a rule
/// holds full keys), the recipient id for a secret or a branch (a wrap label
/// is an id).
fn entry(scope: &str, key: &PublicKey) -> String {
    if scope.starts_with("path:") {
        key.to_key_string()
    } else {
        key.recipient_id().to_string()
    }
}

/// A recipient a seal would wrap to that this clone never accepted for the scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unaccepted {
    pub scope: String,
    /// What `sc policy accept --key` takes for this scope: the full public key
    /// for `path:`, the recipient id otherwise.
    pub key: String,
    pub id: String,
    /// The local `[recipients]` name for the key, if there is one.
    pub name: Option<String>,
}

impl Unaccepted {
    /// The local `[recipients]` name, or `UNKNOWN`, made safe to print.
    fn label(&self) -> String {
        match &self.name {
            Some(n) => scl_core::sanitize_display_line(n).into_owned(),
            None => "UNKNOWN".to_string(),
        }
    }

    /// The scope as text that is safe to print: a rule prefix, secret name or
    /// branch name comes from the repository, so it can hold control characters.
    fn shown_scope(&self) -> String {
        scl_core::sanitize_display_line(&self.scope).into_owned()
    }

    /// Whether the scope prints as itself. A scope that does not never gets a
    /// runnable command, however it would be quoted.
    fn scope_is_plain(&self) -> bool {
        matches!(
            scl_core::sanitize_display_line(&self.scope),
            std::borrow::Cow::Borrowed(_)
        )
    }

    /// The exact `sc policy accept` command; an unknown key needs
    /// `--allow-unknown`. `None` when the scope holds control characters.
    pub fn accept_command(&self) -> Option<String> {
        if !self.scope_is_plain() {
            return None;
        }
        let unknown = if self.name.is_none() {
            " --allow-unknown"
        } else {
            ""
        };
        Some(format!(
            "sc policy accept {} --key {}{unknown}",
            sh_quote(&self.scope),
            self.key
        ))
    }

    /// The command that removes the recipient from the repository data: flags
    /// first, then `--`, then the target, so a target that starts with `-` is
    /// not read as a flag. `None` when the scope holds control characters.
    pub fn remove_command(&self) -> Option<String> {
        if !self.scope_is_plain() {
            return None;
        }
        let (kind, target) = self.scope.split_once(':').unwrap_or(("", &self.scope));
        let (head, flags) = match kind {
            "path" => ("sc revoke", format!("--recipient-id {}", self.id)),
            "secret" => ("sc secret revoke", format!("--recipient-id {}", self.id)),
            _ => (
                "sc branch revoke",
                format!("--recipient-id {} --identity <key>", self.id),
            ),
        };
        Some(format!("{head} {flags} -- {}", sh_quote(target)))
    }

    /// Where to look at a scope that has no safe command.
    fn inspect_command(&self) -> &'static str {
        match self.scope.split_once(':').map(|(k, _)| k) {
            Some("path") => "sc protect --list",
            Some("secret") => "sc secret list",
            _ => "sc branch list",
        }
    }

    /// The Accept and Remove lines of the refusal.
    fn command_lines(&self) -> String {
        match (self.accept_command(), self.remove_command()) {
            (Some(accept), Some(remove)) => format!("  Accept: {accept}\n  Remove: {remove}\n"),
            _ => format!(
                "  The scope holds control characters, so no command is suggested; \
                 inspect it with `{}`.\n",
                self.inspect_command()
            ),
        }
    }
}

/// Quote `s` for a POSIX shell unless it is plainly safe. The `'\''` escape is
/// POSIX only; PowerShell and cmd.exe quote differently and are not handled.
fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The text of [`Error::UnacceptedRecipients`]. Every field that can come from
/// the repository is escaped.
pub(crate) fn describe(pairs: &[Unaccepted]) -> String {
    let mut out = String::new();
    for p in pairs {
        out.push_str(&format!(
            "{} grants a recipient you have not accepted: {} ({}).\n{}",
            p.shown_scope(),
            p.id,
            p.label(),
            p.command_lines()
        ));
    }
    out.push_str("No ref moved and no approval was recorded.");
    out
}

/// One-line form for a skipped `rewrap` entry.
pub(crate) fn describe_inline(pairs: &[Unaccepted]) -> String {
    pairs
        .iter()
        .map(|p| {
            let commands = match (p.accept_command(), p.remove_command()) {
                (Some(accept), Some(remove)) => format!("accept: {accept}; remove: {remove}"),
                _ => format!(
                    "the scope holds control characters, so no command is suggested \
                     (inspect it with `{}`)",
                    p.inspect_command()
                ),
            };
            format!(
                "grants a recipient you have not accepted: {} ({}); {commands}",
                p.id,
                p.label()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// This clone's accepted pairs plus the local escrow keys (accepted in every
/// scope) and `[recipients]` names, as read from `.sc/`.
#[derive(Default, Clone)]
pub(crate) struct Accepted {
    pairs: BTreeSet<(String, String)>,
    escrow: BTreeSet<String>,
    names: BTreeMap<String, String>,
}

impl Accepted {
    pub(crate) fn load(layout: &Layout) -> Result<Accepted> {
        let mut out = Accepted {
            pairs: read_pairs(layout)?,
            ..Default::default()
        };
        // An unreadable or malformed recipients file yields no escrow and no
        // names: fewer keys count as accepted, never more.
        #[derive(serde::Deserialize, Default)]
        struct Escrow {
            key: Option<String>,
            #[serde(default)]
            keys: Vec<String>,
        }
        #[derive(serde::Deserialize, Default)]
        struct File {
            #[serde(default)]
            recipients: BTreeMap<String, String>,
            escrow: Option<Escrow>,
        }
        let file: File = std::fs::read_to_string(layout.dot_sc.join("recipients.toml"))
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default();
        for (name, k) in file.recipients {
            if let Ok(pk) = PublicKey::from_key_string(&k) {
                out.names.insert(pk.recipient_id().to_string(), name);
            }
        }
        let escrow = file.escrow.unwrap_or_default();
        for k in escrow.key.iter().chain(escrow.keys.iter()) {
            if let Ok(pk) = PublicKey::from_key_string(k) {
                out.escrow.insert(pk.recipient_id().to_string());
            }
        }
        Ok(out)
    }

    /// Also count `keys` as escrow: the break-glass set a caller passes in.
    pub(crate) fn with_escrow(mut self, keys: &[PublicKey]) -> Accepted {
        self.escrow
            .extend(keys.iter().map(|k| k.recipient_id().to_string()));
        self
    }

    /// Also count `keys` as accepted for `scope` (the ones the user just named).
    pub(crate) fn with_named(mut self, scope: &str, keys: &[PublicKey]) -> Accepted {
        for k in keys {
            self.pairs.insert((scope.to_string(), entry(scope, k)));
        }
        self
    }

    fn is_accepted(&self, scope: &str, key: &PublicKey) -> bool {
        self.escrow.contains(key.recipient_id().as_str())
            || self.pairs.contains(&(scope.to_string(), entry(scope, key)))
    }

    /// The keys in `keys` not accepted for `scope`, deduped, in input order.
    pub(crate) fn unaccepted(&self, scope: &str, keys: &[PublicKey]) -> Vec<Unaccepted> {
        let mut out: Vec<Unaccepted> = Vec::new();
        for k in keys {
            let key = entry(scope, k);
            if self.is_accepted(scope, k) || out.iter().any(|u| u.key == key) {
                continue;
            }
            let id = k.recipient_id().to_string();
            out.push(Unaccepted {
                scope: scope.to_string(),
                key,
                name: self.names.get(&id).cloned(),
                id,
            });
        }
        out
    }

    /// Refuse (nothing written) unless every key in `keys` is accepted for `scope`.
    pub(crate) fn require(&self, scope: &str, keys: &[PublicKey]) -> Result<()> {
        refuse_if_any(self.unaccepted(scope, keys))
    }
}

/// `Err` naming every pair, or `Ok` when there is none.
pub(crate) fn refuse_if_any(pairs: Vec<Unaccepted>) -> Result<()> {
    if pairs.is_empty() {
        Ok(())
    } else {
        Err(Error::UnacceptedRecipients { pairs })
    }
}

/// Scope text goes through a line-oriented file and a path prefix can hold any
/// byte but NUL, so escape the three characters the format uses.
fn esc(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\t', "%09")
        .replace('\n', "%0A")
        .replace('\r', "%0D")
}

fn unesc(s: &str) -> String {
    s.replace("%0D", "\r")
        .replace("%0A", "\n")
        .replace("%09", "\t")
        .replace("%25", "%")
}

/// The recipient id behind a recorded entry, or `None` when the entry is not a
/// valid key or id for its scope.
fn entry_id(scope: &str, entry: &str) -> Option<RecipientId> {
    if scope.starts_with("path:") {
        PublicKey::from_key_string(entry)
            .ok()
            .map(|k| k.recipient_id())
    } else {
        RecipientId::from_hex(entry).ok()
    }
}

/// A missing file is an empty record; a line that does not parse is skipped
/// (an unreadable pair is never an accepted one).
fn read_pairs(layout: &Layout) -> Result<BTreeSet<(String, String)>> {
    let text = match std::fs::read_to_string(layout.accepted_recipients_path()) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(text
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(s, e)| (unesc(s), e.to_string()))
        .filter(|(s, e)| entry_id(s, e).is_some())
        .collect())
}

fn write_pairs(layout: &Layout, pairs: &BTreeSet<(String, String)>) -> Result<()> {
    let body: String = pairs
        .iter()
        .map(|(s, e)| format!("{}\t{e}\n", esc(s)))
        .collect();
    // As durable as the ref write it precedes: fsynced, renamed, parent fsynced.
    scl_core::fsutil::atomic_write_durable(&layout.accepted_recipients_path(), body.as_bytes())?;
    Ok(())
}

/// `path:<prefix>`, `secret:<NAME>` or `branch:<name>`, with something after the colon.
fn validate_scope(scope: &str) -> Result<()> {
    let ok = ["path:", "secret:", "branch:"]
        .iter()
        .any(|k| scope.strip_prefix(k).is_some_and(|rest| !rest.is_empty()));
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "bad scope {scope:?}: use path:<prefix>, secret:<NAME> or branch:<name>"
        )))
    }
}

impl Repo {
    /// The record as this repo reads it.
    pub(crate) fn accepted(&self) -> Result<Accepted> {
        Accepted::load(&self.layout)
    }

    /// Record recipients as accepted for `scope` (`sc policy accept`;
    /// idempotent). Each entry is the id plus the full public key when the
    /// caller has it; a `path:` scope records full keys, so it is required
    /// there. The whole batch is validated before the record is written, once.
    /// Local file only: allowed while a merge, pick or rebase is stopped.
    pub fn accept_recipients(
        &self,
        scope: &str,
        entries: &[(RecipientId, Option<PublicKey>)],
    ) -> Result<()> {
        validate_scope(scope)?;
        let mut recorded = Vec::with_capacity(entries.len());
        for (id, key) in entries {
            recorded.push(match (scope.starts_with("path:"), key) {
                (true, Some(k)) => entry(scope, k),
                (true, None) => {
                    return Err(Error::InvalidArgument(format!(
                        "{scope} records full public keys: pass the scl-pk- key of {id}, \
                         or a recipient id that is in .sc/recipients.toml"
                    )))
                }
                (false, _) => id.to_string(),
            });
        }
        // Read, change and write under one lock, or two callers on this handle
        // could each read the old record and one change would be lost.
        crate::lock::with_index_lock(&self.layout, || {
            let mut pairs = read_pairs(&self.layout)?;
            let before = pairs.len();
            pairs.extend(recorded.into_iter().map(|e| (scope.to_string(), e)));
            if pairs.len() != before {
                write_pairs(&self.layout, &pairs)
            } else {
                self.sync_unchanged()
            }
        })
    }

    /// [`Repo::accept_recipients`] for keys the user named on the command line.
    pub fn accept_keys(&self, scope: &str, keys: &[PublicKey]) -> Result<()> {
        let entries: Vec<_> = keys
            .iter()
            .map(|k| (k.recipient_id(), Some(k.clone())))
            .collect();
        self.accept_recipients(scope, &entries)
    }

    /// A write that changes nothing still has to leave the record durable: an
    /// earlier attempt may have renamed the new file and failed before its
    /// directory was synced, and a retry then finds the change already in place.
    /// Returning success without a sync would let a later durable ref move
    /// outlive an approval change that a crash can still lose.
    fn sync_unchanged(&self) -> Result<()> {
        Ok(scl_core::fsutil::fsync_dir(&self.layout.dot_sc)?)
    }

    /// Remove every accepted pair of `scope` for this recipient (`sc policy
    /// forget`, and every local revoke). Returns whether there was one.
    pub fn forget_recipient(&self, scope: &str, id: &RecipientId) -> Result<bool> {
        crate::lock::with_index_lock(&self.layout, || {
            let mut pairs = read_pairs(&self.layout)?;
            let before = pairs.len();
            pairs.retain(|(s, e)| s != scope || entry_id(s, e).as_ref() != Some(id));
            let removed = pairs.len() != before;
            if removed {
                write_pairs(&self.layout, &pairs)?;
            } else {
                self.sync_unchanged()?;
            }
            Ok(removed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scl_core::{Object, WrappedKey};
    use scl_crypto::{generate_keypair, SecretKey};
    use std::path::{Path, PathBuf};

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scl-accepted-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn id_of(pk: &PublicKey) -> String {
        pk.recipient_id().to_string()
    }

    /// The error's pairs, when it is a refusal that wrote nothing.
    fn refused(r: Result<impl std::fmt::Debug>) -> Vec<Unaccepted> {
        match r {
            Err(Error::UnacceptedRecipients { pairs }) => pairs,
            other => panic!("expected an unaccepted-recipients refusal, got {other:?}"),
        }
    }

    /// Is a wrap addressed to `id` recorded in any snapshot in the store?
    fn wrapped_to(repo: &Repo, id: &str) -> bool {
        let store_arc = repo.vfs().store();
        let mut s = store_arc.lock().unwrap();
        for oid in s.list_loose().unwrap() {
            if let Ok(Object::Snapshot(snap)) = s.get(&oid) {
                if snap
                    .protection
                    .wrapped
                    .values()
                    .flatten()
                    .any(|w| w.recipient_id == id)
                {
                    return true;
                }
            }
        }
        false
    }

    /// A victim repo with `secret/` protected for the victim, cloned by a writer
    /// who holds no key (`attack` runs in that clone), then fetched back as
    /// remote `a`.
    struct World {
        v: Repo,
        v_root: PathBuf,
        a_root: PathBuf,
        vsk: SecretKey,
        atk: PublicKey,
    }

    fn world(tag: &str, attack: impl FnOnce(&Repo, &PublicKey)) -> World {
        let v_root = dir(&format!("{tag}-v"));
        let a_root = dir(&format!("{tag}-a"));
        std::fs::remove_dir_all(&a_root).unwrap();
        let (vsk, vpk) = generate_keypair();
        let (_, atk) = generate_keypair();
        let v = Repo::init(&v_root).unwrap();
        put(&v_root, "secret/a.txt", "victim data\n");
        put(&v_root, "readme.txt", "hello\n");
        v.protect("secret/", &[vpk], None).unwrap();
        drop(v);
        let a = Repo::clone_to(&v_root, &a_root).unwrap();
        attack(&a, &atk);
        drop(a);
        let v = Repo::open(&v_root).unwrap();
        v.remote_add("a", a_root.to_str().unwrap()).unwrap();
        v.fetch("a").unwrap();
        World {
            v,
            v_root,
            a_root,
            vsk,
            atk,
        }
    }

    impl World {
        fn pull(&self) {
            self.v
                .merge_with_identity("a/main", "me", Some(&self.vsk))
                .unwrap();
        }
        fn cleanup(self) {
            let (v, a) = (self.v_root.clone(), self.a_root.clone());
            drop(self);
            let _ = std::fs::remove_dir_all(v);
            let _ = std::fs::remove_dir_all(a);
        }
    }

    // 1. A narrower rule from a keyless writer: the victim fast-forwards, edits
    // under it and commits. Refused, nothing moved, no wrap to the attacker in
    // the store; after an explicit accept it passes.
    #[test]
    fn a_narrower_rule_from_a_writer_is_refused_until_accepted() {
        let w = world("narrow", |a, atk| {
            a.protect("secret/sub/", std::slice::from_ref(atk), None)
                .unwrap();
        });
        w.pull();
        let atk_id = id_of(&w.atk);
        put(&w.v_root, "secret/sub/x.txt", "new victim data\n");
        let tip = w.v.head_tip().unwrap();
        let pairs = refused(w.v.commit("me", "edit"));
        assert_eq!(
            pairs,
            vec![Unaccepted {
                scope: "path:secret/sub/".into(),
                key: w.atk.to_key_string(),
                id: atk_id.clone(),
                name: None
            }]
        );
        assert_eq!(w.v.head_tip().unwrap(), tip, "the ref did not move");
        assert!(!wrapped_to(&w.v, &atk_id), "no wrap to the attacker stored");

        w.v.accept_keys("path:secret/sub/", std::slice::from_ref(&w.atk))
            .unwrap();
        w.v.commit("me", "edit").unwrap();
        assert!(wrapped_to(&w.v, &atk_id), "sealed to the accepted key");
        w.cleanup();
    }

    // 2a. The same on a fresh clone, and the error names the local recipient
    // (a key listed in recipients.toml is still not an accepted one).
    #[test]
    fn a_fresh_clone_refuses_and_names_the_local_recipient() {
        let w = world("fresh", |a, atk| {
            a.protect("secret/sub/", std::slice::from_ref(atk), None)
                .unwrap();
        });
        let c_root = dir("fresh-c");
        std::fs::remove_dir_all(&c_root).unwrap();
        let c = Repo::clone_to(&w.a_root, &c_root).unwrap();
        put(&c_root, "secret/sub/x.txt", "data\n");
        let atk_id = id_of(&w.atk);
        let unknown = refused(c.commit("me", "m"));
        assert_eq!(unknown[0].name, None);
        let text = Error::UnacceptedRecipients { pairs: unknown }.to_string();
        assert!(
            text.contains(&format!(
                "sc policy accept path:secret/sub/ --key {} --allow-unknown",
                w.atk.to_key_string()
            )) && text.contains(&format!("sc revoke --recipient-id {atk_id} -- secret/sub/"))
                && text.contains("(UNKNOWN)")
                && text.contains("No ref moved and no approval was recorded."),
            "{text}"
        );

        put(
            &c_root,
            ".sc/recipients.toml",
            &format!("[recipients]\nmallory = \"{}\"\n", w.atk.to_key_string()),
        );
        let named = refused(c.commit("me", "m"));
        assert_eq!(named[0].name.as_deref(), Some("mallory"));
        assert!(!named[0]
            .accept_command()
            .unwrap()
            .contains("--allow-unknown"));
        drop(c);
        let _ = std::fs::remove_dir_all(c_root);
        w.cleanup();
    }

    // 2b. A merge where only theirs has the rule: ours' plain file under it must
    // be sealed by the merge, which wraps to their key.
    #[test]
    fn a_merge_that_brings_in_a_rule_refuses_to_seal_to_its_key() {
        let v_root = dir("merge-v");
        let a_root = dir("merge-a");
        std::fs::remove_dir_all(&a_root).unwrap();
        let (_, atk) = generate_keypair();
        let v = Repo::init(&v_root).unwrap();
        put(&v_root, "readme.txt", "hello\n");
        v.commit("me", "base").unwrap();
        drop(v);
        let a = Repo::clone_to(&v_root, &a_root).unwrap();
        a.protect("docs/", std::slice::from_ref(&atk), None)
            .unwrap();
        drop(a);
        let v = Repo::open(&v_root).unwrap();
        put(&v_root, "docs/q.txt", "ours only\n");
        v.commit("me", "docs").unwrap();
        v.remote_add("a", a_root.to_str().unwrap()).unwrap();
        v.fetch("a").unwrap();

        let tip = v.head_tip().unwrap();
        let atk_id = id_of(&atk);
        let pairs = refused(v.merge("a/main", "me"));
        assert_eq!(pairs[0].scope, "path:docs/");
        assert_eq!(pairs[0].id, atk_id);
        assert_eq!(v.head_tip().unwrap(), tip);
        assert_eq!(
            std::fs::read_to_string(v_root.join("docs/q.txt")).unwrap(),
            "ours only\n"
        );
        assert!(!wrapped_to(&v, &atk_id));

        v.accept_keys("path:docs/", std::slice::from_ref(&atk))
            .unwrap();
        v.merge("a/main", "me").unwrap();
        assert!(wrapped_to(&v, &atk_id));
        drop(v);
        let _ = std::fs::remove_dir_all(v_root);
        let _ = std::fs::remove_dir_all(a_root);
    }

    /// Plant a wrap label for `atk_id` (no usable wrap bytes) on a secret.
    fn plant_secret_label(repo: &Repo, name: &str, atk_id: &str) {
        let tip = repo.head_tip().unwrap().unwrap();
        let snap = repo.snapshot(&tip).unwrap();
        let store_arc = repo.vfs().store();
        let mut s = store_arc.lock().unwrap();
        let Object::Secret(mut secret) = s.get(&snap.secrets[name]).unwrap() else {
            panic!("not a secret")
        };
        secret.wrapped_keys.push(WrappedKey {
            recipient_id: atk_id.into(),
            wrapped_dek: vec![0; 48],
        });
        let sid = s.put(Object::Secret(secret)).unwrap();
        drop(s);
        let mut secrets = snap.secrets.clone();
        secrets.insert(name.into(), sid);
        repo.commit_snapshot(snap.root, vec![tip], secrets, snap.protection, "w", "x")
            .unwrap();
    }

    // 3. A bogus wrap label on a secret: rotate without --to would re-seal to
    // that key; rewrap skips the entry, keeps the rest and reports it.
    #[test]
    fn a_planted_secret_label_blocks_rotate_and_is_skipped_by_rewrap() {
        let root = dir("secret-label");
        let (vsk, vpk) = generate_keypair();
        let (_, atk) = generate_keypair();
        let v = Repo::init(&root).unwrap();
        v.secret_add("API_TOKEN", b"t", std::slice::from_ref(&vpk))
            .unwrap();
        v.secret_add("OTHER", b"o", std::slice::from_ref(&vpk))
            .unwrap();
        let atk_id = id_of(&atk);
        plant_secret_label(&v, "API_TOKEN", &atk_id);

        // What the CLI derives from the labels with the key in recipients.toml.
        let both = [vpk.clone(), atk.clone()];
        let pairs = refused(v.secret_rotate("API_TOKEN", None, &both, Some(&vsk)));
        assert_eq!(pairs[0].scope, "secret:API_TOKEN");
        assert_eq!(pairs[0].id, atk_id);
        assert!(pairs[0]
            .remove_command()
            .unwrap()
            .starts_with("sc secret revoke --recipient-id"));

        let report = v.rewrap(&vsk, &[], &both, false).unwrap();
        assert_eq!(report.secrets_rewrapped, vec!["OTHER".to_string()]);
        assert!(report.commit.is_some(), "partial success is kept");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "secret API_TOKEN");
        assert!(
            report.skipped[0].1.contains(&atk_id),
            "{:?}",
            report.skipped
        );

        // Accepting it is the user's call; then the rotate goes through.
        v.accept_keys("secret:API_TOKEN", std::slice::from_ref(&atk))
            .unwrap();
        v.secret_rotate("API_TOKEN", None, &both, Some(&vsk))
            .unwrap();
        drop(v);
        let _ = std::fs::remove_dir_all(root);
    }

    // 4. A bogus kek_wraps label: revoke would hand the fresh KEK to that key.
    #[test]
    fn a_planted_branch_label_blocks_revoke() {
        let root = dir("branch-label");
        let (vsk, vpk) = generate_keypair();
        let (_, bob) = generate_keypair();
        let (_, atk) = generate_keypair();
        let v = Repo::init(&root).unwrap();
        put(&root, "a.txt", "a\n");
        v.commit("me", "base").unwrap();
        v.branch_private("emb", &vsk, std::slice::from_ref(&bob), &[])
            .unwrap();
        let atk_id = id_of(&atk);
        let (mid, mut m) = v.branch_manifest("emb").unwrap().unwrap();
        m.kek_wraps.push(WrappedKey {
            recipient_id: atk_id.clone(),
            wrapped_dek: vec![0; 48],
        });
        m.prev = Some(mid);
        let planted = {
            let store_arc = v.vfs().store();
            let id = store_arc.lock().unwrap().put(Object::Manifest(m)).unwrap();
            id
        };
        crate::refs::write_branch_tip(v.layout(), "emb", &planted).unwrap();

        let remaining = [vpk.clone(), atk.clone()];
        let pairs = refused(v.branch_revoke("emb", &vsk, &bob.recipient_id(), &remaining));
        assert_eq!(pairs[0].scope, "branch:emb");
        assert_eq!(pairs[0].id, atk_id);
        assert_eq!(
            crate::refs::read_branch_tip(v.layout(), "emb").unwrap(),
            Some(planted),
            "the manifest did not change"
        );

        v.accept_keys("branch:emb", std::slice::from_ref(&atk))
            .unwrap();
        v.branch_revoke("emb", &vsk, &bob.recipient_id(), &remaining)
            .unwrap();
        // A local revoke drops the pair, so a later reappearance is refused again.
        assert_eq!(
            v.accepted()
                .unwrap()
                .unaccepted("branch:emb", std::slice::from_ref(&bob))
                .len(),
            1
        );
        drop(v);
        let _ = std::fs::remove_dir_all(root);
    }

    // The writer adds its key to the victim's existing rule.
    fn world_with_foreign_key_in_rule(tag: &str) -> World {
        world(tag, |a, atk| {
            // Built by hand: an honest `sc protect` in this clone would refuse
            // the victim's own key, which the writer has not accepted. The
            // writer cannot unwrap any DEK, so the sealed file keeps its wrap
            // list; only the rule changes.
            let tip = a.head_tip().unwrap().unwrap();
            let snap = a.snapshot(&tip).unwrap();
            let mut prot = snap.protection;
            let rule = prot
                .prefixes
                .iter_mut()
                .find(|p| p.prefix == "secret/")
                .unwrap();
            let epoch = rule.next_epoch();
            rule.set_standing(atk.to_bytes(), epoch, scl_core::RecipientState::Granted);
            a.commit_snapshot(snap.root, vec![tip], snap.secrets, prot, "w", "x")
                .unwrap();
        })
    }

    // 5. Own `protect --to` then commit needs no accept; protect over a merged-in
    // foreign key refuses before any ref move.
    #[test]
    fn protect_accepts_its_own_keys_but_refuses_a_foreign_one_before_moving_a_ref() {
        let w = world_with_foreign_key_in_rule("protect");
        let (_, me) = generate_keypair();
        // Own protect, own commit: no accept anywhere.
        put(&w.v_root, "mine/x.txt", "x\n");
        w.v.protect("mine/", std::slice::from_ref(&me), None)
            .unwrap();
        put(&w.v_root, "mine/x.txt", "y\n");
        w.v.commit("me", "again").unwrap();

        w.pull();
        let tip = w.v.head_tip().unwrap();
        let oplog = w.v.oplog().unwrap().len();
        let pairs = refused(w.v.protect("secret/", std::slice::from_ref(&me), None));
        assert_eq!(pairs[0].scope, "path:secret/");
        assert_eq!(pairs[0].id, id_of(&w.atk));
        assert_eq!(w.v.head_tip().unwrap(), tip, "no ref move");
        assert_eq!(w.v.oplog().unwrap().len(), oplog, "no oplog record");

        w.v.accept_keys("path:secret/", std::slice::from_ref(&w.atk))
            .unwrap();
        w.v.protect("secret/", std::slice::from_ref(&me), None)
            .unwrap();
        w.cleanup();
    }

    // protect also builds its sealing commit before moving any ref, so a seal
    // that another rule's unaccepted key refuses leaves no policy-only commit.
    #[test]
    fn protect_leaves_no_policy_commit_when_another_rule_refuses_its_seal() {
        let w = world("protect-atomic", |a, atk| {
            a.protect("secret/sub/", std::slice::from_ref(atk), None)
                .unwrap();
        });
        w.pull();
        let (_, me) = generate_keypair();
        put(&w.v_root, "secret/sub/x.txt", "victim data\n");
        put(&w.v_root, "docs/y.txt", "y\n");
        let tip = w.v.head_tip().unwrap();
        let oplog = w.v.oplog().unwrap().len();
        let record = std::fs::read(w.v.layout().accepted_recipients_path()).unwrap();
        let pairs = refused(w.v.protect("docs/", std::slice::from_ref(&me), None));
        assert_eq!(pairs[0].scope, "path:secret/sub/");
        assert_eq!(
            std::fs::read(w.v.layout().accepted_recipients_path()).unwrap(),
            record,
            "the named key was recorded although the plan was refused"
        );
        assert_eq!(w.v.head_tip().unwrap(), tip, "no ref move");
        assert_eq!(w.v.oplog().unwrap().len(), oplog, "no oplog record");
        assert!(w
            .v
            .protected_prefixes()
            .unwrap()
            .iter()
            .all(|(p, _)| p != "docs/"));
        w.cleanup();
    }

    // 6. A commit that only carries sealed content passes with an unaccepted key
    // in the rule; the same commit sealing a changed file does not.
    #[test]
    fn a_carry_only_commit_passes_with_an_unaccepted_key_in_the_rule() {
        let w = world_with_foreign_key_in_rule("carry");
        w.pull();
        put(&w.v_root, "readme.txt", "edited\n");
        w.v.commit("me", "carry only").unwrap();
        assert!(
            !wrapped_to(&w.v, &id_of(&w.atk)),
            "carrying minted no wrap for the planted key"
        );

        put(&w.v_root, "secret/a.txt", "changed\n");
        let pairs = refused(w.v.commit("me", "seals"));
        assert_eq!(pairs[0].id, id_of(&w.atk));
        w.cleanup();
    }

    // 7. A secret added in this clone can be rotated with the default recipient
    // set; a key outside it cannot.
    #[test]
    fn secret_add_then_default_rotate_passes() {
        let root = dir("rotate");
        let (vsk, vpk) = generate_keypair();
        let (_, other) = generate_keypair();
        let v = Repo::init(&root).unwrap();
        v.secret_add("S1", b"v", std::slice::from_ref(&vpk))
            .unwrap();
        v.secret_rotate("S1", None, std::slice::from_ref(&vpk), Some(&vsk))
            .unwrap();
        refused(v.secret_rotate("S1", None, &[vpk, other], Some(&vsk)));
        drop(v);
        let _ = std::fs::remove_dir_all(root);
    }

    // 8. A stopped merge refuses on an unaccepted key; accepting while stopped
    // lets the completion retry.
    #[test]
    fn a_stopped_merge_completes_after_an_accept_made_during_the_stop() {
        let v_root = dir("stop-v");
        let a_root = dir("stop-a");
        std::fs::remove_dir_all(&a_root).unwrap();
        let (_, atk) = generate_keypair();
        let v = Repo::init(&v_root).unwrap();
        put(&v_root, "n.txt", "base\n");
        v.commit("me", "base").unwrap();
        drop(v);
        let a = Repo::clone_to(&v_root, &a_root).unwrap();
        put(&a_root, "n.txt", "theirs\n");
        a.protect("docs/", std::slice::from_ref(&atk), None)
            .unwrap();
        drop(a);
        let v = Repo::open(&v_root).unwrap();
        put(&v_root, "n.txt", "ours\n");
        put(&v_root, "docs/q.txt", "ours only\n");
        v.commit("me", "ours").unwrap();
        v.remote_add("a", a_root.to_str().unwrap()).unwrap();
        v.fetch("a").unwrap();
        assert!(matches!(
            v.merge("a/main", "me"),
            Err(Error::MergeConflicts(1))
        ));
        put(&v_root, "n.txt", "resolved\n");

        let atk_id = id_of(&atk);
        let pairs = refused(v.commit("me", "merge"));
        assert_eq!(pairs[0].id, atk_id);
        assert!(
            crate::merge_state::in_progress(v.layout()),
            "the stop is intact"
        );

        v.accept_keys("path:docs/", std::slice::from_ref(&atk))
            .unwrap();
        let id = v.commit("me", "merge").unwrap();
        assert!(!crate::merge_state::in_progress(v.layout()));
        assert_eq!(v.snapshot(&id).unwrap().parents.len(), 2);
        assert!(wrapped_to(&v, &atk_id));
        drop(v);
        let _ = std::fs::remove_dir_all(v_root);
        let _ = std::fs::remove_dir_all(a_root);
    }

    // 9. The record never travels: not in a clone, not by push or fetch, and gc
    // leaves it alone.
    #[test]
    fn the_record_never_appears_in_clone_fetch_or_push() {
        let v_root = dir("travel-v");
        let c_root = dir("travel-c");
        std::fs::remove_dir_all(&c_root).unwrap();
        let (_, pk) = generate_keypair();
        let v = Repo::init(&v_root).unwrap();
        put(&v_root, "secret/a.txt", "x\n");
        v.protect("secret/", &[pk], None).unwrap();
        let record = v.layout().accepted_recipients_path();
        let bytes = std::fs::read(&record).unwrap();
        assert!(!bytes.is_empty(), "premise: protect recorded its key");
        drop(v);

        let c = Repo::clone_to(&v_root, &c_root).unwrap();
        let c_record = c.layout().accepted_recipients_path();
        assert!(!c_record.exists(), "a clone starts with an empty record");
        // What the origin accepted is not inherited: sealing to its key is
        // refused here until this clone accepts it.
        put(&c_root, "secret/b.txt", "b\n");
        refused(c.commit("me", "seal"));
        std::fs::remove_file(c_root.join("secret/b.txt")).unwrap();
        put(&c_root, "more.txt", "m\n");
        c.commit("me", "more").unwrap();
        c.push("origin").unwrap();
        assert!(!c_record.exists(), "a push does not create it either");
        assert_eq!(std::fs::read(&record).unwrap(), bytes, "push left it alone");
        drop(c);

        let v = Repo::open(&v_root).unwrap();
        v.remote_add("c", c_root.to_str().unwrap()).unwrap();
        v.fetch("c").unwrap();
        v.gc(std::time::Duration::from_secs(0)).unwrap();
        assert_eq!(std::fs::read(&record).unwrap(), bytes, "fetch and gc too");
        drop(v);
        let _ = std::fs::remove_dir_all(v_root);
        let _ = std::fs::remove_dir_all(c_root);
    }

    // A prefix may hold tabs, newlines and `%`; the file format must survive it.
    // A path scope records the full key, the others the id.
    #[test]
    fn a_scope_with_control_characters_round_trips() {
        let root = dir("escape");
        let (_, pk) = generate_keypair();
        let (_, other) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        let scope = "path:we\tird\n%0A\r/";
        repo.accept_keys(scope, std::slice::from_ref(&pk)).unwrap();
        repo.accept_keys("secret:S", std::slice::from_ref(&pk))
            .unwrap();
        let text = std::fs::read_to_string(repo.layout().accepted_recipients_path()).unwrap();
        assert!(text.contains(&format!(
            "path:we%09ird%0A%250A%0D/\t{}",
            pk.to_key_string()
        )));
        assert!(text.contains(&format!("secret:S\t{}", id_of(&pk))));
        let acc = repo.accepted().unwrap();
        assert!(acc.unaccepted(scope, std::slice::from_ref(&pk)).is_empty());
        assert_eq!(acc.unaccepted(scope, std::slice::from_ref(&other)).len(), 1);
        assert_eq!(acc.pairs.len(), 2);
        // A path scope needs the full key; a bad scope is refused.
        assert!(repo
            .accept_recipients("path:x/", &[(pk.recipient_id(), None)])
            .is_err());
        repo.accept_recipients("secret:T", &[(pk.recipient_id(), None)])
            .unwrap();
        assert!(repo.accept_keys("nope", std::slice::from_ref(&pk)).is_err());
        // Forgetting goes by recipient id, whichever form was recorded.
        assert!(repo.forget_recipient(scope, &pk.recipient_id()).unwrap());
        assert!(!repo.forget_recipient(scope, &pk.recipient_id()).unwrap());
        assert!(repo
            .forget_recipient("secret:S", &pk.recipient_id())
            .unwrap());
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // Escrow is accepted in every scope.
    #[test]
    fn local_escrow_counts_as_accepted_everywhere() {
        let root = dir("escrow");
        let (_, escrow) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        put(
            &root,
            ".sc/recipients.toml",
            &format!("[escrow]\nkeys = [\"{}\"]\n", escrow.to_key_string()),
        );
        let acc = repo.accepted().unwrap();
        let (_, other) = generate_keypair();
        for scope in ["path:a/", "secret:X", "branch:b"] {
            assert!(acc
                .unaccepted(scope, std::slice::from_ref(&escrow))
                .is_empty());
            assert_eq!(acc.unaccepted(scope, std::slice::from_ref(&other)).len(), 1);
        }
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // Escrow keys a command appends are accepted from the current `[escrow]`
    // config at check time, never recorded: removing one from the config takes
    // the acceptance with it.
    #[test]
    fn escrow_keys_a_command_appends_are_not_recorded() {
        let root = dir("escrow-not-recorded");
        let (sk, me) = generate_keypair();
        let (_, bob) = generate_keypair();
        let (_, escrow) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        let toml = format!("[escrow]\nkeys = [\"{}\"]\n", escrow.to_key_string());
        put(&root, ".sc/recipients.toml", &toml);
        put(&root, "p/x.txt", "x\n");
        repo.protect_with_escrow(
            "p/",
            std::slice::from_ref(&me),
            std::slice::from_ref(&escrow),
            None,
        )
        .unwrap();
        repo.secret_add_with_escrow(
            "S",
            b"v",
            std::slice::from_ref(&me),
            std::slice::from_ref(&escrow),
        )
        .unwrap();
        repo.branch_private(
            "b",
            &sk,
            std::slice::from_ref(&bob),
            std::slice::from_ref(&escrow),
        )
        .unwrap();

        let record = std::fs::read_to_string(repo.layout().accepted_recipients_path()).unwrap();
        assert!(
            !record.contains(&escrow.to_key_string()) && !record.contains(&id_of(&escrow)),
            "escrow recorded: {record}"
        );
        for (scope, key) in [
            ("path:p/", &me),
            ("secret:S", &me),
            ("branch:b", &bob),
            ("branch:b", &sk.public()),
        ] {
            assert!(repo
                .accepted()
                .unwrap()
                .unaccepted(scope, std::slice::from_ref(key))
                .is_empty());
        }
        // Escrow is accepted while it is configured.
        let acc = repo.accepted().unwrap();
        for scope in ["path:p/", "secret:S", "branch:b"] {
            assert!(acc
                .unaccepted(scope, std::slice::from_ref(&escrow))
                .is_empty());
        }
        // And stops being accepted when it is removed from the config.
        put(&root, ".sc/recipients.toml", "[recipients]\n");
        let acc = repo.accepted().unwrap();
        for scope in ["path:p/", "secret:S", "branch:b"] {
            assert_eq!(
                acc.unaccepted(scope, std::slice::from_ref(&escrow)).len(),
                1
            );
        }
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Set `.sc` to `mode` until the guard drops. `0o555` makes the record
    /// unwritable while it stays readable; refs and objects live in
    /// subdirectories, which stay writable, so a ref that moved despite the
    /// failed record write would show up as a changed tip. `0o311` leaves it
    /// searchable but not openable as a directory, so an fsync of `.sc` fails.
    #[cfg(unix)]
    struct DotScMode(PathBuf);
    #[cfg(unix)]
    impl DotScMode {
        fn new(dot_sc: &Path, mode: u32) -> Self {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dot_sc, std::fs::Permissions::from_mode(mode)).unwrap();
            DotScMode(dot_sc.to_path_buf())
        }
    }
    #[cfg(unix)]
    impl Drop for DotScMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    // The local approval goes before the ref moves: when the record cannot be
    // written the revoke fails with nothing moved, and it lands once it can.
    #[cfg(unix)]
    #[test]
    fn a_revoke_drops_the_approval_before_it_moves_the_ref() {
        let root = dir("revoke-order");
        let (sk, a) = generate_keypair();
        let (_, b) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        put(&root, "p/x.txt", "x\n");
        repo.protect("p/", &[a.clone(), b.clone()], None).unwrap();
        repo.secret_add("S", b"v", &[a.clone(), b.clone()]).unwrap();
        repo.branch_private("emb", &sk, std::slice::from_ref(&b), &[])
            .unwrap();
        let tip = repo.head_tip().unwrap();
        let emb = crate::refs::read_branch_tip(repo.layout(), "emb").unwrap();
        {
            let _ro = DotScMode::new(&repo.layout().dot_sc, 0o555);
            assert!(repo.revoke("p/", &b.recipient_id()).is_err());
            assert_eq!(repo.head_tip().unwrap(), tip, "path revoke moved the ref");
            assert!(repo.secret_revoke("S", &b.recipient_id()).is_err());
            assert_eq!(repo.head_tip().unwrap(), tip, "secret revoke moved the ref");
            assert_eq!(repo.secret_recipients("S").unwrap().len(), 2);
            assert!(repo
                .branch_revoke("emb", &sk, &b.recipient_id(), std::slice::from_ref(&a))
                .is_err());
            assert_eq!(
                crate::refs::read_branch_tip(repo.layout(), "emb").unwrap(),
                emb,
                "branch revoke moved the ref"
            );
        }
        repo.revoke("p/", &b.recipient_id()).unwrap();
        repo.secret_revoke("S", &b.recipient_id()).unwrap();
        assert_eq!(repo.secret_recipients("S").unwrap().len(), 1);
        // `a` is the creator of `emb` and the key `branch_private` accepted.
        repo.branch_revoke("emb", &sk, &b.recipient_id(), std::slice::from_ref(&a))
            .unwrap();
        let acc = repo.accepted().unwrap();
        for scope in ["path:p/", "secret:S", "branch:emb"] {
            assert_eq!(acc.unaccepted(scope, std::slice::from_ref(&b)).len(), 1);
            assert!(acc.unaccepted(scope, std::slice::from_ref(&a)).is_empty());
        }
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // The named approvals are recorded before the ref moves, so a record write
    // that fails leaves a `protect` or a `secret add` unlanded.
    #[cfg(unix)]
    #[test]
    fn a_failed_record_write_leaves_protect_and_secret_add_unlanded() {
        let root = dir("write-first");
        let (_, a) = generate_keypair();
        let (_, escrow) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        put(&root, "q/x.txt", "x\n");
        // A first seal creates `.sc/local-key`, which later commands only read.
        repo.protect("q/", std::slice::from_ref(&a), None).unwrap();
        put(&root, "p/x.txt", "x\n");
        let tip = repo.head_tip().unwrap();
        let oplog = repo.oplog().unwrap().len();
        {
            let _ro = DotScMode::new(&repo.layout().dot_sc, 0o555);
            assert!(repo
                .protect_with_escrow(
                    "p/",
                    std::slice::from_ref(&a),
                    std::slice::from_ref(&escrow),
                    None
                )
                .is_err());
            assert_eq!(repo.head_tip().unwrap(), tip, "protect moved the ref");
            assert!(repo
                .secret_add_with_escrow(
                    "S",
                    b"v",
                    std::slice::from_ref(&a),
                    std::slice::from_ref(&escrow)
                )
                .is_err());
            assert_eq!(repo.head_tip().unwrap(), tip, "secret add moved the ref");
        }
        assert_eq!(repo.oplog().unwrap().len(), oplog);
        // Once the record can be written both land, with only the named key recorded.
        repo.protect_with_escrow(
            "p/",
            std::slice::from_ref(&a),
            std::slice::from_ref(&escrow),
            None,
        )
        .unwrap();
        let record = std::fs::read_to_string(repo.layout().accepted_recipients_path()).unwrap();
        assert!(record.contains("path:p/\t"), "{record}");
        assert!(!record.contains(&escrow.to_key_string()), "{record}");
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // A batch with one entry it cannot record writes none of them.
    #[test]
    fn a_batch_with_a_bad_entry_writes_nothing() {
        let root = dir("batch");
        let (_, good) = generate_keypair();
        let (_, other) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        let err = repo
            .accept_recipients(
                "path:x/",
                &[
                    (good.recipient_id(), Some(good.clone())),
                    (other.recipient_id(), None),
                ],
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err}");
        assert!(!repo.layout().accepted_recipients_path().exists());
        // Without the bad entry the same call records, in one write.
        repo.accept_recipients("path:x/", &[(good.recipient_id(), Some(good.clone()))])
            .unwrap();
        assert_eq!(repo.accepted().unwrap().pairs.len(), 1);
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // A scope comes from the repository: it is escaped in the message and a
    // scope with control characters gets no command to run.
    #[test]
    fn a_scope_with_control_characters_is_escaped_and_gets_no_command() {
        let evil = "path:a\n  Accept: sc policy accept x\u{1b}[2J/";
        let pair = Unaccepted {
            scope: evil.into(),
            key: "k".into(),
            id: "0".repeat(32),
            name: Some("na\nme\u{202e}".into()),
        };
        assert_eq!(pair.accept_command(), None);
        assert_eq!(pair.remove_command(), None);
        for text in [
            Error::UnacceptedRecipients {
                pairs: vec![pair.clone()],
            }
            .to_string(),
            describe_inline(std::slice::from_ref(&pair)),
        ] {
            assert!(
                text.chars()
                    .all(|c| c == '\n' || !(c.is_control() || c == '\u{202e}')),
                "raw control character in {text:?}"
            );
            assert!(text.contains("control characters"), "{text}");
            assert!(text.contains("sc protect --list"), "{text}");
            assert!(
                text.lines().all(|l| !l.trim_start().starts_with("Accept:")),
                "{text}"
            );
        }
        // A plain scope still gets both commands.
        let plain = Unaccepted {
            scope: "secret:DB".into(),
            ..pair
        };
        assert!(plain.accept_command().is_some() && plain.remove_command().is_some());
    }

    // The target always goes after the flags and `--`, so one that starts with
    // `-` is not read as a flag.
    #[test]
    fn a_remove_command_puts_the_target_after_the_flags() {
        let id = "0".repeat(32);
        let at = |scope: &str| {
            Unaccepted {
                scope: scope.into(),
                key: "k".into(),
                id: id.clone(),
                name: None,
            }
            .remove_command()
            .unwrap()
        };
        assert_eq!(
            at("path:-x/"),
            format!("sc revoke --recipient-id {id} -- -x/")
        );
        assert_eq!(
            at("secret:-X"),
            format!("sc secret revoke --recipient-id {id} -- -X")
        );
        assert_eq!(
            at("branch:-b"),
            format!("sc branch revoke --recipient-id {id} --identity <key> -- -b")
        );
        assert_eq!(
            at("path:x/"),
            format!("sc revoke --recipient-id {id} -- x/")
        );
    }

    // The record's integrity does not rest on this change alone: a tree that
    // carries `.sc/accepted-recipients` or `.sc/recipients.toml` (the escrow
    // list also counts as accepted) must not be able to write them on clone.
    // That is the working-tree path guard's job (PR #367).
    #[test]
    fn a_cloned_tree_cannot_plant_the_record_or_the_recipients_file() {
        for (i, planted) in [".sc/accepted-recipients", ".sc/recipients.toml"]
            .into_iter()
            .enumerate()
        {
            let s_root = dir(&format!("plant-s{i}"));
            let c_root = dir(&format!("plant-c{i}"));
            std::fs::remove_dir_all(&c_root).unwrap();
            let src = Repo::init(&s_root).unwrap();
            put(&s_root, "readme.txt", "hello\n");
            let tip = src.commit("me", "base").unwrap();
            let snap = src.snapshot(&tip).unwrap();
            // Built through the store: a commit now refuses a `.sc` path itself.
            let root = {
                use scl_core::{EntryKind, FileMode, Object, Tree, TreeEntry};
                let store = src.vfs_handle().store();
                let mut st = store.lock().unwrap();
                let blob = st.put(Object::blob(b"planted".to_vec())).unwrap();
                let leaf = planted.trim_start_matches(".sc/").to_string();
                let sub = st
                    .put(Object::Tree(Tree::new(vec![TreeEntry {
                        name: leaf,
                        kind: EntryKind::Blob,
                        id: blob,
                        mode: FileMode::FILE,
                        perms: 0,
                    }])))
                    .unwrap();
                st.put(Object::Tree(Tree::new(vec![
                    TreeEntry {
                        name: ".sc".into(),
                        kind: EntryKind::Tree,
                        id: sub,
                        mode: FileMode::FILE,
                        perms: 0,
                    },
                    TreeEntry {
                        name: "readme.txt".into(),
                        kind: EntryKind::Blob,
                        id: blob,
                        mode: FileMode::FILE,
                        perms: 0,
                    },
                ])))
                .unwrap()
            };
            src.commit_snapshot(root, vec![tip], snap.secrets, snap.protection, "w", "plant")
                .unwrap();
            drop(src);

            let cloned = Repo::clone_to(&s_root, &c_root);
            assert!(
                cloned.is_err(),
                "a clone of a tree holding {planted} succeeded"
            );
            assert!(
                !c_root.join(planted).exists(),
                "{planted} was written by a checkout"
            );
            drop(cloned);
            let _ = std::fs::remove_dir_all(s_root);
            let _ = std::fs::remove_dir_all(c_root);
        }
    }

    // An unreadable record blocks a seal, not a commit that wraps nothing.
    #[test]
    fn an_unreadable_record_blocks_only_what_seals() {
        let root = dir("lazy");
        let (_, pk) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        put(&root, "plain.txt", "p\n");
        put(&root, "p/x.txt", "x\n");
        repo.protect("p/", std::slice::from_ref(&pk), None).unwrap();
        let record = repo.layout().accepted_recipients_path();
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();

        // Plain edit: the protected file is carried, nothing is wrapped.
        put(&root, "plain.txt", "edited\n");
        repo.commit("me", "plain").unwrap();
        // A seal needs the record.
        put(&root, "p/x.txt", "changed\n");
        let err = repo.commit("me", "seal").unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // A registry entry sealed under another name is skipped by rewrap, as
    // `secret_rotate` refuses it: approving it by the registry name and
    // resealing it under the sealed name would hand it the wrong approvals.
    #[test]
    fn rewrap_skips_a_relabeled_secret_instead_of_resealing_it() {
        let root = dir("relabeled");
        let (sk, pk) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        // `pk` is approved for the registry name only.
        repo.accept_keys("secret:A", std::slice::from_ref(&pk))
            .unwrap();
        let tip = {
            let secret = scl_crypto::seal("B", b"value-of-b", std::slice::from_ref(&pk));
            let sid = repo
                .vfs()
                .store()
                .lock()
                .unwrap()
                .put(Object::Secret(secret))
                .unwrap();
            let root_id = repo.vfs().write_tree(&[]).unwrap();
            let mut secrets = std::collections::BTreeMap::new();
            secrets.insert("A".to_string(), sid);
            repo.commit_snapshot(
                root_id,
                vec![],
                secrets,
                scl_core::Protection::default(),
                "w",
                "plant",
            )
            .unwrap()
        };
        let before = repo.snapshot(&tip).unwrap().secrets;

        let report = repo
            .rewrap(&sk, &[], std::slice::from_ref(&pk), false)
            .unwrap();
        assert!(report.secrets_rewrapped.is_empty(), "{report:?}");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert_eq!(report.skipped[0].0, "secret A");
        assert!(
            report.skipped[0].1.contains("sealed as \"B\""),
            "{:?}",
            report.skipped
        );
        assert!(report.commit.is_none(), "nothing was resealed");
        assert_eq!(repo.snapshot(&tip).unwrap().secrets, before);
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // The record is read when an entry actually mints a wrap: a randomized
    // blob whose targets all have a wrap is rebuilt from the existing ones.
    #[test]
    fn rewrap_reads_the_record_only_for_entries_that_mint_a_wrap() {
        let root = dir("rewrap-lazy");
        let (sk, pk) = generate_keypair();
        let (_, other) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        put(&root, "p/x.txt", "x\n");
        repo.protect("p/", std::slice::from_ref(&pk), None).unwrap();
        let record = repo.layout().accepted_recipients_path();
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();

        // Every target already has a wrap: nothing is minted, no record needed.
        let report = repo
            .rewrap(&sk, &[], std::slice::from_ref(&pk), false)
            .unwrap();
        assert_eq!(report.blobs_rewrapped, 1, "{report:?}");
        // A fresh DEK wraps to every target, so the record is read.
        let err = repo
            .rewrap_with(&sk, &[], std::slice::from_ref(&pk), false, true)
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        // So does a target with no wrap yet.
        let err = repo
            .rewrap(&sk, std::slice::from_ref(&other), &[pk], false)
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // `secret grant` refuses a registry entry sealed under another name before
    // it records an approval or wraps anything, as rotate and rewrap do.
    #[test]
    fn secret_grant_refuses_a_relabeled_secret() {
        let root = dir("grant-relabeled");
        let (sk, pk) = generate_keypair();
        let (_, new) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        let secret = scl_crypto::seal("B", b"value-of-b", std::slice::from_ref(&pk));
        let sid = repo
            .vfs()
            .store()
            .lock()
            .unwrap()
            .put(Object::Secret(secret))
            .unwrap();
        let root_id = repo.vfs().write_tree(&[]).unwrap();
        let mut secrets = std::collections::BTreeMap::new();
        secrets.insert("A".to_string(), sid);
        let tip = repo
            .commit_snapshot(
                root_id,
                vec![],
                secrets,
                scl_core::Protection::default(),
                "w",
                "plant",
            )
            .unwrap();

        let err = repo.secret_grant("A", &sk, &new).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err}");
        assert!(err.to_string().contains("sealed as \"B\""), "{err}");
        assert!(
            !repo.layout().accepted_recipients_path().exists(),
            "an approval was recorded for a grant that was refused"
        );
        assert_eq!(repo.head_tip().unwrap(), Some(tip), "the registry moved");
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // A re-seal checks the approvals after its ciphertext has opened: a corrupt
    // blob is skipped as that, and an unreadable record does not abort the run.
    #[test]
    fn rewrap_skips_a_corrupt_blob_before_it_reads_the_record() {
        let root = dir("rewrap-corrupt");
        let (sk, pk) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        put(&root, "p/x.txt", "x\n");
        repo.protect("p/", std::slice::from_ref(&pk), None).unwrap();
        let tip = repo.head_tip().unwrap().unwrap();
        let snap = repo.snapshot(&tip).unwrap();
        let (bid, mut cipher) = {
            let arc = repo.vfs().store();
            let mut store = arc.lock().unwrap();
            let entries =
                crate::worktree::tree_file_entries_with_perms(&mut store, snap.root).unwrap();
            let (bid, _, _) = entries["p/x.txt"];
            let Object::Blob(b) = store.get(&bid).unwrap() else {
                panic!("not a blob")
            };
            (bid, b.to_vec())
        };
        // The wrap still opens; the ciphertext no longer does.
        *cipher.last_mut().unwrap() ^= 0xff;
        let bad_id = Object::blob(cipher.clone()).id();
        let new_root = repo
            .vfs()
            .write_tree_with_perms(&[(
                "p/x.txt".to_string(),
                cipher,
                scl_core::FileMode::FILE,
                scl_core::PROTECTED | scl_core::RANDOMIZED,
            )])
            .unwrap();
        let mut protection = snap.protection.clone();
        let wraps = protection.wrapped[&bid].clone();
        protection.wrapped.insert(bad_id, wraps);
        repo.commit_snapshot(new_root, vec![tip], snap.secrets, protection, "w", "x")
            .unwrap();
        let record = repo.layout().accepted_recipients_path();
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();

        let report = repo
            .rewrap_with(&sk, &[], std::slice::from_ref(&pk), false, true)
            .unwrap();
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(
            report.skipped[0].1.contains("ciphertext failed to open"),
            "{:?}",
            report.skipped
        );
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // An accept or forget that changes nothing still syncs `.sc`: a retry after
    // a failed directory sync must not report success on an unsynced record.
    #[cfg(unix)]
    #[test]
    fn an_unchanged_accept_or_forget_still_syncs_the_directory() {
        let root = dir("sync");
        let (_, pk) = generate_keypair();
        let (_, other) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        repo.accept_keys("secret:S", std::slice::from_ref(&pk))
            .unwrap();
        {
            let _mode = DotScMode::new(&repo.layout().dot_sc, 0o311);
            if std::fs::File::open(&repo.layout().dot_sc).is_ok() {
                // Permissions are not enforced here (running as root).
                return;
            }
            let err = repo
                .accept_keys("secret:S", std::slice::from_ref(&pk))
                .unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{err}");
            let err = repo
                .forget_recipient("secret:S", &other.recipient_id())
                .unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{err}");
        }
        repo.accept_keys("secret:S", std::slice::from_ref(&pk))
            .unwrap();
        assert!(!repo
            .forget_recipient("secret:S", &other.recipient_id())
            .unwrap());
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // Two names the repository controls can be made to agree: the metadata name
    // of a secret sealed under another name is edited to match the registry.
    // The AEAD still binds the name it was sealed under, so `secret grant`,
    // which opens the secret with the identity, refuses it.
    #[test]
    fn secret_grant_refuses_a_secret_whose_name_metadata_was_edited() {
        let root = dir("grant-edited");
        let (sk, pk) = generate_keypair();
        let (_, new) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        let mut secret = scl_crypto::seal("B", b"value-of-b", std::slice::from_ref(&pk));
        secret.name = "A".to_string();
        let sid = repo
            .vfs()
            .store()
            .lock()
            .unwrap()
            .put(Object::Secret(secret))
            .unwrap();
        let root_id = repo.vfs().write_tree(&[]).unwrap();
        let mut secrets = std::collections::BTreeMap::new();
        secrets.insert("A".to_string(), sid);
        let tip = repo
            .commit_snapshot(
                root_id,
                vec![],
                secrets,
                scl_core::Protection::default(),
                "w",
                "plant",
            )
            .unwrap();

        let err = repo.secret_grant("A", &sk, &new).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err}");
        assert!(
            err.to_string().contains("does not open under that name"),
            "{err}"
        );
        assert!(!repo.layout().accepted_recipients_path().exists());
        assert_eq!(repo.head_tip().unwrap(), Some(tip), "the registry moved");
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // A refused grant or rotate leaves the record alone: the named key is
    // recorded only after the identity is authorized and the operation validated.
    #[test]
    fn a_refused_grant_or_rotate_records_no_approval() {
        let root = dir("refused-approval");
        let (sk, a) = generate_keypair();
        let (wrong, _) = generate_keypair();
        let (_, new) = generate_keypair();
        let repo = Repo::init(&root).unwrap();
        put(&root, "p/x.txt", "x\n");
        repo.protect("p/", std::slice::from_ref(&a), None).unwrap();
        repo.secret_add("S", b"v", std::slice::from_ref(&a))
            .unwrap();
        let record = || std::fs::read(repo.layout().accepted_recipients_path()).unwrap();
        let before = record();

        assert!(matches!(
            repo.grant("p/", &wrong, &new).unwrap_err(),
            Error::NotAuthorized(_)
        ));
        assert_eq!(
            record(),
            before,
            "a refused path grant recorded an approval"
        );
        assert!(repo.secret_grant("S", &wrong, &new).is_err());
        assert_eq!(
            record(),
            before,
            "a refused secret grant recorded an approval"
        );
        let both = [a.clone(), new.clone()];
        assert!(repo
            .secret_rotate_with("S", None, &both, std::slice::from_ref(&new), Some(&wrong))
            .is_err());
        assert_eq!(record(), before, "a refused rotate recorded an approval");
        assert!(repo
            .secret_rotate_with("NOPE", None, &both, std::slice::from_ref(&new), Some(&sk))
            .is_err());
        assert_eq!(record(), before, "a rotate of nothing recorded an approval");

        // With the right identity each lands and records the named key.
        repo.grant("p/", &sk, &new).unwrap();
        repo.secret_grant("S", &sk, &new).unwrap();
        let acc = repo.accepted().unwrap();
        for scope in ["path:p/", "secret:S"] {
            assert!(acc.unaccepted(scope, std::slice::from_ref(&new)).is_empty());
        }
        let (_, third) = generate_keypair();
        let set = [a.clone(), new.clone(), third.clone()];
        repo.secret_rotate_with("S", None, &set, std::slice::from_ref(&third), Some(&sk))
            .unwrap();
        assert!(repo
            .accepted()
            .unwrap()
            .unaccepted("secret:S", std::slice::from_ref(&third))
            .is_empty());
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }

    // The record is read, changed and written under one lock: callers on one
    // handle cannot lose each other's change.
    #[test]
    fn concurrent_accepts_on_one_handle_all_land() {
        let root = dir("concurrent");
        let repo = Repo::init(&root).unwrap();
        let keys: Vec<PublicKey> = (0..32).map(|_| generate_keypair().1).collect();
        std::thread::scope(|s| {
            for chunk in keys.chunks(8) {
                let repo = &repo;
                s.spawn(move || {
                    for k in chunk {
                        repo.accept_keys("secret:S", std::slice::from_ref(k))
                            .unwrap();
                    }
                });
            }
        });
        assert_eq!(repo.accepted().unwrap().pairs.len(), keys.len());
        drop(repo);
        let _ = std::fs::remove_dir_all(root);
    }
}
