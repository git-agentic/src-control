//! `sc serve --store sc+git::` (ADR-0060). The private-branch gate is a security
//! boundary: whatever order of `PutObject`, `PutPack` and `UpdateRef` a client
//! sends, a refused request must leave no `refs/sc/*` and no sealed object on
//! the Git host. Every test drives a real bare repository and inspects it.

use crate::error::Error;
use crate::repo::Repo;
use crate::stdio_transport::WireClient;
use crate::transport::Transport;
use crate::wire::{serve_bucket_with_policy, WirePolicy};
use scl_core::{Object, ObjectId};
use scl_objio::{Bucket, Fetched};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

fn have_git() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

macro_rules! need_git {
    () => {
        if !have_git() {
            eprintln!("git not available; skipping");
            return;
        }
    };
}

fn root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scl-bt-gitserve-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A bare Git repository standing in for the host.
struct Hub {
    dir: PathBuf,
    bare: PathBuf,
    /// The `sc+git::` store URL.
    url: String,
}

impl Hub {
    fn new(tag: &str) -> Hub {
        let dir = root(&format!("{tag}-hub"));
        let bare = dir.join("hub.git");
        git(&dir, &["init", "--bare", "-q", bare.to_str().unwrap()]);
        let url = format!("sc+git::file://{}", bare.display());
        Hub { dir, bare, url }
    }

    /// Every `refs/sc/*` ref on the host.
    fn refs(&self) -> String {
        git(&self.bare, &["for-each-ref", "refs/sc/"])
    }

    /// Every object on the host (not only the reachable ones).
    fn objects(&self) -> String {
        git(
            &self.bare,
            &["cat-file", "--batch-all-objects", "--batch-check"],
        )
    }

    /// No pack stored on the host holds an object of a sealed-branch kind.
    fn assert_no_sealed(&self) {
        let b = scl_objio::GitBucket::open(&format!("file://{}", self.bare.display())).unwrap();
        for key in b
            .list("packs/")
            .unwrap()
            .into_iter()
            .filter(|k| k.ends_with(".pack"))
        {
            let Fetched::New { bytes, .. } = b.get(&key, None).unwrap() else {
                panic!("listed pack {key} is absent")
            };
            for (_, obj) in scl_core::pack::parse_pack(&bytes).unwrap() {
                assert!(
                    !matches!(obj, Object::Sealed(_) | Object::Manifest(_)),
                    "a sealed object reached the Git host in {key}"
                );
            }
        }
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An initialized directory used only as the serve home.
fn serve_home(tag: &str) -> PathBuf {
    let d = root(&format!("{tag}-home"));
    drop(Repo::init(&d).unwrap());
    d
}

fn encoded(repo: &Repo, tip: ObjectId) -> Vec<(ObjectId, Vec<u8>)> {
    let store_arc = repo.vfs().store();
    let mut store = store_arc.lock().unwrap();
    crate::reachable::reachable_objects(&mut *store, &[tip])
        .unwrap()
        .into_iter()
        .map(|id| (id, store.get(&id).unwrap().encode()))
        .collect()
}

fn is_sealed_kind(bytes: &[u8]) -> bool {
    matches!(
        Object::decode(bytes),
        Ok(Object::Sealed(_) | Object::Manifest(_))
    )
}

fn pack_of(objects: &[(ObjectId, Vec<u8>)]) -> Cursor<Vec<u8>> {
    Cursor::new(scl_core::pack::build_pack(objects).unwrap().0)
}

/// A repository with a public `main` and a private branch `emb`.
struct World {
    dir: PathBuf,
    repo: Repo,
    sk: scl_crypto::SecretKey,
    main: ObjectId,
    /// Everything reachable from `main`.
    public: Vec<(ObjectId, Vec<u8>)>,
    /// The private branch's manifest tip.
    emb: ObjectId,
    /// What a push of `emb` sends beyond `public`, sealed-kind objects included.
    private: Vec<(ObjectId, Vec<u8>)>,
}

impl World {
    fn new(tag: &str) -> World {
        let dir = root(&format!("{tag}-world"));
        let repo = Repo::init(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), "public\n").unwrap();
        let main = repo.commit("t", "base").unwrap();
        let (sk, pk) = scl_crypto::generate_keypair();
        repo.branch_private("emb", &sk, std::slice::from_ref(&pk), &[])
            .unwrap();
        repo.switch_with_identity("emb", Some(&sk)).unwrap();
        let mut w = World {
            public: encoded(&repo, main),
            main,
            emb: main,
            private: Vec::new(),
            dir,
            repo,
            sk,
        };
        w.commit_private("embargo.txt", "embargoed\n");
        w
    }

    /// Commit one more file on `emb`; sets `emb` and `private` to the new tip's
    /// objects that `main` does not already carry.
    fn commit_private(&mut self, file: &str, text: &str) {
        std::fs::write(self.dir.join(file), text).unwrap();
        self.repo
            .commit_private("t", "embargoed", Some(&self.sk))
            .unwrap();
        let (_, tip, _) = self.repo.head_private().unwrap().unwrap();
        self.emb = tip;
        let known: std::collections::BTreeSet<ObjectId> =
            self.public.iter().map(|(id, _)| *id).collect();
        self.private = encoded(&self.repo, tip)
            .into_iter()
            .filter(|(id, _)| !known.contains(id))
            .collect();
        assert!(
            self.private.iter().any(|(_, b)| is_sealed_kind(b)),
            "premise: the private branch has sealed objects"
        );
    }

    fn everything(&self) -> Vec<(ObjectId, Vec<u8>)> {
        let mut all = self.public.clone();
        all.extend(self.private.iter().cloned());
        all
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

type Client = WireClient<std::io::PipeReader, std::io::PipeWriter>;
type Server = std::thread::JoinHandle<crate::error::Result<()>>;

/// One `--stdio`-style session over pipes, served from `home` into `store`.
fn session(store: &str, home: &Path, policy: WirePolicy) -> (Client, Server) {
    let (client_read, mut server_write) = std::io::pipe().unwrap();
    let (mut server_read, client_write) = std::io::pipe().unwrap();
    let (store, home) = (store.to_string(), home.to_path_buf());
    let srv = std::thread::spawn(move || {
        serve_bucket_with_policy(&store, &home, &mut server_read, &mut server_write, policy)
    });
    (
        WireClient::handshake(client_read, client_write).unwrap(),
        srv,
    )
}

fn finish(client: Client, srv: Server) {
    client.bye().unwrap();
    drop(client);
    srv.join().unwrap().unwrap();
}

/// The refusal names the server-side flag.
fn assert_refused(e: &Error) {
    let m = e.to_string();
    assert!(m.contains("--allow-private-branches"), "{m}");
    assert!(m.contains("Nothing was uploaded"), "{m}");
}

fn allowing() -> WirePolicy {
    WirePolicy {
        allow_private_branches: true,
        ..Default::default()
    }
}

/// Every order a hostile client can try: a pack mixing public and sealed
/// objects, loose sealed objects, a ref at a manifest, then a clean public
/// push in the same session. Nothing sealed may reach the host, and the
/// session keeps serving.
#[test]
fn a_gated_session_never_lets_a_sealed_object_reach_the_host() {
    need_git!();
    let w = World::new("gate");
    let hub = Hub::new("gate");
    let home = serve_home("gate");
    let (client, srv) = session(&hub.url, &home, WirePolicy::default());

    // A mixed pack: the public part comes first, so a check that only looked at
    // the first record would pass it.
    assert_refused(&client.put_pack(&mut pack_of(&w.everything())).unwrap_err());
    assert_eq!(hub.refs(), "", "a refused pack adds no ref");
    assert_eq!(hub.objects(), "", "a refused pack adds no object");

    // Loose objects: refused before they are staged.
    for (id, bytes) in w.private.iter().filter(|(_, b)| is_sealed_kind(b)) {
        assert_refused(&client.put_object(id, bytes).unwrap_err());
    }
    // A ref at a manifest that was never ingested fails too.
    assert!(client.update_ref("emb", &w.emb, None).is_err());
    assert_eq!(hub.refs(), "", "refused objects and refs add nothing");

    // The same session still takes a public push, and only that reaches the host.
    client.put_pack(&mut pack_of(&w.public)).unwrap();
    client.update_ref("main", &w.main, None).unwrap();
    assert!(client.update_ref("emb", &w.emb, None).is_err());
    finish(client, srv);

    let t = crate::bucket_transport::BucketTransport::open(&hub.url).unwrap();
    assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), w.main)]);
    hub.assert_no_sealed();
    drop(t);
    let tmp = home.join(".sc").join("tmp");
    assert!(
        !tmp.exists() || std::fs::read_dir(&tmp).unwrap().next().is_none(),
        "the Git cache and the spool must be gone with the session"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A private branch that already sits on the host cannot be advanced, or
/// another ref pointed at its manifest, through a gated server; with the
/// operator's flag the same requests work.
#[test]
fn an_existing_private_branch_cannot_be_advanced_or_repointed_without_the_flag() {
    need_git!();
    let mut w = World::new("advance");
    let hub = Hub::new("advance");
    // Put both branches on the host directly, as a writer with push access would.
    {
        let t = crate::bucket_transport::BucketTransport::open(&hub.url).unwrap();
        t.put_pack(&mut pack_of(&w.everything())).unwrap();
        t.update_ref("main", &w.main, None).unwrap();
        t.update_ref("emb", &w.emb, None).unwrap();
    }
    let (old_emb, old_private) = (w.emb, w.private.clone());
    w.commit_private("more.txt", "more embargoed\n");
    let (new_emb, new_private) = (w.emb, w.private.clone());
    assert_ne!(old_emb, new_emb);
    let before = hub.refs();

    let home = serve_home("advance");
    let (client, srv) = session(&hub.url, &home, WirePolicy::default());
    // The advance sends new sealed objects and a new manifest.
    assert_refused(&client.put_pack(&mut pack_of(&new_private)).unwrap_err());
    assert!(client.update_ref("emb", &new_emb, Some(&old_emb)).is_err());
    // Pointing a ref at a manifest already on the host needs no new object, so
    // only the ref check can stop it.
    assert_refused(&client.update_ref("emb-copy", &old_emb, None).unwrap_err());
    assert_eq!(hub.refs(), before, "nothing was written");
    finish(client, srv);

    // With the opt-in the very same requests succeed.
    let (client, srv) = session(&hub.url, &home, allowing());
    client.put_pack(&mut pack_of(&new_private)).unwrap();
    client.update_ref("emb", &new_emb, Some(&old_emb)).unwrap();
    client.update_ref("emb-copy", &old_emb, None).unwrap();
    finish(client, srv);
    let t = crate::bucket_transport::BucketTransport::open(&hub.url).unwrap();
    let refs: std::collections::BTreeMap<_, _> = t.list_refs().unwrap().into_iter().collect();
    assert_eq!(refs.get("emb"), Some(&new_emb));
    assert_eq!(refs.get("emb-copy"), Some(&old_emb));
    drop((t, old_private));
    let _ = std::fs::remove_dir_all(&home);
}

/// The flag only matters for a `sc+git::` store: the other stores take private
/// branches as before, whatever the policy says.
#[test]
fn the_gate_applies_to_git_stores_only() {
    let w = World::new("wal");
    let dir = root("wal-store");
    let store = format!("sc+wal://{}", dir.join("bucket").display());
    let home = serve_home("wal");
    let (client, srv) = session(&store, &home, WirePolicy::default());
    client.put_pack(&mut pack_of(&w.everything())).unwrap();
    client.update_ref("emb", &w.emb, None).unwrap();
    finish(client, srv);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&home);
}

/// A listener on 127.0.0.1 serving `store` from `home`; returns its port.
fn spawn_http(home: PathBuf, store: String, allow_private_branches: bool) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        crate::http_transport::serve_http_listener(
            listener,
            &home,
            false,
            false,
            crate::http_transport::ServeLimits {
                allow_private_branches,
                ..Default::default()
            },
            None,
            Some(store),
        )
        .unwrap();
    });
    port
}

/// The same boundary through `sc serve --http` with a real client: a private
/// branch pushed through a gated server is refused and leaves the host as it
/// was; through a server started with the flag it lands, and advancing it is
/// refused again on the gated one.
#[test]
fn http_push_of_a_private_branch_needs_the_servers_opt_in() {
    need_git!();
    let hub = Hub::new("http");
    let (home_a, home_b) = (serve_home("http-a"), serve_home("http-b"));
    let port_a = spawn_http(home_a.clone(), hub.url.clone(), false);
    let port_b = spawn_http(home_b.clone(), hub.url.clone(), true);

    let mut w = World::new("http");
    // `World::new` leaves `emb` checked out; a public push needs `main`.
    w.repo.switch_with_identity("main", Some(&w.sk)).unwrap();
    w.repo
        .remote_add("a", &format!("sc+http://127.0.0.1:{port_a}/x"))
        .unwrap();
    w.repo
        .remote_add("b", &format!("sc+http://127.0.0.1:{port_b}/x"))
        .unwrap();
    w.repo.push("a").unwrap(); // public content needs no opt-in
    let public_only = hub.refs();
    assert!(!public_only.is_empty());

    w.repo.switch_with_identity("emb", Some(&w.sk)).unwrap();
    assert_refused(&w.repo.push("a").unwrap_err());
    assert_eq!(
        hub.refs(),
        public_only,
        "the refused push left the host as it was"
    );
    hub.assert_no_sealed();

    w.repo.push("b").unwrap(); // the operator of b opted in
    let with_private = hub.refs();
    assert_ne!(with_private, public_only);

    w.commit_private("later.txt", "later\n");
    assert_refused(&w.repo.push("a").unwrap_err());
    assert_eq!(
        hub.refs(),
        with_private,
        "an existing private branch is not advanced"
    );
    w.repo.push("b").unwrap();
    assert_ne!(hub.refs(), with_private);

    let t = crate::bucket_transport::BucketTransport::open(&hub.url).unwrap();
    let refs: std::collections::BTreeMap<_, _> = t.list_refs().unwrap().into_iter().collect();
    assert_eq!(refs.get("emb"), Some(&w.emb));
    drop(t);
    // A client returns before the server thread has dropped its session, so
    // wait (bounded) for the caches to go; they must not outlive the sessions.
    for h in [&home_a, &home_b] {
        let tmp = h.join(".sc").join("tmp");
        let empty = || !tmp.exists() || std::fs::read_dir(&tmp).unwrap().next().is_none();
        for _ in 0..100 {
            if empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(empty(), "a Git cache outlived its session in {h:?}");
    }
}
