//! Client side of the wire protocol (P12): a [`Transport`] impl that speaks
//! frames over any byte stream — in practice a child process's stdio, where
//! the child is `ssh <host> sc serve --stdio <path>` (or a test stand-in).

use std::cell::RefCell;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use scl_core::ObjectId;

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::wire::{self, Request};

/// A [`Transport`] that speaks the wire protocol over any byte stream pair.
/// Interior-mutable because the trait reads `&self` (same pattern as
/// `LocalTransport`'s store cell).
#[derive(Debug)]
pub struct WireClient<R: Read, W: Write> {
    rw: RefCell<(R, W)>,
}

impl<R: Read, W: Write> WireClient<R, W> {
    /// Exchange HELLOs and return a ready client. Fails typed: version skew is
    /// `Protocol`, a served non-repo path is `NotARepo`, a dead peer is
    /// `ConnectionLost`.
    pub fn handshake(r: R, w: W) -> Result<WireClient<R, W>> {
        let client = WireClient { rw: RefCell::new((r, w)) };
        let body = client.call(Request::Hello { version: wire::PROTOCOL_VERSION })?;
        let version = wire::decode_u32_body(&body)?;
        if version != wire::PROTOCOL_VERSION {
            return Err(Error::Protocol(format!(
                "server speaks protocol {version}, this client speaks {}",
                wire::PROTOCOL_VERSION
            )));
        }
        Ok(client)
    }

    /// One request/response round trip; returns the OK body or the typed error.
    fn call(&self, req: Request) -> Result<Vec<u8>> {
        let mut rw = self.rw.borrow_mut();
        wire::write_frame(&mut rw.1, &req.encode())?;
        let frame = wire::read_frame(&mut rw.0)?;
        wire::parse_response(frame)
    }

    /// Announce a clean end of session (the peer exits its serve loop).
    pub fn bye(&self) -> Result<()> {
        let mut rw = self.rw.borrow_mut();
        wire::write_frame(&mut rw.1, &Request::Bye.encode())
    }
}

impl<R: Read, W: Write> Transport for WireClient<R, W> {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        wire::decode_refs_body(&self.call(Request::ListRefs)?)
    }
    fn head_branch(&self) -> Result<String> {
        wire::decode_str_body(&self.call(Request::HeadBranch)?)
    }
    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        wire::decode_bool_body(&self.call(Request::HasObject(*id))?)
    }
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.call(Request::GetObject(*id))
    }
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        self.call(Request::PutObject { id: *id, bytes: bytes.to_vec() })?;
        Ok(())
    }
    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        self.call(Request::UpdateRef {
            branch: branch.to_string(),
            id: *id,
            expected_old: expected_old.copied(),
        })?;
        Ok(())
    }
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>> {
        self.call(Request::GetPack { wants: wants.to_vec(), haves: haves.to_vec() })
    }
    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>> {
        wire::decode_ids_body(&self.call(Request::PutPack(pack.to_vec()))?)
    }
}

/// A [`Transport`] whose far end is a child process speaking the wire protocol
/// on its stdio — `ssh <host> sc serve --stdio <path>` for real remotes.
#[derive(Debug)]
pub struct StdioTransport {
    client: WireClient<std::io::BufReader<ChildStdout>, ChildStdin>,
    child: Child,
}

impl StdioTransport {
    /// Spawn `cmd` with piped stdio and perform the handshake. On a dead or
    /// broken child (ssh auth failure, `sc` missing on the remote), the
    /// child's stderr is folded into the error so the user sees the real cause.
    pub fn spawn(mut cmd: Command) -> Result<StdioTransport> {
        let program = cmd.get_program().to_string_lossy().into_owned();
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::ConnectionLost(format!("failed to spawn {program}: {e}")))?;
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = std::io::BufReader::new(child.stdout.take().expect("stdout piped"));
        match WireClient::handshake(stdout, stdin) {
            Ok(client) => Ok(StdioTransport { client, child }),
            Err(Error::ConnectionLost(msg)) => {
                let stderr = reap_with_stderr(&mut child);
                Err(Error::ConnectionLost(if stderr.is_empty() {
                    format!("{program}: {msg}")
                } else {
                    format!("{program}: {msg}; remote said: {}", stderr.trim())
                }))
            }
            Err(other) => {
                let _ = reap_with_stderr(&mut child);
                Err(other) // typed errors (NotARepo, Protocol) pass through
            }
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.client.bye(); // best-effort: the server exits its loop
        let _ = self.child.wait();
    }
}

/// Kill + reap the child and return up to 64 KiB of its stderr for error text.
fn reap_with_stderr(child: &mut Child) -> String {
    let _ = child.kill();
    let mut text = String::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(64 * 1024).read_to_string(&mut text);
    }
    let _ = child.wait();
    text
}

impl Transport for StdioTransport {
    fn list_refs(&self) -> Result<Vec<(String, ObjectId)>> {
        self.client.list_refs()
    }
    fn head_branch(&self) -> Result<String> {
        self.client.head_branch()
    }
    fn has_object(&self, id: &ObjectId) -> Result<bool> {
        self.client.has_object(id)
    }
    fn get_object(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.client.get_object(id)
    }
    fn put_object(&self, id: &ObjectId, bytes: &[u8]) -> Result<()> {
        self.client.put_object(id, bytes)
    }
    fn update_ref(
        &self,
        branch: &str,
        id: &ObjectId,
        expected_old: Option<&ObjectId>,
    ) -> Result<()> {
        self.client.update_ref(branch, id, expected_old)
    }
    fn get_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> Result<Vec<u8>> {
        self.client.get_pack(wants, haves)
    }
    fn put_pack(&self, pack: &[u8]) -> Result<Vec<ObjectId>> {
        self.client.put_pack(pack)
    }
}

/// A parsed `ssh://[user@]host[:port]/abs/path` remote URL.
///
/// The path is the repo root *on the server* and keeps its leading `/`.
/// Known limitations: paths containing spaces are unsupported over real ssh
/// (the remote shell splits the command) — see ADR-0022; IPv6 host literals
/// (`ssh://[::1]:22/…`) and usernames containing `@` are not understood by
/// this parser (both fail or misparse into a host ssh will reject).
///
/// A host or user starting with `-` is rejected at parse time: `ssh_command`
/// places them as bare argv positionals (`user@host`), and `ssh` itself
/// parses a leading `-` as an option flag — the Git CVE-2017-1000117 class of
/// argv injection (flag smuggling). The trailing `--` in `ssh_command` only
/// protects the remote command, not the host/user positional, so this must
/// be caught here before anything spawns.
#[derive(Debug, Clone, PartialEq)]
pub struct SshUrl {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

impl SshUrl {
    /// Parse an `ssh://` URL; anything malformed is `InvalidArgument` with a
    /// message naming the URL, so `remote add` can fail fast.
    pub fn parse(url: &str) -> Result<SshUrl> {
        let rest = url
            .strip_prefix("ssh://")
            .ok_or_else(|| Error::InvalidArgument(format!("not an ssh:// url: {url}")))?;
        let slash = rest
            .find('/')
            .ok_or_else(|| Error::InvalidArgument(format!("ssh url has no repo path: {url}")))?;
        let (authority, path) = rest.split_at(slash);
        let (user, hostport) = match authority.split_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, authority),
        };
        let (host, port) = match hostport.split_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    Error::InvalidArgument(format!("bad port in ssh url: {url}"))
                })?;
                (h, Some(port))
            }
            None => (hostport, None),
        };
        if host.is_empty() {
            return Err(Error::InvalidArgument(format!("ssh url has empty host: {url}")));
        }
        if host.starts_with('-') {
            return Err(Error::InvalidArgument(format!(
                "ssh url host looks like an option flag: {url}"
            )));
        }
        if let Some(u) = &user {
            if u.starts_with('-') {
                return Err(Error::InvalidArgument(format!(
                    "ssh url host looks like an option flag: {url}"
                )));
            }
        }
        Ok(SshUrl { user, host: host.to_string(), port, path: path.to_string() })
    }
}

/// The command that reaches `sc serve --stdio` on the far side: the user's
/// `ssh` binary (or `$SC_SSH`, Git's `GIT_SSH` pattern — tests and the demo
/// point it at a shim so the whole ssh:// path runs without an sshd).
pub(crate) fn ssh_command(url: &SshUrl) -> Command {
    let program = std::env::var("SC_SSH").unwrap_or_else(|_| "ssh".to_string());
    let mut cmd = Command::new(program);
    if let Some(port) = url.port {
        cmd.arg("-p").arg(port.to_string());
    }
    match &url.user {
        Some(user) => cmd.arg(format!("{user}@{}", url.host)),
        None => cmd.arg(&url.host),
    };
    cmd.arg("--").arg("sc").arg("serve").arg("--stdio").arg(&url.path);
    cmd
}

/// Open the right [`Transport`] for a remote URL: `ssh://` spawns the wire
/// client; anything else is a local `.sc/` path.
pub fn open_transport(url: &str) -> Result<Box<dyn Transport>> {
    if url.starts_with("ssh://") {
        let parsed = SshUrl::parse(url)?;
        Ok(Box::new(StdioTransport::spawn(ssh_command(&parsed))?))
    } else {
        Ok(Box::new(crate::transport::LocalTransport::open(url)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::transport::{LocalTransport, Transport};
    use crate::wire;
    use scl_core::Object;

    fn tmp_repo(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("scl-stdio-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        crate::repo::Repo::init(&root).unwrap();
        root
    }

    /// Connect a WireClient to a `wire::serve` thread over in-process pipes.
    /// Returns the client and the server thread handle.
    fn connect(
        root: std::path::PathBuf,
    ) -> (WireClient<std::io::PipeReader, std::io::PipeWriter>, std::thread::JoinHandle<crate::error::Result<()>>)
    {
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let handle =
            std::thread::spawn(move || wire::serve(&root, &mut server_read, &mut server_write));
        let client = WireClient::handshake(client_read, client_write).unwrap();
        (client, handle)
    }

    #[test]
    fn wire_client_satisfies_the_transport_contract() {
        let root = tmp_repo("contract");
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let tip = crate::repo::Repo::open(&root).unwrap().commit("t", "c1").unwrap();

        let (client, server) = connect(root.clone());

        // refs + head
        assert_eq!(client.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert_eq!(client.head_branch().unwrap(), "main");

        // object roundtrip + corrupt put rejected remotely
        let blob = Object::blob(b"over the wire".to_vec());
        let (id, bytes) = (blob.id(), blob.encode());
        assert!(!client.has_object(&id).unwrap());
        client.put_object(&id, &bytes).unwrap();
        assert!(client.has_object(&id).unwrap());
        assert_eq!(client.get_object(&id).unwrap(), bytes);
        assert!(client.put_object(&id, b"tampered").is_err());

        // pack roundtrip: everything reachable from the tip, no haves
        let pack = client.get_pack(&[tip], &[]).unwrap();
        assert!(!scl_core::pack::parse_pack(&pack).unwrap().is_empty());

        // CAS semantics survive the wire (mirrors transport.rs::update_ref_is_compare_and_swap)
        let c2 = Object::blob(b"c2".to_vec()).id();
        assert!(matches!(client.update_ref("main", &c2, None), Err(Error::NonFastForward)));

        client.bye().unwrap();
        drop(client);
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn handshake_surfaces_not_a_repo_as_typed_error() {
        let root = std::env::temp_dir().join(format!("scl-stdio-norepo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let root2 = root.clone();
        let server =
            std::thread::spawn(move || wire::serve(&root2, &mut server_read, &mut server_write));
        let err = WireClient::handshake(client_read, client_write).unwrap_err();
        assert!(matches!(err, Error::NotARepo), "got {err:?}");
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn handshake_rejects_version_skew() {
        // Hand-rolled "future server" that answers HELLO with version 2.
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let server = std::thread::spawn(move || {
            let f = wire::read_frame(&mut server_read).unwrap();
            assert!(matches!(wire::Request::decode(&f).unwrap(), wire::Request::Hello { .. }));
            wire::write_ok(&mut server_write, &wire::u32_body(2)).unwrap();
        });
        let err = WireClient::handshake(client_read, client_write).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
        server.join().unwrap();
    }

    #[test]
    fn dropped_connection_mid_push_is_typed_and_leaves_remote_ref_intact() {
        // A server that dies exactly when asked to move the ref — the worst
        // moment for a push. Objects are already transferred (put_pack ran);
        // the ref must be untouched and the client must see ConnectionLost.
        let root = tmp_repo("droppush");
        std::fs::write(root.join("a.txt"), b"one").unwrap();
        let tip = crate::repo::Repo::open(&root).unwrap().commit("t", "c1").unwrap();

        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let root2 = root.clone();
        let server = std::thread::spawn(move || {
            let f = wire::read_frame(&mut server_read).unwrap();
            assert!(matches!(wire::Request::decode(&f).unwrap(), wire::Request::Hello { .. }));
            wire::write_ok(&mut server_write, &wire::u32_body(wire::PROTOCOL_VERSION)).unwrap();
            let t = LocalTransport::open(&root2).unwrap();
            loop {
                let f = match wire::read_frame_opt(&mut server_read).unwrap() {
                    Some(f) => f,
                    None => return,
                };
                match wire::Request::decode(&f).unwrap() {
                    wire::Request::UpdateRef { .. } => return, // die without replying
                    wire::Request::PutPack(p) => {
                        let ids = t.put_pack(&p).unwrap();
                        wire::write_ok(&mut server_write, &wire::ids_body(&ids)).unwrap();
                    }
                    other => panic!("unexpected request {other:?}"),
                }
            }
        });

        let client = WireClient::handshake(client_read, client_write).unwrap();
        // "Push": transfer a pack, then try to advance the ref.
        let blob = Object::blob(b"new object".to_vec());
        let (pack, _idx) = scl_core::pack::build_pack(&[(blob.id(), blob.encode())]).unwrap();
        client.put_pack(&pack).unwrap();
        let err = client.update_ref("main", &blob.id(), Some(&tip)).unwrap_err();
        assert!(matches!(err, Error::ConnectionLost(_)), "got {err:?}");
        drop(client);
        server.join().unwrap();

        // The remote ref never moved; the transferred object is merely unreachable.
        let t = LocalTransport::open(&root).unwrap();
        assert_eq!(t.list_refs().unwrap(), vec![("main".to_string(), tip)]);
        assert!(t.has_object(&blob.id()).unwrap());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn stdio_transport_spawn_failure_names_the_program() {
        let cmd = std::process::Command::new("/nonexistent/definitely-not-a-program");
        let err = StdioTransport::spawn(cmd).unwrap_err();
        match err {
            Error::ConnectionLost(msg) => assert!(msg.contains("definitely-not-a-program")),
            other => panic!("expected ConnectionLost, got {other:?}"),
        }
    }

    #[test]
    fn ssh_url_parses_all_forms() {
        let u = SshUrl::parse("ssh://alice@host.example:2222/srv/repo").unwrap();
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.host, "host.example");
        assert_eq!(u.port, Some(2222));
        assert_eq!(u.path, "/srv/repo");

        let u = SshUrl::parse("ssh://host/repo").unwrap();
        assert_eq!(u.user, None);
        assert_eq!(u.port, None);
        assert_eq!(u.host, "host");
        assert_eq!(u.path, "/repo");
    }

    #[test]
    fn ssh_url_rejects_malformed_forms() {
        for bad in [
            "/plain/path",                     // not ssh
            "ssh://host",                      // no path
            "ssh:///path",                     // empty host
            "ssh://host:notaport/path",        // bad port
            "ssh://-oProxyCommand=evil/path",  // host looks like an option flag
            "ssh://-user@host/path",           // user looks like an option flag
        ] {
            assert!(
                matches!(SshUrl::parse(bad), Err(Error::InvalidArgument(_))),
                "should reject {bad}"
            );
        }
    }

    #[test]
    fn ssh_url_allows_hosts_with_internal_dashes() {
        let u = SshUrl::parse("ssh://my-host/path").unwrap();
        assert_eq!(u.host, "my-host");
        assert_eq!(u.user, None);
        assert_eq!(u.path, "/path");
    }

    #[test]
    fn ssh_command_builds_the_expected_argv() {
        let u = SshUrl::parse("ssh://alice@host:2222/srv/repo").unwrap();
        let cmd = ssh_command(&u);
        let args: Vec<String> =
            cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["-p", "2222", "alice@host", "--", "sc", "serve", "--stdio", "/srv/repo"]);

        let u = SshUrl::parse("ssh://host/repo").unwrap();
        let cmd = ssh_command(&u);
        let args: Vec<String> =
            cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["host", "--", "sc", "serve", "--stdio", "/repo"]);
    }

    #[test]
    fn open_transport_dispatches_local_paths_to_local_transport() {
        let root = tmp_repo("factory");
        // A plain path must open (LocalTransport) and answer verbs.
        let t = open_transport(root.to_str().unwrap()).unwrap();
        assert_eq!(t.head_branch().unwrap(), "main");
        // A malformed ssh URL fails fast in parsing, before spawning anything.
        assert!(matches!(open_transport("ssh://nopath"), Err(Error::InvalidArgument(_))));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
