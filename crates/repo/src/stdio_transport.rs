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
    /// Bounded (P25): send the request, then destream the server's
    /// `ST_PACK_CHUNK`/`ST_PACK_END` response frames straight into `out` via
    /// `read_pack_stream` — peak RAM is one chunk. `out` ends up holding the
    /// exact raw `.pack` bytes the pre-P25 single-frame response used to
    /// deliver directly, so this stays a drop-in `Transport::get_pack`: every
    /// existing caller (`sync::transfer_objects`, the repo.rs delta-fetch
    /// regression test) still calls `parse_pack` on `out` unchanged. Doesn't
    /// use `self.call` — that helper only reads one response frame, and this
    /// needs to keep reading off the same connection afterward.
    fn get_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        filter: Option<&[String]>,
        out: &mut dyn Write,
    ) -> Result<()> {
        let mut rw = self.rw.borrow_mut();
        wire::write_frame(
            &mut rw.1,
            &Request::GetPack {
                wants: wants.to_vec(),
                haves: haves.to_vec(),
                filter: filter.map(|f| f.to_vec()).unwrap_or_default(),
            }
            .encode(),
        )?;
        let frame = wire::read_frame(&mut rw.0)?;
        wire::parse_response(frame)?; // Ok(empty body) means "stream follows"; Err propagates typed
        wire::read_pack_stream(&mut rw.0, out)?;
        Ok(())
    }

    /// Bounded (P25): send the marker request, then stream `src` onto the
    /// connection as `ST_PACK_CHUNK`/`ST_PACK_END` frames (peak RAM one
    /// chunk) before reading the response — the server destreams as it
    /// reads, so nothing on either side ever buffers the whole pack.
    fn put_pack(&self, src: &mut dyn Read) -> Result<Vec<ObjectId>> {
        let mut rw = self.rw.borrow_mut();
        wire::write_frame(&mut rw.1, &Request::PutPack.encode())?;
        wire::write_pack_stream(&mut rw.1, src, wire::pack_chunk_size())?;
        let frame = wire::read_frame(&mut rw.0)?;
        wire::decode_ids_body(&wire::parse_response(frame)?)
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
    fn get_pack(
        &self,
        wants: &[ObjectId],
        haves: &[ObjectId],
        filter: Option<&[String]>,
        out: &mut dyn Write,
    ) -> Result<()> {
        self.client.get_pack(wants, haves, filter, out)
    }
    fn put_pack(&self, src: &mut dyn Read) -> Result<Vec<ObjectId>> {
        self.client.put_pack(src)
    }
}

/// A parsed `ssh://[user@]host[:port]/abs/path` remote URL.
///
/// The path is the repo root *on the server* and keeps its leading `/`.
/// Known limitations: the repo path must be shell-inert — spaces and shell
/// metacharacters are rejected at parse time, because the remote args are
/// concatenated into the far host's login shell (see ADR-0022 and the command-
/// injection guard in `parse`); IPv6 host literals (`ssh://[::1]:22/…`) and
/// usernames containing `@` are not understood by this parser (both fail or
/// misparse into a host ssh will reject).
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
        // `ssh host -- sc serve --stdio <path>` concatenates the remote args and
        // hands them to the far host's *login shell*, so a metacharacter in the
        // path (`;`, `|`, `$(…)`, a space, …) executes on the remote — command
        // injection, the class Git closes by shell-quoting the repo path. We fail
        // closed instead: reject any path that isn't shell-inert. This also
        // enforces the previously-documented "spaces unsupported" limitation.
        if let Some(bad) = path.chars().find(|c| !is_shell_safe_path_char(*c)) {
            return Err(Error::InvalidArgument(format!(
                "ssh url path has a shell-unsafe character {bad:?}: {url}"
            )));
        }
        // Belt-and-suspenders: host/user reach ssh as argv, not a shell, but
        // whitespace or control bytes there are never a legitimate hostname and
        // only invite confusion — reject them too.
        if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Error::InvalidArgument(format!("ssh url host is malformed: {url}")));
        }
        if let Some(u) = &user {
            if u.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(Error::InvalidArgument(format!("ssh url user is malformed: {url}")));
            }
        }
        Ok(SshUrl { user, host: host.to_string(), port, path: path.to_string() })
    }
}

/// Characters allowed in an ssh URL repo path. A conservative allow-list of
/// bytes that carry no meaning to a POSIX shell, so the path survives the
/// remote shell verbatim. Everything else (whitespace and every shell
/// metacharacter) is rejected at parse time.
fn is_shell_safe_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "/._-+@:~=,%".contains(c)
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
/// client over a child process's stdio, `sc+http://` dials it directly over
/// TCP; anything else is a local `.sc/` path.
pub fn open_transport(url: &str) -> Result<Box<dyn Transport>> {
    if url.starts_with("ssh://") {
        let parsed = SshUrl::parse(url)?;
        Ok(Box::new(StdioTransport::spawn(ssh_command(&parsed))?))
    } else if url.starts_with("sc+http://") {
        let parsed = crate::http_transport::ScHttpUrl::parse(url)?;
        Ok(Box::new(crate::http_transport::HttpTransport::connect(&parsed)?))
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
        let mut pack = Vec::new();
        client.get_pack(&[tip], &[], None, &mut pack).unwrap();
        assert!(!scl_core::pack::parse_pack(&pack).unwrap().is_empty());

        // CAS semantics survive the wire (mirrors transport.rs::update_ref_is_compare_and_swap)
        let c2 = Object::blob(b"c2".to_vec()).id();
        assert!(matches!(client.update_ref("main", &c2, None), Err(Error::NonFastForward)));

        client.bye().unwrap();
        drop(client);
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// P27 Task 3: the `GetPack.filter` wire field round-trips end-to-end —
    /// a client requesting `filter=Some(["src/"])` over the actual wire
    /// protocol (not just direct `LocalTransport` calls, as
    /// `transport::tests::filtered_get_pack_excludes_out_of_prefix` covers)
    /// gets back a pack missing the out-of-filter blob.
    #[test]
    fn filtered_get_pack_over_wire() {
        let root = tmp_repo("filtered");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/a"), b"src-a").unwrap();
        std::fs::write(root.join("docs/b"), b"docs-b").unwrap();
        let tip = crate::repo::Repo::open(&root).unwrap().commit("t", "c1").unwrap();
        let src_a_id = Object::blob(b"src-a".to_vec()).id();
        let docs_b_id = Object::blob(b"docs-b".to_vec()).id();

        let (client, server) = connect(root.clone());

        let mut pack = Vec::new();
        client.get_pack(&[tip], &[], Some(&["src/".to_string()]), &mut pack).unwrap();
        let ids: Vec<_> =
            scl_core::pack::parse_pack(&pack).unwrap().into_iter().map(|(id, _)| id).collect();
        assert!(ids.contains(&tip), "snapshot must transfer");
        assert!(ids.contains(&src_a_id), "in-filter blob must transfer");
        assert!(!ids.contains(&docs_b_id), "out-of-filter blob must NOT transfer over the wire");

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
    fn handshake_rejects_v2_peer() {
        // Hand-rolled "old server" that answers HELLO with the retired v2
        // (P27 bumped PROTOCOL_VERSION 2 -> 3: `GetPack` gained a `filter`
        // field a v2 decoder doesn't know to read, so a v2 peer must be
        // refused just as cleanly as a too-new one).
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
                    wire::Request::PutPack => {
                        let mut buf = Vec::new();
                        wire::read_pack_stream(&mut server_read, &mut buf).unwrap();
                        let ids = t.put_pack(&mut &buf[..]).unwrap();
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
        client.put_pack(&mut &pack[..]).unwrap();
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

    // SC_PACK_CHUNK env mutation races parallel tests in this module that
    // also transfer packs over the wire (their assertions don't depend on
    // chunk count, so a stray override is harmless to them — see the P25
    // task report — but two tests in THIS module deliberately want a small,
    // stable override for their own duration). Mirrors
    // `crates/cli/src/main.rs`'s `GIT_ENV_LOCK` pattern.
    static PACK_CHUNK_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// P25 correctness heart, end-to-end: a real `wire::serve` thread on
    /// each side, `GetPack` fetched with the server forced to a tiny
    /// `SC_PACK_CHUNK` (so its `ST_PACK_CHUNK` response is provably
    /// many-framed, hand-counted below since `WireClient::get_pack`
    /// de-chunks internally), then the fetched pack pushed into a second
    /// repo via `PutPack` streamed with an explicit tiny `chunk_size` (no
    /// env var needed for this leg — full control without touching global
    /// state).
    #[test]
    fn streaming_push_and_fetch_round_trip_tiny_chunks() {
        let _env_guard = PACK_CHUNK_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let root = tmp_repo("streaming-src");
        for i in 0..5 {
            std::fs::write(
                root.join(format!("f{i}.txt")),
                format!("payload number {i} — filler filler filler filler").repeat(20),
            )
            .unwrap();
        }
        let tip = crate::repo::Repo::open(&root).unwrap().commit("t", "many files").unwrap();

        // ── GetPack leg: hand-rolled client counts ST_PACK_CHUNK frames ──
        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let root2 = root.clone();
        let server = std::thread::spawn(move || {
            std::env::set_var("SC_PACK_CHUNK", "37");
            let result = wire::serve(&root2, &mut server_read, &mut server_write);
            std::env::remove_var("SC_PACK_CHUNK");
            result
        });
        let mut client_read = client_read;
        let mut client_write = client_write;
        wire::write_frame(
            &mut client_write,
            &Request::Hello { version: wire::PROTOCOL_VERSION }.encode(),
        )
        .unwrap();
        wire::parse_response(wire::read_frame(&mut client_read).unwrap()).unwrap();

        wire::write_frame(
            &mut client_write,
            &Request::GetPack { wants: vec![tip], haves: vec![], filter: vec![] }.encode(),
        )
        .unwrap();
        // Empty OK body: "a chunk stream follows".
        wire::parse_response(wire::read_frame(&mut client_read).unwrap()).unwrap();

        let mut chunk_frames = 0usize;
        let mut pack_bytes = Vec::new();
        loop {
            let frame = wire::read_frame(&mut client_read).unwrap();
            match frame.first() {
                Some(&wire::ST_PACK_CHUNK) => {
                    chunk_frames += 1;
                    pack_bytes.extend_from_slice(&frame[1..]);
                }
                Some(&wire::ST_PACK_END) => break,
                other => panic!("unexpected pack-stream marker byte {other:?}"),
            }
        }
        assert!(chunk_frames > 1, "expected multiple chunk frames, got {chunk_frames}");
        let fetched = scl_core::pack::parse_pack(&pack_bytes).unwrap();
        assert!(fetched.iter().any(|(id, _)| *id == tip));

        wire::write_frame(&mut client_write, &Request::Bye.encode()).unwrap();
        drop(client_write);
        drop(client_read);
        server.join().unwrap().unwrap();

        // ── PutPack leg: push the fetched pack into a fresh repo over tiny,
        // explicitly-sized chunks (no env var — full control). ──
        let dst_root =
            std::env::temp_dir().join(format!("scl-stdio-streaming-dst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst_root);
        std::fs::create_dir_all(&dst_root).unwrap();
        crate::repo::Repo::init(&dst_root).unwrap();

        let (client_read2, mut server_write2) = std::io::pipe().unwrap();
        let (mut server_read2, client_write2) = std::io::pipe().unwrap();
        let dst_root2 = dst_root.clone();
        let server2 =
            std::thread::spawn(move || wire::serve(&dst_root2, &mut server_read2, &mut server_write2));
        let client2 = WireClient::handshake(client_read2, client_write2).unwrap();

        // Drive PutPack's wire shape directly so the chunk size is explicit
        // and tiny, independent of SC_PACK_CHUNK.
        {
            let mut rw = client2.rw.borrow_mut();
            wire::write_frame(&mut rw.1, &Request::PutPack.encode()).unwrap();
            wire::write_pack_stream(&mut rw.1, &mut &pack_bytes[..], 11).unwrap();
        }
        let resp = {
            let mut rw = client2.rw.borrow_mut();
            wire::read_frame(&mut rw.0).unwrap()
        };
        let written = wire::decode_ids_body(&wire::parse_response(resp).unwrap()).unwrap();
        assert_eq!(written.len(), fetched.len());
        for (id, _) in &fetched {
            assert!(client2.has_object(id).unwrap());
        }
        client2.bye().unwrap();
        drop(client2);
        server2.join().unwrap().unwrap();

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&dst_root).unwrap();
    }

    /// P25 carry-in pin: a successful chunked `put_pack` leaves the temp
    /// pack file gone; a `put_pack` whose FINAL wire chunk is corrupted
    /// leaves the temp file gone too AND lands zero objects — the two-pass
    /// `ingest_pack_file` verifies the whole (destreamed) pack before
    /// writing anything, so corruption anywhere, including the very last
    /// byte, is caught before pass 2 ever runs.
    #[test]
    fn streaming_receiver_leaves_zero_residue_on_success_and_error() {
        let root = tmp_repo("zeroresidue");
        let layout = crate::layout::Layout::at(&root);

        let a = Object::blob(b"alpha payload for the zero-residue check".to_vec());
        let b = Object::blob(b"bravo payload, also long enough to span chunks".to_vec());
        let (pack, _idx) =
            scl_core::pack::build_pack(&[(a.id(), a.encode()), (b.id(), b.encode())]).unwrap();

        // ── success: chunked put_pack lands both objects, tmp dir ends empty ──
        let (client, server) = connect(root.clone());
        let written = client.put_pack(&mut &pack[..]).unwrap();
        assert_eq!(written.len(), 2);
        assert!(client.has_object(&a.id()).unwrap());
        assert!(client.has_object(&b.id()).unwrap());
        client.bye().unwrap();
        drop(client);
        server.join().unwrap().unwrap();
        assert!(tmp_dir_is_empty(&layout), "temp pack file must be gone after a successful put_pack");

        // ── failure: corrupt the LAST byte of the pack (lands in the final
        // wire chunk given a small chunk_size); nothing must land ──
        let c = Object::blob(b"charlie payload, corrupted on the wire before it lands".to_vec());
        let (mut pack2, _idx2) = scl_core::pack::build_pack(&[(c.id(), c.encode())]).unwrap();
        let last = pack2.len() - 1;
        pack2[last] ^= 0xFF;

        let (client_read, mut server_write) = std::io::pipe().unwrap();
        let (mut server_read, client_write) = std::io::pipe().unwrap();
        let root2 = root.clone();
        let server2 =
            std::thread::spawn(move || wire::serve(&root2, &mut server_read, &mut server_write));
        let mut client_write = client_write;
        let mut client_read = client_read;
        wire::write_frame(
            &mut client_write,
            &Request::Hello { version: wire::PROTOCOL_VERSION }.encode(),
        )
        .unwrap();
        wire::parse_response(wire::read_frame(&mut client_read).unwrap()).unwrap();
        wire::write_frame(&mut client_write, &Request::PutPack.encode()).unwrap();
        // Small explicit chunk_size so the corrupted final byte really does
        // land in the FINAL chunk frame, not the first.
        wire::write_pack_stream(&mut client_write, &mut &pack2[..], 16).unwrap();
        let err = wire::parse_response(wire::read_frame(&mut client_read).unwrap()).unwrap_err();
        assert!(
            matches!(err, Error::Remote(_) | Error::Protocol(_)),
            "expected a typed ingest error, got {err:?}"
        );

        wire::write_frame(&mut client_write, &Request::Bye.encode()).unwrap();
        drop(client_write);
        drop(client_read);
        server2.join().unwrap().unwrap();

        let t = LocalTransport::open(&root).unwrap();
        assert!(
            !t.has_object(&c.id()).unwrap(),
            "corrupt pack must not land any object — atomic after verify"
        );
        assert!(tmp_dir_is_empty(&layout), "temp pack file must be gone after a corrupt ingest too");

        std::fs::remove_dir_all(&root).unwrap();
    }

    fn tmp_dir_is_empty(layout: &crate::layout::Layout) -> bool {
        match std::fs::read_dir(layout.tmp_dir()) {
            Ok(mut entries) => entries.next().is_none(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => panic!("unexpected error reading .sc/tmp: {e}"),
        }
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
            "ssh://host/repo;rm -rf ~",        // command injection into remote shell
            "ssh://host/repo$(touch pwned)",   // command substitution
            "ssh://host/repo`id`",             // backtick substitution
            "ssh://host/repo|curl evil",       // pipe to remote command
            "ssh://host/with space/repo",      // whitespace splits the remote command
            "ssh://host/repo&background",      // background operator
        ] {
            assert!(
                matches!(SshUrl::parse(bad), Err(Error::InvalidArgument(_))),
                "should reject {bad}"
            );
        }
    }

    #[test]
    fn ssh_url_allows_realistic_repo_paths() {
        // The path allow-list must not reject ordinary repo paths.
        for good in [
            "ssh://host/srv/git/my-repo.sc",
            "ssh://host/~user/repos/proj_1",
            "ssh://host/a/b-c/d.e/f+g@h",
        ] {
            assert!(SshUrl::parse(good).is_ok(), "should accept {good}");
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
