use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use scl_forge::limits::{Cidr, Proxies};
use scl_forge::server::{bind_gate, make_app, serve, Limits};
use scl_forge::{admin, db};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "sc-forge", version, about = "A Gitea-compatible Git forge")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP server.
    Serve(ServeArgs),
    /// Operate on the data directory directly (no network).
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long)]
    data_dir: PathBuf,
    /// Address to listen on, e.g. 127.0.0.1:3000.
    #[arg(long)]
    listen: SocketAddr,
    /// External base URL used in every URL the API returns.
    #[arg(long)]
    public_url: String,
    /// A TLS-terminating proxy fronts this server (allows a non-loopback bind).
    #[arg(long)]
    behind_proxy: bool,
    /// Serve plaintext HTTP on a non-loopback address.
    #[arg(long)]
    allow_plaintext: bool,
    /// Header carrying the client address, trusted only from `--trusted-proxies`.
    #[arg(long)]
    trusted_proxy_header: Option<String>,
    /// CIDR blocks whose forwarded-for header is trusted (comma separated).
    #[arg(long, value_delimiter = ',')]
    trusted_proxies: Vec<String>,
    /// Concurrent connections.
    #[arg(long, default_value_t = 512)]
    max_connections: usize,
    /// Largest JSON request body, in bytes.
    #[arg(long, default_value_t = 1 << 20)]
    max_body_bytes: usize,
    /// Concurrent `git` child processes (a busy server answers 503 rather than queueing).
    #[arg(long, default_value_t = 8)]
    git_concurrency: usize,
    /// Concurrent password verifications (Argon2 is memory-hard).
    #[arg(long, default_value_t = 4)]
    argon2_concurrency: usize,
}

#[derive(Subcommand)]
enum AdminCmd {
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    Org {
        #[command(subcommand)]
        cmd: OrgCmd,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    Create {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        admin: bool,
        /// `--must-change-password` and `--must-change-password=false` both parse.
        #[arg(long, num_args = 0..=1, default_missing_value = "true", default_value = "true", action = clap::ArgAction::Set)]
        must_change_password: bool,
        #[arg(long)]
        data_dir: PathBuf,
    },
    ChangePassword {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long, num_args = 0..=1, default_missing_value = "true", default_value = "true", action = clap::ArgAction::Set)]
        must_change_password: bool,
        #[arg(long)]
        data_dir: PathBuf,
    },
    GenerateAccessToken {
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "sc-forge-admin")]
        token_name: String,
        #[arg(long, value_delimiter = ',', default_value = "all")]
        scopes: Vec<String>,
        /// Print only the token.
        #[arg(long)]
        raw: bool,
        #[arg(long)]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum OrgCmd {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        data_dir: PathBuf,
    },
}

/// Parse the command line and run `serve` or an `admin` command.
pub fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Serve(a) => run_serve(a),
        Cmd::Admin { cmd } => run_admin(cmd),
    }
}

fn run_admin(cmd: AdminCmd) -> Result<()> {
    match cmd {
        AdminCmd::User {
            cmd:
                UserCmd::Create {
                    username,
                    password,
                    email,
                    admin: a,
                    must_change_password,
                    data_dir,
                },
        } => {
            admin::user_create(
                &data_dir,
                &username,
                &password,
                &email,
                a,
                must_change_password,
            )?;
            println!("New user '{username}' has been successfully created!");
        }
        AdminCmd::User {
            cmd:
                UserCmd::ChangePassword {
                    username,
                    password,
                    must_change_password,
                    data_dir,
                },
        } => {
            admin::user_change_password(&data_dir, &username, &password, must_change_password)?;
            println!("{username}'s password has been successfully updated!");
        }
        AdminCmd::User {
            cmd:
                UserCmd::GenerateAccessToken {
                    username,
                    token_name,
                    scopes,
                    raw,
                    data_dir,
                },
        } => {
            let t = admin::generate_access_token(&data_dir, &username, &token_name, &scopes)?;
            if raw {
                println!("{t}");
            } else {
                println!("Access token was successfully created: {t}");
            }
        }
        AdminCmd::Org {
            cmd:
                OrgCmd::Create {
                    name,
                    owner,
                    data_dir,
                },
        } => {
            admin::org_create(&data_dir, &name, &owner)?;
            println!("Organization '{name}' has been successfully created!");
        }
    }
    Ok(())
}

fn run_serve(a: ServeArgs) -> Result<()> {
    let public_url =
        scl_forge::server::validate_public_url(&a.public_url).map_err(anyhow::Error::msg)?;
    if a.max_connections == 0 {
        bail!("--max-connections must be at least 1");
    }
    bind_gate(&a.listen, a.behind_proxy, a.allow_plaintext).map_err(anyhow::Error::msg)?;
    let cidrs = a
        .trusted_proxies
        .iter()
        .map(|c| Cidr::parse(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::msg)?;
    if a.trusted_proxy_header.is_some() == cidrs.is_empty() {
        bail!("--trusted-proxy-header and --trusted-proxies must be given together");
    }
    if a.behind_proxy && cidrs.is_empty() {
        eprintln!(
            "sc-forge: warning: --behind-proxy without --trusted-proxy-header/--trusted-proxies: every client shares the proxy's address, \
             so the per-source password-failure budget (30/min) applies to all of them together"
        );
    }
    let proxies = Proxies {
        header: a.trusted_proxy_header.map(|h| h.to_ascii_lowercase()),
        cidrs,
    };
    db::open_for_serve(&a.data_dir)?;
    // One server per data directory: the lock is held until this function returns.
    let _data_lock =
        scl_forge::lifecycle::DirLock::acquire(&a.data_dir).map_err(anyhow::Error::msg)?;
    let git_bin =
        scl_forge::gitproc::find_git().context("git not found: install git or set SC_FORGE_GIT")?;
    let git = std::sync::Arc::new(scl_forge::gitproc::Git::new(
        &a.data_dir,
        git_bin,
        a.git_concurrency,
    )?);
    let git_version = scl_forge::gitproc::check_version(&git).map_err(anyhow::Error::msg)?;
    eprintln!("sc-forge: {git_version}");
    let life = scl_forge::lifecycle::Lifecycle::new(&a.data_dir, git)?;
    // Resolve whatever a crash left, before the listener is bound.
    let report = life.reconcile(&db::connect(&a.data_dir)?, scl_forge::timefmt::now())?;
    if report != scl_forge::lifecycle::Report::default() {
        eprintln!("sc-forge: reconciled {report:?}");
    }
    let app = make_app(a.data_dir, &public_url, proxies, a.argon2_concurrency, life);
    let limits = Limits {
        max_body: a.max_body_bytes,
        max_connections: a.max_connections,
        ..Limits::default()
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result: Result<()> = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(a.listen)
            .await
            .with_context(|| format!("bind {}", a.listen))?;
        eprintln!("sc-forge: listening on {}", listener.local_addr()?);
        let stop = async {
            use tokio::signal::unix::{signal, SignalKind};
            let (mut term, mut int) = (
                signal(SignalKind::terminate()).expect("signal"),
                signal(SignalKind::interrupt()).expect("signal"),
            );
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        };
        serve(listener, app, limits, stop, Duration::from_secs(30)).await;
        Ok(())
    });
    // Queued password verifications run on blocking threads that the drain deadline
    // cannot cancel; do not let dropping the runtime wait for them.
    rt.shutdown_timeout(Duration::from_secs(2));
    result
}
