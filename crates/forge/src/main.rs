//! `sc-forge` binary: `serve`, `admin …`.

#[cfg(not(unix))]
fn main() {
    eprintln!("sc-forge is unix-only");
    std::process::exit(2);
}

#[cfg(unix)]
mod cli;

#[cfg(unix)]
fn main() {
    if let Err(e) = cli::run() {
        // `serve` failing (a bind error, a second server, a migration) is a service event: log it
        // as one so an alert on severity sees a crash loop. Other commands answer a terminal.
        if std::env::args().nth(1).as_deref() == Some("serve") {
            scl_forge::log::emit("ERROR", &format!("{e:#}"), None);
        } else {
            eprintln!("sc-forge: {e:#}");
        }
        std::process::exit(1);
    }
}
