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
        eprintln!("sc-forge: {e:#}");
        std::process::exit(1);
    }
}
