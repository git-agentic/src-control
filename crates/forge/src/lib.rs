//! `scl-forge` — `sc-forge`, a Gitea-compatible Git forge.
//!
//! The whole implementation is unix-only (it supervises `git` child processes
//! from F2 on); on other targets the crate is empty and the binary prints a
//! notice. Design: `docs/superpowers/specs/2026-10-22-p38-forge-design.md`.
#![cfg(unix)]
// The recorded repository object has ~70 keys; `json!` expands recursively over them.
#![recursion_limit = "256"]

pub mod admin;
pub mod api;
pub mod auth;
pub mod db;
pub mod gitproc;
pub mod gitread;
pub mod hook;
pub mod http;
pub mod lifecycle;
pub mod limits;
pub mod names;
pub mod policy;
pub mod refname;
pub mod repo_api;
pub mod repos;
pub mod routes;
pub mod scope;
pub mod server;
pub mod store;
pub mod timefmt;
