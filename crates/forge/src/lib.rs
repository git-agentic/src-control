//! `scl-forge` — `sc-forge`, a Gitea-compatible Git forge.
//!
//! The whole implementation is unix-only (it supervises `git` child processes
//! from F2 on); on other targets the crate is empty and the binary prints a
//! notice. Design: `docs/superpowers/specs/2026-10-22-p38-forge-design.md`.
#![cfg(unix)]

pub mod admin;
pub mod api;
pub mod auth;
pub mod db;
pub mod http;
pub mod limits;
pub mod names;
pub mod routes;
pub mod scope;
pub mod server;
pub mod store;
pub mod timefmt;
