//! Vigildex engine core.
//!
//! Vigildex is a local, read-only guard and usage view for AI coding agents.
//! This crate will hold the model, adapters, parsers, analyzers, diff,
//! attribution, store, pricing and watcher described in
//! `docs/ARCHITECTURE.md`. At milestone M0 it holds only the pieces every
//! later milestone builds on:
//!
//! - [`HomeEnv`]: the home directory the engine reads, with the `--home` /
//!   `VIGILDEX_HOME` override that keeps tests away from the real `$HOME`;
//! - [`ScanReport`]: the versioned envelope of `vigildex scan --json`.
//!
//! # Hard rules
//!
//! The rules in `CLAUDE.md` apply to every line in this crate: read-only, no
//! credential values, no network, no full secrets, no transcript content, and
//! parsers that warn instead of panicking.

pub mod home;
pub mod scan;

pub use home::{HomeEnv, HomeError, HomeSource, HomeView, HOME_ENV_VAR};
pub use scan::{scan, ScanReport, SCHEMA_VERSION};

/// Version of the engine, taken from the workspace version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
