//! Vigildex engine core.
//!
//! Vigildex is a local, read-only guard and usage view for AI coding agents.
//! This crate holds the model, adapters, parsers and reports described in
//! `docs/ARCHITECTURE.md`. At milestone M1 it inventories what Claude Code
//! and Codex can run:
//!
//! - [`HomeEnv`]: the home directory the engine reads, with the `--home` /
//!   `VIGILDEX_HOME` override that keeps tests away from the real `$HOME`;
//! - [`model`]: agents, scopes and the normalised [`Item`]s (MCP servers,
//!   hooks, skills, plugins, instructions, settings, credential metadata);
//! - [`adapters`]: one per agent, each a table of documented paths and keys;
//! - [`inventory`] and [`scan`]: the versioned reports behind the CLI.
//!
//! # Hard rules
//!
//! The rules in `CLAUDE.md` apply to every line in this crate: read-only, no
//! credential values, no network, no full secrets, no transcript content, and
//! parsers that warn instead of panicking.

pub mod adapters;
pub mod agent_dirs;
pub mod collect;
pub mod home;
pub mod inventory;
pub mod launch;
pub mod model;
pub mod parse;
pub mod report;
pub mod scan;

pub use agent_dirs::AgentDirs;
pub use home::{HomeEnv, HomeError, HomeSource, HomeView, HOME_ENV_VAR};
pub use inventory::{inventory, inventory_report};
pub use model::{
    Agent, ArtifactKind, ArtifactRef, ArtifactView, Credential, CredentialKey, Hook, HookHandler,
    Instruction, Item, Launch, McpServer, Pin, Plugin, PluginComponent, RedactedValue, RemoteAuth,
    Runner, Scope, Setting, Skill, SkillKind, Transport, Warning,
};
pub use report::{Inventory, InventoryReport, ScanReport, SCHEMA_VERSION};
pub use scan::scan;

/// Version of the engine, taken from the workspace version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
