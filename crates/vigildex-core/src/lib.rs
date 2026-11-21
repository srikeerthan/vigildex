//! Vigildex engine core.
//!
//! Vigildex is a local, read-only guard and usage view for AI coding agents.
//! This crate holds the model, adapters, parsers and reports described in
//! `docs/ARCHITECTURE.md`. At milestone M2 it inventories what Claude Code
//! and Codex can run and reports the findings of `docs/RULES.md`:
//!
//! - [`HomeEnv`]: the home directory the engine reads, with the `--home` /
//!   `VIGILDEX_HOME` override that keeps tests away from the real `$HOME`;
//! - [`model`]: agents, scopes and the normalised [`Item`]s (MCP servers,
//!   hooks, skills, plugins, instructions, settings, credential metadata);
//! - [`adapters`]: one per agent, each a table of documented paths and keys;
//! - [`secrets`] and [`observe`]: the secret rules and the masked, fingerprinted
//!   observations that let findings see values the inventory never records;
//! - [`analyze`]: the SEC, BILL and RISK rules and the finding policy;
//! - [`inventory`] and [`scan`]: the versioned reports behind the CLI.
//!
//! # Hard rules
//!
//! The rules in `CLAUDE.md` apply to every line in this crate: read-only, no
//! credential values, no network, no full secrets, no transcript content, and
//! parsers that warn instead of panicking.

pub mod adapters;
pub mod agent_dirs;
pub mod analyze;
pub mod clock;
pub mod collect;
pub mod finding;
pub mod home;
pub mod hosts;
pub mod inventory;
pub mod launch;
pub mod model;
pub mod observe;
pub mod parse;
pub mod report;
pub mod scan;
pub mod secrets;

pub use agent_dirs::AgentDirs;
pub use finding::{Category, Finding, FixSteps, Location, Severity, SeverityCounts};
pub use home::{HomeEnv, HomeError, HomeSource, HomeView, HOME_ENV_VAR};
pub use inventory::{inventory, inventory_report};
pub use model::{
    Agent, ArtifactKind, ArtifactRef, ArtifactView, Credential, CredentialKey, Hook, HookHandler,
    Instruction, Item, ItemEntry, ItemTag, Launch, McpServer, Pin, Plugin, PluginComponent,
    RedactedValue, RemoteAuth, Runner, Scope, Setting, Skill, SkillKind, Transport, Warning,
};
pub use report::{FindingsReport, Inventory, InventoryReport, ScanReport, SCHEMA_VERSION};
pub use scan::{findings, findings_report, scan};

/// Version of the engine, taken from the workspace version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
