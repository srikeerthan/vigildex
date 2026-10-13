//! One adapter per agent.
//!
//! An adapter is mostly data: the documented paths it looks at and the key
//! patterns it records (see `docs/DATA_SOURCES.md`). The parsing itself is
//! shared through [`crate::parse`], so a vendor format change is a small
//! table edit in one adapter.

use std::fmt;
use std::path::PathBuf;

use crate::agent_dirs::AgentDirs;
use crate::collect::Collector;
use crate::home::HomeEnv;
use crate::model::Agent;

pub mod claude;
pub mod codex;
pub mod common;
pub mod shared;

/// Finds and parses one agent's files.
pub trait Adapter: fmt::Debug {
    /// The agent this adapter covers.
    fn agent(&self) -> Agent;

    /// Repository roots the agent recorded in its own state, located under
    /// `home` (see [`HomeEnv::locate`]). Roots that do not exist may be
    /// returned; the caller filters them.
    fn project_roots(&self, home: &HomeEnv, dirs: &AgentDirs) -> Vec<PathBuf>;

    /// Reads the agent's files in the home and in every project root,
    /// recording items, artifacts and warnings in `out`.
    fn inventory(&self, home: &HomeEnv, dirs: &AgentDirs, roots: &[PathBuf], out: &mut Collector);
}

/// Every adapter the engine has, in report order.
#[must_use]
pub fn all() -> Vec<Box<dyn Adapter>> {
    vec![
        Box::new(claude::ClaudeCode),
        Box::new(codex::Codex),
        Box::new(shared::Shared),
    ]
}
