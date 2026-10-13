//! Sources several agents read: the Agent Skills folders `~/.agents/skills`
//! and `<repo>/.agents/skills` (Codex, Cursor, Copilot CLI and others).
//!
//! Shell profiles and `.env` files join this adapter with the findings in
//! M2; the relocation variables they carry are already read by
//! [`crate::agent_dirs`].

use std::path::PathBuf;

use super::common;
use super::Adapter;
use crate::agent_dirs::AgentDirs;
use crate::collect::Collector;
use crate::home::HomeEnv;
use crate::model::{Agent, Scope};

/// The shared-sources adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct Shared;

impl Adapter for Shared {
    fn agent(&self) -> Agent {
        Agent::Shared
    }

    fn project_roots(&self, _home: &HomeEnv, _dirs: &AgentDirs) -> Vec<PathBuf> {
        Vec::new()
    }

    fn inventory(&self, home: &HomeEnv, _dirs: &AgentDirs, roots: &[PathBuf], out: &mut Collector) {
        common::skills_dir(
            Agent::Shared,
            &Scope::User,
            &home.root().join(".agents").join("skills"),
            out,
        );
        for root in roots {
            common::skills_dir(
                Agent::Shared,
                &Scope::Project { root: root.clone() },
                &root.join(".agents").join("skills"),
                out,
            );
        }
    }
}
