//! Sources several agents read: the Agent Skills folders `~/.agents/skills`
//! and `<repo>/.agents/skills`, the shell profiles in the home, `.envrc`
//! and the `.env` file at each project root.
//!
//! Profiles and dotenv files are read for two things: the agent-relevant
//! variables they set (`ANTHROPIC_API_KEY`, `OPENAI_BASE_URL`,
//! `CLAUDE_CODE_USE_BEDROCK`, …), which become [`Item::Setting`]s with the
//! value reduced to presence or a sanitised URL, and every assignment's
//! value, which goes through [`observe`] for the secret rules and the
//! billing checks. The relocation variables they carry are read earlier by
//! [`crate::agent_dirs`].

use std::path::{Path, PathBuf};

use super::common;
use super::Adapter;
use crate::agent_dirs::{AgentDirs, SHELL_PROFILES};
use crate::collect::{artifact, Collector};
use crate::home::HomeEnv;
use crate::model::{Agent, ArtifactKind, ArtifactRef, Item, RedactedValue, Scope, Setting};
use crate::observe::{observe, Field, Location, Locator};
use crate::parse::json::safe_text;
use crate::parse::shell;
use crate::secrets::ValueClass;

/// The shared-sources adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct Shared;

/// Variable-name prefixes that make an assignment agent-relevant, so it is
/// inventoried as a setting.
const RELEVANT_PREFIXES: &[&str] = &[
    "ANTHROPIC_",
    "CLAUDE_",
    "OPENAI_",
    "CODEX_",
    "COPILOT_",
    "CURSOR_",
    "GITHUB_COPILOT_",
];

/// Exact variable names that are agent-relevant.
const RELEVANT_NAMES: &[&str] = &["GITHUB_TOKEN", "GH_TOKEN", "AWS_PROFILE", "AWS_REGION"];

/// Variable names (or name parts) whose values are shown: switches, URLs,
/// paths and modes. Everything else relevant is reduced to presence.
const SHOWN_NAME_PARTS: &[&str] = &[
    "_BASE_URL",
    "_USE_",
    "_CONFIG_DIR",
    "_HOME",
    "_MODEL",
    "_PROFILE",
    "_REGION",
    "_PROVIDER_TYPE",
    "_DISABLE_",
    "_ENABLE_",
    "_TELEMETRY",
];

/// Whether the agents read this variable.
#[must_use]
pub fn is_relevant(name: &str) -> bool {
    RELEVANT_NAMES.contains(&name) || RELEVANT_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Whether a relevant variable's value is safe to show.
fn is_shown(name: &str) -> bool {
    SHOWN_NAME_PARTS.iter().any(|part| name.contains(part))
        && !crate::launch::names_a_credential(name)
}

impl Shared {
    /// Reads one profile or dotenv file.
    fn env_file(
        agent: Agent,
        scope: &Scope,
        kind: ArtifactKind,
        field: Field,
        path: &Path,
        out: &mut Collector,
    ) {
        let art: ArtifactRef = artifact(agent, scope.clone(), kind, path);
        let Some(text) = out.read_text(&art) else {
            return;
        };
        for assignment in shell::assignments(&text) {
            let location = Location {
                path: path.to_path_buf(),
                line: Some(assignment.line),
                key_path: Some(assignment.name.clone()),
            };
            let observation = observe(
                &art,
                location,
                field,
                Some(&assignment.name),
                Locator::Setting {
                    key_path: assignment.name.clone(),
                },
                &assignment.value,
            );
            // A profile line is inventoried when the agents read the
            // variable, or when it holds a credential whatever its name.
            if is_relevant(&assignment.name) || observation.secret.is_some() {
                let value = if observation.secret.is_none()
                    && is_shown(&assignment.name)
                    && observation.class == ValueClass::Literal
                {
                    RedactedValue::Text {
                        value: safe_text(&assignment.value),
                    }
                } else if observation.class == ValueClass::Empty {
                    RedactedValue::Text {
                        value: String::new(),
                    }
                } else {
                    RedactedValue::Present
                };
                out.push(Item::Setting(Setting {
                    key_path: assignment.name.clone(),
                    value,
                    line: Some(assignment.line),
                    source: art.clone(),
                }));
            }
            out.observe(observation);
        }
    }
}

impl Adapter for Shared {
    fn agent(&self) -> Agent {
        Agent::Shared
    }

    fn project_roots(&self, _home: &HomeEnv, _dirs: &AgentDirs) -> Vec<PathBuf> {
        Vec::new()
    }

    fn inventory(&self, home: &HomeEnv, _dirs: &AgentDirs, roots: &[PathBuf], out: &mut Collector) {
        let root = home.root();
        for profile in SHELL_PROFILES.iter().chain([".envrc"].iter()) {
            Self::env_file(
                Agent::Shared,
                &Scope::User,
                ArtifactKind::ShellProfile,
                Field::ShellExport,
                &root.join(profile),
                out,
            );
        }
        common::skills_dir(
            Agent::Shared,
            &Scope::User,
            &root.join(".agents").join("skills"),
            out,
        );
        for project in roots {
            let scope = Scope::Project {
                root: project.clone(),
            };
            Self::env_file(
                Agent::Shared,
                &scope,
                ArtifactKind::ShellProfile,
                Field::ShellExport,
                &project.join(".envrc"),
                out,
            );
            Self::env_file(
                Agent::Shared,
                &scope,
                ArtifactKind::EnvFile,
                Field::DotenvVar,
                &project.join(".env"),
                out,
            );
            common::skills_dir(
                Agent::Shared,
                &scope,
                &project.join(".agents").join("skills"),
                out,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relevance_and_visibility() {
        assert!(is_relevant("ANTHROPIC_API_KEY"));
        assert!(is_relevant("GITHUB_TOKEN"));
        assert!(is_relevant("CLAUDE_CODE_USE_BEDROCK"));
        assert!(!is_relevant("PATH"));
        assert!(!is_relevant("ACME_ENV"));
        assert!(is_shown("ANTHROPIC_BASE_URL"));
        assert!(is_shown("CLAUDE_CODE_USE_BEDROCK"));
        assert!(is_shown("CLAUDE_CONFIG_DIR"));
        assert!(!is_shown("ANTHROPIC_API_KEY"));
        assert!(!is_shown("ANTHROPIC_AUTH_TOKEN"));
        assert!(!is_shown("CLAUDE_CODE_OAUTH_TOKEN"));
    }
}
