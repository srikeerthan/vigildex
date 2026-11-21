//! OpenAI Codex: `~/.codex/` (or `CODEX_HOME`) and a repository's `.codex/`
//! and `AGENTS.md`.
//!
//! Paths and keys come from `docs/DATA_SOURCES.md` § OpenAI Codex. The
//! `[hooks]` table and `hooks.json` share the shape Claude Code uses, so the
//! same parser reads both. Skills in `.agents/skills` are read by several
//! agents and belong to the shared adapter; Codex's own `skills/` folder
//! is scanned here (its hidden `.system/` folder, which Codex writes itself,
//! is skipped like every hidden directory).
//!
//! `config.toml` is parsed with spans kept, so every setting, server and
//! hook from it carries a line number.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::common;
use super::Adapter;
use crate::agent_dirs::AgentDirs;
use crate::collect::{artifact, Collector};
use crate::home::HomeEnv;
use crate::model::{Agent, ArtifactKind, Item, RedactedValue, Scope, Setting};
use crate::observe::{observe, Field, Locator};
use crate::parse::json::{join_key, str_at};
use crate::parse::settings::{self, KeyRule};
use crate::parse::{hooks, mcp, toml, Context};

/// The Codex adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct Codex;

const AGENT: Agent = Agent::Codex;

/// Security-relevant keys of `config.toml` (user or project).
const CONFIG_RULES: &[KeyRule] = &[
    KeyRule::value("approval_policy"),
    KeyRule::value("sandbox_mode"),
    KeyRule::value("sandbox_workspace_write.*"),
    // `set` is an object of variables: key names only.
    KeyRule::value("shell_environment_policy.*"),
    KeyRule::value("model_provider"),
    KeyRule::value("model_providers.*.name"),
    KeyRule::value("model_providers.*.base_url"),
    KeyRule::value("model_providers.*.env_key"),
    KeyRule::value("model_providers.*.wire_api"),
    KeyRule::value("openai_base_url"),
    KeyRule::value("chatgpt_base_url"),
    KeyRule::value("forced_login_method"),
    KeyRule::value("forced_chatgpt_workspace_id"),
    KeyRule::value("cli_auth_credentials_store"),
    KeyRule::value("mcp_oauth_credentials_store"),
    KeyRule::value("notify"),
    KeyRule::value("features.*"),
    KeyRule::value("profile"),
    KeyRule::value("profiles.*.approval_policy"),
    KeyRule::value("profiles.*.sandbox_mode"),
    KeyRule::value("profiles.*.model_provider"),
];

/// Keys of `[projects."<path>"]`, recorded at local scope.
const PROJECT_RULES: &[KeyRule] = &[KeyRule::value("trust_level")];

impl Codex {
    fn config_file(home: &HomeEnv, scope: Scope, path: &Path, out: &mut Collector) {
        let art = artifact(AGENT, scope, ArtifactKind::Settings, path);
        let Some(parsed) = out.read_toml(&art) else {
            return;
        };
        let doc = &parsed.value;
        let line_of = |segments: &[&str]| parsed.line_of(segments);
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut observations = Vec::new();
        settings::extract_with_lines(doc, "", &[], CONFIG_RULES, &art, &mut items, &line_of);
        let root = Context::with_lines(&art, &line_of);

        // `notify` runs a command with event JSON; a key embedded in it is a
        // secret in a settings file.
        if let Some(notify) = doc.get("notify") {
            let text = match notify {
                Value::Array(parts) => parts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" "),
                Value::String(s) => s.clone(),
                _ => String::new(),
            };
            if !text.is_empty() {
                observations.push(observe(
                    &art,
                    root.location(&["notify"]),
                    Field::SettingCommand,
                    Some("notify"),
                    Locator::Setting {
                        key_path: "notify".to_owned(),
                    },
                    &text,
                ));
            }
        }

        if let Some(set) = doc
            .get("shell_environment_policy")
            .and_then(|p| p.get("set"))
            .and_then(Value::as_object)
        {
            for (name, value) in set {
                if let Some(value) = value.as_str() {
                    observations.push(observe(
                        &art,
                        root.location(&["shell_environment_policy", "set", name]),
                        Field::SettingEnv,
                        Some(name),
                        Locator::Setting {
                            key_path: "shell_environment_policy.set".to_owned(),
                        },
                        value,
                    ));
                }
            }
        }
        if let Some(map) = doc.get("mcp_servers").and_then(Value::as_object) {
            let ctx = Context {
                source: &art,
                key_prefix: "mcp_servers",
                segments: &["mcp_servers"],
                line_of: &line_of,
            };
            mcp::parse_server_map(map, &ctx, &mut items, &mut warnings, &mut observations);
        }
        if let Some(events) = doc.get("hooks") {
            let ctx = Context {
                source: &art,
                key_prefix: "hooks",
                segments: &["hooks"],
                line_of: &line_of,
            };
            hooks::parse_event_map(events, &ctx, &mut items, &mut warnings, &mut observations);
        }
        if let Some(projects) = doc.get("projects").and_then(Value::as_object) {
            for (recorded, project) in projects {
                let root_dir = home.locate(Path::new(recorded));
                let local = artifact(
                    AGENT,
                    Scope::Local { root: root_dir },
                    ArtifactKind::Settings,
                    path,
                );
                let prefix = join_key("projects", recorded);
                settings::extract_with_lines(
                    project,
                    &prefix,
                    &["projects", recorded],
                    PROJECT_RULES,
                    &local,
                    &mut items,
                    &line_of,
                );
            }
        }
        if let Some(configs) = doc
            .get("skills")
            .and_then(|s| s.get("config"))
            .and_then(Value::as_array)
        {
            for (index, entry) in configs.iter().enumerate() {
                let Some(selector) = str_at(entry, "path").or_else(|| str_at(entry, "name")) else {
                    continue;
                };
                let Some(enabled) = entry.get("enabled").and_then(Value::as_bool) else {
                    continue;
                };
                let index = index.to_string();
                items.push(Item::Setting(Setting {
                    key_path: format!("{}.enabled", join_key("skills.config", selector)),
                    value: RedactedValue::Bool { value: enabled },
                    line: line_of(&["skills", "config", &index, "enabled"]),
                    source: art.clone(),
                }));
            }
        }
        out.extend(items);
        out.warnings_from(warnings);
        out.observations_from(observations);
    }
}

impl Adapter for Codex {
    fn agent(&self) -> Agent {
        AGENT
    }

    fn project_roots(&self, home: &HomeEnv, dirs: &AgentDirs) -> Vec<PathBuf> {
        let path = dirs.codex_home.join("config.toml");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let Ok(doc) = toml::to_json(&text) else {
            return Vec::new();
        };
        doc.get("projects")
            .and_then(Value::as_object)
            .map(|projects| {
                projects
                    .keys()
                    .map(|recorded| home.locate(Path::new(recorded)))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn inventory(&self, home: &HomeEnv, dirs: &AgentDirs, roots: &[PathBuf], out: &mut Collector) {
        let codex_home = &dirs.codex_home;
        Self::config_file(home, Scope::User, &codex_home.join("config.toml"), out);
        if codex_home != &home.root().join(".codex") {
            for name in ["config.toml", "hooks.json"] {
                let path = home.root().join(".codex").join(name);
                if path.is_file() {
                    out.warn(
                        AGENT,
                        &path,
                        format!(
                            "ignored by Codex: CODEX_HOME moves its files to {}",
                            codex_home.display()
                        ),
                    );
                }
            }
        }
        common::hooks_file(AGENT, &Scope::User, &codex_home.join("hooks.json"), out);
        common::instruction(AGENT, &Scope::User, &codex_home.join("AGENTS.md"), out);
        common::skills_dir(AGENT, &Scope::User, &codex_home.join("skills"), out);
        common::credential(AGENT, &codex_home.join("auth.json"), out);

        for root in roots {
            let project = Scope::Project { root: root.clone() };
            let dot_codex = root.join(".codex");
            Self::config_file(home, project.clone(), &dot_codex.join("config.toml"), out);
            common::hooks_file(AGENT, &project, &dot_codex.join("hooks.json"), out);
            common::instruction(AGENT, &project, &root.join("AGENTS.md"), out);
        }
    }
}
