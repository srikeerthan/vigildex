//! Claude Code: `~/.claude/` (or `CLAUDE_CONFIG_DIR`), `~/.claude.json` and
//! a repository's `.claude/`, `.mcp.json` and instruction files.
//!
//! Paths and keys come from `docs/DATA_SOURCES.md` § Claude Code. The
//! managed policy directory (`/Library/Application Support/ClaudeCode`) is
//! outside the home and is not scanned yet.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::common;
use super::Adapter;
use crate::agent_dirs::AgentDirs;
use crate::collect::{artifact, Collector};
use crate::home::HomeEnv;
use crate::model::{
    Agent, ArtifactKind, ArtifactRef, Item, Plugin, PluginComponent, Scope, SkillKind,
};
use crate::observe::{observe, Field, Locator};
use crate::parse::json::{join_key, safe_text, str_at};
use crate::parse::settings::{self, KeyRule};
use crate::parse::{hooks, mcp, Context};

/// The Claude Code adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClaudeCode;

const AGENT: Agent = Agent::ClaudeCode;

/// Security-relevant keys of any settings file (user, project, local).
const SETTINGS_RULES: &[KeyRule] = &[
    KeyRule::value("permissions.allow"),
    KeyRule::value("permissions.ask"),
    KeyRule::value("permissions.deny"),
    KeyRule::value("permissions.defaultMode"),
    KeyRule::value("permissions.additionalDirectories"),
    KeyRule::value("permissions.disableBypassPermissionsMode"),
    // Key names only: values can be credentials.
    KeyRule::value("env"),
    KeyRule::value("apiKeyHelper"),
    KeyRule::value("awsAuthRefresh"),
    KeyRule::value("awsCredentialExport"),
    KeyRule::value("otelHeadersHelper"),
    KeyRule::value("disableAllHooks"),
    KeyRule::value("allowedHttpHookUrls"),
    KeyRule::value("httpHookAllowedEnvVars"),
    KeyRule::value("allowManagedHooksOnly"),
    KeyRule::value("sandbox.*"),
    KeyRule::value("enableAllProjectMcpServers"),
    KeyRule::value("enabledMcpjsonServers"),
    KeyRule::value("disabledMcpjsonServers"),
    KeyRule::value("allowedMcpServers"),
    KeyRule::value("deniedMcpServers"),
    KeyRule::value("managedMcpServers"),
    KeyRule::value("statusLine.type"),
    KeyRule::value("statusLine.command"),
    KeyRule::value("forceLoginMethod"),
    KeyRule::value("extraKnownMarketplaces"),
    KeyRule::value("strictKnownMarketplaces"),
    KeyRule::value("skillOverrides"),
    KeyRule::value("disableBundledSkills"),
    KeyRule::value("autoMode"),
];

/// Settings keys whose value is a command the agent runs. A key embedded in
/// one (`echo sk-ant-…`) is a secret in a settings file (SEC-003).
const COMMAND_KEYS: &[&str] = &[
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
];

/// Keys of `~/.claude.json` at user scope. `oauthAccount` holds the account
/// e-mail and organisation, so it is reduced to its key names: a fresh
/// install writes none of it, an account context adds `accountUuid`,
/// `emailAddress` and `organizationUuid`, and a subscription login adds
/// `billingType`, `organizationType` and the rate-limit tier (names only).
const APP_STATE_RULES: &[KeyRule] = &[
    KeyRule::value("hasAvailableSubscription"),
    KeyRule::value("oauthAccount"),
];

/// Keys of `~/.claude.json` › `projects["<path>"]`, recorded at local scope.
const PROJECT_STATE_RULES: &[KeyRule] = &[
    KeyRule::value("hasTrustDialogAccepted"),
    KeyRule::value("hasTrustDialogHooksAccepted"),
    KeyRule::value("hasClaudeMdExternalIncludesApproved"),
    KeyRule::value("enableAllProjectMcpServers"),
    KeyRule::value("enabledMcpjsonServers"),
    KeyRule::value("disabledMcpjsonServers"),
    KeyRule::value("allowedTools"),
];

impl ClaudeCode {
    /// Whether `CLAUDE_CONFIG_DIR` moves the agent's files away from `~/.claude`.
    fn relocated(home: &HomeEnv, dirs: &AgentDirs) -> bool {
        dirs.claude_config != home.root().join(".claude")
    }

    /// The app-state file. Claude Code resolves it as
    /// `join(CLAUDE_CONFIG_DIR || $HOME, ".claude.json")` (confirmed on
    /// 2.1.296), so with a relocated config directory `~/.claude.json` is
    /// never read by the agent and is not read here either.
    fn app_state_path(home: &HomeEnv, dirs: &AgentDirs) -> PathBuf {
        if Self::relocated(home, dirs) {
            dirs.claude_config.join(".claude.json")
        } else {
            home.root().join(".claude.json")
        }
    }

    /// Files left at the default location while `CLAUDE_CONFIG_DIR` points
    /// elsewhere: the agent ignores them, so they are reported as warnings
    /// rather than inventoried.
    fn warn_ignored_defaults(home: &HomeEnv, dirs: &AgentDirs, out: &mut Collector) {
        if !Self::relocated(home, dirs) {
            return;
        }
        let default_dir = home.root().join(".claude");
        for path in [
            home.root().join(".claude.json"),
            default_dir.join("settings.json"),
            default_dir.join("settings.local.json"),
        ] {
            if path.is_file() {
                out.warn(
                    AGENT,
                    &path,
                    format!(
                        "ignored by Claude Code: CLAUDE_CONFIG_DIR moves its files to {}",
                        dirs.claude_config.display()
                    ),
                );
            }
        }
    }

    fn app_state(home: &HomeEnv, path: &Path, out: &mut Collector) {
        let art = artifact(AGENT, Scope::User, ArtifactKind::AppState, path);
        let Some(doc) = out.read_json(&art) else {
            return;
        };
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut observations = Vec::new();
        settings::extract(&doc, "", APP_STATE_RULES, &art, &mut items);
        match doc.get("mcpServers") {
            Some(Value::Object(map)) => {
                let ctx = Context {
                    source: &art,
                    key_prefix: "mcpServers",
                    segments: &["mcpServers"],
                    line_of: &crate::parse::no_lines,
                };
                mcp::parse_server_map(map, &ctx, &mut items, &mut warnings, &mut observations);
            }
            Some(_) => out.warn(AGENT, path, "mcpServers is not an object; skipped"),
            None => {}
        }
        if let Some(projects) = doc.get("projects").and_then(Value::as_object) {
            for (recorded, project) in projects {
                let root = home.locate(Path::new(recorded));
                let local = artifact(AGENT, Scope::Local { root }, ArtifactKind::AppState, path);
                let prefix = join_key("projects", recorded);
                settings::extract(project, &prefix, PROJECT_STATE_RULES, &local, &mut items);
                let key_prefix = join_key(&prefix, "mcpServers");
                match project.get("mcpServers") {
                    Some(Value::Object(map)) => {
                        let ctx = Context {
                            source: &local,
                            key_prefix: &key_prefix,
                            segments: &["projects", recorded, "mcpServers"],
                            line_of: &crate::parse::no_lines,
                        };
                        mcp::parse_server_map(
                            map,
                            &ctx,
                            &mut items,
                            &mut warnings,
                            &mut observations,
                        );
                    }
                    Some(_) => out.warn(
                        AGENT,
                        path,
                        format!("{key_prefix} is not an object; skipped"),
                    ),
                    None => {}
                }
            }
        }
        out.extend(items);
        out.warnings_from(warnings);
        out.observations_from(observations);
    }

    /// Parses a settings file: security keys, the `env` block's values (for
    /// the secret rules, never recorded) and hooks. When `enabled_plugins`
    /// is given, `enabledPlugins` is collected into it.
    fn settings_file(
        scope: Scope,
        path: &Path,
        enabled_plugins: Option<&mut BTreeMap<String, bool>>,
        out: &mut Collector,
    ) {
        let art = artifact(AGENT, scope, ArtifactKind::Settings, path);
        let Some(doc) = out.read_json(&art) else {
            return;
        };
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut observations = Vec::new();
        settings::extract(&doc, "", SETTINGS_RULES, &art, &mut items);
        let root = Context::root(&art);
        for key in COMMAND_KEYS {
            if let Some(command) = str_at(&doc, key) {
                observations.push(observe(
                    &art,
                    root.location(&[key]),
                    Field::SettingCommand,
                    Some(key),
                    Locator::Setting {
                        key_path: (*key).to_owned(),
                    },
                    command,
                ));
            }
        }
        if let Some(command) = doc.get("statusLine").and_then(|s| str_at(s, "command")) {
            observations.push(observe(
                &art,
                root.location(&["statusLine", "command"]),
                Field::SettingCommand,
                Some("statusLine.command"),
                Locator::Setting {
                    key_path: "statusLine.command".to_owned(),
                },
                command,
            ));
        }
        if let Some(env) = doc.get("env").and_then(Value::as_object) {
            for (name, value) in env {
                if let Some(text) = value.as_str() {
                    observations.push(observe(
                        &art,
                        root.location(&["env", name]),
                        Field::SettingEnv,
                        Some(name),
                        Locator::Setting {
                            key_path: "env".to_owned(),
                        },
                        text,
                    ));
                }
            }
        }
        if let Some(events) = doc.get("hooks") {
            let ctx = Context {
                source: &art,
                key_prefix: "hooks",
                segments: &["hooks"],
                line_of: &crate::parse::no_lines,
            };
            hooks::parse_event_map(events, &ctx, &mut items, &mut warnings, &mut observations);
        }
        if let Some(enabled) = enabled_plugins {
            if let Some(map) = doc.get("enabledPlugins").and_then(Value::as_object) {
                for (id, on) in map {
                    if let Some(on) = on.as_bool() {
                        enabled.insert(id.clone(), on);
                    }
                }
            }
        }
        out.extend(items);
        out.warnings_from(warnings);
        out.observations_from(observations);
    }

    fn mcp_file(scope: Scope, path: &Path, out: &mut Collector) {
        let art = artifact(AGENT, scope, ArtifactKind::McpConfig, path);
        let Some(doc) = out.read_json(&art) else {
            return;
        };
        Self::servers_in(&doc, &art, out);
    }

    /// Parses the servers of a `.mcp.json` document in either shape.
    fn servers_in(doc: &Value, art: &ArtifactRef, out: &mut Collector) {
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut observations = Vec::new();
        match mcp::server_map(doc) {
            Some((map, under)) => {
                let segments: &[&str] = match under {
                    Some(key) => &[key],
                    None => &[],
                };
                let ctx = Context {
                    source: art,
                    key_prefix: under.unwrap_or_default(),
                    segments,
                    line_of: &crate::parse::no_lines,
                };
                mcp::parse_server_map(map, &ctx, &mut items, &mut warnings, &mut observations);
            }
            None if doc.as_object().is_some_and(serde_json::Map::is_empty) => {}
            None => out.warn(AGENT, &art.path, "no mcpServers map found; skipped"),
        }
        out.extend(items);
        out.warnings_from(warnings);
        out.observations_from(observations);
    }

    fn plugins(
        home: &HomeEnv,
        plugins_dir: &Path,
        enabled: &BTreeMap<String, bool>,
        out: &mut Collector,
    ) {
        let registry_path = plugins_dir.join("installed_plugins.json");
        let registry = artifact(AGENT, Scope::User, ArtifactKind::Plugin, &registry_path);
        let Some(doc) = out.read_json(&registry) else {
            return;
        };
        let marketplaces = Self::marketplaces(plugins_dir, out);

        let Some(plugins) = doc.get("plugins").and_then(Value::as_object) else {
            out.warn(AGENT, &registry_path, "no plugins map found; skipped");
            return;
        };
        let mut parsed_installs: BTreeSet<PathBuf> = BTreeSet::new();
        for (id, installs) in plugins {
            let entries: Vec<&Value> = match installs {
                Value::Array(list) => list.iter().collect(),
                Value::Object(_) => vec![installs],
                _ => {
                    out.warn(
                        AGENT,
                        &registry_path,
                        format!("plugin \"{id}\" has no install records; skipped"),
                    );
                    continue;
                }
            };
            let (name, marketplace) = match id.split_once('@') {
                Some((name, market)) => (name.to_owned(), Some(market.to_owned())),
                None => (id.clone(), None),
            };
            for entry in entries {
                let version = str_at(entry, "version").map(str::to_owned);
                let install_path = match str_at(entry, "installPath") {
                    Some(recorded) => home.locate(Path::new(recorded)),
                    None => match (&marketplace, &version) {
                        (Some(market), Some(version)) => plugins_dir
                            .join("cache")
                            .join(market)
                            .join(&name)
                            .join(version),
                        _ => {
                            out.warn(
                                AGENT,
                                &registry_path,
                                format!("plugin \"{id}\" has no installPath; skipped"),
                            );
                            continue;
                        }
                    },
                };
                let installed = install_path.is_dir();
                let scope = Scope::Plugin { id: id.clone() };
                let manifest_path = install_path.join(".claude-plugin").join("plugin.json");
                let manifest = if installed && manifest_path.is_file() {
                    let art = artifact(AGENT, scope.clone(), ArtifactKind::Plugin, &manifest_path);
                    out.read_json(&art).map(|doc| (doc, art))
                } else {
                    None
                };
                let components = Self::components(&install_path, manifest.as_ref().map(|(d, _)| d));
                out.push(Item::Plugin(Plugin {
                    id: id.clone(),
                    name: name.clone(),
                    marketplace: marketplace.clone(),
                    marketplace_source: marketplace
                        .as_ref()
                        .and_then(|m| marketplaces.get(m).cloned()),
                    version: version.or_else(|| {
                        manifest
                            .as_ref()
                            .and_then(|(doc, _)| str_at(doc, "version"))
                            .map(str::to_owned)
                    }),
                    install_scope: str_at(entry, "scope").map(str::to_owned),
                    install_path: install_path.clone(),
                    installed,
                    enabled: enabled.get(id).copied(),
                    components,
                    source: registry.clone(),
                }));
                if installed && parsed_installs.insert(install_path.clone()) {
                    Self::plugin_components(&scope, &install_path, manifest.as_ref(), out);
                }
            }
        }
    }

    /// `known_marketplaces.json`: marketplace name → where it comes from.
    fn marketplaces(plugins_dir: &Path, out: &mut Collector) -> BTreeMap<String, String> {
        let path = plugins_dir.join("known_marketplaces.json");
        let art = artifact(AGENT, Scope::User, ArtifactKind::Plugin, &path);
        let mut out_map = BTreeMap::new();
        let Some(doc) = out.read_json(&art) else {
            return out_map;
        };
        let Some(map) = doc.as_object() else {
            out.warn(AGENT, &path, "not an object; skipped");
            return out_map;
        };
        for (name, entry) in map {
            let Some(source) = entry.get("source") else {
                continue;
            };
            let kind = str_at(source, "source").unwrap_or("unknown");
            let target = str_at(source, "repo")
                .or_else(|| str_at(source, "url"))
                .or_else(|| str_at(source, "path"))
                .unwrap_or("");
            out_map.insert(name.clone(), format!("{kind}:{}", safe_text(target)));
        }
        out_map
    }

    fn components(root: &Path, manifest: Option<&Value>) -> Vec<PluginComponent> {
        let has_dir = |name: &str| root.join(name).is_dir();
        let has_file = |name: &str| root.join(name).is_file();
        let manifest_has = |key: &str| manifest.is_some_and(|m| m.get(key).is_some());
        let mut found = Vec::new();
        if has_dir("skills") || manifest_has("skills") {
            found.push(PluginComponent::Skills);
        }
        if has_dir("commands") || manifest_has("commands") {
            found.push(PluginComponent::Commands);
        }
        if has_dir("agents") || manifest_has("agents") {
            found.push(PluginComponent::Agents);
        }
        if has_file("hooks/hooks.json") || manifest_has("hooks") {
            found.push(PluginComponent::Hooks);
        }
        if has_file(".mcp.json") || manifest_has("mcpServers") {
            found.push(PluginComponent::McpServers);
        }
        if has_file(".lsp.json") || manifest_has("lspServers") {
            found.push(PluginComponent::LspServers);
        }
        if has_dir("output-styles") || manifest_has("outputStyles") {
            found.push(PluginComponent::OutputStyles);
        }
        if has_dir("workflows") || manifest_has("workflows") {
            found.push(PluginComponent::Workflows);
        }
        let manifest_monitors = manifest.is_some_and(|m| {
            m.get("monitors").is_some()
                || m.get("experimental")
                    .is_some_and(|e| e.get("monitors").is_some())
        });
        if has_file("monitors/monitors.json") || manifest_monitors {
            found.push(PluginComponent::Monitors);
        }
        if has_dir("bin") {
            found.push(PluginComponent::Bin);
        }
        if has_file("settings.json") {
            found.push(PluginComponent::Settings);
        }
        found
    }

    /// Parses the components of one installed plugin.
    fn plugin_components(
        scope: &Scope,
        root: &Path,
        manifest: Option<&(Value, ArtifactRef)>,
        out: &mut Collector,
    ) {
        common::hooks_file(AGENT, scope, &root.join("hooks").join("hooks.json"), out);
        Self::mcp_file(scope.clone(), &root.join(".mcp.json"), out);
        common::skills_dir(AGENT, scope, &root.join("skills"), out);
        common::definitions_dir(
            AGENT,
            scope,
            SkillKind::Command,
            &root.join("commands"),
            out,
        );
        common::definitions_dir(AGENT, scope, SkillKind::Subagent, &root.join("agents"), out);

        let Some((manifest, art)) = manifest else {
            return;
        };
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut observations = Vec::new();
        if let Some(map) = manifest.get("mcpServers").and_then(Value::as_object) {
            let ctx = Context {
                source: art,
                key_prefix: "mcpServers",
                segments: &["mcpServers"],
                line_of: &crate::parse::no_lines,
            };
            mcp::parse_server_map(map, &ctx, &mut items, &mut warnings, &mut observations);
        }
        let hooks_ctx = Context {
            source: art,
            key_prefix: "hooks",
            segments: &["hooks"],
            line_of: &crate::parse::no_lines,
        };
        match manifest.get("hooks") {
            Some(Value::Object(_)) => {
                hooks::parse_event_map(
                    manifest.get("hooks").unwrap_or(&Value::Null),
                    &hooks_ctx,
                    &mut items,
                    &mut warnings,
                    &mut observations,
                );
            }
            Some(Value::String(file)) => Self::manifest_hooks_file(scope, root, file, out),
            Some(Value::Array(entries)) => {
                for entry in entries {
                    match entry {
                        Value::Object(_) => {
                            hooks::parse_event_map(
                                entry,
                                &hooks_ctx,
                                &mut items,
                                &mut warnings,
                                &mut observations,
                            );
                        }
                        Value::String(file) => Self::manifest_hooks_file(scope, root, file, out),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        out.extend(items);
        out.warnings_from(warnings);
        out.observations_from(observations);
    }

    /// A hooks file named by the manifest, which must stay inside the
    /// plugin root.
    fn manifest_hooks_file(scope: &Scope, root: &Path, file: &str, out: &mut Collector) {
        if file.contains("..") {
            out.warn(
                AGENT,
                root.join(file),
                "manifest hooks path escapes the plugin root; skipped",
            );
            return;
        }
        let path = root.join(file.trim_start_matches("./"));
        if path != root.join("hooks").join("hooks.json") {
            common::hooks_file(AGENT, scope, &path, out);
        }
    }

    fn project(root: &Path, out: &mut Collector) {
        let project = Scope::Project {
            root: root.to_path_buf(),
        };
        let local = Scope::Local {
            root: root.to_path_buf(),
        };
        let dot_claude = root.join(".claude");
        Self::settings_file(
            project.clone(),
            &dot_claude.join("settings.json"),
            None,
            out,
        );
        Self::settings_file(
            local.clone(),
            &dot_claude.join("settings.local.json"),
            None,
            out,
        );
        Self::mcp_file(project.clone(), &root.join(".mcp.json"), out);

        let mut has_claude_md = false;
        has_claude_md |= common::instruction(AGENT, &project, &root.join("CLAUDE.md"), out);
        has_claude_md |= common::instruction(AGENT, &project, &dot_claude.join("CLAUDE.md"), out);
        has_claude_md |= common::instruction(AGENT, &local, &root.join("CLAUDE.local.md"), out);
        // Claude Code reads AGENTS.md only when it has no CLAUDE.md to read.
        if !has_claude_md {
            common::instruction(AGENT, &project, &root.join("AGENTS.md"), out);
        }
        common::rules_dir(AGENT, &project, &dot_claude.join("rules"), out);
        common::skills_dir(AGENT, &project, &dot_claude.join("skills"), out);
        common::definitions_dir(
            AGENT,
            &project,
            SkillKind::Command,
            &dot_claude.join("commands"),
            out,
        );
        common::definitions_dir(
            AGENT,
            &project,
            SkillKind::Subagent,
            &dot_claude.join("agents"),
            out,
        );
    }
}

impl Adapter for ClaudeCode {
    fn agent(&self) -> Agent {
        AGENT
    }

    fn project_roots(&self, home: &HomeEnv, dirs: &AgentDirs) -> Vec<PathBuf> {
        let path = Self::app_state_path(home, dirs);
        let Ok(bytes) = std::fs::read(&path) else {
            return Vec::new();
        };
        let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
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
        let cfg = &dirs.claude_config;
        Self::app_state(home, &Self::app_state_path(home, dirs), out);
        Self::warn_ignored_defaults(home, dirs, out);

        let mut enabled_plugins = BTreeMap::new();
        Self::settings_file(
            Scope::User,
            &cfg.join("settings.json"),
            Some(&mut enabled_plugins),
            out,
        );
        Self::settings_file(
            Scope::User,
            &cfg.join("settings.local.json"),
            Some(&mut enabled_plugins),
            out,
        );

        common::instruction(AGENT, &Scope::User, &cfg.join("CLAUDE.md"), out);
        common::rules_dir(AGENT, &Scope::User, &cfg.join("rules"), out);
        common::skills_dir(AGENT, &Scope::User, &cfg.join("skills"), out);
        common::definitions_dir(
            AGENT,
            &Scope::User,
            SkillKind::Command,
            &cfg.join("commands"),
            out,
        );
        common::definitions_dir(
            AGENT,
            &Scope::User,
            SkillKind::Subagent,
            &cfg.join("agents"),
            out,
        );

        Self::plugins(home, &cfg.join("plugins"), &enabled_plugins, out);
        common::credential(AGENT, &cfg.join(".credentials.json"), out);

        for root in roots {
            Self::project(root, out);
        }
    }
}
