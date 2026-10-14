//! The analyzers: the SEC, BILL and RISK rules of `docs/RULES.md` applied to
//! an inventory and its observations, then reduced by the finding policy.
//!
//! Each rule module produces [`Candidate`]s; [`policy`] decides how many
//! findings they become (one per location, highest severity wins; one per
//! server across agents) and gives each finding its stable id.

pub mod billing;
pub mod catalogue;
pub mod policy;
pub mod risk;
pub mod secrets;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::finding::{Finding, FixSteps, Severity};
use crate::home::HomeEnv;
use crate::inventory::Scanned;
use crate::model::{Agent, ArtifactKind, ArtifactRef, Item, ItemEntry, RedactedValue, Scope};
use crate::observe::{Location, Locator, Observation};

/// A finding before the policy has been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The rule ID.
    pub rule: &'static str,
    /// The kind of file the finding is in, which decides how locations are
    /// grouped (policy 1: by line in a profile or `.env`, by key elsewhere).
    pub kind: ArtifactKind,
    /// The severity to report.
    pub severity: Severity,
    /// The list title.
    pub title: String,
    /// One sentence on why it matters.
    pub why: String,
    /// Where it is.
    pub location: Location,
    /// Masked evidence.
    pub evidence: Option<String>,
    /// Salted fingerprint of the secret, for secret findings.
    pub fingerprint: Option<String>,
    /// How to fix it.
    pub fix: FixSteps,
    /// The agents affected.
    pub agents: Vec<Agent>,
    /// Inventory item ids involved.
    pub items: Vec<String>,
    /// The item identity, for rules that report one finding per server
    /// across agents and files (policy 3).
    pub identity: Option<String>,
    /// Extra tags.
    pub tags: Vec<String>,
}

/// What every rule module gets to look at.
#[derive(Debug)]
pub struct Analysis<'a> {
    /// The scan.
    pub scanned: &'a Scanned,
    /// The home.
    pub home: &'a HomeEnv,
    /// Plugins that settings switch off: their components are inventoried
    /// but skipped by every rule (policy 4).
    pub disabled_plugins: BTreeSet<String>,
    /// Whether Claude Code is signed in with a subscription
    /// (`hasAvailableSubscription` plus an `oauthAccount` with billing keys).
    pub claude_subscription: bool,
    /// Agents that recorded each project root.
    pub project_agents: BTreeMap<PathBuf, BTreeSet<Agent>>,
    /// Item ids by source path and locator.
    item_index: BTreeMap<(PathBuf, String), String>,
    /// Servers every rule skips (policy 4): `enabled = false`, or a project
    /// `.mcp.json` server the user switched off with
    /// `disabledMcpjsonServers`. Keyed by source path and locator.
    disabled_servers: BTreeSet<(PathBuf, String)>,
}

impl<'a> Analysis<'a> {
    fn new(scanned: &'a Scanned, home: &'a HomeEnv) -> Self {
        let mut disabled_plugins = BTreeSet::new();
        let mut claude_subscription_flag = false;
        let mut claude_billing_account = false;
        let mut project_agents: BTreeMap<PathBuf, BTreeSet<Agent>> = BTreeMap::new();
        let mut item_index = BTreeMap::new();
        let mut disabled_servers = BTreeSet::new();
        // `disabledMcpjsonServers` lists per project root, from
        // `~/.claude.json` and from the project's settings files.
        let mut disabled_mcpjson: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
        for entry in &scanned.inventory.items {
            let source = entry.source();
            item_index
                .entry((source.path.clone(), entry.item.locator()))
                .or_insert_with(|| entry.id.clone());
            match &entry.item {
                Item::McpServer(server) if server.enabled == Some(false) => {
                    disabled_servers.insert((source.path.clone(), entry.item.locator()));
                }
                Item::Setting(setting)
                    if setting.key_path.ends_with("disabledMcpjsonServers")
                        && source.agent == Agent::ClaudeCode =>
                {
                    if let (
                        RedactedValue::List { values },
                        Scope::Project { root } | Scope::Local { root },
                    ) = (&setting.value, &source.scope)
                    {
                        disabled_mcpjson
                            .entry(root.clone())
                            .or_default()
                            .extend(values.iter().cloned());
                    }
                }
                _ => {}
            }
            match &source.scope {
                Scope::Project { root } | Scope::Local { root }
                    if source.agent != Agent::Shared =>
                {
                    project_agents
                        .entry(root.clone())
                        .or_default()
                        .insert(source.agent);
                }
                _ => {}
            }
            match &entry.item {
                Item::Plugin(plugin) if plugin.enabled == Some(false) => {
                    disabled_plugins.insert(plugin.id.clone());
                }
                Item::Setting(setting)
                    if source.agent == Agent::ClaudeCode && source.scope == Scope::User =>
                {
                    match (setting.key_path.as_str(), &setting.value) {
                        ("hasAvailableSubscription", RedactedValue::Bool { value: true }) => {
                            claude_subscription_flag = true;
                        }
                        ("oauthAccount", RedactedValue::Keys { keys }) => {
                            claude_billing_account = keys
                                .iter()
                                .any(|k| k == "billingType" || k == "organizationType");
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        // A project `.mcp.json` server the user switched off.
        for entry in &scanned.inventory.items {
            let source = entry.source();
            let Item::McpServer(server) = &entry.item else {
                continue;
            };
            let Scope::Project { root } = &source.scope else {
                continue;
            };
            if source.kind == ArtifactKind::McpConfig
                && disabled_mcpjson
                    .get(root)
                    .is_some_and(|names| names.contains(&server.name))
            {
                disabled_servers.insert((source.path.clone(), entry.item.locator()));
            }
        }
        Self {
            scanned,
            home,
            disabled_plugins,
            claude_subscription: claude_subscription_flag && claude_billing_account,
            project_agents,
            item_index,
            disabled_servers,
        }
    }

    /// Whether rules apply to a source: everything except the components of
    /// a disabled plugin.
    #[must_use]
    pub fn active(&self, source: &ArtifactRef) -> bool {
        match &source.scope {
            Scope::Plugin { id } => !self.disabled_plugins.contains(id),
            _ => true,
        }
    }

    /// Whether a server is switched off (policy 4).
    #[must_use]
    pub fn server_disabled(&self, path: &Path, locator: &str) -> bool {
        self.disabled_servers
            .contains(&(path.to_path_buf(), locator.to_owned()))
    }

    /// The inventory entries rules may report on: not in a disabled plugin,
    /// not a disabled server.
    pub fn entries(&self) -> impl Iterator<Item = &'a ItemEntry> + '_ {
        self.scanned.inventory.items.iter().filter(move |e| {
            self.active(e.source()) && !self.server_disabled(&e.source().path, &e.item.locator())
        })
    }

    /// The observations rules may report on.
    pub fn observations(&self) -> impl Iterator<Item = &'a Observation> + '_ {
        self.scanned.observations.iter().filter(move |o| {
            self.active(&o.source)
                && !locator_text(&o.locator)
                    .is_some_and(|loc| self.server_disabled(&o.source.path, &loc))
        })
    }

    /// The id of the item an observation belongs to.
    #[must_use]
    pub fn item_of(&self, observation: &Observation) -> Vec<String> {
        let Some(locator) = locator_text(&observation.locator) else {
            return Vec::new();
        };
        self.item_index
            .get(&(observation.source.path.clone(), locator))
            .cloned()
            .into_iter()
            .collect()
    }

    /// The agents that read a file: its own agent, or for a shared source
    /// the agents that recorded the project root, else none.
    #[must_use]
    pub fn agents_of(&self, source: &ArtifactRef) -> Vec<Agent> {
        if source.agent != Agent::Shared {
            return vec![source.agent];
        }
        match &source.scope {
            Scope::Project { root } | Scope::Local { root } => self
                .project_agents
                .get(root)
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Whether a file is part of a repository (committed with it), which
    /// raises BILL-006 to High.
    #[must_use]
    pub fn is_repo_file(&self, source: &ArtifactRef) -> bool {
        matches!(source.scope, Scope::Project { .. })
    }

    /// `~`-relative form of a path, for evidence and ids.
    #[must_use]
    pub fn relative(&self, path: &Path) -> String {
        self.home.relative(path)
    }
}

/// The item locator an observation points at, in [`Item::locator`] form.
fn locator_text(locator: &Locator) -> Option<String> {
    match locator {
        Locator::McpServer { key_path } => Some(format!("mcp:{key_path}")),
        Locator::Hook { key_path } => Some(format!("hook:{key_path}")),
        Locator::Setting { key_path } => Some(format!("setting:{key_path}")),
        Locator::None => None,
    }
}

/// The agent a variable name belongs to, for findings on shared sources.
#[must_use]
pub fn agent_of_variable(name: &str) -> Option<Agent> {
    if name.starts_with("ANTHROPIC_") || name.starts_with("CLAUDE_") {
        Some(Agent::ClaudeCode)
    } else if name.starts_with("OPENAI_") || name.starts_with("CODEX_") {
        Some(Agent::Codex)
    } else if name.starts_with("COPILOT_")
        || name.starts_with("GITHUB_COPILOT_")
        || name == "GITHUB_TOKEN"
        || name == "GH_TOKEN"
    {
        Some(Agent::CopilotCli)
    } else if name.starts_with("CURSOR_") {
        Some(Agent::Cursor)
    } else {
        None
    }
}

/// Longest evidence string a finding carries; a command line is cut after
/// this many characters.
const MAX_EVIDENCE_CHARS: usize = 160;

/// Runs every rule over a scan and applies the finding policy.
#[must_use]
pub fn findings(scanned: &Scanned, home: &HomeEnv) -> Vec<Finding> {
    let analysis = Analysis::new(scanned, home);
    let mut candidates = Vec::new();
    secrets::run(&analysis, &mut candidates);
    billing::run(&analysis, &mut candidates);
    risk::run(&analysis, &mut candidates);
    for candidate in &mut candidates {
        if let Some(evidence) = &candidate.evidence {
            if evidence.chars().count() > MAX_EVIDENCE_CHARS {
                let mut cut: String = evidence.chars().take(MAX_EVIDENCE_CHARS - 1).collect();
                cut.push('…');
                candidate.evidence = Some(cut);
            }
        }
    }
    policy::resolve(candidates, home)
}

/// Problems loading the vendored rule files, as warnings for the report.
#[must_use]
pub fn rule_warnings() -> Vec<crate::model::Warning> {
    crate::secrets::rules()
        .warnings
        .iter()
        .chain(crate::hosts::hosts().warnings.iter())
        .map(|message| crate::model::Warning {
            agent: None,
            path: None,
            message: message.clone(),
        })
        .collect()
}
