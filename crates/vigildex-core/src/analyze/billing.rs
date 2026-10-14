//! BILL rules: billing traps. They read variable names, settings keys and
//! credential-file key names; never a value.

use std::collections::BTreeMap;
use std::path::Path;

use super::catalogue::rule;
use super::{Analysis, Candidate};
use crate::finding::Severity;
use crate::hosts::{self, host_of};
use crate::model::{Agent, ArtifactKind, Item, RedactedValue, Scope, Setting};
use crate::observe::{Field, Location, Observation};

/// The cloud provider switches of BILL-005.
const PROVIDER_SWITCHES: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
];

/// The Copilot token overrides of BILL-009, in precedence order.
const COPILOT_TOKENS: &[&str] = &["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];

/// Base-URL variables and the vendor whose hosts they must point at.
const BASE_URL_VARS: &[(&str, &str, Agent)] = &[
    ("ANTHROPIC_BASE_URL", "anthropic", Agent::ClaudeCode),
    ("OPENAI_BASE_URL", "openai", Agent::Codex),
    (
        "COPILOT_PROVIDER_BASE_URL",
        "copilot_provider",
        Agent::CopilotCli,
    ),
];

/// Runs BILL-001…007 and BILL-009.
pub fn run(analysis: &Analysis<'_>, out: &mut Vec<Candidate>) {
    for observation in analysis.observations() {
        env_variable(analysis, observation, out);
    }
    settings(analysis, out);
    codex_auth(analysis, out);
}

/// Evidence for a variable: `NAME=masked` when a secret was recognised,
/// else `NAME (set)` / `NAME (set at run time)`.
fn variable_evidence(observation: &Observation) -> String {
    let name = observation.name.as_deref().unwrap_or_default();
    match (&observation.secret, observation.class) {
        (Some(hit), _) => format!("{name}={}", hit.masked),
        (None, crate::secrets::ValueClass::Dynamic) => format!("{name} (set at run time)"),
        (None, crate::secrets::ValueClass::Reference) => {
            format!("{name} (set from another variable)")
        }
        (None, _) => format!("{name} (set)"),
    }
}

fn candidate(
    analysis: &Analysis<'_>,
    id: &'static str,
    title: &str,
    observation: &Observation,
    agent: Agent,
) -> Candidate {
    let text = rule(id);
    Candidate {
        rule: id,
        severity: text.severity,
        title: title.to_owned(),
        why: text.why.to_owned(),
        location: observation.location.clone(),
        evidence: Some(variable_evidence(observation)),
        fingerprint: None,
        fix: text.fix_steps(),
        agents: vec![agent],
        items: analysis.item_of(observation),
        identity: None,
        tags: Vec::new(),
    }
}

/// The name-keyed rules on one environment assignment.
fn env_variable(analysis: &Analysis<'_>, observation: &Observation, out: &mut Vec<Candidate>) {
    let Some(name) = observation.name.as_deref() else {
        return;
    };
    let in_profile = observation.field == Field::ShellExport;
    let in_settings = observation.field == Field::SettingEnv;
    let in_dotenv = observation.field == Field::DotenvVar;
    if !(in_profile || in_settings || in_dotenv) || !observation.is_set() {
        return;
    }
    if in_profile || in_settings {
        match name {
            "ANTHROPIC_API_KEY" if analysis.claude_subscription => out.push(candidate(
                analysis,
                "BILL-001",
                "API key bills headless runs",
                observation,
                Agent::ClaudeCode,
            )),
            "ANTHROPIC_AUTH_TOKEN" => out.push(candidate(
                analysis,
                "BILL-002",
                "Auth token overrides your plan",
                observation,
                Agent::ClaudeCode,
            )),
            "CLAUDE_CODE_OAUTH_TOKEN" => out.push(candidate(
                analysis,
                "BILL-004",
                "OAuth token in plain text",
                observation,
                Agent::ClaudeCode,
            )),
            _ if PROVIDER_SWITCHES.contains(&name) && observation.truthy => out.push(candidate(
                analysis,
                "BILL-005",
                "Cloud provider switch is on",
                observation,
                Agent::ClaudeCode,
            )),
            _ if in_profile && COPILOT_TOKENS.contains(&name) => out.push(candidate(
                analysis,
                "BILL-009",
                "Token overrides Copilot login",
                observation,
                Agent::CopilotCli,
            )),
            _ => {}
        }
    }
    if let Some((_, vendor, agent)) = BASE_URL_VARS.iter().find(|(var, _, _)| *var == name) {
        let Some(url) = &observation.host else {
            return;
        };
        if !custom_host(vendor, url) {
            return;
        }
        let repo_file = in_dotenv || analysis.is_repo_file(&observation.source);
        let mut finding = candidate(analysis, "BILL-006", "", observation, *agent);
        finding.evidence = Some(format!("{name}={url}"));
        base_url_severity(&mut finding, repo_file);
        out.push(finding);
    }
}

/// Whether a base URL points away from the vendor and the local machine.
fn custom_host(vendor: &str, url: &str) -> bool {
    match host_of(url) {
        Some(host) => !hosts::is_loopback(&host) && !hosts::hosts().allows(vendor, &host),
        // Not a URL: a reference or relative text the engine cannot judge.
        None => false,
    }
}

/// BILL-006 is Medium (`Custom API gateway`) from the user's own files and
/// High (`Sends your API key elsewhere`) from a repository file.
fn base_url_severity(finding: &mut Candidate, repo_file: bool) {
    if repo_file {
        finding.severity = Severity::High;
        finding.title = "Sends your API key elsewhere".to_owned();
        finding.tags.push("repo_file".to_owned());
    } else {
        finding.title = "Custom API gateway".to_owned();
    }
}

/// Settings-based rules: BILL-003 (Claude `apiKeyHelper`), BILL-006 and
/// BILL-007 on Codex `config.toml` keys.
fn settings(analysis: &Analysis<'_>, out: &mut Vec<Candidate>) {
    // Codex keys are judged per file: the selected provider decides which
    // `model_providers.*.base_url` counts.
    let mut codex_files: BTreeMap<&Path, Vec<(&Setting, &str)>> = BTreeMap::new();
    for entry in analysis.entries() {
        let Item::Setting(setting) = &entry.item else {
            continue;
        };
        let source = entry.source();
        match source.agent {
            Agent::ClaudeCode if setting.key_path == "apiKeyHelper" => {
                let text = rule("BILL-003");
                out.push(Candidate {
                    rule: "BILL-003",
                    severity: text.severity,
                    title: "Key helper bills headless runs".to_owned(),
                    why: text.why.to_owned(),
                    location: Location::key(&source.path, "apiKeyHelper").at_line(setting.line),
                    evidence: Some(format!("apiKeyHelper = {}", value_text(&setting.value))),
                    fingerprint: None,
                    fix: text.fix_steps(),
                    agents: vec![Agent::ClaudeCode],
                    items: vec![entry.id.clone()],
                    identity: None,
                    tags: Vec::new(),
                });
            }
            Agent::Codex
                if source.kind == ArtifactKind::Settings && source.scope == Scope::User =>
            {
                codex_files
                    .entry(source.path.as_path())
                    .or_default()
                    .push((setting, entry.id.as_str()));
            }
            _ => {}
        }
    }
    for (path, settings) in codex_files {
        codex_config(path, &settings, out);
    }
}

fn value_text(value: &RedactedValue) -> String {
    match value {
        RedactedValue::Text { value } => value.clone(),
        RedactedValue::Bool { value } => value.to_string(),
        RedactedValue::Number { value } => value.to_string(),
        RedactedValue::List { values } => values.join(", "),
        RedactedValue::Keys { keys } => keys.join(", "),
        RedactedValue::Present => "(present)".to_owned(),
        RedactedValue::Null => "null".to_owned(),
        #[allow(unreachable_patterns, reason = "RedactedValue is non-exhaustive")]
        _ => String::new(),
    }
}

/// BILL-006 and BILL-007 on one user-scope `config.toml`. Project files are
/// skipped: Codex ignores providers and base URLs there.
fn codex_config(path: &Path, settings: &[(&Setting, &str)], out: &mut Vec<Candidate>) {
    let text_of = |key: &str| {
        settings
            .iter()
            .find_map(|(s, _)| match (s.key_path == key, &s.value) {
                (true, RedactedValue::Text { value }) => Some(value.as_str()),
                _ => None,
            })
    };
    let provider = text_of("model_provider").unwrap_or("openai");
    let mut urls: Vec<(&str, &str)> = Vec::new();
    for (key, vendor) in [
        ("openai_base_url", "openai"),
        ("chatgpt_base_url", "chatgpt"),
    ] {
        if let Some(url) = text_of(key) {
            urls.push((key, vendor));
            let _ = url;
        }
    }
    let provider_key = format!("model_providers.{provider}.base_url");
    if provider != "openai" && text_of(&provider_key).is_some() {
        urls.push((provider_key.as_str(), "openai"));
    }
    for (key, vendor) in urls {
        let Some((setting, id)) = settings.iter().find(|(s, _)| s.key_path == key) else {
            continue;
        };
        let RedactedValue::Text { value: url } = &setting.value else {
            continue;
        };
        if !custom_host(vendor, url) {
            continue;
        }
        let text = rule("BILL-006");
        let mut finding = Candidate {
            rule: "BILL-006",
            severity: text.severity,
            title: String::new(),
            why: text.why.to_owned(),
            location: Location::key(path, key).at_line(setting.line),
            evidence: Some(format!("{key} = \"{url}\"")),
            fingerprint: None,
            fix: text.fix_steps(),
            agents: vec![Agent::Codex],
            items: vec![(*id).to_owned()],
            identity: None,
            tags: Vec::new(),
        };
        base_url_severity(&mut finding, false);
        out.push(finding);
    }
    if provider != "openai" {
        if let Some((setting, id)) = settings
            .iter()
            .find(|(s, _)| s.key_path == "model_provider")
        {
            let text = rule("BILL-007");
            out.push(Candidate {
                rule: "BILL-007",
                severity: text.severity,
                title: "Uses a custom provider".to_owned(),
                why: text.why.to_owned(),
                location: Location::key(path, "model_provider").at_line(setting.line),
                evidence: Some(format!("model_provider = \"{provider}\"")),
                fingerprint: None,
                fix: text.fix_steps(),
                agents: vec![Agent::Codex],
                items: vec![(*id).to_owned()],
                identity: None,
                tags: Vec::new(),
            });
        }
    }
}

/// BILL-007: Codex signed in with an API key. Decided from the key names
/// and JSON value types of `auth.json` only: `OPENAI_API_KEY` is a string
/// and there is no `tokens` object.
fn codex_auth(analysis: &Analysis<'_>, out: &mut Vec<Candidate>) {
    for entry in analysis.entries() {
        let Item::Credential(credential) = &entry.item else {
            continue;
        };
        if entry.source().agent != Agent::Codex || !credential.exists {
            continue;
        }
        let api_key = credential
            .keys
            .iter()
            .any(|k| k.name == "OPENAI_API_KEY" && k.value_type == "string");
        let tokens = credential
            .keys
            .iter()
            .any(|k| k.name == "tokens" && k.value_type == "object");
        if !api_key || tokens {
            continue;
        }
        let text = rule("BILL-007");
        out.push(Candidate {
            rule: "BILL-007",
            severity: text.severity,
            title: "Signed in with an API key".to_owned(),
            why: text.why.to_owned(),
            location: Location::key(&credential.path, "OPENAI_API_KEY"),
            evidence: Some("OPENAI_API_KEY is a string and there is no tokens object".to_owned()),
            fingerprint: None,
            fix: text.fix_steps(),
            agents: vec![Agent::Codex],
            items: vec![entry.id.clone()],
            identity: None,
            tags: Vec::new(),
        });
    }
}
