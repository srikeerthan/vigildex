//! SEC rules: secrets the observations found, by where they sit, plus the
//! credential-file permission check.

use super::catalogue::rule;
use super::{agent_of_variable, Analysis, Candidate};
use crate::model::{Agent, Item};
use crate::observe::{Field, Location, Observation};

/// The rule and title for a hit on a field.
fn rule_for(field: Field) -> (&'static str, &'static str) {
    match field {
        Field::McpEnv | Field::McpHeader => ("SEC-001", "in an MCP config"),
        Field::McpArg => ("SEC-002", "in args"),
        Field::McpUrl => ("SEC-002", "in a server URL"),
        Field::McpCommand => ("SEC-002", "in a command"),
        Field::SettingEnv => ("SEC-003", "in settings env"),
        Field::SettingCommand => ("SEC-003", "in a helper command"),
        Field::HookHeader => ("SEC-003", "in a hook header"),
        Field::HookCommand => ("SEC-003", "in a hook command"),
        Field::HookUrl => ("SEC-003", "in a hook URL"),
        Field::ShellExport => ("SEC-004", "in plain text"),
        Field::DotenvVar => ("SEC-005", "in .env"),
    }
}

/// Runs SEC-001…006.
pub fn run(analysis: &Analysis<'_>, out: &mut Vec<Candidate>) {
    for observation in analysis.observations() {
        let Some(hit) = &observation.secret else {
            continue;
        };
        let (id, place) = rule_for(observation.field);
        let text = rule(id);
        let evidence = match (&observation.name, observation.field) {
            (Some(name), Field::ShellExport | Field::DotenvVar) => {
                format!("{name}={}", hit.masked)
            }
            _ => hit.masked.clone(),
        };
        out.push(Candidate {
            rule: id,
            kind: observation.source.kind,
            severity: text.severity,
            title: format!("{} {place}", hit.kind),
            why: text.why.to_owned(),
            location: observation.location.clone(),
            evidence: Some(evidence),
            fingerprint: None,
            fix: text.fix_steps(),
            agents: agents_for(analysis, observation),
            items: analysis.item_of(observation),
            identity: None,
            tags: Vec::new(),
        });
    }
    credential_files(analysis, out);
}

/// The agents a secret finding concerns: the file's agent, or for a shared
/// source the agent the variable name belongs to, plus (for a project
/// file) the agents that recorded the project.
fn agents_for(analysis: &Analysis<'_>, observation: &Observation) -> Vec<Agent> {
    let mut agents = analysis.agents_of(&observation.source);
    if observation.source.agent == Agent::Shared {
        if let Some(agent) = observation.name.as_deref().and_then(agent_of_variable) {
            agents.push(agent);
        }
    }
    agents.sort();
    agents.dedup();
    agents
}

/// SEC-006: a credential file other users can read.
fn credential_files(analysis: &Analysis<'_>, out: &mut Vec<Candidate>) {
    for entry in analysis.entries() {
        let Item::Credential(credential) = &entry.item else {
            continue;
        };
        if !credential.exists || credential.readable_by_others != Some(true) {
            continue;
        }
        let text = rule("SEC-006");
        let mode = credential.mode.clone().unwrap_or_default();
        out.push(Candidate {
            rule: "SEC-006",
            kind: entry.source().kind,
            severity: text.severity,
            title: "Credential file readable by others".to_owned(),
            why: text.why.to_owned(),
            location: Location::file(&credential.path),
            evidence: Some(format!("mode {mode}")),
            fingerprint: None,
            fix: text.fix_steps(),
            agents: vec![entry.source().agent],
            items: vec![entry.id.clone()],
            identity: None,
            tags: Vec::new(),
        });
    }
}
