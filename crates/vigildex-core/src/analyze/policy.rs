//! The finding policy (`docs/RULES.md` § Finding policy): how many findings
//! a set of rule matches becomes.
//!
//! 1. One finding per location: the highest severity wins; on a tie a rule
//!    that names the key (BILL, RISK) beats the generic secret rule (SEC);
//!    the losers' rule IDs become tags.
//! 2. No cross-file merge for secrets: the same token in two files is two
//!    findings.
//! 3. One finding per server across agents and files: the rules that set an
//!    `identity` (RISK-001, RISK-008, RISK-009) are merged by it.
//!
//! Ids are assigned last, from the rule and the home-relative location:
//! the key path (or variable name) rather than the line, so that editing a
//! profile above a finding does not change its id.

use std::collections::BTreeMap;

use super::Candidate;
use crate::finding::{Category, Finding};
use crate::home::HomeEnv;
use crate::inventory::short_hash;
use crate::observe::Location;

/// Applies the policy and builds the findings.
#[must_use]
pub fn resolve(candidates: Vec<Candidate>, home: &HomeEnv) -> Vec<Finding> {
    let per_location = one_per_location(candidates);
    let merged = merge_by_identity(per_location);
    let mut findings: Vec<Finding> = merged
        .into_iter()
        .map(|c| {
            let rel = home.relative(&c.location.path);
            // The line is used only when the location has no key.
            let place = match (&c.location.key_path, c.location.line) {
                (Some(key), _) => key.clone(),
                (None, Some(line)) => format!("line {line}"),
                (None, None) => String::new(),
            };
            let id = short_hash(&format!("{}|{rel}|{place}", c.rule));
            let mut tags = c.tags;
            tags.sort();
            tags.dedup();
            Finding {
                id,
                rule: c.rule.to_owned(),
                category: Category::of_rule(c.rule).unwrap_or(Category::Risk),
                severity: c.severity,
                title: c.title,
                why: c.why,
                location: c.location,
                evidence: c.evidence,
                fingerprint: c.fingerprint,
                fix: c.fix,
                agents: c.agents,
                items: c.items,
                tags,
            }
        })
        .collect();
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.location.cmp(&b.location))
    });
    // Two findings with one rule at one key (a variable exported twice in a
    // profile) get distinct ids in line order.
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    for finding in &mut findings {
        let count = seen.entry(finding.id.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            finding.id = short_hash(&format!("{}#{count}", finding.id));
        }
    }
    findings
}

/// The grouping key of policy 1: the file plus the line (when the format
/// has lines) or the key path.
fn location_key(location: &Location) -> (String, String) {
    let place = match (location.line, &location.key_path) {
        (Some(line), _) => format!("line:{line}"),
        (None, Some(key)) => format!("key:{key}"),
        (None, None) => String::new(),
    };
    (location.path.to_string_lossy().into_owned(), place)
}

/// Step 1.
fn one_per_location(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut groups: BTreeMap<(String, String), Vec<Candidate>> = BTreeMap::new();
    for candidate in candidates {
        groups
            .entry(location_key(&candidate.location))
            .or_default()
            .push(candidate);
    }
    let mut out = Vec::new();
    for (_, mut group) in groups {
        group.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| is_secret(a.rule).cmp(&is_secret(b.rule)))
                .then_with(|| a.rule.cmp(b.rule))
        });
        let mut iter = group.into_iter();
        let Some(mut winner) = iter.next() else {
            continue;
        };
        for loser in iter {
            if loser.rule != winner.rule {
                winner.tags.push(loser.rule.to_owned());
            }
            winner.tags.extend(loser.tags);
            for item in loser.items {
                if !winner.items.contains(&item) {
                    winner.items.push(item);
                }
            }
            for agent in loser.agents {
                if !winner.agents.contains(&agent) {
                    winner.agents.push(agent);
                }
            }
            if winner.fingerprint.is_none() {
                winner.fingerprint = loser.fingerprint;
            }
        }
        winner.agents.sort();
        out.push(winner);
    }
    out
}

fn is_secret(rule: &str) -> bool {
    rule.starts_with("SEC-")
}

/// Step 3.
fn merge_by_identity(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut merged: Vec<Candidate> = Vec::new();
    let mut index: BTreeMap<(String, String), usize> = BTreeMap::new();
    for candidate in candidates {
        let Some(identity) = candidate.identity.clone() else {
            merged.push(candidate);
            continue;
        };
        let key = (candidate.rule.to_owned(), identity);
        match index.get(&key) {
            Some(&at) => {
                let into = &mut merged[at];
                // The location of the copy that comes first in agent order,
                // then path order.
                let earlier = (candidate.agents_min(), &candidate.location)
                    < (into.agents_min(), &into.location);
                if earlier {
                    into.location = candidate.location;
                }
                if candidate.severity < into.severity {
                    into.severity = candidate.severity;
                }
                for agent in candidate.agents {
                    if !into.agents.contains(&agent) {
                        into.agents.push(agent);
                    }
                }
                for item in candidate.items {
                    if !into.items.contains(&item) {
                        into.items.push(item);
                    }
                }
                into.tags.extend(candidate.tags);
                into.agents.sort();
            }
            None => {
                index.insert(key, merged.len());
                merged.push(candidate);
            }
        }
    }
    merged
}

impl Candidate {
    fn agents_min(&self) -> Option<crate::model::Agent> {
        self.agents.iter().min().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FixSteps, Severity};
    use crate::model::Agent;
    use std::path::PathBuf;

    fn cand(rule: &'static str, severity: Severity, location: Location, agent: Agent) -> Candidate {
        Candidate {
            rule,
            severity,
            title: rule.to_owned(),
            why: String::new(),
            location,
            evidence: None,
            fingerprint: None,
            fix: FixSteps {
                summary: String::new(),
                steps: Vec::new(),
            },
            agents: vec![agent],
            items: vec![format!("{rule}-item")],
            identity: None,
            tags: Vec::new(),
        }
    }

    fn home() -> HomeEnv {
        HomeEnv::resolve(Some(&PathBuf::from(env!("CARGO_MANIFEST_DIR")))).unwrap()
    }

    #[test]
    fn highest_severity_wins_and_ties_go_to_the_key_naming_rule() {
        let line = Location::line("/h/.zshrc", 42);
        let findings = resolve(
            vec![
                cand("SEC-004", Severity::Medium, line.clone(), Agent::Shared),
                cand("BILL-001", Severity::High, line.clone(), Agent::ClaudeCode),
                cand("BILL-009", Severity::Low, line.clone(), Agent::CopilotCli),
            ],
            &home(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "BILL-001");
        assert_eq!(findings[0].tags, vec!["BILL-009", "SEC-004"]);
        assert_eq!(findings[0].items.len(), 3);

        let line = Location::line("/h/.zshrc", 7);
        let findings = resolve(
            vec![
                cand("SEC-004", Severity::Medium, line.clone(), Agent::Shared),
                cand(
                    "BILL-004",
                    Severity::Medium,
                    line.clone(),
                    Agent::ClaudeCode,
                ),
            ],
            &home(),
        );
        assert_eq!(findings[0].rule, "BILL-004");
        assert_eq!(findings[0].tags, vec!["SEC-004"]);
    }

    #[test]
    fn different_files_stay_separate_and_identities_merge() {
        let mut a = cand(
            "RISK-001",
            Severity::Low,
            Location::key("/h/.codex/config.toml", "mcp_servers.lint-helper"),
            Agent::Codex,
        );
        a.identity = Some("same".into());
        let mut b = cand(
            "RISK-001",
            Severity::Low,
            Location::key("/h/.claude.json", "mcpServers.lint-helper"),
            Agent::ClaudeCode,
        );
        b.identity = Some("same".into());
        b.items = vec!["claude-item".into()];
        let sec_a = cand(
            "SEC-001",
            Severity::High,
            Location::key("/h/a.json", "x.env.T"),
            Agent::ClaudeCode,
        );
        let sec_b = cand(
            "SEC-001",
            Severity::High,
            Location::key("/h/b.json", "x.env.T"),
            Agent::ClaudeCode,
        );
        let findings = resolve(vec![a, b, sec_a, sec_b], &home());
        assert_eq!(findings.len(), 3);
        let risk = findings.iter().find(|f| f.rule == "RISK-001").unwrap();
        assert_eq!(risk.agents, vec![Agent::ClaudeCode, Agent::Codex]);
        assert_eq!(risk.location.path, PathBuf::from("/h/.claude.json"));
        assert_eq!(risk.items.len(), 2);
        assert_eq!(findings.iter().filter(|f| f.rule == "SEC-001").count(), 2);
    }

    #[test]
    fn sorted_by_severity_then_rule_and_ids_are_stable() {
        let findings = resolve(
            vec![
                cand(
                    "RISK-001",
                    Severity::Low,
                    Location::key("/h/a", "k"),
                    Agent::Codex,
                ),
                cand(
                    "SEC-006",
                    Severity::High,
                    Location::file("/h/c"),
                    Agent::Codex,
                ),
                cand(
                    "BILL-006",
                    Severity::Medium,
                    Location::key("/h/b", "k"),
                    Agent::Codex,
                ),
            ],
            &home(),
        );
        let rules: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(rules, vec!["SEC-006", "BILL-006", "RISK-001"]);
        let again = resolve(
            vec![cand(
                "SEC-006",
                Severity::High,
                Location::file("/h/c"),
                Agent::Codex,
            )],
            &home(),
        );
        assert_eq!(findings[0].id, again[0].id);
        assert_eq!(findings[0].id.len(), 16);
        // Ids follow the key, not the line.
        let mut at_42 = Location::line("/h/.zshrc", 42);
        at_42.key_path = Some("GITHUB_TOKEN".into());
        let mut at_43 = Location::line("/h/.zshrc", 43);
        at_43.key_path = Some("GITHUB_TOKEN".into());
        let a = resolve(
            vec![cand("SEC-004", Severity::Medium, at_42, Agent::Shared)],
            &home(),
        );
        let b = resolve(
            vec![cand("SEC-004", Severity::Medium, at_43, Agent::Shared)],
            &home(),
        );
        assert_eq!(a[0].id, b[0].id);
    }
}
