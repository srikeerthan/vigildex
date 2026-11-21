//! Steps several adapters share: skill folders, Markdown definitions,
//! instruction files, hooks files and credential metadata.

use std::fs;
use std::path::Path;

use crate::collect::{self, artifact, Collector};
use crate::model::{
    Agent, ArtifactKind, Credential, CredentialKey, Instruction, Item, Scope, SkillKind,
};
use crate::parse::{frontmatter, hooks, skills};

/// Scans a directory of skill folders (`<dir>/<name>/SKILL.md`). A
/// sub-directory without a `SKILL.md` is searched one level deeper, which
/// covers Claude Code's `skills/synced/<name>/`.
pub fn skills_dir(agent: Agent, scope: &Scope, dir: &Path, out: &mut Collector) {
    for sub in collect::subdirs(dir) {
        if sub.join("SKILL.md").is_file() {
            skill(agent, scope, &sub, out);
            continue;
        }
        for nested in collect::subdirs(&sub) {
            if nested.join("SKILL.md").is_file() {
                skill(agent, scope, &nested, out);
            }
        }
    }
}

/// Parses one skill folder.
pub fn skill(agent: Agent, scope: &Scope, dir: &Path, out: &mut Collector) {
    let path = dir.join("SKILL.md");
    let art = artifact(agent, scope.clone(), ArtifactKind::Skill, &path);
    let Some(text) = out.read_text(&art) else {
        return;
    };
    let (items, warnings, observations) =
        skills::parse_definition(SkillKind::Skill, &path, Some(dir), &text, &art);
    out.extend(items);
    out.warnings_from(warnings);
    out.observations_from(observations);
}

/// Parses every Markdown file under `dir` as a command or subagent.
pub fn definitions_dir(
    agent: Agent,
    scope: &Scope,
    kind: SkillKind,
    dir: &Path,
    out: &mut Collector,
) {
    for path in collect::markdown_files(dir) {
        let art = artifact(agent, scope.clone(), ArtifactKind::Skill, &path);
        let Some(text) = out.read_text(&art) else {
            continue;
        };
        let (items, warnings, observations) =
            skills::parse_definition(kind, &path, None, &text, &art);
        out.extend(items);
        out.warnings_from(warnings);
        out.observations_from(observations);
    }
}

/// Records an instruction file, when it exists. Returns whether it did.
pub fn instruction(agent: Agent, scope: &Scope, path: &Path, out: &mut Collector) -> bool {
    let art = artifact(agent, scope.clone(), ArtifactKind::Instructions, path);
    let Some(text) = out.read_text(&art) else {
        return false;
    };
    out.push(Item::Instruction(Instruction {
        path: path.to_path_buf(),
        lines: collect::line_count(&text),
        always_apply: None,
        source: art,
    }));
    true
}

/// Records every rule file under a `rules/` directory. A rule with `paths`
/// frontmatter loads only for matching files, so `always_apply` is false.
pub fn rules_dir(agent: Agent, scope: &Scope, dir: &Path, out: &mut Collector) {
    for path in collect::markdown_files(dir) {
        let art = artifact(agent, scope.clone(), ArtifactKind::Instructions, &path);
        let Some(text) = out.read_text(&art) else {
            continue;
        };
        let fm = frontmatter::parse(&text);
        let scoped = fm
            .fields
            .get("paths")
            .is_some_and(|p| p.is_array() || p.is_string());
        out.push(Item::Instruction(Instruction {
            path: path.clone(),
            lines: collect::line_count(&text),
            always_apply: Some(!scoped),
            source: art,
        }));
    }
}

/// Parses a standalone `hooks.json`.
pub fn hooks_file(agent: Agent, scope: &Scope, path: &Path, out: &mut Collector) {
    let art = artifact(agent, scope.clone(), ArtifactKind::Hooks, path);
    let Some(doc) = out.read_json(&art) else {
        return;
    };
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut observations = Vec::new();
    hooks::parse_hooks_file(&doc, &art, &mut items, &mut warnings, &mut observations);
    out.extend(items);
    out.warnings_from(warnings);
    out.observations_from(observations);
}

/// Records metadata about a credential file: existence, permission bits
/// and, for JSON, top-level key names with their value types.
///
/// Hard rule 2: the file is parsed only to list key names; no value is kept,
/// and the file is not recorded as an artifact (no hash, no size).
pub fn credential(agent: Agent, path: &Path, out: &mut Collector) {
    let art = artifact(agent, Scope::User, ArtifactKind::Credential, path);
    let exists = path.is_file();
    let (mode, readable_by_others) = match collect::permissions(path) {
        Some((mode, others)) if exists => (Some(mode), Some(others)),
        _ => (None, None),
    };
    let mut keys = Vec::new();
    if exists {
        match fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(serde_json::Value::Object(map)) => {
                    keys = map
                        .iter()
                        .map(|(name, value)| CredentialKey {
                            name: name.clone(),
                            value_type: json_type(value).to_owned(),
                        })
                        .collect();
                }
                Ok(_) => out.warn(agent, path, "credential file is not a JSON object"),
                // Deliberately without the parser message, which can quote
                // the file's text.
                Err(_) => out.warn(agent, path, "credential file is not valid JSON"),
            },
            Err(err) => out.warn(agent, path, format!("cannot read credential file: {err}")),
        }
    }
    out.push(Item::Credential(Credential {
        path: path.to_path_buf(),
        exists,
        mode,
        readable_by_others,
        keys,
        source: art,
    }));
}

fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
