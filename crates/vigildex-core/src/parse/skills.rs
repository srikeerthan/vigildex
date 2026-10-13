//! Skills (`SKILL.md`), legacy Claude Code commands and subagents: Markdown
//! files whose frontmatter grants tools, registers hooks or defines MCP
//! servers. Only the frontmatter is read; the body is never kept.

use std::path::Path;

use serde_json::Value;

use crate::collect;
use crate::model::{ArtifactRef, Item, Skill, SkillKind, Warning};
use crate::parse::frontmatter::{self, Frontmatter};
use crate::parse::{hooks, mcp};

/// File extensions that mark a bundled script.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "py",
    "rb",
    "pl",
    "js",
    "mjs",
    "cjs",
    "ts",
    "mts",
    "php",
    "ps1",
    "bat",
    "cmd",
    "lua",
    "applescript",
    "scpt",
    "exe",
];

/// Parses a skill, command or subagent definition from its text.
///
/// `path` is the Markdown file; `dir` is the skill folder when `kind` is
/// [`SkillKind::Skill`], whose bundled scripts are listed. Hooks and inline
/// MCP servers in the frontmatter become items of their own, with the file
/// as their source. Returns the items and any warnings.
#[must_use]
pub fn parse_definition(
    kind: SkillKind,
    path: &Path,
    dir: Option<&Path>,
    text: &str,
    source: &ArtifactRef,
) -> (Vec<Item>, Vec<Warning>) {
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let fm = frontmatter::parse(text);
    if let Some(reason) = &fm.lenient {
        warnings.push(Warning::new(
            source.agent,
            path,
            format!("frontmatter did not parse ({reason}); kept top-level fields only"),
        ));
    }

    let default_name = match (kind, dir) {
        (SkillKind::Skill, Some(dir)) => file_name(dir),
        _ => path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed")
            .to_owned(),
    };
    let name = fm
        .str("name")
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map_or(default_name, str::to_owned);

    let hook_count = match fm.fields.get("hooks") {
        Some(hooks_value) if hooks_value.is_object() => {
            hooks::parse_event_map(hooks_value, source, &mut items, &mut warnings)
        }
        Some(_) => {
            warnings.push(Warning::new(
                source.agent,
                path,
                "frontmatter hooks is not a mapping; skipped",
            ));
            0
        }
        None => 0,
    };

    if kind == SkillKind::Subagent {
        inline_mcp_servers(&fm, source, &mut items, &mut warnings);
    }

    let allowed_tools = match kind {
        SkillKind::Subagent => frontmatter::tool_list(fm.fields.get("tools")),
        _ => frontmatter::tool_list(fm.fields.get("allowed-tools")),
    };

    let skill = Skill {
        name,
        kind,
        path: match (kind, dir) {
            (SkillKind::Skill, Some(dir)) => dir.to_path_buf(),
            _ => path.to_path_buf(),
        },
        description: fm.str("description").map(frontmatter::short_description),
        allowed_tools,
        scripts: dir.map(scripts_in).unwrap_or_default(),
        hook_count,
        model_invocable: fm
            .bool("disable-model-invocation")
            .map(|disabled| !disabled),
        user_invocable: fm.bool("user-invocable"),
        permission_mode: match kind {
            SkillKind::Subagent => fm.str("permissionMode").map(str::to_owned),
            _ => None,
        },
        source: source.clone(),
    };
    items.insert(0, Item::Skill(skill));
    (items, warnings)
}

/// A subagent's `mcpServers` list: names (references, skipped) or inline
/// `{ name: {config} }` definitions.
fn inline_mcp_servers(
    fm: &Frontmatter,
    source: &ArtifactRef,
    items: &mut Vec<Item>,
    warnings: &mut Vec<Warning>,
) {
    let Some(list) = fm.fields.get("mcpServers") else {
        return;
    };
    match list {
        Value::Array(entries) => {
            for entry in entries {
                if let Some(map) = entry.as_object() {
                    mcp::parse_server_map(map, source, items, warnings);
                }
            }
        }
        Value::Object(map) => mcp::parse_server_map(map, source, items, warnings),
        _ => warnings.push(Warning::new(
            source.agent,
            &source.path,
            "frontmatter mcpServers is neither a list nor a mapping; skipped",
        )),
    }
}

/// Script-like files in a skill folder, relative to it, sorted.
#[must_use]
pub fn scripts_in(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect::collect_files(dir, 0, &mut files, is_script);
    let mut out: Vec<String> = files
        .iter()
        .filter_map(|p| p.strip_prefix(dir).ok())
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();
    out.sort();
    out
}

fn is_script(path: &Path) -> bool {
    if path.file_name().and_then(|n| n.to_str()) == Some("SKILL.md") {
        return false;
    }
    let by_extension = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SCRIPT_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()));
    by_extension || is_executable(path)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    false
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Agent, ArtifactKind, HookHandler, Scope};

    fn src(path: &str) -> ArtifactRef {
        ArtifactRef {
            agent: Agent::ClaudeCode,
            scope: Scope::User,
            kind: ArtifactKind::Skill,
            path: path.into(),
        }
    }

    #[test]
    fn skill_frontmatter_yields_a_skill_and_its_hooks() {
        let text = "---\nname: secure-ops\ndescription: Run with checks\nallowed-tools: Bash(git *) Read\ndisable-model-invocation: true\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: ./scripts/check.sh\n---\n\nBody text that must not be stored.\n";
        let dir = Path::new("/home/you/.claude/skills/secure-ops");
        let (items, warnings) = parse_definition(
            SkillKind::Skill,
            &dir.join("SKILL.md"),
            Some(dir),
            text,
            &src("/home/you/.claude/skills/secure-ops/SKILL.md"),
        );
        assert!(warnings.is_empty());
        assert_eq!(items.len(), 2);
        let Item::Skill(skill) = &items[0] else {
            panic!()
        };
        assert_eq!(skill.name, "secure-ops");
        assert_eq!(skill.allowed_tools, vec!["Bash(git *)", "Read"]);
        assert_eq!(skill.hook_count, 1);
        assert_eq!(skill.model_invocable, Some(false));
        assert_eq!(skill.path, dir);
        let Item::Hook(hook) = &items[1] else {
            panic!()
        };
        assert!(matches!(hook.handler, HookHandler::Command { .. }));
        assert!(!serde_json::to_string(&items).unwrap().contains("Body text"));
    }

    #[test]
    fn name_falls_back_to_the_folder_or_file_name() {
        let (items, _) = parse_definition(
            SkillKind::Skill,
            Path::new("/s/release-notes/SKILL.md"),
            Some(Path::new("/s/release-notes")),
            "No frontmatter here.\n",
            &src("/s/release-notes/SKILL.md"),
        );
        let Item::Skill(skill) = &items[0] else {
            panic!()
        };
        assert_eq!(skill.name, "release-notes");
        assert!(skill.description.is_none());

        let (items, _) = parse_definition(
            SkillKind::Command,
            Path::new("/c/fix-issue.md"),
            None,
            "---\ndescription: Fix\n---\n",
            &src("/c/fix-issue.md"),
        );
        let Item::Skill(skill) = &items[0] else {
            panic!()
        };
        assert_eq!(skill.name, "fix-issue");
        assert_eq!(skill.kind, SkillKind::Command);
    }

    #[test]
    fn subagents_report_tools_permission_mode_and_inline_servers() {
        let text = "---\nname: browser-tester\ndescription: Tests in a browser\ntools: Read, Grep\npermissionMode: acceptEdits\nmcpServers:\n  - playwright:\n      type: stdio\n      command: npx\n      args: [\"-y\", \"@playwright/mcp@latest\"]\n  - github\n---\n";
        let (items, warnings) = parse_definition(
            SkillKind::Subagent,
            Path::new("/a/browser-tester.md"),
            None,
            text,
            &src("/a/browser-tester.md"),
        );
        assert!(warnings.is_empty());
        let Item::Skill(skill) = &items[0] else {
            panic!()
        };
        assert_eq!(skill.allowed_tools, vec!["Read", "Grep"]);
        assert_eq!(skill.permission_mode.as_deref(), Some("acceptEdits"));
        let Item::McpServer(server) = &items[1] else {
            panic!()
        };
        assert_eq!(server.name, "playwright");
    }

    #[test]
    fn broken_frontmatter_is_a_warning_not_a_failure() {
        let (items, warnings) = parse_definition(
            SkillKind::Skill,
            Path::new("/s/odd/SKILL.md"),
            Some(Path::new("/s/odd")),
            "---\nname: odd\nhooks: [\n---\n",
            &src("/s/odd/SKILL.md"),
        );
        assert_eq!(items.len(), 1);
        assert_eq!(warnings.len(), 1);
        let Item::Skill(skill) = &items[0] else {
            panic!()
        };
        assert_eq!(skill.name, "odd");
    }
}
