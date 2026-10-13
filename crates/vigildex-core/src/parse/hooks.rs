//! Hook configuration, in the shape Claude Code introduced and Codex adopted:
//!
//! ```json
//! { "<Event>": [ { "matcher": "…", "hooks": [ { "type": "command", "command": "…" } ] } ] }
//! ```
//!
//! A `hooks.json` file wraps that event map in a top-level `hooks` key, with
//! an optional `description`; settings files and skill frontmatter carry the
//! event map under their own `hooks` key. Codex's `[hooks]` table also holds
//! a `state` map of per-hook trust records, which is not an event.

use serde_json::Value;

use crate::launch;
use crate::model::{ArtifactRef, Hook, HookHandler, Item, Warning};
use crate::parse::json::{bool_at, keys_at, str_at, string_list_at, u64_at};

/// Keys inside a hooks map that are not events.
const NOT_EVENTS: &[&str] = &["state", "description"];

/// Parses an event map, appending one [`Item::Hook`] per handler. Returns the
/// number of handlers found.
pub fn parse_event_map(
    events: &Value,
    source: &ArtifactRef,
    items: &mut Vec<Item>,
    warnings: &mut Vec<Warning>,
) -> u32 {
    let Some(events) = events.as_object() else {
        warnings.push(Warning::new(
            source.agent,
            &source.path,
            "hooks is not an object; skipped",
        ));
        return 0;
    };
    let mut count = 0;
    for (event, groups) in events {
        if NOT_EVENTS.contains(&event.as_str()) {
            continue;
        }
        let Some(groups) = groups.as_array() else {
            warnings.push(Warning::new(
                source.agent,
                &source.path,
                format!("hooks.{event} is not an array; skipped"),
            ));
            continue;
        };
        for group in groups {
            let matcher = str_at(group, "matcher").map(str::to_owned);
            // A group may hold `hooks: [...]`; a bare handler object with a
            // `type` is tolerated too, in case a hand-written file skips
            // the group level.
            let handlers: Vec<&Value> = match group.get("hooks").and_then(Value::as_array) {
                Some(list) => list.iter().collect(),
                None if group.get("type").is_some() || group.get("command").is_some() => {
                    vec![group]
                }
                None => {
                    warnings.push(Warning::new(
                        source.agent,
                        &source.path,
                        format!("hooks.{event} has a group without a hooks array; skipped"),
                    ));
                    continue;
                }
            };
            for handler in handlers {
                items.push(Item::Hook(Hook {
                    event: event.clone(),
                    matcher: matcher.clone(),
                    handler: parse_handler(handler),
                    source: source.clone(),
                }));
                count += 1;
            }
        }
    }
    count
}

/// Parses a `hooks.json` document: `{"description": …, "hooks": {events}}`.
/// A document that is already a bare event map is accepted as well.
pub fn parse_hooks_file(
    doc: &Value,
    source: &ArtifactRef,
    items: &mut Vec<Item>,
    warnings: &mut Vec<Warning>,
) -> u32 {
    match doc.get("hooks") {
        Some(events) => parse_event_map(events, source, items, warnings),
        None if doc.is_object() => parse_event_map(doc, source, items, warnings),
        None => {
            warnings.push(Warning::new(
                source.agent,
                &source.path,
                "hooks file is not an object; skipped",
            ));
            0
        }
    }
}

/// Parses one handler object.
#[must_use]
pub fn parse_handler(handler: &Value) -> HookHandler {
    let type_name = str_at(handler, "type");
    let timeout_secs = u64_at(handler, "timeout");
    match type_name {
        Some("command") | None if handler.get("command").is_some() => HookHandler::Command {
            command: str_at(handler, "command")
                .map(launch::mask_text)
                .unwrap_or_default(),
            args: launch::mask_args(&string_list_at(handler, "args")),
            timeout_secs,
            is_async: bool_at(handler, "async").unwrap_or(false),
        },
        Some("http") => HookHandler::Http {
            url: str_at(handler, "url")
                .map(launch::sanitize_url)
                .unwrap_or_default(),
            header_keys: keys_at(handler, "headers"),
            allowed_env_vars: string_list_at(handler, "allowedEnvVars"),
            timeout_secs,
        },
        Some("mcp_tool") => HookHandler::McpTool {
            server: str_at(handler, "server").unwrap_or_default().to_owned(),
            tool: str_at(handler, "tool").unwrap_or_default().to_owned(),
            timeout_secs,
        },
        Some("prompt") => HookHandler::Prompt {
            model: str_at(handler, "model").map(str::to_owned),
            timeout_secs,
        },
        Some("agent") => HookHandler::Agent {
            model: str_at(handler, "model").map(str::to_owned),
            timeout_secs,
        },
        other => HookHandler::Unknown {
            type_name: other.map(str::to_owned),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Agent, ArtifactKind, Scope};
    use serde_json::json;

    fn src() -> ArtifactRef {
        ArtifactRef {
            agent: Agent::ClaudeCode,
            scope: Scope::User,
            kind: ArtifactKind::Settings,
            path: "/x/settings.json".into(),
        }
    }

    #[test]
    fn parses_claude_settings_hooks() {
        let events = json!({
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [
                    {"type": "command", "command": "./guard.sh", "timeout": 5},
                    {"type": "http", "url": "http://localhost:8080/h?x=1", "headers": {"Authorization": "Bearer $T"}, "allowedEnvVars": ["T"]}
                ]
            }],
            "Stop": [{"hooks": [{"type": "prompt", "prompt": "secret prompt text", "model": "haiku"}]}]
        });
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let n = parse_event_map(&events, &src(), &mut items, &mut warnings);
        assert_eq!(n, 3);
        assert!(warnings.is_empty());
        let Item::Hook(first) = &items[0] else {
            panic!()
        };
        assert_eq!(first.event, "PreToolUse");
        assert_eq!(first.matcher.as_deref(), Some("Bash"));
        assert_eq!(
            first.handler,
            HookHandler::Command {
                command: "./guard.sh".into(),
                args: vec![],
                timeout_secs: Some(5),
                is_async: false,
            }
        );
        let Item::Hook(second) = &items[1] else {
            panic!()
        };
        assert_eq!(
            second.handler,
            HookHandler::Http {
                url: "http://localhost:8080/h".into(),
                header_keys: vec!["Authorization".into()],
                allowed_env_vars: vec!["T".into()],
                timeout_secs: None,
            }
        );
        let text = serde_json::to_string(&items[2]).unwrap();
        assert!(!text.contains("secret prompt text"));
    }

    #[test]
    fn hooks_file_wrapper_and_codex_state_key() {
        let doc = json!({
            "description": "Explanatory mode hook",
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": "bash \"${CLAUDE_PLUGIN_ROOT}/x.sh\"", "async": true}]}],
                "state": {"k": {"enabled": false}}
            }
        });
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        assert_eq!(parse_hooks_file(&doc, &src(), &mut items, &mut warnings), 1);
        assert!(warnings.is_empty());
        let Item::Hook(hook) = &items[0] else {
            panic!()
        };
        assert!(matches!(
            hook.handler,
            HookHandler::Command { is_async: true, .. }
        ));
    }

    #[test]
    fn malformed_groups_are_warnings_and_unknown_types_survive() {
        let events = json!({
            "PreToolUse": "not an array",
            "PostToolUse": [{"matcher": "x"}, {"hooks": [{"type": "teleport"}]}]
        });
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let n = parse_event_map(&events, &src(), &mut items, &mut warnings);
        assert_eq!(n, 1);
        assert_eq!(warnings.len(), 2);
        let Item::Hook(hook) = &items[0] else {
            panic!()
        };
        assert_eq!(
            hook.handler,
            HookHandler::Unknown {
                type_name: Some("teleport".into())
            }
        );
    }

    #[test]
    fn command_without_type_is_a_command() {
        assert!(matches!(
            parse_handler(&json!({"command": "echo hi"})),
            HookHandler::Command { .. }
        ));
        assert!(matches!(
            parse_handler(&json!({})),
            HookHandler::Unknown { type_name: None }
        ));
    }
}
