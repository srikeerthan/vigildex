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
//!
//! Command text, HTTP URLs and header values go through [`observe`] for the
//! secret rules; the items keep masked commands and sanitised URLs.

use serde_json::Value;

use crate::launch;
use crate::model::{ArtifactRef, Hook, HookHandler, Item, Warning};
use crate::observe::{observe, Field, Locator, Observation};
use crate::parse::json::{bool_at, keys_at, str_at, string_list_at, u64_at};
use crate::parse::Context;

/// Keys inside a hooks map that are not events.
const NOT_EVENTS: &[&str] = &["state", "description"];

/// Parses an event map at `ctx` (the key path of the map, usually `hooks`),
/// appending one [`Item::Hook`] per handler. Returns the number of
/// handlers found.
pub fn parse_event_map(
    events: &Value,
    ctx: &Context<'_>,
    items: &mut Vec<Item>,
    warnings: &mut Vec<Warning>,
    observations: &mut Vec<Observation>,
) -> u32 {
    let Some(events) = events.as_object() else {
        warnings.push(Warning::new(
            ctx.source.agent,
            &ctx.source.path,
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
                ctx.source.agent,
                &ctx.source.path,
                format!("hooks.{event} is not an array; skipped"),
            ));
            continue;
        };
        for (group_index, group) in groups.iter().enumerate() {
            let matcher = str_at(group, "matcher").map(str::to_owned);
            // A group may hold `hooks: [...]`; a bare handler object with a
            // `type` is tolerated too, in case a hand-written file skips
            // the group level.
            let group_index = group_index.to_string();
            let list = group.get("hooks").and_then(Value::as_array);
            let indices: Vec<String> = (0..list.map_or(0, Vec::len))
                .map(|i| i.to_string())
                .collect();
            let handlers: Vec<(Vec<&str>, &Value)> = match list {
                Some(list) => list
                    .iter()
                    .zip(&indices)
                    .map(|(h, i)| (vec![event.as_str(), &group_index, "hooks", i.as_str()], h))
                    .collect(),
                None if group.get("type").is_some() || group.get("command").is_some() => {
                    vec![(vec![event.as_str(), &group_index], group)]
                }
                None => {
                    warnings.push(Warning::new(
                        ctx.source.agent,
                        &ctx.source.path,
                        format!("hooks.{event} has a group without a hooks array; skipped"),
                    ));
                    continue;
                }
            };
            for (segments, handler) in handlers {
                let locator = Locator::Hook {
                    event: event.clone(),
                    matcher: matcher.clone(),
                };
                observe_handler(handler, &segments, ctx, &locator, observations);
                items.push(Item::Hook(Hook {
                    event: event.clone(),
                    matcher: matcher.clone(),
                    handler: parse_handler(handler),
                    key_path: ctx.key_path(&segments),
                    line: ctx.line(&segments),
                    source: ctx.source.clone(),
                }));
                count += 1;
            }
        }
    }
    count
}

/// Observes the values of one handler that could carry a credential.
fn observe_handler(
    handler: &Value,
    segments: &[&str],
    ctx: &Context<'_>,
    locator: &Locator,
    observations: &mut Vec<Observation>,
) {
    let mut record = |extra: &[&str], field: Field, name: Option<&str>, value: &str| {
        let mut all: Vec<&str> = segments.to_vec();
        all.extend_from_slice(extra);
        observations.push(observe(
            ctx.source,
            ctx.location(&all),
            field,
            name,
            locator.clone(),
            value,
        ));
    };
    if let Some(command) = str_at(handler, "command") {
        record(&["command"], Field::HookCommand, None, command);
    }
    if let Some(url) = str_at(handler, "url") {
        record(&["url"], Field::HookUrl, None, url);
    }
    if let Some(headers) = handler.get("headers").and_then(Value::as_object) {
        for (name, value) in headers {
            if let Some(text) = value.as_str() {
                record(&["headers", name], Field::HookHeader, Some(name), text);
            }
        }
    }
}

/// Parses a `hooks.json` document: `{"description": …, "hooks": {events}}`.
/// A document that is already a bare event map is accepted as well.
pub fn parse_hooks_file(
    doc: &Value,
    source: &ArtifactRef,
    items: &mut Vec<Item>,
    warnings: &mut Vec<Warning>,
    observations: &mut Vec<Observation>,
) -> u32 {
    let ctx = Context {
        source,
        key_prefix: "hooks",
        segments: &["hooks"],
        line_of: &crate::parse::no_lines,
    };
    match doc.get("hooks") {
        Some(events) => parse_event_map(events, &ctx, items, warnings, observations),
        None if doc.is_object() => {
            let root = Context::root(source);
            parse_event_map(doc, &root, items, warnings, observations)
        }
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
    use crate::parse::no_lines;
    use serde_json::json;

    fn src() -> ArtifactRef {
        ArtifactRef {
            agent: Agent::ClaudeCode,
            scope: Scope::User,
            kind: ArtifactKind::Settings,
            path: "/x/settings.json".into(),
        }
    }

    fn ctx(source: &ArtifactRef) -> Context<'_> {
        Context {
            source,
            key_prefix: "hooks",
            segments: &["hooks"],
            line_of: &no_lines,
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
        let source = src();
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut observations = Vec::new();
        let n = parse_event_map(
            &events,
            &ctx(&source),
            &mut items,
            &mut warnings,
            &mut observations,
        );
        assert_eq!(n, 3);
        assert!(warnings.is_empty());
        let Item::Hook(first) = &items[0] else {
            panic!()
        };
        assert_eq!(first.event, "PreToolUse");
        assert_eq!(first.matcher.as_deref(), Some("Bash"));
        assert_eq!(first.key_path, "hooks.PreToolUse[0].hooks[0]");
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
        assert_eq!(second.key_path, "hooks.PreToolUse[0].hooks[1]");
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
        // command, url, header: observed, none a secret.
        assert_eq!(observations.len(), 3);
        assert!(observations.iter().all(|o| o.secret.is_none()));
        assert_eq!(
            observations[2].location.key_path.as_deref(),
            Some("hooks.PreToolUse[0].hooks[1].headers.Authorization")
        );
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
        let source = src();
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        assert_eq!(
            parse_hooks_file(&doc, &source, &mut items, &mut warnings, &mut Vec::new()),
            1
        );
        assert!(warnings.is_empty());
        let Item::Hook(hook) = &items[0] else {
            panic!()
        };
        assert!(matches!(
            hook.handler,
            HookHandler::Command { is_async: true, .. }
        ));
        assert_eq!(hook.key_path, "hooks.SessionStart[0].hooks[0]");
    }

    #[test]
    fn malformed_groups_are_warnings_and_unknown_types_survive() {
        let events = json!({
            "PreToolUse": "not an array",
            "PostToolUse": [{"matcher": "x"}, {"hooks": [{"type": "teleport"}]}]
        });
        let source = src();
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let n = parse_event_map(
            &events,
            &ctx(&source),
            &mut items,
            &mut warnings,
            &mut Vec::new(),
        );
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

    #[test]
    fn secrets_in_hook_commands_and_headers_are_observed_masked() {
        let events = json!({
            "Notification": [{"hooks": [
                {"type": "http", "url": "https://h.example/x?token=FAKEQUERYTOKEN", "headers": {"Authorization": "Bearer ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a"}},
                {"type": "command", "command": "API_TOKEN=acme_FAKEFAKEFAKEFAKEFAKE ./notify.sh"}
            ]}]
        });
        let source = src();
        let mut items = Vec::new();
        let mut observations = Vec::new();
        parse_event_map(
            &events,
            &ctx(&source),
            &mut items,
            &mut Vec::new(),
            &mut observations,
        );
        let hits: Vec<(Field, &str)> = observations
            .iter()
            .filter_map(|o| o.secret.as_ref().map(|s| (o.field, s.masked.as_str())))
            .collect();
        assert_eq!(
            hits,
            vec![
                (Field::HookUrl, "?token=••••KEN"),
                (Field::HookHeader, "ghp_••••f9a"),
                (Field::HookCommand, "••••AKE"),
            ]
        );
        let text = serde_json::to_string(&items).unwrap();
        assert!(!text.contains("FAKE"), "{text}");
    }
}
