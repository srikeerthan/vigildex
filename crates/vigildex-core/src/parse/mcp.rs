//! MCP server definitions, in Claude Code's JSON shape and Codex's TOML
//! shape (after conversion to the same `Value` form).
//!
//! | Field | Claude Code | Codex |
//! |---|---|---|
//! | launch | `command`, `args`, `env` | `command`, `args`, `env`, `env_vars`, `cwd` |
//! | remote | `type`, `url`, `headers`, `headersHelper`, `oauth` | `url`, `bearer_token_env_var`, `http_headers`, `env_http_headers`, `http_headers_helper` |
//! | switch | | `enabled` |
//!
//! Values of `env` and headers are never recorded, only their names.

use serde_json::Value;

use crate::launch;
use crate::model::{ArtifactRef, Item, Launch, McpServer, RemoteAuth, Transport, Warning};
use crate::parse::json::{bool_at, keys_at, str_at, string_list_at};

/// Parses one server definition.
#[must_use]
pub fn parse_server(name: &str, cfg: &Value, source: &ArtifactRef) -> McpServer {
    let launch = if let Some(command) = str_at(cfg, "command") {
        launch::classify(command, &string_list_at(cfg, "args"))
    } else if let Some(url) = str_at(cfg, "url") {
        Launch::Remote {
            url: launch::sanitize_url(url),
            transport: transport_of(str_at(cfg, "type")),
            auth: auth_of(cfg),
        }
    } else {
        Launch::Unknown
    };

    let mut header_keys = keys_at(cfg, "headers");
    header_keys.extend(keys_at(cfg, "http_headers"));
    header_keys.sort();
    header_keys.dedup();

    let mut env_keys = keys_at(cfg, "env");
    // Codex `env_vars` forwards variables from the parent environment by name.
    env_keys.extend(string_list_at(cfg, "env_vars"));
    env_keys.sort();
    env_keys.dedup();

    McpServer {
        name: name.to_owned(),
        launch,
        env_keys,
        header_keys,
        env_header_keys: keys_at(cfg, "env_http_headers"),
        enabled: bool_at(cfg, "enabled"),
        source: source.clone(),
    }
}

fn transport_of(type_name: Option<&str>) -> Transport {
    match type_name {
        // Codex names no type: a URL means streamable HTTP.
        None | Some("http" | "streamable-http" | "streamable_http") => Transport::Http,
        Some("sse") => Transport::Sse,
        Some("ws" | "websocket") => Transport::Ws,
        Some(_) => Transport::Unknown,
    }
}

fn auth_of(cfg: &Value) -> RemoteAuth {
    if let Some(command) =
        str_at(cfg, "headersHelper").or_else(|| str_at(cfg, "http_headers_helper"))
    {
        return RemoteAuth::HeadersHelper {
            command: launch::mask_text(command),
        };
    }
    if let Some(var) = str_at(cfg, "bearer_token_env_var") {
        return RemoteAuth::BearerEnvVar {
            var: var.to_owned(),
        };
    }
    if cfg.get("oauth").is_some_and(Value::is_object) {
        return RemoteAuth::Oauth;
    }
    let has_headers = cfg
        .get("headers")
        .or_else(|| cfg.get("http_headers"))
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty());
    if has_headers {
        return RemoteAuth::StaticHeaders;
    }
    RemoteAuth::None
}

/// Finds the server map in a document that is either `{"mcpServers": {…}}`
/// or, as some Claude Code plugins write it, the bare map of servers.
///
/// The bare form is accepted only when every value is an object, so a
/// settings file with other keys is never mistaken for a server map.
#[must_use]
pub fn server_map(doc: &Value) -> Option<&serde_json::Map<String, Value>> {
    if let Some(map) = doc.get("mcpServers").and_then(Value::as_object) {
        return Some(map);
    }
    let map = doc.as_object()?;
    if !map.is_empty() && map.values().all(Value::is_object) {
        Some(map)
    } else {
        None
    }
}

/// Parses every server in a map, appending items and warnings.
pub fn parse_server_map(
    map: &serde_json::Map<String, Value>,
    source: &ArtifactRef,
    items: &mut Vec<Item>,
    warnings: &mut Vec<Warning>,
) {
    for (name, cfg) in map {
        if cfg.is_object() {
            items.push(Item::McpServer(parse_server(name, cfg, source)));
        } else {
            warnings.push(Warning::new(
                source.agent,
                &source.path,
                format!("MCP server \"{name}\" is not an object; skipped"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Agent, ArtifactKind, Pin, Runner, Scope};
    use serde_json::json;

    fn src() -> ArtifactRef {
        ArtifactRef {
            agent: Agent::ClaudeCode,
            scope: Scope::User,
            kind: ArtifactKind::McpConfig,
            path: "/x/.mcp.json".into(),
        }
    }

    #[test]
    fn stdio_server_records_env_key_names_only() {
        let cfg = json!({
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@acme/lint-helper@latest"],
            "env": {"LINT_HELPER_TOKEN": "lh_FAKEFAKEFAKEFAKE", "LOG": "1"}
        });
        let server = parse_server("lint-helper", &cfg, &src());
        assert_eq!(server.env_keys, vec!["LINT_HELPER_TOKEN", "LOG"]);
        match server.launch {
            Launch::Package { runner, pin, .. } => {
                assert_eq!(runner, Runner::Npx);
                assert_eq!(pin, Pin::Floating);
            }
            other => panic!("{other:?}"),
        }
        let text = serde_json::to_string(&server).unwrap();
        assert!(
            !text.contains("lh_FAKE"),
            "env values must never appear: {text}"
        );
    }

    #[test]
    fn remote_server_strips_query_and_records_header_names() {
        let cfg = json!({
            "type": "http",
            "url": "https://mcp.example.com/mcp?key=FAKE",
            "headers": {"Authorization": "Bearer ${TOKEN}"}
        });
        let server = parse_server("remote", &cfg, &src());
        assert_eq!(
            server.launch,
            Launch::Remote {
                url: "https://mcp.example.com/mcp".into(),
                transport: Transport::Http,
                auth: RemoteAuth::StaticHeaders,
            }
        );
        assert_eq!(server.header_keys, vec!["Authorization"]);
    }

    #[test]
    fn codex_shape_uses_bearer_env_var_and_enabled() {
        let cfg = json!({
            "url": "https://api.githubcopilot.com/mcp/",
            "bearer_token_env_var": "GITHUB_TOKEN",
            "env_http_headers": {"X-Org": "ORG_VAR"},
            "enabled": false
        });
        let server = parse_server("github", &cfg, &src());
        assert_eq!(server.enabled, Some(false));
        assert_eq!(server.env_header_keys, vec!["X-Org"]);
        match server.launch {
            Launch::Remote {
                auth, transport, ..
            } => {
                assert_eq!(transport, Transport::Http);
                assert_eq!(
                    auth,
                    RemoteAuth::BearerEnvVar {
                        var: "GITHUB_TOKEN".into()
                    }
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn neither_command_nor_url_is_unknown_not_an_error() {
        let server = parse_server("odd", &json!({"type": "sdk"}), &src());
        assert_eq!(server.launch, Launch::Unknown);
    }

    #[test]
    fn server_map_accepts_both_plugin_shapes() {
        let wrapped = json!({"mcpServers": {"a": {"url": "https://a"}}});
        let bare = json!({"a": {"url": "https://a"}, "b": {"command": "x"}});
        let settings = json!({"model": "x", "a": {"url": "https://a"}});
        assert_eq!(server_map(&wrapped).unwrap().len(), 1);
        assert_eq!(server_map(&bare).unwrap().len(), 2);
        assert!(server_map(&settings).is_none());
        assert!(server_map(&json!({})).is_none());
    }

    #[test]
    fn non_object_entries_are_warnings() {
        let map = json!({"good": {"command": "x"}, "bad": "oops"});
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        parse_server_map(map.as_object().unwrap(), &src(), &mut items, &mut warnings);
        assert_eq!(items.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("\"bad\""));
    }
}
