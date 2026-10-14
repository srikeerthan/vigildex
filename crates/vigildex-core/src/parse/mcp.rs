//! MCP server definitions, in Claude Code's JSON shape and Codex's TOML
//! shape (after conversion to the same `Value` form).
//!
//! | Field | Claude Code | Codex |
//! |---|---|---|
//! | launch | `command`, `args`, `env` | `command`, `args`, `env`, `env_vars`, `cwd` |
//! | remote | `type`, `url`, `headers`, `headersHelper`, `oauth` | `url`, `bearer_token_env_var`, `http_headers`, `env_http_headers`, `http_headers_helper` |
//! | switch | | `enabled` |
//!
//! Values of `env` and headers are never recorded, only their names. Every
//! value that could hold a credential (`env`, headers, `args`, `url`,
//! `command`) is passed through [`observe`], which keeps a masked,
//! fingerprinted hit for the findings and drops the text.

use serde_json::Value;

use crate::launch;
use crate::model::{Item, Launch, McpServer, RemoteAuth, Transport, Warning};
use crate::observe::{observe, Field, Locator, Observation};
use crate::parse::json::{bool_at, keys_at, str_at, string_list_at};
use crate::parse::Context;

/// Parses one server definition at `ctx` (the key path of the server map).
#[must_use]
pub fn parse_server(
    name: &str,
    cfg: &Value,
    ctx: &Context<'_>,
    observations: &mut Vec<Observation>,
) -> McpServer {
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

    observe_values(name, cfg, ctx, observations);

    McpServer {
        name: name.to_owned(),
        launch,
        env_keys,
        header_keys,
        env_header_keys: keys_at(cfg, "env_http_headers"),
        enabled: bool_at(cfg, "enabled"),
        key_path: ctx.key_path(&[name]),
        line: ctx.line(&[name]),
        source: ctx.source.clone(),
    }
}

/// Runs the secret rules over every value a server definition can carry.
fn observe_values(name: &str, cfg: &Value, ctx: &Context<'_>, observations: &mut Vec<Observation>) {
    let locator = Locator::McpServer {
        key_path: ctx.key_path(&[name]),
    };
    let record = |segments: &[&str], field: Field, var: Option<&str>, value: &str| {
        observe(
            ctx.source,
            ctx.location(segments),
            field,
            var,
            locator.clone(),
            value,
        )
    };
    for (key, field) in [
        ("env", Field::McpEnv),
        ("headers", Field::McpHeader),
        ("http_headers", Field::McpHeader),
    ] {
        if let Some(map) = cfg.get(key).and_then(Value::as_object) {
            for (var, value) in map {
                if let Some(text) = value.as_str() {
                    observations.push(record(&[name, key, var], field, Some(var), text));
                }
            }
        }
    }
    if let Some(args) = cfg.get("args").and_then(Value::as_array) {
        let before = observations.len();
        for (index, arg) in args.iter().enumerate() {
            if let Some(text) = arg.as_str() {
                let index = index.to_string();
                observations.push(record(&[name, "args", &index], Field::McpArg, None, text));
            }
        }
        // `--api-key X`, `--token=…` and an inline `sh -c "TOKEN=… npx …"`
        // body only show up when the arguments are read as one command
        // line; one more observation covers them when no single argument
        // was a hit of its own.
        let per_arg_hit = observations[before..].iter().any(|o| o.secret.is_some());
        let joined: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
        if !per_arg_hit && !joined.is_empty() {
            let joined = joined.join(" ");
            let obs = record(&[name, "args"], Field::McpCommand, None, &joined);
            if obs.secret.is_some() {
                observations.push(obs);
            }
        }
    }
    if let Some(url) = str_at(cfg, "url") {
        observations.push(record(&[name, "url"], Field::McpUrl, None, url));
    }
    if let Some(command) = str_at(cfg, "command") {
        observations.push(record(&[name, "command"], Field::McpCommand, None, command));
    }
    for key in ["headersHelper", "http_headers_helper"] {
        if let Some(command) = str_at(cfg, key) {
            observations.push(record(&[name, key], Field::McpCommand, None, command));
        }
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
/// Returns the map and the key segment it sits under (`None` for the bare
/// form).
#[must_use]
pub fn server_map(doc: &Value) -> Option<(&serde_json::Map<String, Value>, Option<&'static str>)> {
    if let Some(map) = doc.get("mcpServers").and_then(Value::as_object) {
        return Some((map, Some("mcpServers")));
    }
    let map = doc.as_object()?;
    if !map.is_empty() && map.values().all(Value::is_object) {
        Some((map, None))
    } else {
        None
    }
}

/// Parses every server in a map at `ctx`, appending items, warnings and
/// observations.
pub fn parse_server_map(
    map: &serde_json::Map<String, Value>,
    ctx: &Context<'_>,
    items: &mut Vec<Item>,
    warnings: &mut Vec<Warning>,
    observations: &mut Vec<Observation>,
) {
    for (name, cfg) in map {
        if cfg.is_object() {
            items.push(Item::McpServer(parse_server(name, cfg, ctx, observations)));
        } else {
            warnings.push(Warning::new(
                ctx.source.agent,
                &ctx.source.path,
                format!("MCP server \"{name}\" is not an object; skipped"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Agent, ArtifactKind, ArtifactRef, Pin, Runner, Scope};
    use crate::parse::no_lines;
    use serde_json::json;

    fn src() -> ArtifactRef {
        ArtifactRef {
            agent: Agent::ClaudeCode,
            scope: Scope::User,
            kind: ArtifactKind::McpConfig,
            path: "/x/.mcp.json".into(),
        }
    }

    fn ctx(source: &ArtifactRef) -> Context<'_> {
        Context {
            source,
            key_prefix: "mcpServers",
            segments: &["mcpServers"],
            line_of: &no_lines,
        }
    }

    #[test]
    fn stdio_server_records_env_key_names_only_and_observes_the_values() {
        let cfg = json!({
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@acme/lint-helper@latest"],
            "env": {"LINT_HELPER_TOKEN": "lh_FAKEFAKEFAKEFAKEFAKEFAKEFAKE", "LOG": "1"}
        });
        let source = src();
        let mut observations = Vec::new();
        let server = parse_server("lint-helper", &cfg, &ctx(&source), &mut observations);
        assert_eq!(server.env_keys, vec!["LINT_HELPER_TOKEN", "LOG"]);
        assert_eq!(server.key_path, "mcpServers.lint-helper");
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
        // env ×2, args ×2, command: the token is the only hit.
        assert_eq!(observations.len(), 5);
        assert_eq!(
            observations[0].locator,
            Locator::McpServer {
                key_path: "mcpServers.lint-helper".into()
            }
        );
        let hits: Vec<&Observation> = observations.iter().filter(|o| o.secret.is_some()).collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].field, Field::McpEnv);
        assert_eq!(hits[0].name.as_deref(), Some("LINT_HELPER_TOKEN"));
        assert_eq!(
            hits[0].location.key_path.as_deref(),
            Some("mcpServers.lint-helper.env.LINT_HELPER_TOKEN")
        );
        assert!(!format!("{observations:?}").contains("lh_FAKE"));
    }

    #[test]
    fn remote_server_strips_query_and_records_header_names() {
        let cfg = json!({
            "type": "http",
            "url": "https://mcp.example.com/mcp?key=FAKE",
            "headers": {"Authorization": "Bearer ${TOKEN}"}
        });
        let source = src();
        let mut observations = Vec::new();
        let server = parse_server("remote", &cfg, &ctx(&source), &mut observations);
        assert_eq!(
            server.launch,
            Launch::Remote {
                url: "https://mcp.example.com/mcp".into(),
                transport: Transport::Http,
                auth: RemoteAuth::StaticHeaders,
            }
        );
        assert_eq!(server.header_keys, vec!["Authorization"]);
        assert!(observations.iter().all(|o| o.secret.is_none()));
    }

    #[test]
    fn codex_shape_uses_bearer_env_var_and_enabled() {
        let cfg = json!({
            "url": "https://api.githubcopilot.com/mcp/",
            "bearer_token_env_var": "GITHUB_TOKEN",
            "env_http_headers": {"X-Org": "ORG_VAR"},
            "enabled": false
        });
        let source = src();
        let server = parse_server("github", &cfg, &ctx(&source), &mut Vec::new());
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
        let source = src();
        let server = parse_server(
            "odd",
            &json!({"type": "sdk"}),
            &ctx(&source),
            &mut Vec::new(),
        );
        assert_eq!(server.launch, Launch::Unknown);
    }

    #[test]
    fn server_map_accepts_both_plugin_shapes() {
        let wrapped = json!({"mcpServers": {"a": {"url": "https://a"}}});
        let bare = json!({"a": {"url": "https://a"}, "b": {"command": "x"}});
        let settings = json!({"model": "x", "a": {"url": "https://a"}});
        assert_eq!(server_map(&wrapped).unwrap().0.len(), 1);
        assert_eq!(server_map(&wrapped).unwrap().1, Some("mcpServers"));
        assert_eq!(server_map(&bare).unwrap().0.len(), 2);
        assert_eq!(server_map(&bare).unwrap().1, None);
        assert!(server_map(&settings).is_none());
        assert!(server_map(&json!({})).is_none());
    }

    #[test]
    fn credential_flags_and_inline_bodies_in_args_are_found() {
        let source = src();
        let cfg = json!({"command": "server", "args": ["--api-key", "adk_FAKEFAKEFAKEFAKEFAKEFAKEFAKE", "--port", "1"]});
        let mut observations = Vec::new();
        let server = parse_server("flag", &cfg, &ctx(&source), &mut observations);
        let hits: Vec<&Observation> = observations.iter().filter(|o| o.secret.is_some()).collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].location.key_path.as_deref(),
            Some("mcpServers.flag.args")
        );
        assert_eq!(hits[0].secret.as_ref().unwrap().kind, "API key");
        let text = serde_json::to_string(&server).unwrap();
        assert!(!text.contains("adk_FAKE"), "{text}");

        let cfg =
            json!({"command": "sh", "args": ["-c", "API_TOKEN=acme_FAKEFAKEFAKEFAKEFAKE npx x"]});
        let mut observations = Vec::new();
        let server = parse_server("inline", &cfg, &ctx(&source), &mut observations);
        assert!(observations.iter().any(|o| o.secret.is_some()));
        let text = serde_json::to_string(&server).unwrap();
        assert!(!text.contains("acme_FAKE"), "{text}");
    }

    #[test]
    fn identity_ignores_the_masked_password() {
        let source = src();
        let server = |pw: &str| {
            let cfg = json!({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2", format!("postgresql://app:{pw}@db.acme.internal:5432/acme")]});
            Item::McpServer(parse_server(
                "postgres",
                &cfg,
                &ctx(&source),
                &mut Vec::new(),
            ))
        };
        let rel = |p: &std::path::Path| p.display().to_string();
        let a = server("FAKEPASSWORDFAKE").identity_text(&rel);
        let b = server("OTHERPASSWORDFAKE").identity_text(&rel);
        assert_eq!(a, b);
        assert!(!a.contains("FAKE"), "{a}");
    }

    #[test]
    fn non_object_entries_are_warnings() {
        let map = json!({"good": {"command": "x"}, "bad": "oops"});
        let source = src();
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        parse_server_map(
            map.as_object().unwrap(),
            &ctx(&source),
            &mut items,
            &mut warnings,
            &mut Vec::new(),
        );
        assert_eq!(items.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("\"bad\""));
    }
}
