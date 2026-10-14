//! Observations: what the analyzers learn about values the inventory never
//! records.
//!
//! An adapter that reads an environment value, a header, an argument, a URL,
//! a command or a profile export calls [`observe`] with the raw text. The
//! function classifies the value, runs the secret rules on a literal, and
//! returns an [`Observation`] that keeps the field's name, class, host (for
//! URL-shaped values) and the masked, fingerprinted [`SecretHit`], never the
//! value itself. The raw text ends with the call (hard rule 5).
//!
//! `Observation` deliberately has no `serde` derive: it is scan-internal and
//! never part of a report.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::ArtifactRef;
use crate::secrets::{self, SecretHit, ValueClass};

/// Where something sits in a file.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
pub struct Location {
    /// Absolute path of the file.
    pub path: PathBuf,
    /// 1-based line number, when the format gives one (shell profiles,
    /// `.env`, TOML).
    pub line: Option<u32>,
    /// The key path inside the file, when the format has keys
    /// (`mcpServers.github.env.GITHUB_TOKEN`).
    pub key_path: Option<String>,
}

impl Location {
    /// A location with neither line nor key.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            line: None,
            key_path: None,
        }
    }

    /// A location at a key path.
    #[must_use]
    pub fn key(path: impl Into<PathBuf>, key_path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line: None,
            key_path: Some(key_path.into()),
        }
    }

    /// A location on a line.
    #[must_use]
    pub fn line(path: impl Into<PathBuf>, line: u32) -> Self {
        Self {
            path: path.into(),
            line: Some(line),
            key_path: None,
        }
    }

    /// The same location with a line number.
    #[must_use]
    pub fn at_line(mut self, line: Option<u32>) -> Self {
        self.line = line;
        self
    }
}

/// What kind of field a value came from. Decides which secret rule family
/// (SEC-001…005) a hit belongs to and which billing rules read the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Field {
    /// An MCP server's `env` value.
    McpEnv,
    /// An MCP server's `headers` / `http_headers` value.
    McpHeader,
    /// One MCP server argument.
    McpArg,
    /// An MCP server URL.
    McpUrl,
    /// An MCP server command string.
    McpCommand,
    /// A value in a settings `env` block (Claude Code `env`, Codex
    /// `shell_environment_policy.set`).
    SettingEnv,
    /// A command a settings file runs (`apiKeyHelper`, `awsAuthRefresh`,
    /// `otelHeadersHelper`, `statusLine.command`, Codex `notify`).
    SettingCommand,
    /// A hook's HTTP header value.
    HookHeader,
    /// A hook's command text.
    HookCommand,
    /// A hook's HTTP URL.
    HookUrl,
    /// An assignment in a shell profile or `.envrc`.
    ShellExport,
    /// An assignment in a `.env` file.
    DotenvVar,
}

/// Which inventory item a value belongs to, so a finding can cite it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locator {
    /// An MCP server by name, in the same source file.
    McpServer {
        /// The server name.
        name: String,
    },
    /// A hook by event and matcher, in the same source file.
    Hook {
        /// The event name.
        event: String,
        /// The matcher, when the group has one.
        matcher: Option<String>,
    },
    /// A setting by key path, in the same source file.
    Setting {
        /// The key path.
        key_path: String,
    },
    /// No particular item.
    None,
}

/// What the engine kept about one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The file and agent the value was read for.
    pub source: ArtifactRef,
    /// Where in the file.
    pub location: Location,
    /// What kind of field.
    pub field: Field,
    /// The variable, header or key name, when the field has one.
    pub name: Option<String>,
    /// Whether the value was literal text, a reference, dynamic or empty.
    pub class: ValueClass,
    /// Whether the value switches something on: a literal other than `0`,
    /// `false`, `no` or `off`, or any reference or dynamic value.
    pub truthy: bool,
    /// For a literal that is a URL: its origin, `scheme://host[:port]`.
    pub host: Option<String>,
    /// The secret rule that matched a literal, if any.
    pub secret: Option<SecretHit>,
    /// The item the value belongs to.
    pub locator: Locator,
}

/// Records what matters about `value` and drops the rest.
#[must_use]
pub fn observe(
    source: &ArtifactRef,
    location: Location,
    field: Field,
    name: Option<&str>,
    locator: Locator,
    value: &str,
) -> Observation {
    let class = secrets::classify(value);
    let host = if class == ValueClass::Literal {
        crate::hosts::origin_of(value.trim())
    } else {
        None
    };
    // References and substitutions are scanned too: the default of
    // `${VAR:-…}` and the body of `$(…)` can carry a literal.
    let secret = match (class, field) {
        (ValueClass::Empty, _) => None,
        (_, Field::McpCommand | Field::HookCommand | Field::SettingCommand) => {
            secrets::scan_text(value)
        }
        _ => secrets::scan_value(name, value),
    };
    let truthy = match class {
        ValueClass::Literal => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        ValueClass::Reference | ValueClass::Dynamic => true,
        ValueClass::Empty => false,
    };
    Observation {
        source: source.clone(),
        location,
        field,
        name: name.map(str::to_owned),
        class,
        truthy,
        host,
        secret,
        locator,
    }
}

impl Observation {
    /// Whether the variable is set as far as the agent is concerned: a
    /// literal or dynamic value, or (in shell text, where the shell expands
    /// it) a reference. A reference in a JSON or TOML file is a look-alike.
    #[must_use]
    pub fn is_set(&self) -> bool {
        match self.class {
            ValueClass::Literal => true,
            ValueClass::Dynamic => true,
            ValueClass::Reference => matches!(self.field, Field::ShellExport),
            ValueClass::Empty => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Agent, ArtifactKind, Scope};

    fn src() -> ArtifactRef {
        ArtifactRef {
            agent: Agent::ClaudeCode,
            scope: Scope::User,
            kind: ArtifactKind::Settings,
            path: "/h/.claude/settings.json".into(),
        }
    }

    #[test]
    fn observations_keep_host_and_mask_but_not_the_value() {
        let obs = observe(
            &src(),
            Location::key("/h/.claude/settings.json", "env.ANTHROPIC_BASE_URL"),
            Field::SettingEnv,
            Some("ANTHROPIC_BASE_URL"),
            Locator::Setting {
                key_path: "env".into(),
            },
            "https://u:pw12345678@llm-proxy.acme-corp.example/v1?k=FAKEQUERYTOKEN",
        );
        assert_eq!(
            obs.host.as_deref(),
            Some("https://llm-proxy.acme-corp.example")
        );
        assert_eq!(obs.class, ValueClass::Literal);
        let secret = obs.secret.as_ref().unwrap();
        assert_eq!(secret.kind, "URL password");
        let text = format!("{obs:?}");
        assert!(!text.contains("pw12345678"), "{text}");
        assert!(!text.contains("FAKEQUERYTOKEN"), "{text}");
    }

    #[test]
    fn references_are_not_set_in_json_but_are_in_shell_text() {
        let json = observe(
            &src(),
            Location::key("/h/.claude/settings.json", "env.ANTHROPIC_API_KEY"),
            Field::SettingEnv,
            Some("ANTHROPIC_API_KEY"),
            Locator::None,
            "${ANTHROPIC_API_KEY}",
        );
        assert!(!json.is_set());
        assert!(json.secret.is_none());
        assert!(json.host.is_none());
        let with_default = observe(
            &src(),
            Location::key("/h/.claude/settings.json", "env.GITHUB_TOKEN"),
            Field::SettingEnv,
            Some("GITHUB_TOKEN"),
            Locator::None,
            "${GITHUB_TOKEN:-ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a}",
        );
        assert_eq!(with_default.class, ValueClass::Reference);
        assert_eq!(with_default.secret.as_ref().unwrap().masked, "ghp_••••f9a");
        let shell = observe(
            &src(),
            Location::line("/h/.zshrc", 3),
            Field::ShellExport,
            Some("GITHUB_TOKEN"),
            Locator::None,
            "$(op read x)",
        );
        assert!(shell.is_set());
        assert_eq!(shell.class, ValueClass::Dynamic);
        assert!(shell.secret.is_none());
        let empty = observe(
            &src(),
            Location::line("/h/.zshrc", 4),
            Field::ShellExport,
            Some("X"),
            Locator::None,
            "",
        );
        assert!(!empty.is_set());
        let off = observe(
            &src(),
            Location::line("/h/.zshrc", 5),
            Field::ShellExport,
            Some("CLAUDE_CODE_USE_VERTEX"),
            Locator::None,
            "0",
        );
        assert!(off.is_set());
        assert!(!off.truthy);
        assert!(json.truthy, "a reference may be on");
    }

    #[test]
    fn commands_are_scanned_as_free_text() {
        let obs = observe(
            &src(),
            Location::key("/h/.claude/settings.json", "hooks.SessionStart"),
            Field::HookCommand,
            None,
            Locator::Hook {
                event: "SessionStart".into(),
                matcher: None,
            },
            "GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a ./notify.sh",
        );
        assert_eq!(obs.secret.as_ref().unwrap().masked, "ghp_••••f9a");
    }
}
