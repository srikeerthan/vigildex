//! The inventory model: what an agent can run, as plain data.
//!
//! Every type here derives `serde` and `schemars::JsonSchema`, because the
//! CLI `--json` output is a versioned contract (`SCHEMA_VERSION` in
//! [`crate::report`]). Values are already safe to show: commands and URLs
//! are kept, environment variables and headers appear as key names only, and
//! credential files contribute nothing but key names and file metadata.
//!
//! The sketch in `docs/ARCHITECTURE.md` § Core model is the starting point;
//! the differences are noted on the types that diverge.

use std::fmt;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An AI coding agent, or the shared sources that several agents read.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Agent {
    /// Anthropic's Claude Code (CLI, desktop and IDE extensions share `~/.claude`).
    ClaudeCode,
    /// OpenAI Codex (CLI, IDE extension and desktop app share `~/.codex`).
    Codex,
    /// Cursor (adapter arrives in M5).
    Cursor,
    /// GitHub Copilot CLI (adapter arrives in M5).
    CopilotCli,
    /// GitHub Copilot in VS Code agent mode (adapter arrives in M5).
    VsCodeAgent,
    /// Sources read by several agents at once, such as `~/.agents/skills`.
    Shared,
}

impl Agent {
    /// Human-readable name for lists and text output.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::CopilotCli => "Copilot CLI",
            Self::VsCodeAgent => "VS Code agent mode",
            Self::Shared => "Shared",
        }
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Where a configuration applies.
///
/// Project paths are the ones the agent itself recorded (for example the
/// keys of `projects` in `~/.claude.json`), resolved to a directory under the
/// scanned home when the recorded path does not exist there (see
/// [`crate::HomeEnv::locate`]).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Scope {
    /// Organisation policy deployed to the machine.
    Managed,
    /// The user's own files under the home directory.
    User,
    /// A repository's shared files, usually committed.
    Project {
        /// The repository root.
        root: PathBuf,
    },
    /// The user's private settings for one repository, including agent state
    /// recorded against that repository (trust, local MCP servers).
    Local {
        /// The repository root.
        root: PathBuf,
    },
    /// Bundled with an installed plugin.
    Plugin {
        /// The plugin identifier, `name@marketplace` for Claude Code.
        id: String,
    },
}

/// What kind of file an artifact is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArtifactKind {
    /// A settings file (`settings.json`, `config.toml`).
    Settings,
    /// Agent application state (`~/.claude.json`).
    AppState,
    /// A standalone MCP configuration (`.mcp.json`).
    McpConfig,
    /// A standalone hooks file (`hooks.json`).
    Hooks,
    /// A skill, command or subagent definition (Markdown with frontmatter).
    Skill,
    /// A plugin registry or manifest.
    Plugin,
    /// An instruction file loaded into the agent's context.
    Instructions,
    /// A credential file. Only metadata and key names are ever read.
    Credential,
}

/// A file the engine read, and where it sits in the agent's configuration.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct ArtifactRef {
    /// The agent that reads this file.
    pub agent: Agent,
    /// Where the file applies.
    pub scope: Scope,
    /// What kind of file it is.
    pub kind: ArtifactKind,
    /// Absolute path of the file (or directory, for a skill).
    pub path: PathBuf,
}

/// An artifact as listed in a report, with the hash the change engine (M4)
/// will compare against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ArtifactView {
    /// The agent that reads this file.
    pub agent: Agent,
    /// Where the file applies.
    pub scope: Scope,
    /// What kind of file it is.
    pub kind: ArtifactKind,
    /// Absolute path of the file.
    pub path: PathBuf,
    /// Size of the file in bytes.
    pub bytes: u64,
    /// Lower-case hex SHA-256 of the file contents.
    pub sha256: String,
}

/// One thing an agent can run or load, normalised across agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Item {
    /// An MCP server the agent can start or connect to.
    McpServer(McpServer),
    /// A hook handler registered for a lifecycle event.
    Hook(Hook),
    /// A skill, legacy command or subagent definition.
    Skill(Skill),
    /// An installed plugin.
    Plugin(Plugin),
    /// An instruction file loaded into context.
    Instruction(Instruction),
    /// A security-relevant setting.
    Setting(Setting),
    /// Metadata about a credential file (never its contents).
    Credential(Credential),
}

impl Item {
    /// Where the item was read from.
    #[must_use]
    pub fn source(&self) -> &ArtifactRef {
        match self {
            Self::McpServer(it) => &it.source,
            Self::Hook(it) => &it.source,
            Self::Skill(it) => &it.source,
            Self::Plugin(it) => &it.source,
            Self::Instruction(it) => &it.source,
            Self::Setting(it) => &it.source,
            Self::Credential(it) => &it.source,
        }
    }

    /// The item type as it appears in JSON (`mcp_server`, `hook`, …).
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::McpServer(_) => "mcp_server",
            Self::Hook(_) => "hook",
            Self::Skill(_) => "skill",
            Self::Plugin(_) => "plugin",
            Self::Instruction(_) => "instruction",
            Self::Setting(_) => "setting",
            Self::Credential(_) => "credential",
        }
    }

    /// A short label for lists: the server or skill name, the hook event, the
    /// setting key, or the file name.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::McpServer(it) => it.name.clone(),
            Self::Hook(it) => match &it.matcher {
                Some(m) => format!("{} [{m}]", it.event),
                None => it.event.clone(),
            },
            Self::Skill(it) => it.name.clone(),
            Self::Plugin(it) => it.id.clone(),
            Self::Instruction(it) => it.path.to_string_lossy().into_owned(),
            Self::Setting(it) => it.key_path.clone(),
            Self::Credential(it) => it.path.to_string_lossy().into_owned(),
        }
    }

    /// Display order of the item types: what runs first (servers, hooks,
    /// skills, plugins), then what is loaded or set.
    #[must_use]
    pub fn type_rank(&self) -> u8 {
        match self {
            Self::McpServer(_) => 0,
            Self::Hook(_) => 1,
            Self::Skill(_) => 2,
            Self::Plugin(_) => 3,
            Self::Instruction(_) => 4,
            Self::Setting(_) => 5,
            Self::Credential(_) => 6,
        }
    }

    /// Sort key: agent, scope, type, label, then path, so reports are stable
    /// whatever order the file system returned entries in.
    #[must_use]
    pub fn sort_key(&self) -> (Agent, Scope, u8, String, PathBuf) {
        let source = self.source();
        (
            source.agent,
            source.scope.clone(),
            self.type_rank(),
            self.label(),
            source.path.clone(),
        )
    }
}

/// An MCP server definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct McpServer {
    /// The server's name in its configuration.
    pub name: String,
    /// How the server is started or reached.
    pub launch: Launch,
    /// Names of the environment variables the configuration sets for the
    /// server. Values are never recorded.
    pub env_keys: Vec<String>,
    /// Names of static request headers. Values are never recorded.
    pub header_keys: Vec<String>,
    /// Names of headers whose values come from environment variables
    /// (Codex `env_http_headers`).
    pub env_header_keys: Vec<String>,
    /// Whether the configuration enables the server, when it says so
    /// (Codex `enabled`). `None` means the configuration does not say.
    pub enabled: Option<bool>,
    /// Where the definition was read from.
    pub source: ArtifactRef,
}

/// How an MCP server is launched or reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Launch {
    /// A package fetched and run by a package runner (`npx`, `uvx`, `docker`, …).
    Package {
        /// The runner.
        runner: Runner,
        /// The package or image specification as written.
        spec: String,
        /// Whether the specification pins an exact version.
        pin: Pin,
        /// The full argument list after the runner, with obvious credentials
        /// masked.
        args: Vec<String>,
    },
    /// A script run by an interpreter (`node`, `python3`, `bash`, …).
    Interpreter {
        /// The interpreter command as written.
        interpreter: String,
        /// The script path, or the first non-flag argument.
        script: Option<String>,
        /// The full argument list after the interpreter, with obvious
        /// credentials masked.
        args: Vec<String>,
    },
    /// Any other executable.
    Binary {
        /// The command as written.
        command: String,
        /// The argument list, with obvious credentials masked.
        args: Vec<String>,
    },
    /// A remote server reached over HTTP, SSE or WebSocket.
    Remote {
        /// The URL with user information and the query string removed.
        url: String,
        /// The transport named in the configuration.
        transport: Transport,
        /// How the connection authenticates.
        auth: RemoteAuth,
    },
    /// The configuration names neither a command nor a URL.
    Unknown,
}

/// A package runner that downloads code before running it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Runner {
    /// `npx` (npm).
    Npx,
    /// `pnpx` or `pnpm dlx`.
    Pnpx,
    /// `bunx` or `bun x`.
    Bunx,
    /// `uvx` or `uv tool run`.
    Uvx,
    /// `pipx run`.
    Pipx,
    /// `docker run`.
    Docker,
}

/// Whether a package specification pins an exact version.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Pin {
    /// An exact version or digest (`pkg@1.2.3`, `pkg==1.2.3`, `image@sha256:…`).
    Exact,
    /// No version, a tag, `latest` or a range: the code can change under the
    /// agent without a configuration change.
    Floating,
}

/// The transport of a remote MCP server.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Transport {
    /// Streamable HTTP (`http`, `streamable-http`, or Codex's URL form).
    Http,
    /// Server-sent events.
    Sse,
    /// WebSocket.
    Ws,
    /// A transport name the engine does not know.
    Unknown,
}

/// How a remote MCP server authenticates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteAuth {
    /// Nothing in the configuration.
    None,
    /// OAuth, with tokens held by the agent.
    Oauth,
    /// Static headers in the configuration (names in
    /// [`McpServer::header_keys`]).
    StaticHeaders,
    /// A bearer token read from the named environment variable at use time
    /// (Codex `bearer_token_env_var`).
    BearerEnvVar {
        /// The variable name.
        var: String,
    },
    /// A command that prints headers at connection time (Claude Code
    /// `headersHelper`, Codex `http_headers_helper`).
    HeadersHelper {
        /// The command as written.
        command: String,
    },
}

/// A hook handler registered for a lifecycle event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Hook {
    /// The event name as written (`PreToolUse`, `SessionStart`, …).
    pub event: String,
    /// The matcher as written, when the group has one.
    pub matcher: Option<String>,
    /// What runs.
    pub handler: HookHandler,
    /// Where the hook was read from.
    pub source: ArtifactRef,
}

/// What a hook runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum HookHandler {
    /// A shell command.
    Command {
        /// The command as written, with obvious credentials masked.
        command: String,
        /// Exec-form arguments (Claude Code `args`), masked the same way.
        args: Vec<String>,
        /// Timeout in seconds, when set.
        timeout_secs: Option<u64>,
        /// Whether the hook runs in the background.
        #[serde(rename = "async")]
        is_async: bool,
    },
    /// An HTTP request to a URL (Claude Code).
    Http {
        /// The URL with user information and the query string removed.
        url: String,
        /// Header names. Values are never recorded.
        header_keys: Vec<String>,
        /// Environment variables the hook may interpolate into headers.
        allowed_env_vars: Vec<String>,
        /// Timeout in seconds, when set.
        timeout_secs: Option<u64>,
    },
    /// A tool call on an MCP server.
    McpTool {
        /// The server name.
        server: String,
        /// The tool name.
        tool: String,
        /// Timeout in seconds, when set.
        timeout_secs: Option<u64>,
    },
    /// A single model turn with a prompt (the prompt text is not recorded).
    Prompt {
        /// The model, when set.
        model: Option<String>,
        /// Timeout in seconds, when set.
        timeout_secs: Option<u64>,
    },
    /// A subagent run (the prompt text is not recorded).
    Agent {
        /// The model, when set.
        model: Option<String>,
        /// Timeout in seconds, when set.
        timeout_secs: Option<u64>,
    },
    /// A handler type the engine does not know.
    Unknown {
        /// The `type` value as written, if any.
        type_name: Option<String>,
    },
}

/// The kind of Markdown definition a [`Skill`] item came from.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SkillKind {
    /// A `SKILL.md` folder (Agent Skills format).
    Skill,
    /// A legacy Claude Code command file (`commands/<name>.md`).
    Command,
    /// A Claude Code subagent file (`agents/<name>.md`).
    Subagent,
}

/// A skill, legacy command or subagent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Skill {
    /// The name: frontmatter `name`, else the folder or file name.
    pub name: String,
    /// What kind of definition it is.
    pub kind: SkillKind,
    /// The skill folder, or the command or subagent file.
    pub path: PathBuf,
    /// The frontmatter `description`, cut to a short length. The body is
    /// never recorded.
    pub description: Option<String>,
    /// Tools pre-approved while the skill runs (`allowed-tools`, or a
    /// subagent's `tools`).
    pub allowed_tools: Vec<String>,
    /// Script-like files bundled in the skill folder, relative to it.
    pub scripts: Vec<String>,
    /// Number of hook handlers declared in the frontmatter. Each one is also
    /// reported as a [`Hook`] item with this definition as its source.
    pub hook_count: u32,
    /// Whether the model may invoke the skill on its own
    /// (`disable-model-invocation` inverted). `None` when unset.
    pub model_invocable: Option<bool>,
    /// Whether the user may invoke the skill from the `/` menu
    /// (`user-invocable`). `None` when unset.
    pub user_invocable: Option<bool>,
    /// A subagent's `permissionMode`, when set.
    pub permission_mode: Option<String>,
    /// Where the definition was read from.
    pub source: ArtifactRef,
}

/// A component type a plugin bundles.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PluginComponent {
    /// `skills/`.
    Skills,
    /// `commands/`.
    Commands,
    /// `agents/`.
    Agents,
    /// `hooks/hooks.json`.
    Hooks,
    /// `.mcp.json`.
    McpServers,
    /// `.lsp.json`.
    LspServers,
    /// `output-styles/`.
    OutputStyles,
    /// `workflows/`.
    Workflows,
    /// `monitors/monitors.json`: persistent background commands.
    Monitors,
    /// `bin/`: executables added to the Bash tool's `PATH`.
    Bin,
    /// `settings.json` at the plugin root.
    Settings,
}

/// An installed plugin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Plugin {
    /// The identifier as the agent writes it (`name@marketplace`).
    pub id: String,
    /// The plugin name.
    pub name: String,
    /// The marketplace it was installed from, when the identifier has one.
    pub marketplace: Option<String>,
    /// Where the marketplace comes from (`github:owner/repo`, a URL or a
    /// path), when the agent recorded it.
    pub marketplace_source: Option<String>,
    /// The installed version, when recorded.
    pub version: Option<String>,
    /// The install scope recorded by the agent (`user`, `project`, …).
    pub install_scope: Option<String>,
    /// The install folder, as located under the scanned home.
    pub install_path: PathBuf,
    /// Whether the install folder exists.
    pub installed: bool,
    /// Whether settings enable the plugin. `None` when settings do not say.
    pub enabled: Option<bool>,
    /// Component types found in the install folder.
    pub components: Vec<PluginComponent>,
    /// Where the plugin was read from (the install registry).
    pub source: ArtifactRef,
}

/// An instruction file the agent loads into context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Instruction {
    /// Absolute path of the file.
    pub path: PathBuf,
    /// Number of lines. The text is never recorded.
    pub lines: u32,
    /// Whether the file loads in every session. `Some(false)` for a rule
    /// scoped to paths by its frontmatter; `None` when the format has no
    /// such switch.
    pub always_apply: Option<bool>,
    /// Where the file was read from.
    pub source: ArtifactRef,
}

/// A security-relevant setting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Setting {
    /// The key path in the file, with `.` between segments and quoted
    /// segments for paths (`projects["/Users/you/proj"].trust_level`).
    pub key_path: String,
    /// The value, reduced to what is safe to show.
    pub value: RedactedValue,
    /// Where the setting was read from.
    pub source: ArtifactRef,
}

/// A setting value that is safe to show.
///
/// Objects are reduced to their key names, so an `env` block never leaks a
/// value. A secret rule (M2) turns matching text into masked evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RedactedValue {
    /// A boolean.
    Bool {
        /// The value.
        value: bool,
    },
    /// A number.
    Number {
        /// The value.
        value: f64,
    },
    /// A string: a mode, a command, a URL or a path.
    Text {
        /// The value.
        value: String,
    },
    /// A list of strings (rules, paths, hosts).
    List {
        /// The values.
        values: Vec<String>,
    },
    /// An object, reduced to its key names.
    Keys {
        /// The key names.
        keys: Vec<String>,
    },
    /// The key exists; nothing about its value is recorded.
    Present,
    /// The key is set to `null`.
    Null,
}

/// Metadata about a credential file. Hard rule 2: never the values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Credential {
    /// Absolute path of the file.
    pub path: PathBuf,
    /// Whether the file exists. For Claude Code, `false` means the Keychain
    /// holds the credentials.
    pub exists: bool,
    /// Unix permission bits as octal text (`0600`), when available.
    pub mode: Option<String>,
    /// Whether users other than the owner can read the file, when the
    /// platform reports permission bits.
    pub readable_by_others: Option<bool>,
    /// Top-level key names and their JSON value types, for a JSON file.
    pub keys: Vec<CredentialKey>,
    /// Where the metadata was read from.
    pub source: ArtifactRef,
}

/// One top-level key of a JSON credential file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct CredentialKey {
    /// The key name.
    pub name: String,
    /// The JSON type of the value (`string`, `null`, `object`, …). Never the
    /// value itself.
    pub value_type: String,
}

/// Something the engine could not read or understand. A warning never stops
/// a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Warning {
    /// The agent whose file it concerns, when known.
    pub agent: Option<Agent>,
    /// The file it concerns, when known.
    pub path: Option<PathBuf>,
    /// What went wrong, in one sentence.
    pub message: String,
}

impl Warning {
    /// A warning about one file.
    #[must_use]
    pub fn new(agent: Agent, path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self {
            agent: Some(agent),
            path: Some(path.into()),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_serialize_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&Agent::ClaudeCode).unwrap(),
            "\"claude_code\""
        );
        assert_eq!(serde_json::to_string(&Agent::Shared).unwrap(), "\"shared\"");
    }

    #[test]
    fn scope_is_tagged_by_kind() {
        let scope = Scope::Project {
            root: PathBuf::from("/r"),
        };
        assert_eq!(
            serde_json::to_string(&scope).unwrap(),
            r#"{"kind":"project","root":"/r"}"#
        );
    }

    #[test]
    fn scopes_order_managed_user_project_local_plugin() {
        let mut scopes = [
            Scope::Plugin { id: "a".into() },
            Scope::Local {
                root: PathBuf::from("/r"),
            },
            Scope::Project {
                root: PathBuf::from("/r"),
            },
            Scope::User,
            Scope::Managed,
        ];
        scopes.sort();
        assert!(matches!(scopes[0], Scope::Managed));
        assert!(matches!(scopes[1], Scope::User));
        assert!(matches!(scopes[2], Scope::Project { .. }));
        assert!(matches!(scopes[3], Scope::Local { .. }));
        assert!(matches!(scopes[4], Scope::Plugin { .. }));
    }
}
