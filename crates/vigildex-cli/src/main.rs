//! The `vigildex` command-line interface.
//!
//! Exit codes: `0` ok; `1` findings at or above `--fail-on` (from M2);
//! `2` usage or I/O error.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use vigildex_core::{
    Agent, HomeEnv, HomeSource, HookHandler, Inventory, InventoryReport, Item, Launch, Pin,
    RedactedValue, RemoteAuth, ScanReport, Scope,
};

/// Exit code for usage and I/O errors. Clap uses the same code for bad
/// arguments.
const EXIT_ERROR: u8 = 2;

/// See what your AI coding agents can run, and know when it changes.
///
/// Vigildex is local and read-only: it never writes to your agents' files,
/// never reads credential values and never uses the network.
#[derive(Debug, Parser)]
#[command(name = "vigildex", version, propagate_version = true)]
struct Cli {
    /// Read agent files from DIR instead of your home directory
    /// [env: VIGILDEX_HOME]
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan the home directory: the inventory, with counts per agent
    Scan {
        /// Print JSON; the output is a versioned contract (`schema_version`)
        #[arg(long)]
        json: bool,
    },
    /// List what each agent can run: MCP servers, hooks, skills, plugins,
    /// instruction files and security settings
    Inventory {
        /// Only this agent
        #[arg(long, value_enum)]
        agent: Option<AgentArg>,
        /// Only this item type
        #[arg(long = "type", value_enum, value_name = "TYPE")]
        item_type: Option<TypeArg>,
        /// Print JSON; the output is a versioned contract (`schema_version`)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AgentArg {
    ClaudeCode,
    Codex,
    Cursor,
    CopilotCli,
    VscodeAgent,
    Shared,
}

impl From<AgentArg> for Agent {
    fn from(arg: AgentArg) -> Self {
        match arg {
            AgentArg::ClaudeCode => Agent::ClaudeCode,
            AgentArg::Codex => Agent::Codex,
            AgentArg::Cursor => Agent::Cursor,
            AgentArg::CopilotCli => Agent::CopilotCli,
            AgentArg::VscodeAgent => Agent::VsCodeAgent,
            AgentArg::Shared => Agent::Shared,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TypeArg {
    McpServer,
    Hook,
    Skill,
    Plugin,
    Instruction,
    Setting,
    Credential,
}

impl TypeArg {
    fn matches(self, item: &Item) -> bool {
        matches!(
            (self, item),
            (TypeArg::McpServer, Item::McpServer(_))
                | (TypeArg::Hook, Item::Hook(_))
                | (TypeArg::Skill, Item::Skill(_))
                | (TypeArg::Plugin, Item::Plugin(_))
                | (TypeArg::Instruction, Item::Instruction(_))
                | (TypeArg::Setting, Item::Setting(_))
                | (TypeArg::Credential, Item::Credential(_))
        )
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Nothing useful can be done if stderr is gone too.
            let _ = writeln!(io::stderr().lock(), "error: {err:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    let home = HomeEnv::resolve(cli.home.as_deref())?;
    match &cli.command {
        Command::Scan { json } => {
            let report = vigildex_core::scan(&home);
            let text = if *json {
                render_json(&report)?
            } else {
                render_scan_text(&report)
            };
            print(&text)
        }
        Command::Inventory {
            agent,
            item_type,
            json,
        } => {
            let mut report = vigildex_core::inventory_report(&home);
            filter(&mut report.inventory, agent.map(Agent::from), *item_type);
            let text = if *json {
                render_json(&report)?
            } else {
                render_inventory_text(&report)
            };
            print(&text)
        }
    }
}

/// Keeps only the items (and artifacts) that match the filters.
fn filter(inventory: &mut Inventory, agent: Option<Agent>, item_type: Option<TypeArg>) {
    inventory.items.retain(|item| {
        agent.is_none_or(|a| item.source().agent == a) && item_type.is_none_or(|t| t.matches(item))
    });
    if let Some(agent) = agent {
        inventory.artifacts.retain(|a| a.agent == agent);
        inventory
            .warnings
            .retain(|w| w.agent.is_none_or(|a| a == agent));
    }
}

fn render_json<T: serde::Serialize>(report: &T) -> anyhow::Result<String> {
    let mut text =
        serde_json::to_string_pretty(report).context("could not encode the report as JSON")?;
    text.push('\n');
    Ok(text)
}

fn home_line(root: &Path, source: HomeSource) -> String {
    let how = match source {
        HomeSource::Override => "from --home",
        HomeSource::Env => "from VIGILDEX_HOME",
        HomeSource::User => "your home directory",
        // `HomeSource` is non-exhaustive; describe anything newer neutrally.
        _ => "home directory",
    };
    format!("Home: {} ({how})", root.display())
}

fn agents_line(agents: &[Agent]) -> String {
    let names: Vec<&str> = agents.iter().map(|a| a.display_name()).collect();
    format!("Scanned: {}", names.join(", "))
}

fn render_scan_text(report: &ScanReport) -> String {
    let inv = &report.inventory;
    let mut out = format!(
        "vigildex {}\n{}\n{}\nProjects: {}\n\n",
        report.engine_version,
        home_line(&report.home.root, report.home.source),
        agents_line(&inv.scanned),
        inv.project_roots.len()
    );
    const COLUMNS: &[(&str, &str)] = &[
        ("mcp_server", "MCP"),
        ("hook", "Hooks"),
        ("skill", "Skills"),
        ("plugin", "Plugins"),
        ("instruction", "Instr."),
        ("setting", "Settings"),
        ("credential", "Creds"),
    ];
    let mut counts: BTreeMap<Agent, BTreeMap<&str, usize>> = BTreeMap::new();
    for agent in &inv.scanned {
        counts.entry(*agent).or_default();
    }
    for item in &inv.items {
        *counts
            .entry(item.source().agent)
            .or_default()
            .entry(item.type_name())
            .or_default() += 1;
    }
    out.push_str(&format!("{:<20}", "Agent"));
    for (_, title) in COLUMNS {
        out.push_str(&format!("{title:>9}"));
    }
    out.push('\n');
    for (agent, by_type) in &counts {
        out.push_str(&format!("{:<20}", agent.display_name()));
        for (key, _) in COLUMNS {
            out.push_str(&format!("{:>9}", by_type.get(key).copied().unwrap_or(0)));
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "\nFiles read: {}\nWarnings: {}\n",
        inv.artifacts.len(),
        inv.warnings.len()
    ));
    for warning in &inv.warnings {
        out.push_str(&format!("  {}\n", warning_line(warning, &report.home.root)));
    }
    out.push_str("\nRun `vigildex inventory` for the items.\n");
    out
}

fn render_inventory_text(report: &InventoryReport) -> String {
    let inv = &report.inventory;
    let home = &report.home.root;
    let mut out = format!(
        "vigildex {}\n{}\n{}\n",
        report.engine_version,
        home_line(home, report.home.source),
        agents_line(&inv.scanned),
    );
    if !inv.project_roots.is_empty() {
        let roots: Vec<String> = inv
            .project_roots
            .iter()
            .map(|r| short_path(r, home))
            .collect();
        out.push_str(&format!("Projects: {}\n", roots.join(", ")));
    }
    for (var, dir) in &inv.relocations {
        out.push_str(&format!("{var}: {}\n", short_path(dir, home)));
    }
    if inv.items.is_empty() {
        out.push_str("\nNo items found.\n");
    }

    let mut current_agent: Option<Agent> = None;
    let mut current_scope: Option<&Scope> = None;
    for item in &inv.items {
        let source = item.source();
        if current_agent != Some(source.agent) {
            current_agent = Some(source.agent);
            current_scope = None;
            out.push_str(&format!("\n{}\n", source.agent.display_name()));
        }
        if current_scope != Some(&source.scope) {
            current_scope = Some(&source.scope);
            out.push_str(&format!("  {}\n", scope_line(&source.scope, home)));
        }
        out.push_str(&format!(
            "    {:<11} {:<30} {}{}\n",
            item.type_name(),
            label_text(item, home),
            detail(item, home),
            origin_suffix(source, home)
        ));
    }
    if !inv.warnings.is_empty() {
        out.push_str("\nWarnings\n");
        for warning in &inv.warnings {
            out.push_str(&format!("  {}\n", warning_line(warning, home)));
        }
    }
    out
}

fn scope_line(scope: &Scope, home: &Path) -> String {
    match scope {
        Scope::Managed => "managed".to_owned(),
        Scope::User => "user".to_owned(),
        Scope::Project { root } => format!("project {}", short_path(root, home)),
        Scope::Local { root } => format!("local {}", short_path(root, home)),
        Scope::Plugin { id } => format!("plugin {id}"),
        // `Scope` is non-exhaustive.
        _ => "other".to_owned(),
    }
}

fn warning_line(warning: &vigildex_core::Warning, home: &Path) -> String {
    match &warning.path {
        Some(path) => format!("{}: {}", short_path(path, home), warning.message),
        None => warning.message.clone(),
    }
}

/// The label column: paths are shown relative to the home.
fn label_text(item: &Item, home: &Path) -> String {
    match item {
        Item::Instruction(instruction) => short_path(&instruction.path, home),
        Item::Credential(credential) => short_path(&credential.path, home),
        _ => item.label(),
    }
}

/// Names the source file when a scope has more than one settings file
/// (`settings.json` beside `settings.local.json`), so equal key paths do
/// not read as duplicates.
fn origin_suffix(source: &vigildex_core::ArtifactRef, home: &Path) -> String {
    let name = source
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name.contains(".local.") {
        format!("  [{}]", short_path(&source.path, home))
    } else {
        String::new()
    }
}

/// `~`-relative form of a path under the home, for readable lines.
fn short_path(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

fn detail(item: &Item, home: &Path) -> String {
    match item {
        Item::McpServer(server) => {
            let mut text = launch_text(&server.launch);
            if !server.env_keys.is_empty() {
                text.push_str(&format!("  env: {}", server.env_keys.join(", ")));
            }
            if !server.header_keys.is_empty() {
                text.push_str(&format!("  headers: {}", server.header_keys.join(", ")));
            }
            if server.enabled == Some(false) {
                text.push_str("  (disabled)");
            }
            text
        }
        Item::Hook(hook) => match &hook.handler {
            HookHandler::Command { command, args, .. } => {
                let mut text = format!("command: {command}");
                if !args.is_empty() {
                    text.push(' ');
                    text.push_str(&args.join(" "));
                }
                text
            }
            HookHandler::Http { url, .. } => format!("http: {url}"),
            HookHandler::McpTool { server, tool, .. } => format!("mcp_tool: {server}/{tool}"),
            HookHandler::Prompt { .. } => "prompt".to_owned(),
            HookHandler::Agent { .. } => "agent".to_owned(),
            HookHandler::Unknown { type_name } => {
                format!(
                    "unknown handler type {}",
                    type_name.as_deref().unwrap_or("(none)")
                )
            }
            _ => "handler".to_owned(),
        },
        Item::Skill(skill) => {
            let mut text =
                format!("{:?} {}", skill.kind, short_path(&skill.path, home)).to_lowercase();
            if !skill.allowed_tools.is_empty() {
                text.push_str(&format!("  tools: {}", skill.allowed_tools.join(", ")));
            }
            if !skill.scripts.is_empty() {
                text.push_str(&format!("  scripts: {}", skill.scripts.len()));
            }
            if skill.hook_count > 0 {
                text.push_str(&format!("  hooks: {}", skill.hook_count));
            }
            text
        }
        Item::Plugin(plugin) => {
            let mut text = plugin
                .version
                .clone()
                .unwrap_or_else(|| "(no version)".to_owned());
            match plugin.enabled {
                Some(true) => text.push_str("  enabled"),
                Some(false) => text.push_str("  disabled"),
                None => {}
            }
            if !plugin.installed {
                text.push_str("  NOT INSTALLED");
            }
            if !plugin.components.is_empty() {
                let parts: Vec<String> = plugin
                    .components
                    .iter()
                    .map(|c| format!("{c:?}").to_lowercase())
                    .collect();
                text.push_str(&format!("  [{}]", parts.join(", ")));
            }
            text
        }
        Item::Instruction(instruction) => {
            let mut text = format!("{} lines", instruction.lines);
            if instruction.always_apply == Some(false) {
                text.push_str("  (path-scoped)");
            }
            text
        }
        Item::Setting(setting) => format!("= {}", value_text(&setting.value)),
        Item::Credential(credential) => {
            if !credential.exists {
                return "not present".to_owned();
            }
            let mut text = "present".to_owned();
            if let Some(mode) = &credential.mode {
                text.push_str(&format!("  mode {mode}"));
            }
            if !credential.keys.is_empty() {
                let names: Vec<&str> = credential.keys.iter().map(|k| k.name.as_str()).collect();
                text.push_str(&format!("  keys: {}", names.join(", ")));
            }
            text
        }
        // `Item` is non-exhaustive.
        _ => String::new(),
    }
}

fn launch_text(launch: &Launch) -> String {
    match launch {
        Launch::Package {
            runner, spec, pin, ..
        } => {
            let pin = match pin {
                Pin::Exact => "pinned",
                Pin::Floating => "floating",
                _ => "unknown pin",
            };
            format!("{} {spec} ({pin})", format!("{runner:?}").to_lowercase())
        }
        Launch::Interpreter {
            interpreter,
            script,
            ..
        } => format!("{interpreter} {}", script.as_deref().unwrap_or("")),
        Launch::Binary { command, args } => {
            if args.is_empty() {
                command.clone()
            } else {
                format!("{command} {}", args.join(" "))
            }
        }
        Launch::Remote {
            url,
            transport,
            auth,
        } => {
            let auth = match auth {
                RemoteAuth::None => "",
                RemoteAuth::Oauth => "  auth: oauth",
                RemoteAuth::StaticHeaders => "  auth: static headers",
                RemoteAuth::BearerEnvVar { .. } => "  auth: bearer from env",
                RemoteAuth::HeadersHelper { .. } => "  auth: headers helper",
                _ => "  auth: other",
            };
            format!("{} {url}{auth}", format!("{transport:?}").to_lowercase())
        }
        Launch::Unknown => "(no command or url)".to_owned(),
        _ => String::new(),
    }
}

fn value_text(value: &RedactedValue) -> String {
    match value {
        RedactedValue::Bool { value } => value.to_string(),
        RedactedValue::Number { value } => value.to_string(),
        RedactedValue::Text { value } => value.clone(),
        RedactedValue::List { values } => format!("[{}]", values.join(", ")),
        RedactedValue::Keys { keys } => format!("{{{}}}", keys.join(", ")),
        RedactedValue::Present => "(present)".to_owned(),
        RedactedValue::Null => "null".to_owned(),
        _ => "(value)".to_owned(),
    }
}

/// Writes to stdout. A closed pipe (`vigildex scan | head`) is not an error.
fn print(text: &str) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    match stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Err(err) if err.kind() != io::ErrorKind::BrokenPipe => {
            Err(err).context("could not write to stdout")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
