//! Where each agent keeps its files, after the relocation variables in the
//! user's shell profiles are applied.
//!
//! `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and `COPILOT_HOME` move an agent's whole
//! directory. They are read from the profiles *inside the scanned home*, not
//! from this process's environment, so a fixture home is self-contained and
//! a scan of someone else's home honours their shell setup. Only plain
//! `NAME=value` and `export NAME=value` lines count; nothing is evaluated.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::home::HomeEnv;
use crate::model::{Agent, Warning};

/// Relocation variables and the agent they move.
const RELOCATION_VARS: &[(&str, Agent, &str)] = &[
    ("CLAUDE_CONFIG_DIR", Agent::ClaudeCode, ".claude"),
    ("CODEX_HOME", Agent::Codex, ".codex"),
    ("COPILOT_HOME", Agent::CopilotCli, ".copilot"),
];

/// Shell profiles, in the order a login shell reads them, so a later file
/// overrides an earlier one the way the shell would.
pub const SHELL_PROFILES: &[&str] = &[
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
];

/// Resolved agent directories for one home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDirs {
    /// Claude Code's directory (`~/.claude` unless relocated).
    pub claude_config: PathBuf,
    /// Codex's directory (`~/.codex` unless relocated).
    pub codex_home: PathBuf,
    /// Copilot CLI's directory (`~/.copilot` unless relocated).
    pub copilot_home: PathBuf,
    /// The relocation variables found, by name.
    pub relocations: BTreeMap<String, PathBuf>,
    /// Lines that looked like relocations but could not be used.
    pub warnings: Vec<Warning>,
}

impl AgentDirs {
    /// Reads the shell profiles under `home` and resolves each agent's
    /// directory.
    #[must_use]
    pub fn resolve(home: &HomeEnv) -> Self {
        let mut relocations = BTreeMap::new();
        let mut warnings = Vec::new();
        for profile in SHELL_PROFILES {
            let path = home.root().join(profile);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (name, agent, _) in RELOCATION_VARS {
                for raw in assignments(&text, name) {
                    match resolve_value(home, &raw) {
                        Some(dir) => {
                            relocations.insert((*name).to_owned(), dir);
                        }
                        None => warnings.push(Warning::new(
                            *agent,
                            &path,
                            format!(
                                "{name} is set to a value the engine cannot resolve without a shell; the default directory is used"
                            ),
                        )),
                    }
                }
            }
        }
        let dir = |name: &str, default: &str| {
            relocations
                .get(name)
                .cloned()
                .unwrap_or_else(|| home.root().join(default))
        };
        Self {
            claude_config: dir("CLAUDE_CONFIG_DIR", ".claude"),
            codex_home: dir("CODEX_HOME", ".codex"),
            copilot_home: dir("COPILOT_HOME", ".copilot"),
            relocations,
            warnings,
        }
    }
}

/// The raw right-hand sides of `NAME=…` and `export NAME=…` lines, in
/// order. Quotes are removed; nothing else is interpreted.
fn assignments(text: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some(rest) = line.strip_prefix(name) else {
            continue;
        };
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        // A quoted value ends at its closing quote; an unquoted one at the
        // first space or comment.
        let value = value.trim();
        let value = match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value[1..].split(quote).next().unwrap_or_default(),
            _ => value.split([' ', '\t', '#']).next().unwrap_or_default(),
        };
        out.push(value.to_owned());
    }
    out
}

/// Turns a profile value into a directory under the scanned home, or `None`
/// when it needs a shell to evaluate.
fn resolve_value(home: &HomeEnv, raw: &str) -> Option<PathBuf> {
    let root = home.root();
    let expanded = if let Some(rest) = raw.strip_prefix("$HOME") {
        join_rest(root, rest)
    } else if let Some(rest) = raw.strip_prefix("${HOME}") {
        join_rest(root, rest)
    } else if let Some(rest) = raw.strip_prefix('~') {
        join_rest(root, rest)
    } else if raw.contains('$') || raw.contains('`') || raw.contains("$(") {
        return None;
    } else if Path::new(raw).is_absolute() {
        home.locate(Path::new(raw))
    } else {
        // A relative directory depends on the shell's working directory.
        return None;
    };
    Some(expanded)
}

fn join_rest(root: &Path, rest: &str) -> PathBuf {
    let rest = rest.trim_start_matches(['/', '\\']);
    if rest.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_exported_and_plain_assignments_and_strips_quotes() {
        let text = "# comment\nexport CODEX_HOME=\"$HOME/.config/codex\"\nCODEX_HOME='/opt/codex' # trailing\nexport CODEX_HOME_X=1\nexport PATH=$CODEX_HOME/bin:$PATH\n";
        assert_eq!(
            assignments(text, "CODEX_HOME"),
            vec!["$HOME/.config/codex", "/opt/codex"]
        );
    }

    #[test]
    fn values_expand_home_and_reject_dynamic_ones() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let home = HomeEnv::resolve(Some(&dir)).unwrap();
        assert_eq!(resolve_value(&home, "$HOME/.cc"), Some(dir.join(".cc")));
        assert_eq!(resolve_value(&home, "${HOME}/.cc"), Some(dir.join(".cc")));
        assert_eq!(resolve_value(&home, "~/.cc"), Some(dir.join(".cc")));
        assert_eq!(resolve_value(&home, "~"), Some(dir.clone()));
        assert!(resolve_value(&home, "$XDG_CONFIG_HOME/claude").is_none());
        assert!(resolve_value(&home, "relative/dir").is_none());
        // An absolute path under a home-like prefix is located under the
        // scanned home when it exists there: `src` does.
        assert_eq!(
            resolve_value(&home, "/Users/you/src"),
            Some(dir.join("src"))
        );
    }

    #[test]
    fn defaults_apply_without_profiles() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let home = HomeEnv::resolve(Some(&dir)).unwrap();
        let dirs = AgentDirs::resolve(&home);
        assert_eq!(dirs.claude_config, dir.join(".claude"));
        assert_eq!(dirs.codex_home, dir.join(".codex"));
        assert_eq!(dirs.copilot_home, dir.join(".copilot"));
        assert!(dirs.relocations.is_empty());
        assert!(dirs.warnings.is_empty());
    }
}
