//! The rule catalogue as data: severity, the "why" sentence and the fix
//! steps of every rule the engine implements (`docs/RULES.md`). Titles are
//! built by the rule modules because most carry a variable part.

use crate::finding::{FixSteps, Severity};

/// What the catalogue says about one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleText {
    /// The rule ID.
    pub id: &'static str,
    /// Catalogue severity.
    pub severity: Severity,
    /// Why it matters, one sentence.
    pub why: &'static str,
    /// Fix summary, one line.
    pub fix: &'static str,
    /// Fix steps, in order.
    pub steps: &'static [&'static str],
}

impl RuleText {
    /// The fix as a [`FixSteps`].
    #[must_use]
    pub fn fix_steps(&self) -> FixSteps {
        FixSteps {
            summary: self.fix.to_owned(),
            steps: self.steps.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

/// Every implemented rule.
pub const RULES: &[RuleText] = &[
    RuleText {
        id: "SEC-001",
        severity: Severity::High,
        why: "Anyone who can read this file can use the token, and the agent starts the server with it in every session.",
        fix: "Replace the value with an environment reference, then rotate the token",
        steps: &[
            "Rotate the token at the provider.",
            "Put the new token in your shell environment or a secret manager, not in the file.",
            "Reference it from the config: `${VAR}` in Claude Code, `${env:VAR}` in Cursor, `bearer_token_env_var` or `env_http_headers` in Codex.",
        ],
    },
    RuleText {
        id: "SEC-002",
        severity: Severity::Medium,
        why: "The credential is passed on the server's command line, where every process listing and config backup can see it.",
        fix: "Pass the credential through an environment reference instead",
        steps: &[
            "Export the value in your shell environment (or a secret manager).",
            "Replace the literal with a reference such as `${DATABASE_URL}`.",
            "Rotate the credential if the file was ever shared or committed.",
        ],
    },
    RuleText {
        id: "SEC-003",
        severity: Severity::High,
        why: "The agent injects this value into every session, and the settings file is read by anything that can read your home or the repository.",
        fix: "Move the value out of the settings file",
        steps: &[
            "Keep the value in the Keychain, `op run`, or an env file outside the repository.",
            "Remove it from the settings file and rotate it if the file was shared or committed.",
        ],
    },
    RuleText {
        id: "SEC-004",
        severity: Severity::Medium,
        why: "Every program you run inherits this variable, and the profile is plain text that backups and dotfile syncs copy around.",
        fix: "Load the credential at use time instead of exporting it",
        steps: &[
            "Remove the export from the profile.",
            "Load it when needed: `export VAR=\"$(op read 'op://…')\"` or `security find-generic-password -w`.",
            "Rotate the credential if the profile was ever synced or shared.",
        ],
    },
    RuleText {
        id: "SEC-005",
        severity: Severity::Medium,
        why: "A `.env` file at the repository root is loaded by tooling and read by agents working in the folder, and is easy to commit by mistake.",
        fix: "Keep secrets out of the repository's `.env`",
        steps: &[
            "Check that `.env` is listed in `.gitignore`.",
            "Move the value to a secret manager or an env file outside the repository.",
            "Rotate the credential if the file was ever committed.",
        ],
    },
    RuleText {
        id: "SEC-006",
        severity: Severity::High,
        why: "Other users on this machine can read the credential file.",
        fix: "Restrict the file to your user",
        steps: &["Run `chmod 600` on the file."],
    },
    RuleText {
        id: "BILL-001",
        severity: Severity::High,
        why: "Claude Code uses `ANTHROPIC_API_KEY` for every `claude -p` run even though a subscription is signed in, so those runs are billed to the key.",
        fix: "Remove the key from your environment and let the subscription login bill",
        steps: &[
            "Delete the export from the profile (or scope it to the one script that needs it).",
            "Start a new shell and check `env | grep ANTHROPIC` shows nothing.",
        ],
    },
    RuleText {
        id: "BILL-002",
        severity: Severity::High,
        why: "`ANTHROPIC_AUTH_TOKEN` outranks both the API key and the subscription login, so every session is billed to it.",
        fix: "Remove the token unless you mean to bill through it",
        steps: &[
            "Delete the export (or settings `env` entry).",
            "Start a new shell and check `env | grep ANTHROPIC` shows nothing.",
        ],
    },
    RuleText {
        id: "BILL-003",
        severity: Severity::Medium,
        why: "`apiKeyHelper` supplies an API key for every session, including headless runs in untrusted folders, and that key is billed outside the subscription.",
        fix: "Remove the helper unless you mean to bill through an API key",
        steps: &[
            "Delete `apiKeyHelper` from the settings file.",
            "If a repository sets it, review the script it runs before trusting the folder.",
        ],
    },
    RuleText {
        id: "BILL-004",
        severity: Severity::Medium,
        why: "`CLAUDE_CODE_OAUTH_TOKEN` is a long-lived login token; in plain text it lets anyone who reads the file act as you.",
        fix: "Keep the token out of plain text",
        steps: &[
            "Remove the export and sign in with `claude login` instead.",
            "If a script needs it, load it from a secret manager at run time.",
            "Revoke the token in your Anthropic account if the file was shared.",
        ],
    },
    RuleText {
        id: "BILL-005",
        severity: Severity::Low,
        why: "With this switch on, Claude Code sends requests to the cloud provider and bills that account instead of your subscription.",
        fix: "Switch it off unless you mean to use the cloud provider",
        steps: &["Remove the variable, or set it only in the shell that needs it."],
    },
    RuleText {
        id: "BILL-006",
        severity: Severity::Medium,
        why: "Requests, and the API key with them, go to this host instead of the vendor.",
        fix: "Point the base URL back at the vendor unless you trust this gateway",
        steps: &[
            "Check who runs the host and why the base URL was set.",
            "Remove the override, or keep it only for the shell or project that needs it.",
            "If a repository set it, rotate the API key that was used while it applied.",
        ],
    },
    RuleText {
        id: "BILL-007",
        severity: Severity::Low,
        why: "Codex usage is billed to the API key or custom provider rather than counted against a ChatGPT plan.",
        fix: "Sign in with ChatGPT if you want plan billing",
        steps: &[
            "Run `codex logout`, then `codex login` and choose ChatGPT.",
            "Remove `model_provider` or `openai_base_url` from `config.toml` if they point at a custom provider you do not need.",
        ],
    },
    RuleText {
        id: "BILL-009",
        severity: Severity::Low,
        why: "Copilot CLI uses this token ahead of its own login, so sessions run as whatever that token can reach.",
        fix: "Unset the token for Copilot sessions",
        steps: &[
            "Remove the export, or set it only in the shell that needs it.",
            "Sign in with `copilot login` (or `gh auth login`) for the stored login to apply.",
        ],
    },
    RuleText {
        id: "RISK-001",
        severity: Severity::Low,
        why: "A floating version means the code this server runs can change under the agent without any configuration change.",
        fix: "Pin the server to an exact version",
        steps: &[
            "Replace the tag or missing version with an exact one: `pkg@1.2.3` for npx, `pkg==1.2.3` for uvx, `image@sha256:…` for Docker.",
            "Re-pin when you update, on purpose.",
        ],
    },
    RuleText {
        id: "RISK-002",
        severity: Severity::Medium,
        why: "The hook fetches code from the network and runs it, so whoever controls that URL controls what runs on your machine.",
        fix: "Run a reviewed local copy instead",
        steps: &[
            "Download the script once, read it, and keep it in the repository or your home.",
            "Point the hook at the local file.",
        ],
    },
    RuleText {
        id: "RISK-003",
        severity: Severity::Medium,
        why: "The hook sends event data, which can include prompts and file paths, to a server outside this machine.",
        fix: "Check where the hook posts and remove it if you did not set it up",
        steps: &[
            "Confirm the URL is a service you run or trust.",
            "Otherwise delete the hook.",
        ],
    },
    RuleText {
        id: "RISK-004",
        severity: Severity::Medium,
        why: "Every tool call runs without approval, so one bad instruction can act on your files and accounts.",
        fix: "Turn approvals back on",
        steps: &[
            "Claude Code: set `permissions.defaultMode` back to `default` or `acceptEdits`.",
            "Codex: use `approval_policy = \"on-request\"` or keep `sandbox_mode` at `workspace-write`.",
        ],
    },
    RuleText {
        id: "RISK-005",
        severity: Severity::Low,
        why: "The login tokens are kept in a plain file instead of the system keychain.",
        fix: "Store credentials in the keychain",
        steps: &["Codex: set `cli_auth_credentials_store = \"keyring\"` (or `auto`) and sign in again."],
    },
    RuleText {
        id: "RISK-006",
        severity: Severity::Medium,
        why: "Every MCP server a repository ships in `.mcp.json` starts without a prompt, including servers added by a pull.",
        fix: "Approve project servers one by one",
        steps: &["Set `enableAllProjectMcpServers` to `false` and let Claude Code ask per server."],
    },
    RuleText {
        id: "RISK-007",
        severity: Severity::Low,
        why: "The skill pre-approves every shell command while it runs.",
        fix: "Restrict `allowed-tools` to the commands the skill needs",
        steps: &["Replace `Bash` with specific rules such as `Bash(git status *)`."],
    },
    RuleText {
        id: "RISK-008",
        severity: Severity::High,
        why: "Code in a hidden or temporary folder is easy to plant and hard to notice, which is how a replaced server or hook hides.",
        fix: "Move the code somewhere visible or remove the entry",
        steps: &[
            "Check what the file is and who put it there.",
            "Keep servers and hooks under the agent's own directory or the repository.",
        ],
    },
    RuleText {
        id: "RISK-009",
        severity: Severity::Medium,
        why: "The container runs with host privileges, the host network or the host's root filesystem, which is as much access as running outside Docker.",
        fix: "Drop the privileged flags",
        steps: &[
            "Remove `--privileged`, `--network host` and host-root mounts.",
            "Mount only the folders the server needs.",
        ],
    },
];

/// The catalogue entry for a rule.
///
/// # Panics
///
/// Never: every rule the analyzers emit is in [`RULES`], which a unit test
/// checks.
#[must_use]
pub fn rule(id: &str) -> &'static RuleText {
    RULES.iter().find(|r| r.id == id).unwrap_or(&RULES[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_has_text_and_ids_are_unique() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
        for r in RULES {
            assert!(!r.why.is_empty());
            assert!(!r.fix.is_empty());
            assert!(!r.steps.is_empty());
            assert_eq!(rule(r.id).id, r.id);
        }
    }
}
