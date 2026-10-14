//! Findings over the fixture homes (`docs/HANDOFF.md` M2 exit criterion):
//! `mockup-demo` yields exactly the nine findings on the app's Findings
//! screen, and `messy` triggers every other rule a home can trigger, each
//! beside a look-alike that must not fire (`fixtures/README.md`).
//!
//! Git keeps no `0600` mode, so each test copies the home to a temporary
//! directory and sets the credential stand-ins' modes explicitly (finding
//! policy 7).

// Helper functions in an integration-test file are not inside `#[test]`, so
// clippy.toml's allow-*-in-tests options do not cover them.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers may panic; a panic here is a test failure"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use vigildex_core::{Finding, HomeEnv, Severity};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root exists")
}

/// Copies a fixture home into a fresh temporary directory and sets the
/// credential stand-ins' permission bits.
fn temp_home(name: &str, modes: &[(&str, u32)]) -> PathBuf {
    // Tests run in parallel inside one process: each copy gets its own
    // directory.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "vigildex-findings-{}-{n}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    copy_tree(&repo_root().join("fixtures/homes").join(name), &dir);
    for (rel, mode) in modes {
        set_mode(&dir.join(rel), *mode);
    }
    dir
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("target dir created");
    for entry in fs::read_dir(from).expect("source dir readable") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("file copied");
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode set");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn findings_of(home: &Path) -> Vec<Finding> {
    let env = HomeEnv::resolve(Some(home)).expect("home resolves");
    vigildex_core::findings(&env)
}

/// `rule | ~/path[:line][ › key]`, the shape used in the expectations.
fn summary(finding: &Finding, home: &Path) -> String {
    let rel = finding
        .location
        .path
        .strip_prefix(home)
        .map(|p| format!("~/{}", p.display()))
        .unwrap_or_else(|_| finding.location.path.display().to_string());
    let line = finding
        .location
        .line
        .map(|l| format!(":{l}"))
        .unwrap_or_default();
    let key = finding
        .location
        .key_path
        .as_deref()
        .map(|k| format!(" › {k}"))
        .unwrap_or_default();
    format!("{} | {rel}{line}{key}", finding.rule)
}

fn json(home: &Path, findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings)
        .expect("findings serialise")
        .replace(home.to_str().expect("UTF-8 temp path"), "[HOME]")
}

#[track_caller]
fn assert_no_secret_values(text: &str) {
    for needle in [
        "FAKE",
        "you@example.com",
        "fixture prompt",
        "FAKEQUERYTOKEN",
        "PLACEHOLDER",
    ] {
        assert!(
            !text.contains(needle),
            "{needle} leaked into the output:\n{text}"
        );
    }
}

#[test]
fn mockup_demo_yields_exactly_the_nine_screen_findings() {
    let home = temp_home(
        "mockup-demo",
        &[
            (".claude/.credentials.json", 0o600),
            (".codex/auth.json", 0o600),
        ],
    );
    let findings = findings_of(&home);
    let got: Vec<(String, String)> = findings
        .iter()
        .map(|f| (summary(f, &home), f.title.clone()))
        .collect();
    let expected: Vec<(&str, &str)> = vec![
        (
            "BILL-001 | ~/.zshrc:42 › ANTHROPIC_API_KEY",
            "API key bills headless runs",
        ),
        (
            "BILL-006 | ~/.claude/settings.json › env.ANTHROPIC_BASE_URL",
            "Custom API gateway",
        ),
        (
            "RISK-002 | ~/proj/dotfiles-sync/.claude/settings.json › hooks.SessionStart[0].hooks[0]",
            "Hook pipes curl to sh",
        ),
        (
            "RISK-004 | ~/.codex/config.toml:3 › approval_policy",
            "Auto-approves every tool",
        ),
        (
            "SEC-002 | ~/proj/acme-api/.mcp.json › mcpServers.postgres.args[2]",
            "Database password in args",
        ),
        (
            "SEC-004 | ~/.zshrc:43 › GITHUB_TOKEN",
            "GitHub token in plain text",
        ),
        (
            "BILL-007 | ~/.codex/auth.json › OPENAI_API_KEY",
            "Signed in with an API key",
        ),
        (
            "RISK-001 | ~/.claude.json › mcpServers.lint-helper",
            "MCP server on @latest",
        ),
        (
            "RISK-005 | ~/.codex/config.toml:5 › cli_auth_credentials_store",
            "Credentials in a plain file",
        ),
    ];
    let expected: Vec<(String, String)> = expected
        .into_iter()
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .collect();
    assert_eq!(got, expected, "{:#?}", findings);

    // Policy 1: the losing rules are tags on the winner.
    let by_rule = |rule: &str| findings.iter().find(|f| f.rule == rule).unwrap();
    assert_eq!(by_rule("BILL-001").tags, vec!["SEC-004"]);
    assert_eq!(by_rule("SEC-004").tags, vec!["BILL-009"]);
    assert_eq!(
        by_rule("BILL-001").evidence.as_deref(),
        Some("ANTHROPIC_API_KEY=sk-ant-••••7Qa")
    );
    assert_eq!(
        by_rule("SEC-004").evidence.as_deref(),
        Some("GITHUB_TOKEN=ghp_••••f9a")
    );
    assert_eq!(
        by_rule("SEC-002").evidence.as_deref(),
        Some("postgresql://app:••••@db.acme.internal:5432/acme")
    );
    // No digest of a secret exists before the store has a key (M4).
    assert!(findings.iter().all(|f| f.fingerprint.is_none()));
    // Every finding cites at least one inventory item.
    for finding in &findings {
        assert!(!finding.items.is_empty(), "{finding:#?}");
        assert!(!finding.agents.is_empty(), "{finding:#?}");
        assert_eq!(finding.id.len(), 16);
    }

    let text = json(&home, &findings);
    assert_no_secret_values(&text);
    insta::assert_snapshot!("mockup_demo_findings", text);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn credential_file_modes_are_read_from_the_real_file() {
    let home = temp_home(
        "mockup-demo",
        &[
            (".claude/.credentials.json", 0o644),
            (".codex/auth.json", 0o600),
        ],
    );
    let findings = findings_of(&home);
    let sec006: Vec<String> = findings
        .iter()
        .filter(|f| f.rule == "SEC-006")
        .map(|f| summary(f, &home))
        .collect();
    assert_eq!(sec006, vec!["SEC-006 | ~/.claude/.credentials.json"]);
    assert_eq!(findings.len(), 10);
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn messy_triggers_every_other_rule_and_no_look_alike() {
    let home = temp_home(
        "messy",
        &[
            (".claude/.credentials.json", 0o644),
            (".codex/auth.json", 0o600),
        ],
    );
    let findings = findings_of(&home);
    let summaries: BTreeSet<String> = findings.iter().map(|f| summary(f, &home)).collect();
    let titles: BTreeSet<(String, String)> = findings
        .iter()
        .map(|f| (summary(f, &home), f.title.clone()))
        .collect();
    let has = |s: &str| assert!(summaries.contains(s), "missing {s}\n{summaries:#?}");
    let titled = |s: &str, t: &str| {
        assert!(
            titles.contains(&(s.to_owned(), t.to_owned())),
            "missing {s} titled {t}\n{titles:#?}"
        );
    };
    let not = |s: &str| assert!(!summaries.contains(s), "look-alike fired: {s}");

    // .zshrc
    titled(
        "BILL-002 | ~/.zshrc:5 › ANTHROPIC_AUTH_TOKEN",
        "Auth token overrides your plan",
    );
    titled(
        "BILL-004 | ~/.zshrc:7 › CLAUDE_CODE_OAUTH_TOKEN",
        "OAuth token in plain text",
    );
    titled(
        "BILL-005 | ~/.zshrc:9 › CLAUDE_CODE_USE_BEDROCK",
        "Cloud provider switch is on",
    );
    titled(
        "SEC-004 | ~/.zshrc:11 › OPENAI_API_KEY",
        "OpenAI API key in plain text",
    );
    titled(
        "SEC-004 | ~/.zshrc:13 › COPILOT_GITHUB_TOKEN",
        "GitHub token in plain text",
    );
    titled(
        "BILL-009 | ~/.zshrc:20 › GITHUB_TOKEN",
        "Token overrides Copilot login",
    );
    for line in [2, 15, 17, 18, 21] {
        assert!(
            !findings
                .iter()
                .any(|f| f.location.path.ends_with(".zshrc") && f.location.line == Some(line)),
            "line {line} of .zshrc must not fire"
        );
    }
    let bill004 = findings.iter().find(|f| f.rule == "BILL-004").unwrap();
    assert_eq!(bill004.tags, vec!["SEC-004"]);
    let copilot = findings
        .iter()
        .find(|f| f.location.line == Some(13) && f.location.path.ends_with(".zshrc"))
        .unwrap();
    assert_eq!(copilot.rule, "SEC-004");
    assert_eq!(copilot.tags, vec!["BILL-009"]);

    // .claude.json
    titled(
        "SEC-001 | ~/.claude.json › mcpServers.lint-helper.env.LINT_HELPER_TOKEN",
        "Token in an MCP config",
    );
    titled(
        "RISK-001 | ~/.claude.json › mcpServers.lint-helper",
        "MCP server on @latest",
    );
    titled(
        "RISK-001 | ~/.claude.json › mcpServers.playwright",
        "MCP server on @latest",
    );
    titled(
        "RISK-009 | ~/.claude.json › mcpServers.sys-admin",
        "Docker server runs privileged",
    );
    not("RISK-001 | ~/.claude.json › mcpServers.sys-admin");
    not("RISK-001 | ~/.claude.json › mcpServers.pinned-ok");
    not("RISK-001 | ~/.claude.json › mcpServers.sys-tools");
    not("RISK-009 | ~/.claude.json › mcpServers.sys-tools");
    has("RISK-006 | ~/.claude.json › projects[\"/Users/you/proj/dotfiles-sync\"].enableAllProjectMcpServers");
    titled(
        "SEC-002 | ~/.claude.json › mcpServers.acme-docs-token.url",
        "Query credential in a server URL",
    );
    titled(
        "SEC-002 | ~/.claude.json › mcpServers.acme-helper.headersHelper",
        "GitHub token in a command",
    );
    let sys_admin = findings.iter().find(|f| f.rule == "RISK-009").unwrap();
    assert_eq!(sys_admin.tags, vec!["RISK-001"]);
    // Policy 3: lint-helper is one finding for both agents.
    let lint = findings
        .iter()
        .filter(|f| {
            f.rule == "RISK-001"
                && f.title == "MCP server on @latest"
                && f.evidence.as_deref() == Some("npx -y @acme/lint-helper@latest")
        })
        .collect::<Vec<_>>();
    assert_eq!(lint.len(), 1);
    assert_eq!(
        lint[0].agents,
        vec![
            vigildex_core::Agent::ClaudeCode,
            vigildex_core::Agent::Codex
        ]
    );
    assert_eq!(lint[0].items.len(), 2);

    // .claude/settings.json and settings.local.json
    titled(
        "RISK-004 | ~/.claude/settings.json › permissions.defaultMode",
        "Auto-approves every tool",
    );
    titled(
        "SEC-003 | ~/.claude/settings.json › env.OPENAI_API_KEY",
        "OpenAI API key in settings env",
    );
    titled(
        "BILL-006 | ~/.claude/settings.json › env.ANTHROPIC_BASE_URL",
        "Custom API gateway",
    );
    not("BILL-001 | ~/.claude/settings.json › env.ANTHROPIC_API_KEY");
    not("SEC-003 | ~/.claude/settings.json › env.ANTHROPIC_API_KEY");
    titled(
        "BILL-003 | ~/.claude/settings.json › apiKeyHelper",
        "Key helper bills headless runs",
    );
    titled(
        "RISK-006 | ~/.claude/settings.json › enableAllProjectMcpServers",
        "Trusts every project MCP server",
    );
    titled(
        "RISK-003 | ~/.claude/settings.json › hooks.Notification[0].hooks[0]",
        "Hook posts to a remote URL",
    );
    titled(
        "SEC-003 | ~/.claude/settings.json › hooks.Notification[0].hooks[0].url",
        "Query credential in a hook URL",
    );
    titled(
        "RISK-002 | ~/.claude/settings.json › hooks.PostToolUse[0].hooks[0]",
        "Hook downloads and runs code",
    );
    titled(
        "RISK-002 | ~/.claude/settings.json › hooks.SessionStart[0].hooks[0]",
        "Hook downloads and runs code",
    );
    not("RISK-003 | ~/.claude/settings.json › hooks.Stop[0].hooks[0]");
    titled(
        "RISK-002 | ~/.claude/settings.local.json › hooks.PreToolUse[0].hooks[0]",
        "Hook downloads and runs code",
    );
    not("RISK-008 | ~/.claude/settings.local.json › hooks.PreToolUse[0].hooks[0]");

    // Skills and the plugin
    titled(
        "RISK-007 | ~/.claude/skills/yolo/SKILL.md › allowed-tools",
        "Skill can run any command",
    );
    not("RISK-007 | ~/.claude/skills/tidy/SKILL.md › allowed-tools");
    titled("RISK-007 | ~/.claude/plugins/cache/acme-tools/acme-deploy/0.3.1/skills/deploy-check/SKILL.md › allowed-tools", "Skill can run any command");
    titled("SEC-001 | ~/.claude/plugins/cache/acme-tools/acme-deploy/0.3.1/.mcp.json › acme-deploy.headers.X-Api-Key", "API key in an MCP config");
    assert!(!summaries
        .iter()
        .any(|s| s.contains("acme-deploy/0.3.1/hooks/hooks.json")));

    // .codex
    not("RISK-004 | ~/.codex/config.toml:3 › approval_policy");
    not("RISK-005 | ~/.codex/config.toml:5 › cli_auth_credentials_store");
    titled(
        "BILL-006 | ~/.codex/config.toml:7 › openai_base_url",
        "Custom API gateway",
    );
    titled(
        "BILL-007 | ~/.codex/config.toml:8 › model_provider",
        "Uses a custom provider",
    );
    titled(
        "BILL-006 | ~/.codex/config.toml:12 › model_providers.proxy.base_url",
        "Custom API gateway",
    );
    not("BILL-006 | ~/.codex/config.toml:18 › model_providers.local.base_url");
    titled(
        "SEC-003 | ~/.codex/config.toml:22 › shell_environment_policy.set.ACME_API_TOKEN",
        "Token in settings env",
    );
    titled(
        "SEC-001 | ~/.codex/config.toml:27 › mcp_servers.lint-helper.env.LINT_HELPER_TOKEN",
        "Token in an MCP config",
    );
    titled(
        "SEC-001 | ~/.codex/config.toml:31 › mcp_servers.github.http_headers.Authorization",
        "GitHub token in an MCP config",
    );
    titled(
        "RISK-001 | ~/.codex/config.toml:33 › mcp_servers.fetch",
        "MCP server unpinned",
    );
    not("RISK-001 | ~/.codex/config.toml:37 › mcp_servers.pinned-ok");
    titled(
        "RISK-002 | ~/.codex/hooks.json › hooks.SessionStart[0].hooks[0]",
        "Hook pipes curl to sh",
    );
    assert!(!findings
        .iter()
        .any(|f| f.rule == "BILL-007" && f.title == "Signed in with an API key"));

    // proj/acme-api
    titled(
        "SEC-002 | ~/proj/acme-api/.mcp.json › mcpServers.postgres.args[2]",
        "Database password in args",
    );
    titled(
        "SEC-001 | ~/proj/acme-api/.mcp.json › mcpServers.github.headers.Authorization",
        "GitHub token in an MCP config",
    );
    not("SEC-001 | ~/proj/acme-api/.mcp.json › mcpServers.safe-ref.headers.Authorization");
    not("SEC-002 | ~/proj/acme-api/.mcp.json › mcpServers.postgres-ref.args[2]");
    not("SEC-002 | ~/proj/acme-api/.mcp.json › mcpServers.postgres-nopw.args[2]");
    titled(
        "BILL-003 | ~/proj/acme-api/.claude/settings.json › apiKeyHelper",
        "Key helper bills headless runs",
    );
    titled(
        "SEC-003 | ~/proj/acme-api/.claude/settings.json › env.DATABASE_URL",
        "Database password in settings env",
    );
    titled(
        "BILL-006 | ~/proj/acme-api/.claude/settings.json › env.ANTHROPIC_BASE_URL",
        "Sends your API key elsewhere",
    );
    not("RISK-004 | ~/proj/acme-api/.claude/settings.json › permissions.defaultMode");
    not("RISK-006 | ~/proj/acme-api/.claude/settings.json › enableAllProjectMcpServers");
    titled(
        "SEC-005 | ~/proj/acme-api/.env:1 › DATABASE_URL",
        "Database password in .env",
    );
    titled(
        "SEC-005 | ~/proj/acme-api/.env:2 › OPENAI_API_KEY",
        "OpenAI API key in .env",
    );
    titled(
        "BILL-006 | ~/proj/acme-api/.env:3 › ANTHROPIC_BASE_URL",
        "Sends your API key elsewhere",
    );
    assert!(!findings
        .iter()
        .any(|f| f.location.path.ends_with(".env") && f.location.line == Some(4)));
    titled(
        "RISK-004 | ~/proj/acme-api/.codex/config.toml:2 › approval_policy",
        "Auto-approves every tool",
    );
    not("BILL-006 | ~/proj/acme-api/.codex/config.toml:1 › openai_base_url");
    let repo_url = findings
        .iter()
        .find(|f| f.rule == "BILL-006" && f.location.path.ends_with(".env"))
        .unwrap();
    assert_eq!(repo_url.severity, Severity::High);
    assert!(repo_url.tags.contains(&"repo_file".to_owned()));

    // proj/dotfiles-sync
    titled(
        "RISK-008 | ~/proj/dotfiles-sync/.mcp.json › mcpServers.sync-bridge",
        "Server runs from a hidden folder",
    );
    titled(
        "RISK-008 | ~/proj/dotfiles-sync/.mcp.json › mcpServers.tmp-tool",
        "Server runs from a temp folder",
    );
    not("RISK-004 | ~/proj/dotfiles-sync/.claude/settings.json › permissions.defaultMode");
    titled(
        "RISK-002 | ~/proj/dotfiles-sync/.claude/settings.json › hooks.SessionStart[0].hooks[0]",
        "Hook pipes curl to sh",
    );

    // Policy 7: the trigger stand-in and the look-alike.
    has("SEC-006 | ~/.claude/.credentials.json");
    not("SEC-006 | ~/.codex/auth.json");

    // Every implemented rule fires somewhere in messy or the mockup.
    let rules: BTreeSet<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
    for rule in [
        "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "BILL-002", "BILL-003",
        "BILL-004", "BILL-005", "BILL-006", "BILL-007", "BILL-009", "RISK-001", "RISK-002",
        "RISK-003", "RISK-004", "RISK-006", "RISK-007", "RISK-008", "RISK-009",
    ] {
        assert!(
            rules.contains(rule),
            "{rule} never fired in messy: {rules:?}"
        );
    }

    let text = json(&home, &findings);
    assert_no_secret_values(&text);
    assert!(!text.contains("lh_FAKE") && !text.contains("adk_FAKE"));
    insta::assert_snapshot!("messy_findings", text);
    let _ = fs::remove_dir_all(&home);
}

/// Ids and identities depend on the home-relative location only, so the
/// same home scanned from two places gives the same ids.
#[test]
fn ids_are_the_same_wherever_the_home_sits() {
    let checkout = repo_root().join("fixtures/homes/mockup-demo");
    let copy = temp_home("mockup-demo", &[]);
    let from = |home: &Path| {
        let env = HomeEnv::resolve(Some(home)).expect("home resolves");
        let report = vigildex_core::scan(&env);
        let items: Vec<(String, String)> = report
            .inventory
            .items
            .iter()
            .map(|e| (e.id.clone(), e.identity.clone()))
            .collect();
        let findings: Vec<String> = report
            .findings
            .iter()
            .filter(|f| f.rule != "SEC-006")
            .map(|f| f.id.clone())
            .collect();
        (items, findings)
    };
    assert_eq!(from(&checkout), from(&copy));
    let _ = fs::remove_dir_all(&copy);
}

/// Inserting a line above a profile finding moves its line but not its id.
#[test]
fn profile_finding_ids_survive_a_line_shift() {
    let home = temp_home(
        "mockup-demo",
        &[
            (".claude/.credentials.json", 0o600),
            (".codex/auth.json", 0o600),
        ],
    );
    let before: Vec<(String, Option<u32>)> = findings_of(&home)
        .iter()
        .filter(|f| f.location.path.ends_with(".zshrc"))
        .map(|f| (f.id.clone(), f.location.line))
        .collect();
    let zshrc = home.join(".zshrc");
    let text = fs::read_to_string(&zshrc).unwrap();
    fs::write(&zshrc, format!("# inserted\n{text}")).unwrap();
    let after: Vec<(String, Option<u32>)> = findings_of(&home)
        .iter()
        .filter(|f| f.location.path.ends_with(".zshrc"))
        .map(|f| (f.id.clone(), f.location.line))
        .collect();
    assert_eq!(before.len(), 2);
    for ((id_a, line_a), (id_b, line_b)) in before.iter().zip(&after) {
        assert_eq!(id_a, id_b);
        assert_eq!(line_a.map(|l| l + 1), *line_b);
    }
    let _ = fs::remove_dir_all(&home);
}

/// Shell profiles and `.env` files are listed without a content hash.
#[test]
fn env_files_are_not_hashed() {
    let home = temp_home("messy", &[]);
    let env = HomeEnv::resolve(Some(&home)).expect("home resolves");
    let inventory = vigildex_core::inventory(&env);
    let mut saw_profile = false;
    for artifact in &inventory.artifacts {
        let env_like = matches!(
            artifact.kind,
            vigildex_core::ArtifactKind::ShellProfile | vigildex_core::ArtifactKind::EnvFile
        );
        assert_eq!(artifact.sha256.is_none(), env_like, "{artifact:?}");
        saw_profile |= env_like;
    }
    assert!(saw_profile);
    let _ = fs::remove_dir_all(&home);
}

/// Nothing from the fixture secrets reaches any report, warnings and text
/// output included.
#[test]
fn no_fixture_secret_reaches_any_report() {
    let home = temp_home("messy", &[]);
    let env = HomeEnv::resolve(Some(&home)).expect("home resolves");
    let scan = serde_json::to_string(&vigildex_core::scan(&env)).unwrap();
    let findings = serde_json::to_string(&vigildex_core::findings_report(&env)).unwrap();
    let inventory = serde_json::to_string(&vigildex_core::inventory_report(&env)).unwrap();
    for text in [scan, findings, inventory] {
        assert_no_secret_values(&text);
        assert!(!text.contains("lh_FAKE"), "{text}");
        assert!(!text.contains("acme_FAKE"), "{text}");
        assert!(!text.contains("adk_FAKE"), "{text}");
    }
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn basic_and_relocated_homes_have_no_secret_findings() {
    for name in ["basic", "relocated"] {
        let home = temp_home(name, &[]);
        let findings = findings_of(&home);
        assert!(
            findings
                .iter()
                .all(|f| f.category != vigildex_core::Category::Secret),
            "{name}: {findings:#?}"
        );
        let _ = fs::remove_dir_all(&home);
    }
}
