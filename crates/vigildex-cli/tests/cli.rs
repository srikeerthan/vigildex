//! End-to-end tests: run the real `vigildex` binary against fixture homes.
//!
//! Every command starts from an empty environment with `HOME` pointing at a
//! path that does not exist, so no test can read the developer's real home
//! directory, even by accident.

// Helper functions in an integration-test file are not inside `#[test]`, so
// clippy.toml's allow-*-in-tests options do not cover them.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers may panic; a panic here is a test failure"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BOGUS_HOME: &str = "/nonexistent/vigildex-tests-must-not-read-the-real-home";

/// The two credential stand-ins every fixture home carries. Git keeps no
/// `0600` mode, so tests that report findings copy the home and set the
/// modes explicitly (finding policy 7).
const CREDENTIAL_FILES: [&str; 2] = [".claude/.credentials.json", ".codex/auth.json"];

/// The repository root, with symlinks resolved.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root exists")
}

fn fixture_home(name: &str) -> PathBuf {
    repo_root().join("fixtures/homes").join(name)
}

/// A copy of a fixture home in a fresh temporary directory, with the
/// credential stand-ins set to `modes` (in `CREDENTIAL_FILES` order).
fn temp_home(name: &str, modes: [u32; 2]) -> PathBuf {
    // Tests run in parallel inside one process: each copy gets its own
    // directory.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("vigildex-cli-{}-{n}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    copy_tree(&fixture_home(name), &dir);
    for (rel, mode) in CREDENTIAL_FILES.iter().zip(modes) {
        set_mode(&dir.join(rel), mode);
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
    if path.is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode set");
    }
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// A hermetic `vigildex` command, run from the repository root.
fn vigildex() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vigildex"));
    cmd.env_clear()
        .env("HOME", BOGUS_HOME)
        .current_dir(repo_root());
    cmd
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("the vigildex binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

/// Replaces the machine-specific repository path, the crate version, the
/// scan time and file permission bits (which depend on the umask at
/// checkout) so snapshots are portable and survive a version bump.
fn redact(text: &str) -> String {
    let root = repo_root();
    let text = text
        .replace(root.to_str().expect("the repo path is UTF-8"), "[REPO]")
        .replace(env!("CARGO_PKG_VERSION"), "[VERSION]")
        .replace(
            "\"readable_by_others\": true",
            "\"readable_by_others\": \"[UMASK]\"",
        )
        .replace(
            "\"readable_by_others\": false",
            "\"readable_by_others\": \"[UMASK]\"",
        );
    redact_modes(&redact_time(&text))
}

/// The same, for a temporary copy of a fixture home: its path becomes
/// `[HOME]` and the modes are left as the test set them.
fn redact_temp(text: &str, home: &Path) -> String {
    let text = text
        .replace(home.to_str().expect("the temp path is UTF-8"), "[HOME]")
        .replace(env!("CARGO_PKG_VERSION"), "[VERSION]");
    redact_time(&text)
}

/// `"scanned_at": "2026-10-14T00:00:00Z"` → `"scanned_at": "[TIME]"`.
fn redact_time(text: &str) -> String {
    const KEY: &str = "\"scanned_at\": \"";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(KEY) {
        let (head, tail) = rest.split_at(pos + KEY.len());
        out.push_str(head);
        out.push_str("[TIME]");
        rest = tail.find('"').map_or("", |end| &tail[end..]);
    }
    out.push_str(rest);
    out
}

/// `"mode": "0644"` → `"mode": "[MODE]"` and `mode 0644` → `mode [MODE]`.
fn redact_modes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("mode") {
        let (head, tail) = rest.split_at(pos + "mode".len());
        out.push_str(head);
        let separators = ["\": \"", " "];
        let mut consumed = false;
        for sep in separators {
            if let Some(after) = tail.strip_prefix(sep) {
                let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
                if digits.len() == 4 {
                    out.push_str(sep);
                    out.push_str("[MODE]");
                    rest = &after[digits.len()..];
                    consumed = true;
                }
                break;
            }
        }
        if !consumed {
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

#[track_caller]
fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        stdout(output),
        stderr(output)
    );
}

/// Fixture homes carry same-shape fake secrets, an account e-mail and a fake
/// prompt. None of them may ever appear in a report.
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
fn version_prints_the_workspace_version() {
    let output = run(vigildex().arg("--version"));
    assert_exit(&output, 0);
    assert_eq!(
        stdout(&output),
        format!("vigildex {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(stderr(&output), "");
}

#[test]
fn scan_json_on_the_basic_fixture_home() {
    let output = run(vigildex()
        .args(["scan", "--json", "--home"])
        .arg(fixture_home("basic")));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    insta::assert_snapshot!("scan_json_basic", redact(&stdout(&output)));
}

#[test]
fn scan_json_carries_the_schema_version() {
    let output = run(vigildex()
        .args(["scan", "--json", "--home"])
        .arg(fixture_home("basic")));
    assert_exit(&output, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    assert_eq!(report["schema_version"], 3);
    assert_eq!(report["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["home"]["source"], "override");
    assert_eq!(
        report["inventory"]["scanned"],
        serde_json::json!(["claude_code", "codex", "shared"])
    );
}

#[test]
fn scan_text_on_the_basic_fixture_home() {
    let output = run(vigildex()
        .args(["scan", "--home"])
        .arg(fixture_home("basic")));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    insta::assert_snapshot!("scan_text_basic", redact(&stdout(&output)));
}

#[test]
fn scan_json_on_the_mockup_demo_fixture_home() {
    let home = temp_home("mockup-demo", [0o600, 0o600]);
    let output = run(vigildex().args(["scan", "--json", "--home"]).arg(&home));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    let report: serde_json::Value = serde_json::from_str(&text).expect("stdout is JSON");
    assert_eq!(report["findings"].as_array().expect("findings").len(), 9);
    insta::assert_snapshot!("scan_json_mockup_demo", redact_temp(&text, &home));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn scan_text_on_the_mockup_demo_fixture_home() {
    let home = temp_home("mockup-demo", [0o600, 0o600]);
    let output = run(vigildex().args(["scan", "--home"]).arg(&home));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    assert!(
        text.contains("Findings: 9 (1 high, 5 medium, 3 low)"),
        "{text}"
    );
    insta::assert_snapshot!("scan_text_mockup_demo", redact_temp(&text, &home));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn findings_text_on_the_mockup_demo_fixture_home() {
    let home = temp_home("mockup-demo", [0o600, 0o600]);
    let output = run(vigildex().args(["findings", "--home"]).arg(&home));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    for title in [
        "API key bills headless runs",
        "Custom API gateway",
        "Signed in with an API key",
        "GitHub token in plain text",
        "Database password in args",
        "Hook pipes curl to sh",
        "Auto-approves every tool",
        "MCP server on @latest",
        "Credentials in a plain file",
    ] {
        assert!(text.contains(title), "{title} missing:\n{text}");
    }
    insta::assert_snapshot!("findings_text_mockup_demo", redact_temp(&text, &home));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn findings_json_on_the_mockup_demo_fixture_home() {
    let home = temp_home("mockup-demo", [0o600, 0o600]);
    let output = run(vigildex().args(["findings", "--json", "--home"]).arg(&home));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    let report: serde_json::Value = serde_json::from_str(&text).expect("stdout is JSON");
    assert_eq!(report["schema_version"], 3);
    let findings = report["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 9);
    let rules: Vec<&str> = findings.iter().filter_map(|f| f["rule"].as_str()).collect();
    assert_eq!(
        rules,
        vec![
            "BILL-001", "BILL-006", "RISK-002", "RISK-004", "SEC-002", "SEC-004", "BILL-007",
            "RISK-001", "RISK-005"
        ]
    );
    insta::assert_snapshot!("findings_json_mockup_demo", redact_temp(&text, &home));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn findings_severity_filter_and_fail_on_exit_code() {
    let home = temp_home("mockup-demo", [0o600, 0o600]);
    // Only High and Medium, and High is present, so --fail-on high fails.
    let output = run(vigildex()
        .args([
            "findings",
            "--json",
            "--severity",
            "medium",
            "--fail-on",
            "high",
            "--home",
        ])
        .arg(&home));
    assert_exit(&output, 1);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    let findings = report["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 6);
    assert!(findings.iter().all(|f| f["severity"] != "low"));

    // The gate is judged before the display filter: hiding High findings
    // with --severity low... cannot pass --fail-on high.
    let output = run(vigildex()
        .args([
            "findings",
            "--severity",
            "info",
            "--fail-on",
            "high",
            "--home",
        ])
        .arg(&home));
    assert_exit(&output, 1);

    // Nothing at Info or above Info... every finding is Low or higher, so
    // --fail-on info fails too; a home without findings passes.
    let output = run(vigildex()
        .args(["findings", "--fail-on", "info", "--home"])
        .arg(&home));
    assert_exit(&output, 1);
    let output = run(vigildex()
        .args(["findings", "--fail-on", "high", "--home"])
        .arg(fixture_home("basic")));
    assert_exit(&output, 0);
    assert!(
        stdout(&output).contains("Findings: 0"),
        "{}",
        stdout(&output)
    );
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn findings_json_on_the_messy_fixture_home() {
    let home = temp_home("messy", [0o644, 0o600]);
    let output = run(vigildex().args(["findings", "--json", "--home"]).arg(&home));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    assert!(!text.contains("lh_FAKE") && !text.contains("adk_FAKE") && !text.contains("acme_FAKE"));
    let report: serde_json::Value = serde_json::from_str(&text).expect("stdout is JSON");
    let findings = report["findings"].as_array().expect("findings");
    // One credential stand-in readable by others, the other not.
    let sec006: Vec<&str> = findings
        .iter()
        .filter(|f| f["rule"] == "SEC-006")
        .filter_map(|f| f["location"]["path"].as_str())
        .collect();
    assert_eq!(sec006.len(), 1);
    assert!(sec006[0].ends_with(".claude/.credentials.json"));
    insta::assert_snapshot!("findings_json_messy", redact_temp(&text, &home));
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn findings_on_a_checkout_report_the_checkout_modes_honestly() {
    // No temp copy: the stand-ins have whatever mode the umask gave them,
    // so SEC-006 may or may not fire, but nothing else changes.
    let output = run(vigildex()
        .args(["findings", "--json", "--home"])
        .arg(fixture_home("mockup-demo")));
    assert_exit(&output, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    let others = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|f| f["rule"] != "SEC-006")
        .count();
    assert_eq!(others, 9);
}

#[test]
fn inventory_json_on_the_mockup_demo_fixture_home() {
    let output = run(vigildex()
        .args(["inventory", "--json", "--home"])
        .arg(fixture_home("mockup-demo")));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    let report: serde_json::Value = serde_json::from_str(&text).expect("stdout is JSON");
    assert_eq!(report["schema_version"], 3);
    let items = report["inventory"]["items"].as_array().expect("items");
    for type_name in [
        "mcp_server",
        "hook",
        "skill",
        "plugin",
        "instruction",
        "setting",
        "credential",
    ] {
        assert!(
            items.iter().any(|i| i["type"] == type_name),
            "no {type_name} item in the mockup-demo inventory"
        );
    }
    insta::assert_snapshot!("inventory_json_mockup_demo", redact(&text));
}

#[test]
fn inventory_text_on_the_mockup_demo_fixture_home() {
    let output = run(vigildex()
        .args(["inventory", "--home"])
        .arg(fixture_home("mockup-demo")));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    insta::assert_snapshot!("inventory_text_mockup_demo", redact(&text));
}

#[test]
fn inventory_filters_by_agent_and_type() {
    let output = run(vigildex()
        .args([
            "inventory",
            "--json",
            "--agent",
            "codex",
            "--type",
            "mcp-server",
            "--home",
        ])
        .arg(fixture_home("mockup-demo")));
    assert_exit(&output, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    let items = report["inventory"]["items"].as_array().expect("items");
    assert!(!items.is_empty());
    for item in items {
        assert_eq!(item["type"], "mcp_server");
        assert_eq!(item["source"]["agent"], "codex");
    }
    let names: Vec<&str> = items.iter().filter_map(|i| i["name"].as_str()).collect();
    assert_eq!(names, vec!["fetch", "github", "acme-docs"]);
    // The filter is a view: the scanned list still names every agent.
    assert_eq!(
        report["inventory"]["scanned"]
            .as_array()
            .expect("scanned")
            .len(),
        3
    );
}

#[test]
fn relocated_config_dirs_are_honoured_and_stale_defaults_are_warned() {
    let output = run(vigildex()
        .args(["inventory", "--json", "--home"])
        .arg(fixture_home("relocated")));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    // Nothing from the default locations is inventoried...
    assert!(!text.contains("stale-server"), "{text}");
    assert!(!text.contains("bypassPermissions"), "{text}");
    assert!(!text.contains("\"never\""), "{text}");
    // ...while the relocated files are.
    assert!(text.contains("work-docs"), "{text}");
    assert!(text.contains("work-fetch"), "{text}");
    let report: serde_json::Value = serde_json::from_str(&text).expect("stdout is JSON");
    let relocations = &report["inventory"]["relocations"];
    assert!(relocations["CLAUDE_CONFIG_DIR"]
        .as_str()
        .unwrap()
        .ends_with("/.claude-work"));
    assert!(relocations["CODEX_HOME"]
        .as_str()
        .unwrap()
        .ends_with("/.codex-work"));
    let warnings = report["inventory"]["warnings"]
        .as_array()
        .expect("warnings");
    assert_eq!(warnings.len(), 3, "{warnings:#?}");
    insta::assert_snapshot!("inventory_json_relocated", redact(&text));
}

#[test]
fn inventory_json_on_the_messy_fixture_home() {
    let output = run(vigildex()
        .args(["inventory", "--json", "--home"])
        .arg(fixture_home("messy")));
    assert_exit(&output, 0);
    assert_eq!(stderr(&output), "");
    let text = stdout(&output);
    assert_no_secret_values(&text);
    // A plaintext header value and a Docker image with a floating tag are
    // inventoried without leaking the value: names and launch only.
    assert!(text.contains("\"X-Api-Key\""), "{text}");
    assert!(text.contains("ghcr.io/acme/mcp-sys:latest"), "{text}");
    assert!(!text.contains("adk_"), "{text}");
    insta::assert_snapshot!("inventory_json_messy", redact(&text));
}

#[test]
fn inventory_text_on_the_basic_fixture_home() {
    let output = run(vigildex()
        .args(["inventory", "--home"])
        .arg(fixture_home("basic")));
    assert_exit(&output, 0);
    insta::assert_snapshot!("inventory_text_basic", redact(&stdout(&output)));
}

#[test]
fn home_flag_accepts_a_relative_path_and_any_position() {
    // The command documented in CLAUDE.md, with the global flag before the
    // subcommand this time.
    let output = run(vigildex().args(["--home", "fixtures/homes/basic", "scan", "--json"]));
    assert_exit(&output, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    assert_eq!(
        report["home"]["root"],
        fixture_home("basic").to_str().expect("UTF-8 path")
    );
}

#[test]
fn trailing_separator_does_not_change_the_root() {
    let mut with_slash = fixture_home("basic").into_os_string();
    with_slash.push("/");
    let output = run(vigildex()
        .args(["scan", "--json", "--home"])
        .arg(with_slash));
    assert_exit(&output, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    assert_eq!(
        report["home"]["root"],
        fixture_home("basic").to_str().expect("UTF-8 path")
    );
}

#[test]
fn env_var_selects_the_home() {
    let output = run(vigildex()
        .env("VIGILDEX_HOME", fixture_home("basic"))
        .args(["scan", "--json"]));
    assert_exit(&output, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    assert_eq!(report["home"]["source"], "env");
    assert_eq!(
        report["home"]["root"],
        fixture_home("basic").to_str().expect("UTF-8 path")
    );
}

#[test]
fn home_flag_wins_over_the_env_var() {
    let output = run(vigildex()
        .env("VIGILDEX_HOME", fixture_home("does-not-exist"))
        .args(["scan", "--json", "--home"])
        .arg(fixture_home("basic")));
    assert_exit(&output, 0);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");
    assert_eq!(report["home"]["source"], "override");
}

#[test]
fn missing_home_is_an_io_error() {
    let output = run(vigildex()
        .args(["scan", "--json", "--home"])
        .arg(fixture_home("does-not-exist")));
    assert_exit(&output, 2);
    assert_eq!(stdout(&output), "");
    let err = stderr(&output);
    assert!(
        err.starts_with("error: cannot access the home directory"),
        "{err}"
    );
    assert!(err.contains("does-not-exist"), "{err}");
}

#[test]
fn home_that_is_a_file_is_an_io_error() {
    let output = run(vigildex()
        .args(["scan", "--home"])
        .arg(repo_root().join("fixtures/README.md")));
    assert_exit(&output, 2);
    assert_eq!(stdout(&output), "");
    assert!(
        stderr(&output).contains("is not a directory"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn empty_env_var_is_an_error_not_a_fallback() {
    let output = run(vigildex().env("VIGILDEX_HOME", "").arg("scan"));
    assert_exit(&output, 2);
    assert_eq!(stdout(&output), "");
    assert!(
        stderr(&output).contains("VIGILDEX_HOME is set but empty"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn without_an_override_the_real_home_is_used_and_tests_cannot_reach_it() {
    // No --home and no VIGILDEX_HOME: the CLI falls back to $HOME, which the
    // harness points at a path that does not exist.
    let output = run(vigildex().arg("scan"));
    assert_exit(&output, 2);
    assert_eq!(stdout(&output), "");
    assert!(stderr(&output).contains(BOGUS_HOME), "{}", stderr(&output));
}

#[test]
fn missing_subcommand_is_a_usage_error() {
    let output = run(&mut vigildex());
    assert_exit(&output, 2);
    assert_eq!(stdout(&output), "");
    assert!(
        stderr(&output).contains("Usage: vigildex"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn unknown_flag_is_a_usage_error() {
    let output = run(vigildex().args(["scan", "--no-such-flag"]));
    assert_exit(&output, 2);
    assert_eq!(stdout(&output), "");
}

#[test]
fn unknown_agent_is_a_usage_error() {
    let output = run(vigildex()
        .args(["inventory", "--agent", "gemini", "--home"])
        .arg(fixture_home("basic")));
    assert_exit(&output, 2);
    assert_eq!(stdout(&output), "");
}

#[test]
fn time_redaction_handles_json() {
    assert_eq!(
        redact_time(r#"{"scanned_at": "2026-10-14T11:59:59Z", "home": {}}"#),
        r#"{"scanned_at": "[TIME]", "home": {}}"#
    );
    assert_eq!(redact_time("no time here"), "no time here");
}

#[test]
fn mode_redaction_handles_json_and_text() {
    assert_eq!(
        redact_modes(r#"{"mode": "0644", "readable_by_others": true}"#),
        r#"{"mode": "[MODE]", "readable_by_others": true}"#
    );
    assert_eq!(
        redact_modes("present  mode 0600  keys: a"),
        "present  mode [MODE]  keys: a"
    );
    assert_eq!(
        redact_modes("defaultMode = acceptEdits"),
        "defaultMode = acceptEdits"
    );
}
