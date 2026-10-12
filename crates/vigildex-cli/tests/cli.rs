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

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BOGUS_HOME: &str = "/nonexistent/vigildex-tests-must-not-read-the-real-home";

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

/// Replaces the machine-specific repository path and the crate version so
/// snapshots are portable and survive a version bump.
fn redact(text: &str) -> String {
    let root = repo_root();
    text.replace(root.to_str().expect("the repo path is UTF-8"), "[REPO]")
        .replace(env!("CARGO_PKG_VERSION"), "[VERSION]")
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
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["home"]["source"], "override");
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
