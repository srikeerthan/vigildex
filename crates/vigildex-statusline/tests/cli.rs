//! End-to-end tests for the placeholder status-line helper.

// Helper functions in an integration-test file are not inside `#[test]`, so
// clippy.toml's allow-*-in-tests options do not cover them.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers may panic; a panic here is a test failure"
)]

use std::process::{Command, Output, Stdio};

fn helper() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vigildex-statusline"));
    // Hermetic: no inherited environment, no real home, no inherited stdin.
    cmd.env_clear()
        .env(
            "HOME",
            "/nonexistent/vigildex-tests-must-not-read-the-real-home",
        )
        .stdin(Stdio::null());
    cmd
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("the helper binary runs")
}

#[test]
fn version_prints_the_workspace_version() {
    let output = run(helper().arg("--version"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("vigildex-statusline {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn anything_else_says_not_implemented_and_prints_nothing_to_stdout() {
    for args in [&[][..], &["--wrap", "echo", "hi"][..]] {
        let output = run(helper().args(args));
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        // Claude Code shows the helper's stdout as the status line, so the
        // placeholder must never write there.
        assert!(output.stdout.is_empty(), "args: {args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("not implemented yet"),
            "args: {args:?}"
        );
    }
}
