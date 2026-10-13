//! Runs the adapters over the redacted samples collected from a real Mac
//! (`fixtures/claude/<version>/`, `fixtures/codex/<version>/`).
//!
//! The samples are single files as the vendor wrote them, not a home
//! layout, so each test assembles a temporary home from them and snapshots
//! the inventory. This is the regression net for vendor format changes: a
//! new sample version gets a new test here.

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

use vigildex_core::HomeEnv;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root exists")
}

/// A fresh, empty directory to assemble a fake home in.
fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vigildex-real-samples-{}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp home created");
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

fn copy_file(from: &Path, to: &Path) {
    fs::create_dir_all(to.parent().expect("parent")).expect("parent created");
    fs::copy(from, to).expect("file copied");
}

/// The inventory of `home` as JSON with the temporary root replaced, so the
/// snapshot is portable.
fn inventory_json(home: &Path) -> String {
    let env = HomeEnv::resolve(Some(home)).expect("home resolves");
    let inventory = vigildex_core::inventory(&env);
    let json = serde_json::to_string_pretty(&inventory).expect("inventory serialises");
    json.replace(home.to_str().expect("UTF-8 temp path"), "[HOME]")
}

#[test]
fn claude_code_2_1_296_samples() {
    let samples = repo_root().join("fixtures/claude/2.1.296");
    let home = temp_home("claude-2.1.296");
    copy_file(&samples.join("claude.json"), &home.join(".claude.json"));
    copy_file(
        &samples.join("settings.json"),
        &home.join(".claude/settings.json"),
    );
    copy_file(
        &samples.join("settings.local.json"),
        &home.join(".claude/settings.local.json"),
    );
    copy_tree(&samples.join("plugins"), &home.join(".claude/plugins"));

    let json = inventory_json(&home);
    insta::assert_snapshot!("claude_2_1_296_inventory", json);

    // The account e-mail, identifiers and per-project prompt history in
    // claude.json must never reach a report. `oauthAccount` contributes its
    // key names only, so the e-mail address and the UUID values are the
    // things to look for.
    assert!(!json.contains("you@example.com"), "{json}");
    assert!(
        !json.contains("00000000-0000-4000-8000-000000000000"),
        "{json}"
    );
    assert!(!json.contains("machineID"), "{json}");
    assert!(!json.contains("userID"), "{json}");
    assert!(!json.contains("customApiKeyResponses"), "{json}");
    assert!(!json.contains("\"history\""), "{json}");

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn codex_0_46_0_samples() {
    let samples = repo_root().join("fixtures/codex/0.46.0");
    let home = temp_home("codex-0.46.0");
    copy_file(
        &samples.join("config.toml"),
        &home.join(".codex/config.toml"),
    );
    // The synthesised stand-in with the key names Codex writes.
    copy_file(
        &samples.join("auth.current.json"),
        &home.join(".codex/auth.json"),
    );
    copy_file(
        &samples.join("version.json"),
        &home.join(".codex/version.json"),
    );

    let json = inventory_json(&home);
    insta::assert_snapshot!("codex_0_46_0_inventory", json);

    // Credential values (even fake ones) must never reach a report.
    assert!(!json.contains("FAKE"), "{json}");
    assert!(!json.contains("eyJ"), "{json}");

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn codex_auth_variants_report_key_names_and_types_only() {
    let samples = repo_root().join("fixtures/codex/0.46.0");
    for variant in ["auth.api-key.json", "auth.chatgpt.json"] {
        let home = temp_home(&format!("codex-{variant}"));
        copy_file(&samples.join(variant), &home.join(".codex/auth.json"));
        let json = inventory_json(&home);
        insta::assert_snapshot!(format!("codex_0_46_0_{variant}"), json);
        assert!(!json.contains("FAKE"), "{json}");
        let _ = fs::remove_dir_all(&home);
    }
}
