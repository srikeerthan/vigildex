//! `vigildex-statusline`: the opt-in Claude Code status-line helper.
//!
//! This is a Phase 1b placeholder. The real helper (see
//! `docs/ARCHITECTURE.md` § Status-line helper) wraps the user's existing
//! status-line command, records only the plan-limit fields, and never fails
//! the status line. None of that exists yet, so apart from `--version` this
//! binary says so and exits non-zero rather than pretending to work. Nothing
//! installs it: the install flow is also Phase 1b.

use std::io::{self, Write};
use std::process::ExitCode;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for "not implemented" and bad usage.
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    let first = std::env::args_os().nth(1);
    match first.as_ref().and_then(|arg| arg.to_str()) {
        Some("--version" | "-V") => {
            // Ignore a closed stdout: there is nobody left to tell.
            let _ = writeln!(io::stdout().lock(), "{NAME} {VERSION}");
            ExitCode::SUCCESS
        }
        _ => {
            let _ = writeln!(
                io::stderr().lock(),
                "{NAME} {VERSION}: not implemented yet (Phase 1b). Only --version works."
            );
            ExitCode::from(EXIT_ERROR)
        }
    }
}
