//! The `vigildex` command-line interface.
//!
//! Exit codes: `0` ok; `1` findings at or above `--fail-on` (from M2);
//! `2` usage or I/O error.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use vigildex_core::{HomeEnv, HomeSource, ScanReport};

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
    /// Scan the home directory (no agent adapters yet: reports the home only)
    Scan {
        /// Print JSON; the output is a versioned contract (`schema_version`)
        #[arg(long)]
        json: bool,
    },
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
    match cli.command {
        Command::Scan { json } => {
            let report = vigildex_core::scan(&home);
            let text = if json {
                render_json(&report)?
            } else {
                render_text(&report)
            };
            print(&text)
        }
    }
}

fn render_json(report: &ScanReport) -> anyhow::Result<String> {
    let mut text =
        serde_json::to_string_pretty(report).context("could not encode the report as JSON")?;
    text.push('\n');
    Ok(text)
}

fn render_text(report: &ScanReport) -> String {
    let how = match report.home.source {
        HomeSource::Override => "from --home",
        HomeSource::Env => "from VIGILDEX_HOME",
        HomeSource::User => "your home directory",
        // `HomeSource` is non-exhaustive; describe anything newer neutrally.
        _ => "home directory",
    };
    format!(
        "vigildex {version}\n\
         Home: {home} ({how})\n\
         Nothing scanned: this build has no agent adapters yet.\n",
        version = report.engine_version,
        home = report.home.root.display(),
    )
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
