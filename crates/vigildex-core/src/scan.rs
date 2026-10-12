//! The `vigildex scan` report.
//!
//! At milestone M0 no agent adapter exists, so a scan resolves the home
//! directory and reports nothing else. The report deliberately has no
//! inventory, findings or sessions sections yet: an empty list would read as
//! "nothing found" when the truth is "nothing looked for". Sections are added
//! by the milestones that implement them.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::home::{HomeEnv, HomeView};

/// Version of the CLI `--json` contract.
///
/// Convention (CLAUDE.md): any change to a `--json` output bumps this number
/// and gets a note in `CHANGELOG.md`.
pub const SCHEMA_VERSION: u32 = 1;

/// Output of `vigildex scan --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ScanReport {
    /// Version of this JSON contract; see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Version of the engine that produced the report.
    pub engine_version: String,
    /// The home directory that was scanned and how it was chosen.
    pub home: HomeView,
}

/// Scans the given home directory.
///
/// No adapters exist yet, so this reads nothing from disk: it returns the
/// report envelope for `home`.
#[must_use]
pub fn scan(home: &HomeEnv) -> ScanReport {
    ScanReport {
        schema_version: SCHEMA_VERSION,
        engine_version: crate::VERSION.to_owned(),
        home: home.view(),
    }
}
