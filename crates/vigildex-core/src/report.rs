//! The versioned report types behind `vigildex inventory --json` and
//! `vigildex scan --json`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::finding::Finding;
use crate::home::HomeView;
use crate::model::{Agent, ArtifactView, ItemEntry, Warning};

/// Version of the CLI `--json` contract.
///
/// Convention (CLAUDE.md): any change to a `--json` output bumps this number
/// and gets a note in `CHANGELOG.md`.
pub const SCHEMA_VERSION: u32 = 3;

/// Everything the adapters found in one home: what each agent can run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Inventory {
    /// The agents that were looked for. An agent missing from this list was
    /// not scanned, which is different from an agent with no items.
    pub scanned: Vec<Agent>,
    /// Repository roots the agents recorded (trust decisions, local MCP
    /// servers), located under the scanned home and found to exist.
    pub project_roots: Vec<PathBuf>,
    /// Relocation variables found in the home's shell profiles
    /// (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`), with the
    /// directory each resolved to.
    pub relocations: BTreeMap<String, PathBuf>,
    /// The items, sorted by agent, scope, type and name, each with its
    /// identifiers and tags.
    pub items: Vec<ItemEntry>,
    /// Every file that was read, with its hash.
    pub artifacts: Vec<ArtifactView>,
    /// Files that could not be read or understood. Never fatal.
    pub warnings: Vec<Warning>,
}

/// Output of `vigildex inventory --json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct InventoryReport {
    /// Version of this JSON contract; see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Version of the engine that produced the report.
    pub engine_version: String,
    /// When the scan ran, as RFC 3339 UTC.
    pub scanned_at: String,
    /// The home directory that was scanned and how it was chosen.
    pub home: HomeView,
    /// The inventory.
    pub inventory: Inventory,
}

/// Output of `vigildex findings --json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct FindingsReport {
    /// Version of this JSON contract; see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Version of the engine that produced the report.
    pub engine_version: String,
    /// When the scan ran, as RFC 3339 UTC.
    pub scanned_at: String,
    /// The home directory that was scanned and how it was chosen.
    pub home: HomeView,
    /// The findings, sorted by severity, rule and location.
    pub findings: Vec<Finding>,
    /// Files that could not be read or understood while scanning. Never
    /// fatal.
    pub warnings: Vec<Warning>,
}

/// Output of `vigildex scan --json`: the inventory and the findings.
/// Sessions (M3) join as a further section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ScanReport {
    /// Version of this JSON contract; see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Version of the engine that produced the report.
    pub engine_version: String,
    /// When the scan ran, as RFC 3339 UTC.
    pub scanned_at: String,
    /// The home directory that was scanned and how it was chosen.
    pub home: HomeView,
    /// The inventory.
    pub inventory: Inventory,
    /// The findings, sorted by severity, rule and location.
    pub findings: Vec<Finding>,
}
