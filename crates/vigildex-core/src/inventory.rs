//! Running every adapter over one home.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::adapters;
use crate::agent_dirs::AgentDirs;
use crate::collect::Collector;
use crate::home::HomeEnv;
use crate::model::Item;
use crate::report::{Inventory, InventoryReport, SCHEMA_VERSION};

/// Builds the inventory of `home`.
///
/// Project roots are gathered from every adapter first (Claude Code and
/// Codex both record the folders they were run in), then each adapter
/// scans its own files in the home and in every root. The home itself is
/// never treated as a project root, so user files are not counted twice.
#[must_use]
pub fn inventory(home: &HomeEnv) -> Inventory {
    let dirs = AgentDirs::resolve(home);
    let adapters = adapters::all();

    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    for adapter in &adapters {
        for root in adapter.project_roots(home, &dirs) {
            if root != home.root() && root.is_dir() {
                roots.insert(root);
            }
        }
    }
    let roots: Vec<PathBuf> = roots.into_iter().collect();

    let mut out = Collector::new();
    out.warnings_from(dirs.warnings.iter().cloned());
    for adapter in &adapters {
        adapter.inventory(home, &dirs, &roots, &mut out);
    }
    let (mut items, mut artifacts, mut warnings) = out.finish();
    items.sort_by_cached_key(Item::sort_key);
    artifacts.sort_by(|a, b| a.path.cmp(&b.path).then(a.scope.cmp(&b.scope)));
    warnings.sort_by(|a, b| a.path.cmp(&b.path).then(a.message.cmp(&b.message)));
    warnings.dedup();

    Inventory {
        scanned: adapters.iter().map(|a| a.agent()).collect(),
        project_roots: roots,
        relocations: dirs.relocations,
        items,
        artifacts,
        warnings,
    }
}

/// Builds the `vigildex inventory --json` report for `home`.
#[must_use]
pub fn inventory_report(home: &HomeEnv) -> InventoryReport {
    InventoryReport {
        schema_version: SCHEMA_VERSION,
        engine_version: crate::VERSION.to_owned(),
        home: home.view(),
        inventory: inventory(home),
    }
}
