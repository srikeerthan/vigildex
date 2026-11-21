//! Running every adapter over one home, and giving every item its
//! identifiers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::adapters;
use crate::agent_dirs::AgentDirs;
use crate::collect::Collector;
use crate::home::HomeEnv;
use crate::launch::runner_of_command;
use crate::model::{HookHandler, Item, ItemEntry, ItemTag, PluginComponent, Scope};
use crate::observe::Observation;
use crate::report::{Inventory, InventoryReport, SCHEMA_VERSION};

/// Everything a scan of one home collected, before analysis.
#[derive(Debug)]
pub struct Scanned {
    /// The inventory.
    pub inventory: Inventory,
    /// What the analyzers learn about values the items do not record.
    pub observations: Vec<Observation>,
    /// Where each agent keeps its files.
    pub dirs: AgentDirs,
}

/// Runs every adapter over `home`.
///
/// Project roots are gathered from every adapter first (Claude Code and
/// Codex both record the folders they were run in), then each adapter
/// scans its own files in the home and in every root. The home itself is
/// never treated as a project root, so user files are not counted twice.
#[must_use]
pub fn collect(home: &HomeEnv) -> Scanned {
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
    let collected = out.finish();
    let mut items = collected.items;
    let mut artifacts = collected.artifacts;
    let mut warnings = collected.warnings;
    items.sort_by_cached_key(Item::sort_key);
    artifacts.sort_by(|a, b| a.path.cmp(&b.path).then(a.scope.cmp(&b.scope)));
    warnings.sort_by(|a, b| a.path.cmp(&b.path).then(a.message.cmp(&b.message)));
    warnings.dedup();

    Scanned {
        inventory: Inventory {
            scanned: adapters.iter().map(|a| a.agent()).collect(),
            project_roots: roots,
            relocations: dirs.relocations.clone(),
            items: entries(items, home),
            artifacts,
            warnings,
        },
        observations: collected.observations,
        dirs,
    }
}

/// Builds the inventory of `home`.
#[must_use]
pub fn inventory(home: &HomeEnv) -> Inventory {
    collect(home).inventory
}

/// Builds the `vigildex inventory --json` report for `home`.
#[must_use]
pub fn inventory_report(home: &HomeEnv) -> InventoryReport {
    InventoryReport {
        schema_version: SCHEMA_VERSION,
        engine_version: crate::VERSION.to_owned(),
        scanned_at: crate::clock::now_rfc3339(),
        home: home.view(),
        inventory: inventory(home),
    }
}

/// Gives every item its `id`, `identity` and tags.
fn entries(items: Vec<Item>, home: &HomeEnv) -> Vec<ItemEntry> {
    let rel = |path: &Path| home.relative(path);
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    items
        .into_iter()
        .map(|item| {
            let identity_text = item.identity_text(&rel);
            let source = item.source();
            let occurrence = format!(
                "{identity_text}|{:?}|{}|{}|{}",
                source.agent,
                scope_text(&source.scope, &rel),
                rel(&source.path),
                item.locator()
            );
            let mut id = short_hash(&occurrence);
            // Two identical definitions in one file (the same hook twice)
            // get distinct ids.
            let count = seen.entry(id.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                id = short_hash(&format!("{occurrence}#{count}"));
            }
            ItemEntry {
                id,
                identity: short_hash(&identity_text),
                tags: tags_of(&item),
                item,
            }
        })
        .collect()
}

fn scope_text(scope: &Scope, rel: &dyn Fn(&Path) -> String) -> String {
    match scope {
        Scope::Managed => "managed".to_owned(),
        Scope::User => "user".to_owned(),
        Scope::Project { root } => format!("project:{}", rel(root)),
        Scope::Local { root } => format!("local:{}", rel(root)),
        Scope::Plugin { id } => format!("plugin:{id}"),
        #[allow(unreachable_patterns, reason = "Scope is non-exhaustive")]
        _ => "other".to_owned(),
    }
}

/// The inventory tags of finding policy 5.
fn tags_of(item: &Item) -> Vec<ItemTag> {
    let mut tags = Vec::new();
    match item {
        Item::Skill(skill) if !skill.scripts.is_empty() => tags.push(ItemTag::BundledScripts),
        Item::Hook(hook) => {
            if let HookHandler::Command { command, .. } = &hook.handler {
                if runner_of_command(command).is_some() {
                    tags.push(ItemTag::PackageRunner);
                }
            }
        }
        Item::Plugin(plugin) => {
            if plugin.components.contains(&PluginComponent::Monitors) {
                tags.push(ItemTag::PluginMonitors);
            }
            if plugin.components.contains(&PluginComponent::Bin) {
                tags.push(ItemTag::PluginBin);
            }
        }
        _ => {}
    }
    tags
}

/// The first 16 hex characters of a SHA-256, for identifiers.
#[must_use]
pub fn short_hash(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
