//! The `vigildex scan` and `vigildex findings` reports.
//!
//! A scan is the union of every section the engine can produce: the
//! inventory (M1) and the findings (M2); sessions (M3) join later. A section
//! that does not exist yet is absent rather than empty, so an empty list
//! always means "looked and found nothing".

use crate::analyze;
use crate::finding::Finding;
use crate::home::HomeEnv;
use crate::inventory::collect;
use crate::report::{FindingsReport, ScanReport, SCHEMA_VERSION};

/// Scans the given home directory: inventory and findings.
#[must_use]
pub fn scan(home: &HomeEnv) -> ScanReport {
    let mut scanned = collect(home);
    let findings = analyze::findings(&scanned, home);
    scanned.inventory.warnings.extend(analyze::rule_warnings());
    ScanReport {
        schema_version: SCHEMA_VERSION,
        engine_version: crate::VERSION.to_owned(),
        scanned_at: crate::clock::now_rfc3339(),
        home: home.view(),
        inventory: scanned.inventory,
        findings,
    }
}

/// The findings of the given home directory.
#[must_use]
pub fn findings(home: &HomeEnv) -> Vec<Finding> {
    let scanned = collect(home);
    analyze::findings(&scanned, home)
}

/// Builds the `vigildex findings --json` report for `home`.
#[must_use]
pub fn findings_report(home: &HomeEnv) -> FindingsReport {
    let scanned = collect(home);
    let findings = analyze::findings(&scanned, home);
    let mut warnings = scanned.inventory.warnings;
    warnings.extend(analyze::rule_warnings());
    FindingsReport {
        schema_version: SCHEMA_VERSION,
        engine_version: crate::VERSION.to_owned(),
        scanned_at: crate::clock::now_rfc3339(),
        home: home.view(),
        findings,
        warnings,
    }
}
