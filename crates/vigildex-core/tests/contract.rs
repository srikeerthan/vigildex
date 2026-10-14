//! Guards the `--json` contract.
//!
//! The snapshots are the JSON Schemas of the report types. If one changes,
//! bump `SCHEMA_VERSION` and add a note to `CHANGELOG.md` in the same change
//! (CLAUDE.md § Conventions).

use vigildex_core::{FindingsReport, InventoryReport, ScanReport, SCHEMA_VERSION};

#[test]
fn scan_report_schema_is_stable() {
    let schema = schemars::schema_for!(ScanReport);
    insta::assert_json_snapshot!("scan_report_schema", schema);
}

#[test]
fn inventory_report_schema_is_stable() {
    let schema = schemars::schema_for!(InventoryReport);
    insta::assert_json_snapshot!("inventory_report_schema", schema);
}

#[test]
fn findings_report_schema_is_stable() {
    let schema = schemars::schema_for!(FindingsReport);
    insta::assert_json_snapshot!("findings_report_schema", schema);
}

#[test]
fn schema_version_matches_the_snapshot_generation() {
    // Changing this number is a contract change: update CHANGELOG.md too.
    assert_eq!(SCHEMA_VERSION, 3);
}
