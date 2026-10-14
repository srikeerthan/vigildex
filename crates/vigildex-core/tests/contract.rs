//! Guards the `--json` contract.
//!
//! The snapshots are the JSON Schemas of the report types. If one changes,
//! bump `SCHEMA_VERSION` and add a note to `CHANGELOG.md` in the same change
//! (CLAUDE.md § Conventions).

use std::path::Path;

use vigildex_core::{FindingsReport, HomeEnv, InventoryReport, ScanReport, SCHEMA_VERSION};

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

/// Every report round-trips through its own JSON: no flattened item may
/// emit a key twice (a strict parser rejects the document).
#[test]
fn reports_round_trip_through_json() {
    for home in ["mockup-demo", "messy"] {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/homes")
            .join(home);
        let env = HomeEnv::resolve(Some(&root)).expect("home resolves");
        let scan = vigildex_core::scan(&env);
        let text = serde_json::to_string(&scan).unwrap();
        let back: ScanReport =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{home}: {e}"));
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&scan).unwrap()
        );
        let inventory = vigildex_core::inventory_report(&env);
        let text = serde_json::to_string(&inventory).unwrap();
        let back: InventoryReport =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{home}: {e}"));
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&inventory).unwrap()
        );
        let findings = vigildex_core::findings_report(&env);
        let text = serde_json::to_string(&findings).unwrap();
        let back: FindingsReport =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{home}: {e}"));
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&findings).unwrap()
        );
    }
}

#[test]
fn schema_version_matches_the_snapshot_generation() {
    // Changing this number is a contract change: update CHANGELOG.md too.
    assert_eq!(SCHEMA_VERSION, 3);
}
