//! The `vigildex scan` report.
//!
//! A scan is the union of every section the engine can produce. At
//! milestone M1 that is the inventory; findings (M2) and sessions (M3) join
//! it as they land. A section that does not exist yet is absent rather than
//! empty, so an empty list always means "looked and found nothing".

use crate::home::HomeEnv;
use crate::inventory::inventory;
use crate::report::{ScanReport, SCHEMA_VERSION};

/// Scans the given home directory.
#[must_use]
pub fn scan(home: &HomeEnv) -> ScanReport {
    ScanReport {
        schema_version: SCHEMA_VERSION,
        engine_version: crate::VERSION.to_owned(),
        home: home.view(),
        inventory: inventory(home),
    }
}
