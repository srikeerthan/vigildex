//! UniFFI bindings for the Vigildex engine.
//!
//! The macOS app embeds the engine through this crate: it is built as a
//! static library, packaged into `VigildexEngine.xcframework`, and called
//! from Swift through bindings that UniFFI generates (milestone M7; see
//! `docs/ARCHITECTURE.md` § FFI surface).
//!
//! At milestone M0 the surface is one function, enough to prove that the
//! scaffolding builds on macOS and Linux and passes the licence check. The
//! `Engine` object and its `*View` records arrive with the milestones that
//! implement them.
//!
//! # Unsafe code
//!
//! This crate contains no hand-written `unsafe`, and the workspace lint
//! `unsafe_code = "forbid"` keeps it that way. The only unsafe code is the
//! FFI glue that the UniFFI macros below generate.

uniffi::setup_scaffolding!();

/// Version of the embedded engine, for the app's About panel and for
/// checking that the app and engine builds match.
#[uniffi::export]
#[must_use]
pub fn engine_version() -> String {
    vigildex_core::VERSION.to_owned()
}

#[cfg(test)]
mod tests {
    /// The app compares this value with its own embedded engine version, so
    /// the FFI crate and the core must keep sharing the workspace version.
    #[test]
    fn engine_version_is_the_workspace_version() {
        assert_eq!(super::engine_version(), env!("CARGO_PKG_VERSION"));
    }
}
