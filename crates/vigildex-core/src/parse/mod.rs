//! Format parsers shared by the adapters.
//!
//! Every parser works on `serde_json::Value`, whatever the file format: TOML
//! and YAML frontmatter are converted to the same shape first. Values are
//! navigated by key, never deserialised into strict structs, so an unknown
//! field or a missing key is never an error (hard rule 7).

pub mod frontmatter;
pub mod hooks;
pub mod json;
pub mod mcp;
pub mod settings;
pub mod skills;
pub mod toml;
