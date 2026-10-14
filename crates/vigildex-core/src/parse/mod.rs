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
pub mod shell;
pub mod skills;
pub mod toml;

use crate::model::ArtifactRef;
use crate::observe::Location;
use crate::parse::json::join_key;
use crate::parse::settings::LineResolver;

/// Where a parser is in a document: the source file, the key path reached
/// so far and, for formats with spans (TOML), how to turn a key path into a
/// line number.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// The file being parsed.
    pub source: &'a ArtifactRef,
    /// The key path of the value being parsed, as text (`projects["/x"]`),
    /// empty at the root.
    pub key_prefix: &'a str,
    /// The raw key segments of `key_prefix`.
    pub segments: &'a [&'a str],
    /// Line lookup for the raw segments of a key.
    pub line_of: LineResolver<'a>,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("source", self.source)
            .field("key_prefix", &self.key_prefix)
            .field("segments", &self.segments)
            .finish_non_exhaustive()
    }
}

/// A resolver for formats without line numbers.
pub fn no_lines(_: &[&str]) -> Option<u32> {
    None
}

impl<'a> Context<'a> {
    /// A context at the root of a document without line numbers (JSON,
    /// YAML frontmatter).
    #[must_use]
    pub fn root(source: &'a ArtifactRef) -> Self {
        Self {
            source,
            key_prefix: "",
            segments: &[],
            line_of: &no_lines,
        }
    }

    /// A context at the root of a document with line numbers (TOML).
    #[must_use]
    pub fn with_lines(source: &'a ArtifactRef, line_of: LineResolver<'a>) -> Self {
        Self {
            source,
            key_prefix: "",
            segments: &[],
            line_of,
        }
    }

    /// The key path text for `segments` below this context.
    #[must_use]
    pub fn key_path(&self, below: &[&str]) -> String {
        let mut path = self.key_prefix.to_owned();
        for segment in below {
            path = if segment.bytes().all(|b| b.is_ascii_digit()) && !segment.is_empty() {
                format!("{path}[{segment}]")
            } else {
                join_key(&path, segment)
            };
        }
        path
    }

    /// The line of `segments` below this context, when the format has lines.
    #[must_use]
    pub fn line(&self, below: &[&str]) -> Option<u32> {
        let mut all: Vec<&str> = self.segments.to_vec();
        all.extend_from_slice(below);
        (self.line_of)(&all)
    }

    /// A finding location for `segments` below this context.
    #[must_use]
    pub fn location(&self, below: &[&str]) -> Location {
        Location {
            path: self.source.path.clone(),
            line: self.line(below),
            key_path: Some(self.key_path(below)),
        }
    }
}
