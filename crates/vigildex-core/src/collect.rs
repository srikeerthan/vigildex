//! Reading files on behalf of adapters.
//!
//! Every byte an adapter looks at goes through a [`Collector`], which hashes
//! the file, records it as an artifact, caps the size, and turns I/O and
//! syntax errors into [`Warning`]s. Adapters therefore never panic on a
//! malformed file (hard rule 7) and never forget to list what they read.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::model::{Agent, ArtifactKind, ArtifactRef, ArtifactView, Item, Scope, Warning};

/// Files above this size are skipped with a warning. Agent configuration
/// files are kilobytes; `~/.claude.json` can reach a few megabytes.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Accumulates the items, artifacts and warnings of one scan.
#[derive(Debug, Default)]
pub struct Collector {
    items: Vec<Item>,
    artifacts: Vec<ArtifactView>,
    warnings: Vec<Warning>,
    seen: BTreeSet<PathBuf>,
}

impl Collector {
    /// An empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an item.
    pub fn push(&mut self, item: Item) {
        self.items.push(item);
    }

    /// Records several items.
    pub fn extend(&mut self, items: impl IntoIterator<Item = Item>) {
        self.items.extend(items);
    }

    /// Records a warning about one file.
    pub fn warn(&mut self, agent: Agent, path: impl Into<PathBuf>, message: impl Into<String>) {
        self.warnings.push(Warning::new(agent, path, message));
    }

    /// Records warnings produced elsewhere.
    pub fn warnings_from(&mut self, warnings: impl IntoIterator<Item = Warning>) {
        self.warnings.extend(warnings);
    }

    /// Reads a file and records it as an artifact.
    ///
    /// Returns `None`, without a warning, when the file does not exist: most
    /// documented paths are absent on most machines. Any other failure is a
    /// warning.
    pub fn read(&mut self, artifact: &ArtifactRef) -> Option<Vec<u8>> {
        let path = &artifact.path;
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return None,
            Err(err) => {
                self.warn(artifact.agent, path, format!("cannot read: {err}"));
                return None;
            }
        };
        // Follow a symlink to a file, but never read a directory as a file.
        let target = if meta.file_type().is_symlink() {
            match fs::metadata(path) {
                Ok(meta) => meta,
                Err(err) => {
                    self.warn(artifact.agent, path, format!("broken symlink: {err}"));
                    return None;
                }
            }
        } else {
            meta
        };
        if !target.is_file() {
            self.warn(artifact.agent, path, "not a regular file");
            return None;
        }
        if target.len() > MAX_FILE_BYTES {
            self.warn(
                artifact.agent,
                path,
                format!(
                    "skipped: {} bytes is above the {} byte limit",
                    target.len(),
                    MAX_FILE_BYTES
                ),
            );
            return None;
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.warn(artifact.agent, path, format!("cannot read: {err}"));
                return None;
            }
        };
        if self.seen.insert(path.clone()) {
            self.artifacts.push(ArtifactView {
                agent: artifact.agent,
                scope: artifact.scope.clone(),
                kind: artifact.kind,
                path: path.clone(),
                bytes: bytes.len() as u64,
                sha256: sha256_hex(&bytes),
            });
        }
        Some(bytes)
    }

    /// Reads a file as text. Invalid UTF-8 is replaced, with a warning.
    pub fn read_text(&mut self, artifact: &ArtifactRef) -> Option<String> {
        let bytes = self.read(artifact)?;
        match String::from_utf8(bytes) {
            Ok(text) => Some(text),
            Err(err) => {
                self.warn(
                    artifact.agent,
                    &artifact.path,
                    "not valid UTF-8; decoded lossily",
                );
                Some(String::from_utf8_lossy(err.as_bytes()).into_owned())
            }
        }
    }

    /// Reads and parses a JSON file. A syntax error is a warning and `None`.
    pub fn read_json(&mut self, artifact: &ArtifactRef) -> Option<serde_json::Value> {
        let bytes = self.read(artifact)?;
        match serde_json::from_slice(&bytes) {
            Ok(value) => Some(value),
            Err(err) => {
                self.warn(
                    artifact.agent,
                    &artifact.path,
                    format!("not valid JSON: {err}"),
                );
                None
            }
        }
    }

    /// Reads and parses a TOML file into the same `Value` shape as JSON.
    pub fn read_toml(&mut self, artifact: &ArtifactRef) -> Option<serde_json::Value> {
        let text = self.read_text(artifact)?;
        match crate::parse::toml::to_json(&text) {
            Ok(value) => Some(value),
            Err(err) => {
                self.warn(
                    artifact.agent,
                    &artifact.path,
                    format!("not valid TOML: {err}"),
                );
                None
            }
        }
    }

    /// Takes everything collected so far.
    #[must_use]
    pub fn finish(self) -> (Vec<Item>, Vec<ArtifactView>, Vec<Warning>) {
        (self.items, self.artifacts, self.warnings)
    }
}

/// Lower-case hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Builds an [`ArtifactRef`].
#[must_use]
pub fn artifact(
    agent: Agent,
    scope: Scope,
    kind: ArtifactKind,
    path: impl Into<PathBuf>,
) -> ArtifactRef {
    ArtifactRef {
        agent,
        scope,
        kind,
        path: path.into(),
    }
}

/// The entries of a directory, sorted by name. A missing or unreadable
/// directory is an empty list: discovery treats it as "nothing there".
#[must_use]
pub fn list_dir(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    paths
}

/// Sub-directories of `dir`, sorted, skipping hidden ones. Symlinked
/// directories are followed (Claude Code follows symlinked skill folders).
#[must_use]
pub fn subdirs(dir: &Path) -> Vec<PathBuf> {
    list_dir(dir)
        .into_iter()
        .filter(|p| p.is_dir() && !is_hidden(p))
        .collect()
}

/// Whether the last path component starts with a dot.
#[must_use]
pub fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with('.'))
}

/// Markdown files under `dir`, recursively (bounded depth), sorted, skipping
/// hidden entries.
#[must_use]
pub fn markdown_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_files(dir, 0, &mut out, |p| {
        p.extension().and_then(|e| e.to_str()) == Some("md")
    });
    out.sort();
    out
}

/// Maximum directory depth for recursive listings, so a symlink loop or a
/// huge tree cannot stall a scan.
const MAX_DEPTH: usize = 6;

/// Files under `dir` for which `keep` holds, recursively, skipping hidden
/// entries. The result is unsorted; callers sort.
pub fn collect_files(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    keep: impl Fn(&Path) -> bool + Copy,
) {
    if depth > MAX_DEPTH {
        return;
    }
    for entry in list_dir(dir) {
        if is_hidden(&entry) {
            continue;
        }
        if entry.is_dir() {
            collect_files(&entry, depth + 1, out, keep);
        } else if entry.is_file() && keep(&entry) {
            out.push(entry);
        }
    }
}

/// Unix permission bits of a path, as `(octal text, readable by others)`.
/// `None` on platforms without permission bits or when the file is missing.
#[must_use]
pub fn permissions(path: &Path) -> Option<(String, bool)> {
    let meta = fs::metadata(path).ok()?;
    mode_view(&meta)
}

#[cfg(unix)]
fn mode_view(meta: &fs::Metadata) -> Option<(String, bool)> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    Some((format!("{mode:04o}"), mode & 0o044 != 0))
}

#[cfg(not(unix))]
fn mode_view(_meta: &fs::Metadata) -> Option<(String, bool)> {
    None
}

/// Number of lines in a text, counting a final line without a newline.
#[must_use]
pub fn line_count(text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let newlines = text.bytes().filter(|b| *b == b'\n').count();
    let count = if text.ends_with('\n') {
        newlines
    } else {
        newlines + 1
    };
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_known_digest_of_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn line_count_handles_missing_trailing_newline() {
        assert_eq!(line_count(""), 0);
        assert_eq!(line_count("a"), 1);
        assert_eq!(line_count("a\n"), 1);
        assert_eq!(line_count("a\nb"), 2);
        assert_eq!(line_count("a\nb\n"), 2);
    }

    #[test]
    fn missing_files_are_not_warnings() {
        let mut c = Collector::new();
        let art = artifact(
            Agent::ClaudeCode,
            Scope::User,
            ArtifactKind::Settings,
            "/nonexistent/vigildex/settings.json",
        );
        assert!(c.read(&art).is_none());
        let (items, artifacts, warnings) = c.finish();
        assert!(items.is_empty());
        assert!(artifacts.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_directory_is_a_warning_not_a_panic() {
        let mut c = Collector::new();
        let art = artifact(
            Agent::ClaudeCode,
            Scope::User,
            ArtifactKind::Settings,
            env!("CARGO_MANIFEST_DIR"),
        );
        assert!(c.read(&art).is_none());
        let (_, _, warnings) = c.finish();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("not a regular file"));
    }

    #[test]
    fn invalid_json_is_a_warning() {
        let dir = std::env::temp_dir().join(format!("vigildex-collect-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bad.json");
        fs::write(&file, b"{ not json").unwrap();
        let mut c = Collector::new();
        let art = artifact(Agent::Codex, Scope::User, ArtifactKind::Settings, &file);
        assert!(c.read_json(&art).is_none());
        let (_, artifacts, warnings) = c.finish();
        assert_eq!(artifacts.len(), 1, "the file was still recorded as read");
        assert!(warnings[0].message.starts_with("not valid JSON"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
