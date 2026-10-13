//! Home directory resolution.
//!
//! Every path the engine reads is derived from a [`HomeEnv`], never from
//! `$HOME` directly. That is what lets the CLI `--home` flag, the
//! [`HOME_ENV_VAR`] environment variable and the tests point the engine at a
//! fake home folder under `fixtures/homes/`.
//!
//! Relocation variables (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`)
//! are read from the shell profiles inside the home, not from this process's
//! environment. They arrive with the shared shell-profile adapter in M1.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Environment variable that points the engine at a different home directory.
///
/// An explicit override (the CLI `--home` flag or the FFI configuration) wins
/// over this variable.
pub const HOME_ENV_VAR: &str = "VIGILDEX_HOME";

/// How the home directory was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HomeSource {
    /// Passed explicitly: the CLI `--home` flag or the FFI configuration.
    Override,
    /// Taken from the `VIGILDEX_HOME` environment variable.
    Env,
    /// The current user's own home directory.
    User,
}

impl fmt::Display for HomeSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Override => "the home override",
            Self::Env => HOME_ENV_VAR,
            Self::User => "the user's home directory",
        })
    }
}

/// The home directory the engine reads agent files from.
///
/// Build one with [`HomeEnv::resolve`]; there is no other constructor, so a
/// `HomeEnv` always holds an absolute path to a directory that existed when
/// it was resolved. The path is kept as the user wrote it apart from being
/// made absolute: `..` components and symlinks are not resolved, so
/// `/Users/you` stays `/Users/you` even when the home is a symlink. Anything
/// that keys on the path (the store, in M4) must canonicalize on its own.
///
/// Reports carry a [`HomeView`], plain data, instead of this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeEnv {
    /// Absolute path of the home directory.
    root: PathBuf,
    /// How `root` was chosen.
    source: HomeSource,
}

impl HomeEnv {
    /// Resolves the home directory for this process.
    ///
    /// Precedence, highest first:
    ///
    /// 1. `override_dir`: the CLI `--home` flag or the FFI configuration;
    /// 2. the [`HOME_ENV_VAR`] environment variable;
    /// 3. the current user's home directory.
    ///
    /// The first source that is present is used. A source that is present but
    /// unusable (empty, missing, inaccessible, or not a directory) is an
    /// error; resolution never falls through to the real home, so a mistyped
    /// override cannot make the engine read files the caller meant to avoid.
    ///
    /// # Errors
    ///
    /// Returns a [`HomeError`] when the chosen path is empty, cannot be
    /// accessed, or is not a directory, or when no home directory can be
    /// found at all.
    pub fn resolve(override_dir: Option<&Path>) -> Result<Self, HomeError> {
        Self::resolve_with(
            override_dir,
            std::env::var_os(HOME_ENV_VAR),
            std::env::home_dir,
        )
    }

    /// Pure form of [`HomeEnv::resolve`]: the environment is passed in, so
    /// tests never touch process-wide state or the developer's real home.
    fn resolve_with(
        override_dir: Option<&Path>,
        env_value: Option<OsString>,
        user_home: impl FnOnce() -> Option<PathBuf>,
    ) -> Result<Self, HomeError> {
        let (candidate, source) = if let Some(dir) = override_dir {
            (dir.to_path_buf(), HomeSource::Override)
        } else if let Some(value) = env_value {
            (PathBuf::from(value), HomeSource::Env)
        } else {
            let dir = user_home().ok_or(HomeError::NoUserHome)?;
            (dir, HomeSource::User)
        };
        Self::checked(candidate, source)
    }

    fn checked(candidate: PathBuf, source: HomeSource) -> Result<Self, HomeError> {
        if candidate.as_os_str().is_empty() {
            return Err(HomeError::Empty { origin: source });
        }
        // `absolute` does not touch the file system and keeps symlinks and
        // `..`, so the path stays the one the user knows.
        let root = match std::path::absolute(&candidate) {
            Ok(root) => root,
            Err(err) => {
                return Err(HomeError::Inaccessible {
                    path: candidate,
                    origin: source,
                    source: err,
                })
            }
        };
        // Rebuilding from components drops a trailing separator, so
        // `~/fake/` and `~/fake` produce the same root.
        let root: PathBuf = root.components().collect();
        // `metadata` only needs search permission on the parents: this checks
        // that the directory exists and is reachable, not that it is readable.
        match std::fs::metadata(&root) {
            Ok(meta) if meta.is_dir() => Ok(Self { root, source }),
            Ok(_) => Err(HomeError::NotADirectory {
                path: root,
                origin: source,
            }),
            Err(err) => Err(HomeError::Inaccessible {
                path: root,
                origin: source,
                source: err,
            }),
        }
    }

    /// Absolute path of the home directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// How the home directory was chosen.
    #[must_use]
    pub fn source(&self) -> HomeSource {
        self.source
    }

    /// The plain-data form of this home, for reports.
    #[must_use]
    pub fn view(&self) -> HomeView {
        HomeView {
            root: self.root.clone(),
            source: self.source,
        }
    }

    /// Finds a path an agent recorded in its own files.
    ///
    /// Agents write absolute paths (`/Users/you/proj/acme`). When such a path
    /// exists it is used as written. When it does not, and it sits under a
    /// home-like prefix (`/Users/<name>`, `/home/<name>`, `/root`,
    /// `C:\Users\<name>`), the same relative path is tried under this home.
    /// That is what lets a fixture home refer to its own folders with the
    /// paths a real agent would have written. When neither exists, the path
    /// is returned as written, so callers can report it as missing.
    #[must_use]
    pub fn locate(&self, recorded: &Path) -> PathBuf {
        if recorded.exists() {
            return recorded.to_path_buf();
        }
        if let Some(rest) = strip_home_prefix(recorded) {
            let candidate = if rest.as_os_str().is_empty() {
                self.root.clone()
            } else {
                self.root.join(rest)
            };
            if candidate.exists() {
                return candidate;
            }
        }
        recorded.to_path_buf()
    }
}

/// `/Users/<name>/rest`, `/home/<name>/rest`, `/root/rest` or
/// `C:\Users\<name>\rest` → `rest`.
fn strip_home_prefix(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut parts = path
        .components()
        .filter(|c| !matches!(c, Component::Prefix(_) | Component::RootDir));
    let first = parts.next()?;
    let Component::Normal(first) = first else {
        return None;
    };
    match first.to_str()? {
        "Users" | "home" => {
            // Skip the user name.
            parts.next()?;
        }
        "root" => {}
        _ => return None,
    }
    Some(parts.collect())
}

/// A resolved home directory as it appears in reports: plain data with no
/// validation, so a report can be read on a machine where the directory
/// does not exist. See [`HomeEnv`] for the validated form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct HomeView {
    /// Absolute path of the home directory.
    pub root: PathBuf,
    /// How `root` was chosen.
    pub source: HomeSource,
}

/// Why a home directory could not be resolved.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HomeError {
    /// The chosen source held an empty path.
    #[error("{origin} is set but empty; it must name a directory")]
    Empty {
        /// Where the empty path came from.
        origin: HomeSource,
    },

    /// The path does not exist or cannot be accessed.
    #[error("cannot access the home directory {} (from {origin})", path.display())]
    Inaccessible {
        /// The path that was tried.
        path: PathBuf,
        /// Where the path came from.
        origin: HomeSource,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// The path exists but is not a directory.
    #[error("the home path {} (from {origin}) is not a directory", path.display())]
    NotADirectory {
        /// The path that was tried.
        path: PathBuf,
        /// Where the path came from.
        origin: HomeSource,
    },

    /// No override was given and the operating system reported no home.
    #[error(
        "could not find the current user's home directory; pass a home override or set {HOME_ENV_VAR}"
    )]
    NoUserHome,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that always exists: this crate's own folder.
    fn existing_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// A regular file that always exists: this crate's manifest.
    fn existing_file() -> PathBuf {
        existing_dir().join("Cargo.toml")
    }

    fn missing_dir() -> PathBuf {
        existing_dir().join("no-such-home-directory")
    }

    /// A user-home lookup that fails the test if resolution reaches it.
    fn must_not_ask_for_user_home() -> Option<PathBuf> {
        panic!("resolution fell through to the user's real home directory");
    }

    #[test]
    fn override_wins_over_env_and_user_home() {
        let dir = existing_dir();
        let env = HomeEnv::resolve_with(
            Some(&dir),
            Some(missing_dir().into_os_string()),
            must_not_ask_for_user_home,
        )
        .unwrap();
        assert_eq!(env.root(), dir);
        assert_eq!(env.source(), HomeSource::Override);
    }

    #[test]
    fn env_var_wins_over_user_home() {
        let dir = existing_dir();
        let env = HomeEnv::resolve_with(
            None,
            Some(dir.clone().into_os_string()),
            must_not_ask_for_user_home,
        )
        .unwrap();
        assert_eq!(env.root(), dir);
        assert_eq!(env.source(), HomeSource::Env);
    }

    #[test]
    fn falls_back_to_the_user_home() {
        let dir = existing_dir();
        let env = HomeEnv::resolve_with(None, None, || Some(dir.clone())).unwrap();
        assert_eq!(env.root(), dir);
        assert_eq!(env.source(), HomeSource::User);
    }

    #[test]
    fn relative_override_becomes_absolute() {
        // Cargo runs unit tests with the crate folder as the working
        // directory; `absolute` joins onto that same directory.
        let env = HomeEnv::resolve_with(Some(Path::new("src")), None, must_not_ask_for_user_home)
            .unwrap();
        assert!(env.root().is_absolute());
        assert_eq!(env.root(), std::env::current_dir().unwrap().join("src"));
    }

    #[test]
    fn trailing_separator_is_dropped() {
        let mut with_slash = existing_dir().into_os_string();
        with_slash.push(std::path::MAIN_SEPARATOR_STR);
        let env = HomeEnv::resolve_with(
            Some(Path::new(&with_slash)),
            None,
            must_not_ask_for_user_home,
        )
        .unwrap();
        assert_eq!(env.root(), existing_dir());
    }

    #[test]
    fn view_is_plain_data_with_the_same_fields() {
        let dir = existing_dir();
        let env = HomeEnv::resolve_with(Some(&dir), None, must_not_ask_for_user_home).unwrap();
        let view = env.view();
        assert_eq!(view.root, dir);
        assert_eq!(view.source, HomeSource::Override);
    }

    #[test]
    fn empty_override_is_an_error_and_does_not_fall_through() {
        let err = HomeEnv::resolve_with(
            Some(Path::new("")),
            Some(existing_dir().into_os_string()),
            must_not_ask_for_user_home,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            HomeError::Empty {
                origin: HomeSource::Override
            }
        ));
    }

    #[test]
    fn empty_env_var_is_an_error_and_does_not_fall_through() {
        let err = HomeEnv::resolve_with(None, Some(OsString::new()), must_not_ask_for_user_home)
            .unwrap_err();
        assert!(matches!(
            err,
            HomeError::Empty {
                origin: HomeSource::Env
            }
        ));
        assert_eq!(
            err.to_string(),
            "VIGILDEX_HOME is set but empty; it must name a directory"
        );
    }

    #[test]
    fn missing_directory_is_inaccessible() {
        let missing = missing_dir();
        let err =
            HomeEnv::resolve_with(Some(&missing), None, must_not_ask_for_user_home).unwrap_err();
        match err {
            HomeError::Inaccessible {
                path,
                origin,
                source,
            } => {
                assert_eq!(path, missing);
                assert_eq!(origin, HomeSource::Override);
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected Inaccessible, got {other:?}"),
        }
    }

    #[test]
    fn missing_env_directory_does_not_fall_through() {
        let err = HomeEnv::resolve_with(
            None,
            Some(missing_dir().into_os_string()),
            must_not_ask_for_user_home,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            HomeError::Inaccessible {
                origin: HomeSource::Env,
                ..
            }
        ));
    }

    #[test]
    fn file_is_not_a_directory() {
        let file = existing_file();
        let err = HomeEnv::resolve_with(Some(&file), None, must_not_ask_for_user_home).unwrap_err();
        assert!(matches!(
            err,
            HomeError::NotADirectory {
                origin: HomeSource::Override,
                ..
            }
        ));
    }

    #[test]
    fn locate_keeps_existing_paths_and_remaps_home_like_ones() {
        let dir = existing_dir();
        let env = HomeEnv::resolve_with(Some(&dir), None, must_not_ask_for_user_home).unwrap();
        // Exists as written: unchanged.
        assert_eq!(env.locate(&dir.join("src")), dir.join("src"));
        // A recorded path under another user's home maps onto this home.
        assert_eq!(env.locate(Path::new("/Users/you/src")), dir.join("src"));
        assert_eq!(
            env.locate(Path::new("/home/you/src/lib.rs")),
            dir.join("src/lib.rs")
        );
        assert_eq!(env.locate(Path::new("/root/src")), dir.join("src"));
        assert_eq!(env.locate(Path::new("/Users/you")), dir);
        // Missing under both: returned as written.
        assert_eq!(
            env.locate(Path::new("/Users/you/no-such-dir")),
            PathBuf::from("/Users/you/no-such-dir")
        );
        assert_eq!(
            env.locate(Path::new("/opt/no-such-dir")),
            PathBuf::from("/opt/no-such-dir")
        );
    }

    #[test]
    fn no_user_home_is_an_error() {
        let err = HomeEnv::resolve_with(None, None, || None).unwrap_err();
        assert!(matches!(err, HomeError::NoUserHome));
    }

    #[test]
    fn empty_user_home_is_an_error() {
        let err = HomeEnv::resolve_with(None, None, || Some(PathBuf::new())).unwrap_err();
        assert!(matches!(
            err,
            HomeError::Empty {
                origin: HomeSource::User
            }
        ));
    }
}
