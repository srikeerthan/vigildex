# Changelog

Notable changes to the engine, CLI and status-line helper. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

Any change to the `--json` output contract bumps `schema_version` and gets its
own **JSON contract** entry (CLAUDE.md § Conventions).

## [Unreleased]

### Added

- Cargo workspace with the four crates from `docs/ARCHITECTURE.md`:
  `vigildex-core`, `vigildex-cli`, `vigildex-ffi` and `vigildex-statusline`
  (milestone M0).
- `--home DIR` global flag and `VIGILDEX_HOME` environment variable, so the CLI
  and tests read a fake home under `fixtures/homes/` instead of `$HOME`.
- `vigildex scan [--json]` skeleton. It resolves the home directory and reports
  it; there are no agent adapters yet, so it scans nothing.
- `vigildex-ffi` exports `engine_version()` through UniFFI.
- `vigildex-statusline` placeholder that answers `--version` only.
- CI on macOS and Ubuntu: `fmt`, `clippy`, `test`, `deny` and `audit`.
- `scripts/collect-fixtures.py`: copies agent files from a real home into
  `fixtures/` after redaction (allowlisted sources, key-whitelisted transcripts,
  same-shape fake secrets, staged output checked by a verifier). Standard
  library only; tests in `scripts/tests/`.
- Redacted samples from a real Mac (13 Oct 2026) under `fixtures/claude/`,
  `fixtures/codex/`, `fixtures/cursor/`, `fixtures/copilot/` and
  `fixtures/shared/`, with the verification-spike results folded into
  `docs/DATA_SOURCES.md`.

### JSON contract

- `schema_version` 1: `scan --json` returns `schema_version`, `engine_version`
  and `home` (`root`, `source`).
