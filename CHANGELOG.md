# Changelog

Notable changes to the engine, CLI and status-line helper. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

Any change to the `--json` output contract bumps `schema_version` and gets its
own **JSON contract** entry (CLAUDE.md § Conventions).

## [Unreleased]

### Added

- Inventory (milestone M1): the engine finds what Claude Code and Codex can
  run and `vigildex inventory [--agent A] [--type T] [--json]` lists it. Items
  are MCP servers (with launch classification: package runner and pin,
  interpreter, binary or remote URL), hooks, skills (including legacy
  commands and subagents), plugins with their components, instruction files,
  security-relevant settings and credential-file metadata. Values are already
  safe to show: `env` and header blocks appear as key names, URLs lose user
  information and query strings, URL passwords and `--token=…`-style
  arguments are masked, and credential files contribute key names and
  permission bits only.
- Claude Code adapter: `~/.claude.json` (user and local MCP servers, trust
  markers, subscription marker), `settings.json` and `settings.local.json`
  at user, project and local scope, `.mcp.json`, hooks in settings and
  frontmatter, skills, commands, subagents, rules, `CLAUDE.md` /
  `CLAUDE.local.md` / `AGENTS.md`, plugins (`installed_plugins.json`,
  `known_marketplaces.json`, the plugin cache with both `.mcp.json` shapes)
  and `.credentials.json` metadata.
- Codex adapter: `config.toml` (approval and sandbox policy, providers and
  base URLs, `mcp_servers`, inline `[hooks]`, `projects` trust,
  `skills.config`), `hooks.json`, `AGENTS.md`, `~/.codex/skills` and
  `auth.json` metadata, at user and project scope.
- Shared adapter for the Agent Skills folders `~/.agents/skills` and
  `<repo>/.agents/skills`.
- `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and `COPILOT_HOME` are read from the shell
  profiles inside the scanned home.
- Paths an agent recorded under another home (`/Users/you/…`) are located
  under the scanned home when they do not exist as written, which makes
  fixture homes self-contained.
- `fixtures/homes/mockup-demo`: a fake home with the mockup's data
  (lint-helper MCP server, `ANTHROPIC_API_KEY` in `.zshrc`, two projects,
  plugins, hooks and skills); `fixtures/homes/basic` gained a minimal
  settings file for each agent. Snapshot tests cover both homes and the
  real-sample files under `fixtures/claude/2.1.296` and
  `fixtures/codex/0.46.0`.
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

### Changed

- `fixtures/homes/mockup-demo` now matches the app screens: applying the
  rules catalogue to it yields exactly the nine findings on the Findings
  screen (`docs/RULES.md` § List titles maps them), the stray key sits on
  `.zshrc` line 42, lint-helper is configured for Claude Code and Cursor, and
  `proj/demo-repo` carries the pre-flight sheet's sample files. Everything it
  no longer shows moved to the new `fixtures/homes/messy`, which also holds a
  look-alike that must not fire for each rule.
- `docs/RULES.md` gains the list titles from the screens, a finding policy
  (one finding per location, no cross-file merge, one finding per server
  across agents, disabled servers skipped, inventory tags for bundled scripts
  and plugin monitors, the repo severity bump for pre-flight only, masks with
  three trailing characters), `PRE-001…003` and titles for the `CHG` events.
  `docs/ARCHITECTURE.md` lists the engine additions the screens need per
  milestone and corrects the Codex `resets_in_seconds` note.
- With `CLAUDE_CONFIG_DIR` set, the Claude Code adapter reads only the
  relocated `.claude.json` and settings files, as Claude Code itself does
  (confirmed on 2.1.296), and reports files left at `~/.claude.json` and
  `~/.claude/` as warnings; the Codex adapter does the same for `CODEX_HOME`.
  A `fixtures/homes/relocated` home covers both.
- `oauthAccount` in `~/.claude.json` is recorded as its key names instead of
  bare presence, so the billing checks can tell an identity-only entry from a
  subscription account without reading a value.
- `docs/DATA_SOURCES.md` closes two verify items: `~/.claude.json` follows
  `CLAUDE_CONFIG_DIR`, and Codex hooks are enabled by default behind the
  `[features] hooks` flag (`codex_hooks` is a legacy alias).

### JSON contract

- `schema_version` 2: `scan --json` and `inventory --json` return
  `schema_version`, `engine_version`, `home` and `inventory` (`scanned`,
  `project_roots`, `relocations`, `items`, `artifacts`, `warnings`). The
  schemas are snapshotted in `crates/vigildex-core/tests/contract.rs`.
- `schema_version` 1: `scan --json` returns `schema_version`, `engine_version`
  and `home` (`root`, `source`).
