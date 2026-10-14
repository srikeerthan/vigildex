# Changelog

Notable changes to the engine, CLI and status-line helper. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

Any change to the `--json` output contract bumps `schema_version` and gets its
own **JSON contract** entry (CLAUDE.md § Conventions).

## [Unreleased]

### Added

- Findings (milestone M2): `vigildex findings [--severity S] [--fail-on S]
  [--json]` reports plaintext secrets (SEC-001…006), billing traps
  (BILL-001…007, BILL-009) and risky settings (RISK-001…009) from
  `docs/RULES.md`, each with a list title, a "why" sentence, a masked
  evidence string, fix steps, the agents and inventory items involved, and
  the rule IDs that lost the per-location tie as tags. `vigildex scan`
  includes the findings. `--fail-on` exits with status 1 and is judged
  before `--severity` filters the display. `fixtures/homes/mockup-demo`
  yields exactly the nine findings on the app's Findings screen, and
  `fixtures/homes/messy` triggers every other implemented rule beside a
  look-alike that must not fire.
- Secret rules in the gitleaks TOML shape under `rules/secrets/` (vendor
  tokens, credentials in URLs, name-keyed generic rules), embedded at build
  time, with a vendor host allowlist in `rules/hosts.toml`. Values are
  scanned at the point of detection and dropped: a finding keeps a masked
  form only (vendor prefix plus the last three characters for recognised
  tokens, the last three for unknown shapes, nothing for passwords). The
  defaults of `${VAR:-default}` and the bodies of `$(…)` are scanned too.
- Shell profiles (`.zshenv` … `.bashrc`, `.envrc`) and the `.env` at each
  project root are read: agent-relevant variables become settings with line
  numbers, every value goes through the secret rules, and the files are
  listed without a content hash.
- Every inventory item carries an `id` (this occurrence), an `identity`
  (what runs, shared across agents and files) and `tags` (`bundled_scripts`,
  `package_runner`, `plugin_monitors`, `plugin_bin`). MCP servers and hooks
  carry their `key_path`; settings, servers and hooks from `config.toml`
  carry their line number.
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

- Settings values that are strings are sanitised before they are recorded:
  URLs lose user information and query strings, and a vendor token or
  inline credential inside a command (`apiKeyHelper`, `statusLine.command`,
  Codex `notify`, a `headersHelper`) is masked. The same masking applies to
  hook commands and server arguments in the inventory.
- TOML syntax warnings name the line, never the source text.
- The rule data files moved to `crates/vigildex-core/rules/` so the crate
  packages on its own; `rules/` at the repository root is a link to them.
- `fixtures/homes/messy` gained triggers for the secret-location variants
  (a token in a server URL query, in a `headersHelper` command, in a hook
  header, in a hook command and in an `apiKeyHelper` command).
- `fixtures/homes/mockup-demo` now matches the app screens: applying the
  rules catalogue to it yields exactly the nine findings on the Findings
  screen (`fixtures/README.md` maps each row to its rule and file), the stray key sits on
  `.zshrc` line 42, lint-helper is configured for Claude Code and Cursor, and
  `proj/demo-repo` carries the pre-flight sheet's sample files. Everything it
  no longer shows moved to the new `fixtures/homes/messy`, which holds the
  other rules a home directory can trigger, each beside a look-alike that
  must not fire.
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

- `schema_version` 3: `scan --json`, `inventory --json` and the new
  `findings --json` carry `scanned_at` (RFC 3339 UTC). `scan --json` gains
  `findings`; `findings --json` returns `schema_version`, `engine_version`,
  `scanned_at`, `home`, `findings` and `warnings`. Each inventory item is
  wrapped with `id`, `identity` and `tags`; `mcp_server` and `hook` items
  gain `key_path` and `line`, `setting` items gain `line`; the `plugin`
  item's own identifier (`name@marketplace`) is `plugin_id`, so `id` is
  always the entry id; `artifacts[].kind` gains `shell_profile` (profiles and `.envrc`) and
  `env_file` (a project `.env`); `artifacts[].sha256` is nullable (those two
  kinds are not hashed). A finding has `id`, `rule`, `category`, `severity`, `title`,
  `why`, `location { path, line, key_path }`, `evidence`, `fingerprint`
  (always `null` in this version), `fix { summary, steps }`, `agents`,
  `items` and `tags`.
- `schema_version` 2: `scan --json` and `inventory --json` return
  `schema_version`, `engine_version`, `home` and `inventory` (`scanned`,
  `project_roots`, `relocations`, `items`, `artifacts`, `warnings`). The
  schemas are snapshotted in `crates/vigildex-core/tests/contract.rs`.
- `schema_version` 1: `scan --json` returns `schema_version`, `engine_version`
  and `home` (`root`, `source`).
