# Data sources

Paths are for macOS; Linux is usually the same under `~`. Sources: vendor docs and open-source trackers read on 4 Oct 2026 (full citations in `docs/research/`), plus a read-only survey of a real Mac on 13 Oct 2026 (Claude Code 2.1.296, Codex CLI 0.46.0, Cursor Agent CLI 2025.09.12, Copilot CLI 1.0.96). Redacted samples from that survey live in `fixtures/<agent>/<version-or-date>/`, produced by `scripts/collect-fixtures.py`.

- **Sanctioned** = documented by the vendor as an interface.
- **Internal** = an on-disk format the vendor may change in any release.
- **verify** = not yet confirmed on real files. Confirm it, add a redacted fixture and update this file in the same PR.

Churn: **H** = the agent rewrites it in normal use; **M** = written on approvals, settings changes or token refresh; **L** = changes only on deliberate install or edit.

**Engine conventions (M1 inventory):**

- Agents record absolute paths (`/Users/you/proj/acme`, plugin `installPath`). When such a path does not exist and sits under a home-like prefix (`/Users/<name>`, `/home/<name>`, `/root`, `C:\Users\<name>`), the engine retries the same relative path under the scanned home. That is what makes a fixture home under `fixtures/homes/` self-contained; a real home is unaffected because its recorded paths exist.
- Relocation variables (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`) move an agent's whole directory, `~/.claude.json` included for Claude Code; files left at the default location are reported as warnings, not inventoried, because the agent ignores them. The variables are read from the shell profiles inside the scanned home (`.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.profile`, `.bash_profile`, `.bash_login`, `.bashrc`, in that order; the last assignment wins). Only `NAME=value` and `export NAME=value` lines count; `$HOME`, `${HOME}` and a leading `~` expand to the scanned home and any other `$` makes the value unresolvable (warning, default directory used). Nothing is evaluated.
- Hidden directories are never descended into when listing skills, commands, agents or rules (so Codex's `~/.codex/skills/.system/` is skipped). Credential files contribute key names, JSON value types and permission bits only, and are not hashed.
- System-wide directories outside the home (Claude Code's managed policy directory, `/etc/codex/skills`) are not scanned yet; they cannot live in a fixture home.

---

## Claude Code

Relocation: `CLAUDE_CONFIG_DIR` moves `~/.claude` **and** `~/.claude.json`. Confirmed on 2.1.296 (2026-10-13, syscall trace plus the path resolver in the shipped binary): the app-state file is `join(CLAUDE_CONFIG_DIR || $HOME, ".claude.json")`, so with the variable set `$HOME/.claude.json` is never opened, not even when it exists; `backups/`, `policy-limits.json` and `remote-settings.json` sit beside it in the config directory; a missing directory is created; a relative value resolves against the working directory; an empty value counts as unset. The engine reads only the relocated `.claude.json` and `settings*.json` in that case and reports files left at the default locations as warnings.

| Surface | Path | Security-relevant content | Churn | Diff |
|---|---|---|---|---|
| User settings | `~/.claude/settings.json` | `permissions.allow/ask/deny/defaultMode/additionalDirectories`, `permissions.disableBypassPermissionsMode`, `env`, `apiKeyHelper`, `hooks`, `disableAllHooks`, `allowedHttpHookUrls`, `httpHookAllowedEnvVars`, `sandbox.*`, `enabledPlugins`, `extraKnownMarketplaces`, `statusLine`, `enableAllProjectMcpServers`, `enabledMcpjsonServers` | M; the CLI also rewrites the file at every session start, so diff parsed keys, never mtimes | Key-level |
| Project settings | `<repo>/.claude/settings.json` | Same keys. Hooks, `env`, `apiKeyHelper` and skill `allowed-tools` apply in `claude -p`/SDK runs **even in an untrusted folder** | L (git) | Key-level, plus pre-flight |
| Local settings | `~/.claude/settings.local.json`, `<repo>/.claude/settings.local.json` | "Don't ask again" approvals accumulate here as `allow` rules. The user-level file exists too and can carry `hooks` | M | Key-level; each new rule is an event |
| Managed policy | `/Library/Application Support/ClaudeCode/managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json` | `allowManagedHooksOnly`, `allowedMcpServers`/`deniedMcpServers`, `forceLoginMethod`, `allowedProviders` | L | Whole-file hash; any change alerts |
| App state | `~/.claude.json` (backups in `~/.claude/backups/`, five newest kept) | `mcpServers` (user scope), `projects["<path>"].mcpServers` (local scope), `projects["<path>"].hasTrustDialogAccepted`, `hasTrustDialogHooksAccepted`. The subscription-login marker is the `oauthAccount` object (key names only; it holds the account e-mail and organisation) plus `hasAvailableSubscription`. **Never read:** `oauthAccount` values, `customApiKeyResponses` (API-key identifiers), `projects["<path>"].history` (prompts), `userID`, `machineID` | **H**: rewritten every 60–70 s during a session, with a backup each time | Key-level on those keys only |
| Project MCP | `<repo>/.mcp.json` | `mcpServers`; `${VAR}` / `${VAR:-default}` expansion in `command`, `args`, `env`, `url`, `headers`; `headersHelper` | L | Key-level |
| Hooks | Inside any settings file; plugin `hooks/hooks.json`; skill and agent frontmatter | 30+ events; handler types `command`, `http`, `mcp_tool`, `prompt`, `agent` | L | Per event and matcher |
| Skills and more | `~/.claude/{skills,commands,agents,rules,output-styles}/`, `<repo>/.claude/...` | `SKILL.md` frontmatter (`allowed-tools`, `hooks`) and bundled scripts | L | Per-file hash |
| Plugins | `~/.claude/plugins/` (`installed_plugins.json`, `known_marketplaces.json`, `cache/<marketplace>/<plugin>/<version>/`, org-synced plugins under `synced/<orgUuid>_<userUuid>/`; `.in_use/<pid>` markers are touched at every session start) | Plugin manifest; components: skills, commands, agents, hooks, MCP, LSP, `monitors` (persistent background commands), `bin/` (added to the Bash tool's `PATH`) | M | Manifest and components diff |
| Instructions | `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.claude/rules/*.md`; auto memory `~/.claude/projects/<p>/memory/MEMORY.md` | Loaded into context | L (memory H) | Hash; don't alert on memory |
| Credentials | Keychain item "Claude Code-credentials"; fallback `~/.claude/.credentials.json` (0600); `~/.claude/sessions/<pid>.<sha256>.key` (0600, beside each session lock file) | **Metadata only**: exists, mode, owner. With the Keychain in use, `.credentials.json` does not exist | M | Mode/owner change |

**Notes:**

- **Credential precedence.** The order is:
  1. cloud provider switches (`CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` / `_FOUNDRY`);
  2. `ANTHROPIC_AUTH_TOKEN`;
  3. `ANTHROPIC_API_KEY`;
  4. `apiKeyHelper`;
  5. `CLAUDE_CODE_OAUTH_TOKEN`;
  6. Anthropic profile credentials;
  7. subscription OAuth.

  In `-p` (non-interactive) mode an `ANTHROPIC_API_KEY` that's present is **always** used. This is the basis of BILL-001…005.
- **Hot reload.** Claude Code reloads `permissions`, `hooks` and `apiKeyHelper` mid-session, so a malicious edit takes effect without a restart.
- **Trust.** It can be set by hand (`hasTrustDialogAccepted: true`), which is the basis of CHG-003.
- **Never read** (prompts, shell state, personal files): `~/.claude/history.jsonl`, `shell-snapshots/`, `session-env/`, `file-history/`, `paste-cache/`, `security/`, `telemetry/`, `cache/`, `projects/<p>/memory/`.
- **Formats confirmed for the inventory (M1, 2026-10-13)** on the 2.1.296 samples in `fixtures/claude/2.1.296/`, and on the vendor docs read the same day where noted:
  - `~/.claude.json`: `mcpServers` (user scope) and `projects["<path>"].mcpServers` (local scope) entries carry `type` (`stdio` or `http`), `command`, `args`, `env`, `url`. A fresh install (2.1.296, `claude mcp add -s user` in an empty home) writes `firstStartTime`, `firstStartVersion`, `machineID`, `userID`, `migrationVersion`, `seenNotifications`, `opusProMigrationComplete`, `sonnet1m45MigrationComplete`, `hasResetAutoModeOptInForDefaultOffer` and `mcpServers`, and no `oauthAccount` or `hasAvailableSubscription`; with an account context in the environment `oauthAccount` appears with `accountUuid`, `emailAddress` and `organizationUuid` only; after a subscription login (the 2.1.296 sample) it also holds `billingType`, `organizationType`, `organizationRateLimitTier`, `hasExtraUsageEnabled` and more. Presence alone therefore means "an account is known"; the engine records the key *names* of `oauthAccount` (never values) so the billing checks (M2) can tell an identity-only entry from a subscription account. Project objects carry `allowedTools`, `mcpContextUris`, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `hasTrustDialogAccepted`, `hasClaudeMdExternalIncludesApproved`, `hasClaudeMdExternalIncludesWarningShown`, `lastCost`, `lastDuration`, `lastSessionId`, `lastModelUsage` and (never read) `history`. Project keys are absolute paths, and the home itself appears as a project when Claude Code was run there. The engine records `mcpServers`, `hasTrustDialogAccepted`, `hasTrustDialogHooksAccepted`, `hasClaudeMdExternalIncludesApproved`, `enableAllProjectMcpServers`, `enabledMcpjsonServers`, `disabledMcpjsonServers` and `allowedTools` per project, plus `hasAvailableSubscription` and the *presence* of `oauthAccount` at user level.
  - `settings.json` (2.1.296) carried `permissions.allow`, `model`, `skillOverrides`, `disableBundledSkills`, `enabledPlugins` (`"<name>@<marketplace>": bool`), `extraKnownMarketplaces`, `alwaysThinkingEnabled`, `modelSettings`, `tui`, `editorMode`, `autoCompactEnabled`, `agentPushNotifEnabled`, `skipWorkflowUsageWarning` and `autoMode.environment`. The user-level `settings.local.json` carried `hooks`. Hook groups are `{"matcher", "hooks": [{"type": "command", "command", "timeout"}]}` under the event name.
  - Plugins (2.1.296): `installed_plugins.json` is `{"version": 2, "plugins": {"<name>@<marketplace>": [{"scope", "installPath", "version", "installedAt", "lastUpdated", "gitCommitSha"?}]}}` with one array entry per install scope. `known_marketplaces.json` is `{"<marketplace>": {"source": {"source": "github", "repo"}, "installLocation", "lastUpdated"}}`. `plugins/config.json` holds `{"repositories": {}}` (legacy, unused). The cache is `cache/<marketplace>/<plugin>/<version>/` with `.claude-plugin/plugin.json` (`name`, `version`?, `description`, `author`), `hooks/hooks.json` (`{"description", "hooks": {<events>}}`, commands using `${CLAUDE_PLUGIN_ROOT}`) and `.mcp.json` in **two shapes**: wrapped in `mcpServers` (context7) or a bare `{"<server>": {…}}` map (github). The recorded `installPath` can name a version folder the cache no longer holds (19 of 20 in the sample, after updates); the engine reports those as `installed: false`.
  - Hooks (docs): 33 events; handler types `command` (`command`, `args`, `async`, `shell`, `onFailure`), `http` (`url`, `headers`, `allowedEnvVars`), `mcp_tool` (`server`, `tool`, `input`), `prompt` and `agent` (`prompt`, `model`), with common `type`, `if`, `timeout`, `statusMessage`, `once`. Skill and subagent frontmatter `hooks` use the same event map; subagent frontmatter can also hold `tools`, `permissionMode` and `mcpServers` (a list of server names or inline `{name: config}` maps).
  - Skills (docs): frontmatter fields `name`, `description`, `when_to_use`, `argument-hint`, `arguments`, `disable-model-invocation`, `user-invocable`, `allowed-tools`, `disallowed-tools`, `model`, `effort`, `context`, `agent`, `background`, `hooks`, `paths`, `shell`, plus `metadata`, `license`, `compatibility`; unknown fields are ignored. Legacy `.claude/commands/*.md` still works with the same frontmatter except `name` and `paths`. Locations: the managed directory, `~/.claude/skills/<name>/SKILL.md`, `.claude/skills/`, nested `<subdir>/.claude/skills/`, plugin `skills/`, and claude.ai-synced skills under `~/.claude/skills/synced/` (exact layout **verify**; the engine searches one folder level below a skills directory).
  - Instructions (docs, v2.1.277+): `AGENTS.md` and `.claude/AGENTS.md` are read only when no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` exists in the working directory or above (default `claude-md-or-agents-md`); the engine mirrors that at the repository root. `.claude/rules/*.md` is discovered recursively, and a rule with `paths` frontmatter loads on demand (`always_apply: false`). Managed `CLAUDE.md`: `/Library/Application Support/ClaudeCode/CLAUDE.md` (macOS), `/etc/claude-code/CLAUDE.md` (Linux and WSL), `C:\Program Files\ClaudeCode\CLAUDE.md` (Windows).
  - Managed settings (docs): `managed-settings.json`, `managed-settings.d/*.json` and `managed-mcp.json` live in `/Library/Application Support/ClaudeCode/` (macOS), `/etc/claude-code/` (Linux and WSL) and `C:\Program Files\ClaudeCode\` (Windows; the legacy `C:\ProgramData\ClaudeCode\managed-settings.json` is no longer read). `permissions.defaultMode` values `auto` and `bypassPermissions` take effect only from user or managed settings since v2.1.257.
- **Verified 2026-10-13** on Claude Code 2.1.149–2.1.296; samples in `fixtures/claude/<version>/`.

### Sessions and usage (internal format; the docs say it "changes between versions")

| Item | Detail |
|---|---|
| Transcripts | `~/.claude/projects/<cwd with non-alphanumerics → "-">/<session-id>.jsonl`; subagents under `<session-id>/subagents/*.jsonl` and `<session-id>/subagents/workflows/wf_<id>/agent-<id>.jsonl`. Besides `assistant`, `user` and `system`, files hold many side record types (`last-prompt`, `custom-title`, `mode`, `attachment`, `queue-operation`, `pr-link`, `agent-name`, `cost-state`, …) that parsers must skip. Default retention is 30 days (`cleanupPeriodDays`). |
| Usage | `type: "assistant"` lines → `message.usage`: `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`; cache-write TTL split `cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens` (confirmed on 2.1.209–2.1.296: present on every record, and the two sum to `cache_creation_input_tokens`). Usage is repeated on every content-block line of one response, so de-duplicate by `message.id` (2–3× overcount otherwise). Skip `message.model == "<synthetic>"`. Tolerate extra keys: `inference_geo`, `iterations`, `server_tool_use`, `service_tier`, `speed`, `fallback_credit` (2.1.295+). |
| Thinking | `usage.output_tokens_details.thinking_tokens` is in transcripts from Claude Code 2.1.266 on and absent before (0 of 3,125 records in a 2.1.209 file; 1,215 of 1,219 in a 2.1.284 file, the rest `<synthetic>`). Decide `reported.thinking` per record: true when the key exists, otherwise thinking stays inside Output. |
| Running sessions | `~/.claude/sessions/` lock files (removed on exit). `claude agents --json [--all]` is the sanctioned way to read background sessions: `state` (working, blocked, done, failed, stopped), `status` (busy, waiting, idle), `waitingFor`, `pid`, `sessionId`, `cwd`, `name`. Interactive sessions don't appear until backgrounded, so combine it with lock files and the process list. |
| Plan limits | Status-line stdin JSON only: `rate_limits.five_hour` / `seven_day` → `used_percentage`, `resets_at` (Unix seconds). Pro/Max only, only after the first API response, and each window may be absent. The JSON also has `cost.total_cost_usd`, `context_window.*` and `session_id`. The script runs on each new assistant message, with an optional `refreshInterval`. For testing, a status line can be injected with `claude --settings <file>` without touching `~/.claude/settings.json`. |

## OpenAI Codex

Relocation: `CODEX_HOME` moves `~/.codex`. The CLI, IDE extension and ChatGPT desktop app share it.

| Surface | Path | Security-relevant content | Churn | Diff |
|---|---|---|---|---|
| User config | `~/.codex/config.toml` | `approval_policy`, `sandbox_mode`, `sandbox_workspace_write.*`, `shell_environment_policy.*`, `mcp_servers.<id>.*` (command, args, env, url, `bearer_token_env_var`, `http_headers`), `model_provider(s)`, `openai_base_url`, `chatgpt_base_url`, `forced_login_method`, `cli_auth_credentials_store`, `notify`, `hooks`, `projects.<path>.trust_level` | M (confirmed 2026-10-13: Codex 0.46 writes `projects.<path>.trust_level` itself, also for `codex exec` runs) | Key-level |
| Project config | `<repo>/.codex/config.toml` (trusted projects only) | Codex **ignores** base URLs, providers, `notify` and profiles here | L | Key-level |
| Hooks | `~/.codex/hooks.json`, `[hooks]` in `config.toml`, `<repo>/.codex/hooks.json` | 12 events; Codex records trust against each hook's hash | L | Key-level and hash |
| Skills | `.agents/skills` (cwd, parents, repo root), `~/.agents/skills`, `/etc/codex/skills` | Folders with `SKILL.md` | L | Hash |
| Instructions | `AGENTS.md` | | L | Hash |
| Credentials | `~/.codex/auth.json` (when `cli_auth_credentials_store` is `file` or `auto`) | **Key names only; never read values.** Keys at 0.46: `OPENAI_API_KEY` (always present, `null` when unused), `tokens` (`id_token`, `access_token`, `refresh_token`, `account_id`), `last_refresh`. Current `main` adds `auth_mode`, `agent_identity`, `personal_access_token`, `bedrock_api_key`, `bedrock_access_keys`. Because the API-key slot is always present, key names alone cannot tell the mode: use `auth_mode` when present, otherwise the JSON *type* of `OPENAI_API_KEY` (null vs string; policy decision pending). `codex login status` prints the mode without values, but it reflects the file, not whether the login still works: a stale refresh token fails with 401 at use. | M (rewritten on token refresh) | Mode/owner |

### Sessions and usage (internal format, open source in `codex-rs/protocol`)

| Item | Detail |
|---|---|
| Rollouts | `~/.codex/sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl`, plus `~/.codex/archived_sessions/` |
| Usage | `event_msg` lines with `payload.type == "token_count"` → `info.total_token_usage` and `info.last_token_usage`, each with `input_tokens`, `cached_input_tokens`, `output_tokens`, `reasoning_output_tokens`, `total_tokens`. Totals are **cumulative**, so take deltas. The model comes from `turn_context` lines. No `token_count` events exist before 2025-09-06. Quirks on real files: the first `token_count` of a session has `info: null`; 0.44 emits every `token_count` twice; 0.32 rollouts have no `turn_context` rows, so their model is unknown; `turn_context.effort` appears in 0.46. |
| Mapping | Input = `input_tokens − cached_input_tokens`; Cache read = `cached_input_tokens`; Output = `output_tokens − reasoning_output_tokens`; Thinking = `reasoning_output_tokens`; Cache write is not reported. (Subset relations confirmed on 131 events across 0.32–0.46: `cached ≤ input`, `reasoning ≤ output`, `total == input + output`; totals are monotonic within a session.) |
| Plan limits | `rate_limits` in `token_count` events: `primary` / `secondary` → `used_percent`, `window_minutes`, `resets_in_seconds` (relative: add the row timestamp; there is no `resets_at` in 0.44–0.46). `credits` (`has_credits`, `unlimited`, `balance`) and `plan_type` were absent on 0.44–0.46 and stay **verify** for newer releases |

**Notes:**

- **Credential precedence** (source `codex-rs/login`, confirmed on 0.46.0 with an invalid key): `CODEX_API_KEY` in the environment wins over a stored ChatGPT login in `codex exec`, which passes `enable_codex_api_key_env = true`; the interactive TUI passes `false` and ignores it. Inside `auth.json` an API key wins over `tokens`. `OPENAI_API_KEY` in the environment is not read by the auth module at all: an invalid value is ignored and the ChatGPT login is used. `forced_login_method` restricts which modes are accepted. This is the basis of BILL-007.
- **Formats confirmed for the inventory (M1, 2026-10-13)** from the 0.46.0 samples and from the `openai/codex` source on `main` that day (`codex-rs/config/src/`); the vendor docs site was unreachable from the build environment:
  - `config.toml` top-level keys (`ConfigToml`): `model`, `model_provider`, `model_providers`, `approval_policy`, `sandbox_mode`, `sandbox_workspace_write` (`writable_roots`, `network_access`, `exclude_tmpdir_env_var`, `exclude_slash_tmp`), `shell_environment_policy`, `mcp_servers`, `mcp_oauth_credentials_store`, `cli_auth_credentials_store` (`auto` uses the keyring when available, else a file), `forced_login_method`, `forced_chatgpt_workspace_id`, `openai_base_url`, `chatgpt_base_url`, `notify`, `hooks`, `projects`, `skills`, `features`, `profiles`, `profile`, `model_reasoning_effort`, `history`, `file_opener`, `tui`, `windows`, `developer_instructions`, `project_doc_max_bytes`, `project_doc_fallback_filenames`.
  - `[mcp_servers.<id>]` (`McpServerConfig`): the transport is untagged and chosen by which key is present. `command` selects stdio with `args`, `env`, `env_vars` (variables forwarded by name) and `cwd`; `url` selects streamable HTTP with `bearer_token_env_var`, `http_headers`, `env_http_headers` and `http_headers_helper` (a local command that prints headers). Mixing the two families is rejected. Common keys: `enabled` (default `true`), `required`, `startup_timeout_sec`, `tool_timeout_sec`, `enabled_tools`, `disabled_tools`, `scopes`, `oauth_resource`, `environment_id`, `auth`, `startup_readiness`, `tools`.
  - Hooks (`hook_config.rs`): `hooks.json` is `{"description"?, "hooks": {"<Event>": [{"matcher"?, "hooks": [handler]}]}}` and rejects unknown top-level keys. Twelve events: `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop`, `Interrupt`. Handlers are tagged by `type`: `command` (`command`, `commandWindows`, `timeout`, `async`, `statusMessage`, `additionalContextLimit`), `mcp_tool` (`server`, `tool`, `input`, `timeout`, `statusMessage`), `prompt` and `agent` (empty; Codex skips them with a warning). The `[hooks]` table in `config.toml` carries the same event keys plus `state`, a map of `"<source>:<event>:<group>:<handler>"` to `{enabled, trusted_hash}`. Hooks are loaded from each config layer's `hooks.json` and `[hooks]`, then from managed `requirements.toml` (`allow_managed_hooks_only = true` there ignores every other source), then from plugins; trust is a hash of the normalised handler, so the same hook in TOML and JSON shares one identity. The feature flag is `[features] hooks` (`Feature::CodexHooks`), canonical since rust-v0.129.0; `codex_hooks` is a legacy alias that still toggles the same feature from `config.toml`, `-c features.codex_hooks=…` or `--disable codex_hooks`. It was introduced in 0.114.0 as `codex_hooks`, under development and off by default, and has been `Stable` and on by default since 0.124.0, so current releases need no flag: on codex-cli 0.162.1 (npm `latest`, 2026-10-13) `codex features list` with an empty `CODEX_HOME` prints `hooks  stable  true`, and `[features] hooks = false` or `--disable hooks` switches hooks off (`HooksConfig.feature_enabled = config.features.enabled(Feature::CodexHooks)`; `list_hooks` returns nothing when false). A separate `plugin_hooks` flag is `Removed`. Confirmed 2026-10-13 from the `openai/codex` tags rust-v0.110.0–0.162.1 and the 0.162.1 binary.
  - Skills (`skills/src/parser.rs`, `config/src/skills_config.rs`): Codex reads only `name`, `description` and `metadata.short-description` from `SKILL.md` frontmatter; `description` is required, `name` defaults to the folder name and is capped at 64 characters, unknown fields are ignored, and a repair pass quotes scalars that contain `: `. `[skills]` holds `bundled`, `include_instructions`, `max_context_tokens` and `config`, an array of `{path | name, enabled}` selectors (`[[skills.config]]`). `~/.codex/skills/` holds user skills beside the Codex-written `.system/` folder. The discovery directories listed in the table above were not re-confirmed from source.
  - Project trust (`project_trust.rs`): `[projects."<path>"]` keys are matched as canonical then original spellings; a key for the working directory wins over one for the repository root; POSIX keys are case-sensitive.
  - `auth.json`: the engine records top-level key names and JSON value types only (`OPENAI_API_KEY: null` beside `tokens: object` is the ChatGPT login; `OPENAI_API_KEY: string` alone is the API-key login), never values, and does not hash the file.
- **Shared home.** The IDE extension and desktop app write into `~/.codex` too (`skills/.system/` appeared on a day with no CLI session), so attribution must not assume the CLI. `version.json` is rewritten on every update check.
- **Never read:** `~/.codex/history.jsonl` (one raw prompt per line) and `log/codex-tui.log`.
- **Verified 2026-10-13** on Codex CLI 0.32.0–0.46.0; samples in `fixtures/codex/<version>/`. Of the current releases, codex-cli 0.162.1 is confirmed for the feature flags and the `codex features list|enable|disable` subcommands only; its rollout and `rate_limits` formats are still **verify**.

## Cursor

| Surface | Path | Security-relevant content | Churn | Diff |
|---|---|---|---|---|
| MCP | `~/.cursor/mcp.json`, `<repo>/.cursor/mcp.json` | `mcpServers`; `${env:NAME}`, `${userHome}`, `${workspaceFolder}` interpolation | L | Key-level |
| Hooks | `~/.cursor/hooks.json`, `<repo>/.cursor/hooks.json`, enterprise `/Library/Application Support/Cursor/hooks.json` | `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `beforeSubmitPrompt`; failures fail **open** unless `failClosed: true` | L | Key-level |
| CLI permissions | `~/.cursor/cli-config.json`, `<repo>/.cursor/cli.json` | `Shell(...)`, `Read(...)`, `Write(...)`, `WebFetch(...)`, `Mcp(server:tool)` | M (confirmed on `cli-config.json`: keys `editor`, `hasChangedDefaultModel`, `model`, `permissions{allow,deny}`, `privacyCache`, `version`) | Key-level |
| Trust marker | `~/.cursor/projects/<slug>/.workspace-trusted` (the slug encodes the absolute workspace path) | `trustedAt`, `workspacePath` | L | Per-file; candidate input for CHG-003 |
| Launcher args | `~/.cursor/argv.json` | JSONC with `//` comment lines; strip them before parsing. `crash-reporter-id` is a machine identifier | L | Hash |
| Rules and skills | `.cursor/rules/*.mdc` (`alwaysApply`, `globs`), nested `AGENTS.md`; skills in `.cursor/skills`, `~/.cursor/skills`, plus `.agents/skills`, `.claude/skills`, `.codex/skills` | | L | Hash |
| Editor state | `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb` (SQLite; contains the auth token) | **Never open.** File metadata only. | H | None |
| Editor settings | `~/Library/Application Support/Cursor/User/settings.json` (**verify** path; no Cursor IDE on the 2026-10-13 test machine) | `security.workspace.trust.enabled` (off by default) | M | Key-level |

**Usage:** Cursor keeps **no per-request token counts on disk**. The Cursor Agent CLI writes transcripts under `~/.cursor/projects` and `~/.cursor/chats` but outputs no token usage (as of July 2026). The app shows Cursor usage as "on cursor.com" with a dashboard link. Never use the cookie-based endpoints other trackers use. **Never read** `~/.cursor/ide_state.json` (recently viewed file paths). Samples in `fixtures/cursor/<date>/`.

## GitHub Copilot

### Copilot CLI

Relocation: `COPILOT_HOME` moves `~/.copilot`.

| Surface | Path | Security-relevant content | Churn | Diff |
|---|---|---|---|---|
| Settings | `~/.copilot/settings.json`; repo `.github/copilot/settings.json` and `.local.json` | `allowedUrls` (URL approvals are appended), `deniedUrls`, `permissions`, `sandbox`, model | M | Key-level |
| Saved approvals | `~/.copilot/permissions-config.json` | Tool and directory decisions per repo root | M | Key-level; each new approval is an event |
| Internal state | `~/.copilot/config.json` | Plaintext token fallback when the keychain is unavailable: **flag presence only**, never read values | H | Metadata only |
| MCP | `~/.copilot/mcp-config.json`, `.mcp.json`, `.github/mcp.json` | Servers | L | Key-level |
| Hooks and policy | `~/.copilot/hooks/`, `.github/hooks/*.json`; policy `/etc/github-copilot/policy.d/*.json` | `preToolUse` and others | L | Key-level |
| Other | `~/.copilot/{skills,agents,instructions,installed-plugins,servers}/`, `copilot-instructions.md`, `providers.json` (BYOK), `mcp-secrets/` and `mcp-oauth-config/` (fallback secret storage) | Flag fallback secret dirs | L/M | Hash |
| State (never read) | `~/.copilot/command-history-state.json` (prompt history), `open-sessions-state.json`, `sidebar-sessions-state/`, `logs/process-<ts>-<pid>.log` | Metadata only | H | None |

**Token precedence:** `COPILOT_GITHUB_TOKEN` > `GH_TOKEN` > `GITHUB_TOKEN` > keychain OAuth > `gh auth token`. Environment variables silently override the stored login (BILL-009). BYOK uses `COPILOT_PROVIDER_BASE_URL`, `COPILOT_PROVIDER_TYPE`, `COPILOT_PROVIDER_API_KEY`.

**Sessions and usage (internal):**

- Files: `~/.copilot/session-state/<session-id>/events.jsonl`, `~/.copilot/session-store.db` (SQLite) and `~/.copilot/logs/process-<ts>-<pid>.log`.
- `session-state/<id>/events.jsonl` rows are `{id, parentId, timestamp, type, data}`. Types seen on CLI 1.0.96 (2026-10-13, a session with no turns): `session.start`, `session.info` (`data.currentTokens`, `systemTokens`, `conversationTokens`, `toolDefinitionsTokens`: context-window sizes, not per-request usage), `session.model_change`, `session.shutdown`. Whether `assistant.usage` (`inputTokens`, `outputTokens`, `reasoningTokens`, `cacheReadTokens`, `cacheWriteTokens`, `cost`, documented by GitHub's SDK as *ephemeral*) is persisted after a real turn is still **verify**. Sample in `fixtures/copilot/<date>/`.
- The Copilot CLI status-line JSON exposes session totals (input, output, cache read, cache write, reasoning, premium requests).
- If nothing is persisted, plan a status-line feed like Claude's.

### VS Code agent mode

| Surface | Path | Content |
|---|---|---|
| MCP | User `mcp.json` (via "MCP: Open User Configuration"; **verify** path), `.vscode/mcp.json` | `servers`, `inputs` (`promptString` with `password: true` → `${input:id}`) |
| Settings | `~/Library/Application Support/Code/User/settings.json` (confirmed 2026-10-13) | `chat.tools.global.autoApprove` ("disables critical security protections"), `chat.tools.terminal.autoApprove`, `chat.mcp.gallery.enabled`; `terminal.integrated.env.osx` injects environment values into every VS Code terminal and is a secret surface |

**Usage:** server-side only, shown as "on github.com" with a link.

## Cross-agent

| Surface | Path | Why |
|---|---|---|
| Shared skills | `~/.agents/skills`, `<repo>/.agents/skills` | Read by Codex, Cursor, Copilot CLI and others |
| Shell profiles | `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`, `.bashrc`, `.bash_profile`, `.profile`, `.envrc` | Exported keys, base URLs, `*_HOME` relocations |
| `.env` files | Project roots the user watches | Keys and base URLs (scan; don't alert on edits) |
| `PATH` | Resolved `claude`, `codex`, `copilot`, `cursor-agent`, `code` binaries | Detect shadowed or fake agent binaries (RISK-010) |

## Never used (by design)

- `api.anthropic.com/api/oauth/usage`, `claude.ai` cookies, PTY scraping of `/usage`;
- `chatgpt.com/backend-api/wham/usage`;
- `cursor.com/api/*` with session cookies;
- `api.github.com/copilot_internal/*`;
- any browser cookie store or Keychain item belonging to another app;
- local LLM proxies or base-URL interception.

These conflict with vendor terms (Anthropic forbids collecting or intermediating Claude.ai credentials and session tokens), break often, or both.
