# Data sources

Paths are for macOS; Linux is usually the same under `~`. Sources: vendor docs and open-source trackers read on 4 Oct 2026 (full citations in `docs/research/`).

- **Sanctioned** = documented by the vendor as an interface.
- **Internal** = an on-disk format the vendor may change in any release.
- **verify** = not yet confirmed on real files. Confirm it, add a redacted fixture and update this file in the same PR.

Churn: **H** = the agent rewrites it in normal use; **M** = written on approvals, settings changes or token refresh; **L** = changes only on deliberate install or edit.

---

## Claude Code

Relocation: `CLAUDE_CONFIG_DIR` moves `~/.claude`.

| Surface | Path | Security-relevant content | Churn | Diff |
|---|---|---|---|---|
| User settings | `~/.claude/settings.json` | `permissions.allow/ask/deny/defaultMode/additionalDirectories`, `permissions.disableBypassPermissionsMode`, `env`, `apiKeyHelper`, `hooks`, `disableAllHooks`, `allowedHttpHookUrls`, `httpHookAllowedEnvVars`, `sandbox.*`, `enabledPlugins`, `extraKnownMarketplaces`, `statusLine`, `enableAllProjectMcpServers`, `enabledMcpjsonServers` | M | Key-level |
| Project settings | `<repo>/.claude/settings.json` | Same keys. Hooks, `env`, `apiKeyHelper` and skill `allowed-tools` apply in `claude -p`/SDK runs **even in an untrusted folder** | L (git) | Key-level, plus pre-flight |
| Local settings | `<repo>/.claude/settings.local.json` | "Don't ask again" approvals accumulate here as `allow` rules | M | Key-level; each new rule is an event |
| Managed policy | `/Library/Application Support/ClaudeCode/managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json` | `allowManagedHooksOnly`, `allowedMcpServers`/`deniedMcpServers`, `forceLoginMethod`, `allowedProviders` | L | Whole-file hash; any change alerts |
| App state | `~/.claude.json` (backups in `~/.claude/backups/`, five newest kept) | `mcpServers` (user scope), `projects["<path>"].mcpServers` (local scope), `projects["<path>"].hasTrustDialogAccepted`; also holds the OAuth session (**never read values**) | **H** | Key-level on those keys only |
| Project MCP | `<repo>/.mcp.json` | `mcpServers`; `${VAR}` / `${VAR:-default}` expansion in `command`, `args`, `env`, `url`, `headers`; `headersHelper` | L | Key-level |
| Hooks | Inside any settings file; plugin `hooks/hooks.json`; skill and agent frontmatter | 30+ events; handler types `command`, `http`, `mcp_tool`, `prompt`, `agent` | L | Per event and matcher |
| Skills and more | `~/.claude/{skills,commands,agents,rules,output-styles}/`, `<repo>/.claude/...` | `SKILL.md` frontmatter (`allowed-tools`, `hooks`) and bundled scripts | L | Per-file hash |
| Plugins | `~/.claude/plugins/` (`installed_plugins.json`, marketplaces) | Plugin manifest; components: skills, commands, agents, hooks, MCP, LSP, `monitors` (persistent background commands), `bin/` (added to the Bash tool's `PATH`) | M | Manifest and components diff |
| Instructions | `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.claude/rules/*.md`; auto memory `~/.claude/projects/<p>/memory/MEMORY.md` | Loaded into context | L (memory H) | Hash; don't alert on memory |
| Credentials | Keychain item "Claude Code-credentials"; fallback `~/.claude/.credentials.json` (0600) | **Metadata only**: exists, mode, owner | M | Mode/owner change |

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

### Sessions and usage (internal format; the docs say it "changes between versions")

| Item | Detail |
|---|---|
| Transcripts | `~/.claude/projects/<cwd with non-alphanumerics → "-">/<session-id>.jsonl`; subagents under `<session-id>/subagents/`. Default retention is 30 days (`cleanupPeriodDays`). |
| Usage | `type: "assistant"` lines → `message.usage`: `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`; cache-write TTL split `cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens` (**verify**). De-duplicate by `message.id`. |
| Thinking | The API reports `usage.output_tokens_details.thinking_tokens` (thinking is billed as output). Whether transcripts keep that field is **verify**. If absent, thinking stays inside Output and `reported.thinking = false`. |
| Running sessions | `~/.claude/sessions/` lock files (removed on exit). `claude agents --json [--all]` is the sanctioned way to read background sessions: `state` (working, blocked, done, failed, stopped), `status` (busy, waiting, idle), `waitingFor`, `pid`, `sessionId`, `cwd`, `name`. Interactive sessions don't appear until backgrounded, so combine it with lock files and the process list. |
| Plan limits | Status-line stdin JSON only: `rate_limits.five_hour` / `seven_day` → `used_percentage`, `resets_at` (Unix seconds). Pro/Max only, only after the first API response, and each window may be absent. The JSON also has `cost.total_cost_usd`, `context_window.*` and `session_id`. The script runs on each new assistant message, with an optional `refreshInterval`. |

## OpenAI Codex

Relocation: `CODEX_HOME` moves `~/.codex`. The CLI, IDE extension and ChatGPT desktop app share it.

| Surface | Path | Security-relevant content | Churn | Diff |
|---|---|---|---|---|
| User config | `~/.codex/config.toml` | `approval_policy`, `sandbox_mode`, `sandbox_workspace_write.*`, `shell_environment_policy.*`, `mcp_servers.<id>.*` (command, args, env, url, `bearer_token_env_var`, `http_headers`), `model_provider(s)`, `openai_base_url`, `chatgpt_base_url`, `forced_login_method`, `cli_auth_credentials_store`, `notify`, `hooks`, `projects.<path>.trust_level` | M (**verify** whether Codex writes trust keys itself) | Key-level |
| Project config | `<repo>/.codex/config.toml` (trusted projects only) | Codex **ignores** base URLs, providers, `notify` and profiles here | L | Key-level |
| Hooks | `~/.codex/hooks.json`, `[hooks]` in `config.toml`, `<repo>/.codex/hooks.json` | 12 events; Codex records trust against each hook's hash | L | Key-level and hash |
| Skills | `.agents/skills` (cwd, parents, repo root), `~/.agents/skills`, `/etc/codex/skills` | Folders with `SKILL.md` | L | Hash |
| Instructions | `AGENTS.md` | | L | Hash |
| Credentials | `~/.codex/auth.json` (when `cli_auth_credentials_store` is `file` or `auto`) | **Key names only.** Infer auth mode (API key vs ChatGPT) from which keys exist; never read values. The schema is internal (**verify**). | M | Mode/owner |

### Sessions and usage (internal format, open source in `codex-rs/protocol`)

| Item | Detail |
|---|---|
| Rollouts | `~/.codex/sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl`, plus `~/.codex/archived_sessions/` |
| Usage | `event_msg` lines with `payload.type == "token_count"` → `info.total_token_usage` and `info.last_token_usage`, each with `input_tokens`, `cached_input_tokens`, `output_tokens`, `reasoning_output_tokens`, `total_tokens`. Totals are **cumulative**, so take deltas. The model comes from `turn_context` lines. No `token_count` events exist before 2025-09-06. |
| Mapping | Input = `input_tokens − cached_input_tokens`; Cache read = `cached_input_tokens`; Output = `output_tokens − reasoning_output_tokens`; Thinking = `reasoning_output_tokens`; Cache write is not reported. (Subset relations: **verify** against `protocol.rs`.) |
| Plan limits | `rate_limits` in `token_count` events: `primary` / `secondary` → `used_percent`, `window_minutes`, `resets_at`; `credits` → `has_credits`, `unlimited`, `balance`; `plan_type` |

## Cursor

| Surface | Path | Security-relevant content | Churn | Diff |
|---|---|---|---|---|
| MCP | `~/.cursor/mcp.json`, `<repo>/.cursor/mcp.json` | `mcpServers`; `${env:NAME}`, `${userHome}`, `${workspaceFolder}` interpolation | L | Key-level |
| Hooks | `~/.cursor/hooks.json`, `<repo>/.cursor/hooks.json`, enterprise `/Library/Application Support/Cursor/hooks.json` | `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `beforeSubmitPrompt`; failures fail **open** unless `failClosed: true` | L | Key-level |
| CLI permissions | `~/.cursor/cli-config.json`, `<repo>/.cursor/cli.json` | `Shell(...)`, `Read(...)`, `Write(...)`, `WebFetch(...)`, `Mcp(server:tool)` | M (**verify**) | Key-level |
| Rules and skills | `.cursor/rules/*.mdc` (`alwaysApply`, `globs`), nested `AGENTS.md`; skills in `.cursor/skills`, `~/.cursor/skills`, plus `.agents/skills`, `.claude/skills`, `.codex/skills` | | L | Hash |
| Editor state | `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb` (SQLite; contains the auth token) | **Never open.** File metadata only. | H | None |
| Editor settings | `~/Library/Application Support/Cursor/User/settings.json` (**verify** path) | `security.workspace.trust.enabled` (off by default) | M | Key-level |

**Usage:** Cursor keeps **no per-request token counts on disk**. The Cursor Agent CLI writes transcripts under `~/.cursor/projects` and `~/.cursor/chats` but outputs no token usage (as of July 2026). The app shows Cursor usage as "on cursor.com" with a dashboard link. Never use the cookie-based endpoints other trackers use.

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
| Other | `~/.copilot/{skills,agents,instructions,installed-plugins}/`, `copilot-instructions.md`, `providers.json` (BYOK), `mcp-secrets/` and `mcp-oauth-config/` (fallback secret storage) | Flag fallback secret dirs | L/M | Hash |

**Token precedence:** `COPILOT_GITHUB_TOKEN` > `GH_TOKEN` > `GITHUB_TOKEN` > keychain OAuth > `gh auth token`. Environment variables silently override the stored login (BILL-009). BYOK uses `COPILOT_PROVIDER_BASE_URL`, `COPILOT_PROVIDER_TYPE`, `COPILOT_PROVIDER_API_KEY`.

**Sessions and usage (internal):**

- Files: `~/.copilot/session-state/<session-id>/events.jsonl`, `~/.copilot/session-store.db` (SQLite) and `~/.copilot/logs/process-<ts>-<pid>.log`.
- Token fields on disk are **verify**. GitHub's SDK documents an `assistant.usage` event (`inputTokens`, `outputTokens`, `reasoningTokens`, `cacheReadTokens`, `cacheWriteTokens`, `cost`) but marks it *ephemeral*.
- The Copilot CLI status-line JSON exposes session totals (input, output, cache read, cache write, reasoning, premium requests).
- If nothing is persisted, plan a status-line feed like Claude's.

### VS Code agent mode

| Surface | Path | Content |
|---|---|---|
| MCP | User `mcp.json` (via "MCP: Open User Configuration"; **verify** path), `.vscode/mcp.json` | `servers`, `inputs` (`promptString` with `password: true` → `${input:id}`) |
| Settings | `~/Library/Application Support/Code/User/settings.json` (**verify**) | `chat.tools.global.autoApprove` ("disables critical security protections"), `chat.tools.terminal.autoApprove` |

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
