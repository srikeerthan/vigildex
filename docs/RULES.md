# Rules catalogue

Every finding and change event has a stable rule ID. IDs never get reused; retired rules stay listed as retired. Severity is the default and users can't edit it in Phase 1.

| Severity | Meaning | UI glyph (app) |
|---|---|---|
| High | Likely costs money, leaks a credential, or runs untrusted code | Red filled triangle |
| Medium | Risky default or exposure worth fixing soon | Orange filled circle with "!" |
| Low | Hygiene; worth knowing | Blue filled circle with "i" |
| Info | Neutral inventory fact | Grey outline circle with "i" |

Each finding carries **title** (≤ 6 words, shown in lists), **location** (path, line, key path), **masked evidence**, **why** (one sentence, shown on selection), and **fix steps** (per agent, copyable). Keep titles short; the app shows details only when a row is selected.

---

## Secrets (SEC)

Engine: gitleaks/Betterleaks-format TOML rules in `rules/secrets/*.toml` (MIT, with attribution in `NOTICE`), or Kingfisher as an embedded engine (Apache-2.0). **No live verification.** Provider-format checks (prefix plus checksum, e.g. GitHub tokens) come before entropy, to keep false positives down.

**Fields to scan:**

- MCP server `env` values, `headers` / `http_headers` values;
- `args` (`--token=…`, `--api-key …`);
- `url` userinfo and query (`https://user:pass@`, `?key=`), database URLs (`postgres://user:pass@`);
- inline `command` strings (`sh -c "TOKEN=… npx …"`);
- settings `env` blocks;
- `.env` files in watched projects;
- `export` lines in shell profiles.

**Recognised references (never flag):** `${VAR}`, `${VAR:-default}`, `${env:NAME}`, `${input:id}`, `${file:/path}`, `op://…`, `bearer_token_env_var`, `headersHelper`, values pointing at the Keychain.

| ID | Title | Severity | Example | Fix (summary) |
|---|---|---|---|---|
| SEC-001 | Token stored in an MCP config | High | `~/.cursor/mcp.json › github › env › GITHUB_PERSONAL_ACCESS_TOKEN = ghp_••••3f9a` | Replace with an env reference (`${env:…}` in Cursor, `${VAR}` in Claude), then rotate the token |
| SEC-002 | Password in MCP server args/URL | Medium | `acme-api/.mcp.json › postgres › args › postgresql://app:••••@db…` | Use `${DATABASE_URL}` |
| SEC-003 | Secret in a settings `env` block | High | `~/.claude/settings.json › env › OPENAI_API_KEY` | Move to the Keychain / `op run` / env file outside the repo |
| SEC-004 | Secret exported in a shell profile | Medium | `~/.zshrc:42 export GITHUB_TOKEN=…` | Load from the Keychain or 1Password at use time |
| SEC-005 | Secret in a project `.env` the agent auto-loads | Medium | `<repo>/.env` | Keep out of git; check `.gitignore` |
| SEC-006 | Credential file readable by others | High | `~/.claude/.credentials.json` mode not 0600 | `chmod 600` |
| SEC-007 | Secrets in old config backups | Low | `~/.claude/backups/…` still holds a removed token | Delete backups after rotating |

## Billing traps (BILL)

Local only. Never read values; presence and key names are enough.

| ID | Check | Severity | Data |
|---|---|---|---|
| BILL-001 | `ANTHROPIC_API_KEY` set while a Claude subscription login exists (always used in `claude -p`) | High | Shell profiles, `.envrc`, settings `env`; login marker key in `~/.claude.json` (**verify** key name) |
| BILL-002 | `ANTHROPIC_AUTH_TOKEN` set (outranks the API key) | High | Same |
| BILL-003 | `apiKeyHelper` defined (project scope runs in `-p` without trust) | Medium | Claude settings, any scope |
| BILL-004 | `CLAUDE_CODE_OAUTH_TOKEN` exported (a one-year token in plaintext) | Medium | Shell profiles, settings `env` |
| BILL-005 | Cloud provider switch set unintentionally (`CLAUDE_CODE_USE_BEDROCK/VERTEX/FOUNDRY`) | Low | Env and settings |
| BILL-006 | Base URL points at a non-vendor host (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `openai_base_url`, `[model_providers].base_url`, `COPILOT_PROVIDER_BASE_URL`). **High if set in a repo file** (CVE-2026-21852 pattern) | Medium / High | Env, settings `env`, `config.toml`, `.env`; host allowlist in `rules/hosts.toml` plus user-approved gateways and localhost |
| BILL-007 | Codex signed in with an API key or custom provider | Low | `auth.json` key names, `config.toml` |
| BILL-008 | Codex drawing on paid credits (plan limit reached, balance falling) | Medium | Rollout `rate_limits.credits` |
| BILL-009 | Copilot login overridden by `COPILOT_GITHUB_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN`, or a BYOK provider set | Low | Env, `~/.copilot/providers.json` |

**Account checklist (manual, stored ticks only).** These settings live on vendor websites; the app links there and records "last confirmed":

- CHECK-001: Claude extra-usage spend limit set.
- CHECK-002: Claude auto-reload off.
- CHECK-003: ChatGPT/Codex auto top-up off.
- CHECK-004: Cursor on-demand spend limit set.
- CHECK-005: Copilot premium-request budget set.

## Risk flags (RISK)

| ID | Check | Severity |
|---|---|---|
| RISK-001 | MCP server runs a floating version (`npx pkg`, `@latest`, a range, a Docker tag without digest) | Low |
| RISK-002 | Hook or script downloads and runs code (`curl … \| sh`, `wget`, `base64 -d \| sh`, `eval`) | Medium |
| RISK-003 | HTTP hook posts to a non-loopback URL | Medium |
| RISK-004 | Bypass or auto-approve mode on: Claude `defaultMode: bypassPermissions`; Codex `approval_policy = "never"` with `danger-full-access`; VS Code `chat.tools.global.autoApprove: true`; Cursor CLI broad `Shell(*)` allow | Medium |
| RISK-005 | Credentials kept in a plaintext file (Codex `cli_auth_credentials_store = "file"`, Copilot `config.json` token fallback, Copilot `mcp-secrets/` in use) | Low |
| RISK-006 | `enableAllProjectMcpServers: true` | Medium |
| RISK-007 | Skill bundles scripts or has unrestricted `allowed-tools: Bash` | Low |
| RISK-008 | MCP server or hook runs from a hidden or temp folder (`~/.cache/.x/…`, `/tmp/…`) | High |
| RISK-009 | Docker MCP server with `--privileged`, host-root mounts or `--network host` | Medium |
| RISK-010 | Agent binary on `PATH` shadowed or outside its usual install location | High |
| RISK-011 | Plugin `monitors` (persistent background commands) or `bin/` added to `PATH` | Low |
| RISK-012 | Cursor rule with `alwaysApply: true` from a repo | Info |
| RISK-013 | Workspace trust disabled (Cursor default) | Info |

## Change events (CHG) and alert triggers

Every security-key diff becomes a change in the timeline. **Only these send a notification** (`alert = true`):

| ID | Trigger | Default severity |
|---|---|---|
| CHG-001 | New or changed hook (any agent, any scope) | High if no owning agent was running, else Medium |
| CHG-002 | New MCP server, or a changed `command` / `args` / `url` | High if no owning agent was running or it comes from a hidden folder |
| CHG-003 | Folder marked trusted (`hasTrustDialogAccepted`, Codex `trust_level`) that was never opened in that agent | High |
| CHG-004 | New `allow` rule, or bypass/auto-approve mode turned on | Low for "don't ask again" rules written by the agent itself, Medium otherwise |
| CHG-005 | Base URL or API key added anywhere | High |
| CHG-006 | New skill or plugin that runs code | Medium |
| CHG-007 | Fake or shadowed agent binary appears on `PATH` | High |
| CHG-008 | Managed policy file appears or changes | Medium |

Timeline-only (no notification): instruction file edits, rule files, setting toggles that aren't security keys, `AGENTS.md` updates, baseline creation.

## Repo pre-flight (PRE)

When a watched project gains agent config (new folder, or `.git/ORIG_HEAD` changes after a pull), list what it would switch on: `.claude/`, `.mcp.json`, `.codex/`, `.cursor/`, `.github/hooks/`, `.github/copilot/`, `.vscode/mcp.json`, `.agents/`, `AGENTS.md`, `.env`.

Highlight the items that apply **without a trust prompt** in headless runs (Claude hooks, `env`, `apiKeyHelper`, skill `allowed-tools`). Reuse the SEC, BILL and RISK rules on the repo files; findings from repo files go up one severity.

## Rule data files

```
rules/secrets/*.toml     # gitleaks-format: id, description, regex, keywords, entropy, secretGroup, allowlist
rules/hosts.toml         # vendor API hosts per agent (base-URL allowlist)
rules/launchers.toml     # npx/uvx/bunx/pipx/docker patterns and how to read their pins
rules/managers.toml      # known config managers and package managers for attribution
```

Rule changes need a fixture that triggers the rule and one that must not.
