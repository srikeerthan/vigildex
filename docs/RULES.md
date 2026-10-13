# Rules catalogue

Every finding and change event has a stable rule ID. IDs never get reused; retired rules stay listed as retired. Severity is the default and users can't edit it in Phase 1.

| Severity | Meaning | UI glyph (app) |
|---|---|---|
| High | Likely costs money, leaks a credential, or runs untrusted code | Red filled triangle |
| Medium | Risky default or exposure worth fixing soon | Orange filled circle with "!" |
| Low | Hygiene; worth knowing | Blue filled circle with "i" |
| Info | Neutral inventory fact | Grey outline circle with "i" |

Each finding carries **title** (≤ 6 words, shown in lists), **location** (path, line, key path), **masked evidence**, **why** (one sentence, shown on selection), and **fix steps** (per agent, copyable). Keep titles short; the app shows details only when a row is selected.

## List titles

The titles shown in lists come from the app screens (`vigildex-mac/docs/SCREENS.md`) and are the canonical `title` of a finding; the Check columns below describe the condition. `{Kind}` is the secret kind the matching rule names (GitHub token, database password, API key).

| ID | List title |
|---|---|
| SEC-001 | `{Kind} in an MCP config` |
| SEC-002 | `{Kind} in args` |
| SEC-003 | `{Kind} in settings env` |
| SEC-004 | `{Kind} in plain text` |
| SEC-005 | `{Kind} in .env` |
| SEC-006 | `Credential file readable by others` |
| SEC-007 | `Secret left in a backup` |
| BILL-001 | `API key bills headless runs` |
| BILL-002 | `Auth token overrides your plan` |
| BILL-003 | `Key helper bills headless runs` |
| BILL-004 | `OAuth token in plain text` |
| BILL-005 | `Cloud provider switch is on` |
| BILL-006 | `Custom API gateway` (Medium); `Sends your API key elsewhere` (High, repo file) |
| BILL-007 | `Signed in with an API key`; `Uses a custom provider` |
| BILL-008 | `Codex is spending credits` |
| BILL-009 | `Token overrides Copilot login` |
| RISK-001 | `MCP server on @latest` (`MCP server unpinned` for a range or missing version) |
| RISK-002 | `Hook pipes curl to sh` (`Hook downloads and runs code` for the other patterns) |
| RISK-003 | `Hook posts to a remote URL` |
| RISK-004 | `Auto-approves every tool` |
| RISK-005 | `Credentials in a plain file` |
| RISK-006 | `Trusts every project MCP server` |
| RISK-007 | `Skill can run any command` |
| RISK-008 | `Server runs from a hidden folder` |
| RISK-009 | `Docker server runs privileged` |
| RISK-010 | `Agent binary is shadowed` |
| RISK-012 | `Rule in every Cursor chat` |
| RISK-013 | `Workspace trust is off` |

## Finding policy

These rules decide how many findings a set of matches becomes. They were fixed on 13 Oct 2026 from the nine findings the app screens show for `fixtures/homes/mockup-demo`.

1. **One finding per location.** When several rules match the same file and key (or the same line of a profile), the highest-severity rule wins and the other IDs are recorded as tags on that finding; on equal severity the rule that names the key (BILL, RISK) beats the generic secret rule (SEC). So BILL-001 over SEC-004 for an exported `ANTHROPIC_API_KEY`, BILL-004 over SEC-004 for `CLAUDE_CODE_OAUTH_TOKEN`, SEC-004 over BILL-009 for an exported `GITHUB_TOKEN`, and RISK-009 over RISK-001 for a privileged Docker server on a floating tag.
2. **No cross-file merge.** The same secret in two files is two findings, each with the rule of its own location.
3. **One finding per server across agents.** The same MCP server (same name and launch) configured for several agents is one finding that carries every agent.
4. **Disabled things.** A server with `enabled = false`, and every component of a plugin that `enabledPlugins` turns off, is inventoried but skipped by every rule.
5. **Inventory tags, not findings.** A skill that merely bundles scripts, a plugin with `monitors` or `bin/` (RISK-011), and a hook that runs a package runner (`npx prettier …`) are shown as "Why flagged" tags on the inventory row; RISK-007 fires only on an unrestricted `Bash` in `allowed-tools`, and RISK-002 only on its listed patterns.
6. **Repo severity bump.** The one-step bump for repository files applies to pre-flight reports only; the Findings list keeps catalogue severities.
7. **Permission bits.** SEC-006 reads the mode of the real file. Git stores no `0600`, so fixture tests copy the home to a temporary directory and set the stand-ins' modes explicitly.
8. **Masks.** Evidence keeps a short prefix and the last three characters: `sk-ant-••••7Qa`, `ghp_••••f9a`. A rule must capture the whole token, so the mask ends with the token's real last characters.
9. **Fixture fakes.** Secret rules match on vendor prefix and length class (`ghp_` plus 36 characters, `sk-ant-api03-` plus at least 80), never on entropy alone, so the `FAKE` values in `fixtures/` trigger them.

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

| ID | Check | Severity | Example | Fix (summary) |
|---|---|---|---|---|
| SEC-001 | Token stored in an MCP config | High | `~/.cursor/mcp.json › github › env › GITHUB_PERSONAL_ACCESS_TOKEN = ghp_••••f9a` | Replace with an env reference (`${env:…}` in Cursor, `${VAR}` in Claude), then rotate the token |
| SEC-002 | Password in MCP server args/URL | Medium | `acme-api/.mcp.json › postgres › args › postgresql://app:••••@db…` | Use `${DATABASE_URL}` |
| SEC-003 | Secret in a settings `env` block | High | `~/.claude/settings.json › env › OPENAI_API_KEY` | Move to the Keychain / `op run` / env file outside the repo |
| SEC-004 | Secret exported in a shell profile | Medium | `~/.zshrc:43 export GITHUB_TOKEN=…` | Load from the Keychain or 1Password at use time |
| SEC-005 | Secret in a project `.env` the agent auto-loads | Medium | `<repo>/.env` | Keep out of git; check `.gitignore` |
| SEC-006 | Credential file readable by others | High | `~/.claude/.credentials.json` mode not 0600 | `chmod 600` |
| SEC-007 | Secrets in old config backups | Low | `~/.claude/backups/…` still holds a removed token | Delete backups after rotating |

## Billing traps (BILL)

Local only. Never read values; presence and key names are enough.

| ID | Check | Severity | Data |
|---|---|---|---|
| BILL-001 | `ANTHROPIC_API_KEY` set while a Claude subscription login exists (always used in `claude -p`) | High | Shell profiles, `.envrc`, settings `env`; login marker in `~/.claude.json`: `hasAvailableSubscription` plus an `oauthAccount` with billing keys (`billingType`, `organizationType`), key names only |
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
| RISK-004 | Bypass or auto-approve mode on: Claude `defaultMode: bypassPermissions` in user or managed settings (a project or local value is inert since Claude Code 2.1.257 and is inventoried, not reported); Codex `approval_policy = "never"` with `danger-full-access`; VS Code `chat.tools.global.autoApprove: true`; Cursor CLI broad `Shell(*)` allow | Medium |
| RISK-005 | Credentials kept in a plaintext file (Codex `cli_auth_credentials_store = "file"`, Copilot `config.json` token fallback, Copilot `mcp-secrets/` in use) | Low |
| RISK-006 | `enableAllProjectMcpServers: true` | Medium |
| RISK-007 | Skill has unrestricted `allowed-tools: Bash` (bundled scripts are an inventory tag, finding policy 5) | Low |
| RISK-008 | MCP server or hook runs from a hidden or temp folder (`~/.cache/.x/…`, `/tmp/…`). Paths inside the owning agent's own directory (`~/.claude`, `~/.codex`, `~/.cursor`, `~/.copilot`, their relocated forms) and the plugin cache (`${CLAUDE_PLUGIN_ROOT}`) are not hidden folders | High |
| RISK-009 | Docker MCP server with `--privileged`, host-root mounts or `--network host` | Medium |
| RISK-010 | Agent binary on `PATH` shadowed or outside its usual install location | High |
| RISK-011 | Plugin `monitors` (persistent background commands) or `bin/` added to `PATH` | Low |
| RISK-012 | Cursor rule with `alwaysApply: true` from a repo | Info |
| RISK-013 | Workspace trust disabled (Cursor default) | Info |

## Change events (CHG) and alert triggers

Every security-key diff becomes a change in the timeline. **Only these send a notification** (`alert = true`):

| ID | Trigger | List title | Default severity |
|---|---|---|---|
| CHG-001 | New or changed hook (any agent, any scope) | `New hook` / `Hook changed` | High if no owning agent was running, else Medium |
| CHG-002 | New MCP server, or a changed `command` / `args` / `url` | `New MCP server` / `MCP server changed` | High if no owning agent was running or it comes from a hidden folder |
| CHG-003 | Folder marked trusted (`hasTrustDialogAccepted`, Codex `trust_level`) that was never opened in that agent | `Folder marked trusted` | High |
| CHG-004 | New `allow` rule, or bypass/auto-approve mode turned on | `New allow rule` / `Bypass mode turned on` | Low for "don't ask again" rules written by the agent itself, Medium otherwise |
| CHG-005 | Base URL or API key added anywhere | `API key or base URL added` | High |
| CHG-006 | New skill or plugin that runs code | `New skill or plugin` | Medium |
| CHG-007 | Fake or shadowed agent binary appears on `PATH` | `Agent binary changed on PATH` | High |
| CHG-008 | Managed policy file appears or changes | `Managed policy changed` | Medium |

The notification title is the list title and its body names the item and its agents (`New MCP server` / `lint-helper · Claude Code, Cursor`); the list row shows the title with the item name as its grey detail. (`SCREENS.md` § 2 still says "New MCP server added"; the app should use the list title.)

Timeline-only (no notification): instruction file edits, rule files, setting toggles that aren't security keys, `AGENTS.md` updates, baseline creation.

## Repo pre-flight (PRE)

When a watched project gains agent config (new folder, or `.git/ORIG_HEAD` changes after a pull), list what it would switch on: `.claude/`, `.mcp.json`, `.codex/`, `.cursor/`, `.github/hooks/`, `.github/copilot/`, `.vscode/mcp.json`, `.agents/`, `AGENTS.md`, `.env`.

Highlight the items that apply **without a trust prompt** in headless runs (Claude hooks, `env`, `apiKeyHelper`, skill `allowed-tools`). Reuse the SEC, BILL and RISK rules on the repo files; in the pre-flight report (and only there) their severity goes up one step, capped at High. Rows that have no SEC, BILL or RISK rule carry a PRE ID:

| ID | Row | List title | Severity |
|---|---|---|---|
| PRE-001 | A hook in a repo settings file; runs in headless sessions with no trust prompt | `Runs a script at {event}` (`Runs a script at session start`) | Medium |
| PRE-002 | An instruction file the agent loads (`CLAUDE.md`, `AGENTS.md`, rules) | `Agent instructions` | Info |
| PRE-003 | A repo `env` block, `apiKeyHelper` or skill `allowed-tools` that applies without trust | `Settings apply without trust` | Medium |

The sample sheet for `fixtures/homes/mockup-demo/proj/demo-repo`: BILL-006 at High (`Sends your API key elsewhere`), PRE-001 (`Runs a script at session start`), RISK-001 raised to Medium (`MCP server on @latest`), RISK-012 raised to Low (`Rule in every Cursor chat`), PRE-002 (`Agent instructions`, 118 lines).

## Rule data files

```
rules/secrets/*.toml     # gitleaks-format: id, description, regex, keywords, entropy, secretGroup, allowlist
rules/hosts.toml         # vendor API hosts per agent (base-URL allowlist)
rules/launchers.toml     # npx/uvx/bunx/pipx/docker patterns and how to read their pins
rules/managers.toml      # known config managers and package managers for attribution
```

Rule changes need a fixture that triggers the rule and one that must not.
