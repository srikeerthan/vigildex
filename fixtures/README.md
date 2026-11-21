# Fixtures

Redacted sample files for tests. Nothing here is real: no real secrets, no
real user names in paths, no transcript text.

## Layout

```
fixtures/
  homes/<name>/              fake home folders, used through `--home` / `VIGILDEX_HOME`
    basic/                   the smallest home: one settings file per agent
    mockup-demo/             the app mockup's data: two projects, plugins, hooks, skills, a stray key
    relocated/               CLAUDE_CONFIG_DIR and CODEX_HOME set in .zshenv, with stale files at the defaults
    messy/                   the rules the mockup does not show, each beside a look-alike that must not fire
  <agent>/<date-or-version>/ raw sample files for one agent's parser tests
    claude/  codex/  cursor/  copilot/
  shared/<date-or-version>/  cross-agent sources: `~/.agents/skills`, shell profiles, `.env` files
```

- **`homes/<name>/`** is laid out exactly like a real home directory
  (`.claude/settings.json`, `.codex/config.toml`, `.zshrc` and so on). The CLI
  and the snapshot tests run against these. `docs/ARCHITECTURE.md` § Testing
  plans `basic`, `mockup-demo` and `messy`; add each one with the milestone
  that needs it.
- **`<agent>/<date-or-version>/`** holds single files as the vendor wrote
  them on that date or in that version, so a parser can be tested against
  each format it has seen. Use an ISO date (`2026-10-04`) or the agent's
  version (`2.1.0`). `crates/vigildex-core/tests/real_samples.rs` assembles
  temporary homes from these and snapshots the inventory.

## Using a fixture home

```sh
cargo run -p vigildex-cli -- scan --home fixtures/homes/basic --json
cargo run -p vigildex-cli -- inventory --home fixtures/homes/mockup-demo
VIGILDEX_HOME=fixtures/homes/basic cargo run -p vigildex-cli -- scan
```

`--home` wins over `VIGILDEX_HOME`, which wins over the real home directory.
An override that is empty, missing or not a directory is an error; Vigildex
never falls back to the real home when an override was given.

Tests must never read the developer's real `$HOME`. The CLI test harness
clears the environment and points `HOME` at a path that does not exist, so a
test that forgets `--home` fails instead of scanning your machine.

### Recorded paths inside a fixture home

Agents write absolute paths into their own files: project keys in
`~/.claude.json` and `config.toml`, plugin `installPath` values. Fixture homes
write them the way a real agent would (`/Users/you/proj/acme-api`,
`/Users/you/.claude/plugins/cache/…`). When such a path does not exist, the
engine retries the same relative path under the scanned home, so
`/Users/you/proj/acme-api` resolves to `fixtures/homes/mockup-demo/proj/acme-api`.
A path that exists nowhere is reported as written (a plugin whose cache folder
is gone shows `installed: false`), which is what a real home with stale
records looks like too.

### What `mockup-demo` contains

The data behind the app mockups (`vigildex-mac/docs/SCREENS.md`). Applying
`docs/RULES.md` with its finding policy to this home yields exactly the nine
findings on the Findings screen, and nothing else:

| Screen row | Rule | Where |
|---|---|---|
| API key bills headless runs | BILL-001 | `.zshrc` line 42, beside `hasAvailableSubscription: true` and a billing `oauthAccount` in `.claude.json` |
| Custom API gateway | BILL-006 | `.claude/settings.json` › `env.ANTHROPIC_BASE_URL` |
| Signed in with an API key | BILL-007 | `.codex/auth.json` with a string `OPENAI_API_KEY` and no `tokens` |
| GitHub token in plain text | SEC-004 | `.zshrc` line 43 |
| Database password in args | SEC-002 | `proj/acme-api/.mcp.json` › postgres |
| Hook pipes curl to sh | RISK-002 | `proj/dotfiles-sync/.claude/settings.json` SessionStart |
| Auto-approves every tool | RISK-004 | `.codex/config.toml` › `approval_policy = "never"` with `danger-full-access` |
| MCP server on @latest | RISK-001 | lint-helper in `.claude.json` (and `.cursor/mcp.json` from M5 on: one finding, two agents) |
| Credentials in a plain file | RISK-005 | `.codex/config.toml` › `cli_auth_credentials_store = "file"` |

The count assumes finding policy 7: the two credential stand-ins are
`0644` in a checkout, so the M2 tests (`crates/vigildex-core/tests/findings.rs`,
the CLI `findings` and `scan` tests) copy the home to a temporary directory
and set their mode to `0600` before scanning. On a checkout, `vigildex
findings --home fixtures/homes/mockup-demo` shows the same nine plus a
SEC-006 for each stand-in whose mode the umask left world-readable. Everything else in the home is inventory
without a finding, or a look-alike that must not fire: a `${LINT_HELPER_TOKEN}` reference, a `Bearer ${GITHUB_TOKEN}`
MCP header and a `Bearer $HOOK_TOKEN` hook header (a reference inside a
header never counts as a secret, whatever its length), a pinned playwright
server, a disabled floating `fetch` server, a localhost provider that no
`model_provider` selects, an HTTP hook to a loopback URL, hook and server
commands under `~/.claude` and `~/.codex` (an agent's own directory is not a
hidden folder), skills with restricted tools, and the `acme-deploy` plugin
with `bin/` and a monitor (inventory tags). `proj/demo-repo` holds the pre-flight sheet's sample files
and is recorded by no agent, so only `preflight` (M6) reads it. Sessions and
usage data for the Sessions and Usage screens arrive with M3.

### What `messy` contains

The rules the mockup does not show, each with a look-alike that must not
fire, for M2's coverage tests. Not covered here because a home directory
alone cannot trigger them: SEC-007 (backups), BILL-008 (Codex rollouts, M3),
RISK-010 (binaries on `PATH`), RISK-013 and the Cursor, Copilot and VS Code
variants of RISK-004, RISK-005 and BILL-009 (adapters in M5). SEC-006 is set
up by the test harness (policy 7): one stand-in gets `0644` as the trigger
and the other `0600` as the look-alike.

- `.zshrc`: `ANTHROPIC_AUTH_TOKEN` (BILL-002, with SEC-004 as a tag),
  `CLAUDE_CODE_OAUTH_TOKEN` (BILL-004, with SEC-004 as a tag),
  `CLAUDE_CODE_USE_BEDROCK` (BILL-005), `OPENAI_API_KEY` (SEC-004),
  `COPILOT_GITHUB_TOKEN` with a `ghu_` value (SEC-004 `GitHub token in plain
  text`, with BILL-009 as a tag: policy 1), `GITHUB_TOKEN=$(op read …)`
  (BILL-009 by name; its value is resolved at use time, so it is a SEC-004
  look-alike); look-alikes: a switch set to `0`, two commented-out keys, and
  a `$(security …)` value.
- `.claude.json`: `disabledMcpjsonServers: ["legacy"]` for `acme-api`, so the
  `legacy` server in that project's `.mcp.json` (a token on `@latest`) is
  skipped by every rule (policy 4); lint-helper with a plaintext token (SEC-001) on `@latest`
  (RISK-001, one finding shared with the Codex copy), `playwright@latest`
  (RISK-001), a `--privileged --network host` Docker server on a floating tag
  (RISK-009, with RISK-001 as a tag), a digest-pinned unprivileged Docker
  server and a pinned npm server that must not fire, a remote server with a
  token in its URL query (SEC-002 `Query credential in a server URL`), a
  remote server whose `headersHelper` embeds a token (SEC-002 `GitHub token
  in a command`), `enableAllProjectMcpServers` on `dotfiles-sync` (RISK-006).
- `.claude/settings.json`: `bypassPermissions` at user scope (RISK-004), an
  `env` block with `OPENAI_API_KEY` (SEC-003), a non-vendor base URL
  (BILL-006) and `ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"` (a reference:
  neither SEC-003 nor BILL-001), `apiKeyHelper` (BILL-003),
  `enableAllProjectMcpServers` (RISK-006), a remote HTTP hook (RISK-003) with
  a token in its query (SEC-003 `Query credential in a hook URL`, a second
  location), `wget | bash` and `eval "$(curl …)"` hooks (RISK-002), a
  loopback HTTP hook that must not fire; `settings.local.json` with a
  `base64 -d /tmp/.p | sh` hook (RISK-002: the executed programs are
  `base64` and `sh`, so RISK-008 does not fire on the data file), a remote
  hook with a literal bearer token in its header (SEC-003 `GitHub token in a
  hook header` beside RISK-003) and a hook command carrying a token (SEC-003
  `Token in a hook command`).
- Skills `yolo` (unrestricted `Bash`, RISK-007) and `tidy` (restricted, must
  not fire); the `acme-deploy` plugin with a plaintext header (SEC-001), a
  second unrestricted-`Bash` skill (RISK-007), a plain command hook that must
  not fire, `bin/` and a monitor (inventory tags).
- `.codex/config.toml`: `approval_policy = "never"` without
  `danger-full-access` (must not fire RISK-004), `cli_auth_credentials_store =
  "keyring"` (must not fire RISK-005), a selected custom provider on a
  non-vendor host (BILL-007 `Uses a custom provider`, BILL-006 on
  `model_providers.proxy.base_url`) beside an `openai_base_url` that is inert
  once the custom provider is selected (must not fire), a localhost provider
  (must not fire), a token in `shell_environment_policy.set` (SEC-003),
  lint-helper with a plaintext token, a plaintext `Authorization` header and
  an `X-Api-Key` header in the same inline table (two SEC-001 findings on one
  line: policy 1 groups a TOML file by key, a profile by line), floating
  `fetch` (RISK-001 `MCP server unpinned`), a pinned server and a disabled
  server with a token (must not fire anything, policy 4); a `curl | sh` hook
  in `hooks.json`; a ChatGPT-mode `auth.json` (must not fire BILL-007). Every
  finding from this file carries its line number.
- `proj/acme-api`: the postgres password in `.mcp.json` (SEC-002) beside a
  `${DATABASE_URL}` reference and a password-free URL (look-alikes), a
  plaintext bearer header beside a `${GITHUB_TOKEN}` reference (SEC-001 and
  its look-alike), `apiKeyHelper`, `DATABASE_URL` and a non-vendor
  `ANTHROPIC_BASE_URL` in project settings (BILL-003, SEC-003, BILL-006),
  `enableAllProjectMcpServers: false`, a project-scope `bypassPermissions`
  and a hook under the repository's own `.claude/hooks/` (none must fire),
  secrets in `.env` (SEC-005, BILL-006), Cursor rules
  with `alwaysApply` true and false (RISK-012 and its look-alike, M5), and a
  project `.codex/config.toml` with `approval_policy = "never"` plus
  `danger-full-access` (RISK-004 at project scope) and an `openai_base_url`
  that Codex ignores in a project file (must not fire).
- `proj/dotfiles-sync`: a hidden-folder server and a `/tmp` server (RISK-008),
  project-scope `bypassPermissions` (inert since Claude Code 2.1.257, must
  not fire), the `curl | sh` hook, and an `apiKeyHelper` with an Anthropic
  key embedded in the command (SEC-003 `Anthropic API key in a helper
  command`, High, with BILL-003 as a tag).
- The plugin's bare-map `.mcp.json` (`{"acme-deploy": {…}}`) keeps its key
  path as written: `acme-deploy.headers.X-Api-Key`.

The two credential stand-ins (`.claude/.credentials.json`, `.codex/auth.json`)
carry the real key names with placeholder or empty values. Git does not keep
a `0600` mode, so their permission bits in a checkout depend on the umask; the
CLI snapshots redact them.

## Redaction rules

Before you commit a sample (see also `CONTRIBUTING.md`):

1. Replace user names in paths with `you` (`/Users/you/...`).
2. Replace every secret with an obviously fake value of the same shape, such
   as `ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE`. Never commit a real key,
   even a revoked one. Keep `FAKE` in the value: the CLI tests assert that the
   string never reaches a report.
3. Delete transcript message text, prompts and tool output. Keep only the
   usage and metadata lines a test needs.
4. Never copy credential files (`.credentials.json`, `auth.json`,
   `state.vscdb`, Copilot `config.json`). Where a test needs one to exist,
   create an empty or key-names-only stand-in.

## Collecting samples from a real Mac

`scripts/collect-fixtures.py` produces the `<agent>/<version-or-date>/` and
`shared/<date>/` samples from a real home directory. It only reads an explicit
allowlist of files, never opens credential or prompt stores (and never follows
symlinks), rebuilds transcripts from a key whitelist, replaces secrets with
same-shape fakes, maps every project path to `/Users/you/proj/<n>`, and copies
nothing until a verifier has passed over the staged output. Run it as:

```sh
python3 -I scripts/collect-fixtures.py plan                       # dry run
python3 -I scripts/collect-fixtures.py write --public-name <repo> # stage, verify, copy
python3 -I scripts/collect-fixtures.py churn                      # mtimes, for the churn spike
python3 -I -m unittest discover -s scripts/tests                  # its tests
```

Review `git diff` before committing; the script never stages anything.

### Provenance of the 2026-10-13 samples

| Folder | Source | Notes |
|---|---|---|
| `claude/2.1.149` … `2.1.296` | Claude Code transcripts, one per CLI version, first 150 records each; one subagent transcript (2.1.295) | Side record types keep one blanked sample each. `2.1.209` has no `output_tokens_details`; later versions do. |
| `claude/2.1.296/` | `settings.json`, `settings.local.json`, `claude.json` (reduced `~/.claude.json`), `plugins/*`, three official-marketplace plugin manifests, one session lock file | `autoMode.environment` and over-long rules are blanked; a third-party marketplace is renamed `marketplace-1`. |
| `codex/0.32.0`, `0.44.0`, `0.46.0` | One rollout per CLI version plus a no-turn session | Every `token_count` and `turn_context` row is kept; prose rows are blanked. |
| `codex/0.46.0/` | `config.toml`, `version.json`, legacy TypeScript-era files, three **synthesized** `auth.*.json` stand-ins | The real `auth.json` was never opened; the stand-ins carry the key names from the Codex source. |
| `cursor/2026-10-13/` | `cli-config.json`, `argv.json` (JSONC), one `.workspace-trusted` marker | No Cursor IDE on the source machine. |
| `copilot/2026-10-13/` | One Copilot CLI 1.0.96 `events.jsonl` (no turns), VS Code user settings reduced to the Copilot and chat keys | `assistant.usage` is still unverified. |
| `shared/2026-10-13/` | `.zshrc` reduced to its key-bearing `export` lines | Values are fakes of the same shape. |

`homes/mockup-demo`, `homes/basic`, `homes/relocated` and `homes/messy` are
hand-written (13 Oct 2026) from the formats confirmed in `docs/DATA_SOURCES.md`; they are
not copies of a real machine. `relocated` exercises the behaviour confirmed on
Claude Code 2.1.296 and codex-cli 0.162.1: with `CLAUDE_CONFIG_DIR` or
`CODEX_HOME` set, the agent reads only the relocated directory, so the
inventory reports the files left at the default locations as warnings.

## Placeholders

The `.gitkeep` files only keep empty folders in git. Delete one when its
folder gets real content.
