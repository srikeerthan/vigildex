# Fixtures

Redacted sample files for tests. Nothing here is real: no real secrets, no
real user names in paths, no transcript text.

## Layout

```
fixtures/
  homes/<name>/              fake home folders, used through `--home` / `VIGILDEX_HOME`
    basic/                   the smallest home: one settings file per agent
    mockup-demo/             the app mockup's data: two projects, plugins, hooks, skills, a stray key
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

The data behind the app mockups, arranged so that later milestones can
reproduce the mockup's findings from it:

| Where | What | Later rule |
|---|---|---|
| `.zshrc` | `ANTHROPIC_API_KEY` exported beside a Max subscription login in `.claude.json` | SEC-004, BILL-001 |
| `.claude.json` | `lint-helper` (`npx … @latest`, floating) and `context7` at user scope; `playwright` and trust markers per project; the home itself as a project | RISK-001, CHG-003 |
| `.claude/settings.json` | `env` with a base URL and an API key, an HTTP hook, a formatter hook, `enabledPlugins`, a status line | SEC-003, BILL-006, RISK-003 |
| `.claude/plugins/` | Four installed plugins, one of them (`superpowers`) with a missing cache folder; `acme-deploy` bundles hooks, a bare-map `.mcp.json`, a skill, `bin/` and a monitor | RISK-011 |
| `.claude/skills/`, `commands/`, `agents/` | A skill with `allowed-tools: Bash` and frontmatter hooks, a legacy command, a subagent with an inline MCP server | RISK-007 |
| `.codex/config.toml` | `approval_policy = "never"` with `danger-full-access`, a plaintext credential store, a local provider, three MCP servers, an inline hook with trust state, two trusted projects, a disabled skill | RISK-004, RISK-005, BILL-007 |
| `proj/acme-api/` | `.mcp.json` with a password in a `postgres` URL and a headers helper, project settings with `apiKeyHelper` and hooks, rules, a skill, `.codex/` config and hooks, a shared skill, `.env` | SEC-002, BILL-003, SEC-005 |
| `proj/dotfiles-sync/` | A `curl … \| sh` hook, `bypassPermissions`, an MCP server from a hidden folder, `AGENTS.md` without `CLAUDE.md` | RISK-002, RISK-004, RISK-008 |

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

`homes/mockup-demo` and `homes/basic` are hand-written (13 Oct 2026) from the
formats confirmed in `docs/DATA_SOURCES.md`; they are not copies of a real
machine.

## Placeholders

The `.gitkeep` files only keep empty folders in git. Delete one when its
folder gets real content.
