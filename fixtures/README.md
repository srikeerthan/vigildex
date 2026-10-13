# Fixtures

Redacted sample files for tests. Nothing here is real: no real secrets, no
real user names in paths, no transcript text.

## Layout

```
fixtures/
  homes/<name>/              fake home folders, used through `--home` / `VIGILDEX_HOME`
    basic/                   the smallest home; empty until the first adapters land (M1)
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
  version (`2.1.0`).

## Using a fixture home

```sh
cargo run -p vigildex-cli -- scan --home fixtures/homes/basic --json
VIGILDEX_HOME=fixtures/homes/basic cargo run -p vigildex-cli -- scan
```

`--home` wins over `VIGILDEX_HOME`, which wins over the real home directory.
An override that is empty, missing or not a directory is an error; Vigildex
never falls back to the real home when an override was given.

Tests must never read the developer's real `$HOME`. The CLI test harness
clears the environment and points `HOME` at a path that does not exist, so a
test that forgets `--home` fails instead of scanning your machine.

## Redaction rules

Before you commit a sample (see also `CONTRIBUTING.md`):

1. Replace user names in paths with `you` (`/Users/you/...`).
2. Replace every secret with an obviously fake value of the same shape, such
   as `ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE`. Never commit a real key,
   even a revoked one.
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

## Placeholders

The `.gitkeep` files only keep empty folders in git. Delete one when its
folder gets real content.
