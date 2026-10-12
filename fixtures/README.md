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

## Placeholders

The `.gitkeep` files only keep empty folders in git. Delete one when its
folder gets real content.
