# Privacy and data-source rules

Vigildex reads some of the most sensitive files on a developer's machine. These rules are the promise to users. Code that breaks them doesn't merge.

## What Vigildex may and may not do

| May | May not |
|---|---|
| Read agent config files at documented paths | Read credential values, other apps' Keychain items or browser cookies |
| Read local session and usage logs (usage and metadata fields only) | Store prompts, responses, tool output or file contents from transcripts |
| Run agents' own read-only commands, such as `claude agents --json` | Call undocumented vendor endpoints with the user's tokens |
| Check that credential files exist, and their permissions | Send file contents, secrets or transcripts off the machine |
| List running processes to label who probably changed a file | Send telemetry or crash reports |
| Show masked secrets (prefix and last 3–4 characters) | Test found keys against the provider's API |
| Call official APIs with the user's own key, opt-in, in later phases (e.g. OpenRouter key limits) | Write to agent configs in Phase 1, except the opt-in status-line helper |

## What is stored, and where

Everything lives in `~/Library/Application Support/Vigildex/`. Delete the folder to remove all of it.

- **`vigildex.db`** (SQLite):
  - config snapshots of security-relevant keys only, with secrets masked;
  - change history;
  - findings with salted fingerprints (no values);
  - daily token counts;
  - session metadata (agent, project path, times, token counts);
  - checklist ticks.
- **`claude-limits.json`** (only if the Phase 1b helper is installed): the latest 5-hour and weekly percentages and reset times.

## Network

The engine and CLI make no network connections. The macOS app connects only to check for app updates (Sparkle, signed). That's stated in the app's privacy note, and users can turn it off.
