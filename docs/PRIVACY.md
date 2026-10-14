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
| Show masked secrets (a vendor prefix and the last three characters for recognised tokens; the last three only for unknown shapes; nothing for passwords) | Test found keys against the provider's API |
| Call official APIs with the user's own key, opt-in, in later phases (e.g. OpenRouter key limits) | Write to agent configs in Phase 1, except the opt-in status-line helper |

## What is stored, and where

Everything lives in `~/Library/Application Support/Vigildex/`. Delete the folder to remove all of it.

- **`vigildex.db`** (SQLite):
  - config snapshots of security-relevant keys only, with secrets masked;
  - change history;
  - findings with masked evidence only; a keyed fingerprint (HMAC under a per-installation key kept in the store) arrives with M4, and until then no digest of a secret is computed at all;
  - daily token counts;
  - session metadata (agent, project path, times, token counts);
  - checklist ticks.
- **`claude-limits.json`** (only if the Phase 1b helper is installed): the latest 5-hour and weekly percentages and reset times.

## Files read for findings

Shell profiles (`.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.profile`, `.bash_profile`, `.bash_login`, `.bashrc`, `.envrc`) and the `.env` at each project root are read for the variables they set. Each value is classified and run through the secret rules while it is in memory, then dropped: a report shows the variable name, whether it is set, and masked evidence. These files are listed without a content hash, because a hash of a few `NAME=value` lines would be a checkable digest of the secrets in them. Parser warnings name a line number, never the line.

## Network

The engine and CLI make no network connections. The macOS app connects only to check for app updates (Sparkle, signed). That's stated in the app's privacy note, and users can turn it off.
