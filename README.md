# vigildex

**See everything your AI coding agents can run, know when it changes, and catch the config mistakes that cost you money.**

Vigildex is a local, read-only engine and CLI for Claude Code, OpenAI Codex, Cursor and GitHub Copilot. It:

- **Inventories** every MCP server, hook, skill, plugin, instruction file and security setting, per agent and scope.
- **Watches** for changes, with a setting-level timeline and a "probably changed by" label.
- **Finds** plaintext secrets, billing traps (such as a stray `ANTHROPIC_API_KEY` that quietly replaces your subscription) and risky settings.
- **Reads** local session logs for tokens by type (input, cache write, cache read, output, thinking) and estimated cost.
- **Pre-flights** freshly cloned repos before you run an agent in them.

It never sends anything off your machine, never reads credential values and never writes to your agents' files.

> **Status:** pre-alpha. Nothing to install yet.

## Planned usage

```sh
brew install srikeerthan/tap/vigildex     # not yet published
vigildex scan
vigildex findings --fail-on high
vigildex usage --week --by type
vigildex preflight ~/code/some-new-repo
```

A native macOS menu bar app built on this engine is in development.

## Principles

- **Read-only.** Vigildex doesn't change your setup.
- **Local-only.** No account, no telemetry, no network calls.
- **Honest.** It detects and explains; it doesn't claim to prevent attacks.

See [docs/PRIVACY.md](docs/PRIVACY.md) for exactly what it reads and stores.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Data sources per agent](docs/DATA_SOURCES.md)
- [Rules catalogue](docs/RULES.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Licence

Apache-2.0. "Vigildex" and the Vigildex logo are trademarks; see [TRADEMARKS.md](TRADEMARKS.md).
