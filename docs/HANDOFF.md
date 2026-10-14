# Handoff: Vigildex engine

_Prepared 4 Oct 2026 from the research and design sessions that named and scoped the product. Paths, field names and vendor behaviour come from vendor docs read on that date; anything marked **verify** has not been confirmed on real files._

## What we're building

**Vigildex** shows what your AI coding agents can run, tells you when that changes, and catches the config mistakes that cost you money. It's local-first and read-only, and it never sends anything off your machine.

- **Users:** individual developers who run two or more agents (Claude Code, Codex, Cursor, Copilot) on a Mac.
- **Shape:** an open-source Rust engine and CLI (this repo), plus a closed SwiftUI menu bar app (`vigildex-mac`) that embeds the engine.
- **Positioning:** "see everything your AI agents can run, know when it changes, and catch the config mistakes that cost you money."

### Why this shape

- Usage trackers (ccusage, CodexBar, tokscale, Agent Sessions) are commodities. Usage alone isn't a product.
- Enterprise tools (Fleet's `ai_tools` table, GitGuardian `ggshield ai discover`, 1Password Device Trust AI Insights) already inventory agents for security teams through MDM.
- Free scanners (Snyk Agent Scan, Cisco MCP and Skill scanners) scan once but don't watch.
- The gap is **local, consumer-grade cross-agent change monitoring plus secret and billing lint for individuals**. An open engine earns the trust a tool like this needs: anyone can check what it reads.
- Full research is in `docs/research/`.

## Principles (apply to every phase)

1. **Read-only first.** Phase 1 never writes to agent configs, except the opt-in status-line helper (1b).
2. **Local-only.** No account and no telemetry. Secrets, transcripts and file contents never leave the machine.
3. **Open engine.** Anyone can check exactly what Vigildex reads.
4. **Few alerts.** Only high-signal changes notify; everything else waits in the timeline.
5. **Honest claims.** Vigildex detects, explains and helps recovery. It does not prevent attacks, and "probably changed by" is a heuristic.
6. **Safe data sources only.** Documented files and sanctioned interfaces. No undocumented endpoints, cookies or credential values.

## Decisions already made

| Decision | Choice | Why |
|---|---|---|
| Name | **Vigildex** (wordmark lowercase "vigildex") | Vigil = keeping watch; dex = index. No exact-name conflicts found; "Vigil" is crowded, so always use the full name. |
| Licence | Apache-2.0 for the engine, CLI, rules and status-line helper; the app is closed | Patent grant, permissive, compatible with a paid app |
| Language | Rust workspace | Fast, safe parsers; one core for CLI, app and later Windows/Linux |
| App integration | UniFFI → XCFramework → Swift Package binary target | Native SwiftUI app; engine in-process |
| Platform | macOS first (14+); Windows/Linux in Phase 3 | Attribution and UX are best on macOS |
| Phase 1 agents | Claude Code, Codex, Cursor, GitHub Copilot (CLI and VS Code agent mode) | Most-used set; together they cover the main config formats |
| Secret rules | gitleaks/Betterleaks-format TOML rules (MIT), or Kingfisher (Apache-2.0) as an embeddable engine | Licence-clean. **Not TruffleHog** (AGPL). |
| Prices | Vendored LiteLLM `model_prices_and_context_window.json` (MIT) snapshot | The table every tracker uses; offline |
| Token categories | Input, Cache write, Cache read, Output, Thinking | What the agents actually report (see DATA_SOURCES) |
| Attribution | Heuristic: process snapshot plus agent session windows ("probable writer" with confidence) | Endpoint Security needs Apple approval and root; deferred to Phase 5 |
| Distribution | GitHub Releases via `cargo-dist`, a Homebrew tap, and crates.io | Standard Rust distribution |
| Contributions | DCO sign-off, no CLA | Lighter for contributors; Apache-2.0 covers patents |

## Phase 1 scope (engine)

| Feature | Engine output | Data source |
|---|---|---|
| Inventory ("What can run") | Every MCP server, hook, skill, plugin, instruction file and security setting, per agent and scope. Each item has its exact command or URL, source file, first seen, pinned or floating, and flags. | Agent config files at documented paths |
| Change history | Baseline on first scan, then setting-level diffs with a probable-writer label and confidence | File watcher, snapshots in SQLite, process list |
| Findings: secrets | Plaintext keys in MCP configs, settings `env` blocks, auto-loaded `.env` files and shell profiles, masked, with per-agent fix steps | Local secret rules |
| Findings: billing traps | Stray API keys beside a subscription login, base URLs to unknown hosts, Codex on an API key, Copilot token overrides | Shell profiles, `.envrc`, settings `env`, auth mode (key names only) |
| Findings: risk flags | Floating `npx`/`uvx` servers, hooks that download and run code, remote HTTP hooks, bypass/auto-approve modes, plaintext credential files | Parsed configs, file permissions |
| Sessions | Running and recent sessions: agent, project, state, start, last activity, token breakdown | `claude agents --json`, `~/.claude/sessions/`, Claude/Codex/Copilot session files, process list |
| Usage | Tokens by type, agent, model and day; estimated cost at list price; Codex plan-limit windows | Session logs and the vendored price table |
| Repo pre-flight | When a watched folder gains agent config (clone or pull): what it would switch on | Watcher on project folders the user chooses |
| Alerts (events for the app) | Only: new or changed hook; new MCP server or changed command/URL; folder marked trusted that was never opened; new allow rule or bypass mode; added base URL or API key; new skill or plugin that runs code; a fake agent binary on `PATH` | Change engine |
| **1b** Claude plan limits | 5-hour and weekly percentages and reset times | Claude Code status-line JSON via an opt-in helper |

The account checklist (spend caps, auto-reload off) is manual and lives in the app; the engine only stores the ticks.

## Milestones

Rough estimates for one developer. Each milestone ends with the CLI showing the new data.

| # | Milestone | Done when |
|---|---|---|
| M0 | Workspace, CI (fmt, clippy, test, deny, audit on macOS and Linux), fixtures layout, `--home` override | `vigildex --version` builds in CI |
| M1 | Claude Code and Codex adapters → inventory | `vigildex inventory --json` lists MCP servers, hooks, skills, plugins, instructions and security settings from fixtures |
| M2 | Findings: secrets, billing, risk | `vigildex findings` reproduces the mockup's 9 findings (`SCREENS.md` § 6; the row-to-rule-to-file map is in `fixtures/README.md`, titles in `docs/RULES.md` § List titles) from `fixtures/homes/mockup-demo`, and `fixtures/homes/messy` covers the other rules a home can trigger, each with a look-alike |
| M3 | Sessions and usage with the token breakdown and pricing | `vigildex usage --week` matches hand-computed totals on fixtures |
| M4 | Baseline, watcher, key-level diff, attribution, alert events | Editing a fixture config prints one `CHG-` event with a writer label |
| M5 | Cursor and Copilot adapters | Inventory and findings cover all four agents |
| M6 | Repo pre-flight | `vigildex preflight <dir>` lists what a repo would switch on |
| M7 | FFI and XCFramework release; CLI 0.1 via `cargo-dist` and Homebrew | The app repo builds against a tagged engine release |
| 1b | `vigildex-statusline` helper plus install/uninstall plan | The helper passes through any existing status line unchanged and records limits |

**Milestone status (14 Oct 2026):** M0, M1 and M2 are done. `vigildex findings --home fixtures/homes/mockup-demo` yields the nine screen findings once the credential stand-ins are `0600` (the tests copy the home and set the modes), and `fixtures/homes/messy` triggers every other implemented rule beside its look-alikes. M3 (sessions and usage) is next.

## Do these first: verification spikes on a real Mac

Run each agent for a day, then confirm the following. Save **redacted** samples into `fixtures/` and update `DATA_SOURCES.md`.

1. **Claude Code transcripts.** Do assistant `message.usage` entries include `cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens` and any separate thinking count (`output_tokens_details.thinking_tokens`, which the API now reports)? Where is the subscription-login marker in `~/.claude.json` (key name only)?
2. **Claude status line.** Does the stdin JSON contain `rate_limits.five_hour` / `seven_day` on your plan and version? Can a wrapper pass through an existing status line safely?
3. **Codex rollouts.** Confirm the `token_count` structure (`info.total_token_usage`, `last_token_usage`, `rate_limits`) and that `cached_input_tokens` ⊂ `input_tokens` and `reasoning_output_tokens` ⊂ `output_tokens`.
4. **Copilot CLI.** Are per-request token counts persisted anywhere (`~/.copilot/session-state/<id>/events.jsonl`, `session-store.db`)? The SDK calls `assistant.usage` ephemeral. If they aren't stored, plan a status-line feed like Claude's.
5. **Churn.** How often does each agent rewrite its own config files? This sets the alert noise budget.
6. **Codex auth precedence.** Which credential wins when `OPENAI_API_KEY` or `CODEX_API_KEY` sits beside a ChatGPT login?

**Status (13 Oct 2026, one Mac; details in `DATA_SOURCES.md`, samples under `fixtures/`):**

1. Done. The 5m/1h split is on every record from 2.1.209 to 2.1.296 and sums to `cache_creation_input_tokens`; `output_tokens_details.thinking_tokens` exists from 2.1.266 on; the login marker is `oauthAccount` plus `hasAvailableSubscription`.
2. Open. No status line was configured; capture it with `claude --settings <file>` (no write to real settings).
3. Done for 0.32–0.46: structure confirmed, containment held on 131/131 events, totals cumulative. Caveats: `resets_in_seconds` not `resets_at`, duplicate events in 0.44, `info: null` on the first event. Current releases still to confirm.
4. Partly. Copilot CLI 1.0.96 was installed on 13 Oct; a no-turn session persisted only context-window counts (`session.info`). Re-check after a real turn.
5. Done. `~/.claude.json` every 60–70 s; `settings.json` at every session start; Codex writes `config.toml` on trust and `auth.json` on refresh; Cursor nothing in a year. A 24-hour diff of `scripts/collect-fixtures.py churn` output remains.
6. Done. `CODEX_API_KEY` wins in `codex exec` only; the TUI ignores it; `OPENAI_API_KEY` is never read; inside `auth.json` the API key wins over tokens.

## Open questions (product)

- From the screens review of 13 Oct 2026 (`SCREENS.md` against the fixture and the rules): the What Can Run inspector example shows lint-helper running `node ~/.cache/.lh/index.js` (a hidden folder, RISK-008 High) while the Findings screen lists no such finding; in the fixture lint-helper runs `npx -y @acme/lint-helper@latest`, so the inspector example should show a floating-version server. The "41 items · 4 agents" counts need Cursor and Copilot (M5) and should be re-derived from the fixture then. The Cursor session row has no local data source. Copilot "38 premium" needs a premium-request feed (Copilot status line, 1b). The header tooltip "Nothing leaves this Mac" should allow for the app's signed update check (`PRIVACY.md`). `acknowledgeFinding` is marked "later" although "9 open" means "not acknowledged". The § 2 notification title "New MCP server added" should be the CHG-002 list title `New MCP server`.
- Does Claude Code expand `${VAR}` references inside a settings `env` block? The engine treats such a value as not set (never as a secret) until this is confirmed on a real install (`docs/DATA_SOURCES.md`).
- Do hooks still run in YOLO/bypass modes in Cursor and Copilot? (Phase 3 enforcement depends on it.)
- Can a repository's `"disableAllHooks": true` switch off a user's hooks in Claude Code?
- Apply for Apple's Endpoint Security entitlement early. There's no stated timeline, and one report says about 2 months.

## Where the design lives

Screens, brand and app architecture are in the private `vigildex-mac` repo (`docs/SCREENS.md`, `docs/DESIGN.md`). The engine must provide every field those screens show; `docs/ARCHITECTURE.md` § FFI surface lists them.
