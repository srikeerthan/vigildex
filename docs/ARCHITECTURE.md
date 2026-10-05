# Architecture

The design below is a proposal. Change it when real files disagree, but keep the hard rules in `CLAUDE.md`.

## Overview

```
            ┌──────────────────────────── vigildex-core ────────────────────────────┐
 files ───► │ adapters (claude, codex, cursor, copilot, shared)                       │
 process    │   discover ─► parse ─► normalize to Items                               │
 list   ──► │ analyzers: secrets · billing · risk · capability                       │──► Findings
            │ store (SQLite): baseline snapshots, changes, findings, usage cache      │
            │ watch (notify + debounce) ─► hash ─► parse ─► key-level diff            │──► Changes / AlertEvents
            │ attribution: process snapshot + agent session windows                   │
            │ sessions + usage readers (incremental tail) ─► pricing                  │──► Sessions / Usage
            └────────────────────────────────────────────────────────────────────────┘
                 ▲                         ▲                          ▲
          vigildex-cli               vigildex-ffi (UniFFI)      vigildex-statusline (1b)
          (`vigildex …`)             → XCFramework → Swift app   (Claude status-line wrapper)
```

The engine runs **in-process**: inside the CLI for one-shot commands, and inside the macOS app (a login item) for continuous watching. There's no separate daemon in Phase 1. A LaunchAgent can come later if background watching without the app is needed.

## Crates

| Crate | Purpose | Key dependencies |
|---|---|---|
| `vigildex-core` | Everything that isn't I/O glue | `serde`, `serde_json`, `jsonc-parser`, `toml_edit` (spans and line numbers), `dotenvy` (or a small line parser), `regex`, `sha2`, `rusqlite` (bundled), `notify` + `notify-debouncer-full`, `sysinfo`, `schemars`, `thiserror`, `time` |
| `vigildex-cli` | `vigildex` binary | `clap`, `anyhow`, `owo-colors` (or similar) |
| `vigildex-ffi` | UniFFI proc-macro bindings; built as a static lib for an XCFramework | `uniffi` |
| `vigildex-statusline` | Tiny binary for Phase 1b; no dependency on core beyond a shared `limits` module | `serde_json` |

Dev and CI tools: `insta`, `cargo-deny`, `cargo-audit`, `cargo-dist`.

## Core model (sketch)

```rust
enum Agent { ClaudeCode, Codex, Cursor, CopilotCli, VsCodeAgent }
enum Scope { Managed, User, Project { root: PathBuf }, Local { root: PathBuf }, Plugin { id: String } }

struct ArtifactRef { agent: Agent, scope: Scope, kind: ArtifactKind, path: PathBuf }
enum ArtifactKind { Settings, AppState, McpConfig, Hooks, Skill, Plugin, Instructions,
                    CredentialMeta, ShellProfile, EnvFile, SessionLog, Policy }

enum Item {
  McpServer   { name: String, launch: Launch, env_keys: Vec<String>, headers_keys: Vec<String>, source: ArtifactRef },
  Hook        { event: String, matcher: Option<String>, handler: HookHandler, source: ArtifactRef },
  Skill       { name: String, dir: PathBuf, scripts: Vec<PathBuf>, allowed_tools: Vec<String>, source: ArtifactRef },
  Plugin      { id: String, version: Option<String>, components: Vec<String>, source: ArtifactRef },
  Instruction { path: PathBuf, lines: u32, always_apply: Option<bool>, source: ArtifactRef },
  Setting     { key_path: String, value: RedactedValue, source: ArtifactRef },   // security-relevant keys only
}

enum Launch {
  Package { runner: Runner /* npx, uvx, bunx, pipx, docker */, spec: String, pinned: Pin },
  Binary  { path: PathBuf, args: Vec<String> },
  Interpreter { interp: String, script: PathBuf, args: Vec<String> },
  Remote  { url: Url, auth: RemoteAuth /* none, oauth, static_header */ },
}

struct Finding  { id: Uuid, rule: RuleId, severity: Severity, title: String, location: Location,
                  evidence: MaskedEvidence, fingerprint: String, fix: FixSteps, agent: Option<Agent> }
struct Location { path: PathBuf, line: Option<u32>, key_path: Option<String> }

struct Change   { id: Uuid, at: OffsetDateTime, artifact: ArtifactRef, key_path: String,
                  before: Option<RedactedValue>, after: Option<RedactedValue>, severity: Severity,
                  rule: Option<RuleId>, writer: ProbableWriter, alert: bool }
struct ProbableWriter { process: Option<String>, pid: Option<u32>, parent_chain: Vec<String>,
                        agent_running: Vec<Agent>, label: WriterLabel, confidence: Confidence }

struct Session  { agent: Agent, id: String, project: Option<PathBuf>, state: SessionState,
                  started: OffsetDateTime, last_activity: OffsetDateTime, tokens: TokenBreakdown }
struct TokenBreakdown { input: u64, cache_write: u64, cache_read: u64, output: u64, thinking: u64,
                        reported: ReportedTypes /* which of the five the source actually reports */ }
struct PlanLimit { agent: Agent, window: LimitWindow /* five_hour, weekly */, used_pct: f32,
                   resets_at: OffsetDateTime, observed_at: OffsetDateTime, source: LimitSource }
```

`RedactedValue` holds a value only when it's safe to show: a command, URL host, or boolean or enum setting. Anything a secret rule matches becomes masked evidence plus a fingerprint.

## Adapters

```rust
trait Adapter {
    fn agent(&self) -> Agent;
    fn discover(&self, env: &HomeEnv) -> Vec<ArtifactRef>;               // documented paths + env overrides
    fn parse(&self, a: &ArtifactRef, bytes: &[u8]) -> Result<Vec<Item>, ParseWarning>;
    fn security_keys(&self, kind: ArtifactKind) -> &'static [KeyPattern]; // what to diff and alert on
    fn hot_keys(&self, kind: ArtifactKind) -> &'static [KeyPattern];      // churny keys to ignore
    fn sessions(&self, env: &HomeEnv) -> Vec<Session>;                    // may be empty
    fn usage_since(&self, env: &HomeEnv, cursor: &mut UsageCursor) -> Vec<UsageRecord>;
}
```

- `HomeEnv` resolves `$HOME` (or the `--home` override) and relocation variables read from the user's shell profiles: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`.
- Adapters are data-heavy (paths, key patterns). Keep that data in tables, not code branches, so a format change is a small diff.
- Shared adapters cover `~/.agents/skills`, shell profiles (`.zshrc`, `.zprofile`, `.zshenv`, `.bashrc`, `.bash_profile`, `.profile`, `.envrc`) and `.env` files.

## Parsing

| Format | Approach |
|---|---|
| JSON | `serde_json::Value`, keeping key paths |
| JSONC (Cursor/VS Code) | `jsonc-parser`, then `Value` |
| TOML (Codex) | `toml_edit` for line numbers in findings |
| Markdown frontmatter (skills, `.mdc` rules) | Split the leading `---` block; parse with a maintained YAML crate (evaluate `saphyr` or `serde_yaml_ng`); body is never stored |
| dotenv / shell profiles | Line parser for `export KEY=value` and `KEY=value`; no shell evaluation; record the line number; ignore functions and conditionals but note "dynamic" values |

Hash every file (SHA-256) before parsing; skip the parse if unchanged.

## Change detection

1. Watch only enumerated directories (never all of `$HOME`) with `notify` (FSEvents on macOS) and a 1–2 s debounce (`notify-debouncer-full`).
2. On an event: hash; if changed, parse; compute a **key-level diff limited to `security_keys`**. Whole-file hashing is only for low-churn files (hook files, managed policy, skill folders, shell profiles).
3. Ignore `hot_keys`. For example, `~/.claude.json` is rewritten constantly; only `mcpServers`, `projects.*.mcpServers` and `projects.*.hasTrustDialogAccepted` matter.
4. Emit a `Change` per key path. Mark `alert = true` only for the alert triggers in `RULES.md` § Alert triggers.
5. "Accept" moves the new value into the baseline (an app action, `vigildex baseline accept <id>`). It never edits the source file.

## Attribution ("probably changed by")

At event time:

- take a process snapshot (`sysinfo`): executable path, parent chain, start time;
- check agent session windows: Claude `~/.claude/sessions/` lock files, recent session-log mtimes, running `claude` / `codex` / `copilot` / `cursor-agent` processes;
- check a list of known config managers (cc-switch, ToolHive, MCPM) and package managers (`npm`, `pnpm`, `uv`, `pip`, `brew`);
- for project files, check git events (`.git/HEAD`, `ORIG_HEAD` mtimes) to label "came with git pull".

Labels: `ExpectedAgentWrite`, `AgentWasRunning`, `NoOwningAppRunning`, `PackageInstall { cmd, cwd }`, `GitPull`, `User`, `Unknown`. Confidence is High, Medium or Low. **Never claim certainty**: the UI always says "probably".

## Store

- SQLite (WAL mode) at `~/Library/Application Support/Vigildex/vigildex.db` on macOS (`dirs` crate). The CLI and app share it; migrations live in core.
- Tables: `artifacts` (path, hash, last_parsed), `items` (current snapshot), `baseline` (accepted values per key path), `changes` (append-only), `findings` (with fingerprint, `acknowledged_at`), `sessions_cache`, `usage_daily` (agent × model × day × token type), `usage_cursors` (file → byte offset), `checklist` (manual billing checks, `last_confirmed`), `settings`.
- Retention: changes and usage 400 days by default; findings until resolved.
- Phase 3 adds tamper evidence (HMAC over records with a Keychain-held key). Not in Phase 1.

## Sessions and usage

- Tail logs incrementally using saved byte offsets. Handle rotation and truncation by re-scanning the file and de-duplicating by message ID.
- Claude Code: de-duplicate streamed entries by `message.id` before summing.
- Codex: totals are cumulative per session, so take deltas between consecutive `token_count` events, and get the model from `turn_context`.
- Store `TokenBreakdown` with the `reported` flags so the app can show "—" for types a source doesn't report, rather than a false zero.
- **Pricing**: vendored LiteLLM snapshot (`scripts/update-prices.sh` refreshes it in a PR). Price cache writes by TTL where the log says so (5 m vs 1 h). Thinking is priced as output. All money is labelled "≈ at API list price"; subscriptions are not billed per token.

## Plan limits

- **Codex:** read the `rate_limits` snapshot from the newest rollout `token_count` event (`primary` / `secondary` → used percent, window minutes, `resets_at`; `credits`; `plan_type`). No credentials touched. (`codex app-server` `account/rateLimits/read` is a documented alternative to evaluate later.)
- **Claude:** only through the Phase 1b status-line helper (below). Never `api/oauth/usage`, cookies, or PTY-scraping `/usage`.

## Status-line helper (Phase 1b)

`vigildex-statusline --wrap <original command…>`:

1. Read stdin (the Claude Code status-line JSON) fully.
2. Extract only `rate_limits.five_hour` / `seven_day` (`used_percentage`, `resets_at`). Write them atomically to `~/Library/Application Support/Vigildex/claude-limits.json` with `observed_at`. Nothing else is stored.
3. Run the wrapped command with the **same stdin bytes** and copy its stdout unchanged. If there's no wrapped command, print nothing (or a minimal default).
4. Never fail the status line. On any error, still run the wrapped command. Target under 30 ms overhead; no network.

Install and uninstall are **plans**, not writes: core returns `StatuslinePlan { file, before, after, backup_path }`. The app shows the diff, the user confirms, and the app writes with a backup and verifies. Uninstall restores the original `statusLine` exactly. This is the only write Vigildex makes in Phase 1.

## CLI

```
vigildex scan        [--home DIR] [--json]          # inventory + findings + sessions summary
vigildex inventory   [--agent A] [--type T] [--json]
vigildex findings    [--severity S] [--fail-on S] [--json]
vigildex changes     [--since 7d] [--json]
vigildex watch                                       # foreground watcher printing change events
vigildex sessions    [--json]
vigildex usage       [--day|--week|--month] [--by agent|model|type] [--json]
vigildex preflight   <DIR> [--json]
vigildex baseline    accept <CHANGE_ID> | reset
vigildex schema      <command>                       # prints the JSON schema
```

Exit codes: `0` ok; `1` findings at or above `--fail-on`; `2` usage or IO error. `--json` output includes `schema_version`.

## FFI surface (what the Mac app needs)

```
Engine::new(config: EngineConfig) -> Engine              // data dir, home override, watched project roots
engine.scan() -> ScanSummary                              // counts per section, last_scan_at
engine.inventory(filter) -> Vec<ItemView>
engine.findings(filter) -> Vec<FindingView>
engine.acknowledge_finding(id)
engine.changes(since) -> Vec<ChangeView>
engine.accept_change(id)
engine.sessions() -> Vec<SessionView>
engine.usage(range, group_by) -> UsageReport              // per day, per agent, per token type, est. cost
engine.plan_limits() -> Vec<PlanLimitView>
engine.preflight(dir) -> PreflightReport
engine.checklist() / set_checklist(id, confirmed)
engine.statusline_plan_install() / statusline_plan_uninstall() -> StatuslinePlan
engine.start_watching(listener: Box<dyn EngineListener>) / stop_watching()
trait EngineListener { on_change(ChangeView), on_alert(AlertView), on_scan_complete(ScanSummary) }
```

- `*View` structs are flat, FFI-friendly records, already masked and formatted where it helps (relative times are computed in Swift).
- Calls are synchronous; the Swift side runs them on a background actor.
- Build: `scripts/build-xcframework.sh` builds a static lib for `aarch64-apple-darwin` and `x86_64-apple-darwin`, combines them with `lipo`, generates Swift bindings, and packages `VigildexEngine.xcframework`. Releases attach a zip plus its SwiftPM checksum.

## Performance budgets

- Cold scan of a typical home (four agents, ~10 repos): under 1 s.
- Watcher idle: about 0% CPU. Per change event: under 50 ms to diff.
- Usage tail: incremental. Never re-read a whole transcript directory on each tick.

## Testing

- **Fixtures:** `fixtures/homes/<name>/` are fake home folders (e.g. `basic`, `mockup-demo`, `messy`) with agent files. They must contain no real secrets; use clearly fake values (`ghp_FAKEFAKEFAKE…`).
- **Snapshots:** `insta` snapshots of `--json` output for each fixture home.
- **Parsers:** unit tests for malformed and unknown-field cases.
- **Integration:** the CLI runs against fixture homes and checks exit codes.
- **Mockup fixture:** `fixtures/homes/mockup-demo` should reproduce the sample data in the app mockups (lint-helper MCP server, `ANTHROPIC_API_KEY` in `.zshrc`, and so on). That gives the app realistic previews.

## Release

- `cargo-dist`: GitHub Releases (macOS arm64/x86_64, Linux x86_64/arm64), a Homebrew tap formula, and GitHub artifact attestations.
- Publish crates to crates.io under the `vigildex-*` names. Reserve them with a real 0.1, not empty placeholders.
- The XCFramework zip and its checksum are attached to the same release tag.
