# Vigildex engine: instructions for Claude Code

Vigildex is a local, read-only guard and usage view for AI coding agents: Claude Code, OpenAI Codex, Cursor and GitHub Copilot (Copilot CLI and VS Code agent mode). This repo is the **open-source engine** (Rust, Apache-2.0). It:

- finds everything each agent can run (MCP servers, hooks, skills, plugins, instruction files, security settings);
- records a baseline and reports setting-level changes, with a "probably changed by" label;
- flags secrets, billing traps and risky settings;
- reads local session and usage logs (tokens by type, estimated cost, plan limits where a sanctioned source exists);
- checks newly cloned or pulled repos for agent config before you run an agent there.

The macOS app lives in the private repo `srikeerthan/vigildex-mac` and embeds this engine through UniFFI.

**Read before writing code:** `docs/HANDOFF.md`, then `docs/ARCHITECTURE.md`, `docs/DATA_SOURCES.md` and `docs/RULES.md`. `docs/PRIVACY.md` is the contract with users.

## Hard rules (never break these)

1. **Read-only.** Never write to any agent's files. The one exception is the opt-in Claude status-line helper (Phase 1b), installed only through the reviewed flow in `docs/ARCHITECTURE.md` § Status-line helper.
2. **Never read credential values.** That covers macOS Keychain items, the contents of `~/.claude/.credentials.json`, values in `~/.codex/auth.json`, Cursor's `state.vscdb`, Copilot's `config.json` token fields, and browser cookies. Existence, file mode and owner are allowed. For JSON credential files, read key *names* only.
3. **No network.** The engine makes no network calls: no telemetry, no update checks and no live verification of found secrets. The price table is vendored at build time.
4. **No undocumented vendor endpoints** and no reuse of the user's tokens or cookies.
5. **Never keep or print a full secret.** Mask at the point of detection (`sk-ant-••••7Qa`: a short prefix plus the last 3–4 characters). Findings carry a salted fingerprint, never the value.
6. **Transcripts.** Parse only usage and metadata fields from session logs. Never persist message content, tool output or prompts.
7. **Vendor formats are internal and change without notice.** Every parser must tolerate unknown fields and missing keys, report "unknown" and keep going. A malformed file is a warning, never a panic.

## Commands

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo insta review                  # review snapshot changes
cargo deny check && cargo audit     # licences and advisories
./scripts/build-xcframework.sh      # macOS only; writes target/VigildexEngine.xcframework
cargo run -p vigildex-cli -- scan --home fixtures/homes/basic --json
```

## Conventions

- Stable Rust, edition 2021, with the MSRV pinned in `rust-toolchain.toml`.
- `thiserror` in library crates; `anyhow` only in `vigildex-cli`.
- No `unsafe` outside generated FFI code.
- Every adapter ships redacted fixtures in `fixtures/<agent>/<date-or-version>/` plus `insta` snapshot tests. Never commit real secrets, real paths with user names, or transcript text.
- Public types derive `serde` and `schemars::JsonSchema`. CLI `--json` output is a versioned contract (`schema_version`), and changing it needs a version bump and a note in `CHANGELOG.md`.
- Every finding has a stable rule ID (`SEC-`, `BILL-`, `RISK-`, `CHG-`); see `docs/RULES.md`.
- Dependencies must be MIT, Apache-2.0, BSD or similarly permissive. No GPL or AGPL (`cargo-deny` enforces this).
- Commits: imperative mood, with a DCO sign-off (`git commit -s`). Small PRs, one adapter or rule family at a time.
- Tests use a fake home directory (`--home` flag / `VIGILDEX_HOME` env var). Never read the developer's real `$HOME` in tests.

## Layout (target)

```
crates/
  vigildex-core/        model, adapters, parsers, analyzers, diff, attribution, store, pricing, watch
  vigildex-cli/         `vigildex` binary (clap)
  vigildex-ffi/         UniFFI bindings for the macOS app
  vigildex-statusline/  tiny Claude status-line helper (Phase 1b)
rules/                  secret rules (gitleaks-format TOML), host allowlists, known launchers
fixtures/               redacted sample files per agent and a few fake home folders
scripts/                build-xcframework.sh, update-prices.sh
docs/                   handoff, architecture, data sources, rules, privacy, roadmap, research
```

## When unsure

- If a data source is not in `docs/DATA_SOURCES.md`, or is marked **verify**, confirm it on real files first. Then add a redacted fixture and update the doc in the same PR.
- If a feature seems to need a write, network access or a credential value, stop and ask. It's probably out of scope for Phase 1.
