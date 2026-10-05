# Roadmap

Each phase starts only when the one before shows real use. Engine milestones for Phase 1 are in `docs/HANDOFF.md`.

## Phase 1: read-only (now)

Inventory, change history with a probable-writer label, findings (secrets, billing traps, risk flags), sessions, usage by token type, repo pre-flight and alert events. Agents: Claude Code, Codex, Cursor, GitHub Copilot. macOS first. The CLI ships on its own.

**Phase 1b:** opt-in Claude status-line helper for plan limits (the only write).

## Phase 2: manage, with backups

Turn off or remove MCP servers, hooks, skills and plugins using each agent's own commands where they exist (`claude mcp`, `codex mcp`, `copilot mcp`). Also:

- pin floating versions;
- revert a change to an earlier snapshot;
- guided secret fixes (Keychain, env reference or 1Password; connection test; rotate reminder; clean old backups);
- billing-trap fixes;
- quarantine new skills and plugins.

Every write shows a diff first and keeps a backup.

## Phase 3: protect and broaden

Opt-in enforcement hooks:

- block credential-file reads;
- block flagged MCP servers;
- block new prompts after a spend cap;
- set Cursor hooks to fail closed;
- self-checks that the hooks are still installed.

Also in Phase 3:

- a policy writer for each agent's managed settings (with the user's admin password);
- spend alerts for pay-per-token use;
- MCP tool pinning (sandboxed, on request);
- more agents (OpenCode, Antigravity CLI, Pi, Grok Build, Claude Desktop);
- Windows and Linux inventory, findings and diffs;
- tamper evidence (signed snapshots).

## Phase 4: small teams (only if teams ask)

A team view of findings and inventory across members (counts and metadata only), shared policy kept in the team's git repo, and Slack or email alerts.

## Phase 5: later

- Endpoint Security on macOS for true writer attribution and blocking. Apply for the entitlement early.
- Encrypted sync of baselines and policies.
- Session handoff between machines.
- Imports from other open-source usage trackers.

## Not planned

| Item | Why |
|---|---|
| Clearing an agent's context from outside | Agents don't allow it, and prompt caches live on vendor servers |
| Account billing settings via cookies or private endpoints | Conflicts with vendor terms and breaks often |
| Claude limits via the undocumented usage endpoint | Rate-limited, with the same terms risk |
| MCP or LLM proxy | Breaks tool search and caching, and adds trust cost |
| Cloud or LLM analysis of configs and skills | Breaks the local-only promise |
| Mac App Store build | Its sandbox blocks reading agent config folders |
