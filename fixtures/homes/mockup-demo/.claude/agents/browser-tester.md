---
name: browser-tester
description: Tests features in a real browser using Playwright
tools: Read, Grep, Bash(npm test *)
permissionMode: acceptEdits
mcpServers:
  - playwright:
      type: stdio
      command: npx
      args: ["-y", "@playwright/mcp@latest"]
  - github
---

You test web features end to end. Report failures with a screenshot path.
