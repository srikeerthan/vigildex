---
name: deploy
description: Deploy the current branch to staging with a pre-flight check
allowed-tools: Bash(./scripts/deploy.py *) Bash(./scripts/preflight.sh)
disable-model-invocation: true
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "./scripts/preflight.sh"
          timeout: 20
---

1. Run `scripts/deploy.py --env staging`.
2. Report the deployment URL.
