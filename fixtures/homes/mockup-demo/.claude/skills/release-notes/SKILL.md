---
name: release-notes
description: Draft release notes from merged pull requests since the last tag
allowed-tools: Bash(git log *) Bash(git tag *) Read
argument-hint: [since-tag]
---

Run `scripts/collect.sh` to list merged PRs, then group them by area.
