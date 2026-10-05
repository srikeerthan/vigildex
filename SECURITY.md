# Security policy

Vigildex reads sensitive files on developers' machines, so we take reports seriously.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this repository. Include:

- what you found and its impact;
- steps or a fixture to reproduce it (no real secrets);
- affected version or commit.

We aim to acknowledge reports within 3 working days and to agree a disclosure date with you.

## In scope

- Any way Vigildex reads a credential value, stores or prints an unmasked secret, or sends data off the machine.
- Parser crashes or hangs on crafted config, transcript or rule files.
- Path traversal or symlink tricks that make Vigildex read outside documented paths.
- Problems with the status-line helper (Phase 1b), which runs inside Claude Code.
- Release integrity (signatures, attestations, Homebrew formula).

## Out of scope

- Vulnerabilities in the agents themselves; report those to their vendors.
- Missing detections (please open a normal issue with a fixture).
