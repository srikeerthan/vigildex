# Contributing

Thanks for helping. Vigildex is young, so small, focused PRs are best.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/) instead of a CLA. Add a sign-off to every commit:

```sh
git commit -s -m "Add Codex hooks.json parser"
```

## Before you open a PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## Adding or updating an agent adapter

1. Document the source in `docs/DATA_SOURCES.md`: path, format, security-relevant keys, churn, and whether it's sanctioned or internal.
2. Add **redacted** fixtures under `fixtures/<agent>/<date-or-version>/`:
   - Replace user names in paths with `you`.
   - Replace secrets with obviously fake values (`ghp_FAKEFAKEFAKEFAKE…`).
   - Delete transcript message text. Keep only the usage and metadata lines you need.
3. Add parser tests and an `insta` snapshot.
4. Unknown fields must not break parsing.

## Adding a rule

- Give it the next free ID in `docs/RULES.md` and add a row.
- Add one fixture that triggers it and one look-alike that must not.
- Keep titles to six words or fewer. Write fix steps per agent.

## What we won't merge

- Network calls from the engine or CLI.
- Reading credential values, Keychain items or browser cookies.
- Undocumented vendor endpoints.
- GPL- or AGPL-licensed dependencies.

## Licence

By contributing, you agree your contribution is licensed under Apache-2.0.
