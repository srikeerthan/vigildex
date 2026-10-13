//! Classifying how an MCP server or hook command is launched, and masking the
//! obvious credentials that commands sometimes carry inline.
//!
//! The classification is a table of package runners and interpreters, so a
//! new runner is a one-line change. It is deliberately best-effort: when a
//! command is not recognised it is reported as a plain binary with its
//! arguments, never dropped.

use std::path::Path;

use crate::model::{Launch, Pin, Runner};

/// A package runner and how to read its arguments.
struct RunnerRule {
    /// The command's base name.
    command: &'static str,
    /// Leading arguments that select the runner mode (`["dlx"]` for
    /// `pnpm dlx`). Empty when the command alone is enough.
    subcommand: &'static [&'static str],
    /// The runner.
    runner: Runner,
    /// Flags that take a value in the next argument, so the value is not
    /// mistaken for the package.
    value_flags: &'static [&'static str],
    /// A flag whose value *is* the package (`npx --package`, `uvx --from`,
    /// `pipx --spec`).
    spec_flag: &'static [&'static str],
}

const RUNNERS: &[RunnerRule] = &[
    RunnerRule {
        command: "npx",
        subcommand: &[],
        runner: Runner::Npx,
        value_flags: &["-c", "--call", "--node-options", "--loglevel", "--registry"],
        spec_flag: &["-p", "--package"],
    },
    RunnerRule {
        command: "pnpx",
        subcommand: &[],
        runner: Runner::Pnpx,
        value_flags: &[],
        spec_flag: &["-p", "--package"],
    },
    RunnerRule {
        command: "pnpm",
        subcommand: &["dlx"],
        runner: Runner::Pnpx,
        value_flags: &[],
        spec_flag: &["-p", "--package"],
    },
    RunnerRule {
        command: "bunx",
        subcommand: &[],
        runner: Runner::Bunx,
        value_flags: &[],
        spec_flag: &["-p", "--package"],
    },
    RunnerRule {
        command: "bun",
        subcommand: &["x"],
        runner: Runner::Bunx,
        value_flags: &[],
        spec_flag: &["-p", "--package"],
    },
    RunnerRule {
        command: "uvx",
        subcommand: &[],
        runner: Runner::Uvx,
        value_flags: &[
            "-w",
            "--with",
            "--with-editable",
            "--with-requirements",
            "-p",
            "--python",
            "--index",
            "--index-url",
            "--extra-index-url",
            "-c",
            "--constraint",
            "--directory",
            "--project",
            "--cache-dir",
            "--refresh-package",
            "--reinstall-package",
            "--env-file",
        ],
        spec_flag: &["--from"],
    },
    RunnerRule {
        command: "uv",
        subcommand: &["tool", "run"],
        runner: Runner::Uvx,
        value_flags: &[
            "-w",
            "--with",
            "--with-editable",
            "--with-requirements",
            "-p",
            "--python",
            "--index",
            "--index-url",
            "--extra-index-url",
            "-c",
            "--constraint",
            "--directory",
            "--project",
            "--cache-dir",
            "--refresh-package",
            "--reinstall-package",
            "--env-file",
        ],
        spec_flag: &["--from"],
    },
    RunnerRule {
        command: "pipx",
        subcommand: &["run"],
        runner: Runner::Pipx,
        value_flags: &["--python", "--pip-args", "--index-url", "-i"],
        spec_flag: &["--spec"],
    },
    RunnerRule {
        command: "docker",
        subcommand: &["run"],
        runner: Runner::Docker,
        value_flags: &[
            "-e",
            "--env",
            "--env-file",
            "-v",
            "--volume",
            "--mount",
            "--tmpfs",
            "--name",
            "--network",
            "--net",
            "-p",
            "--publish",
            "-w",
            "--workdir",
            "-u",
            "--user",
            "--entrypoint",
            "--platform",
            "--pull",
            "-l",
            "--label",
            "--label-file",
            "--add-host",
            "--cap-add",
            "--cap-drop",
            "--security-opt",
            "--device",
            "--ulimit",
            "--log-driver",
            "--log-opt",
            "--restart",
            "-m",
            "--memory",
            "--memory-swap",
            "--cpus",
            "--cpu-shares",
            "--shm-size",
            "--stop-timeout",
            "--stop-signal",
            "--health-cmd",
            "--health-interval",
            "--health-retries",
            "--health-timeout",
            "--hostname",
            "-h",
            "--ip",
            "--dns",
            "--pid",
            "--ipc",
            "--uts",
            "--userns",
            "--cgroup-parent",
            "--cidfile",
            "--group-add",
            "--storage-opt",
            "--sysctl",
            "--runtime",
            "--gpus",
            "--annotation",
            "--attach",
            "-a",
        ],
        spec_flag: &[],
    },
];

/// Interpreters whose first non-flag argument is the script they run.
const INTERPRETERS: &[&str] = &[
    "node",
    "nodejs",
    "python",
    "python3",
    "python2",
    "bash",
    "sh",
    "zsh",
    "fish",
    "dash",
    "ruby",
    "perl",
    "php",
    "deno",
    "bun",
    "ts-node",
    "tsx",
    "lua",
    "osascript",
];

/// Classifies a command line into a [`Launch`].
///
/// `command` is the executable as written; `args` its arguments. Arguments
/// are masked with [`mask_args`] before they are recorded.
#[must_use]
pub fn classify(command: &str, args: &[String]) -> Launch {
    let base = base_name(command);
    let args: Vec<String> = mask_args(args);

    for rule in RUNNERS {
        if rule.command != base {
            continue;
        }
        let Some(rest) = strip_subcommand(&args, rule.subcommand) else {
            continue;
        };
        let spec = find_spec(rest, rule);
        let pin = spec
            .as_deref()
            .map_or(Pin::Floating, |s| pin_of(rule.runner, s));
        return Launch::Package {
            runner: rule.runner,
            spec: spec.unwrap_or_default(),
            pin,
            args,
        };
    }

    if INTERPRETERS.contains(&base) {
        let script = script_of(&args);
        return Launch::Interpreter {
            interpreter: command.to_owned(),
            script,
            args,
        };
    }

    Launch::Binary {
        command: command.to_owned(),
        args,
    }
}

/// The last path component of a command, so `/usr/local/bin/npx` is `npx`.
fn base_name(command: &str) -> &str {
    Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command)
}

/// Removes the leading subcommand words (`dlx`, `tool run`, `run`) when they
/// are present; `None` when they are not.
fn strip_subcommand<'a>(args: &'a [String], sub: &[&str]) -> Option<&'a [String]> {
    if args.len() < sub.len() {
        return None;
    }
    if args.iter().zip(sub).all(|(a, s)| a == s) {
        Some(&args[sub.len()..])
    } else {
        None
    }
}

/// Finds the package or image specification among a runner's arguments.
fn find_spec(args: &[String], rule: &RunnerRule) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        // `--flag=value`: a spec flag gives the spec; others are skipped.
        if let Some((flag, value)) = arg.split_once('=') {
            if arg.starts_with('-') {
                if rule.spec_flag.contains(&flag) {
                    return Some(value.to_owned());
                }
                continue;
            }
        }
        if rule.spec_flag.contains(&arg.as_str()) {
            return iter.next().cloned();
        }
        if rule.value_flags.contains(&arg.as_str()) {
            iter.next();
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        return Some(arg.clone());
    }
    None
}

/// Whether a specification pins an exact version for the given runner.
fn pin_of(runner: Runner, spec: &str) -> Pin {
    match runner {
        Runner::Npx | Runner::Pnpx | Runner::Bunx => npm_pin(spec),
        Runner::Uvx | Runner::Pipx => python_pin(spec),
        Runner::Docker => {
            if spec.contains("@sha256:") {
                Pin::Exact
            } else {
                Pin::Floating
            }
        }
        #[allow(
            unreachable_patterns,
            reason = "Runner is non-exhaustive for future runners"
        )]
        _ => Pin::Floating,
    }
}

/// `pkg@1.2.3` and `@scope/pkg@1.2.3` are exact; a dist-tag, a range or no
/// version at all floats.
fn npm_pin(spec: &str) -> Pin {
    // Skip the scope's leading `@` before looking for the version separator.
    let body = spec.strip_prefix('@').unwrap_or(spec);
    match body.rsplit_once('@') {
        Some((_, version)) if is_exact_semver(version) => Pin::Exact,
        _ => Pin::Floating,
    }
}

/// `pkg==1.2.3` (or `pkg@1.2.3`, which uv accepts) is exact; anything else
/// floats, including `>=` and `~=` ranges.
fn python_pin(spec: &str) -> Pin {
    if let Some((_, version)) = spec.split_once("==") {
        if is_exact_semver(version.trim()) {
            return Pin::Exact;
        }
    }
    if let Some((_, version)) = spec.rsplit_once('@') {
        if is_exact_semver(version.trim()) {
            return Pin::Exact;
        }
    }
    Pin::Floating
}

/// `MAJOR.MINOR.PATCH` with an optional pre-release or build suffix, and no
/// range operator or wildcard.
fn is_exact_semver(version: &str) -> bool {
    let core = version
        .split(['-', '+'])
        .next()
        .unwrap_or_default()
        .strip_prefix('v')
        .unwrap_or(version);
    let core = core.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The script an interpreter runs: the argument after `-c` for shells, else
/// the first argument that is not a flag.
fn script_of(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-c" || arg == "-e" || arg == "--eval" {
            return iter.next().cloned();
        }
        if arg.starts_with('-') {
            continue;
        }
        return Some(arg.clone());
    }
    None
}

/// Words that mark a variable, flag or query parameter as a credential.
const CREDENTIAL_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "api-key",
    "auth",
    "credential",
    "private_key",
    "private-key",
];

fn names_a_credential(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    CREDENTIAL_WORDS.iter().any(|w| lower.contains(w))
}

/// Masks a secret the way the UI shows it: a short prefix, `••••`, and the
/// last three characters (`sk-ant-••••7Qa`). Short values are masked whole.
#[must_use]
pub fn mask_secret(value: &str) -> String {
    const DOTS: &str = "••••";
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 12 {
        return DOTS.to_owned();
    }
    // The prefix is the vendor marker up to the last `-` or `_` within the
    // first eight characters (`sk-ant-`, `ghp_`), else the first two.
    let prefix_len = chars
        .iter()
        .take(8)
        .rposition(|c| *c == '-' || *c == '_')
        .map_or(2, |i| i + 1);
    let prefix: String = chars[..prefix_len].iter().collect();
    let suffix: String = chars[chars.len() - 3..].iter().collect();
    format!("{prefix}{DOTS}{suffix}")
}

/// Masks the obvious credentials in a list of arguments: passwords in URLs,
/// `--token=…`-style flags (and the value after a bare `--token`), and
/// inline `NAME=value` assignments whose name says it is a credential.
#[must_use]
pub fn mask_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut mask_next = false;
    for arg in args {
        if mask_next {
            out.push(mask_secret(arg));
            mask_next = false;
            continue;
        }
        if arg.starts_with('-') && !arg.contains('=') && names_a_credential(arg) {
            mask_next = true;
            out.push(arg.clone());
            continue;
        }
        out.push(mask_text(arg));
    }
    out
}

/// Masks the obvious credentials inside one string: URL passwords and
/// `NAME=value` words whose name says it is a credential.
#[must_use]
pub fn mask_text(text: &str) -> String {
    if !text.contains("://") && !text.contains('=') {
        return text.to_owned();
    }
    let mut changed = false;
    let words: Vec<String> = text
        .split(' ')
        .map(|word| {
            let masked = mask_word(word);
            if masked != word {
                changed = true;
            }
            masked
        })
        .collect();
    if changed {
        words.join(" ")
    } else {
        text.to_owned()
    }
}

fn mask_word(word: &str) -> String {
    if let Some(masked) = mask_url_password(word) {
        return masked;
    }
    if let Some((name, value)) = word.split_once('=') {
        let name = name.trim_start_matches('-');
        let is_identifier = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if is_identifier && names_a_credential(name) && !value.is_empty() && !is_reference(value) {
            return format!(
                "{}={}",
                &word[..word.len() - value.len() - 1],
                mask_secret(value)
            );
        }
    }
    word.to_owned()
}

/// `${VAR}`, `${VAR:-default}`, `$VAR`, `${env:NAME}`, `${input:id}`,
/// `op://…`: references the agent resolves at use time, never a secret.
fn is_reference(value: &str) -> bool {
    value.starts_with('$') || value.starts_with("op://")
}

/// Replaces the password in `scheme://user:password@host…` with dots.
fn mask_url_password(word: &str) -> Option<String> {
    let (scheme, rest) = word.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, _) = authority.rsplit_once('@')?;
    let (user, password) = userinfo.split_once(':')?;
    if password.is_empty() || is_reference(password) {
        return None;
    }
    Some(format!("{scheme}://{user}:••••{}", &rest[userinfo.len()..]))
}

/// Reduces a URL to `scheme://host[:port]/path`: user information, the query
/// string and the fragment are removed, because any of them can carry a
/// credential. A string that is not a URL is returned unchanged.
#[must_use]
pub fn sanitize_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let scheme_ok = !scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.');
    if !scheme_ok {
        return url.to_owned();
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let after = &rest[authority_end..];
    let path_end = after.find(['?', '#']).unwrap_or(after.len());
    format!("{scheme}://{host}{}", &after[..path_end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn npx_latest_is_a_floating_package() {
        let launch = classify("npx", &args(&["-y", "@playwright/mcp@latest"]));
        assert_eq!(
            launch,
            Launch::Package {
                runner: Runner::Npx,
                spec: "@playwright/mcp@latest".into(),
                pin: Pin::Floating,
                args: args(&["-y", "@playwright/mcp@latest"]),
            }
        );
    }

    #[test]
    fn npx_with_a_full_version_is_pinned() {
        match classify(
            "/usr/local/bin/npx",
            &args(&["-y", "@acme/lint-helper@1.4.2"]),
        ) {
            Launch::Package { pin, spec, .. } => {
                assert_eq!(pin, Pin::Exact);
                assert_eq!(spec, "@acme/lint-helper@1.4.2");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn npx_package_flag_names_the_spec() {
        match classify("npx", &args(&["--package", "foo@2.0.0", "foo-cli"])) {
            Launch::Package { spec, pin, .. } => {
                assert_eq!(spec, "foo@2.0.0");
                assert_eq!(pin, Pin::Exact);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn uvx_without_a_version_floats_and_pins_with_double_equals() {
        match classify("uvx", &args(&["mcp-server-fetch"])) {
            Launch::Package {
                runner, spec, pin, ..
            } => {
                assert_eq!(runner, Runner::Uvx);
                assert_eq!(spec, "mcp-server-fetch");
                assert_eq!(pin, Pin::Floating);
            }
            other => panic!("{other:?}"),
        }
        match classify(
            "uvx",
            &args(&["--from", "mcp-server-fetch==2026.1.0", "fetch"]),
        ) {
            Launch::Package { spec, pin, .. } => {
                assert_eq!(spec, "mcp-server-fetch==2026.1.0");
                assert_eq!(pin, Pin::Exact);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn docker_image_needs_a_digest_to_count_as_pinned() {
        let floating = classify(
            "docker",
            &args(&["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/acme/mcp:1.2"]),
        );
        match floating {
            Launch::Package {
                runner, spec, pin, ..
            } => {
                assert_eq!(runner, Runner::Docker);
                assert_eq!(spec, "ghcr.io/acme/mcp:1.2");
                assert_eq!(pin, Pin::Floating);
            }
            other => panic!("{other:?}"),
        }
        match classify(
            "docker",
            &args(&["run", "--rm", "ghcr.io/acme/mcp@sha256:0123abcd"]),
        ) {
            Launch::Package { pin, .. } => assert_eq!(pin, Pin::Exact),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn docker_without_run_is_a_binary() {
        assert!(matches!(
            classify("docker", &args(&["compose", "up"])),
            Launch::Binary { .. }
        ));
    }

    #[test]
    fn interpreters_report_their_script() {
        match classify(
            "python3",
            &args(&["-u", "/opt/mcp/server.py", "--port", "1"]),
        ) {
            Launch::Interpreter { script, .. } => {
                assert_eq!(script.as_deref(), Some("/opt/mcp/server.py"));
            }
            other => panic!("{other:?}"),
        }
        match classify("sh", &args(&["-c", "echo hi"])) {
            Launch::Interpreter { script, .. } => assert_eq!(script.as_deref(), Some("echo hi")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unknown_commands_are_binaries_with_their_args() {
        assert_eq!(
            classify("/Users/you/.cache/.x/mcp-bridge", &args(&["--stdio"])),
            Launch::Binary {
                command: "/Users/you/.cache/.x/mcp-bridge".into(),
                args: args(&["--stdio"]),
            }
        );
    }

    #[test]
    fn masks_keep_a_prefix_and_the_last_three_characters() {
        assert_eq!(
            mask_secret("sk-ant-api03-FAKEFAKEFAKEFAKE7Qa"),
            "sk-ant-••••7Qa"
        );
        assert_eq!(
            mask_secret("ghp_FAKEFAKEFAKEFAKEFAKEFAKE3f9a"),
            "ghp_••••f9a"
        );
        assert_eq!(mask_secret("abcdefghijklmnop"), "ab••••nop");
        assert_eq!(mask_secret("short"), "••••");
    }

    #[test]
    fn url_passwords_are_masked_in_args() {
        let masked = mask_args(&args(&[
            "postgresql://app:hunter2hunter2@db.internal:5432/acme",
        ]));
        assert_eq!(
            masked,
            args(&["postgresql://app:••••@db.internal:5432/acme"])
        );
    }

    #[test]
    fn credential_flags_are_masked_with_and_without_equals() {
        let masked = mask_args(&args(&[
            "--token=ghp_FAKEFAKEFAKEFAKEFAKEFAKE3f9a",
            "--api-key",
            "sk-proj-FAKEFAKEFAKEFAKEFAKE123",
            "--port=8080",
        ]));
        assert_eq!(
            masked,
            args(&[
                "--token=ghp_••••f9a",
                "--api-key",
                "sk-proj-••••123",
                "--port=8080"
            ])
        );
    }

    #[test]
    fn inline_assignments_are_masked_but_references_are_kept() {
        assert_eq!(
            mask_text("GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKE3f9a npx server"),
            "GITHUB_TOKEN=ghp_••••f9a npx server"
        );
        assert_eq!(
            mask_text("GITHUB_TOKEN=${GITHUB_TOKEN} npx server"),
            "GITHUB_TOKEN=${GITHUB_TOKEN} npx server"
        );
        assert_eq!(
            mask_text("PORT=8080 node server.js"),
            "PORT=8080 node server.js"
        );
    }

    #[test]
    fn urls_lose_userinfo_query_and_fragment() {
        assert_eq!(
            sanitize_url("https://user:pw@mcp.example.com:8443/mcp?key=abc#frag"),
            "https://mcp.example.com:8443/mcp"
        );
        assert_eq!(
            sanitize_url("https://mcp.context7.com/mcp?client=claude-code-plugin"),
            "https://mcp.context7.com/mcp"
        );
        assert_eq!(sanitize_url("not a url"), "not a url");
        assert_eq!(
            sanitize_url("${API_BASE_URL:-https://api.example.com}/mcp"),
            "${API_BASE_URL:-https://api.example.com}/mcp"
        );
    }
}
