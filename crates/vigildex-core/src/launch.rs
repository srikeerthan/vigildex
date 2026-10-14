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

/// Whether a command's base name is a known interpreter whose first
/// non-flag argument is the script it runs.
#[must_use]
pub fn is_interpreter(base_name: &str) -> bool {
    INTERPRETERS.contains(&base_name)
}

/// Classifies a command line into a [`Launch`].
///
/// `command` is the executable as written; `args` its arguments. Arguments
/// are masked with [`mask_args`] before they are recorded.
#[must_use]
pub fn classify(command: &str, args: &[String]) -> Launch {
    let base = base_name(command);
    let args: Vec<String> = mask_args(args);
    // A command written as one string can carry a credential too.
    let command = &mask_text(command);

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

/// The package runner a command line starts with (`npx prettier …`,
/// `uv tool run …`), if any. Used for the inventory tag on hooks.
#[must_use]
pub fn runner_of_command(command_line: &str) -> Option<Runner> {
    let words: Vec<String> = command_line
        .split_whitespace()
        .map(|w| w.trim_matches(['"', '\'']).to_owned())
        .collect();
    let (first, rest) = words.split_first()?;
    let base = base_name(first);
    RUNNERS
        .iter()
        .find(|rule| rule.command == base && strip_subcommand(rest, rule.subcommand).is_some())
        .map(|rule| rule.runner)
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

/// Whether a variable, flag or header name says it holds a credential.
#[must_use]
pub fn names_a_credential(name: &str) -> bool {
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

/// Masks a secret whose shape the engine does not know: `••••` and the last
/// three characters (`••••AKE`). Short values are masked whole.
#[must_use]
pub fn mask_secret_short(value: &str) -> String {
    const DOTS: &str = "••••";
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 12 {
        return DOTS.to_owned();
    }
    let suffix: String = chars[chars.len() - 3..].iter().collect();
    format!("{DOTS}{suffix}")
}

/// Masks the obvious credentials in a list of arguments: passwords in URLs,
/// `--token=…`-style flags (and the value after a bare `--token`), and
/// inline `NAME=value` assignments whose name says it is a credential.
#[must_use]
pub fn mask_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut mask_next: Option<&str> = None;
    for arg in args {
        if let Some(flag) = mask_next.take() {
            if !arg.starts_with('-') && !is_reference(arg) {
                out.push(mask_value(flag, arg));
                continue;
            }
        }
        if arg.starts_with('-') && !arg.contains('=') && names_a_credential(arg) {
            mask_next = Some(arg);
            out.push(arg.clone());
            continue;
        }
        out.push(mask_text(arg));
    }
    out
}

/// The mask for a value named by `name` (a flag or variable): nothing for a
/// password, the last three characters for anything else. Vendor tokens are
/// masked by the secret rules before this runs.
fn mask_value(name: &str, value: &str) -> String {
    // Already masked by a secret rule (`ghp_••••f9a`): keep the vendor mask.
    if value.contains("••••") {
        return value.to_owned();
    }
    let lower = name.to_ascii_lowercase();
    if lower.contains("pass") || lower.contains("pwd") {
        "••••".to_owned()
    } else {
        mask_secret_short(value)
    }
}

/// Masks the credentials inside one string: every token a vendor or URL
/// secret rule recognises, URL passwords, and `NAME=value` words whose name
/// says it is a credential.
#[must_use]
pub fn mask_text(text: &str) -> String {
    let text = crate::secrets::mask_in_text(text);
    if !text.contains("://") && !text.contains('=') && !text.contains('-') {
        return text;
    }
    // Words and the whitespace between them, kept as written.
    let mut out = String::with_capacity(text.len());
    let mut pending_flag: Option<String> = None;
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (word, after) = rest.split_at(word_end);
        let space_end = after
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(after.len());
        let (space, tail) = after.split_at(space_end);
        if word.is_empty() {
            out.push_str(space);
            rest = tail;
            continue;
        }
        let bare = word.trim_matches(['"', '\'']);
        let masked = match pending_flag.take() {
            Some(flag) if !bare.starts_with('-') && !is_reference(bare) && !bare.is_empty() => {
                word.replacen(bare, &mask_value(&flag, bare), 1)
            }
            _ => mask_word(word),
        };
        if bare.starts_with('-') && !bare.contains('=') && names_a_credential(bare) {
            pending_flag = Some(bare.to_owned());
        }
        out.push_str(&masked);
        out.push_str(space);
        rest = tail;
    }
    out
}

/// Masks one whitespace-separated word, looking through a surrounding
/// quote (`'TOKEN=…'` inside `sh -c '…'`).
fn mask_word(word: &str) -> String {
    let open = word.chars().next().filter(|c| matches!(c, '"' | '\''));
    let Some(quote) = open else {
        return mask_bare_word(word);
    };
    let inner = &word[1..];
    let (inner, close) = match inner.strip_suffix(quote) {
        Some(stripped) if !stripped.is_empty() => (stripped, true),
        _ => (inner, false),
    };
    let masked = mask_bare_word(inner);
    if close {
        format!("{quote}{masked}{quote}")
    } else {
        format!("{quote}{masked}")
    }
}

fn mask_bare_word(word: &str) -> String {
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
                mask_value(name, value)
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

/// Where a URL starts inside `text`: the scheme before the first `://`,
/// which may follow other text (`${API_BASE_URL:-https://…}`). Returns the
/// byte offsets of the scheme start and of the `://`.
fn url_start(text: &str) -> Option<(usize, usize)> {
    let sep = text.find("://")?;
    let mut scheme_start = text[..sep]
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'))
        .map_or(0, |i| i + c_len(&text[..sep], i));
    // A scheme starts with a letter: skip the `-` of `${X:-https://…}`.
    while scheme_start < sep && !text.as_bytes()[scheme_start].is_ascii_alphabetic() {
        scheme_start += 1;
    }
    if scheme_start == sep {
        return None;
    }
    Some((scheme_start, sep))
}

/// Length of the character at byte `i` of `text`.
fn c_len(text: &str, i: usize) -> usize {
    text[i..].chars().next().map_or(1, char::len_utf8)
}

/// Where a URL that starts at `from` ends: the first whitespace, quote or
/// closing brace/bracket/parenthesis, so a URL inside `${X:-…}` or `"…"`
/// keeps the wrapper.
fn url_end(text: &str, scheme_start: usize, from: usize) -> usize {
    // A URL that is the whole text ends at its end: a password may hold
    // `)` or `'`. One embedded in other text (`${X:-https://…}`, `"…"`)
    // ends at the first whitespace, quote or closing bracket, so the
    // wrapper is kept.
    if scheme_start == 0 && !text.contains(char::is_whitespace) {
        return text.len();
    }
    text[from..]
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '}' | ')' | ']' | '`' | '>'))
        .map_or(text.len(), |i| from + i)
}

/// Replaces the password in `scheme://user:password@host…` with dots. The
/// URL may be embedded in other text.
pub(crate) fn mask_url_password(word: &str) -> Option<String> {
    let (scheme_start, sep) = url_start(word)?;
    let end = url_end(word, scheme_start, sep + 3);
    let rest = &word[sep + 3..end];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, _) = authority.rsplit_once('@')?;
    let (user, password) = userinfo.split_once(':')?;
    if password.is_empty() || is_reference(password) {
        return None;
    }
    Some(format!(
        "{}{}://{user}:••••{}{}",
        &word[..scheme_start],
        &word[scheme_start..sep],
        &rest[userinfo.len()..],
        &word[end..]
    ))
}

/// Removes the query string and fragment of a URL, keeping everything else
/// as written. Not a URL: returned unchanged.
#[must_use]
pub(crate) fn strip_query(url: &str) -> String {
    let Some((scheme_start, sep)) = url_start(url) else {
        return url.to_owned();
    };
    let end = url_end(url, scheme_start, sep + 3);
    let rest = &url[sep + 3..end];
    let cut = rest.find(['?', '#']).map_or(end, |i| sep + 3 + i);
    format!("{}{}", &url[..cut], &url[end..])
}

/// Reduces a URL to `scheme://host[:port]/path`: user information, the query
/// string and the fragment are removed, because any of them can carry a
/// credential. The URL may be embedded in other text
/// (`${API_BASE_URL:-https://…}/mcp`); text that holds no URL is returned
/// unchanged.
#[must_use]
pub fn sanitize_url(url: &str) -> String {
    let Some((scheme_start, sep)) = url_start(url) else {
        return url.to_owned();
    };
    let end = url_end(url, scheme_start, sep + 3);
    let rest = &url[sep + 3..end];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let after = &rest[authority_end..];
    let path_end = after.find(['?', '#']).unwrap_or(after.len());
    format!(
        "{}{}://{host}{}{}",
        &url[..scheme_start],
        &url[scheme_start..sep],
        &after[..path_end],
        &url[end..]
    )
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
    fn runner_of_command_lines() {
        assert_eq!(
            runner_of_command("npx prettier --write x"),
            Some(Runner::Npx)
        );
        assert_eq!(runner_of_command("uv tool run ruff"), Some(Runner::Uvx));
        assert_eq!(
            runner_of_command("docker run --rm img"),
            Some(Runner::Docker)
        );
        assert_eq!(runner_of_command("docker compose up"), None);
        assert_eq!(runner_of_command("./scripts/guard.sh"), None);
        assert_eq!(runner_of_command(""), None);
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
        assert_eq!(mask_secret_short("abcdefghijklmnop"), "••••nop");
        assert_eq!(mask_secret_short("short"), "••••");
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
        // A recognised vendor token keeps its prefix; a value of unknown
        // shape (here a 28-character `ghp_` that is not a GitHub token, and
        // a short `sk-proj-`) keeps only its last three characters.
        let masked = mask_args(&args(&[
            "--token=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a",
            "--api-key",
            "sk-proj-FAKEFAKEFAKEFAKEFAKE123",
            "--token=ghp_FAKEFAKEFAKEFAKEFAKEFAKE3f9a",
            "--port=8080",
        ]));
        assert_eq!(
            masked,
            args(&[
                "--token=ghp_••••f9a",
                "--api-key",
                "••••123",
                "--token=••••f9a",
                "--port=8080"
            ])
        );
        // Unknown shapes keep the last three characters; passwords nothing.
        assert_eq!(
            mask_args(&args(&[
                "--token",
                "LEAK30-LEAK30-x",
                "--password",
                "hunter2-rocks!",
                "--token",
                "${T}"
            ])),
            args(&[
                "--token",
                "••••0-x",
                "--password",
                "••••",
                "--token",
                "${T}"
            ])
        );
    }

    #[test]
    fn inline_assignments_are_masked_but_references_are_kept() {
        assert_eq!(
            mask_text("GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a npx server"),
            "GITHUB_TOKEN=ghp_••••f9a npx server"
        );
        assert_eq!(
            mask_text("GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKE3f9a npx server"),
            "GITHUB_TOKEN=••••f9a npx server",
            "not a GitHub token shape: no prefix is kept"
        );
        assert_eq!(
            mask_text("GITHUB_TOKEN=${GITHUB_TOKEN} npx server"),
            "GITHUB_TOKEN=${GITHUB_TOKEN} npx server"
        );
        assert_eq!(
            mask_text("PORT=8080 node server.js"),
            "PORT=8080 node server.js"
        );
        assert_eq!(
            mask_text("sh -c 'API_TOKEN=acme_FAKEFAKEFAKEFAKE npx x'"),
            "sh -c 'API_TOKEN=••••AKE npx x'"
        );
        assert_eq!(
            mask_text("--token 'abc'"),
            "--token '••••'",
            "a short value named by a credential flag is masked whole"
        );
        // Flags with a separate value, across any whitespace, and in-place
        // formatting that keeps newlines and tabs.
        assert_eq!(
            mask_text("fetch-key --api-key adk_LEAK22LEAK22LEAK22LEAK22 --port 1"),
            "fetch-key --api-key ••••K22 --port 1"
        );
        assert_eq!(
            mask_text("cd /x\nAPI_TOKEN=acme_LEAK28LEAK28LEAK28 ./run"),
            "cd /x\nAPI_TOKEN=••••K28 ./run"
        );
        assert_eq!(
            mask_text("a\tTOKEN=LEAKTOK9LEAKTOK9 b"),
            "a\tTOKEN=••••OK9 b"
        );
        assert_eq!(
            mask_text("notify --password hunter2-LEAK11x"),
            "notify --password ••••"
        );
        // A bare vendor token anywhere in the text is masked too.
        assert_eq!(
            mask_text("echo sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE7Qa"),
            "echo sk-ant-••••7Qa"
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
        // A URL inside a default still loses its user information and query.
        assert_eq!(
            sanitize_url("${API_BASE_URL:-https://u:pw@api.example.com/v1?k=FAKE}/mcp"),
            "${API_BASE_URL:-https://api.example.com/v1}/mcp"
        );
        assert_eq!(
            mask_url_password("${DB:-postgresql://app:FAKEPW@db/acme}").as_deref(),
            Some("${DB:-postgresql://app:••••@db/acme}")
        );
        assert_eq!(
            strip_query("${X:-https://h.example/x?token=FAKE}/y"),
            "${X:-https://h.example/x}/y"
        );
        assert_eq!(
            sanitize_url("https://user:LEAK18)pw@mcp.example/x"),
            "https://mcp.example/x"
        );
        assert_eq!(
            mask_url_password("https://user:LEAK18)pw@mcp.example/x").as_deref(),
            Some("https://user:••••@mcp.example/x")
        );
        assert_eq!(
            strip_query("https://h.example/x?token=FAKE#f"),
            "https://h.example/x"
        );
    }
}
