//! Secret detection: the vendored rules under `rules/secrets/*.toml`, the
//! scanner that applies them, and the masking and fingerprinting that happen
//! at the point of detection.
//!
//! The rules are gitleaks-shaped TOML (`id`, `description`, `regex`,
//! `keywords`, `secretGroup`, `allowlist.regexes`) with three Vigildex
//! extensions: `names` and `namesNot` (regexes on the field name, for the
//! name-keyed generic rules) and `maskStyle = "full"` (hide the whole secret,
//! for passwords inside URLs). They are compiled once, on first use. A rule
//! that fails to compile is reported through [`RuleSet::warnings`] and
//! skipped; the other rules still run (hard rule 7).
//!
//! Hard rule 5: a [`SecretHit`] carries the masked form, never the value.
//! Callers drop the raw text as soon as [`scan_value`] or [`scan_text`]
//! returns. No digest of a secret is computed either: a hash under a
//! public constant would let anyone holding a report confirm a guessed
//! password offline. Keyed fingerprints arrive with the store (M4).

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::launch::{mask_secret, mask_secret_short, mask_url_password, strip_query};
use crate::parse::json::{str_at, string_list_at, u64_at};

/// The vendored rule files, embedded at build time. Add a file here when you
/// add one under `rules/secrets/`.
///
/// The paths reach outside the crate directory, which `cargo build` accepts
/// in the workspace; `cargo package` (M7) will need the files copied into the
/// crate or a `build.rs`.
const RULE_FILES: &[(&str, &str)] = &[
    (
        "rules/secrets/vendors.toml",
        include_str!("../rules/secrets/vendors.toml"),
    ),
    (
        "rules/secrets/urls.toml",
        include_str!("../rules/secrets/urls.toml"),
    ),
    (
        "rules/secrets/generic.toml",
        include_str!("../rules/secrets/generic.toml"),
    ),
];

/// A compiled secret rule.
#[derive(Debug)]
pub struct Rule {
    /// The rule's identifier (`github-token`).
    pub id: String,
    /// The secret kind, as shown in finding titles (`GitHub token`).
    pub kind: String,
    regex: Regex,
    keywords: Vec<String>,
    secret_group: usize,
    allowlist: Vec<Regex>,
    names: Option<Regex>,
    names_not: Option<Regex>,
    mask: MaskStyle,
}

/// How much of a secret the evidence shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaskStyle {
    /// The vendor prefix and the last three characters (`sk-ant-••••7Qa`).
    Prefix,
    /// Two characters and the last three (`lh••••AKE`), for tokens whose
    /// shape the engine does not know.
    Short,
    /// Nothing but dots, for passwords.
    Full,
}

/// Every rule that compiled, in file order.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    /// Rules or files that could not be loaded, one message each.
    pub warnings: Vec<String>,
}

impl RuleSet {
    /// The rules, in the order they are tried.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Parses one rule file. Errors become warnings; nothing panics.
    fn load_file(&mut self, name: &str, text: &str) {
        let doc = match crate::parse::toml::to_json(text) {
            Ok(doc) => doc,
            Err(err) => {
                self.warnings.push(format!("{name}: not valid TOML: {err}"));
                return;
            }
        };
        let Some(rules) = doc.get("rules").and_then(Value::as_array) else {
            self.warnings.push(format!("{name}: no [[rules]] array"));
            return;
        };
        for (index, entry) in rules.iter().enumerate() {
            match Rule::from_json(entry) {
                Ok(rule) => self.rules.push(rule),
                Err(err) => self.warnings.push(format!("{name}: rule #{index}: {err}")),
            }
        }
    }
}

impl Rule {
    fn from_json(entry: &Value) -> Result<Self, String> {
        let id = str_at(entry, "id").ok_or("missing id")?.to_owned();
        let kind = str_at(entry, "description")
            .ok_or_else(|| format!("{id}: missing description"))?
            .to_owned();
        let regex = compile(str_at(entry, "regex").ok_or_else(|| format!("{id}: missing regex"))?)
            .map_err(|err| format!("{id}: regex: {err}"))?;
        let secret_group = u64_at(entry, "secretGroup").unwrap_or(0) as usize;
        if secret_group > regex.captures_len().saturating_sub(1) {
            return Err(format!(
                "{id}: secretGroup {secret_group} is beyond the regex's capture groups"
            ));
        }
        let allowlist = entry
            .get("allowlist")
            .map(|a| string_list_at(a, "regexes"))
            .unwrap_or_default()
            .iter()
            .map(|pattern| compile(pattern).map_err(|err| format!("{id}: allowlist: {err}")))
            .collect::<Result<Vec<_>, _>>()?;
        let names = str_at(entry, "names")
            .map(|p| compile(p).map_err(|err| format!("{id}: names: {err}")))
            .transpose()?;
        let names_not = str_at(entry, "namesNot")
            .map(|p| compile(p).map_err(|err| format!("{id}: namesNot: {err}")))
            .transpose()?;
        let mask = match str_at(entry, "maskStyle") {
            Some("full") => MaskStyle::Full,
            Some("short") => MaskStyle::Short,
            Some("prefix") | None => MaskStyle::Prefix,
            Some(other) => return Err(format!("{id}: unknown maskStyle {other:?}")),
        };
        Ok(Self {
            id,
            kind,
            regex,
            keywords: string_list_at(entry, "keywords"),
            secret_group,
            allowlist,
            names,
            names_not,
            mask,
        })
    }

    /// Whether the rule is name-keyed (applies only to a named field).
    fn name_keyed(&self) -> bool {
        self.names.is_some()
    }

    /// Whether the rule applies to a field with this name.
    fn accepts_name(&self, name: Option<&str>) -> bool {
        match (&self.names, name) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(names), Some(name)) => {
                names.is_match(name) && !self.names_not.as_ref().is_some_and(|n| n.is_match(name))
            }
        }
    }

    /// Runs the rule on a literal value.
    fn apply(&self, value: &str) -> Option<SecretHit> {
        if !self.keywords.is_empty() && !self.keywords.iter().any(|k| value.contains(k.as_str())) {
            return None;
        }
        let caps = self.regex.captures(value)?;
        let whole = caps.get(0)?;
        let secret = caps.get(self.secret_group)?;
        if secret.as_str().is_empty() || self.allowlist.iter().any(|a| a.is_match(secret.as_str()))
        {
            return None;
        }
        let masked = if whole.as_str().contains("://") && self.mask == MaskStyle::Full {
            // The query string could carry a second credential: drop it.
            mask_url_password(whole.as_str())
                .map_or_else(|| "••••".to_owned(), |url| strip_query(&url))
        } else {
            // The match with the secret span replaced by its mask, so the
            // evidence keeps context such as `token=` or `Bearer `.
            let start = secret.start() - whole.start();
            let end = secret.end() - whole.start();
            let text = whole.as_str();
            let dots = match self.mask {
                MaskStyle::Prefix => mask_secret(secret.as_str()),
                MaskStyle::Short => mask_secret_short(secret.as_str()),
                MaskStyle::Full => "••••".to_owned(),
            };
            format!("{}{dots}{}", &text[..start], &text[end..])
        };
        Some(SecretHit {
            rule: self.id.clone(),
            kind: self.kind.clone(),
            masked,
        })
    }

    /// The masked form of every match of this rule in `text`, spliced in
    /// place of the secret; `None` when the rule does not match.
    fn mask_all(&self, text: &str) -> Option<String> {
        if !self.keywords.is_empty() && !self.keywords.iter().any(|k| text.contains(k.as_str())) {
            return None;
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        let mut changed = false;
        for caps in self.regex.captures_iter(text) {
            let (Some(whole), Some(secret)) = (caps.get(0), caps.get(self.secret_group)) else {
                continue;
            };
            if secret.as_str().is_empty()
                || self.allowlist.iter().any(|a| a.is_match(secret.as_str()))
            {
                continue;
            }
            let dots = match self.mask {
                MaskStyle::Prefix => mask_secret(secret.as_str()),
                MaskStyle::Short => mask_secret_short(secret.as_str()),
                MaskStyle::Full => "••••".to_owned(),
            };
            out.push_str(&text[last..secret.start()]);
            out.push_str(&dots);
            last = secret.end();
            changed = true;
            let _ = whole;
        }
        if !changed {
            return None;
        }
        out.push_str(&text[last..]);
        Some(out)
    }
}

fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
}

/// The compiled rules, loaded on first use.
pub fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut set = RuleSet::default();
        for (name, text) in RULE_FILES {
            set.load_file(name, text);
        }
        set
    })
}

/// A secret a rule recognised. Holds the masked form, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHit {
    /// The rule that matched (`github-token`).
    pub rule: String,
    /// The secret kind for titles (`GitHub token`).
    pub kind: String,
    /// The evidence to show: the match with the secret masked
    /// (`ghp_••••f9a`, `postgresql://app:••••@db…`).
    pub masked: String,
}

/// What kind of text a configuration value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueClass {
    /// Plain text: the only class a secret rule runs on.
    Literal,
    /// A reference the agent resolves at use time (`${VAR}`, `$VAR`,
    /// `${env:NAME}`, `${input:id}`, `op://…`).
    Reference,
    /// Shell command substitution (`$(…)`, backticks): the value exists only
    /// when the shell runs the profile.
    Dynamic,
    /// Nothing.
    Empty,
}

/// Classifies a value.
#[must_use]
pub fn classify(value: &str) -> ValueClass {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        ValueClass::Empty
    } else if trimmed.contains("$(") || trimmed.contains('`') {
        ValueClass::Dynamic
    } else if trimmed.starts_with('$') || trimmed.starts_with("op://") {
        ValueClass::Reference
    } else {
        ValueClass::Literal
    }
}

/// Scans the value of a named field (an environment variable, a header, an
/// argument). The first matching rule wins, and vendor rules come before
/// the name-keyed generic ones.
///
/// A reference (`${VAR}`) or a command substitution (`$(…)`) is never a
/// secret itself, but the default of `${VAR:-default}` and the body of
/// `$(…)` can carry a literal, so those pieces are scanned with the same
/// field name.
#[must_use]
pub fn scan_value(name: Option<&str>, value: &str) -> Option<SecretHit> {
    scan_value_at(name, value, 0)
}

/// How far the scanners look into nested `${…}` and `$(…)` constructs. A
/// credential sits at most a level or two deep; the cap keeps a
/// pathological line from costing a stack frame and a copy per level.
const MAX_NESTING: usize = 8;

fn scan_value_at(name: Option<&str>, value: &str, depth: usize) -> Option<SecretHit> {
    match classify(value) {
        ValueClass::Literal => rules()
            .rules()
            .iter()
            .filter(|rule| rule.accepts_name(name))
            .find_map(|rule| rule.apply(value)),
        ValueClass::Reference | ValueClass::Dynamic if depth < MAX_NESTING => {
            embedded_literals(value)
                .into_iter()
                .filter(|piece| piece != value)
                .find_map(|piece| scan_value_at(name, &piece, depth + 1))
        }
        ValueClass::Reference | ValueClass::Dynamic | ValueClass::Empty => None,
    }
}

/// The literal pieces inside a reference or substitution: the defaults of
/// `${NAME:-default}`, `${NAME:=default}`, `${NAME-default}` and
/// `${NAME:+alt}` (brace-nesting aware) and the bodies of `$(…)` and
/// backticks, plus the text around them.
#[must_use]
pub fn embedded_literals(value: &str) -> Vec<String> {
    let mut pieces = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    let mut outside = String::new();
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let start = i + 2;
            let mut depth = 1;
            let mut j = start;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            // The closing brace is ASCII, so `j - 1` is a char boundary
            // when one was consumed; an unterminated `${` runs to the end.
            let end = if depth == 0 { j - 1 } else { j };
            let inner = &value[start..end.max(start)];
            // `NAME:-default`, `NAME:=default`, `NAME-default`, `NAME:+alt`.
            let name_end = inner
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(inner.len());
            let rest = &inner[name_end..];
            let default = rest
                .strip_prefix(":-")
                .or_else(|| rest.strip_prefix(":="))
                .or_else(|| rest.strip_prefix(":+"))
                .or_else(|| rest.strip_prefix('-'))
                .or_else(|| rest.strip_prefix('='));
            if let Some(default) = default {
                if !default.is_empty() {
                    pieces.push(default.to_owned());
                }
            }
            i = j;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            let start = i + 2;
            let mut depth = 1;
            let mut j = start;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let end = if depth == 0 { j - 1 } else { j };
            let body = &value[start..end.max(start)];
            if !body.is_empty() {
                pieces.push(body.to_owned());
            }
            i = j;
            continue;
        }
        if bytes[i] == b'`' {
            let start = i + 1;
            let end = value[start..].find('`').map_or(bytes.len(), |e| start + e);
            let body = &value[start..end];
            if !body.is_empty() {
                pieces.push(body.to_owned());
            }
            i = (end + 1).min(bytes.len());
            continue;
        }
        // Advance one character (UTF-8 aware).
        let ch_len = value[i..].chars().next().map_or(1, char::len_utf8);
        outside.push_str(&value[i..i + ch_len]);
        i += ch_len;
    }
    // The text around the constructs, unless it is the whole value (a plain
    // `$VAR` reference has nothing inside to look at).
    let outside = outside.trim();
    if !outside.is_empty() && outside != "$" && outside != value.trim() {
        pieces.push(outside.to_owned());
    }
    pieces
}

/// Scans free text such as a command line: the vendor and URL rules run over
/// the whole text, then the name-keyed rules over every `NAME=value`,
/// `--flag=value` and `--flag value` word whose name says it is a credential.
#[must_use]
pub fn scan_text(text: &str) -> Option<SecretHit> {
    scan_text_at(text, 0)
}

fn scan_text_at(text: &str, depth: usize) -> Option<SecretHit> {
    if let Some(hit) = rules()
        .rules()
        .iter()
        .filter(|rule| !rule.name_keyed())
        .find_map(|rule| rule.apply(text))
    {
        return Some(hit);
    }
    if depth < MAX_NESTING && (text.contains("$(") || text.contains('`')) {
        if let Some(hit) = embedded_literals(text)
            .into_iter()
            .filter(|piece| piece != text)
            .find_map(|piece| scan_text_at(&piece, depth + 1))
        {
            return Some(hit);
        }
    }
    let words: Vec<&str> = text.split_whitespace().map(unquote).collect();
    let mut iter = words.iter().peekable();
    while let Some(word) = iter.next() {
        if let Some((name, value)) = word.split_once('=') {
            let name = name.trim_start_matches('-');
            if is_identifier(name) {
                if let Some(hit) = scan_named(name, value, depth) {
                    return Some(hit);
                }
            }
            continue;
        }
        if word.starts_with('-') {
            let name = word.trim_start_matches('-');
            if let Some(next) = iter.peek() {
                if is_identifier(name) && !next.starts_with('-') {
                    if let Some(hit) = scan_named(name, next, depth) {
                        return Some(hit);
                    }
                }
            }
        }
    }
    None
}

/// Name-keyed rules only, for the words of a command line.
fn scan_named(name: &str, value: &str, depth: usize) -> Option<SecretHit> {
    match classify(value) {
        ValueClass::Literal => rules()
            .rules()
            .iter()
            .filter(|rule| rule.name_keyed() && rule.accepts_name(Some(name)))
            .find_map(|rule| rule.apply(value)),
        ValueClass::Reference | ValueClass::Dynamic if depth < MAX_NESTING => {
            embedded_literals(value)
                .into_iter()
                .filter(|piece| piece != value)
                .find_map(|piece| scan_named(name, &piece, depth + 1))
        }
        ValueClass::Reference | ValueClass::Dynamic | ValueClass::Empty => None,
    }
}

/// Replaces every vendor and URL token in `text` with its masked form, so
/// a command, path or URL can be shown without the credential it carries.
/// Name-keyed rules are not applied here; [`crate::launch::mask_text`]
/// handles `NAME=value` words.
#[must_use]
pub fn mask_in_text(text: &str) -> String {
    let mut current = text.to_owned();
    for rule in rules().rules().iter().filter(|rule| !rule.name_keyed()) {
        if let Some(masked) = rule.mask_all(&current) {
            current = masked;
        }
    }
    current
}

fn unquote(word: &str) -> &str {
    word.trim_matches(['"', '\''])
}

fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANTHROPIC: &str = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE7Qa";
    const GITHUB: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a";
    const OPENAI: &str = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE";

    #[test]
    fn every_vendored_rule_compiles() {
        let set = rules();
        assert!(set.warnings.is_empty(), "{:?}", set.warnings);
        assert!(set.rules().len() > 20);
    }

    #[test]
    fn vendor_tokens_are_recognised_and_masked_with_the_last_three_characters() {
        let hit = scan_value(Some("ANTHROPIC_API_KEY"), ANTHROPIC).unwrap();
        assert_eq!(hit.kind, "Anthropic API key");
        assert_eq!(hit.masked, "sk-ant-••••7Qa");
        let hit = scan_value(Some("GITHUB_TOKEN"), GITHUB).unwrap();
        assert_eq!(hit.kind, "GitHub token");
        assert_eq!(hit.masked, "ghp_••••f9a");
        let hit = scan_value(None, OPENAI).unwrap();
        assert_eq!(hit.kind, "OpenAI API key");
        assert!(hit.masked.starts_with("sk-proj-••••"));
        let hit = scan_value(
            Some("COPILOT_GITHUB_TOKEN"),
            "ghu_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE9b1c",
        )
        .unwrap();
        assert_eq!(hit.masked, "ghu_••••b1c");
        let hit = scan_value(None, "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK").unwrap();
        assert_eq!(hit.kind, "Google API key");
        let hit = scan_value(Some("CLAUDE_CODE_OAUTH_TOKEN"), "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE2Zx").unwrap();
        assert_eq!(hit.kind, "Anthropic OAuth token");
        assert_eq!(hit.masked, "sk-ant-••••2Zx");
    }

    #[test]
    fn hits_never_carry_the_value() {
        let hit = scan_value(Some("GITHUB_TOKEN"), GITHUB).unwrap();
        let text = format!("{hit:?}");
        assert!(!text.contains("FAKEFAKE"), "{text}");
        let _ = ANTHROPIC;
    }

    #[test]
    fn literals_inside_references_and_substitutions_are_found() {
        let hit = scan_value(
            Some("DATABASE_URL"),
            "${DATABASE_URL:-postgresql://app:FAKEPASSWORDFAKE@db.acme.internal:5432/acme}",
        )
        .unwrap();
        assert_eq!(hit.kind, "Database password");
        assert_eq!(
            hit.masked,
            "postgresql://app:••••@db.acme.internal:5432/acme"
        );
        let hit = scan_value(
            Some("ANTHROPIC_API_KEY"),
            &format!("${{ANTHROPIC_API_KEY:-{ANTHROPIC}}}"),
        )
        .unwrap();
        assert_eq!(hit.masked, "sk-ant-••••7Qa");
        let hit = scan_value(Some("GITHUB_TOKEN"), &format!("$(echo {GITHUB})")).unwrap();
        assert_eq!(hit.kind, "GitHub token");
        let hit = scan_value(
            Some("LINT_HELPER_TOKEN"),
            "${LINT_HELPER_TOKEN:-lh_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE}",
        )
        .unwrap();
        assert_eq!(hit.kind, "Token");
        assert!(scan_value(Some("GITHUB_TOKEN"), "${GITHUB_TOKEN:-${FALLBACK}}").is_none());
        assert!(scan_value(
            Some("GITHUB_TOKEN"),
            "$(op read 'op://Private/GitHub/token')"
        )
        .is_none());
        assert!(scan_value(Some("X"), "${X}").is_none());
        assert!(scan_value(Some("PATH"), "$HOME/.local/bin:$PATH").is_none());
        assert!(scan_value(Some("X"), "$(").is_none());
        assert_eq!(embedded_literals("$HOME/.x"), Vec::<String>::new());
        assert_eq!(
            embedded_literals("${A:-one} $(two) `three` four"),
            vec!["one", "two", "three", "four"]
        );
        assert_eq!(embedded_literals("${A:-${B:-deep}}"), vec!["${B:-deep}"]);
        // Unterminated constructs ending in a multibyte character are a
        // malformed line, never a panic (hard rule 7).
        assert_eq!(embedded_literals("${é"), Vec::<String>::new());
        assert!(scan_value(Some("X"), "${é").is_none());
        assert!(scan_value(Some("GITHUB_TOKEN"), "$(é").is_none());
        assert!(scan_text("echo $(é").is_none());
        assert!(scan_text("echo `é").is_none());
        assert_eq!(embedded_literals("${X:-é"), vec!["é"]);
        assert_eq!(embedded_literals("$(é"), vec!["é"]);
        assert_eq!(
            scan_text(&format!("eval \"$(echo {GITHUB})\""))
                .unwrap()
                .kind,
            "GitHub token"
        );
    }

    #[test]
    fn nesting_is_bounded_in_time_and_stack() {
        // Pathological nesting neither overflows the stack nor takes a copy
        // per level without end; the token is still found when it sits
        // within the first levels.
        let deep = format!("{}x{}", "${A:-".repeat(20_000), "}".repeat(20_000));
        assert!(scan_value(Some("GITHUB_TOKEN"), &deep).is_none());
        let deep = format!("echo {}x{}", "$(".repeat(20_000), ")".repeat(20_000));
        assert!(scan_text(&deep).is_none());
        let shallow = format!("${{A:-${{B:-${{C:-{GITHUB}}}}}}}");
        assert_eq!(
            scan_value(Some("GITHUB_TOKEN"), &shallow).unwrap().kind,
            "GitHub token"
        );
    }

    #[test]
    fn mask_in_text_replaces_every_vendor_token() {
        let text = format!("echo {ANTHROPIC} && curl -u app:x https://u:hunter2hunter2@h.example/x?token=FAKEQUERYTOKEN {GITHUB}");
        let masked = mask_in_text(&text);
        assert!(!masked.contains("FAKEFAKE"), "{masked}");
        assert!(masked.contains("sk-ant-••••7Qa"), "{masked}");
        assert!(masked.contains("ghp_••••f9a"), "{masked}");
        assert!(
            masked.contains("https://u:••••@h.example/x?token=••••KEN"),
            "{masked}"
        );
        assert_eq!(
            mask_in_text("npx prettier --write x"),
            "npx prettier --write x"
        );
    }

    #[test]
    fn a_short_github_token_is_not_a_token() {
        // 35 characters after the prefix: the length class does not match.
        assert!(scan_value(None, "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK3f9").is_none());
    }

    #[test]
    fn database_urls_mask_the_whole_password() {
        let hit = scan_value(
            None,
            "postgresql://app:FAKEPASSWORDFAKE@db.acme.internal:5432/acme",
        )
        .unwrap();
        assert_eq!(hit.kind, "Database password");
        assert_eq!(
            hit.masked,
            "postgresql://app:••••@db.acme.internal:5432/acme"
        );
        assert!(scan_value(None, "postgresql://app@db.acme.internal:5432/acme").is_none());
        assert!(scan_value(None, "postgresql://app:${DB_PASSWORD}@db/acme").is_none());
        let hit = scan_value(None, "https://user:hunter2hunter2@proxy.example/x").unwrap();
        assert_eq!(hit.kind, "URL password");
        assert_eq!(hit.masked, "https://user:••••@proxy.example/x");
        // Evidence never keeps a query string: it could hold a second secret.
        let hit = scan_value(
            None,
            "https://user:hunter2hunter2@proxy.example/x?token=FAKEQUERYTOKEN#f",
        )
        .unwrap();
        assert_eq!(hit.masked, "https://user:••••@proxy.example/x");
    }

    #[test]
    fn query_credentials_are_found_but_ordinary_parameters_are_not() {
        let hit = scan_value(
            None,
            "https://hooks.acme-corp.example/claude?token=FAKEQUERYTOKEN",
        )
        .unwrap();
        assert_eq!(hit.kind, "Query credential");
        assert_eq!(hit.masked, "?token=••••KEN");
        assert!(scan_value(
            None,
            "https://mcp.context7.com/mcp?client=claude-code-plugin"
        )
        .is_none());
    }

    #[test]
    fn name_keyed_rules_need_a_credential_name_and_a_literal() {
        let hit = scan_value(
            Some("LINT_HELPER_TOKEN"),
            "lh_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        )
        .unwrap();
        assert_eq!(hit.kind, "Token");
        assert_eq!(hit.masked, "••••AKE", "no vendor prefix to keep");
        let hit = scan_value(Some("DB_PASSWORD"), "my-db-password-2024!!").unwrap();
        assert_eq!(hit.kind, "Password");
        assert_eq!(hit.masked, "••••", "a password shows nothing");
        let hit = scan_value(Some("X-Api-Key"), "adk_FAKEFAKEFAKEFAKEFAKEFAKEFAKE").unwrap();
        assert_eq!(hit.kind, "API key");
        let hit = scan_value(Some("ACME_API_TOKEN"), "acme_FAKEFAKEFAKEFAKEFAKE").unwrap();
        assert_eq!(hit.kind, "Token");
        let hit = scan_value(
            Some("Authorization"),
            "Bearer adk_FAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        )
        .unwrap();
        assert_eq!(hit.kind, "Bearer token");
        assert_eq!(hit.masked, "Bearer ••••AKE");
        // A recognised vendor token keeps its vendor kind inside a header.
        let hit = scan_value(Some("Authorization"), &format!("Bearer {GITHUB}")).unwrap();
        assert_eq!(hit.kind, "GitHub token");
        assert_eq!(hit.masked, "ghp_••••f9a");

        assert!(scan_value(Some("LINT_HELPER_LOG"), "warn-warn-warn-warn").is_none());
        assert!(scan_value(Some("LINT_HELPER_TOKEN"), "${LINT_HELPER_TOKEN}").is_none());
        assert!(scan_value(Some("LINT_HELPER_TOKEN"), "${env:LINT_HELPER_TOKEN}").is_none());
        assert!(scan_value(Some("Authorization"), "Bearer ${GITHUB_TOKEN}").is_none());
        assert!(scan_value(Some("Authorization"), "Bearer $HOOK_TOKEN").is_none());
        // Excluded by the reference allowlist, not by length.
        assert!(scan_value(Some("Authorization"), "Bearer $HOOK_TOKEN_LONG_ENOUGH").is_none());
        assert!(scan_value(Some("Authorization"), "Bearer ${HOOK_TOKEN_LONG_ENOUGH}").is_none());
        assert!(scan_value(
            Some("GITHUB_TOKEN"),
            "$(op read 'op://Private/GitHub/token')"
        )
        .is_none());
        assert!(scan_value(Some("TOKEN_FILE"), "/Users/you/.config/acme/token").is_none());
        assert!(scan_value(Some("TOKEN_TTL"), "3600000000000").is_none());
        assert!(scan_value(Some("API_KEY_URL"), "https://keys.example.com/get").is_none());
        assert!(scan_value(Some("CODEX_SANDBOX"), "1").is_none());
        assert!(
            scan_value(None, "lh_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE").is_none(),
            "no name, no generic rule"
        );
    }

    #[test]
    fn free_text_finds_tokens_assignments_and_flags() {
        let hit = scan_text(&format!("GITHUB_TOKEN={GITHUB} npx server")).unwrap();
        assert_eq!(hit.kind, "GitHub token");
        let hit = scan_text("sh -c 'API_TOKEN=acme_FAKEFAKEFAKEFAKEFAKE npx server'").unwrap();
        assert_eq!(hit.kind, "Token");
        let hit = scan_text("server --api-key adk_FAKEFAKEFAKEFAKEFAKEFAKEFAKE --port 1").unwrap();
        assert_eq!(hit.kind, "API key");
        let hit = scan_text("server --token=acme_FAKEFAKEFAKEFAKEFAKE").unwrap();
        assert_eq!(hit.kind, "Token");
        assert!(scan_text("GITHUB_TOKEN=${GITHUB_TOKEN} npx server").is_none());
        assert!(scan_text("curl -fsSL https://dotfiles-sync.example/setup.sh | sh").is_none());
        assert!(scan_text("npx prettier --write \"$CLAUDE_FILE_PATHS\"").is_none());
        assert!(scan_text("--api-key --port 1").is_none());
    }

    #[test]
    fn classification() {
        assert_eq!(classify(""), ValueClass::Empty);
        assert_eq!(classify("  "), ValueClass::Empty);
        assert_eq!(classify("${VAR}"), ValueClass::Reference);
        assert_eq!(classify("$VAR"), ValueClass::Reference);
        assert_eq!(classify("${env:NAME}"), ValueClass::Reference);
        assert_eq!(classify("op://Private/x"), ValueClass::Reference);
        assert_eq!(classify("$(op read x)"), ValueClass::Dynamic);
        assert_eq!(classify("`cat x`"), ValueClass::Dynamic);
        assert_eq!(classify("sk-ant-x"), ValueClass::Literal);
        assert_eq!(classify("Bearer $T"), ValueClass::Literal);
    }
}
