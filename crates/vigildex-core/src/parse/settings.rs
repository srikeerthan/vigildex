//! Security-relevant settings, selected by key-path patterns.
//!
//! Each adapter owns a table of patterns (`permissions.allow`,
//! `model_providers.*.base_url`, …). A pattern segment of `*` matches every
//! key at that level. Matching values are reduced with
//! [`crate::parse::json::redact`], so an `env` object contributes key names
//! only. Keys that are absent produce nothing: the inventory reports what is
//! set, not defaults.

use serde_json::Value;

use crate::model::{ArtifactRef, Item, RedactedValue, Setting};
use crate::parse::json::{join_key, redact};

/// How a matched key is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    /// Reduce the value with [`redact`].
    Value,
    /// Record only that the key exists (`oauthAccount`).
    Presence,
}

/// One pattern in an adapter's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRule {
    /// Dot-separated key path; `*` matches any one key.
    pub pattern: &'static str,
    /// How to record a match.
    pub record: Record,
}

impl KeyRule {
    /// A rule that records the redacted value.
    #[must_use]
    pub const fn value(pattern: &'static str) -> Self {
        Self {
            pattern,
            record: Record::Value,
        }
    }

    /// A rule that records only the key's presence.
    #[must_use]
    pub const fn presence(pattern: &'static str) -> Self {
        Self {
            pattern,
            record: Record::Presence,
        }
    }
}

/// Resolves the raw key segments of a match to a line number, for formats
/// that have one (see [`crate::parse::toml::line_of`]).
pub type LineResolver<'a> = &'a dyn Fn(&[&str]) -> Option<u32>;

/// Applies `rules` to `root`, appending one [`Item::Setting`] per match.
/// `prefix` is prepended to every key path (for a project sub-object).
/// Lines are left unset; see [`extract_with_lines`].
pub fn extract(
    root: &Value,
    prefix: &str,
    rules: &[KeyRule],
    source: &ArtifactRef,
    items: &mut Vec<Item>,
) {
    extract_with_lines(root, prefix, &[], rules, source, items, &|_| None);
}

/// [`extract`] with a line resolver. `prefix_segments` are the raw keys
/// that `prefix` stands for, so the resolver gets the full segment list.
pub fn extract_with_lines(
    root: &Value,
    prefix: &str,
    prefix_segments: &[&str],
    rules: &[KeyRule],
    source: &ArtifactRef,
    items: &mut Vec<Item>,
    line_of: LineResolver<'_>,
) {
    for rule in rules {
        let segments: Vec<&str> = rule.pattern.split('.').collect();
        let mut raw: Vec<&str> = prefix_segments.to_vec();
        walk(
            root,
            prefix,
            &mut raw,
            &segments,
            rule.record,
            source,
            items,
            line_of,
        );
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "a recursive walker over key paths; bundling the state would not make it clearer"
)]
fn walk<'a>(
    value: &'a Value,
    key_path: &str,
    raw: &mut Vec<&'a str>,
    segments: &[&str],
    record: Record,
    source: &ArtifactRef,
    items: &mut Vec<Item>,
    line_of: LineResolver<'_>,
) {
    let Some((head, rest)) = segments.split_first() else {
        let redacted = match record {
            Record::Value => redact(value),
            Record::Presence => RedactedValue::Present,
        };
        items.push(Item::Setting(Setting {
            key_path: key_path.to_owned(),
            value: redacted,
            line: line_of(raw),
            source: source.clone(),
        }));
        return;
    };
    let Some(map) = value.as_object() else {
        return;
    };
    if *head == "*" {
        for (key, child) in map {
            raw.push(key.as_str());
            walk(
                child,
                &join_key(key_path, key),
                raw,
                rest,
                record,
                source,
                items,
                line_of,
            );
            raw.pop();
        }
    } else if let Some((key, child)) = map.get_key_value(*head) {
        raw.push(key.as_str());
        walk(
            child,
            &join_key(key_path, head),
            raw,
            rest,
            record,
            source,
            items,
            line_of,
        );
        raw.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Agent, ArtifactKind, Scope};
    use serde_json::json;

    fn src() -> ArtifactRef {
        ArtifactRef {
            agent: Agent::Codex,
            scope: Scope::User,
            kind: ArtifactKind::Settings,
            path: "/x/config.toml".into(),
        }
    }

    fn setting(item: &Item) -> (&str, &RedactedValue) {
        match item {
            Item::Setting(s) => (s.key_path.as_str(), &s.value),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn exact_wildcard_and_presence_rules() {
        let root = json!({
            "approval_policy": "never",
            "env": {"OPENAI_API_KEY": "sk-secret"},
            "model_providers": {"local": {"base_url": "http://localhost:11434/v1", "name": "Ollama"}},
            "oauthAccount": {"emailAddress": "you@example.com"},
            "absent_elsewhere": true
        });
        let rules = [
            KeyRule::value("approval_policy"),
            KeyRule::value("env"),
            KeyRule::value("model_providers.*.base_url"),
            KeyRule::presence("oauthAccount"),
            KeyRule::value("missing.key"),
        ];
        let mut items = Vec::new();
        extract(&root, "", &rules, &src(), &mut items);
        let found: Vec<(&str, &RedactedValue)> = items.iter().map(setting).collect();
        assert_eq!(
            found,
            vec![
                (
                    "approval_policy",
                    &RedactedValue::Text {
                        value: "never".into()
                    }
                ),
                (
                    "env",
                    &RedactedValue::Keys {
                        keys: vec!["OPENAI_API_KEY".into()]
                    }
                ),
                (
                    "model_providers.local.base_url",
                    &RedactedValue::Text {
                        value: "http://localhost:11434/v1".into()
                    }
                ),
                ("oauthAccount", &RedactedValue::Present),
            ]
        );
        let text = serde_json::to_string(&items).unwrap();
        assert!(!text.contains("sk-secret"));
        assert!(!text.contains("you@example.com"));
    }

    #[test]
    fn line_resolver_sees_the_raw_segments() {
        let root = json!({"model_providers": {"local": {"base_url": "http://localhost/v1"}}});
        let mut items = Vec::new();
        extract_with_lines(
            &root,
            "",
            &[],
            &[KeyRule::value("model_providers.*.base_url")],
            &src(),
            &mut items,
            &|segs| {
                assert_eq!(segs, ["model_providers", "local", "base_url"]);
                Some(7)
            },
        );
        let Item::Setting(setting) = &items[0] else {
            panic!()
        };
        assert_eq!(setting.line, Some(7));
    }

    #[test]
    fn prefix_is_prepended_for_project_objects() {
        let project = json!({"trust_level": "trusted"});
        let mut items = Vec::new();
        extract(
            &project,
            r#"projects["/Users/you/proj"]"#,
            &[KeyRule::value("trust_level")],
            &src(),
            &mut items,
        );
        assert_eq!(
            setting(&items[0]).0,
            r#"projects["/Users/you/proj"].trust_level"#
        );
    }

    #[test]
    fn non_object_intermediate_values_match_nothing() {
        let root = json!({"permissions": "oops"});
        let mut items = Vec::new();
        extract(
            &root,
            "",
            &[KeyRule::value("permissions.allow")],
            &src(),
            &mut items,
        );
        assert!(items.is_empty());
    }
}
