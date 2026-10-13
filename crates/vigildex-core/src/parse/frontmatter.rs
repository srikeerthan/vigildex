//! Markdown frontmatter: the leading `---` block of skills, commands,
//! subagents and rules.
//!
//! Only the frontmatter is parsed. The body is counted, never kept.

use saphyr::{LoadableYamlNode, Scalar, Yaml};
use serde_json::{Map, Value};

/// The frontmatter of a Markdown file, as a JSON-shaped value.
#[derive(Debug, Clone, PartialEq)]
pub struct Frontmatter {
    /// The parsed fields: an object, or `Null` when the file has no
    /// frontmatter.
    pub fields: Value,
    /// Set when the YAML did not parse and only top-level `key: value`
    /// scalars were recovered line by line.
    pub lenient: Option<String>,
}

impl Frontmatter {
    /// The string field `key`.
    #[must_use]
    pub fn str(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(Value::as_str)
    }

    /// The boolean field `key`.
    #[must_use]
    pub fn bool(&self, key: &str) -> Option<bool> {
        self.fields.get(key).and_then(Value::as_bool)
    }
}

/// Splits a Markdown text into its frontmatter YAML and body.
///
/// Frontmatter exists only when the first line is exactly `---` (a UTF-8
/// byte-order mark and trailing whitespace are tolerated) and a later line
/// is `---` or `...`. Without a closing line there is no frontmatter and the
/// whole text is body, which is how Claude Code and Codex treat it too.
#[must_use]
pub fn split(text: &str) -> (Option<&str>, &str) {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.split_inclusive('\n');
    let Some(first) = lines.next() else {
        return (None, text);
    };
    if first.trim_end() != "---" {
        return (None, text);
    }
    let mut offset = first.len();
    let yaml_start = offset;
    for line in lines {
        let trimmed = line.trim_end();
        if trimmed == "---" || trimmed == "..." {
            let yaml = &text[yaml_start..offset];
            let body = &text[offset + line.len()..];
            return (Some(yaml), body);
        }
        offset += line.len();
    }
    (None, text)
}

/// Parses a Markdown text's frontmatter.
#[must_use]
pub fn parse(text: &str) -> Frontmatter {
    let (yaml, _body) = split(text);
    let Some(yaml) = yaml else {
        return Frontmatter {
            fields: Value::Null,
            lenient: None,
        };
    };
    match yaml_to_json(yaml) {
        Ok(Value::Object(map)) => Frontmatter {
            fields: Value::Object(map),
            lenient: None,
        },
        Ok(_) => Frontmatter {
            fields: Value::Object(Map::new()),
            lenient: Some("frontmatter is not a mapping".to_owned()),
        },
        Err(err) => Frontmatter {
            fields: lenient_fields(yaml),
            lenient: Some(err),
        },
    }
}

/// Converts the first YAML document in `yaml` to a JSON-shaped value.
///
/// # Errors
///
/// Returns the parser's message when the YAML does not parse.
pub fn yaml_to_json(yaml: &str) -> Result<Value, String> {
    let docs = Yaml::load_from_str(yaml).map_err(|err| err.to_string())?;
    Ok(docs.first().map_or(Value::Null, node_to_json))
}

fn node_to_json(node: &Yaml<'_>) -> Value {
    match node {
        Yaml::Value(scalar) => scalar_to_json(scalar),
        Yaml::Representation(text, _, _) => Value::String(text.to_string()),
        Yaml::Sequence(items) => Value::Array(items.iter().map(node_to_json).collect()),
        Yaml::Mapping(map) => {
            let mut out = Map::new();
            for (key, value) in map.iter() {
                let Some(key) = key_text(key) else {
                    continue;
                };
                out.insert(key, node_to_json(value));
            }
            Value::Object(out)
        }
        Yaml::Tagged(_, inner) => node_to_json(inner),
        Yaml::Alias(_) | Yaml::BadValue => Value::Null,
    }
}

fn scalar_to_json(scalar: &Scalar<'_>) -> Value {
    match scalar {
        Scalar::Null => Value::Null,
        Scalar::Boolean(b) => Value::Bool(*b),
        Scalar::Integer(i) => Value::from(*i),
        Scalar::FloatingPoint(f) => Value::from(f.into_inner()),
        Scalar::String(s) => Value::String(s.to_string()),
    }
}

fn key_text(key: &Yaml<'_>) -> Option<String> {
    match key {
        Yaml::Value(scalar) => match scalar {
            Scalar::String(s) => Some(s.to_string()),
            Scalar::Boolean(b) => Some(b.to_string()),
            Scalar::Integer(i) => Some(i.to_string()),
            Scalar::FloatingPoint(f) => Some(f.to_string()),
            Scalar::Null => Some("null".to_owned()),
        },
        Yaml::Representation(text, _, _) => Some(text.to_string()),
        _ => None,
    }
}

/// Recovers top-level `key: value` scalars from YAML that did not parse, so
/// a skill with an unquoted colon in its description still gets a name.
fn lenient_fields(yaml: &str) -> Value {
    let mut map = Map::new();
    for line in yaml.lines() {
        if line.starts_with([' ', '\t', '-', '#']) {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || key.contains(' ') {
            continue;
        }
        let value = value.trim().trim_matches(['"', '\'']);
        // A collection (or the start of a broken one) is not a scalar.
        if value.is_empty() || value.starts_with(['[', '{']) {
            continue;
        }
        let json = match value {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => Value::String(value.to_owned()),
        };
        map.insert(key.to_owned(), json);
    }
    Value::Object(map)
}

/// Splits a tool list as skills write it: whitespace- or comma-separated,
/// where a rule such as `Bash(git add *)` keeps its inner spaces.
#[must_use]
pub fn split_tool_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0u32;
    for ch in text.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ' ' | '\t' | '\n' | ',' if depth == 0 => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// A tool list from a frontmatter value: a string to split, or an array.
#[must_use]
pub fn tool_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => split_tool_list(s),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .flat_map(split_tool_list)
            .collect(),
        _ => Vec::new(),
    }
}

/// Collapses whitespace and cuts a description for display.
#[must_use]
pub fn short_description(text: &str) -> String {
    const MAX: usize = 160;
    let collapsed: Vec<&str> = text.split_whitespace().collect();
    let joined = collapsed.join(" ");
    if joined.chars().count() <= MAX {
        return joined;
    }
    let mut cut: String = joined.chars().take(MAX - 1).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn splits_frontmatter_from_body() {
        let text = "---\nname: deploy\ndescription: Ship it\n---\n# Body\n";
        let (yaml, body) = split(text);
        assert_eq!(yaml, Some("name: deploy\ndescription: Ship it\n"));
        assert_eq!(body, "# Body\n");
    }

    #[test]
    fn no_leading_dashes_means_no_frontmatter() {
        let (yaml, body) = split("# Title\n---\nnot frontmatter\n---\n");
        assert!(yaml.is_none());
        assert!(body.starts_with("# Title"));
    }

    #[test]
    fn unclosed_frontmatter_is_body() {
        let (yaml, _) = split("---\nname: x\n");
        assert!(yaml.is_none());
    }

    #[test]
    fn parses_nested_hooks_and_lists() {
        let text = "---\nname: secure-ops\nallowed-tools: Bash(git add *) Bash(git status *)\ndisable-model-invocation: true\nhooks:\n  PreToolUse:\n    - matcher: \"Bash\"\n      hooks:\n        - type: command\n          command: \"./scripts/check.sh\"\n---\nbody\n";
        let fm = parse(text);
        assert!(fm.lenient.is_none());
        assert_eq!(fm.str("name"), Some("secure-ops"));
        assert_eq!(fm.bool("disable-model-invocation"), Some(true));
        assert_eq!(
            fm.fields["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            json!("./scripts/check.sh")
        );
        assert_eq!(
            tool_list(fm.fields.get("allowed-tools")),
            vec!["Bash(git add *)", "Bash(git status *)"]
        );
    }

    #[test]
    fn malformed_yaml_recovers_top_level_scalars() {
        let text = "---\nname: odd\ndescription: Use when: things break\nhooks: [unclosed\n---\n";
        let fm = parse(text);
        assert!(fm.lenient.is_some());
        assert_eq!(fm.str("name"), Some("odd"));
        assert_eq!(fm.str("description"), Some("Use when: things break"));
    }

    #[test]
    fn tool_lists_split_on_commas_and_spaces_outside_parens() {
        assert_eq!(
            split_tool_list("Read, Grep,Glob"),
            vec!["Read", "Grep", "Glob"]
        );
        assert_eq!(
            split_tool_list("Bash(npm run *) Read"),
            vec!["Bash(npm run *)", "Read"]
        );
        assert_eq!(
            tool_list(Some(&json!(["Read", "Bash(ls *)"]))),
            vec!["Read", "Bash(ls *)"]
        );
    }

    #[test]
    fn descriptions_are_collapsed_and_cut() {
        assert_eq!(short_description("  a\n  b  "), "a b");
        let long = "x".repeat(400);
        let cut = short_description(&long);
        assert_eq!(cut.chars().count(), 160);
        assert!(cut.ends_with('…'));
    }
}
