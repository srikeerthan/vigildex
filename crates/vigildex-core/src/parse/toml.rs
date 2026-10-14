//! TOML to `serde_json::Value`, so Codex configuration can use the same
//! parsers as JSON configuration.
//!
//! `toml_edit` keeps spans, which later milestones use for line numbers in
//! findings; for the inventory only the values matter.

use std::ops::Range;

use serde_json::{Map, Value};
use toml_edit::{Item, Table};

/// The 1-based line on which the value at `path` (raw key segments) starts,
/// or `None` when the text does not parse or the key is absent. Dotted and
/// quoted keys, inline tables, arrays (by index) and arrays of tables (by
/// index) are all walked. A table that exists only implicitly (`[a.b]`
/// creates `a`) has no span of its own; the lookup carries on and reports
/// the first explicit span below it.
#[must_use]
pub fn line_of(text: &str, path: &[&str]) -> Option<u32> {
    Parsed::parse(text).ok()?.line_of(path)
}

/// The byte offset at which the value at `path` starts.
fn offset_of(root: &Table, path: &[&str]) -> Option<usize> {
    // Only the immutable document keeps spans; `DocumentMut` drops them.
    let mut node = Node::Table(root);
    let mut span: Option<Range<usize>> = None;
    for key in path {
        let (next, next_span) = match node {
            Node::Table(table) => descend_table(table, key)?,
            Node::Item(item) => match item {
                Item::Table(table) => descend_table(table, key)?,
                Item::Value(value) => descend_value(value, key)?,
                Item::ArrayOfTables(tables) => {
                    let index: usize = key.parse().ok()?;
                    let table = tables.get(index)?;
                    (Node::Table(table), table.span())
                }
                Item::None => return None,
            },
            Node::Value(value) => descend_value(value, key)?,
        };
        node = next;
        span = next_span.or(span);
    }
    span.map(|s| s.start)
}

/// A position in a TOML document while walking a key path.
enum Node<'a> {
    Table(&'a Table),
    Item(&'a Item),
    Value(&'a toml_edit::Value),
}

fn descend_table<'a>(table: &'a Table, key: &str) -> Option<(Node<'a>, Option<Range<usize>>)> {
    let (k, v) = table.get_key_value(key)?;
    Some((Node::Item(v), v.span().or_else(|| k.span())))
}

fn descend_value<'a>(
    value: &'a toml_edit::Value,
    key: &str,
) -> Option<(Node<'a>, Option<Range<usize>>)> {
    match value {
        toml_edit::Value::InlineTable(table) => {
            let (k, v) = table.get_key_value(key)?;
            Some((Node::Item(v), v.span().or_else(|| k.span())))
        }
        toml_edit::Value::Array(array) => {
            let index: usize = key.parse().ok()?;
            let v = array.get(index)?;
            Some((Node::Value(v), v.span()))
        }
        _ => None,
    }
}

/// 1-based line of a byte offset.
fn line_at(text: &str, offset: usize) -> u32 {
    let count = text
        .as_bytes()
        .iter()
        .take(offset)
        .filter(|b| **b == b'\n')
        .count();
    u32::try_from(count + 1).unwrap_or(u32::MAX)
}

/// Parses TOML text into a JSON-shaped value. Tables become objects, arrays
/// of tables become arrays, and date-times become their string form.
///
/// # Errors
///
/// Returns the parser's message and position when the text is not valid
/// TOML. The message never quotes the source: a broken line can hold a
/// token.
pub fn to_json(text: &str) -> Result<Value, String> {
    Ok(Parsed::parse(text)?.value)
}

/// A parsed TOML document: its JSON-shaped value and, for line numbers,
/// the document with its spans.
#[derive(Debug)]
pub struct Parsed {
    /// The document as a JSON-shaped value.
    pub value: Value,
    doc: toml_edit::Document<String>,
    text_len: usize,
    newlines: Vec<usize>,
}

impl Parsed {
    /// Parses `text`.
    ///
    /// # Errors
    ///
    /// The parser's message and position, without the source line.
    pub fn parse(text: &str) -> Result<Self, String> {
        let doc = toml_edit::Document::parse(text.to_owned()).map_err(|err| {
            let position = err
                .span()
                .map(|span| format!(" at line {}", line_at(text, span.start)))
                .unwrap_or_default();
            format!("{}{position}", err.message())
        })?;
        Ok(Self {
            value: table_to_json(doc.as_table()),
            doc,
            text_len: text.len(),
            newlines: text
                .bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i)
                .collect(),
        })
    }

    /// The 1-based line on which the value at `path` (raw key segments)
    /// starts; see [`line_of`].
    #[must_use]
    pub fn line_of(&self, path: &[&str]) -> Option<u32> {
        let offset = offset_of(self.doc.as_table(), path)?;
        let before = self
            .newlines
            .partition_point(|nl| *nl < offset.min(self.text_len));
        u32::try_from(before + 1).ok()
    }
}

fn table_to_json(table: &Table) -> Value {
    let mut map = Map::new();
    for (key, item) in table.iter() {
        if let Some(value) = item_to_json(item) {
            map.insert(key.to_owned(), value);
        }
    }
    Value::Object(map)
}

fn item_to_json(item: &Item) -> Option<Value> {
    match item {
        Item::None => None,
        Item::Value(value) => Some(value_to_json(value)),
        Item::Table(table) => Some(table_to_json(table)),
        Item::ArrayOfTables(tables) => {
            Some(Value::Array(tables.iter().map(table_to_json).collect()))
        }
    }
}

fn value_to_json(value: &toml_edit::Value) -> Value {
    match value {
        toml_edit::Value::String(s) => Value::String(s.value().clone()),
        toml_edit::Value::Integer(i) => Value::from(*i.value()),
        toml_edit::Value::Float(f) => Value::from(*f.value()),
        toml_edit::Value::Boolean(b) => Value::Bool(*b.value()),
        toml_edit::Value::Datetime(d) => Value::String(d.value().to_string()),
        toml_edit::Value::Array(array) => Value::Array(array.iter().map(value_to_json).collect()),
        toml_edit::Value::InlineTable(table) => {
            let mut map = Map::new();
            for (key, value) in table.iter() {
                map.insert(key.to_owned(), value_to_json(value));
            }
            Value::Object(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tables_dotted_keys_and_arrays_of_tables_convert() {
        let text = r#"
model = "gpt-5"
approval_policy = "never"

[projects."/Users/you/proj/1"]
trust_level = "trusted"

[mcp_servers.github]
url = "https://api.githubcopilot.com/mcp/"
bearer_token_env_var = "GITHUB_TOKEN"
http_headers = { "X-Team" = "acme" }
enabled = true
startup_timeout_sec = 20.5

[[skills.config]]
path = "/Users/you/.agents/skills/noisy/SKILL.md"
enabled = false
"#;
        let value = to_json(text).unwrap();
        assert_eq!(value["model"], json!("gpt-5"));
        assert_eq!(
            value["projects"]["/Users/you/proj/1"]["trust_level"],
            json!("trusted")
        );
        assert_eq!(value["mcp_servers"]["github"]["enabled"], json!(true));
        assert_eq!(
            value["mcp_servers"]["github"]["http_headers"]["X-Team"],
            json!("acme")
        );
        assert_eq!(
            value["mcp_servers"]["github"]["startup_timeout_sec"],
            json!(20.5)
        );
        assert_eq!(value["skills"]["config"][0]["enabled"], json!(false));
    }

    #[test]
    fn lines_are_found_for_keys_tables_inline_tables_and_arrays_of_tables() {
        let text = "model = \"x\"\napproval_policy = \"never\"\n\n[shell_environment_policy]\nset = { A = \"1\", TOKEN = \"t\" }\n\n[mcp_servers.lint-helper]\ncommand = \"npx\"\nenv = { LINT_HELPER_TOKEN = \"lh\" }\n\n[projects.\"/Users/you/proj\"]\ntrust_level = \"trusted\"\n\n[[skills.config]]\npath = \"a\"\n\n[[skills.config]]\npath = \"b\"\nenabled = false\n";
        assert_eq!(line_of(text, &["approval_policy"]), Some(2));
        assert_eq!(
            line_of(text, &["shell_environment_policy", "set", "TOKEN"]),
            Some(5)
        );
        assert_eq!(
            line_of(
                text,
                &["mcp_servers", "lint-helper", "env", "LINT_HELPER_TOKEN"]
            ),
            Some(9)
        );
        assert_eq!(line_of(text, &["mcp_servers", "lint-helper"]), Some(7));
        assert_eq!(
            line_of(text, &["projects", "/Users/you/proj", "trust_level"]),
            Some(12)
        );
        assert_eq!(
            line_of(text, &["skills", "config", "1", "enabled"]),
            Some(19)
        );
        assert_eq!(line_of(text, &["missing"]), None);
        assert_eq!(line_of(text, &["approval_policy", "deeper"]), None);
        assert_eq!(line_of("not = toml =", &["not"]), None);
    }

    #[test]
    fn invalid_toml_is_an_error_message_without_the_source() {
        let err = to_json("model = ").unwrap_err();
        assert!(!err.is_empty());
        let err =
            to_json("ok = 1\nset = { TOKEN = \"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE3f9a\" \n")
                .unwrap_err();
        assert!(!err.contains("ghp_"), "{err}");
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn parsed_documents_resolve_lines_without_reparsing() {
        let parsed = Parsed::parse("a = 1\n[t]\nb = 2\n").unwrap();
        assert_eq!(parsed.value["t"]["b"], json!(2));
        assert_eq!(parsed.line_of(&["t", "b"]), Some(3));
        assert_eq!(parsed.line_of(&["t"]), Some(2));
        assert_eq!(parsed.line_of(&["x"]), None);
    }

    #[test]
    fn datetimes_become_strings() {
        let value = to_json("at = 2026-10-13T00:00:00Z").unwrap();
        assert_eq!(value["at"], json!("2026-10-13T00:00:00Z"));
    }
}
