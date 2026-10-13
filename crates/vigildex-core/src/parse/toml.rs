//! TOML to `serde_json::Value`, so Codex configuration can use the same
//! parsers as JSON configuration.
//!
//! `toml_edit` keeps spans, which later milestones use for line numbers in
//! findings; for the inventory only the values matter.

use std::str::FromStr;

use serde_json::{Map, Value};
use toml_edit::{DocumentMut, Item, Table};

/// Parses TOML text into a JSON-shaped value. Tables become objects, arrays
/// of tables become arrays, and date-times become their string form.
///
/// # Errors
///
/// Returns the parser's message when the text is not valid TOML.
pub fn to_json(text: &str) -> Result<Value, String> {
    let doc = DocumentMut::from_str(text).map_err(|err| err.to_string())?;
    Ok(table_to_json(doc.as_table()))
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
    fn invalid_toml_is_an_error_message() {
        let err = to_json("model = ").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn datetimes_become_strings() {
        let value = to_json("at = 2026-10-13T00:00:00Z").unwrap();
        assert_eq!(value["at"], json!("2026-10-13T00:00:00Z"));
    }
}
