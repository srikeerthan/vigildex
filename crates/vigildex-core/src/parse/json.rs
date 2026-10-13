//! Helpers for navigating `serde_json::Value` without panicking.

use serde_json::Value;

use crate::model::RedactedValue;

/// The string at `key`, when the value is an object with a string there.
#[must_use]
pub fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// The boolean at `key`.
#[must_use]
pub fn bool_at(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

/// The non-negative integer at `key`. A float is truncated.
#[must_use]
pub fn u64_at(value: &Value, key: &str) -> Option<u64> {
    let number = value.get(key)?;
    number
        .as_u64()
        .or_else(|| number.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
}

/// The object at `key`.
#[must_use]
pub fn object_at<'a>(value: &'a Value, key: &str) -> Option<&'a serde_json::Map<String, Value>> {
    value.get(key).and_then(Value::as_object)
}

/// A list of strings from an array of strings, or from one string. Elements
/// that are not strings are skipped.
#[must_use]
pub fn string_list(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// The list of strings at `key`, empty when absent.
#[must_use]
pub fn string_list_at(value: &Value, key: &str) -> Vec<String> {
    value.get(key).map(string_list).unwrap_or_default()
}

/// The key names of the object at `key`, empty when absent or not an object.
#[must_use]
pub fn keys_at(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// A short, single-line form of a scalar for lists and labels.
#[must_use]
pub fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Null => Some("null".to_owned()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// Reduces a value to what is safe to show (see [`RedactedValue`]).
#[must_use]
pub fn redact(value: &Value) -> RedactedValue {
    match value {
        Value::Null => RedactedValue::Null,
        Value::Bool(b) => RedactedValue::Bool { value: *b },
        Value::Number(n) => RedactedValue::Number {
            value: n.as_f64().unwrap_or(f64::NAN),
        },
        Value::String(s) => RedactedValue::Text { value: s.clone() },
        Value::Array(items) => RedactedValue::List {
            values: items
                .iter()
                .map(|v| scalar_text(v).unwrap_or_else(|| "<object>".to_owned()))
                .collect(),
        },
        Value::Object(map) => RedactedValue::Keys {
            keys: map.keys().cloned().collect(),
        },
    }
}

/// Formats one key-path segment: identifiers are bare, anything else is
/// quoted in brackets (`projects["/Users/you/proj"]`).
#[must_use]
pub fn key_segment(key: &str) -> String {
    let bare = !key.is_empty()
        && !key.as_bytes()[0].is_ascii_digit()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if bare {
        key.to_owned()
    } else {
        format!("[{}]", Value::String(key.to_owned()))
    }
}

/// Joins a key-path prefix and a key.
#[must_use]
pub fn join_key(prefix: &str, key: &str) -> String {
    let segment = key_segment(key);
    if prefix.is_empty() {
        segment
    } else if segment.starts_with('[') {
        format!("{prefix}{segment}")
    } else {
        format!("{prefix}.{segment}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_paths_quote_non_identifiers() {
        assert_eq!(join_key("", "env"), "env");
        assert_eq!(join_key("permissions", "allow"), "permissions.allow");
        assert_eq!(
            join_key("projects", "/Users/you/proj"),
            r#"projects["/Users/you/proj"]"#
        );
        assert_eq!(
            join_key(r#"projects["/x"]"#, "trust_level"),
            r#"projects["/x"].trust_level"#
        );
    }

    #[test]
    fn redaction_keeps_scalars_lists_and_key_names_only() {
        assert_eq!(redact(&json!(true)), RedactedValue::Bool { value: true });
        assert_eq!(
            redact(&json!(["a", 1, null])),
            RedactedValue::List {
                values: vec!["a".into(), "1".into(), "null".into()]
            }
        );
        assert_eq!(
            redact(&json!({"OPENAI_API_KEY": "sk-secret", "B": 1})),
            RedactedValue::Keys {
                keys: vec!["B".into(), "OPENAI_API_KEY".into()]
            }
        );
    }

    #[test]
    fn string_list_accepts_a_single_string() {
        assert_eq!(string_list(&json!("x")), vec!["x"]);
        assert_eq!(string_list(&json!(["x", 2, "y"])), vec!["x", "y"]);
        assert!(string_list(&json!(3)).is_empty());
    }
}
