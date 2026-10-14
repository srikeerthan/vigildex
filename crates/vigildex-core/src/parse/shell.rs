//! Variable assignments in shell profiles (`.zshrc`, `.bashrc`, `.envrc`) and
//! dotenv files (`.env`).
//!
//! Only `NAME=value` and `export NAME=value` lines count, with the line
//! number kept for findings. Nothing is evaluated: a quoted value ends at its
//! closing quote, an unquoted one at the first whitespace or comment, and a
//! command substitution (`$(…)`, backticks) is kept whole so the caller can
//! classify it as dynamic. Comments, functions, conditionals and compound
//! lines (`[ -f x ] && export …`) are ignored.

/// One assignment, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The variable name.
    pub name: String,
    /// The raw value, quotes removed. Callers must not keep it.
    pub value: String,
    /// 1-based line number.
    pub line: u32,
    /// Whether the line used `export`.
    pub exported: bool,
}

/// Every assignment in `text`, in order.
#[must_use]
pub fn assignments(text: &str) -> Vec<Assignment> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let Some(assignment) = parse_line(raw, u32::try_from(index + 1).unwrap_or(u32::MAX)) else {
            continue;
        };
        out.push(assignment);
    }
    out
}

fn parse_line(raw: &str, line: u32) -> Option<Assignment> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (exported, rest) = match strip_word(trimmed, "export") {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };
    let name_end = rest
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))?;
    let name = &rest[..name_end];
    if name.is_empty() || name.as_bytes()[0].is_ascii_digit() {
        return None;
    }
    let after = &rest[name_end..];
    let value = after.strip_prefix('=')?;
    Some(Assignment {
        name: name.to_owned(),
        value: value_of(value),
        line,
        exported,
    })
}

/// `word` followed by whitespace, with the whitespace removed.
fn strip_word<'a>(text: &'a str, word: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(word)?;
    if rest.starts_with([' ', '\t']) {
        Some(rest.trim_start())
    } else {
        None
    }
}

/// The value part of an assignment: quotes removed, cut at the first
/// unquoted whitespace or comment, with `$(…)` and backtick substitutions
/// kept whole.
fn value_of(text: &str) -> String {
    let text = text.trim_start();
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                let mut escaped = false;
                for inner in chars.by_ref() {
                    if escaped {
                        out.push(inner);
                        escaped = false;
                    } else if inner == '\\' {
                        escaped = true;
                    } else if inner == '"' {
                        break;
                    } else {
                        out.push(inner);
                    }
                }
            }
            '\'' => {
                for inner in chars.by_ref() {
                    if inner == '\'' {
                        break;
                    }
                    out.push(inner);
                }
            }
            '$' if chars.peek() == Some(&'(') => {
                out.push('$');
                let mut depth = 0u32;
                for inner in chars.by_ref() {
                    out.push(inner);
                    match inner {
                        '(' => depth += 1,
                        ')' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            '`' => {
                out.push('`');
                for inner in chars.by_ref() {
                    out.push(inner);
                    if inner == '`' {
                        break;
                    }
                }
            }
            ' ' | '\t' | ';' | '#' => break,
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<(String, u32, bool)> {
        assignments(text)
            .into_iter()
            .map(|a| (a.name, a.line, a.exported))
            .collect()
    }

    #[test]
    fn exports_and_plain_assignments_with_line_numbers() {
        let text = "# comment\nexport A=1\nB='two words'\n\nexport C=\"three # not a comment\" # trailing\nD=4 # comment\n";
        let found = assignments(text);
        assert_eq!(
            names(text),
            vec![
                ("A".to_owned(), 2, true),
                ("B".to_owned(), 3, false),
                ("C".to_owned(), 5, true),
                ("D".to_owned(), 6, false),
            ]
        );
        assert_eq!(found[1].value, "two words");
        assert_eq!(found[2].value, "three # not a comment");
        assert_eq!(found[3].value, "4");
    }

    #[test]
    fn substitutions_are_kept_whole_and_other_lines_are_ignored() {
        let text = "export GITHUB_TOKEN=\"$(op read 'op://Private/GitHub/token')\"\nexport GEMINI_API_KEY=$(security find-generic-password -s gemini -w)\nX=`cat f`\nalias ll='ls -la'\nmkcd() { mkdir -p \"$1\"; }\n[ -f x ] && export Y=1\nexportZ=1\n1BAD=2\nPATH=\"$HOME/.local/bin:$PATH\"\n";
        let found = assignments(text);
        let values: Vec<&str> = found.iter().map(|a| a.value.as_str()).collect();
        assert_eq!(
            values,
            vec![
                "$(op read 'op://Private/GitHub/token')",
                "$(security find-generic-password -s gemini -w)",
                "`cat f`",
                "1",
                "$HOME/.local/bin:$PATH",
            ]
        );
        // `exportZ=1` is a plain assignment to a variable called `exportZ`.
        assert_eq!(found[3].name, "exportZ");
        assert!(!found[3].exported);
        assert_eq!(found[4].name, "PATH");
        assert_eq!(found[4].line, 9);
    }

    #[test]
    fn dotenv_lines_without_export() {
        let text = "DATABASE_URL=postgresql://app:pw@db:5432/acme\nPORT=8080\nexport RUST_LOG=debug\nEMPTY=\n";
        let found = assignments(text);
        assert_eq!(found.len(), 4);
        assert_eq!(found[0].value, "postgresql://app:pw@db:5432/acme");
        assert!(!found[0].exported);
        assert!(found[2].exported);
        assert_eq!(found[3].value, "");
    }

    #[test]
    fn escaped_quotes_inside_double_quotes() {
        let found = assignments("A=\"say \\\"hi\\\"\"\n");
        assert_eq!(found[0].value, "say \"hi\"");
    }
}
