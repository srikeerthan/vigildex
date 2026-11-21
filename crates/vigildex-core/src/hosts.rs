//! Vendor API hosts (`rules/hosts.toml`) and the host checks behind BILL-006
//! and RISK-003.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::Value;

use crate::parse::json::string_list_at;

const HOSTS_FILE: &str = include_str!("../rules/hosts.toml");

/// Hosts per vendor, as listed in `rules/hosts.toml`.
#[derive(Debug, Default)]
pub struct Hosts {
    vendors: BTreeMap<String, Vec<String>>,
    /// Problems loading the file, one message each.
    pub warnings: Vec<String>,
}

impl Hosts {
    fn load(text: &str) -> Self {
        let mut hosts = Self::default();
        let doc = match crate::parse::toml::to_json(text) {
            Ok(doc) => doc,
            Err(err) => {
                hosts
                    .warnings
                    .push(format!("rules/hosts.toml: not valid TOML: {err}"));
                return hosts;
            }
        };
        let Some(map) = doc.as_object() else {
            hosts
                .warnings
                .push("rules/hosts.toml: not a table".to_owned());
            return hosts;
        };
        for (vendor, entry) in map {
            if entry.get("hosts").is_some_and(Value::is_array) {
                let list: Vec<String> = string_list_at(entry, "hosts")
                    .iter()
                    .map(|h| h.to_ascii_lowercase())
                    .collect();
                hosts.vendors.insert(vendor.clone(), list);
            } else {
                hosts
                    .warnings
                    .push(format!("rules/hosts.toml: [{vendor}] has no hosts list"));
            }
        }
        hosts
    }

    /// Whether `vendor` lists `host` (exactly, or through a `*.domain`
    /// pattern). An unknown vendor lists nothing.
    #[must_use]
    pub fn allows(&self, vendor: &str, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.vendors
            .get(vendor)
            .is_some_and(|list| list.iter().any(|pattern| host_matches(pattern, &host)))
    }

    /// The vendors the file names.
    #[must_use]
    pub fn vendors(&self) -> Vec<&str> {
        self.vendors.keys().map(String::as_str).collect()
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
        None => pattern == host,
    }
}

/// The vendor hosts, loaded on first use.
pub fn hosts() -> &'static Hosts {
    static HOSTS: OnceLock<Hosts> = OnceLock::new();
    HOSTS.get_or_init(|| Hosts::load(HOSTS_FILE))
}

/// The host of a URL, lower-cased, without port, user information or
/// brackets. `None` when the text is not a URL.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        host_port.rsplit_once(':').map_or(host_port, |(h, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                host_port
            }
        })
    };
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// The origin of a URL, `scheme://host[:port]`, lower-cased, without user
/// information, path or query. `None` when the text is not a URL.
#[must_use]
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return None;
    }
    let host = host_of(url)?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let port = if host_port.starts_with('[') {
        host_port.rsplit_once("]:").map(|(_, p)| p)
    } else {
        host_port
            .rsplit_once(':')
            .filter(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .map(|(_, p)| p)
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Some(match port {
        Some(port) => format!("{}://{host}:{port}", scheme.to_ascii_lowercase()),
        None => format!("{}://{host}", scheme.to_ascii_lowercase()),
    })
}

/// Whether a host is the local machine: `localhost`, `*.localhost`,
/// `127.0.0.0/8`, `::1` or `0.0.0.0`.
#[must_use]
pub fn is_loopback(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host == "::1"
        || host == "0.0.0.0"
        || host == "0:0:0:0:0:0:0:1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vendored_file_loads() {
        let h = hosts();
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);
        assert!(h.allows("anthropic", "api.anthropic.com"));
        assert!(h.allows("anthropic", "API.Anthropic.com"));
        assert!(h.allows("anthropic", "eu.anthropic.com"));
        assert!(!h.allows("anthropic", "anthropic.com.evil.example"));
        assert!(!h.allows("anthropic", "llm-proxy.acme-corp.example"));
        assert!(h.allows("openai", "api.openai.com"));
        assert!(h.allows("openai", "acme.openai.azure.com"));
        assert!(!h.allows("copilot_provider", "api.openai.com"));
        assert!(!h.allows("nobody", "api.openai.com"));
    }

    #[test]
    fn suffix_patterns_need_a_dot_and_a_label() {
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "aexample.com"));
        assert!(host_matches("example.com", "example.com"));
    }

    #[test]
    fn hosts_are_extracted_from_urls() {
        assert_eq!(
            host_of("https://api.anthropic.com/v1").as_deref(),
            Some("api.anthropic.com")
        );
        assert_eq!(
            host_of("http://LOCALHOST:11434/v1").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            host_of("https://u:p@Proxy.Example:8443/x?y").as_deref(),
            Some("proxy.example")
        );
        assert_eq!(host_of("http://[::1]:8080/").as_deref(), Some("::1"));
        assert_eq!(host_of("not a url"), None);
        assert_eq!(host_of("${BASE}/v1"), None);
    }

    #[test]
    fn origins_drop_everything_but_scheme_host_and_port() {
        assert_eq!(
            origin_of("https://u:pw@Proxy.Example:8443/x?y#z").as_deref(),
            Some("https://proxy.example:8443")
        );
        assert_eq!(
            origin_of("http://localhost:11434/v1").as_deref(),
            Some("http://localhost:11434")
        );
        assert_eq!(
            origin_of("https://api.anthropic.com").as_deref(),
            Some("https://api.anthropic.com")
        );
        assert_eq!(
            origin_of("http://[::1]:8080/").as_deref(),
            Some("http://[::1]:8080")
        );
        assert_eq!(origin_of("${BASE}/v1"), None);
        assert_eq!(origin_of("not a url"), None);
    }

    #[test]
    fn loopback_hosts() {
        assert!(is_loopback("localhost"));
        assert!(is_loopback("api.localhost"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.1.2.3"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("0.0.0.0"));
        assert!(!is_loopback("10.0.0.1"));
        assert!(!is_loopback("localhost.example.com"));
        assert!(!is_loopback("llm-proxy.acme-corp.example"));
    }
}
