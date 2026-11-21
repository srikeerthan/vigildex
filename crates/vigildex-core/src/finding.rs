//! Findings: what the SEC, BILL and RISK rules report (`docs/RULES.md`).
//!
//! Every type derives `serde` and `schemars::JsonSchema`: findings are part
//! of the `--json` contract. Evidence is masked before it reaches a
//! [`Finding`]; nothing in a finding derives from a secret's value.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::Agent;
pub use crate::observe::Location;

/// How much a finding matters. Ordered from most to least severe, so
/// `High < Low` in the `Ord` sense and lists sort High first. The four
/// levels are fixed by `docs/RULES.md`; the enum is still non-exhaustive
/// like every other public enum of the contract.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    /// Likely costs money, leaks a credential, or runs untrusted code.
    High,
    /// Risky default or exposure worth fixing soon.
    Medium,
    /// Hygiene; worth knowing.
    Low,
    /// Neutral inventory fact.
    Info,
}

impl Severity {
    /// The severity one step higher (pre-flight bump), capped at High.
    #[must_use]
    pub fn bumped(self) -> Self {
        match self {
            Self::High | Self::Medium => Self::High,
            Self::Low => Self::Medium,
            Self::Info => Self::Low,
            #[allow(unreachable_patterns, reason = "Severity is non-exhaustive")]
            _ => self,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
            #[allow(unreachable_patterns, reason = "Severity is non-exhaustive")]
            _ => "Other",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// The rule family a finding belongs to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Category {
    /// `SEC-`: a credential in plain text.
    Secret,
    /// `BILL-`: a billing trap.
    Billing,
    /// `RISK-`: a risky setting.
    Risk,
}

impl Category {
    /// The category of a rule ID by its prefix.
    #[must_use]
    pub fn of_rule(rule: &str) -> Option<Self> {
        if rule.starts_with("SEC-") {
            Some(Self::Secret)
        } else if rule.starts_with("BILL-") {
            Some(Self::Billing)
        } else if rule.starts_with("RISK-") {
            Some(Self::Risk)
        } else {
            None
        }
    }
}

/// How to fix a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct FixSteps {
    /// One line, shown in the list.
    pub summary: String,
    /// Steps in order, copyable; commands are written as the user would
    /// type them.
    pub steps: Vec<String>,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct Finding {
    /// Stable identifier: a hash of the rule and the location, relative to
    /// the home, so it survives rescans and moves between machines.
    pub id: String,
    /// The rule ID (`SEC-004`).
    pub rule: String,
    /// The rule family.
    pub category: Category,
    /// Catalogue severity.
    pub severity: Severity,
    /// The list title (`GitHub token in plain text`).
    pub title: String,
    /// One sentence on why it matters.
    pub why: String,
    /// Where it is.
    pub location: Location,
    /// Masked evidence (`ghp_••••f9a`, `approval_policy = "never"`), when
    /// there is something to show.
    pub evidence: Option<String>,
    /// Keyed fingerprint of the secret, for secret findings only. Always
    /// `null` until a store with a per-installation key exists (M4): the
    /// engine computes no digest of a secret before then, because a hash
    /// under a public constant would let anyone holding a report confirm a
    /// guessed password offline.
    pub fingerprint: Option<String>,
    /// How to fix it.
    pub fix: FixSteps,
    /// The agents affected.
    pub agents: Vec<Agent>,
    /// Identifiers of the inventory items involved.
    pub items: Vec<String>,
    /// Rule IDs that also matched this location but lost the tie
    /// (finding policy 1), and notes such as `repo_file`.
    pub tags: Vec<String>,
}

/// Counts per severity, for summaries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct SeverityCounts {
    /// High findings.
    pub high: usize,
    /// Medium findings.
    pub medium: usize,
    /// Low findings.
    pub low: usize,
    /// Info findings.
    pub info: usize,
}

impl SeverityCounts {
    /// Counts the findings in a list.
    #[must_use]
    pub fn of(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
                #[allow(unreachable_patterns, reason = "Severity is non-exhaustive")]
                _ => {}
            }
        }
        counts
    }

    /// Every finding.
    #[must_use]
    pub fn total(self) -> usize {
        self.high + self.medium + self.low + self.info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_sort_high_first() {
        let mut list = [
            Severity::Low,
            Severity::High,
            Severity::Info,
            Severity::Medium,
        ];
        list.sort();
        assert_eq!(
            list,
            [
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info
            ]
        );
        assert_eq!(Severity::Low.bumped(), Severity::Medium);
        assert_eq!(Severity::High.bumped(), Severity::High);
    }

    #[test]
    fn categories_follow_the_rule_prefix() {
        assert_eq!(Category::of_rule("SEC-001"), Some(Category::Secret));
        assert_eq!(Category::of_rule("BILL-006"), Some(Category::Billing));
        assert_eq!(Category::of_rule("RISK-004"), Some(Category::Risk));
        assert_eq!(Category::of_rule("CHG-001"), None);
    }
}
