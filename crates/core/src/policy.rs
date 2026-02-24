use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{KeyEntry, VaultData};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecretPolicy {
    #[serde(default)]
    pub default_rotation_period_days: Option<u32>,
    #[serde(default)]
    pub default_warn_before_days: Option<u32>,
    #[serde(default)]
    pub rules: Vec<SecretPolicyRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecretPolicyRule {
    pub pattern: String,
    #[serde(default)]
    pub require_description: bool,
    #[serde(default)]
    pub require_tags: bool,
    #[serde(default)]
    pub require_owner: bool,
    #[serde(default)]
    pub require_expiry: bool,
    #[serde(default)]
    pub max_age_days: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyViolation {
    pub key: String,
    pub code: String,
    pub message: String,
}

pub fn load_policy(path: &Path) -> Result<SecretPolicy> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading policy file {}", path.display()))?;
    let policy = toml::from_str::<SecretPolicy>(&content)
        .with_context(|| format!("failed parsing policy file {}", path.display()))?;
    Ok(policy)
}

pub fn validate_vault_policy(
    vault: &VaultData,
    policy: &SecretPolicy,
    now: DateTime<Utc>,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    for entry in vault.keys.values() {
        let matching = policy
            .rules
            .iter()
            .filter(|rule| pattern_matches(&rule.pattern, &entry.name));
        for rule in matching {
            validate_rule(rule, entry, now, &mut violations);
        }
    }
    violations
}

fn validate_rule(
    rule: &SecretPolicyRule,
    entry: &KeyEntry,
    now: DateTime<Utc>,
    out: &mut Vec<PolicyViolation>,
) {
    if rule.require_description && entry.description.trim().is_empty() {
        out.push(PolicyViolation {
            key: entry.name.clone(),
            code: "missing_description".to_string(),
            message: "description is required by policy".to_string(),
        });
    }
    if rule.require_tags && entry.tags.is_empty() {
        out.push(PolicyViolation {
            key: entry.name.clone(),
            code: "missing_tags".to_string(),
            message: "at least one tag is required by policy".to_string(),
        });
    }
    if rule.require_owner
        && entry
            .owner
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        out.push(PolicyViolation {
            key: entry.name.clone(),
            code: "missing_owner".to_string(),
            message: "owner is required by policy".to_string(),
        });
    }
    if rule.require_expiry && entry.expires_at.is_none() {
        out.push(PolicyViolation {
            key: entry.name.clone(),
            code: "missing_expiry".to_string(),
            message: "expiry is required by policy".to_string(),
        });
    }
    if let Some(max_age_days) = rule.max_age_days {
        let age_days = (now - entry.last_updated).num_days();
        if age_days > max_age_days {
            out.push(PolicyViolation {
                key: entry.name.clone(),
                code: "max_age_exceeded".to_string(),
                message: format!("key age {age_days}d exceeds policy max of {max_age_days}d"),
            });
        }
    }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return true;
    }
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut cursor = 0usize;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 && anchored_start {
            if !value[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
            continue;
        }
        if i == parts.len() - 1 && anchored_end {
            return value[cursor..].ends_with(part);
        }
        if let Some(pos) = value[cursor..].find(part) {
            cursor += pos + part.len();
        } else {
            return false;
        }
    }
    true
}
