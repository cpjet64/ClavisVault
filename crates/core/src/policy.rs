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
    if rule.require_tags && !entry.tags.iter().any(|tag| !tag.trim().is_empty()) {
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
        let age_anchor = if let Some(last_rotated) = entry.last_rotated_at {
            last_rotated
        } else if entry.created_at.timestamp() != 0 {
            entry.created_at
        } else {
            entry.last_updated
        };
        let age_days = (now - age_anchor).num_days();
        if age_days > max_age_days {
            out.push(PolicyViolation {
                key: entry.name.clone(),
                code: "max_age_exceeded".to_string(),
                message: format!(
                    "key age {age_days}d exceeds policy max of {max_age_days}d (age anchor: rotation/creation time)"
                ),
            });
        }
    }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let mut segments: Vec<&str> = pattern.split('*').collect();
    if starts_with_wildcard {
        while let Some(first) = segments.first() {
            if first.is_empty() {
                let _ = segments.remove(0);
            } else {
                break;
            }
        }
    }

    let mut tail = value;

    if starts_with_wildcard {
        if let Some(first) = segments.first().filter(|value| !value.is_empty()) {
            if let Some(pos) = tail.find(first) {
                tail = &tail[pos + first.len()..];
                let _ = segments.remove(0);
            } else {
                return false;
            }
        }
    } else if let Some(prefix) = segments.first() {
        if prefix.is_empty() || !tail.starts_with(prefix) {
            return false;
        }
        tail = &tail[prefix.len()..];
        let _ = segments.remove(0);
    }

    let end_anchor = if ends_with_wildcard {
        None
    } else {
        while let Some(last) = segments.last() {
            if !last.is_empty() {
                break;
            }
            segments.pop();
        }
        segments.pop()
    };

    for segment in segments {
        if segment.is_empty() {
            continue;
        }
        if let Some(pos) = tail.find(segment) {
            tail = &tail[pos + segment.len()..];
        } else {
            return false;
        }
    }

    match end_anchor {
        Some(end) => tail.ends_with(end),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    use super::{SecretPolicy, SecretPolicyRule, pattern_matches, validate_vault_policy};
    use crate::types::{KeyEntry, VaultData};

    fn key_entry(
        name: &str,
        tags: Vec<String>,
        created_at_days_ago: i64,
        last_updated_days_ago: i64,
        last_rotated_days_ago: Option<i64>,
    ) -> KeyEntry {
        let now = Utc::now();
        KeyEntry {
            name: name.to_string(),
            description: "desc".to_string(),
            tags,
            last_updated: now - Duration::days(last_updated_days_ago),
            created_at: now - Duration::days(created_at_days_ago),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: last_rotated_days_ago.map(|d| now - Duration::days(d)),
            owner: Some("team-security".to_string()),
            secret: Some("secret-value".to_string()),
        }
    }

    #[test]
    fn require_tags_rejects_whitespace_only_tags() {
        let mut keys = HashMap::new();
        keys.insert(
            "API_KEY".to_string(),
            key_entry(
                "API_KEY",
                vec!["   ".to_string(), "\t".to_string()],
                1,
                1,
                Some(1),
            ),
        );
        let vault = VaultData {
            version: 2,
            salt: [1u8; 16],
            keys,
        };
        let policy = SecretPolicy {
            default_rotation_period_days: None,
            default_warn_before_days: None,
            rules: vec![SecretPolicyRule {
                pattern: "*".to_string(),
                require_description: false,
                require_tags: true,
                require_owner: false,
                require_expiry: false,
                max_age_days: None,
            }],
        };

        let violations = validate_vault_policy(&vault, &policy, Utc::now());
        assert!(violations.iter().any(|v| v.code == "missing_tags"));
    }

    #[test]
    fn max_age_uses_rotation_or_creation_anchor_not_last_updated() {
        let mut keys = HashMap::new();
        keys.insert(
            "OLD_SECRET".to_string(),
            key_entry("OLD_SECRET", vec!["prod".to_string()], 40, 0, Some(40)),
        );
        let vault = VaultData {
            version: 2,
            salt: [2u8; 16],
            keys,
        };
        let policy = SecretPolicy {
            default_rotation_period_days: None,
            default_warn_before_days: None,
            rules: vec![SecretPolicyRule {
                pattern: "*".to_string(),
                require_description: false,
                require_tags: false,
                require_owner: false,
                require_expiry: false,
                max_age_days: Some(7),
            }],
        };

        let violations = validate_vault_policy(&vault, &policy, Utc::now());
        assert!(
            violations.iter().any(|v| v.code == "max_age_exceeded"),
            "policy should evaluate age from rotation/creation anchor rather than metadata update time"
        );
    }

    #[test]
    fn pattern_matches_handles_anchored_and_wildcard_forms() {
        assert!(pattern_matches("*", "OPENAI_API_KEY"));
        assert!(pattern_matches("OPENAI_*", "OPENAI_API_KEY"));
        assert!(pattern_matches("*_API_KEY", "OPENAI_API_KEY"));
        assert!(pattern_matches("OPENAI*KEY", "OPENAI_API_KEY"));
        assert!(!pattern_matches("GITHUB_*", "OPENAI_API_KEY"));
        assert!(!pattern_matches("OPENAI_API_KEY", "OPENAI_TOKEN"));
    }

    #[test]
    fn pattern_matches_is_utf8_safe_for_multibyte_values() {
        let value = "🔒secret🧪";
        assert!(pattern_matches("🔒*🧪", value));
        assert!(pattern_matches("*secret*", value));
        assert!(pattern_matches("🔒secret🧪", value));
        assert!(!pattern_matches("*💥", value));
    }

    #[test]
    fn pattern_matches_handles_empty_and_mixed_asterisks() {
        assert!(pattern_matches("", ""));
        assert!(!pattern_matches("", "x"));
        assert!(pattern_matches("🔒**🧪", "🔒abc🧪"));
        assert!(!pattern_matches("🔒**🧪", "abc🔒"));
    }

    #[test]
    fn pattern_matches_requires_segment_order() {
        assert!(pattern_matches("A*B*C", "AxxByyC"));
        assert!(!pattern_matches("A*B*C", "AxxCyyB"));
        assert!(!pattern_matches("A*B*C", "AxxB"));
    }
}
