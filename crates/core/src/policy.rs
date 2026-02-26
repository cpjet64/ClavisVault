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

#[cfg_attr(test, inline(never))]
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
        if !tail.starts_with(prefix) {
            return false;
        }
        tail = &tail[prefix.len()..];
        let _ = segments.remove(0);
    }

    let end_anchor = if ends_with_wildcard {
        None
    } else {
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
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        SecretPolicy, SecretPolicyRule, load_policy, pattern_matches, validate_vault_policy,
    };
    use crate::types::{KeyEntry, VaultData};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-core-{name}-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir creation should work");
        path
    }

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
    fn load_policy_reads_file() {
        let dir = temp_dir("policy-load-success");
        let policy_path = dir.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
defaultRotationPeriodDays = 42
defaultWarnBeforeDays = 14

[[rules]]
pattern = "API_*"
require_description = true
require_tags = true
require_owner = false
require_expiry = false
max_age_days = 30
"#,
        )
        .expect("seed policy file should write");

        let policy = load_policy(&policy_path).expect("policy should load");
        assert_eq!(policy.default_rotation_period_days, Some(42));
        assert_eq!(policy.default_warn_before_days, Some(14));
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].pattern, "API_*");
    }

    #[test]
    fn load_policy_reports_missing_file() {
        let dir = temp_dir("policy-load-missing");
        let missing = dir.join("missing.toml");

        let err = load_policy(&missing).expect_err("load should fail for missing file");
        assert!(err.to_string().contains("failed reading policy file"));
    }

    #[test]
    fn load_policy_reports_toml_parse_error() {
        let dir = temp_dir("policy-load-parse-error");
        let policy_path = dir.join("bad-policy.toml");
        fs::write(&policy_path, "this isn't toml").expect("seed invalid toml policy should write");

        let err = load_policy(&policy_path).expect_err("load should fail for malformed toml");
        assert!(err.to_string().contains("failed parsing policy file"));
    }

    #[test]
    fn validate_rule_checks_missing_description_owner_and_expiry() {
        let mut keys = HashMap::new();
        keys.insert(
            "CREDS".to_string(),
            KeyEntry {
                name: "CREDS".to_string(),
                description: "".to_string(),
                tags: vec!["".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: None,
                secret: Some("value".to_string()),
            },
        );
        let vault = VaultData {
            version: 2,
            salt: [3u8; 16],
            keys,
        };
        let policy = SecretPolicy {
            default_rotation_period_days: None,
            default_warn_before_days: None,
            rules: vec![SecretPolicyRule {
                pattern: "C*".to_string(),
                require_description: true,
                require_tags: false,
                require_owner: true,
                require_expiry: true,
                max_age_days: None,
            }],
        };

        let violations = validate_vault_policy(&vault, &policy, Utc::now());
        let codes: Vec<_> = violations.into_iter().map(|v| v.code).collect();
        assert!(codes.contains(&"missing_description".to_string()));
        assert!(codes.contains(&"missing_owner".to_string()));
        assert!(codes.contains(&"missing_expiry".to_string()));
    }

    #[test]
    fn validate_rule_uses_creation_anchor_when_last_rotated_is_missing() {
        let mut keys = HashMap::new();
        let now = Utc::now();
        keys.insert(
            "ROTATION".to_string(),
            KeyEntry {
                name: "ROTATION".to_string(),
                description: "secret".to_string(),
                tags: vec!["ops".to_string()],
                last_updated: now - Duration::days(3),
                created_at: now - Duration::days(40),
                expires_at: Some(now - Duration::days(1)),
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: None,
                owner: Some("team".to_string()),
                secret: Some("token".to_string()),
            },
        );
        let vault = VaultData {
            version: 2,
            salt: [4u8; 16],
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
        let violations = validate_vault_policy(&vault, &policy, now);
        assert!(violations.iter().any(|v| v.code == "max_age_exceeded"));
    }

    #[test]
    fn pattern_matches_exact_match_is_true_for_non_wildcard_pattern() {
        assert!(pattern_matches("EXACT", "EXACT"));
        assert!(!pattern_matches("exact", "EXACT"));
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
    fn validate_rule_uses_last_updated_anchor_when_created_timestamp_is_zero() {
        let now = Utc::now();
        let mut keys = HashMap::new();
        keys.insert(
            "ANCHOR".to_string(),
            KeyEntry {
                name: "ANCHOR".to_string(),
                description: "valid".to_string(),
                tags: vec!["prod".to_string()],
                last_updated: now - chrono::Duration::days(15),
                created_at: chrono::DateTime::from_timestamp(0, 0)
                    .expect("epoch timestamp is valid"),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: None,
                owner: Some("team".to_string()),
                secret: Some("value".to_string()),
            },
        );
        let vault = VaultData {
            version: 2,
            salt: [11u8; 16],
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

        let violations = validate_vault_policy(&vault, &policy, now);
        assert!(violations.iter().any(|v| v.code == "max_age_exceeded"));
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

    #[test]
    fn pattern_matches_skips_empty_leading_and_trailing_wildcard_segments() {
        assert!(pattern_matches("**A**", "zzAyy"));
        assert!(pattern_matches("*A*", "A"));
        assert!(!pattern_matches("*A**", "B"));
    }

    #[test]
    fn pattern_matches_starts_with_wildcard_requires_first_segment_match() {
        assert!(!pattern_matches("*TOKEN", "OPENAI_API_KEY"));
    }

    #[test]
    fn pattern_matches_handles_consecutive_wildcards_and_empty_internal_segments() {
        assert!(pattern_matches("OPENAI**KEY", "OPENAI--SUPER--KEY"));
        assert!(pattern_matches("OPENAI***_KEY", "OPENAI----_KEY"));
        assert!(!pattern_matches("OPENAI**MISSING", "OPENAI--TOKEN"));
    }

    #[test]
    fn pattern_matches_starts_with_multiple_wildcards_and_skips_empty_prefixes() {
        assert!(pattern_matches("**SECRET**KEY", "PREFIX_SECRET_KEY"));
        assert!(!pattern_matches("**SECRET**", "prefix-secret"));
        assert!(!pattern_matches("**SECRET**", "prefix"));
    }

    #[test]
    fn pattern_matches_with_no_matching_mid_segment_rejects_early() {
        assert!(!pattern_matches("A*B*C", "A1X1C"));
        assert!(!pattern_matches("A**B**C", "A1C"));
    }

    #[test]
    fn pattern_matches_treats_only_wildcards_as_global_match() {
        assert!(pattern_matches("***", "ANY_VALUE"));
        assert!(pattern_matches("**", "12345"));
    }

    #[test]
    fn pattern_matches_skips_leading_wildcards_and_handles_missing_required_tail() {
        assert!(pattern_matches("**OPENAI", "OPENAI_API_KEY"));
        assert!(!pattern_matches("**OPENAI", "my-openai"));
        assert!(!pattern_matches("OPENAI*TOKEN", "OPENAI"));
        assert!(!pattern_matches("OPENAI*TOKEN", "OPENAI--TOKEN--END"));
    }

    #[test]
    fn pattern_matches_rejects_fixed_prefix_mismatch() {
        assert!(!pattern_matches("OPENAI_*", "GITHUB_TOKEN"));
    }

    #[test]
    fn pattern_matches_rejects_missing_segment_in_middle() {
        assert!(!pattern_matches("A*B*C", "AxxCyy"));
        assert!(!pattern_matches("A*B*B", "AxxByy"));
    }

    #[test]
    fn pattern_matches_handles_only_trailing_and_leading_wildcards_with_tail_rules() {
        assert!(pattern_matches("A*", "AXYZ"));
        assert!(!pattern_matches("A*", "BA"));
        assert!(pattern_matches("*Z", "AZ"));
        assert!(pattern_matches("*Z", "ZA"));
        assert!(pattern_matches("*Z", "AZA"));
    }

    #[test]
    fn pattern_matches_with_interior_wildcard_respects_tail_anchor() {
        assert!(pattern_matches("A*B", "A1B"));
        assert!(!pattern_matches("A*B", "A1B2"));
        assert!(!pattern_matches("A*B", "AB2"));
    }

    #[test]
    fn pattern_matches_handles_leading_wildcard_without_prefix() {
        assert!(pattern_matches("*SERVICE", "API_SERVICE"));
        assert!(pattern_matches("*SERVICE", "SERVICE"));
        assert!(pattern_matches("*_SERVICE", "API_SERVICE"));
        assert!(!pattern_matches("*_SERVICE", "SERVICE_TOKEN"));
    }

    #[test]
    fn pattern_matches_handles_missing_wildcard_segment_with_tail_anchor() {
        assert!(pattern_matches("A**B*", "AxyB"));
        assert!(pattern_matches("A**B*", "A--B--tail"));
        assert!(!pattern_matches("A**B*", "A--C"));
    }

    #[test]
    fn pattern_matches_empty_pattern_only_matches_empty_value() {
        assert!(pattern_matches("", ""));
        assert!(!pattern_matches("", "x"));
    }

    #[test]
    fn pattern_matches_pattern_star_is_global_match() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("**", ""));
    }

    #[test]
    fn pattern_matches_handles_leading_and_trailing_wildcards_together() {
        assert!(pattern_matches("*SERVICE*", "API_SERVICE"));
        assert!(pattern_matches("A**A*", "AANYA"));
        assert!(!pattern_matches("A**A*", "AONLY"));
    }

    #[test]
    fn pattern_matches_handles_trailing_global_segment_and_tail_mismatch() {
        assert!(pattern_matches("**TOKEN", "prefix_TOKEN"));
        assert!(!pattern_matches("**TOKEN", "token_prefix"));
        assert!(pattern_matches("A**", "A"));
        assert!(!pattern_matches("A**", "BA"));
    }

    #[test]
    fn pattern_matches_without_wildcards_falls_back_to_exact_match() {
        assert!(pattern_matches("EXACT", "EXACT"));
        assert!(!pattern_matches("EXACT", "EXACT_SUFFIX"));
        assert!(!pattern_matches("EXACT", ""));
    }

    #[test]
    fn pattern_matches_starts_with_wildcard_can_skip_implicit_prefix_segments() {
        assert!(pattern_matches("***SERVICE", "API_SERVICE"));
        assert!(!pattern_matches("*SERVICE", "OPENAI"));
    }

    #[test]
    fn pattern_matches_requires_prefix_match_without_wildcard_prefix() {
        assert!(pattern_matches("PROD_*", "PROD_KEY"));
        assert!(!pattern_matches("PROD_*", "DEV_PROD_KEY"));
    }

    #[test]
    fn pattern_matches_non_wildcard_prefix_branch_consumes_first_segment() {
        assert!(pattern_matches("prefix*tail", "prefix-anything-tail"));
        assert!(!pattern_matches("prefix*tail", "prefix-anything-nope"));
    }

    #[test]
    fn pattern_matches_starting_wildcard_without_first_segment_falls_back_to_tail_match() {
        assert!(pattern_matches("**TOKEN", "X_TOKEN"));
        assert!(pattern_matches("***TOKEN", "TOKEN"));
        assert!(!pattern_matches("**TOKEN", "TOK"));
    }

    #[test]
    fn pattern_matches_respects_trailing_wildcard_anchor_behavior() {
        assert!(pattern_matches("A*B*", "AxxB"));
        assert!(pattern_matches("A*B*", "AxxByy"));
        assert!(!pattern_matches("A*B*", "AxxC"));
    }

    #[test]
    fn pattern_matches_supports_redundant_wildcards_and_floating_segments() {
        assert!(pattern_matches("***TOKEN***VALUE", "MY_TOKEN__VALUE"));
        assert!(!pattern_matches("***TOKEN***VALUE", "TOKEN"));
        assert!(pattern_matches("A**B**C**", "A-anything-B-something-C"));
        assert!(!pattern_matches("A**B**C**", "A--C--"));
    }
}
