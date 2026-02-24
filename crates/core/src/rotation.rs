use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::types::VaultData;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RotationStatus {
    Healthy,
    Due,
    Expired,
    NoPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RotationFinding {
    pub name: String,
    pub status: RotationStatus,
    pub days_until_due: Option<i64>,
    pub expires_at: Option<DateTime<Utc>>,
    pub owner: Option<String>,
}

pub fn list_rotation_findings(vault: &VaultData, now: DateTime<Utc>) -> Vec<RotationFinding> {
    let mut findings = Vec::with_capacity(vault.keys.len());
    for entry in vault.keys.values() {
        if let Some(expires_at) = entry.expires_at {
            let days_until_due = (expires_at - now).num_days();
            let status = if expires_at <= now {
                RotationStatus::Expired
            } else if days_until_due <= i64::from(entry.warn_before_days.unwrap_or(14)) {
                RotationStatus::Due
            } else {
                RotationStatus::Healthy
            };
            findings.push(RotationFinding {
                name: entry.name.clone(),
                status,
                days_until_due: Some(days_until_due),
                expires_at: Some(expires_at),
                owner: entry.owner.clone(),
            });
            continue;
        }

        if let Some(period_days) = entry.rotation_period_days {
            let last = entry.last_rotated_at.unwrap_or(entry.last_updated);
            let due = last + Duration::days(i64::from(period_days));
            let days_until_due = (due - now).num_days();
            let warn_days = i64::from(entry.warn_before_days.unwrap_or(14));
            let status = if due <= now {
                RotationStatus::Expired
            } else if days_until_due <= warn_days {
                RotationStatus::Due
            } else {
                RotationStatus::Healthy
            };
            findings.push(RotationFinding {
                name: entry.name.clone(),
                status,
                days_until_due: Some(days_until_due),
                expires_at: Some(due),
                owner: entry.owner.clone(),
            });
            continue;
        }

        findings.push(RotationFinding {
            name: entry.name.clone(),
            status: RotationStatus::NoPolicy,
            days_until_due: None,
            expires_at: None,
            owner: entry.owner.clone(),
        });
    }
    findings.sort_by(|a, b| a.name.cmp(&b.name));
    findings
}

pub fn rotate_key(
    vault: &mut VaultData,
    key_name: &str,
    new_secret: Option<String>,
    now: DateTime<Utc>,
) -> Result<()> {
    let Some(entry) = vault.keys.get_mut(key_name) else {
        bail!("key not found: {key_name}");
    };
    entry.last_updated = now;
    entry.last_rotated_at = Some(now);
    if new_secret.is_some() {
        entry.secret = new_secret;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    use crate::types::KeyEntry;

    struct KeyEntryInput<'a> {
        name: &'a str,
        expires_at: Option<DateTime<Utc>>,
        rotation_period_days: Option<u32>,
        last_rotated_at: Option<DateTime<Utc>>,
        last_updated: DateTime<Utc>,
        warn_before_days: Option<u32>,
        secret: Option<&'a str>,
        owner: Option<&'a str>,
    }

    fn key_entry(input: KeyEntryInput<'_>) -> KeyEntry {
        KeyEntry {
            name: input.name.to_string(),
            description: "test secret".to_string(),
            tags: vec!["coverage".to_string()],
            last_updated: input.last_updated,
            created_at: Utc::now(),
            expires_at: input.expires_at,
            rotation_period_days: input.rotation_period_days,
            warn_before_days: input.warn_before_days,
            last_rotated_at: input.last_rotated_at,
            owner: input.owner.map(str::to_string),
            secret: input.secret.map(str::to_string),
        }
    }

    #[test]
    fn list_rotation_findings_reports_policy_states_and_sorting() {
        let now = Utc::now();
        let mut vault = VaultData {
            version: 2,
            salt: [0; 16],
            keys: HashMap::new(),
        };

        vault.keys.insert(
            "ROTATE_Y".to_string(),
            key_entry(KeyEntryInput {
                name: "ROTATE_Y",
                expires_at: None,
                rotation_period_days: Some(90),
                last_rotated_at: Some(now - Duration::days(89)),
                last_updated: now,
                warn_before_days: Some(1),
                secret: Some("old"),
                owner: Some("owner-y"),
            }),
        );
        vault.keys.insert(
            "ROTATE_X".to_string(),
            key_entry(KeyEntryInput {
                name: "ROTATE_X",
                expires_at: Some(now + Duration::days(14)),
                rotation_period_days: None,
                last_rotated_at: None,
                last_updated: now - Duration::days(1),
                warn_before_days: Some(5),
                secret: Some("new"),
                owner: None,
            }),
        );
        vault.keys.insert(
            "ROTATE_Z".to_string(),
            key_entry(KeyEntryInput {
                name: "ROTATE_Z",
                expires_at: Some(now - Duration::days(1)),
                rotation_period_days: Some(30),
                last_rotated_at: Some(now - Duration::days(31)),
                last_updated: now,
                warn_before_days: Some(7),
                secret: None,
                owner: None,
            }),
        );
        vault.keys.insert(
            "ROTATE_NP".to_string(),
            key_entry(KeyEntryInput {
                name: "ROTATE_NP",
                expires_at: None,
                rotation_period_days: None,
                last_rotated_at: None,
                last_updated: now,
                warn_before_days: Some(7),
                secret: None,
                owner: None,
            }),
        );

        let findings = list_rotation_findings(&vault, now);

        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].name, "ROTATE_NP");
        assert!(matches!(findings[0].status, RotationStatus::NoPolicy));
        assert!(findings[1].days_until_due.is_some());
        assert_eq!(findings[1].name, "ROTATE_X");
        assert!(matches!(findings[1].status, RotationStatus::Healthy));
        assert_eq!(findings[2].name, "ROTATE_Y");
        assert!(matches!(findings[2].status, RotationStatus::Due));
        assert_eq!(findings[3].name, "ROTATE_Z");
        assert!(matches!(findings[3].status, RotationStatus::Expired));
    }

    #[test]
    fn rotate_key_updates_rotation_timestamp_and_secret() {
        let now = Utc::now();
        let mut vault = VaultData {
            version: 2,
            salt: [0; 16],
            keys: HashMap::new(),
        };
        vault.keys.insert(
            "MUTATE_ME".to_string(),
            key_entry(KeyEntryInput {
                name: "MUTATE_ME",
                expires_at: Some(now - Duration::days(10)),
                rotation_period_days: Some(30),
                last_rotated_at: Some(now - Duration::days(20)),
                last_updated: now - Duration::days(20),
                warn_before_days: Some(7),
                secret: Some("old"),
                owner: None,
            }),
        );

        rotate_key(&mut vault, "MUTATE_ME", Some("fresh".to_string()), now)
            .expect("rotate key should succeed");

        let rotated = vault.keys.get("MUTATE_ME").expect("key present");
        assert_eq!(rotated.last_updated, now);
        assert_eq!(rotated.last_rotated_at, Some(now));
        assert_eq!(rotated.secret, Some("fresh".to_string()));
    }

    #[test]
    fn rotate_key_rejects_unknown_key_name() {
        let now = Utc::now();
        let mut vault = VaultData {
            version: 2,
            salt: [0; 16],
            keys: HashMap::new(),
        };

        let err = rotate_key(&mut vault, "MISSING", None, now).unwrap_err();
        assert!(err.to_string().contains("key not found"));
    }
}
