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
