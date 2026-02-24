use std::{collections::HashMap, path::PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const VAULT_VERSION: u32 = 2;
pub const DEFAULT_AUDIT_LOG_MAX_AGE_DAYS: i64 = 90;

fn default_created_at() -> DateTime<Utc> {
    Utc.timestamp_opt(0, 0).single().unwrap_or_else(Utc::now)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub last_updated: DateTime<Utc>,
    #[serde(default = "default_created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub rotation_period_days: Option<u32>,
    #[serde(default)]
    pub warn_before_days: Option<u32>,
    #[serde(default)]
    pub last_rotated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
}

impl KeyEntry {
    pub fn zeroize_secret(&mut self) {
        if let Some(secret) = self.secret.as_mut() {
            secret.zeroize();
        }
        self.secret = None;
    }

    pub fn ensure_metadata_defaults(&mut self) -> bool {
        let mut changed = false;
        if self.created_at.timestamp() == 0 {
            self.created_at = self.last_updated;
            changed = true;
        }
        if self.last_rotated_at.is_none() {
            self.last_rotated_at = Some(self.last_updated);
            changed = true;
        }
        if self.rotation_period_days.is_some() && self.warn_before_days.is_none() {
            self.warn_before_days = Some(14);
            changed = true;
        }
        changed
    }
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        if let Some(secret) = self.secret.as_mut() {
            secret.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum ExportLegacyMode {
    Allow,
    #[default]
    Warn,
    #[serde(rename = "block")]
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExportSignerTrustPolicy {
    #[serde(default)]
    pub trusted_signers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub legacy_import_mode: ExportLegacyMode,
}

impl ExportSignerTrustPolicy {
    pub fn is_signer_trusted(&self, signer_key_id: &str, signer_public_key: &str) -> bool {
        self.trusted_signers
            .get(signer_key_id)
            .is_some_and(|public_key| public_key == signer_public_key)
    }

    pub fn allow_legacy_import(&self) -> bool {
        matches!(self.legacy_import_mode, ExportLegacyMode::Allow)
    }

    pub fn warn_legacy_import(&self) -> bool {
        matches!(self.legacy_import_mode, ExportLegacyMode::Warn)
    }

    pub fn record_trusted_signer(&mut self, signer_key_id: String, signer_public_key: String) {
        self.trusted_signers
            .insert(signer_key_id, signer_public_key);
    }

    pub fn signer_matches_existing_key(
        &self,
        signer_key_id: &str,
        signer_public_key: &str,
    ) -> bool {
        match self.trusted_signers.get(signer_key_id) {
            Some(existing_public_key) => existing_public_key == signer_public_key,
            None => false,
        }
    }

    pub fn remove_unknown_signer(&mut self, signer_key_id: &str) {
        self.trusted_signers.remove(signer_key_id);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultData {
    pub version: u32,
    pub salt: [u8; 16],
    pub keys: HashMap<String, KeyEntry>,
}

impl VaultData {
    pub fn new(salt: [u8; 16]) -> Self {
        Self {
            version: VAULT_VERSION,
            salt,
            keys: HashMap::new(),
        }
    }

    pub fn zeroize_secrets(&mut self) {
        for entry in self.keys.values_mut() {
            entry.zeroize_secret();
        }
    }

    pub fn migrate_in_place(&mut self) -> bool {
        let mut changed = false;
        if self.version < VAULT_VERSION {
            self.version = VAULT_VERSION;
            changed = true;
        }
        for entry in self.keys.values_mut() {
            if entry.ensure_metadata_defaults() {
                changed = true;
            }
        }
        changed
    }
}

impl Drop for VaultData {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

pub fn migrate_vault_data(vault: &mut VaultData) -> bool {
    vault.migrate_in_place()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedHeader {
    pub version: u32,
    pub nonce: [u8; 12],
    pub salt: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedVaultBlob {
    pub header: EncryptedHeader,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedVault {
    pub path: PathBuf,
    pub header: EncryptedHeader,
    pub ciphertext: Vec<u8>,
}

impl EncryptedVault {
    pub fn to_blob(&self) -> EncryptedVaultBlob {
        EncryptedVaultBlob {
            header: self.header.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }

    pub fn from_blob(path: impl Into<PathBuf>, blob: EncryptedVaultBlob) -> Self {
        Self {
            path: path.into(),
            header: blob.header,
            ciphertext: blob.ciphertext,
        }
    }

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(rmp_serde::to_vec(&self.to_blob())?)
    }

    pub fn from_bytes(path: impl Into<PathBuf>, bytes: &[u8]) -> anyhow::Result<Self> {
        let blob: EncryptedVaultBlob = rmp_serde::from_slice(bytes)?;
        Ok(Self::from_blob(path, blob))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterKey {
    bytes: Vec<u8>,
}

impl MasterKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_zeroizes_on_drop_path() {
        let key = MasterKey::new(vec![1, 2, 3, 4]);
        assert_eq!(key.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn key_entry_ensure_metadata_defaults_populates_missing_values() {
        let mut entry = KeyEntry {
            name: "ROTATED".to_string(),
            description: "metadata default".to_string(),
            tags: vec![],
            last_updated: Utc::now(),
            created_at: default_created_at(),
            expires_at: None,
            rotation_period_days: Some(30),
            warn_before_days: None,
            last_rotated_at: None,
            owner: None,
            secret: Some("seed".to_string()),
        };

        let changed = entry.ensure_metadata_defaults();

        assert!(changed);
        assert_eq!(entry.created_at, entry.last_updated);
        assert_eq!(entry.last_rotated_at, Some(entry.last_updated));
        assert_eq!(entry.warn_before_days, Some(14));
    }

    #[test]
    fn key_entry_ensure_metadata_defaults_no_changes_when_complete() {
        let now = Utc::now();
        let mut entry = KeyEntry {
            name: "STABLE".to_string(),
            description: "metadata stable".to_string(),
            tags: vec!["ci".to_string()],
            last_updated: now,
            created_at: now,
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(now),
            owner: Some("owner".to_string()),
            secret: Some("secret".to_string()),
        };

        let changed = entry.ensure_metadata_defaults();

        assert!(!changed);
        assert_eq!(entry.created_at, now);
        assert_eq!(entry.last_rotated_at, Some(now));
        assert!(entry.secret.is_some());
    }

    #[test]
    fn key_entry_zeroize_secret_handles_none_and_some() {
        let mut with_secret = KeyEntry {
            name: "WITH_SECRET".to_string(),
            description: "has secret".to_string(),
            tags: vec![],
            last_updated: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(Utc::now()),
            owner: None,
            secret: Some("keep_out".to_string()),
        };
        with_secret.zeroize_secret();
        assert!(with_secret.secret.is_none());

        let mut without_secret = KeyEntry {
            name: "WITHOUT_SECRET".to_string(),
            description: "empty".to_string(),
            tags: vec![],
            last_updated: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(Utc::now()),
            owner: None,
            secret: None,
        };
        without_secret.zeroize_secret();
        assert!(without_secret.secret.is_none());
    }

    #[test]
    fn export_signer_trust_policy_tracks_and_matches_signers() {
        let mut policy = ExportSignerTrustPolicy::default();
        policy.record_trusted_signer("kid-1".to_string(), "pubkey-A".to_string());
        policy.record_trusted_signer("kid-2".to_string(), "pubkey-B".to_string());

        assert!(policy.is_signer_trusted("kid-1", "pubkey-A"));
        assert!(policy.signer_matches_existing_key("kid-2", "pubkey-B"));
        assert!(!policy.signer_matches_existing_key("kid-2", "other"));
        assert!(!policy.is_signer_trusted("missing", "none"));

        policy.remove_unknown_signer("kid-1");
        assert!(!policy.is_signer_trusted("kid-1", "pubkey-A"));
    }

    #[test]
    fn export_signer_trust_policy_respects_legacy_flags() {
        let mut policy = ExportSignerTrustPolicy::default();
        assert!(policy.warn_legacy_import());
        assert!(!policy.allow_legacy_import());

        policy.legacy_import_mode = ExportLegacyMode::Allow;
        assert!(policy.allow_legacy_import());
        assert!(!policy.warn_legacy_import());

        policy.legacy_import_mode = ExportLegacyMode::Block;
        assert!(!policy.warn_legacy_import());
        assert!(!policy.allow_legacy_import());
    }

    #[test]
    fn encrypted_vault_blob_round_trip() {
        let vault = EncryptedVault {
            path: PathBuf::from("vault.cv"),
            header: EncryptedHeader {
                version: 1,
                nonce: [7; 12],
                salt: [9; 16],
            },
            ciphertext: vec![10, 20, 30],
        };

        let bytes = vault.to_bytes().expect("serialize blob");
        let restored = EncryptedVault::from_bytes("vault.cv", &bytes).expect("deserialize blob");

        assert_eq!(restored, vault);
    }

    #[test]
    fn encrypted_vault_from_blob_round_trips_path_and_bytes() {
        let blob = EncryptedVaultBlob {
            header: EncryptedHeader {
                version: 5,
                nonce: [2; 12],
                salt: [11; 16],
            },
            ciphertext: vec![42, 43, 44],
        };

        let vault = EncryptedVault::from_blob("/tmp/my-vault.cv", blob.clone());
        assert_eq!(vault.path, PathBuf::from("/tmp/my-vault.cv"));
        assert_eq!(vault.to_blob(), blob);
    }

    #[test]
    fn vault_data_migrate_in_place_without_changes() {
        let mut vault = VaultData::new([8; 16]);
        let changed = vault.migrate_in_place();

        assert!(!changed);
        assert_eq!(vault.version, VAULT_VERSION);
        assert!(vault.keys.is_empty());
    }

    #[test]
    fn vault_data_zeroize_secrets_clears_values() {
        let mut vault = VaultData::new([7; 16]);
        vault.keys.insert(
            "OPENAI_API_KEY".to_string(),
            KeyEntry {
                name: "OPENAI_API_KEY".to_string(),
                description: "test".to_string(),
                tags: vec!["ci".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: Some("ci".to_string()),
                secret: Some("top-secret".to_string()),
            },
        );

        vault.zeroize_secrets();
        assert!(
            vault
                .keys
                .values()
                .all(|entry| entry.secret.as_deref().is_none())
        );
    }

    #[test]
    fn key_entry_drop_path_handles_present_secret() {
        let entry = KeyEntry {
            name: "DROP_ME".to_string(),
            description: "drop coverage".to_string(),
            tags: vec!["coverage".to_string()],
            last_updated: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(Utc::now()),
            owner: None,
            secret: Some("sensitive".to_string()),
        };
        drop(entry);
    }

    #[test]
    fn migrate_vault_upgrades_version_and_key_metadata() {
        let mut vault = VaultData::new([1; 16]);
        vault.version = 1;
        vault.keys.insert(
            "MIGRATE_ME".to_string(),
            KeyEntry {
                name: "MIGRATE_ME".to_string(),
                description: "legacy key".to_string(),
                tags: vec![],
                last_updated: Utc::now(),
                created_at: default_created_at(),
                expires_at: None,
                rotation_period_days: Some(90),
                warn_before_days: None,
                last_rotated_at: None,
                owner: None,
                secret: None,
            },
        );

        let changed = migrate_vault_data(&mut vault);
        let entry = vault.keys.get("MIGRATE_ME").expect("key should exist");
        assert!(changed);
        assert_eq!(vault.version, VAULT_VERSION);
        assert!(entry.created_at.timestamp() > 0);
        assert_eq!(entry.warn_before_days, Some(14));
        assert!(entry.last_rotated_at.is_some());
    }
}
