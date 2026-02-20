use std::{collections::HashMap, path::PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const VAULT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub last_updated: DateTime<Utc>,
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
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        if let Some(secret) = self.secret.as_mut() {
            secret.zeroize();
        }
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
}

impl Drop for VaultData {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
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
    fn vault_data_zeroize_secrets_clears_values() {
        let mut vault = VaultData::new([7; 16]);
        vault.keys.insert(
            "OPENAI_API_KEY".to_string(),
            KeyEntry {
                name: "OPENAI_API_KEY".to_string(),
                description: "test".to_string(),
                tags: vec!["ci".to_string()],
                last_updated: Utc::now(),
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
}
