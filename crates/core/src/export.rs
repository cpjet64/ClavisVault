use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, rand_core::RngCore},
};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::types::VaultData;

const EXPORT_KEY_LEN: usize = 32;
const EXPORT_ARGON2_MEMORY_KIB: u32 = 19_456;
const EXPORT_ARGON2_TIME_COST: u32 = 4;
const EXPORT_ARGON2_PARALLELISM: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedExport {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_export(vault: &VaultData, passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = derive_export_key(passphrase, &salt)?;

    let mut plaintext = serde_json::to_vec(vault).context("failed to serialize vault export")?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid key"))?;
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_ref())
        .context("failed encrypting export")?;

    plaintext.zeroize();
    key.zeroize();

    let export = EncryptedExport {
        version: 1,
        created_at: Utc::now(),
        salt,
        nonce,
        ciphertext,
    };

    Ok(serde_json::to_vec_pretty(&export)?)
}

pub fn decrypt_export(encoded: &[u8], passphrase: &str) -> Result<VaultData> {
    let export: EncryptedExport =
        serde_json::from_slice(encoded).context("failed parsing encrypted export")?;

    let mut key = derive_export_key(passphrase, &export.salt)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid key"))?;
    let mut plaintext = cipher
        .decrypt((&export.nonce).into(), export.ciphertext.as_ref())
        .context("failed decrypting export")?;

    let vault = serde_json::from_slice::<VaultData>(&plaintext)
        .context("failed decoding exported vault payload")?;

    plaintext.zeroize();
    key.zeroize();

    Ok(vault)
}

fn derive_export_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; EXPORT_KEY_LEN]> {
    let params = Params::new(
        EXPORT_ARGON2_MEMORY_KIB,
        EXPORT_ARGON2_TIME_COST,
        EXPORT_ARGON2_PARALLELISM,
        Some(EXPORT_KEY_LEN),
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; EXPORT_KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .context("failed deriving export key")?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::types::{KeyEntry, VaultData};

    #[test]
    fn encrypted_export_round_trip() {
        let mut vault = VaultData::new([7; 16]);
        vault.keys.insert(
            "TOKEN".to_string(),
            KeyEntry {
                name: "TOKEN".to_string(),
                description: "token".to_string(),
                secret: None,
                tags: vec!["prod".to_string()],
                last_updated: Utc::now(),
            },
        );

        let encoded =
            encrypt_export(&vault, "export-passphrase").expect("encrypt export should work");
        let decoded =
            decrypt_export(&encoded, "export-passphrase").expect("decrypt export should work");

        assert_eq!(decoded.version, vault.version);
        assert_eq!(decoded.salt, vault.salt);
        assert_eq!(decoded.keys, vault.keys);
    }

    #[test]
    fn decrypt_fails_for_wrong_passphrase() {
        let vault = VaultData::new([8; 16]);
        let encoded = encrypt_export(&vault, "good-passphrase").expect("encrypt should work");
        assert!(decrypt_export(&encoded, "wrong-passphrase").is_err());
    }
}
