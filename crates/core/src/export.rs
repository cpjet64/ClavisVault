use std::io::{Cursor, Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::types::VaultData;

const EXPORT_FORMAT_VERSION: u32 = 1;
const EXPORT_MANIFEST_PATH: &str = "manifest.json";
const EXPORT_PAYLOAD_PATH: &str = "vault.json";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct EncryptedExportManifest {
    pub version: u32,
    pub created_at: DateTime<Utc>,
}

pub fn encrypt_export(vault: &VaultData, passphrase: &str) -> Result<Vec<u8>> {
    ensure_export_passphrase(passphrase)?;
    let payload = Zeroizing::new(
        serde_json::to_vec(vault).context("failed to serialize vault export payload")?,
    );
    let manifest = EncryptedExportManifest {
        version: EXPORT_FORMAT_VERSION,
        created_at: Utc::now(),
    };
    let manifest_bytes =
        serde_json::to_vec(&manifest).context("failed to serialize export manifest")?;
    let passphrase_owned = Zeroizing::new(passphrase.to_owned());
    let file_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .with_aes_encryption(AesMode::Aes256, passphrase_owned.as_str());
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));

    writer
        .start_file(EXPORT_MANIFEST_PATH, file_options)
        .context("failed starting export manifest file")?;
    writer
        .write_all(&manifest_bytes)
        .context("failed writing export manifest")?;

    writer
        .start_file(EXPORT_PAYLOAD_PATH, file_options)
        .context("failed starting encrypted vault payload file")?;
    writer
        .write_all(payload.as_slice())
        .context("failed writing encrypted vault payload")?;

    let cursor = writer
        .finish()
        .context("failed finalizing encrypted export archive")?;
    Ok(cursor.into_inner())
}

pub fn decrypt_export(encoded: &[u8], passphrase: &str) -> Result<VaultData> {
    ensure_export_passphrase(passphrase)?;
    let mut archive =
        ZipArchive::new(Cursor::new(encoded)).context("failed parsing encrypted export archive")?;
    let mut manifest_json = Vec::new();
    {
        let mut manifest_file = archive
            .by_name_decrypt(EXPORT_MANIFEST_PATH, passphrase.as_bytes())
            .context("failed opening encrypted export manifest")?;
        manifest_file
            .read_to_end(&mut manifest_json)
            .context("failed reading encrypted export manifest")?;
    }
    let manifest: EncryptedExportManifest = serde_json::from_slice(&manifest_json)
        .context("failed decoding encrypted export manifest")?;
    if manifest.version != EXPORT_FORMAT_VERSION {
        bail!("unsupported export format version: {}", manifest.version);
    }

    let mut payload = Zeroizing::new(Vec::new());
    {
        let mut payload_file = archive
            .by_name_decrypt(EXPORT_PAYLOAD_PATH, passphrase.as_bytes())
            .context("failed opening encrypted vault payload")?;
        payload_file
            .read_to_end(&mut payload)
            .context("failed reading encrypted vault payload")?;
    }

    serde_json::from_slice::<VaultData>(&payload).context("failed decoding exported vault payload")
}

fn ensure_export_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.trim().is_empty() {
        return Err(anyhow!("export passphrase must not be empty"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use chrono::Utc;
    use zip::ZipArchive;

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

    #[test]
    fn encrypted_export_is_aes_zip_archive() {
        let vault = VaultData::new([9; 16]);
        let encoded = encrypt_export(&vault, "zip-passphrase").expect("encrypt should work");
        assert!(encoded.starts_with(b"PK\x03\x04"));

        let mut archive =
            ZipArchive::new(Cursor::new(encoded)).expect("export should be a readable zip archive");
        assert_eq!(archive.len(), 2);

        {
            let manifest_entry = archive
                .by_name_decrypt(EXPORT_MANIFEST_PATH, b"zip-passphrase")
                .expect("manifest should decrypt");
            assert!(manifest_entry.encrypted());
        }

        let mut payload_entry = archive
            .by_name_decrypt(EXPORT_PAYLOAD_PATH, b"zip-passphrase")
            .expect("payload should decrypt");
        assert!(payload_entry.encrypted());

        let mut payload_bytes = Vec::new();
        payload_entry
            .read_to_end(&mut payload_bytes)
            .expect("payload should be readable");
        let decoded = serde_json::from_slice::<VaultData>(&payload_bytes)
            .expect("payload should decode as vault json");
        assert_eq!(decoded.salt, vault.salt);
    }

    #[test]
    fn encrypt_export_rejects_empty_passphrase() {
        let vault = VaultData::new([1; 16]);
        assert!(encrypt_export(&vault, "   ").is_err());
    }
}
